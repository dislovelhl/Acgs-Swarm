"""SQLite authority boundary for proof-carrying DAG state transitions.

Every other runtime store is a projection. ``BEGIN IMMEDIATE`` acquires the
write fence; the successful SQLite ``COMMIT`` is the single authority
linearization point.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.codec import canonical_statement
from constitutional_swarm.apcc.crypto import (
    AUTHORITY_DOMAIN,
    POLICY_DOMAIN,
    PROPOSAL_DOMAIN,
    b64u_encode,
    domain_preimage,
    predecessor_root as apcc_predecessor_root,
    sha256_digest,
)
from constitutional_swarm.apcc.model import (
    AuthorityStatusValue,
    CandidateLifecycle,
    CertificateBindings,
    CertificateContext,
    CertificateEvidence,
    CertificateSignatures,
    CertificateSubject,
    FailureCode,
    PredecessorRef,
    RequestOutcome,
    Signature,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AtomicCommitRequest,
    AuthorityRuntime,
    LogicalNodeStatusRequest,
    ProposeCommitRequest,
    RevocationRequest,
    RevocationScope,
    StageResultRequest,
)
from constitutional_swarm.apcc.service import APCCCommitService
from constitutional_swarm.apcc.sqlite_store import (
    SQLiteAuthorityStore,
    _GCBAtomicCommitRequest,
    _GCBProjectionCheckpoint,
    _GCBProjectionDenied,
    _GCBProjectionFault,
    _GCBProjectionPlan,
)
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.governance_errors import GovernanceBypassDenied

GCB_RECEIPT_PROFILE = "acgs-swarm/gcb-receipt/v1"
GCB_SIGNATURE_ALGORITHM = "Ed25519"
GCB_COMMIT_INTENT = "governed_commit"
_DOMAIN = b"ACGS-SWARM\x00GCB\x00V1\x00"
_VERDICT_DOMAIN = b"ACGS-SWARM\x00GCB\x00VERDICT\x00V1\x00"
_CONTROL_DOMAIN = b"ACGS-SWARM\x00GCB\x00CONTROL\x00V1\x00"
_CONTROL_SIGNER_DOMAIN = b"ACGS-SWARM-GCB-CONTROL-V1"
_MAX_WORKFLOW_NODES = 1000
_ATTEMPT_DOMAIN = b"ACGS-SWARM\x00GCB\x00ATTEMPT\x00V1\x00"
_LegacyTransaction = sqlite3.Connection


class _GCBFaultCheckpoint(Enum):
    """Closed, raise-only crash checkpoints for trusted recovery tests."""

    BEFORE_REVOCATION_FENCE_COMMIT = "before_revocation_fence_commit"
    AFTER_REVOCATION_FENCE_COMMIT = "after_revocation_fence_commit"
    DURING_REVOCATION_PROPAGATION = "during_revocation_propagation"
    AFTER_DURABLE_COMMIT = "after_durable_commit"


class _GCBInjectedFault(RuntimeError):
    pass


# Normative refinement anchors kept executable by
# ``test_tla_actions_have_implementation_refinement_anchors``.
GCB_TLA_ACTION_MAP: Mapping[str, tuple[str, ...]] = {
    "Claim": ("claim",),
    "ProduceResult": ("stage_result",),
    "TryCommit": ("commit",),
    "RejectConflict": ("commit", "concurrent_state_conflict"),
    "RejectCrossContext": ("commit", "stale_or_mismatched"),
    "RejectRevokedAttempt": ("claim", "agent_revoked"),
    "ExactReplay": ("commit", "request_hash"),
    "Equivocation": ("commit", "idempotency_conflict"),
    "RevokeRoot": ("revoke_root",),
    "PropagationCrash": (
        "resume_revocation_propagation",
        "during_revocation_propagation",
    ),
    "RecoverPropagation": ("resume_revocation_propagation",),
    "Propagate": ("resume_revocation_propagation",),
    "Dispatch": ("_dispatch_outbox", "_dispatch_revocation_outbox"),
    "CrashRecover": ("attach_workflow",),
    "ReconfigurePolicy": ("update_policy", "ControlAction.UPDATE_POLICY"),
    "RevokeExecutor": ("revoke_agent", "ControlAction.REVOKE_AGENT"),
    "FenceWorkflowGeneration": (
        "bump_workflow_generation",
        "ControlAction.BUMP_WORKFLOW_GENERATION",
    ),
    "ValidatorFailure": ("_validate", "invalid_authoritative_verdict"),
    "RecoverValidator": ("open", "verifier_public_key"),
    "ResponseLoss": ("commit", "request_hash"),
}


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class CommitOutcome(Enum):
    COMMITTED = "committed"
    DENIED = "denied"


class VerdictDecision(Enum):
    """Only these signed verifier decisions are authoritative."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class ControlAction(Enum):
    CREATE_WORKFLOW = "create_workflow"
    REGISTER_AGENT = "register_agent"
    UPDATE_POLICY = "update_policy"
    REVOKE_AGENT = "revoke_agent"
    REVOKE_ROOT = "revoke_root"
    BUMP_WORKFLOW_GENERATION = "bump_workflow_generation"
    FENCE_NODE_FOR_REVIEW = "fence_node_for_review"


@dataclass(frozen=True, order=True, slots=True)
class PredecessorBinding:
    node_id: str
    node_version: int
    commit_id: str
    receipt_digest: str
    authoritative_result_digest: str


@dataclass(frozen=True, slots=True)
class GovernedReceiptPayload:
    profile: str
    signature_algorithm: str
    key_id: str
    issued_at: int
    expires_at: int
    intent: str
    verifier_policy_id: str
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    input_digest: str
    output_digest: str
    predecessor_bindings: tuple[PredecessorBinding, ...]
    predecessor_root: str
    policy_version: str
    policy_digest: str
    policy_epoch: int
    authority_snapshot_digest: str
    authority_root: str
    authority_epoch: int
    agent_revocation_epoch: int
    workflow_revocation_generation: int
    workflow_generation: int
    state_version: int
    expected_node_state_version: int
    nonce: str
    commit_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        statement = {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.producer-statement",
            "producer_key_id": self.key_id,
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "attempt_id": self.attempt_id,
            "agent_id": self.agent_id,
            "actor_authority": self.authority_snapshot_digest,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "predecessor_root": self.predecessor_root,
            "expected_node_version": str(self.expected_node_state_version),
            "commit_id": self.commit_id,
            "nonce": self.nonce,
            "issued_at_ms": str(self.issued_at * 1000),
            "expires_at_ms": str(self.expires_at * 1000),
        }
        return domain_preimage(PROPOSAL_DOMAIN, canonical_statement(statement))


@dataclass(frozen=True, slots=True)
class SignedGovernedReceipt:
    payload: GovernedReceiptPayload
    signature: str

    def replace(self, **changes: Any) -> SignedGovernedReceipt:
        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class AttemptAuthorizationPayload:
    """Agent proof-of-possession authorizing one claim and result stage."""

    store_id: str
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    key_id: str
    expected_node_state_version: int
    policy_epoch: int
    authority_epoch: int
    agent_revocation_epoch: int
    workflow_revocation_generation: int
    workflow_generation: int
    issued_at: int
    expires_at: int
    nonce: str

    def canonical_bytes(self) -> bytes:
        return _ATTEMPT_DOMAIN + json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        ).encode("ascii")


@dataclass(frozen=True, slots=True)
class SignedAttemptAuthorization:
    payload: AttemptAuthorizationPayload
    signature: str


@dataclass(frozen=True, slots=True)
class AuthoritativeVerdict:
    decision: VerdictDecision
    store_id: str
    verifier_policy_id: str
    policy_id: str
    policy_version: str
    verifier_key_id: str
    receipt_digest: str
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    expected_node_state_version: int
    policy_epoch: int
    authority_epoch: int
    agent_revocation_epoch: int
    workflow_revocation_generation: int
    workflow_generation: int
    issued_at: int
    expires_at: int
    reason: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        body = asdict(self)
        body["decision"] = self.decision.value
        body.pop("signature")
        return body

    def canonical_bytes(self) -> bytes:
        return _VERDICT_DOMAIN + _authoritative_verdict_body(self)


def _authoritative_verdict_body(verdict: AuthoritativeVerdict) -> bytes:
    return json.dumps(
        verdict.unsigned_dict(), sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _sign_authoritative_verdict(
    unsigned: AuthoritativeVerdict,
    signer: Any,
    *,
    detached: bool,
) -> AuthoritativeVerdict:
    if detached:
        signature = signer.sign(
            _VERDICT_DOMAIN.removesuffix(b"\x00"),
            _authoritative_verdict_body(unsigned),
        )
    else:
        signature = signer.sign(unsigned.canonical_bytes())
    return replace(unsigned, signature=base64.b64encode(signature).decode("ascii"))


@dataclass(frozen=True, slots=True)
class ControlCommand:
    store_id: str
    command_id: str
    action: ControlAction
    workflow_id: str
    expected_control_version: int
    issued_at: int
    expires_at: int
    parameters: Mapping[str, Any]
    admin_key_id: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "store_id": self.store_id,
            "command_id": self.command_id,
            "action": self.action.value,
            "workflow_id": self.workflow_id,
            "expected_control_version": self.expected_control_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "parameters": dict(self.parameters),
            "admin_key_id": self.admin_key_id,
        }

    def canonical_bytes(self) -> bytes:
        return _CONTROL_SIGNER_DOMAIN + b"\x00" + self.canonical_body()

    def canonical_body(self) -> bytes:
        return json.dumps(
            self.unsigned_dict(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")


@dataclass(frozen=True, slots=True)
class CommitRequest:
    receipt: SignedGovernedReceipt
    verdict: AuthoritativeVerdict

    @property
    def commit_id(self) -> str:
        return self.receipt.payload.commit_id

    def canonical_hash(self) -> str:
        if isinstance(self.verdict, AuthoritativeVerdict):
            verdict_body: Any = {
                **self.verdict.unsigned_dict(),
                "signature": self.verdict.signature,
            }
        else:
            verdict_body = {
                "invalid_type": type(self.verdict).__name__,
                "representation": repr(self.verdict),
            }
        body = {
            "payload": self.receipt.payload.to_dict(),
            "signature": self.receipt.signature,
            "verdict": verdict_body,
        }
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CommitDecision:
    commit_id: str
    outcome: CommitOutcome
    reason: str
    workflow_id: str
    node_id: str
    state_version: int


@dataclass(frozen=True, slots=True)
class ControlDecision:
    command_id: str
    outcome: CommitOutcome
    reason: str
    control_version: int
    result: int | None = None


@dataclass(frozen=True, slots=True)
class GovernedNodeState:
    workflow_id: str
    node_id: str
    status: str
    version: int
    attempt_id: str | None
    claimed_by: str | None
    artifact_id: str | None
    commit_id: str | None


def sign_governed_receipt(
    payload: GovernedReceiptPayload, private_key: Ed25519PrivateKey
) -> SignedGovernedReceipt:
    signature = private_key.sign(payload.canonical_bytes())
    return SignedGovernedReceipt(payload, base64.b64encode(signature).decode("ascii"))


def sign_attempt_authorization(
    payload: AttemptAuthorizationPayload, private_key: Ed25519PrivateKey
) -> SignedAttemptAuthorization:
    signature = private_key.sign(payload.canonical_bytes())
    return SignedAttemptAuthorization(
        payload, base64.b64encode(signature).decode("ascii")
    )


def sign_authoritative_verdict(
    *,
    receipt: SignedGovernedReceipt,
    private_key: Ed25519PrivateKey,
    store_id: str,
    verifier_policy_id: str,
    verifier_key_id: str,
    decision: VerdictDecision = VerdictDecision.ALLOW,
    reason: str = "verified",
    lifetime_seconds: int = 60,
) -> AuthoritativeVerdict:
    payload = receipt.payload
    now = int(time.time())
    unsigned = AuthoritativeVerdict(
        decision=decision,
        store_id=store_id,
        verifier_policy_id=verifier_policy_id,
        policy_id=payload.verifier_policy_id,
        policy_version=payload.policy_version,
        verifier_key_id=verifier_key_id,
        receipt_digest=_signed_receipt_digest(receipt),
        workflow_id=payload.workflow_id,
        node_id=payload.node_id,
        attempt_id=payload.attempt_id,
        agent_id=payload.agent_id,
        expected_node_state_version=payload.expected_node_state_version,
        policy_epoch=payload.policy_epoch,
        authority_epoch=payload.authority_epoch,
        agent_revocation_epoch=payload.agent_revocation_epoch,
        workflow_revocation_generation=payload.workflow_revocation_generation,
        workflow_generation=payload.workflow_generation,
        issued_at=now,
        expires_at=now + lifetime_seconds,
        reason=reason,
        signature="",
    )
    return _sign_authoritative_verdict(unsigned, private_key, detached=False)


def sign_control_command(
    command: ControlCommand, private_key: Ed25519PrivateKey
) -> ControlCommand:
    signature = private_key.sign(command.canonical_bytes())
    return replace(command, signature=base64.b64encode(signature).decode("ascii"))


def _signed_receipt_material(receipt: SignedGovernedReceipt) -> str:
    return json.dumps(
        {"payload": receipt.payload.to_dict(), "signature": receipt.signature},
        sort_keys=True,
        separators=(",", ":"),
    )


def _signed_receipt_digest(receipt: SignedGovernedReceipt) -> str:
    return hashlib.sha256(_signed_receipt_material(receipt).encode()).hexdigest()


def predecessor_root(bindings: Sequence[PredecessorBinding]) -> str:
    encoded = json.dumps(
        [asdict(binding) for binding in sorted(bindings)],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _apcc_predecessors(
    workflow_id: str, bindings: Sequence[PredecessorBinding]
) -> tuple[PredecessorRef, ...]:
    references = tuple(
        PredecessorRef(
            workflow_id,
            item.node_id,
            str(item.node_version),
            item.commit_id,
            item.receipt_digest,
            item.authoritative_result_digest,
        )
        for item in bindings
    )
    return tuple(
        sorted(references, key=lambda item: canonical_statement(item.to_object()))
    )


@final
class GovernedCommitBoundary:
    """Restricted agent-facing durable commit port.

    Instances can only be obtained by opening an already sealed authority or
    from the one-time trusted bootstrap.  The runtime port exposes claims,
    staging, commit, reads, and signed control-command submission; it does not
    accept a Python policy callable or unsigned authority mutation.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.path: str
        self._fault_checkpoint: _GCBFaultCheckpoint | None
        self._fault_checkpoint_fired: bool
        self._busy_timeout_ms: int
        self.store_id: str
        self.verifier_policy_id: str
        self.verifier_key_id: str
        self._apcc_config: APCCAuthorityConfig
        self._apcc_store: SQLiteAuthorityStore
        self._apcc_service: APCCCommitService
        self._policy_signer: Any
        self._registry_signer: Any
        del args, kwargs
        raise GovernanceBypassDenied(
            "use GovernedCommitBoundary.open on a sealed store"
        )

    @classmethod
    def open(
        cls, path: str | Path, *, busy_timeout_ms: int = 5_000
    ) -> GovernedCommitBoundary:
        """Raw stores cannot be opened outside the typed authority bootstrap."""
        del path, busy_timeout_ms
        raise GovernanceBypassDenied(
            "APCC authority requires typed trusted bootstrap recovery"
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path, timeout=self._busy_timeout_ms / 1000, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        return conn

    @contextmanager
    def _transaction(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if hasattr(self, "_apcc_store"):
                self._apcc_store._validate_mutation_checkpoint(conn)
            yield conn
            if hasattr(self, "_apcc_store"):
                self._apcc_store._finalize_attached_gcb_transaction(conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(
        self,
        *,
        provision: bool,
        store_id: str,
        verifier_policy_id: str,
        verifier_public_key: Ed25519PublicKey | None,
        verifier_key_id: str,
        admin_public_key: Ed25519PublicKey | None,
        admin_key_id: str,
        allow_apcc_peer: bool = False,
    ) -> None:
        existed = Path(self.path).exists() and Path(self.path).stat().st_size > 0
        if provision and existed and not allow_apcc_peer:
            raise GovernanceBypassDenied("authority_store_already_exists")
        if not provision and not existed:
            raise GovernanceBypassDenied("sealed_authority_store_required")
        with self._connect() as conn:
            if provision:
                if (
                    not store_id
                    or not verifier_policy_id
                    or verifier_public_key is None
                    or not verifier_key_id
                    or admin_public_key is None
                    or not admin_key_id
                ):
                    raise ValueError("complete bootstrap trust anchors are required")
                if conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
                ).fetchone():
                    raise GovernanceBypassDenied("authority_store_already_exists")
                conn.execute(
                    """CREATE TABLE schema_meta(
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        version INTEGER NOT NULL)"""
                )
                conn.execute("INSERT INTO schema_meta VALUES(1,3)")
            try:
                version_row = conn.execute(
                    "SELECT version FROM schema_meta WHERE singleton=1"
                ).fetchone()
            except sqlite3.Error as exc:
                raise GovernanceBypassDenied("sealed_authority_store_required") from exc
            if version_row is None:
                raise GovernanceBypassDenied("sealed_authority_store_required")
            version = version_row[0]
            if version != 3:
                raise RuntimeError(f"unsupported GCB schema version: {version}")
            schema_sql = """
                CREATE TABLE IF NOT EXISTS store_seal(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    store_id TEXT NOT NULL UNIQUE, sealed INTEGER NOT NULL CHECK(sealed=1),
                    verifier_policy_id TEXT NOT NULL, verifier_key_id TEXT NOT NULL,
                    verifier_public_key BLOB NOT NULL, verifier_key_fingerprint TEXT NOT NULL,
                    admin_key_id TEXT NOT NULL, admin_public_key BLOB NOT NULL,
                    admin_key_fingerprint TEXT NOT NULL, control_version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS workflows(
                    workflow_id TEXT PRIMARY KEY, generation INTEGER NOT NULL,
                    policy_version TEXT NOT NULL, policy_digest TEXT NOT NULL,
                    policy_epoch INTEGER NOT NULL, verifier_policy_id TEXT NOT NULL,
                    authority_root TEXT NOT NULL, authority_epoch INTEGER NOT NULL,
                    revocation_generation INTEGER NOT NULL, state_version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS agents(
                    workflow_id TEXT NOT NULL, agent_id TEXT NOT NULL, public_key BLOB NOT NULL,
                    key_id TEXT NOT NULL, capabilities TEXT NOT NULL,
                    authority_epoch INTEGER NOT NULL, revocation_epoch INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
                    PRIMARY KEY(workflow_id,agent_id),
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id));
                CREATE TABLE IF NOT EXISTS nodes(
                    workflow_id TEXT NOT NULL, node_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN('blocked','ready','claimed',
                      'result_produced','governed_committed','denied','revoked','superseded')),
                    version INTEGER NOT NULL, input_digest TEXT NOT NULL,
                    required_capabilities TEXT NOT NULL, predecessors TEXT NOT NULL,
                    attempt_id TEXT, claimed_by TEXT, artifact_id TEXT, result_digest TEXT,
                    commit_id TEXT, receipt_digest TEXT,
                    tainted INTEGER NOT NULL DEFAULT 0 CHECK(tainted IN(0,1)),
                    PRIMARY KEY(workflow_id,node_id),
                    UNIQUE(workflow_id,commit_id),
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id));
                CREATE TABLE IF NOT EXISTS staged_artifacts(
                    workflow_id TEXT NOT NULL,node_id TEXT NOT NULL,attempt_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,artifact_json TEXT NOT NULL,output_digest TEXT NOT NULL,
                    PRIMARY KEY(workflow_id,node_id,attempt_id), UNIQUE(workflow_id,artifact_id),
                    FOREIGN KEY(workflow_id,node_id)
                      REFERENCES nodes(workflow_id,node_id));
                CREATE TABLE IF NOT EXISTS decisions(
                    commit_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,outcome TEXT NOT NULL,
                    reason TEXT NOT NULL,workflow_id TEXT NOT NULL,node_id TEXT NOT NULL,
                    state_version INTEGER NOT NULL,nonce TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS receipt_evidence(
                    commit_id TEXT PRIMARY KEY, receipt_material TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL, verdict_material TEXT NOT NULL,
                    verdict_digest TEXT NOT NULL,
                    FOREIGN KEY(commit_id) REFERENCES decisions(commit_id));
                CREATE TABLE IF NOT EXISTS security_events(
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL, event_key TEXT NOT NULL,
                    workflow_id TEXT NOT NULL, node_id TEXT NOT NULL,
                    material TEXT NOT NULL, created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS gcb_control_events(
                    command_id TEXT PRIMARY KEY, action TEXT NOT NULL,
                    workflow_id TEXT NOT NULL, expected_control_version INTEGER NOT NULL,
                    resulting_control_version INTEGER NOT NULL, outcome TEXT NOT NULL,
                    reason TEXT NOT NULL, result_value INTEGER,
                    command_material TEXT NOT NULL,
                    created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox(
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,commit_id TEXT NOT NULL UNIQUE,
                    workflow_id TEXT NOT NULL,node_id TEXT NOT NULL,artifact_json TEXT NOT NULL,
                    dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN(0,1)),
                    FOREIGN KEY(commit_id) REFERENCES decisions(commit_id));
                CREATE TABLE IF NOT EXISTS revoked_roots(
                    workflow_id TEXT NOT NULL, root_node_id TEXT NOT NULL,
                    generation INTEGER NOT NULL, event_id TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    PRIMARY KEY(workflow_id,root_node_id),
                    FOREIGN KEY(workflow_id,root_node_id)
                      REFERENCES nodes(workflow_id,node_id));
                CREATE TABLE IF NOT EXISTS revocation_outbox(
                    event_id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL,
                    root_node_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    processed INTEGER NOT NULL DEFAULT 0 CHECK(processed IN(0,1)),
                    dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN(0,1)),
                    FOREIGN KEY(workflow_id,root_node_id)
                      REFERENCES nodes(workflow_id,node_id));
                CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(dispatched,event_id);
                CREATE INDEX IF NOT EXISTS idx_revocation_pending
                  ON revocation_outbox(processed,generation);
                """
            if provision:
                conn.executescript(schema_sql)
            self._validate_schema_shape(conn)
            if provision:
                assert verifier_public_key is not None
                assert admin_public_key is not None
                verifier_raw = verifier_public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                admin_raw = admin_public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                conn.execute(
                    """INSERT INTO store_seal VALUES(1,?,1,?,?,?,?,?,?,?,0)""",
                    (
                        store_id,
                        verifier_policy_id,
                        verifier_key_id,
                        verifier_raw,
                        hashlib.sha256(verifier_raw).hexdigest(),
                        admin_key_id,
                        admin_raw,
                        hashlib.sha256(admin_raw).hexdigest(),
                    ),
                )
            seal = conn.execute(
                "SELECT * FROM store_seal WHERE singleton=1 AND sealed=1"
            ).fetchone()
            if seal is None:
                raise GovernanceBypassDenied("authority_store_not_sealed")
            if (
                hashlib.sha256(seal["verifier_public_key"]).hexdigest()
                != seal["verifier_key_fingerprint"]
                or hashlib.sha256(seal["admin_public_key"]).hexdigest()
                != seal["admin_key_fingerprint"]
            ):
                raise GovernanceBypassDenied("authority_anchor_integrity_failure")
            self.store_id = seal["store_id"]
            self.verifier_policy_id = seal["verifier_policy_id"]
            self.verifier_key_id = seal["verifier_key_id"]
            if not provision:
                workflows = conn.execute("SELECT workflow_id FROM workflows").fetchall()
                for workflow in workflows:
                    self._verify_committed_evidence(conn, workflow["workflow_id"])

    @staticmethod
    def _validate_schema_shape(conn: sqlite3.Connection) -> None:
        expected_columns = {
            "schema_meta": ("singleton", "version"),
            "store_seal": (
                "singleton",
                "store_id",
                "sealed",
                "verifier_policy_id",
                "verifier_key_id",
                "verifier_public_key",
                "verifier_key_fingerprint",
                "admin_key_id",
                "admin_public_key",
                "admin_key_fingerprint",
                "control_version",
            ),
            "workflows": (
                "workflow_id",
                "generation",
                "policy_version",
                "policy_digest",
                "policy_epoch",
                "verifier_policy_id",
                "authority_root",
                "authority_epoch",
                "revocation_generation",
                "state_version",
            ),
            "agents": (
                "workflow_id",
                "agent_id",
                "public_key",
                "key_id",
                "capabilities",
                "authority_epoch",
                "revocation_epoch",
                "revoked",
            ),
            "nodes": (
                "workflow_id",
                "node_id",
                "status",
                "version",
                "input_digest",
                "required_capabilities",
                "predecessors",
                "attempt_id",
                "claimed_by",
                "artifact_id",
                "result_digest",
                "commit_id",
                "receipt_digest",
                "tainted",
            ),
            "staged_artifacts": (
                "workflow_id",
                "node_id",
                "attempt_id",
                "artifact_id",
                "artifact_json",
                "output_digest",
            ),
            "decisions": (
                "commit_id",
                "request_hash",
                "outcome",
                "reason",
                "workflow_id",
                "node_id",
                "state_version",
                "nonce",
            ),
            "receipt_evidence": (
                "commit_id",
                "receipt_material",
                "receipt_digest",
                "verdict_material",
                "verdict_digest",
            ),
            "security_events": (
                "event_id",
                "event_type",
                "event_key",
                "workflow_id",
                "node_id",
                "material",
                "created_at",
            ),
            "gcb_control_events": (
                "command_id",
                "action",
                "workflow_id",
                "expected_control_version",
                "resulting_control_version",
                "outcome",
                "reason",
                "result_value",
                "command_material",
                "created_at",
            ),
            "outbox": (
                "event_id",
                "commit_id",
                "workflow_id",
                "node_id",
                "artifact_json",
                "dispatched",
            ),
            "revoked_roots": (
                "workflow_id",
                "root_node_id",
                "generation",
                "event_id",
                "reason",
            ),
            "revocation_outbox": (
                "event_id",
                "workflow_id",
                "root_node_id",
                "generation",
                "processed",
                "dispatched",
            ),
        }
        actual_tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not set(expected_columns).issubset(actual_tables):
            raise GovernanceBypassDenied("authority_schema_shape_mismatch")
        for table, columns in expected_columns.items():
            actual = tuple(
                row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')
            )
            if actual != columns:
                raise GovernanceBypassDenied("authority_schema_shape_mismatch")
        named_indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name,tbl_name FROM sqlite_master "
                "WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
            if row[1] in expected_columns
        }
        if named_indexes != {"idx_outbox_pending", "idx_revocation_pending"}:
            raise GovernanceBypassDenied("authority_schema_shape_mismatch")
        if conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name IN (" + ",".join("?" for _ in expected_columns) + ")",
            tuple(expected_columns),
        ).fetchone()[0]:
            raise GovernanceBypassDenied("authority_schema_shape_mismatch")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise GovernanceBypassDenied("authority_integrity_check_failed")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise GovernanceBypassDenied("authority_foreign_key_check_failed")

    @staticmethod
    def _artifact_json(artifact: Artifact) -> str:
        return json.dumps(
            artifact.canonical_dict(), sort_keys=True, separators=(",", ":")
        )

    @staticmethod
    def _artifact_from_json(raw: str) -> Artifact:
        body = json.loads(raw)
        body["tags"] = tuple(body["tags"])
        body["parent_artifacts"] = tuple(body["parent_artifacts"])
        return Artifact(**body)

    def control_version(self) -> int:
        with self._connect() as conn:
            return int(
                conn.execute(
                    "SELECT control_version FROM store_seal WHERE singleton=1"
                ).fetchone()[0]
            )

    def apply_control_command(self, command: ControlCommand) -> ControlDecision:
        """Authenticate, audit, CAS, and apply one authority transition."""
        material = json.dumps(
            {**command.unsigned_dict(), "signature": command.signature},
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            with self._transaction() as conn:
                prior = conn.execute(
                    "SELECT * FROM gcb_control_events WHERE command_id=?",
                    (command.command_id,),
                ).fetchone()
                if prior is not None:
                    if prior["command_material"] != material:
                        self._security_event(
                            conn,
                            "control_collision_attempt",
                            command.command_id,
                            command.workflow_id,
                            "",
                            material,
                        )
                        return ControlDecision(
                            command.command_id,
                            CommitOutcome.DENIED,
                            "control_idempotency_conflict",
                            prior["resulting_control_version"],
                        )
                    return ControlDecision(
                        command.command_id,
                        CommitOutcome(prior["outcome"]),
                        prior["reason"],
                        prior["resulting_control_version"],
                        prior["result_value"],
                    )
                seal = conn.execute(
                    "SELECT * FROM store_seal WHERE singleton=1 AND sealed=1"
                ).fetchone()
                current_version = int(seal["control_version"])
                denial = self._validate_control_command(command, seal, current_version)
                if denial is not None:
                    self._record_control(
                        conn,
                        command,
                        material,
                        CommitOutcome.DENIED,
                        denial,
                        current_version,
                        None,
                    )
                    return ControlDecision(
                        command.command_id,
                        CommitOutcome.DENIED,
                        denial,
                        current_version,
                    )
                try:
                    result = self._apply_control_action(conn, command)
                except (GovernanceBypassDenied, KeyError, TypeError, ValueError) as exc:
                    reason = str(exc) or type(exc).__name__
                    self._record_control(
                        conn,
                        command,
                        material,
                        CommitOutcome.DENIED,
                        reason,
                        current_version,
                        None,
                    )
                    self._security_event(
                        conn,
                        "control_transition_denied",
                        command.command_id,
                        command.workflow_id,
                        "",
                        material,
                    )
                    return ControlDecision(
                        command.command_id,
                        CommitOutcome.DENIED,
                        reason,
                        current_version,
                    )
                next_version = current_version + 1
                changed = conn.execute(
                    """UPDATE store_seal SET control_version=?
                       WHERE singleton=1 AND control_version=?""",
                    (next_version, current_version),
                ).rowcount
                if changed != 1:
                    raise sqlite3.OperationalError("control_version_cas_failed")
                self._record_control(
                    conn,
                    command,
                    material,
                    CommitOutcome.COMMITTED,
                    "verified_admin_transition",
                    next_version,
                    result,
                )
                if command.action is ControlAction.REVOKE_ROOT:
                    # The SQLite COMMIT is the fence linearization point.  A
                    # crash or response loss after it must not undo authority.
                    if hasattr(self, "_apcc_store"):
                        self._apcc_store._finalize_attached_gcb_transaction(conn)
                    conn.commit()
                    self._inject_fault(
                        _GCBFaultCheckpoint.AFTER_REVOCATION_FENCE_COMMIT
                    )
                return ControlDecision(
                    command.command_id,
                    CommitOutcome.COMMITTED,
                    "verified_admin_transition",
                    next_version,
                    result,
                )
        except sqlite3.Error:
            return ControlDecision(
                command.command_id,
                CommitOutcome.DENIED,
                "persistence_error",
                -1,
            )

    def _validate_control_command(
        self, command: ControlCommand, seal: sqlite3.Row, current_version: int
    ) -> str | None:
        if command.store_id != seal["store_id"]:
            return "control_store_mismatch"
        if command.admin_key_id != seal["admin_key_id"]:
            return "control_admin_key_mismatch"
        if command.expected_control_version != current_version:
            return "stale_control_version"
        now = int(time.time())
        if command.issued_at > now + 30 or command.expires_at < now:
            return "control_command_expired_or_not_yet_valid"
        if command.expires_at <= command.issued_at:
            return "invalid_control_command_lifetime"
        try:
            signature = base64.b64decode(command.signature, validate=True)
            Ed25519PublicKey.from_public_bytes(seal["admin_public_key"]).verify(
                signature, command.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            return "invalid_control_signature"
        return None

    def _apply_control_action(
        self, conn: sqlite3.Connection, command: ControlCommand
    ) -> int | None:
        parameters = dict(command.parameters)
        workflow_id = command.workflow_id
        if command.action is ControlAction.CREATE_WORKFLOW:
            nodes = {
                str(node_id): tuple(str(dep) for dep in dependencies)
                for node_id, dependencies in dict(parameters["nodes"]).items()
            }
            if len(nodes) > _MAX_WORKFLOW_NODES:
                raise GovernanceBypassDenied("node_status_batch_too_large")
            if not workflow_id or not nodes or not parameters.get("policy_version"):
                raise GovernanceBypassDenied("invalid_workflow_definition")
            if conn.execute(
                "SELECT 1 FROM workflows WHERE workflow_id=?", (workflow_id,)
            ).fetchone():
                raise GovernanceBypassDenied("authoritative workflow already exists")
            unknown = {
                dep for deps in nodes.values() for dep in deps if dep not in nodes
            }
            if unknown:
                raise GovernanceBypassDenied("unknown_predecessor")
            policy_version = str(parameters["policy_version"])
            policy_digest = str(
                parameters.get("policy_digest")
                or _canonical_digest({"policy_version": policy_version})
            )
            verifier_policy_id = str(
                parameters.get("verifier_policy_id") or self.verifier_policy_id
            )
            if verifier_policy_id != self.verifier_policy_id:
                raise GovernanceBypassDenied("unsealed_verifier_policy")
            generation = int(parameters.get("generation", 1))
            authority_root = _canonical_digest([])
            authority_epoch = 1
            if hasattr(self, "_apcc_config"):
                registry_binding = self._apcc_config.registry_trust[0]
                authority_root = registry_binding.scope[0]
                authority_epoch = int(registry_binding.scope[1])
            conn.execute(
                """INSERT INTO workflows(
                     workflow_id,generation,policy_version,policy_digest,policy_epoch,
                     verifier_policy_id,authority_root,authority_epoch,
                     revocation_generation,state_version)
                   VALUES(?,?,?,?,1,?,?,?,?,0)""",
                (
                    workflow_id,
                    generation,
                    policy_version,
                    policy_digest,
                    verifier_policy_id,
                    authority_root,
                    authority_epoch,
                    1,
                ),
            )
            required_capabilities = dict(parameters.get("required_capabilities", {}))
            input_digests = dict(parameters.get("input_digests", {}))
            for node_id, deps in nodes.items():
                default_input_digest = hashlib.sha256(
                    f"{workflow_id}\x00{node_id}".encode()
                ).hexdigest()
                if hasattr(self, "_apcc_config"):
                    default_input_digest = sha256_digest(
                        f"{workflow_id}\x00{node_id}".encode()
                    )
                digest = str(input_digests.get(node_id) or default_input_digest)
                if hasattr(self, "_apcc_config") and len(digest) == 64:
                    try:
                        digest = b64u_encode(bytes.fromhex(digest))
                    except ValueError:
                        pass
                conn.execute(
                    """INSERT INTO nodes(workflow_id,node_id,status,version,input_digest,
                       required_capabilities,predecessors,tainted) VALUES(?,?,?,0,?,?,?,0)""",
                    (
                        workflow_id,
                        node_id,
                        "ready" if not deps else "blocked",
                        digest,
                        json.dumps(sorted(required_capabilities.get(node_id, ()))),
                        json.dumps(sorted(deps)),
                    ),
                )
            return generation
        if command.action is ControlAction.REGISTER_AGENT:
            workflow = self._workflow(conn, workflow_id)
            raw_key = base64.b64decode(str(parameters["public_key"]), validate=True)
            Ed25519PublicKey.from_public_bytes(raw_key)
            authority_epoch = workflow["authority_epoch"] + 1
            key_id = str(
                parameters.get("key_id") or hashlib.sha256(raw_key).hexdigest()[:32]
            )
            if hasattr(self, "_apcc_config"):
                producer_binding = next(
                    (
                        binding
                        for binding in self._apcc_config.producer_trust
                        if binding.public_key == raw_key
                    ),
                    None,
                )
                if producer_binding is None:
                    raise GovernanceBypassDenied("untrusted_producer_key")
                key_id = producer_binding.key_id
                authority_epoch = int(self._apcc_config.registry_trust[0].scope[1])
            conn.execute(
                """INSERT INTO agents(
                     workflow_id,agent_id,public_key,key_id,capabilities,
                     authority_epoch,revocation_epoch,revoked)
                   VALUES(?,?,?,?,?,?,1,0)""",
                (
                    workflow_id,
                    str(parameters["agent_id"]),
                    raw_key,
                    key_id,
                    json.dumps(sorted(set(parameters.get("capabilities", ())))),
                    authority_epoch,
                ),
            )
            authority_root = self._authority_root(conn, workflow_id)
            if hasattr(self, "_apcc_config"):
                authority_root = self._apcc_config.registry_trust[0].scope[0]
            next_state_version = workflow["state_version"] + int(
                hasattr(self, "_apcc_config")
            )
            conn.execute(
                """UPDATE workflows
                   SET authority_epoch=?,authority_root=?,state_version=?
                   WHERE workflow_id=?""",
                (authority_epoch, authority_root, next_state_version, workflow_id),
            )
            return (
                next_state_version if hasattr(self, "_apcc_config") else authority_epoch
            )
        if command.action is ControlAction.UPDATE_POLICY:
            workflow = self._workflow(conn, workflow_id)
            version = str(parameters["policy_version"])
            digest = str(
                parameters.get("policy_digest")
                or _canonical_digest({"policy_version": version})
            )
            epoch = workflow["policy_epoch"] + 1
            if hasattr(self, "_apcc_config"):
                self._apcc_policy_binding(
                    self.verifier_policy_id,
                    version,
                    epoch,
                )
            conn.execute(
                """UPDATE workflows SET policy_version=?,policy_digest=?,policy_epoch=?
                   WHERE workflow_id=?""",
                (version, digest, epoch, workflow_id),
            )
            return epoch
        if command.action is ControlAction.REVOKE_AGENT:
            workflow = self._workflow(conn, workflow_id)
            agent_id = str(parameters["agent_id"])
            agent = self._agent(conn, workflow_id, agent_id)
            epoch = agent["revocation_epoch"] + 1
            if hasattr(self, "_apcc_store"):
                conn.execute(
                    """UPDATE agents SET revoked=1,revocation_epoch=?
                       WHERE workflow_id=? AND agent_id=?""",
                    (epoch, workflow_id, agent_id),
                )
            else:
                authority_epoch = workflow["authority_epoch"] + 1
                conn.execute(
                    """UPDATE agents SET revoked=1,revocation_epoch=?,authority_epoch=?
                       WHERE workflow_id=? AND agent_id=?""",
                    (epoch, authority_epoch, workflow_id, agent_id),
                )
                authority_root = self._authority_root(conn, workflow_id)
                conn.execute(
                    """UPDATE workflows SET authority_epoch=?,authority_root=?
                       WHERE workflow_id=?""",
                    (authority_epoch, authority_root, workflow_id),
                )
            self._taint_descendants(conn, workflow_id, agent_id)
            if hasattr(self, "_apcc_store"):
                self._apcc_store._revoke_on_connection(
                    conn,
                    RevocationRequest(
                        RevocationScope.ACTOR,
                        workflow_id,
                        agent_id,
                        str(epoch),
                        "GCB signed actor revocation",
                    ),
                )
            return epoch
        if command.action is ControlAction.BUMP_WORKFLOW_GENERATION:
            workflow = self._workflow(conn, workflow_id)
            generation = workflow["generation"] + 1
            conn.execute(
                "UPDATE workflows SET generation=? WHERE workflow_id=?",
                (generation, workflow_id),
            )
            return generation
        if command.action is ControlAction.REVOKE_ROOT:
            workflow = self._workflow(conn, workflow_id)
            node_id = str(parameters["node_id"])
            event_id = str(parameters["event_id"])
            root = self._node(conn, workflow_id, node_id)
            if root["status"] != "governed_committed":
                raise GovernanceBypassDenied("revocation_root_not_governed_committed")
            generation = workflow["revocation_generation"] + 1
            if hasattr(self, "_apcc_store"):
                logical = conn.execute(
                    """SELECT certificate_digest FROM logical_nodes
                       WHERE workflow_id=? AND node_id=?""",
                    (workflow_id, node_id),
                ).fetchone()
                if logical is None or logical["certificate_digest"] is None:
                    raise GovernanceBypassDenied("canonical_certificate_missing")
                self._apcc_store._revoke_on_connection(
                    conn,
                    RevocationRequest(
                        RevocationScope.CERTIFICATE,
                        workflow_id,
                        logical["certificate_digest"],
                        str(generation),
                        str(parameters["reason"]),
                    ),
                )
            conn.execute(
                """INSERT INTO revoked_roots(
                     workflow_id,root_node_id,generation,event_id,reason)
                   VALUES(?,?,?,?,?)""",
                (workflow_id, node_id, generation, event_id, str(parameters["reason"])),
            )
            conn.execute(
                """INSERT INTO revocation_outbox(
                     event_id,workflow_id,root_node_id,generation,processed,dispatched)
                   VALUES(?,?,?,?,0,0)""",
                (event_id, workflow_id, node_id, generation),
            )
            conn.execute(
                "UPDATE workflows SET revocation_generation=? WHERE workflow_id=?",
                (generation, workflow_id),
            )
            self._inject_fault(_GCBFaultCheckpoint.BEFORE_REVOCATION_FENCE_COMMIT)
            return generation
        if command.action is ControlAction.FENCE_NODE_FOR_REVIEW:
            changed = conn.execute(
                "UPDATE nodes SET version=version+1 WHERE workflow_id=? AND node_id=?",
                (workflow_id, str(parameters["node_id"])),
            ).rowcount
            if changed != 1:
                raise GovernanceBypassDenied("unknown_node")
            return None
        raise GovernanceBypassDenied("unknown_control_action")

    def _record_control(
        self,
        conn: sqlite3.Connection,
        command: ControlCommand,
        material: str,
        outcome: CommitOutcome,
        reason: str,
        resulting_version: int,
        result: int | None,
    ) -> None:
        conn.execute(
            """INSERT INTO gcb_control_events VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                command.command_id,
                command.action.value,
                command.workflow_id,
                command.expected_control_version,
                resulting_version,
                outcome.value,
                reason,
                result,
                material,
                int(time.time()),
            ),
        )

    @staticmethod
    def _security_event(
        conn: sqlite3.Connection,
        event_type: str,
        event_key: str,
        workflow_id: str,
        node_id: str,
        material: str,
    ) -> None:
        conn.execute(
            """INSERT INTO security_events(
                 event_type,event_key,workflow_id,node_id,material,created_at)
               VALUES(?,?,?,?,?,?)""",
            (event_type, event_key, workflow_id, node_id, material, int(time.time())),
        )

    def attach_workflow(
        self,
        *,
        workflow_id: str,
        nodes: Mapping[str, Sequence[str]],
        policy_version: str,
        required_capabilities: Mapping[str, Sequence[str]] | None = None,
        input_digests: Mapping[str, str] | None = None,
    ) -> dict[str, GovernedNodeState]:
        """Recover an existing workflow only when its authority shape matches.

        This is a read-only projection attach.  It never creates nodes, changes
        status, promotes staged artifacts, or rewrites policy state.
        """
        if len(nodes) > _MAX_WORKFLOW_NODES:
            raise GovernanceBypassDenied("node_status_batch_too_large")
        required_capabilities = required_capabilities or {}
        input_digests = input_digests or {}
        with self._transaction() as conn:
            workflow = self._workflow(conn, workflow_id)
            if workflow["policy_version"] != policy_version:
                raise GovernanceBypassDenied("recovery_policy_mismatch")
            stored = {
                row["node_id"]: row
                for row in conn.execute(
                    "SELECT * FROM nodes WHERE workflow_id=?", (workflow_id,)
                ).fetchall()
            }
            if set(stored) != set(nodes):
                raise GovernanceBypassDenied("recovery_topology_mismatch")
            for node_id, predecessors in nodes.items():
                row = stored[node_id]
                expected_input = input_digests.get(
                    node_id,
                    hashlib.sha256(f"{workflow_id}\x00{node_id}".encode()).hexdigest(),
                )
                if hasattr(self, "_apcc_config") and len(expected_input) == 64:
                    try:
                        expected_input = b64u_encode(bytes.fromhex(expected_input))
                    except ValueError:
                        pass
                if (
                    json.loads(row["predecessors"]) != sorted(predecessors)
                    or json.loads(row["required_capabilities"])
                    != sorted(required_capabilities.get(node_id, ()))
                    or row["input_digest"] != expected_input
                ):
                    raise GovernanceBypassDenied("recovery_topology_mismatch")
            self._verify_committed_evidence(conn, workflow_id)
            return {
                node_id: self._effective_node_state(conn, row)
                for node_id, row in stored.items()
            }

    def _verify_committed_evidence(
        self, conn: sqlite3.Connection, workflow_id: str
    ) -> None:
        """Fail closed if any authoritative node lacks intact signed evidence."""
        seal = conn.execute(
            "SELECT * FROM store_seal WHERE singleton=1 AND sealed=1"
        ).fetchone()
        rows = conn.execute(
            """SELECT * FROM nodes WHERE workflow_id=? AND commit_id IS NOT NULL""",
            (workflow_id,),
        ).fetchall()
        apcc_backed = (
            conn.execute(
                """SELECT count(*) FROM sqlite_master
                   WHERE type='table' AND name IN ('metadata','apcc_decisions')"""
            ).fetchone()[0]
            == 2
        )
        for node in rows:
            evidence = conn.execute(
                """SELECT e.*,d.outcome,d.workflow_id,d.node_id
                   FROM receipt_evidence e JOIN decisions d USING(commit_id)
                   WHERE e.commit_id=?""",
                (node["commit_id"],),
            ).fetchone()
            if evidence is None or evidence["outcome"] != CommitOutcome.COMMITTED.value:
                raise GovernanceBypassDenied("recovery_evidence_missing")
            if (
                evidence["workflow_id"] != workflow_id
                or evidence["node_id"] != node["node_id"]
            ):
                raise GovernanceBypassDenied("recovery_evidence_context_mismatch")
            if (
                hashlib.sha256(evidence["receipt_material"].encode()).hexdigest()
                != evidence["receipt_digest"]
            ):
                raise GovernanceBypassDenied("recovery_receipt_digest_mismatch")
            if (
                hashlib.sha256(evidence["verdict_material"].encode()).hexdigest()
                != evidence["verdict_digest"]
            ):
                raise GovernanceBypassDenied("recovery_verdict_digest_mismatch")
            try:
                receipt_body = json.loads(evidence["receipt_material"])
                payload_body = dict(receipt_body["payload"])
                payload_body["predecessor_bindings"] = tuple(
                    PredecessorBinding(**binding)
                    for binding in payload_body["predecessor_bindings"]
                )
                receipt = SignedGovernedReceipt(
                    GovernedReceiptPayload(**payload_body), receipt_body["signature"]
                )
                agent = self._agent(conn, workflow_id, receipt.payload.agent_id)
                Ed25519PublicKey.from_public_bytes(agent["public_key"]).verify(
                    base64.b64decode(receipt.signature, validate=True),
                    receipt.payload.canonical_bytes(),
                )
                verdict_body = json.loads(evidence["verdict_material"])
                verdict_body["decision"] = VerdictDecision(verdict_body["decision"])
                verdict = AuthoritativeVerdict(**verdict_body)
                policy_binding = next(
                    (
                        binding
                        for binding in self._apcc_config.policy_trust
                        if binding.scope
                        == (
                            receipt.payload.verifier_policy_id,
                            receipt.payload.policy_version,
                            str(receipt.payload.policy_epoch),
                        )
                    ),
                    None,
                )
                if policy_binding is None:
                    raise ValueError("untrusted policy binding")
                Ed25519PublicKey.from_public_bytes(policy_binding.public_key).verify(
                    base64.b64decode(verdict.signature, validate=True),
                    verdict.canonical_bytes(),
                )
            except (
                InvalidSignature,
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise GovernanceBypassDenied("recovery_signature_invalid") from exc
            if (
                receipt.payload.commit_id != node["commit_id"]
                or receipt.payload.node_id != node["node_id"]
                or receipt.payload.workflow_id != workflow_id
                or receipt.payload.output_digest != node["result_digest"]
                or evidence["receipt_digest"] != node["receipt_digest"]
                or verdict.receipt_digest != evidence["receipt_digest"]
                or verdict.store_id != seal["store_id"]
                or verdict.verifier_key_id != policy_binding.key_id
                or verdict.verifier_policy_id != receipt.payload.verifier_policy_id
                or verdict.policy_id != receipt.payload.verifier_policy_id
                or verdict.policy_version != receipt.payload.policy_version
                or verdict.policy_epoch != receipt.payload.policy_epoch
                or verdict.decision is not VerdictDecision.ALLOW
            ):
                raise GovernanceBypassDenied("recovery_evidence_binding_mismatch")
            expected_predecessors: list[PredecessorBinding] = []
            for binding in receipt.payload.predecessor_bindings:
                predecessor = self._node(conn, workflow_id, binding.node_id)
                predecessor_evidence = conn.execute(
                    "SELECT receipt_material FROM receipt_evidence WHERE commit_id=?",
                    (binding.commit_id,),
                ).fetchone()
                if predecessor_evidence is None:
                    raise GovernanceBypassDenied(
                        "recovery_predecessor_evidence_mismatch"
                    )
                try:
                    predecessor_payload = json.loads(
                        predecessor_evidence["receipt_material"]
                    )["payload"]
                    committed_predecessor_version = (
                        int(predecessor_payload["expected_node_state_version"]) + 1
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise GovernanceBypassDenied(
                        "recovery_predecessor_evidence_mismatch"
                    ) from exc
                predecessor_receipt_digest = predecessor["receipt_digest"]
                if apcc_backed:
                    logical = conn.execute(
                        """SELECT certificate_digest FROM logical_nodes
                           WHERE workflow_id=? AND node_id=?""",
                        (workflow_id, binding.node_id),
                    ).fetchone()
                    if logical is None or logical["certificate_digest"] is None:
                        raise GovernanceBypassDenied(
                            "recovery_predecessor_evidence_mismatch"
                        )
                    predecessor_receipt_digest = logical["certificate_digest"]
                if (
                    binding.node_id not in json.loads(node["predecessors"])
                    or binding.node_version != committed_predecessor_version
                    or binding.commit_id != predecessor["commit_id"]
                    or binding.receipt_digest != predecessor_receipt_digest
                    or binding.authoritative_result_digest
                    != predecessor["result_digest"]
                ):
                    raise GovernanceBypassDenied(
                        "recovery_predecessor_evidence_mismatch"
                    )
                expected_predecessors.append(binding)
            expected_predecessor_root = predecessor_root(expected_predecessors)
            if apcc_backed:
                expected_predecessor_root = apcc_predecessor_root(
                    _apcc_predecessors(workflow_id, expected_predecessors)
                )
            if (
                len(expected_predecessors) != len(json.loads(node["predecessors"]))
                or expected_predecessor_root != receipt.payload.predecessor_root
            ):
                raise GovernanceBypassDenied("recovery_predecessor_evidence_mismatch")

    def resume_revocation_propagation(self, *, limit: int = 100) -> int:
        """Idempotently materialize fenced root closures."""
        processed = 0
        with self._transaction() as conn:
            events = conn.execute(
                """SELECT * FROM revocation_outbox WHERE processed=0
                   ORDER BY generation,event_id LIMIT ?""",
                (limit,),
            ).fetchall()
            for event in events:
                closure = self._descendant_closure(
                    conn, event["workflow_id"], event["root_node_id"]
                )
                self._inject_fault(_GCBFaultCheckpoint.DURING_REVOCATION_PROPAGATION)
                for node_id in closure:
                    row = self._node(conn, event["workflow_id"], node_id)
                    if node_id == event["root_node_id"]:
                        status = "revoked"
                    elif row["status"] == "governed_committed":
                        status = "superseded"
                    else:
                        status = "blocked"
                    conn.execute(
                        """UPDATE nodes SET status=?,tainted=1,version=version+1
                           WHERE workflow_id=? AND node_id=?""",
                        (status, event["workflow_id"], node_id),
                    )
                conn.execute(
                    "UPDATE revocation_outbox SET processed=1 WHERE event_id=?",
                    (event["event_id"],),
                )
                processed += 1
        return processed

    def _dispatch_revocation_outbox(self, projection: Any, *, limit: int = 100) -> int:
        """Retract projected artifacts after durable revocation materialization."""
        dispatched = 0
        with self._transaction() as conn:
            events = conn.execute(
                """SELECT * FROM revocation_outbox
                   WHERE processed=1 AND dispatched=0 AND workflow_id=?
                   ORDER BY generation,event_id LIMIT ?""",
                (projection.workflow_id, limit),
            ).fetchall()
            for event in events:
                closure = self._descendant_closure(
                    conn, event["workflow_id"], event["root_node_id"]
                )
                rows = conn.execute(
                    f"""SELECT artifact_id FROM nodes WHERE workflow_id=?
                         AND node_id IN ({",".join("?" for _ in closure)})
                         AND artifact_id IS NOT NULL""",
                    (event["workflow_id"], *sorted(closure)),
                ).fetchall()
                for row in rows:
                    projection.revoke(row["artifact_id"])
                conn.execute(
                    "UPDATE revocation_outbox SET dispatched=1 WHERE event_id=?",
                    (event["event_id"],),
                )
                dispatched += 1
        return dispatched

    def pending_revocations(self) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT count(*) FROM revocation_outbox WHERE processed=0 OR dispatched=0"
            ).fetchone()[0]

    def prepare_attempt_authorization(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        nonce: str,
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> AttemptAuthorizationPayload:
        """Build the exact claim context an agent must sign."""
        with self._connect() as conn:
            workflow = self._workflow(conn, workflow_id)
            node = self._node(conn, workflow_id, node_id)
            agent = self._agent(conn, workflow_id, agent_id)
            if node["status"] != "ready":
                raise GovernanceBypassDenied(f"node_not_ready:{node['status']}")
            if agent["revoked"]:
                raise GovernanceBypassDenied("agent_revoked")
            now = int(time.time()) if issued_at is None else issued_at
            return AttemptAuthorizationPayload(
                store_id=self.store_id,
                workflow_id=workflow_id,
                node_id=node_id,
                attempt_id=attempt_id,
                agent_id=agent_id,
                key_id=agent["key_id"],
                expected_node_state_version=node["version"],
                policy_epoch=workflow["policy_epoch"],
                authority_epoch=workflow["authority_epoch"],
                agent_revocation_epoch=agent["revocation_epoch"],
                workflow_revocation_generation=workflow["revocation_generation"],
                workflow_generation=workflow["generation"],
                issued_at=now,
                expires_at=expires_at if expires_at is not None else now + 60,
                nonce=nonce,
            )

    def _validate_attempt_authorization(
        self,
        conn: sqlite3.Connection,
        authorization: SignedAttemptAuthorization | None = None,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        staging: bool,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        if not isinstance(authorization, SignedAttemptAuthorization):
            raise GovernanceBypassDenied("signed_attempt_authorization_required")
        payload = authorization.payload
        workflow = self._workflow(conn, workflow_id)
        node = self._node(conn, workflow_id, node_id)
        agent = self._agent(conn, workflow_id, agent_id)
        expected = {
            "store_id": self.store_id,
            "workflow_id": workflow_id,
            "node_id": node_id,
            "attempt_id": attempt_id,
            "agent_id": agent_id,
            "key_id": agent["key_id"],
            "expected_node_state_version": node["version"] - (1 if staging else 0),
            "policy_epoch": workflow["policy_epoch"],
            "authority_epoch": workflow["authority_epoch"],
            "agent_revocation_epoch": agent["revocation_epoch"],
            "workflow_revocation_generation": workflow["revocation_generation"],
            "workflow_generation": workflow["generation"],
        }
        for name, value in expected.items():
            if getattr(payload, name) != value:
                raise GovernanceBypassDenied(f"stale_or_mismatched_attempt_{name}")
        now = int(time.time())
        if (
            not payload.nonce
            or payload.issued_at > now + 30
            or payload.expires_at < now
            or payload.expires_at <= payload.issued_at
        ):
            raise GovernanceBypassDenied("attempt_authorization_expired_or_invalid")
        try:
            signature = base64.b64decode(authorization.signature, validate=True)
            Ed25519PublicKey.from_public_bytes(agent["public_key"]).verify(
                signature, payload.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            raise GovernanceBypassDenied(
                "invalid_attempt_authorization_signature"
            ) from None
        if agent["revoked"]:
            raise GovernanceBypassDenied("agent_revoked")
        return workflow, node, agent

    def claim(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        authorization: SignedAttemptAuthorization | None = None,
        required_capabilities: Sequence[str] = (),
    ) -> GovernedNodeState:
        with self._transaction() as conn:
            _workflow, node, agent = self._validate_attempt_authorization(
                conn,
                authorization,
                workflow_id=workflow_id,
                node_id=node_id,
                attempt_id=attempt_id,
                agent_id=agent_id,
                staging=False,
            )
            requirements = set(json.loads(node["required_capabilities"])) | set(
                required_capabilities
            )
            if agent["revoked"]:
                raise GovernanceBypassDenied("agent_revoked")
            if requirements and not requirements.issubset(
                set(json.loads(agent["capabilities"]))
            ):
                raise GovernanceBypassDenied("authority_or_capability_denied")
            if node["status"] != "ready":
                raise GovernanceBypassDenied(f"node_not_ready:{node['status']}")
            if node["tainted"] or self._is_revoked_closure(conn, workflow_id, node_id):
                raise GovernanceBypassDenied("node_tainted_by_revocation")
            conn.execute(
                """UPDATE nodes SET status='claimed',version=version+1,attempt_id=?,claimed_by=?
                   WHERE workflow_id=? AND node_id=?""",
                (attempt_id, agent_id, workflow_id, node_id),
            )
            return self._node_state(self._node(conn, workflow_id, node_id))

    def stage_result(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        artifact: Artifact,
        authorization: SignedAttemptAuthorization | None = None,
    ) -> GovernedNodeState:
        with self._transaction() as conn:
            _workflow, node, _agent = self._validate_attempt_authorization(
                conn,
                authorization,
                workflow_id=workflow_id,
                node_id=node_id,
                attempt_id=attempt_id,
                agent_id=artifact.agent_id,
                staging=True,
            )
            if (
                node["status"] != "claimed"
                or node["attempt_id"] != attempt_id
                or node["claimed_by"] != artifact.agent_id
                or artifact.task_id != node_id
                or self._is_revoked_closure(conn, workflow_id, node_id)
            ):
                raise GovernanceBypassDenied("staging_context_mismatch")
            artifact_json = self._artifact_json(artifact)
            output_digest = hashlib.sha256(artifact_json.encode()).hexdigest()
            if hasattr(self, "_apcc_service"):
                output_digest = sha256_digest(artifact_json.encode("utf-8"))
            conn.execute(
                "INSERT INTO staged_artifacts VALUES(?,?,?,?,?,?)",
                (
                    workflow_id,
                    node_id,
                    attempt_id,
                    artifact.artifact_id,
                    artifact_json,
                    output_digest,
                ),
            )
            conn.execute(
                """UPDATE nodes SET status='result_produced',version=version+1,
                   artifact_id=?,result_digest=? WHERE workflow_id=? AND node_id=?""",
                (artifact.artifact_id, output_digest, workflow_id, node_id),
            )
            return self._node_state(self._node(conn, workflow_id, node_id))

    def prepare_receipt_payload(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        commit_id: str,
        nonce: str,
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> GovernedReceiptPayload:
        with self._connect() as conn:
            workflow = self._workflow(conn, workflow_id)
            node = self._node(conn, workflow_id, node_id)
            if node["status"] != "result_produced":
                raise GovernanceBypassDenied("result_not_produced")
            if self._is_revoked_closure(conn, workflow_id, node_id):
                raise GovernanceBypassDenied("node_tainted_by_revocation")
            staged = conn.execute(
                """SELECT * FROM staged_artifacts
                   WHERE workflow_id=? AND node_id=? AND attempt_id=?""",
                (workflow_id, node_id, attempt_id),
            ).fetchone()
            if staged is None:
                raise GovernanceBypassDenied("missing_staged_result")
            agent = self._agent(conn, workflow_id, agent_id)
            bindings = tuple(self._predecessor_bindings(conn, workflow_id, node))
            binding_root = predecessor_root(bindings)
            actor_authority = self._authority_snapshot_digest(agent)
            if hasattr(self, "_apcc_config"):
                producer_binding = next(
                    binding
                    for binding in self._apcc_config.producer_trust
                    if binding.key_id == agent["key_id"]
                )
                actor_authority = producer_binding.scope[1]
                binding_root = apcc_predecessor_root(
                    _apcc_predecessors(workflow_id, bindings)
                )
            issued = int(time.time()) if issued_at is None else issued_at
            if issued_at is None and hasattr(self, "_apcc_store"):
                issued = self._apcc_store._runtime.clock.now_ms() // 1000
            expires = issued + 300 if expires_at is None else expires_at
            expected_node_version = node["version"]
            if hasattr(self, "_apcc_config"):
                logical_node = conn.execute(
                    "SELECT version FROM logical_nodes WHERE workflow_id=? AND node_id=?",
                    (workflow_id, node_id),
                ).fetchone()
                expected_node_version = (
                    int(logical_node["version"]) if logical_node is not None else 0
                )
                try:
                    nonce_bytes = bytes.fromhex(nonce)
                except ValueError as exc:
                    raise GovernanceBypassDenied("invalid_apcc_nonce") from exc
                if len(nonce_bytes) != 16:
                    raise GovernanceBypassDenied("invalid_apcc_nonce")
                nonce = b64u_encode(nonce_bytes)
            return GovernedReceiptPayload(
                GCB_RECEIPT_PROFILE,
                GCB_SIGNATURE_ALGORITHM,
                agent["key_id"],
                issued,
                expires,
                GCB_COMMIT_INTENT,
                workflow["verifier_policy_id"],
                workflow_id,
                node_id,
                attempt_id,
                agent_id,
                node["input_digest"],
                staged["output_digest"],
                bindings,
                binding_root,
                workflow["policy_version"],
                workflow["policy_digest"],
                workflow["policy_epoch"],
                actor_authority,
                workflow["authority_root"],
                workflow["authority_epoch"],
                agent["revocation_epoch"],
                workflow["revocation_generation"],
                workflow["generation"],
                workflow["state_version"],
                expected_node_version,
                nonce,
                commit_id,
            )

    def build_request(
        self, receipt: SignedGovernedReceipt, verdict: AuthoritativeVerdict
    ) -> CommitRequest:
        return CommitRequest(receipt, verdict)

    def _apcc_validation_reason(self, request: CommitRequest) -> str | None:
        request_hash = request.canonical_hash()
        with self._connect() as connection:
            prior = connection.execute(
                "SELECT * FROM decisions WHERE commit_id=?", (request.commit_id,)
            ).fetchone()
            if (
                prior is not None
                and prior["request_hash"] == request_hash
                and prior["outcome"] == CommitOutcome.COMMITTED.value
            ):
                return None
            return self._validate(connection, request)

    def _deny_invalid_apcc_request(
        self, request: CommitRequest
    ) -> CommitDecision | None:
        request_hash = request.canonical_hash()
        payload = request.receipt.payload
        try:
            with self._transaction() as connection:
                prior = connection.execute(
                    "SELECT * FROM decisions WHERE commit_id=?", (request.commit_id,)
                ).fetchone()
                if prior is not None:
                    if prior["request_hash"] == request_hash:
                        if prior["outcome"] == CommitOutcome.COMMITTED.value:
                            return None
                        return self._decision(prior)
                    self._security_event(
                        connection,
                        "commit_collision_attempt",
                        request.commit_id,
                        payload.workflow_id,
                        payload.node_id,
                        json.dumps(
                            {
                                "prior_request_hash": prior["request_hash"],
                                "request": request_hash,
                            },
                            sort_keys=True,
                        ),
                    )
                    return CommitDecision(
                        request.commit_id,
                        CommitOutcome.DENIED,
                        "idempotency_conflict",
                        payload.workflow_id,
                        payload.node_id,
                        prior["state_version"],
                    )
                reason = self._validate(connection, request)
                if reason is None:
                    return None
                workflow = connection.execute(
                    "SELECT state_version FROM workflows WHERE workflow_id=?",
                    (payload.workflow_id,),
                ).fetchone()
                state_version = -1 if workflow is None else workflow[0]
                return self._record(
                    connection,
                    request,
                    request_hash,
                    CommitOutcome.DENIED,
                    reason,
                    state_version,
                )
        except (sqlite3.Error, RuntimeError):
            return CommitDecision(
                request.commit_id,
                CommitOutcome.DENIED,
                "persistence_error",
                payload.workflow_id,
                payload.node_id,
                -1,
            )

    def _to_apcc_request(self, request: CommitRequest) -> AtomicCommitRequest:
        payload = request.receipt.payload
        policy_binding = self._apcc_policy_binding(
            payload.verifier_policy_id,
            payload.policy_version,
            payload.policy_epoch,
        )
        registry_binding = self._apcc_config.registry_trust[0]
        producer = {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.producer-statement",
            "producer_key_id": payload.key_id,
            "workflow_id": payload.workflow_id,
            "node_id": payload.node_id,
            "attempt_id": payload.attempt_id,
            "agent_id": payload.agent_id,
            "actor_authority": payload.authority_snapshot_digest,
            "input_digest": payload.input_digest,
            "output_digest": payload.output_digest,
            "predecessor_root": payload.predecessor_root,
            "expected_node_version": str(payload.expected_node_state_version),
            "commit_id": payload.commit_id,
            "nonce": payload.nonce,
            "issued_at_ms": str(payload.issued_at * 1000),
            "expires_at_ms": str(payload.expires_at * 1000),
        }
        proposal_digest = sha256_digest(canonical_statement(producer))
        policy = {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.policy-statement",
            "policy_key_id": policy_binding.key_id,
            "proposal_digest": proposal_digest,
            "decision": "allow",
            "policy_id": policy_binding.scope[0],
            "policy_version": payload.policy_version,
            "policy_epoch": str(payload.policy_epoch),
            "workflow_id": payload.workflow_id,
            "node_id": payload.node_id,
            "attempt_id": payload.attempt_id,
            "issued_at_ms": str(payload.issued_at * 1000),
            "expires_at_ms": str(payload.expires_at * 1000),
        }
        authority = {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.authority-statement",
            "authority_key_id": registry_binding.key_id,
            "proposal_digest": proposal_digest,
            "agent_id": payload.agent_id,
            "producer_key_id": payload.key_id,
            "actor_authority": payload.authority_snapshot_digest,
            "authority_root": payload.authority_root,
            "authority_epoch": str(payload.authority_epoch),
            "agent_revocation_generation": str(payload.agent_revocation_epoch),
            "workflow_revocation_generation": str(
                payload.workflow_revocation_generation
            ),
            "workflow_epoch": str(payload.workflow_generation),
            "workflow_id": payload.workflow_id,
            "node_id": payload.node_id,
            "attempt_id": payload.attempt_id,
            "issued_at_ms": str(payload.issued_at * 1000),
            "expires_at_ms": str(payload.expires_at * 1000),
        }
        predecessors = _apcc_predecessors(
            payload.workflow_id, payload.predecessor_bindings
        )
        subject = CertificateSubject(
            payload.workflow_id,
            payload.node_id,
            payload.attempt_id,
            payload.agent_id,
            payload.authority_snapshot_digest,
            payload.input_digest,
            payload.output_digest,
        )
        context = CertificateContext(
            policy_binding.scope[0],
            payload.policy_version,
            str(payload.policy_epoch),
            payload.authority_root,
            str(payload.authority_epoch),
            str(payload.agent_revocation_epoch),
            str(payload.workflow_revocation_generation),
            str(payload.workflow_generation),
        )
        evidence = CertificateEvidence(
            producer,
            proposal_digest,
            policy,
            sha256_digest(canonical_statement(policy)),
            authority,
            sha256_digest(canonical_statement(authority)),
        )
        assert self._policy_signer is not None
        assert self._registry_signer is not None
        signatures = CertificateSignatures(
            Signature(
                "Ed25519",
                payload.key_id,
                b64u_encode(base64.b64decode(request.receipt.signature, validate=True)),
            ),
            Signature(
                "Ed25519",
                policy_binding.key_id,
                b64u_encode(
                    self._policy_signer.sign(POLICY_DOMAIN, canonical_statement(policy))
                ),
            ),
            Signature(
                "Ed25519",
                registry_binding.key_id,
                b64u_encode(
                    self._registry_signer.sign(
                        AUTHORITY_DOMAIN, canonical_statement(authority)
                    )
                ),
            ),
        )
        bindings = CertificateBindings(
            str(payload.expected_node_state_version),
            str(payload.expected_node_state_version + 1),
            payload.predecessor_root,
            predecessors,
        )
        receipt_material = _signed_receipt_material(request.receipt)
        verdict_material = json.dumps(
            {
                **request.verdict.unsigned_dict(),
                "signature": request.verdict.signature,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        projection_plan = _GCBProjectionPlan(
            workflow_id=payload.workflow_id,
            node_id=payload.node_id,
            attempt_id=payload.attempt_id,
            agent_id=payload.agent_id,
            commit_id=payload.commit_id,
            nonce=payload.nonce,
            expected_node_version=payload.expected_node_state_version,
            committed_node_version=payload.expected_node_state_version + 1,
            expected_workflow_state_version=payload.state_version,
            policy_digest=payload.policy_digest,
            request_hash=request.canonical_hash(),
            receipt_material=receipt_material,
            receipt_digest=hashlib.sha256(receipt_material.encode()).hexdigest(),
            verdict_material=verdict_material,
            verdict_digest=hashlib.sha256(verdict_material.encode()).hexdigest(),
        )
        return _GCBAtomicCommitRequest(
            subject,
            context,
            evidence,
            bindings,
            signatures,
            payload.commit_id,
            payload.nonce,
            proposal_digest,
            projection_plan,
        )

    def _apcc_policy_binding(
        self,
        policy_id: str,
        policy_version: str,
        policy_epoch: int,
    ) -> Any:
        scope = (policy_id, policy_version, str(policy_epoch))
        binding = next(
            (
                candidate
                for candidate in self._apcc_config.policy_trust
                if candidate.scope == scope
            ),
            None,
        )
        if binding is None or self._policy_signer is None:
            raise GovernanceBypassDenied("untrusted_policy_binding")
        try:
            signer_public_key = self._policy_signer.public_key_bytes(policy_version)
        except TypeError:
            signer_public_key = self._policy_signer.public_key_bytes()
        if bytes(signer_public_key) != binding.public_key:
            raise GovernanceBypassDenied("untrusted_policy_binding")
        return binding

    def _prepare_apcc_candidate(self, request: AtomicCommitRequest) -> None:
        with self._apcc_store._transaction() as connection:
            node = connection.execute(
                "SELECT version FROM logical_nodes WHERE workflow_id=? AND node_id=?",
                (request.subject.workflow_id, request.subject.node_id),
            ).fetchone()
            if node is None:
                connection.execute(
                    "INSERT INTO logical_nodes VALUES (?, ?, ?, NULL)",
                    (
                        request.subject.workflow_id,
                        request.subject.node_id,
                        request.bindings.expected_node_version,
                    ),
                )
            candidate = connection.execute(
                "SELECT lifecycle FROM candidates WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                (
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                ),
            ).fetchone()
            if candidate is None:
                connection.execute(
                    "INSERT INTO candidates VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, NULL)",
                    (
                        request.subject.workflow_id,
                        request.subject.node_id,
                        request.subject.attempt_id,
                        request.subject.agent_id,
                        CandidateLifecycle.EXECUTING.value,
                        request.bindings.expected_node_version,
                        json.dumps(
                            request.subject.to_object(),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            request.context.to_object(),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            [
                                item.to_object()
                                for item in request.bindings.predecessors
                            ],
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        sha256_digest(f"candidate:{request.commit_id}".encode("utf-8")),
                    ),
                )
                lifecycle = CandidateLifecycle.EXECUTING
            else:
                lifecycle = CandidateLifecycle(candidate[0])
        if lifecycle is CandidateLifecycle.COMMIT_PENDING:
            return
        with self._connect() as connection:
            staged = connection.execute(
                "SELECT artifact_json FROM staged_artifacts WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                (
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                ),
            ).fetchone()
        if staged is None:
            raise GovernanceBypassDenied("missing_staged_result")
        self._apcc_service.stage_result(
            StageResultRequest(
                request.subject,
                request.bindings.expected_node_version,
                staged[0].encode("utf-8"),
            )
        )
        self._apcc_service.assemble_evidence(AssembleEvidenceRequest(request))
        self._apcc_service.propose_commit(ProposeCommitRequest(request))

    def commit(self, request: CommitRequest) -> CommitDecision:
        if hasattr(self, "_apcc_service"):
            denial = self._deny_invalid_apcc_request(request)
            if denial is not None:
                return denial
            atomic = self._to_apcc_request(request)
            with self._connect() as connection:
                already_recorded = connection.execute(
                    "SELECT 1 FROM commit_index WHERE commit_id=?",
                    (request.commit_id,),
                ).fetchone()
            if already_recorded is None:
                try:
                    self._prepare_apcc_candidate(atomic)
                except ValueError:
                    # Another connection may have advanced this shared
                    # candidate between any two lifecycle operations.  The
                    # atomic commit transaction is the authority that decides
                    # whether this exact request won or must be denied.
                    pass
            try:
                result = self._apcc_service.commit(atomic)
            except _GCBProjectionDenied as error:
                denial = self._deny_invalid_apcc_request(request)
                if denial is None:
                    raise GovernanceBypassDenied(
                        f"APCC legacy validation race: {error.reason}"
                    ) from None
                return denial
            except _GCBProjectionFault:
                return CommitDecision(
                    request.commit_id,
                    CommitOutcome.DENIED,
                    "persistence_error",
                    request.receipt.payload.workflow_id,
                    request.receipt.payload.node_id,
                    -1,
                )
            else:
                if result.decision.outcome is RequestOutcome.COMMITTED:
                    with self._connect() as connection:
                        row = connection.execute(
                            "SELECT * FROM decisions WHERE commit_id=?",
                            (request.commit_id,),
                        ).fetchone()
                    if row is None:
                        raise GovernanceBypassDenied("legacy_projection_missing")
                    decision = self._decision(row)
                    self._inject_fault(_GCBFaultCheckpoint.AFTER_DURABLE_COMMIT)
                    return decision
                return CommitDecision(
                    request.commit_id,
                    CommitOutcome.DENIED,
                    (
                        "agent_revoked"
                        if result.decision.reason is FailureCode.ACTOR_REVOKED
                        else result.decision.reason
                    ),
                    request.receipt.payload.workflow_id,
                    request.receipt.payload.node_id,
                    -1,
                )
        raise GovernanceBypassDenied("APCC authority service is not attached")

    def _inject_fault(self, checkpoint: _GCBFaultCheckpoint) -> None:
        if self._fault_checkpoint is checkpoint and not self._fault_checkpoint_fired:
            self._fault_checkpoint_fired = True
            raise _GCBInjectedFault(checkpoint.value)

    def _validate(
        self,
        conn: _LegacyTransaction,
        request: CommitRequest,
        *,
        apcc_expected_node_version: int | None = None,
    ) -> str | None:
        payload = request.receipt.payload
        if payload.profile != GCB_RECEIPT_PROFILE:
            return "unknown_receipt_profile"
        if payload.signature_algorithm != GCB_SIGNATURE_ALGORITHM:
            return "unknown_signature_algorithm"
        if payload.intent != GCB_COMMIT_INTENT:
            return "invalid_commit_intent"
        if not all(
            (
                payload.workflow_id,
                payload.node_id,
                payload.attempt_id,
                payload.agent_id,
                payload.key_id,
                payload.verifier_policy_id,
                payload.nonce,
                payload.commit_id,
            )
        ):
            return "missing_receipt_binding"
        try:
            workflow = self._workflow(conn, payload.workflow_id)
            node = self._node(conn, payload.workflow_id, payload.node_id)
            agent = self._agent(conn, payload.workflow_id, payload.agent_id)
        except KeyError:
            return "unknown_context"
        try:
            signature = base64.b64decode(request.receipt.signature, validate=True)
            Ed25519PublicKey.from_public_bytes(agent["public_key"]).verify(
                signature, payload.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            return "invalid_signature"
        expected_actor_authority = self._authority_snapshot_digest(agent)
        expected_node_version = node["version"]
        if hasattr(self, "_apcc_config"):
            producer_binding = next(
                (
                    binding
                    for binding in self._apcc_config.producer_trust
                    if binding.key_id == agent["key_id"]
                ),
                None,
            )
            if producer_binding is None:
                return "authority_or_capability_denied"
            expected_actor_authority = producer_binding.scope[1]
            logical_node = conn.execute(
                "SELECT version FROM logical_nodes WHERE workflow_id=? AND node_id=?",
                (payload.workflow_id, payload.node_id),
            ).fetchone()
            expected_node_version = (
                apcc_expected_node_version
                if apcc_expected_node_version is not None
                else int(logical_node["version"])
                if logical_node is not None
                else 0
            )
            compatibility_version = 2 + bool(json.loads(node["predecessors"]))
            if (
                not node["tainted"]
                and not agent["revoked"]
                and node["version"] != compatibility_version
            ):
                return "stale_or_mismatched_expected_node_state_version"
        expected = {
            "policy_version": workflow["policy_version"],
            "policy_digest": workflow["policy_digest"],
            "policy_epoch": workflow["policy_epoch"],
            "verifier_policy_id": workflow["verifier_policy_id"],
            "authority_snapshot_digest": expected_actor_authority,
            "agent_revocation_epoch": agent["revocation_epoch"],
            "authority_root": workflow["authority_root"],
            "authority_epoch": workflow["authority_epoch"],
            "workflow_revocation_generation": workflow["revocation_generation"],
            "workflow_generation": workflow["generation"],
            "state_version": workflow["state_version"],
            "expected_node_state_version": expected_node_version,
            "input_digest": node["input_digest"],
            "attempt_id": node["attempt_id"],
            "agent_id": node["claimed_by"],
            "key_id": agent["key_id"],
        }
        if (
            hasattr(self, "_apcc_config")
            and payload.state_version < workflow["state_version"]
        ):
            authority_transition = conn.execute(
                """SELECT 1 FROM gcb_control_events
                   WHERE workflow_id=? AND action=? AND outcome=?
                     AND result_value=?
                   LIMIT 1""",
                (
                    payload.workflow_id,
                    ControlAction.REGISTER_AGENT.value,
                    CommitOutcome.COMMITTED.value,
                    workflow["state_version"],
                ),
            ).fetchone()
            if authority_transition is not None:
                return "stale_or_mismatched_authority_epoch"
        for name, expected_value in expected.items():
            if getattr(payload, name) != expected_value:
                return f"stale_or_mismatched_{name}"
        now = int(time.time())
        if hasattr(self, "_apcc_store"):
            now = self._apcc_store._runtime.clock.now_ms() // 1000
        if payload.issued_at > now + 30 or payload.expires_at < now:
            return "receipt_expired_or_not_yet_valid"
        if payload.expires_at <= payload.issued_at:
            return "invalid_receipt_lifetime"
        if node["status"] != "result_produced":
            return "node_not_result_produced"
        if node["tainted"] or self._is_revoked_closure(
            conn, payload.workflow_id, payload.node_id
        ):
            return "node_tainted_by_revocation"
        if agent["revoked"]:
            return "agent_revoked"
        requirements = set(json.loads(node["required_capabilities"]))
        if requirements and not requirements.issubset(
            set(json.loads(agent["capabilities"]))
        ):
            return "authority_or_capability_denied"
        staged = conn.execute(
            """SELECT * FROM staged_artifacts
               WHERE workflow_id=? AND node_id=? AND attempt_id=?""",
            (payload.workflow_id, payload.node_id, payload.attempt_id),
        ).fetchone()
        if staged is None or payload.output_digest != staged["output_digest"]:
            return "output_digest_mismatch"
        try:
            bindings = tuple(
                self._predecessor_bindings(conn, payload.workflow_id, node)
            )
            root = predecessor_root(bindings)
            if hasattr(self, "_apcc_config"):
                root = apcc_predecessor_root(
                    _apcc_predecessors(payload.workflow_id, bindings)
                )
        except GovernanceBypassDenied:
            return "predecessor_not_governed_committed"
        if payload.predecessor_bindings != bindings or payload.predecessor_root != root:
            return "predecessor_binding_mismatch"
        verdict = request.verdict
        if not isinstance(verdict, AuthoritativeVerdict):
            return "invalid_authoritative_verdict"
        receipt_digest = _signed_receipt_digest(request.receipt)
        policy_binding = None
        if hasattr(self, "_apcc_config"):
            policy_binding = next(
                (
                    binding
                    for binding in self._apcc_config.policy_trust
                    if binding.scope
                    == (
                        workflow["verifier_policy_id"],
                        workflow["policy_version"],
                        str(workflow["policy_epoch"]),
                    )
                ),
                None,
            )
            if policy_binding is None:
                return "untrusted_policy_binding"
        verdict_expected = {
            "store_id": self.store_id,
            "verifier_policy_id": workflow["verifier_policy_id"],
            "policy_id": workflow["verifier_policy_id"],
            "policy_version": workflow["policy_version"],
            "verifier_key_id": (
                policy_binding.key_id
                if policy_binding is not None
                else self.verifier_key_id
            ),
            "receipt_digest": receipt_digest,
            "workflow_id": payload.workflow_id,
            "node_id": payload.node_id,
            "attempt_id": payload.attempt_id,
            "agent_id": payload.agent_id,
            "expected_node_state_version": payload.expected_node_state_version,
            "policy_epoch": payload.policy_epoch,
            "authority_epoch": payload.authority_epoch,
            "agent_revocation_epoch": payload.agent_revocation_epoch,
            "workflow_revocation_generation": payload.workflow_revocation_generation,
            "workflow_generation": payload.workflow_generation,
        }
        for name, expected_value in verdict_expected.items():
            if getattr(verdict, name) != expected_value:
                return f"stale_or_mismatched_verdict_{name}"
        if verdict.issued_at > now + 30 or verdict.expires_at < now:
            return "verdict_expired_or_not_yet_valid"
        if verdict.expires_at <= verdict.issued_at:
            return "invalid_verdict_lifetime"
        try:
            verdict_signature = base64.b64decode(verdict.signature, validate=True)
            if policy_binding is not None:
                verifier_public_key = policy_binding.public_key
            else:
                verifier_key = conn.execute(
                    "SELECT verifier_public_key FROM store_seal WHERE singleton=1 AND sealed=1"
                ).fetchone()
                if verifier_key is None:
                    return "invalid_verdict_signature"
                verifier_public_key = verifier_key["verifier_public_key"]
            Ed25519PublicKey.from_public_bytes(verifier_public_key).verify(
                verdict_signature, verdict.canonical_bytes()
            )
        except (InvalidSignature, ValueError, TypeError):
            return "invalid_verdict_signature"
        if verdict.decision is VerdictDecision.DENY:
            return "policy_denied"
        if verdict.decision is VerdictDecision.ESCALATE:
            return "policy_escalated"
        if verdict.decision is not VerdictDecision.ALLOW:
            return "invalid_authoritative_verdict"
        return None

    def _bind_projection(self, workflow_id: str, store: ArtifactStore) -> Any:
        """Create the sole capability-bearing projector for one workflow."""
        with self._connect() as conn:
            self._workflow(conn, workflow_id)
        seal_id = _canonical_digest(
            {"store_id": self.store_id, "workflow_id": workflow_id, "path": self.path}
        )
        return store._bind_governed(
            workflow_id=workflow_id,
            seal_id=seal_id,
            guard=lambda artifact_id: (
                self.authoritative_artifact(workflow_id, artifact_id) is not None
            ),
        )

    def _dispatch_outbox(self, projection: Any, *, limit: int = 100) -> int:
        dispatched = 0
        with self._transaction() as conn:
            rows = conn.execute(
                """SELECT * FROM outbox WHERE dispatched=0 AND workflow_id=?
                   ORDER BY event_id LIMIT ?""",
                (projection.workflow_id, limit),
            ).fetchall()
            for row in rows:
                if not self._apcc_node_is_consumable(
                    conn, row["workflow_id"], row["node_id"]
                ):
                    conn.execute(
                        "UPDATE outbox SET dispatched=1 WHERE event_id=?",
                        (row["event_id"],),
                    )
                    continue
                if self._is_revoked_closure(conn, row["workflow_id"], row["node_id"]):
                    conn.execute(
                        "UPDATE outbox SET dispatched=1 WHERE event_id=?",
                        (row["event_id"],),
                    )
                    dispatched += 1
                    continue
                artifact = self._artifact_from_json(row["artifact_json"])
                existing = projection.get(artifact.artifact_id)
                if existing is None:
                    callbacks = projection.publish(artifact)
                    projection.dispatch(artifact.artifact_id, callbacks)
                elif existing != artifact:
                    raise GovernanceBypassDenied("projection_artifact_conflict")
                else:
                    projection.redispatch(artifact)
                conn.execute(
                    "UPDATE outbox SET dispatched=1 WHERE event_id=?",
                    (row["event_id"],),
                )
                dispatched += 1
        return dispatched

    def workflow_node_states(
        self, workflow_id: str, node_ids: Sequence[str]
    ) -> tuple[GovernedNodeState, ...]:
        """Read ordered legacy/APCC node state from one attested snapshot."""
        resolved_ids = tuple(node_ids)
        if len(resolved_ids) > _MAX_WORKFLOW_NODES:
            raise GovernanceBypassDenied("node_status_batch_too_large")
        if not workflow_id or any(not node_id for node_id in resolved_ids):
            raise ValueError("workflow and node identities cannot be empty")
        if not hasattr(self, "_apcc_store"):
            raise GovernanceBypassDenied("APCC authority is not configured")
        nonces = tuple(b64u_encode(secrets.token_bytes(16)) for _ in resolved_ids)
        if len(set(nonces)) != len(nonces):
            raise GovernanceBypassDenied("authority_status_nonce_collision")
        requests = tuple(
            LogicalNodeStatusRequest(workflow_id, node_id, nonce)
            for node_id, nonce in zip(resolved_ids, nonces, strict=True)
        )
        if not requests:
            return ()
        with self._apcc_store._read_transaction() as connection:
            results = self._apcc_store._logical_node_status_batch_at(
                connection, requests
            )
            connection.row_factory = sqlite3.Row
            if len(results) != len(requests):
                raise GovernanceBypassDenied("authority_status_batch_length_mismatch")
            legacy_rows = connection.execute(
                "SELECT * FROM nodes WHERE workflow_id=?", (workflow_id,)
            ).fetchall()
            if len(legacy_rows) > _MAX_WORKFLOW_NODES:
                raise GovernanceBypassDenied("node_status_batch_too_large")
            revoked_roots = {
                row["root_node_id"]
                for row in connection.execute(
                    "SELECT root_node_id FROM revoked_roots WHERE workflow_id=?",
                    (workflow_id,),
                ).fetchall()
            }
            legacy_states = self._effective_node_states(legacy_rows, revoked_roots)
            states: list[GovernedNodeState] = []
            for request, result in zip(requests, results, strict=True):
                if result.request != request:
                    raise GovernanceBypassDenied(
                        "authority_status_batch_order_mismatch"
                    )
                try:
                    state = legacy_states[request.node_id]
                except KeyError:
                    raise KeyError(request.node_id) from None
                logical = result.logical_node
                if logical.current_certificate_digest is None:
                    if (
                        state.status == "governed_committed"
                        or state.commit_id is not None
                    ):
                        raise GovernanceBypassDenied("canonical_certificate_missing")
                    states.append(state)
                    continue
                if result.status is None or result.commit_id is None:
                    raise GovernanceBypassDenied("canonical_certificate_missing")
                if state.commit_id not in (None, result.commit_id):
                    raise GovernanceBypassDenied(
                        "canonical_certificate_identity_mismatch"
                    )
                if result.status.status is not AuthorityStatusValue.CURRENT:
                    states.append(
                        state
                        if state.status != "governed_committed"
                        else replace(state, status="revoked")
                    )
                    continue
                states.append(
                    replace(
                        state,
                        status="governed_committed",
                        version=int(logical.current_node_version),
                        commit_id=result.commit_id,
                    )
                )
            return tuple(states)

    def node_state(self, workflow_id: str, node_id: str) -> GovernedNodeState:
        return self.workflow_node_states(workflow_id, (node_id,))[0]

    def current_status(self, certificate_digest: str, request_nonce: str) -> Any:
        if not hasattr(self, "_apcc_store"):
            raise GovernanceBypassDenied("APCC authority is not configured")
        return self._apcc_store.current_status(certificate_digest, request_nonce)

    def authoritative_artifact(
        self, workflow_id: str, artifact_id: str
    ) -> Artifact | None:
        """Read an artifact only while its governed commit remains consumable."""
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM nodes WHERE workflow_id=? AND artifact_id=?""",
                (workflow_id, artifact_id),
            ).fetchone()
            if (
                row is None
                or row["status"] != "governed_committed"
                or row["tainted"]
                or self._is_revoked_closure(conn, workflow_id, row["node_id"])
                or not self._apcc_node_is_consumable(conn, workflow_id, row["node_id"])
            ):
                return None
            staged = conn.execute(
                """SELECT artifact_json FROM staged_artifacts
                   WHERE workflow_id=? AND node_id=? AND artifact_id=?""",
                (workflow_id, row["node_id"], artifact_id),
            ).fetchone()
            return None if staged is None else self._artifact_from_json(staged[0])

    def _apcc_node_is_consumable(
        self,
        conn: sqlite3.Connection,
        workflow_id: str,
        node_id: str,
    ) -> bool:
        if not hasattr(self, "_apcc_store"):
            return True
        logical = conn.execute(
            """SELECT certificate_digest FROM logical_nodes
               WHERE workflow_id=? AND node_id=?""",
            (workflow_id, node_id),
        ).fetchone()
        if logical is None or logical["certificate_digest"] is None:
            return False
        try:
            status = self._apcc_store.current_status(
                logical["certificate_digest"],
                b64u_encode(secrets.token_bytes(16)),
            )
        except (RuntimeError, ValueError):
            return False
        return status.status is AuthorityStatusValue.CURRENT

    def pending_outbox(self) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT count(*) FROM outbox WHERE dispatched=0"
            ).fetchone()[0]

    @staticmethod
    def _workflow(conn: _LegacyTransaction, workflow_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM workflows WHERE workflow_id=?", (workflow_id,)
        ).fetchone()
        if row is None:
            raise KeyError(workflow_id)
        return row

    @staticmethod
    def _agent(
        conn: _LegacyTransaction, workflow_id: str, agent_id: str
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM agents WHERE workflow_id=? AND agent_id=?",
            (workflow_id, agent_id),
        ).fetchone()
        if row is None:
            raise KeyError(agent_id)
        return row

    @staticmethod
    def _node(conn: _LegacyTransaction, workflow_id: str, node_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM nodes WHERE workflow_id=? AND node_id=?",
            (workflow_id, node_id),
        ).fetchone()
        if row is None:
            raise KeyError(node_id)
        return row

    @staticmethod
    def _node_state(row: sqlite3.Row) -> GovernedNodeState:
        return GovernedNodeState(
            row["workflow_id"],
            row["node_id"],
            row["status"],
            row["version"],
            row["attempt_id"],
            row["claimed_by"],
            row["artifact_id"],
            row["commit_id"],
        )

    def _effective_node_state(
        self, conn: sqlite3.Connection, row: sqlite3.Row
    ) -> GovernedNodeState:
        state = self._node_state(row)
        workflow_id = row["workflow_id"]
        node_id = row["node_id"]
        if not self._is_revoked_closure(conn, workflow_id, node_id):
            return state
        roots = {
            root["root_node_id"]
            for root in conn.execute(
                "SELECT root_node_id FROM revoked_roots WHERE workflow_id=?",
                (workflow_id,),
            ).fetchall()
        }
        if node_id in roots:
            status = "revoked"
        elif row["status"] in {"revoked", "superseded", "blocked"}:
            status = row["status"]
        elif row["status"] == "governed_committed":
            status = "superseded"
        else:
            status = "blocked"
        return replace(state, status=status)

    @classmethod
    def _effective_node_states(
        cls,
        rows: Sequence[sqlite3.Row],
        revoked_roots: set[str],
    ) -> dict[str, GovernedNodeState]:
        """Compute one workflow's revocation closure without per-node SQL."""
        row_by_id = {str(row["node_id"]): row for row in rows}
        children: dict[str, list[str]] = {}
        for node_id, row in row_by_id.items():
            for predecessor in json.loads(row["predecessors"]):
                children.setdefault(str(predecessor), []).append(node_id)
        revoked_nodes: set[str] = set()
        pending = list(revoked_roots)
        while pending:
            node_id = pending.pop()
            if node_id in revoked_nodes:
                continue
            revoked_nodes.add(node_id)
            pending.extend(children.get(node_id, ()))
        states: dict[str, GovernedNodeState] = {}
        for node_id, row in row_by_id.items():
            state = cls._node_state(row)
            if node_id not in revoked_nodes:
                states[node_id] = state
                continue
            if node_id in revoked_roots:
                status = "revoked"
            elif row["status"] in {"revoked", "superseded", "blocked"}:
                status = row["status"]
            elif row["status"] == "governed_committed":
                status = "superseded"
            else:
                status = "blocked"
            states[node_id] = replace(state, status=status)
        return states

    @staticmethod
    def _decision(row: sqlite3.Row) -> CommitDecision:
        return CommitDecision(
            row["commit_id"],
            CommitOutcome(row["outcome"]),
            row["reason"],
            row["workflow_id"],
            row["node_id"],
            row["state_version"],
        )

    def _record(
        self,
        conn: sqlite3.Connection,
        request: CommitRequest,
        request_hash: str,
        outcome: CommitOutcome,
        reason: str,
        state_version: int,
    ) -> CommitDecision:
        payload = request.receipt.payload
        conn.execute(
            "INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?)",
            (
                request.commit_id,
                request_hash,
                outcome.value,
                reason,
                payload.workflow_id,
                payload.node_id,
                state_version,
                payload.nonce,
            ),
        )
        receipt_material = _signed_receipt_material(request.receipt)
        verdict = request.verdict
        if isinstance(verdict, AuthoritativeVerdict):
            verdict_material = json.dumps(
                {**verdict.unsigned_dict(), "signature": verdict.signature},
                sort_keys=True,
                separators=(",", ":"),
            )
        else:
            verdict_material = json.dumps(
                {"invalid_verdict_type": type(verdict).__name__}, sort_keys=True
            )
        conn.execute(
            """INSERT INTO receipt_evidence(
                 commit_id,receipt_material,receipt_digest,
                 verdict_material,verdict_digest) VALUES(?,?,?,?,?)""",
            (
                request.commit_id,
                receipt_material,
                _signed_receipt_digest(request.receipt),
                verdict_material,
                hashlib.sha256(verdict_material.encode()).hexdigest(),
            ),
        )
        if outcome is CommitOutcome.DENIED:
            self._security_event(
                conn,
                "commit_denied",
                request.commit_id,
                payload.workflow_id,
                payload.node_id,
                json.dumps(
                    {"reason": reason, "request_hash": request_hash}, sort_keys=True
                ),
            )
        return CommitDecision(
            request.commit_id,
            outcome,
            reason,
            payload.workflow_id,
            payload.node_id,
            state_version,
        )

    def _predecessor_bindings(
        self, conn: _LegacyTransaction, workflow_id: str, node: sqlite3.Row
    ) -> list[PredecessorBinding]:
        bindings: list[PredecessorBinding] = []
        for predecessor in json.loads(node["predecessors"]):
            row = self._node(conn, workflow_id, predecessor)
            if (
                row["status"] != "governed_committed"
                or row["tainted"]
                or not row["commit_id"]
                or not row["receipt_digest"]
                or not row["result_digest"]
            ):
                raise GovernanceBypassDenied("predecessor_not_governed_committed")
            node_version = row["version"]
            receipt_digest = row["receipt_digest"]
            if hasattr(self, "_apcc_config"):
                logical = conn.execute(
                    """SELECT version,certificate_digest FROM logical_nodes
                       WHERE workflow_id=? AND node_id=?""",
                    (workflow_id, predecessor),
                ).fetchone()
                if logical is None or logical["certificate_digest"] is None:
                    raise GovernanceBypassDenied("predecessor_not_governed_committed")
                node_version = int(logical["version"])
                receipt_digest = logical["certificate_digest"]
            bindings.append(
                PredecessorBinding(
                    predecessor,
                    node_version,
                    row["commit_id"],
                    receipt_digest,
                    row["result_digest"],
                )
            )
        return sorted(bindings)

    @staticmethod
    def _authority_snapshot_digest(agent: sqlite3.Row) -> str:
        return _canonical_digest(
            {
                "agent_id": agent["agent_id"],
                "key_id": agent["key_id"],
                "capabilities": json.loads(agent["capabilities"]),
                "authority_epoch": agent["authority_epoch"],
                "revocation_epoch": agent["revocation_epoch"],
                "revoked": bool(agent["revoked"]),
            }
        )

    @staticmethod
    def _authority_root(conn: sqlite3.Connection, workflow_id: str) -> str:
        entries = []
        for agent in conn.execute(
            """SELECT agent_id,key_id,capabilities,authority_epoch,revocation_epoch,revoked
               FROM agents WHERE workflow_id=? ORDER BY agent_id""",
            (workflow_id,),
        ).fetchall():
            entries.append(
                {
                    "agent_id": agent["agent_id"],
                    "key_id": agent["key_id"],
                    "capabilities": json.loads(agent["capabilities"]),
                    "authority_epoch": agent["authority_epoch"],
                    "revocation_epoch": agent["revocation_epoch"],
                    "revoked": bool(agent["revoked"]),
                }
            )
        return _canonical_digest(entries)

    def _unlock_children(
        self, conn: _LegacyTransaction, workflow_id: str, committed_node_id: str
    ) -> None:
        rows = conn.execute(
            "SELECT * FROM nodes WHERE workflow_id=? AND status='blocked'",
            (workflow_id,),
        ).fetchall()
        for row in rows:
            predecessors = json.loads(row["predecessors"])
            if committed_node_id not in predecessors:
                continue
            if self._is_revoked_closure(conn, workflow_id, row["node_id"]):
                continue
            placeholders = ",".join("?" for _ in predecessors)
            states = conn.execute(
                f"SELECT status,commit_id FROM nodes WHERE workflow_id=? AND node_id IN ({placeholders})",
                (workflow_id, *predecessors),
            ).fetchall()
            if len(states) == len(predecessors) and all(
                state["status"] == "governed_committed" and state["commit_id"]
                for state in states
            ):
                conn.execute(
                    "UPDATE nodes SET status='ready',version=version+1 WHERE workflow_id=? AND node_id=?",
                    (workflow_id, row["node_id"]),
                )

    def _taint_descendants(
        self, conn: sqlite3.Connection, workflow_id: str, agent_id: str
    ) -> None:
        tainted = {
            row["node_id"]
            for row in conn.execute(
                """SELECT node_id FROM nodes
                   WHERE workflow_id=? AND claimed_by=?
                     AND status!='governed_committed'""",
                (workflow_id, agent_id),
            ).fetchall()
        }
        changed = True
        while changed:
            changed = False
            for row in conn.execute(
                "SELECT node_id,predecessors FROM nodes WHERE workflow_id=?",
                (workflow_id,),
            ).fetchall():
                if row["node_id"] not in tainted and tainted.intersection(
                    json.loads(row["predecessors"])
                ):
                    tainted.add(row["node_id"])
                    changed = True
        for node_id in tainted:
            conn.execute(
                """UPDATE nodes SET tainted=1,
                   status=CASE WHEN status='governed_committed' THEN status ELSE 'revoked' END,
                   version=version+1 WHERE workflow_id=? AND node_id=?""",
                (workflow_id, node_id),
            )

    def _descendant_closure(
        self, conn: sqlite3.Connection, workflow_id: str, root_node_id: str
    ) -> set[str]:
        closure = {root_node_id}
        rows = conn.execute(
            "SELECT node_id,predecessors FROM nodes WHERE workflow_id=?",
            (workflow_id,),
        ).fetchall()
        changed = True
        while changed:
            changed = False
            for row in rows:
                if row["node_id"] not in closure and closure.intersection(
                    json.loads(row["predecessors"])
                ):
                    closure.add(row["node_id"])
                    changed = True
        return closure

    def _is_revoked_closure(
        self, conn: _LegacyTransaction, workflow_id: str, node_id: str
    ) -> bool:
        roots = {
            row["root_node_id"]
            for row in conn.execute(
                "SELECT root_node_id FROM revoked_roots WHERE workflow_id=?",
                (workflow_id,),
            ).fetchall()
        }
        if not roots:
            return False
        ancestors = {node_id}
        pending = [node_id]
        while pending:
            current = pending.pop()
            row = self._node(conn, workflow_id, current)
            for predecessor in json.loads(row["predecessors"]):
                if predecessor not in ancestors:
                    ancestors.add(predecessor)
                    pending.append(predecessor)
        return bool(ancestors.intersection(roots))


class TrustedGovernanceBootstrap:
    """One-time trusted provisioning and signed test/admin client surface.

    This type intentionally is not re-exported from the package root. Runtime
    agents receive only ``GovernedCommitBoundary``.  Production deployments can
    keep the signing methods in a separate privileged process; the local helper
    exists so tests and the single-host benchmark exercise the same signatures.
    """

    def __init__(
        self,
        *,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        policy_signer: Any,
        registry_signer: Any,
        control_signer: Any,
    ) -> None:
        self.config = config
        self.runtime = runtime
        self._policy_signer = policy_signer
        self._registry_signer = registry_signer
        self._control_signer = control_signer
        self.policy_id = config.policy_trust[0].scope[0]
        self.store_id = config.authority_store_id
        self.verifier_key_id = config.policy_trust[0].key_id
        self.admin_key_id = hashlib.sha256(
            bytes(control_signer.public_key_bytes())
        ).hexdigest()[:32]
        self.default_verdict = VerdictDecision.ALLOW

    @staticmethod
    def _key_id(public_key: Ed25519PublicKey) -> str:
        return hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest()[:32]

    def provision(
        self,
        path: str | Path,
    ) -> TrustedGovernanceAdmin:
        return self._provision(path, projection_fault=None)

    def _provision_with_projection_fault(
        self, path: str | Path, *, checkpoint: _GCBProjectionCheckpoint
    ) -> TrustedGovernanceAdmin:
        return self._provision(path, projection_fault=checkpoint)

    def _provision(
        self,
        path: str | Path,
        *,
        projection_fault: _GCBProjectionCheckpoint | None,
    ) -> TrustedGovernanceAdmin:
        resolved = Path(path)
        if resolved.exists() and resolved.stat().st_size > 0:
            raise GovernanceBypassDenied("authority_store_already_exists")
        SQLiteAuthorityStore.provision(resolved, self.config, (), runtime=self.runtime)
        verifier_public = Ed25519PublicKey.from_public_bytes(
            bytes(self._policy_signer.public_key_bytes())
        )
        admin_public = Ed25519PublicKey.from_public_bytes(
            bytes(self._control_signer.public_key_bytes())
        )
        port = self._open_attached_port(
            resolved,
            provision=True,
            verifier_public_key=verifier_public,
            admin_public_key=admin_public,
            projection_fault=projection_fault,
        )
        return TrustedGovernanceAdmin(self, port)

    def open_admin(
        self,
        path: str | Path,
    ) -> TrustedGovernanceAdmin:
        port = self._open_attached_port(path, provision=False)
        if port.store_id != self.store_id:
            raise GovernanceBypassDenied("bootstrap_store_identity_mismatch")
        return TrustedGovernanceAdmin(self, port)

    def _open_attached_port(
        self,
        path: str | Path,
        *,
        provision: bool,
        verifier_public_key: Ed25519PublicKey | None = None,
        admin_public_key: Ed25519PublicKey | None = None,
        projection_fault: _GCBProjectionCheckpoint | None = None,
    ) -> GovernedCommitBoundary:
        """Atomically construct a GCB port with its typed APCC authority."""
        port = object.__new__(GovernedCommitBoundary)
        port.path = str(path)
        if port.path == ":memory:":
            raise ValueError("GCB authority requires a durable SQLite file")
        port._fault_checkpoint = None
        port._fault_checkpoint_fired = False
        port._busy_timeout_ms = 5_000
        port._apcc_config = self.config
        port._policy_signer = self._policy_signer
        port._registry_signer = self._registry_signer
        Path(port.path).parent.mkdir(parents=True, exist_ok=True)
        port._initialize(
            provision=provision,
            store_id=self.store_id,
            verifier_policy_id=self.policy_id,
            verifier_public_key=verifier_public_key,
            verifier_key_id=self.verifier_key_id,
            admin_public_key=admin_public_key,
            admin_key_id=self.admin_key_id,
            allow_apcc_peer=True,
        )
        store = SQLiteAuthorityStore._open_gcb(
            Path(port.path),
            self.config,
            self.runtime,
            projection_fault=projection_fault,
        )
        port._apcc_store = store
        port._apcc_service = APCCCommitService(
            store=store, config=self.config, runtime=self.runtime
        )
        return port

    def verdict_for(
        self,
        receipt: SignedGovernedReceipt,
        *,
        decision: VerdictDecision = VerdictDecision.ALLOW,
        reason: str = "verified",
        lifetime_seconds: int = 60,
    ) -> AuthoritativeVerdict:
        payload = receipt.payload
        now = self.runtime.clock.now_ms() // 1000
        binding = next(
            (
                candidate
                for candidate in self.config.policy_trust
                if candidate.scope
                == (
                    payload.verifier_policy_id,
                    payload.policy_version,
                    str(payload.policy_epoch),
                )
            ),
            None,
        )
        if binding is None:
            # Preserve a signed denial path for malformed receipts. Validation
            # rejects their stale context before considering this verdict.
            binding = self.config.policy_trust[0]
        unsigned = AuthoritativeVerdict(
            decision=decision,
            store_id=self.store_id,
            verifier_policy_id=payload.verifier_policy_id,
            policy_id=binding.scope[0],
            policy_version=binding.scope[1],
            verifier_key_id=binding.key_id,
            receipt_digest=_signed_receipt_digest(receipt),
            workflow_id=payload.workflow_id,
            node_id=payload.node_id,
            attempt_id=payload.attempt_id,
            agent_id=payload.agent_id,
            expected_node_state_version=payload.expected_node_state_version,
            policy_epoch=int(binding.scope[2]),
            authority_epoch=payload.authority_epoch,
            agent_revocation_epoch=payload.agent_revocation_epoch,
            workflow_revocation_generation=payload.workflow_revocation_generation,
            workflow_generation=payload.workflow_generation,
            issued_at=now,
            expires_at=now + lifetime_seconds,
            reason=reason,
            signature="",
        )
        return _sign_authoritative_verdict(unsigned, self._policy_signer, detached=True)

    @staticmethod
    def sign_agent_receipt(
        payload: GovernedReceiptPayload, private_key: Ed25519PrivateKey
    ) -> SignedGovernedReceipt:
        return sign_governed_receipt(payload, private_key)


class TrustedGovernanceAdmin:
    """Privileged signed control client; never hand this object to an agent."""

    def __init__(
        self, bootstrap: TrustedGovernanceBootstrap, port: GovernedCommitBoundary
    ) -> None:
        self._bootstrap = bootstrap
        self.commit_port = port
        self._commands: dict[str, ControlCommand] = {}

    def __getattr__(self, name: str) -> Any:
        """Forward runtime-only operations for trusted local harnesses."""
        return getattr(self.commit_port, name)

    def build_request(
        self,
        receipt: SignedGovernedReceipt,
        verdict: AuthoritativeVerdict | None = None,
    ) -> CommitRequest:
        resolved = verdict or self._bootstrap.verdict_for(
            receipt, decision=self._bootstrap.default_verdict
        )
        return self.commit_port.build_request(receipt, resolved)

    def bind_projection(self, workflow_id: str, store: ArtifactStore) -> Any:
        return self.commit_port._bind_projection(workflow_id, store)

    def dispatch_outbox(self, projection: Any, *, limit: int = 100) -> int:
        return self.commit_port._dispatch_outbox(projection, limit=limit)

    def dispatch_revocation_outbox(self, projection: Any, *, limit: int = 100) -> int:
        return self.commit_port._dispatch_revocation_outbox(projection, limit=limit)

    def _command(
        self,
        action: ControlAction,
        workflow_id: str,
        parameters: Mapping[str, Any],
        *,
        command_id: str | None = None,
        expected_control_version: int | None = None,
    ) -> ControlDecision:
        resolved_command_id = (
            command_id
            or hashlib.sha256(
                f"{time.time_ns()}:{action.value}:{workflow_id}".encode()
            ).hexdigest()
        )
        command = self._commands.get(resolved_command_id)
        if command is None:
            now = int(time.time())
            unsigned = ControlCommand(
                store_id=self.commit_port.store_id,
                command_id=resolved_command_id,
                action=action,
                workflow_id=workflow_id,
                expected_control_version=(
                    self.commit_port.control_version()
                    if expected_control_version is None
                    else expected_control_version
                ),
                issued_at=now,
                expires_at=now + 60,
                parameters=dict(parameters),
                admin_key_id=self._bootstrap.admin_key_id,
                signature="",
            )
            signature = self._bootstrap._control_signer.sign(
                _CONTROL_SIGNER_DOMAIN, unsigned.canonical_body()
            )
            command = replace(
                unsigned, signature=base64.b64encode(signature).decode("ascii")
            )
            self._commands[resolved_command_id] = command
        decision = self.commit_port.apply_control_command(command)
        if decision.outcome is not CommitOutcome.COMMITTED:
            raise GovernanceBypassDenied(decision.reason)
        return decision

    def create_workflow(
        self,
        *,
        workflow_id: str,
        nodes: Mapping[str, Sequence[str]],
        policy_version: str,
        required_capabilities: Mapping[str, Sequence[str]] | None = None,
        input_digests: Mapping[str, str] | None = None,
        generation: int = 1,
        policy_digest: str | None = None,
        verifier_policy_id: str | None = None,
    ) -> None:
        self._command(
            ControlAction.CREATE_WORKFLOW,
            workflow_id,
            {
                "nodes": {key: list(value) for key, value in nodes.items()},
                "policy_version": policy_version,
                "required_capabilities": {
                    key: list(value)
                    for key, value in (required_capabilities or {}).items()
                },
                "input_digests": dict(input_digests or {}),
                "generation": generation,
                "policy_digest": policy_digest,
                "verifier_policy_id": verifier_policy_id or self._bootstrap.policy_id,
            },
        )

    def register_agent(
        self,
        *,
        workflow_id: str,
        agent_id: str,
        public_key: Ed25519PublicKey,
        capabilities: Sequence[str],
        key_id: str | None = None,
    ) -> None:
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._command(
            ControlAction.REGISTER_AGENT,
            workflow_id,
            {
                "agent_id": agent_id,
                "public_key": base64.b64encode(raw).decode("ascii"),
                "capabilities": list(capabilities),
                "key_id": key_id,
            },
        )

    def update_policy(
        self,
        *,
        workflow_id: str,
        policy_version: str,
        policy_digest: str | None = None,
    ) -> int:
        return int(
            self._command(
                ControlAction.UPDATE_POLICY,
                workflow_id,
                {"policy_version": policy_version, "policy_digest": policy_digest},
            ).result
            or 0
        )

    def revoke_agent(self, *, workflow_id: str, agent_id: str) -> int:
        return int(
            self._command(
                ControlAction.REVOKE_AGENT, workflow_id, {"agent_id": agent_id}
            ).result
            or 0
        )

    def revoke_root(
        self,
        *,
        workflow_id: str,
        node_id: str,
        event_id: str,
        reason: str,
    ) -> int:
        return int(
            self._command(
                ControlAction.REVOKE_ROOT,
                workflow_id,
                {"node_id": node_id, "event_id": event_id, "reason": reason},
                command_id=event_id,
            ).result
            or 0
        )

    def bump_workflow_generation(self, *, workflow_id: str) -> int:
        return int(
            self._command(
                ControlAction.BUMP_WORKFLOW_GENERATION, workflow_id, {}
            ).result
            or 0
        )

    def fence_node_for_review(self, *, workflow_id: str, node_id: str) -> None:
        self._command(
            ControlAction.FENCE_NODE_FOR_REVIEW, workflow_id, {"node_id": node_id}
        )
