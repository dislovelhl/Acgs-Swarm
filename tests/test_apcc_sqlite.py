"""Real SQLite APCC authority-store contract (intentionally RED initially)."""

from __future__ import annotations

import base64
import copy
import inspect
import json
import multiprocessing
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Protocol, cast, get_type_hints

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import constitutional_swarm.governed_commit as governed_commit_module
import constitutional_swarm.swarm as swarm_module
import constitutional_swarm.apcc.sqlite_store as sqlite_store_module
import constitutional_swarm.authority_service as authority_service_module
from constitutional_swarm.apcc.codec import (
    decode_certificate,
    encode_certificate,
)
from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    CandidateLifecycle,
    CandidateState,
    CommitCertificate,
    FailureCode,
    LogicalNodeState,
    RequestOutcome,
    Signature,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AtomicCommitRequest,
    AuthorityRuntime,
    AuthoritySigningRole,
    AuthorityStore,
    CommitResult,
    CommitContextRequest,
    CommitContext,
    OutboxRecoveryRequest,
    OutboxRecoveryResult,
    PersistedOutboxEvent,
    ProposeCommitRequest,
    RecoveryRequest,
    ReplayCommitRequest,
    RevocationRequest,
    RevocationScope,
    StageResultRequest,
    StatusFreshnessPolicy,
    SupersessionCommitted,
    SupersessionConflicted,
    SupersessionRequest,
)
from constitutional_swarm.apcc.service import APCCCommitService
from constitutional_swarm.apcc.sqlite_store import (
    SQLiteAuthorityReader,
    SQLiteAuthorityStore,
    _GCBAtomicCommitRequest,
    _GCBProjectionCheckpoint,
    _GCBProjectionPlan,
)
from constitutional_swarm.apcc.verifier import (
    ScopedTrust,
    TrustBinding,
    TrustRole,
    verify_current,
)
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitDecision as GovernedCommitDecision,
    CommitRequest as GovernedCommitRequest,
    SignedGovernedReceipt,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode
from tests.apcc_conformance import (
    AuthoritySnapshot,
    AuthorityStoreHarness,
    FaultProbe,
    _FailController,
    _InjectedFault,
    assert_authority_store_conforms,
    assert_authority_store_extended_conforms,
    assert_canonical_request_digest_recomputation_conforms,
    assert_certificate_revocation_terminality_conforms,
    assert_commit_signer_is_authority_only_conforms,
    assert_complete_request_identity_is_guarded_conforms,
    assert_default_causal_limits_are_enforced_conforms,
    assert_equal_revocation_generation_is_not_retroactive_conforms,
    assert_fault_is_atomic,
    assert_final_certificate_is_the_validated_certificate_conforms,
    assert_invalid_final_commit_signature_is_atomic_conforms,
    assert_lifecycle_outcome_orthogonality_conforms,
    assert_negative_decisions_reserve_nonce_conforms,
    assert_ordinary_commit_requires_empty_pointer_conforms,
    assert_pending_proposal_identity_is_exact_conforms,
    assert_predecessor_reference_field_conforms,
    assert_repeated_single_event_outbox_recovery_conforms,
    assert_repeated_supersession_chain_conforms,
    assert_request_digest_cache_is_not_authority_bearing_conforms,
    assert_reachable_adjacency_cycle_fails_closed_conforms,
    assert_reachable_adjacency_matches_signed_bindings_conforms,
    assert_reachable_ancestor_integrity_conforms,
    assert_revoked_current_certificate_cannot_be_superseded_conforms,
    assert_root_revocation_generation_is_current_conforms,
    assert_revocation_generation_monotonicity_conforms,
    assert_stage_after_commit_pending_cannot_regress_conforms,
    assert_staged_result_digest_binding_conforms,
    assert_supersession_replay_identity_conforms,
    assert_supersession_fault_is_atomic,
    assert_transitive_ancestor_revocation_admission_conforms,
)
from tests.gcb_apcc_support import (
    InProcessExecutionClientHarness,
    TrustedAuthorityLifecycleHarness,
    compose_test_executor,
    provision_executor_workflow,
)
from tests.test_apcc_verifier import (
    DOMAINS,
    SEEDS,
    _b64u,
    _canonical,
    _digest,
    _signature,
    valid_vector,
)


def _nonce(byte: int) -> str:
    return base64.urlsafe_b64encode(bytes([byte]) * 16).rstrip(b"=").decode("ascii")


def _canonical_authority_request_digest(request: AtomicCommitRequest) -> str:
    body = {
        "subject": request.subject.to_object(),
        "context": request.context.to_object(),
        "evidence": request.evidence.to_object(),
        "bindings": request.bindings.to_object(),
        "signatures": request.signatures.to_object(),
        "commit_id": request.commit_id,
        "nonce": request.nonce,
    }
    return sha256_digest(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


_CONTROL_SEED = bytes(range(160, 192))
_BINDING_MUTATIONS = tuple(
    (role, field_name)
    for role in TrustRole
    for field_name in (
        ("key_id", "public_key", "scope")
        if role in (TrustRole.PRODUCER, TrustRole.POLICY, TrustRole.REGISTRY)
        else ("key_id", "public_key")
    )
)


class _GCBNodeState(Protocol):
    commit_id: str | None


class _GCBCommitPort(Protocol):
    path: str | Path
    _apcc_store: SQLiteAuthorityStore

    def commit(self, request: GovernedCommitRequest) -> GovernedCommitDecision: ...

    def _to_apcc_request(
        self, request: GovernedCommitRequest
    ) -> AtomicCommitRequest: ...

    def _prepare_apcc_candidate(self, request: AtomicCommitRequest) -> None: ...

    def current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus: ...


class _GCBAdmin(Protocol):
    commit_port: _GCBCommitPort

    def register_agent(
        self,
        *,
        workflow_id: str,
        agent_id: str,
        public_key: Ed25519PublicKey,
        capabilities: tuple[str, ...],
    ) -> object: ...

    def build_request(
        self, receipt: SignedGovernedReceipt
    ) -> GovernedCommitRequest: ...

    def commit(self, request: GovernedCommitRequest) -> GovernedCommitDecision: ...

    def node_state(self, workflow_id: str, node_id: str) -> _GCBNodeState: ...


class _GCBBootstrap(Protocol):
    def provision(self, path: Path) -> _GCBAdmin: ...

    def open_admin(self, path: Path) -> _GCBAdmin: ...

    def _provision_with_projection_fault(
        self, path: Path, *, checkpoint: _GCBProjectionCheckpoint
    ) -> _GCBAdmin: ...


class _GCBBootstrapFactory(Protocol):
    def __call__(
        self,
        *,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        policy_signer: _DetachedSigner,
        registry_signer: _DetachedSigner,
        control_signer: _DetachedSigner,
    ) -> _GCBBootstrap: ...


class _SwarmExecutorFactory(Protocol):
    def __call__(
        self,
        registry: CapabilityRegistry,
        artifact_store: ArtifactStore,
        commit_boundary: _GCBAdmin,
        *,
        policy_version: str,
    ) -> SwarmExecutor: ...


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


class _OutboxSink:
    delivered: list[tuple[str, bytes]]
    fail_after_delivery: bool

    def __init__(self) -> None:
        self.delivered = []
        self.fail_after_delivery = False

    def deliver(self, event_id: str, payload: bytes) -> None:
        self.delivered.append((event_id, payload))
        if self.fail_after_delivery:
            raise _InjectedFault("after_sink_delivery_before_mark")


_OUTBOX_SINK = _OutboxSink()


class _DetachedSigner:
    def __init__(self, seed: bytes) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, domain: bytes, canonical_body: bytes) -> bytes:
        return self._key.sign(domain + b"\x00" + canonical_body)


_GCB_BOOTSTRAP: _GCBBootstrapFactory = getattr(
    governed_commit_module, "TrustedGovernanceBootstrap"
)
_SWARM_EXECUTOR: _SwarmExecutorFactory = getattr(swarm_module, "SwarmExecutor")


class _KeyProvider:
    _commit_signatures = 0
    _status_signatures = 0

    def __init__(
        self,
        commit_seed: bytes = SEEDS["commit"],
        status_seed: bytes = SEEDS["status"],
    ) -> None:
        self.created_pid = os.getpid()
        self._seeds = {
            AuthoritySigningRole.COMMIT: commit_seed,
            AuthoritySigningRole.STATUS: status_seed,
        }
        self.invalid_commit_signature = False
        self.status_signature_mode = "valid"

    def _seed(self, role: AuthoritySigningRole) -> bytes:
        return self._seeds[role]

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        del key_id
        return (
            Ed25519PrivateKey.from_private_bytes(self._seed(role))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        if role is AuthoritySigningRole.COMMIT:
            type(self)._commit_signatures += 1
            if self.invalid_commit_signature:
                return Signature("Ed25519", key_id, _b64u(bytes(64)))
        if role is AuthoritySigningRole.STATUS:
            type(self)._status_signatures += 1
            if self.status_signature_mode == "zero":
                return Signature("Ed25519", key_id, _b64u(bytes(64)))
            if self.status_signature_mode == "wrong-key":
                signature = Ed25519PrivateKey.from_private_bytes(
                    SEEDS["producer"]
                ).sign(domain + b"\x00" + canonical_body)
                return Signature("Ed25519", key_id, _b64u(signature))
            if self.status_signature_mode == "wrong-id":
                return Signature("Ed25519", "wrong-status-key", _b64u(bytes(64)))
            if self.status_signature_mode == "malformed":
                return Signature("Ed25519", key_id, "not+base64")
        signature = Ed25519PrivateKey.from_private_bytes(self._seed(role)).sign(
            domain + b"\x00" + canonical_body
        )
        return Signature("Ed25519", key_id, _b64u(signature))

    @classmethod
    def commit_signature_count(cls) -> int:
        return cls._commit_signatures

    @classmethod
    def status_signature_count(cls) -> int:
        return cls._status_signatures


class _Clock:
    def __init__(self) -> None:
        self._sequence = [1_760_000_001_000]

    def now_ms(self) -> int:
        if len(self._sequence) > 1:
            return self._sequence.pop(0)
        return self._sequence[0]

    def set_sequence(self, values: tuple[int, ...]) -> None:
        assert values
        self._sequence = list(values)


def _runtime(
    commit_seed: bytes = SEEDS["commit"],
    status_seed: bytes = SEEDS["status"],
) -> AuthorityRuntime:
    return AuthorityRuntime(
        _KeyProvider(commit_seed, status_seed), _Clock(), _OUTBOX_SINK
    )


def _config(authority_store_id: str = "store-1") -> APCCAuthorityConfig:
    bindings = valid_vector().trust.bindings
    by_role = {
        role: tuple(binding for binding in bindings if binding.role is role)
        for role in TrustRole
    }
    return APCCAuthorityConfig(
        authority_store_id=authority_store_id,
        producer_trust=by_role[TrustRole.PRODUCER],
        policy_trust=by_role[TrustRole.POLICY],
        registry_trust=by_role[TrustRole.REGISTRY],
        commit_trust=replace(by_role[TrustRole.COMMIT][0], scope=(authority_store_id,)),
        status_trust=replace(by_role[TrustRole.STATUS][0], scope=(authority_store_id,)),
        freshness=StatusFreshnessPolicy("5000", "1000"),
    )


def _gcb_config(
    producer_public_key: bytes, authority_store_id: str = "dispatcher-store"
) -> APCCAuthorityConfig:
    """Caller-chosen exact GCB scopes; control is a sixth external key."""
    authority_root = _digest(b"dispatcher-authority-root")
    return APCCAuthorityConfig(
        authority_store_id=authority_store_id,
        producer_trust=(
            TrustBinding(
                role=TrustRole.PRODUCER,
                scope=("agent", "authority:dispatcher:actor-authority", authority_root),
                key_id="dispatcher-producer-key",
                public_key=producer_public_key,
            ),
        ),
        policy_trust=(
            TrustBinding(
                role=TrustRole.POLICY,
                scope=("dispatcher-policy", "1", "1"),
                key_id="dispatcher-policy-key",
                public_key=_public_key(SEEDS["policy"]),
            ),
        ),
        registry_trust=(
            TrustBinding(
                role=TrustRole.REGISTRY,
                scope=(authority_root, "1"),
                key_id="dispatcher-registry-key",
                public_key=_public_key(SEEDS["authority"]),
            ),
        ),
        commit_trust=TrustBinding(
            role=TrustRole.COMMIT,
            scope=(authority_store_id,),
            key_id="dispatcher-commit-key",
            public_key=_public_key(SEEDS["commit"]),
        ),
        status_trust=TrustBinding(
            role=TrustRole.STATUS,
            scope=(authority_store_id,),
            key_id="dispatcher-status-key",
            public_key=_public_key(SEEDS["status"]),
        ),
        freshness=StatusFreshnessPolicy("5000", "1000"),
    )


def _config_with_mutated_binding(
    role: TrustRole, field_name: str
) -> tuple[APCCAuthorityConfig, AuthorityRuntime]:
    config = _config()
    binding = next(item for item in config.trust_bindings if item.role is role)
    commit_seed = SEEDS["commit"]
    status_seed = SEEDS["status"]
    if field_name == "key_id":
        mutated = replace(binding, key_id=f"changed-{binding.key_id}")
    elif field_name == "scope":
        mutated = replace(
            binding,
            scope=(*binding.scope[:-1], f"changed-{binding.scope[-1]}"),
        )
    else:
        replacement_seed = bytes([240 + tuple(TrustRole).index(role)]) * 32
        mutated = replace(binding, public_key=_public_key(replacement_seed))
        if role is TrustRole.COMMIT:
            commit_seed = replacement_seed
        elif role is TrustRole.STATUS:
            status_seed = replacement_seed
    if role is TrustRole.PRODUCER:
        changed = replace(config, producer_trust=(mutated,))
    elif role is TrustRole.POLICY:
        changed = replace(config, policy_trust=(mutated,))
    elif role is TrustRole.REGISTRY:
        changed = replace(config, registry_trust=(mutated,))
    elif role is TrustRole.COMMIT:
        changed = replace(config, commit_trust=mutated)
    else:
        changed = replace(config, status_trust=mutated)
    return changed, _runtime(commit_seed, status_seed)


def _request(
    *,
    commit_id: str,
    nonce_byte: int,
    workflow_id: str = "workflow-1",
    expected_node_version: str = "0",
    attempt_id: str = "attempt-1",
    node_id: str = "node-1",
    predecessors: list[dict[str, str]] | None = None,
    result_bytes: bytes = b"output",
    agent_revocation_generation: str = "3",
    workflow_revocation_generation: str = "4",
) -> AtomicCommitRequest:
    """Build a separately signed request; no final commit seal is reused."""
    payload = copy.deepcopy(valid_vector().payload)
    nonce = _nonce(nonce_byte)
    producer = payload["evidence"]["producer_statement"]
    producer.update(
        {
            "workflow_id": workflow_id,
            "node_id": node_id,
            "attempt_id": attempt_id,
            "commit_id": commit_id,
            "nonce": nonce,
            "expected_node_version": expected_node_version,
            "output_digest": _digest(result_bytes),
        }
    )
    payload["bindings"]["predecessors"] = predecessors or []
    payload["bindings"]["predecessor_root"] = _digest(
        _canonical(payload["bindings"]["predecessors"])
    )
    payload["context"].update(
        {
            "agent_revocation_generation": agent_revocation_generation,
            "workflow_revocation_generation": workflow_revocation_generation,
        }
    )
    payload["evidence"]["authority_statement"].update(
        {
            "agent_revocation_generation": agent_revocation_generation,
            "workflow_revocation_generation": workflow_revocation_generation,
        }
    )
    producer["predecessor_root"] = payload["bindings"]["predecessor_root"]
    producer_bytes = _canonical(producer)
    proposal_digest = _digest(producer_bytes)
    for statement_name, seed, domain, key_id, signature_name in (
        (
            "producer_statement",
            SEEDS["producer"],
            DOMAINS["producer"],
            "producer-key",
            "producer",
        ),
        (
            "policy_statement",
            SEEDS["policy"],
            DOMAINS["policy"],
            "policy-key",
            "policy_authority",
        ),
        (
            "authority_statement",
            SEEDS["authority"],
            DOMAINS["authority"],
            "authority-key",
            "authority_registry",
        ),
    ):
        statement = payload["evidence"][statement_name]
        if statement_name != "producer_statement":
            statement["workflow_id"] = workflow_id
            statement["node_id"] = node_id
            statement["attempt_id"] = attempt_id
            statement["proposal_digest"] = proposal_digest
        payload["evidence"][f"{statement_name}_digest"] = _digest(_canonical(statement))
        payload["signatures"][signature_name] = _signature(
            seed, domain, _canonical(statement), key_id
        )
    payload["subject"]["workflow_id"] = workflow_id
    payload["subject"]["node_id"] = node_id
    payload["subject"]["attempt_id"] = attempt_id
    payload["subject"]["output_digest"] = _digest(result_bytes)
    payload["decision"].update({"commit_id": commit_id, "nonce": nonce})
    payload["bindings"].update(
        {
            "expected_node_version": expected_node_version,
            "committed_node_version": str(int(expected_node_version) + 1),
        }
    )
    certificate = CommitCertificate.from_object(payload)
    return AtomicCommitRequest(
        subject=certificate.subject,
        context=certificate.context,
        evidence=certificate.evidence,
        bindings=certificate.bindings,
        signatures=certificate.signatures,
        commit_id=commit_id,
        nonce=nonce,
        request_digest=sha256_digest(producer_bytes),
    )


def _predecessor(
    request: AtomicCommitRequest, committed: CommitResult
) -> dict[str, str]:
    assert committed.certificate_digest
    return {
        "workflow_id": request.subject.workflow_id,
        "node_id": request.subject.node_id,
        "committed_node_version": request.bindings.committed_node_version,
        "commit_id": request.commit_id,
        "certificate_digest": committed.certificate_digest,
        "output_digest": request.subject.output_digest,
    }


def _initial_contexts() -> tuple[CommitContext, ...]:
    vector = valid_vector()
    certificate = CommitCertificate.from_object(vector.payload)

    def initial_context(workflow_id: str, node_id: str) -> CommitContext:
        subject = replace(certificate.subject, workflow_id=workflow_id, node_id=node_id)
        return CommitContext(
            subject=subject,
            governance=certificate.context,
            candidate_state=CandidateState(
                subject.workflow_id,
                subject.node_id,
                subject.attempt_id,
                CandidateLifecycle.EXECUTING,
            ),
            logical_node_state=LogicalNodeState(
                subject.workflow_id, subject.node_id, "0", None
            ),
            predecessors=(),
            audit_event_id=f"bootstrap-{node_id}",
        )

    base_nodes = (
        ("workflow-1", "node-1"),
        ("workflow-1", "root"),
        ("workflow-1", "middle"),
        ("workflow-1", "leaf"),
        ("workflow-1", "child"),
        ("workflow-2", "node-1"),
    )
    depth_nodes = tuple(("workflow-1", f"depth-node-{index}") for index in range(66))
    return tuple(
        initial_context(workflow_id, node_id)
        for workflow_id, node_id in base_nodes + depth_nodes
    )


def _open_store(path: Path, controller: FaultProbe | None) -> SQLiteAuthorityStore:
    if not path.exists():
        SQLiteAuthorityStore.provision(
            path, config=_config(), initial_contexts=_initial_contexts()
        )
    if controller is None:
        return SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime())
    return _SQLiteStoreFactory.open_with_probe(path, _config(), _runtime(), controller)


def _reopen_store(path: Path) -> SQLiteAuthorityStore:
    return SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime())


def _snapshot(store: SQLiteAuthorityStore) -> AuthoritySnapshot:
    """Test-only canonical observer over every authority/control table."""
    semantic_names = {"apcc_decisions": "decisions", "apcc_outbox": "outbox"}
    with sqlite3.connect(store.database_path) as connection:
        tables: list[str] = []
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ):
            assert isinstance(name, str)
            tables.append(name)
        contents = {
            semantic_names.get(name, name): tuple(
                repr(row).encode("utf-8")
                for row in connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid')
            )
            for name in tables
        }
    pointers = tuple(
        row
        for name, rows in contents.items()
        if "node" in name or "pointer" in name
        for row in rows
    )
    return AuthoritySnapshot(contents, pointers)


def _force_sql_mutation(
    connection: sqlite3.Connection,
    table: str,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    """Test-only corruption that preserves the provisioned schema definition."""
    triggers = connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
        (table,),
    ).fetchall()
    for name, _sql in triggers:
        connection.execute(f'DROP TRIGGER "{name}"')
    connection.execute(statement, parameters)
    for _name, sql in triggers:
        connection.execute(sql)


def _gcb_authority_snapshot(admin: _GCBAdmin) -> AuthoritySnapshot:
    """Read the durable authority tables through the existing GCB path."""
    with sqlite3.connect(admin.commit_port.path) as connection:
        table_names = tuple(
            name
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        tables = {
            name: tuple(
                repr(row).encode("utf-8")
                for row in connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid')
            )
            for name in table_names
        }
    pointers = tuple(
        row
        for name, rows in tables.items()
        if "node" in name or "certificate" in name or "pointer" in name
        for row in rows
    )
    return AuthoritySnapshot(tables, pointers)


def _stage_request(request: AtomicCommitRequest) -> StageResultRequest:
    return StageResultRequest(
        request.subject, request.bindings.expected_node_version, b"output"
    )


def _advance_candidate(
    store: SQLiteAuthorityStore, request: AtomicCommitRequest
) -> None:
    staged = store.stage_result(_stage_request(request))
    assert staged.candidate_state.lifecycle is CandidateLifecycle.RESULT_STAGED
    assembled = store.assemble_evidence(_assemble_evidence_request(request))
    assert assembled.candidate_state.lifecycle is CandidateLifecycle.EVIDENCE_ASSEMBLED
    proposed = store.propose_commit(_propose_commit_request(request))
    assert proposed.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING


def _resigned_status(
    authority_status: AuthorityStatus, **changes: str
) -> AuthorityStatus:
    body = authority_status.body_object()
    body.update(changes)
    return AuthorityStatus.from_object(
        {
            "body": body,
            "signature": _signature(
                SEEDS["status"], DOMAINS["status"], _canonical(body), "status-key"
            ),
        }
    )


def _only_conflict_and_audit(
    before: AuthoritySnapshot, after: AuthoritySnapshot, commit_id: str
) -> None:
    changed = {
        name
        for name in set(before.tables) | set(after.tables)
        if before.tables.get(name) != after.tables.get(name)
    }
    assert changed == {"commit_conflicts", "audit_events"}
    assert (
        len(after.tables["commit_conflicts"])
        == len(before.tables["commit_conflicts"]) + 1
    )
    assert len(after.tables["audit_events"]) == len(before.tables["audit_events"]) + 1
    assert commit_id.encode("utf-8") in after.tables["commit_conflicts"][-1]
    assert commit_id.encode("utf-8") in after.tables["audit_events"][-1]
    assert before.current_pointers == after.current_pointers


def _only_denied_decision_and_audit(
    before: AuthoritySnapshot, after: AuthoritySnapshot, commit_id: str
) -> None:
    changed = {
        name
        for name in set(before.tables) | set(after.tables)
        if before.tables.get(name) != after.tables.get(name)
    }
    expected = {
        "commit_index",
        "request_index",
        "decisions",
        "audit_events",
    }
    assert changed in (expected, expected | {"nonce_ledger"})
    assert len(after.tables["commit_index"]) == len(before.tables["commit_index"]) + 1
    assert len(after.tables["request_index"]) == len(before.tables["request_index"]) + 1
    if "nonce_ledger" in changed:
        assert (
            len(after.tables["nonce_ledger"]) == len(before.tables["nonce_ledger"]) + 1
        )
    assert len(after.tables["decisions"]) == len(before.tables["decisions"]) + 1
    assert len(after.tables["audit_events"]) == len(before.tables["audit_events"]) + 1
    assert commit_id.encode("utf-8") in after.tables["decisions"][-1]
    assert commit_id.encode("utf-8") in after.tables["audit_events"][-1]
    assert before.current_pointers == after.current_pointers


def _missing_recovery_delta(
    before: AuthoritySnapshot, after: AuthoritySnapshot
) -> None:
    """Missing recovery is either side-effect free or emits exactly one audit row."""
    if after == before:
        return
    changed = {
        name
        for name in set(before.tables) | set(after.tables)
        if before.tables.get(name) != after.tables.get(name)
    }
    assert changed == {"audit_events"}
    assert len(after.tables["audit_events"]) == len(before.tables["audit_events"]) + 1
    assert before.current_pointers == after.current_pointers


def _only_outbox_delivery(before: AuthoritySnapshot, after: AuthoritySnapshot) -> None:
    changed = {
        name
        for name in set(before.tables) | set(after.tables)
        if before.tables.get(name) != after.tables.get(name)
    }
    assert changed == {"outbox", "audit_events"}
    assert len(after.tables["outbox"]) == len(before.tables["outbox"])
    assert len(after.tables["audit_events"]) == len(before.tables["audit_events"]) + 1
    assert before.current_pointers == after.current_pointers


_COMMIT_WRITE_TABLES = frozenset(
    {
        "commit_index",
        "request_index",
        "nonce_ledger",
        "audit_events",
        "evidence_refs",
        "certificates",
        "decisions",
        "certificate_dispositions",
        "logical_nodes",
        "trust_log",
        "outbox",
    }
)
_WORKFLOW_REVOCATION_WRITE_TABLES = frozenset(
    {
        "workflow_revocations",
        "control_events",
        "trust_log",
        "audit_events",
        "outbox",
    }
)
_CERTIFICATE_REVOCATION_WRITE_TABLES = frozenset(
    {
        "certificate_dispositions",
        "control_events",
        "trust_log",
        "audit_events",
        "outbox",
    }
)
_ACTOR_REVOCATION_WRITE_TABLES = frozenset(
    {"actor_revocations", "control_events", "trust_log", "audit_events", "outbox"}
)


def _commit_write_tables(request: AtomicCommitRequest) -> frozenset[str]:
    if request.bindings.predecessors:
        return _COMMIT_WRITE_TABLES | frozenset({"predecessor_edges"})
    return _COMMIT_WRITE_TABLES


def _supersession_write_tables(request: AtomicCommitRequest) -> frozenset[str]:
    return _commit_write_tables(request) | frozenset({"supersession_edges"})


def _assert_exact_authority_delta(
    before: AuthoritySnapshot,
    after: AuthoritySnapshot,
    *,
    changed_tables: frozenset[str],
    pointer_changed: bool,
) -> None:
    """Every named authority write changes; all other authority tables are exact."""
    assert set(before.tables) == set(after.tables)
    actual = {
        table for table in before.tables if before.tables[table] != after.tables[table]
    }
    assert actual == changed_tables
    for table in changed_tables:
        assert after.tables[table] != before.tables[table]
        assert after.tables[table]
    for table in set(before.tables) - changed_tables:
        assert after.tables[table] == before.tables[table]
    if pointer_changed:
        assert before.current_pointers != after.current_pointers
    else:
        assert before.current_pointers == after.current_pointers


def _assemble_evidence_request(
    request: AtomicCommitRequest,
) -> AssembleEvidenceRequest:
    return AssembleEvidenceRequest(request)


def _propose_commit_request(request: AtomicCommitRequest) -> ProposeCommitRequest:
    return ProposeCommitRequest(request)


def _outbox_event(store: SQLiteAuthorityStore, commit_id: str) -> PersistedOutboxEvent:
    return store.get_outbox_event(commit_id)


def _snapshot_authority_store(store: AuthorityStore) -> AuthoritySnapshot:
    assert isinstance(store, SQLiteAuthorityStore)
    return _snapshot(store)


def _authority_outbox_event(
    store: AuthorityStore, commit_id: str
) -> PersistedOutboxEvent:
    assert isinstance(store, SQLiteAuthorityStore)
    return _outbox_event(store, commit_id)


def _tamper_certificate_payload(store: AuthorityStore, digest: str) -> None:
    assert isinstance(store, SQLiteAuthorityStore)
    with sqlite3.connect(store.database_path) as connection:
        (payload,) = connection.execute(
            "SELECT certificate_json FROM certificates WHERE certificate_digest=?",
            (digest,),
        ).fetchone()
        certificate = decode_certificate(bytes(payload))
        tampered = replace(
            certificate,
            context=replace(certificate.context, policy_version="999"),
        )
        connection.execute(
            "UPDATE certificates SET certificate_json=? WHERE certificate_digest=?",
            (encode_certificate(tampered), digest),
        )


def _replace_predecessor_edges(
    store: AuthorityStore, child_commit_id: str, digests: tuple[str, ...]
) -> None:
    assert isinstance(store, SQLiteAuthorityStore)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM predecessor_edges WHERE child_commit_id=?",
            (child_commit_id,),
        )
        connection.executemany(
            "INSERT INTO predecessor_edges(child_commit_id, predecessor_digest) VALUES (?, ?)",
            ((child_commit_id, digest) for digest in digests),
        )


def _set_clock_sequence(store: AuthorityStore, values: tuple[int, ...]) -> None:
    assert isinstance(store, SQLiteAuthorityStore)
    clock = store._runtime.clock
    assert isinstance(clock, _Clock)
    clock.set_sequence(values)


def _set_invalid_commit_signature(store: AuthorityStore, invalid: bool) -> None:
    assert isinstance(store, SQLiteAuthorityStore)
    provider = store._runtime.key_provider
    assert isinstance(provider, _KeyProvider)
    provider.invalid_commit_signature = invalid


def _harness() -> AuthorityStoreHarness:
    return AuthorityStoreHarness(
        _open_store,
        _reopen_store,
        _request,
        valid_vector().trust,
        _snapshot_authority_store,
        _stage_request,
        _assemble_evidence_request,
        _propose_commit_request,
        _authority_outbox_event,
        _only_conflict_and_audit,
        _only_denied_decision_and_audit,
        _missing_recovery_delta,
        _only_outbox_delivery,
        _KeyProvider.commit_signature_count,
        _tamper_certificate_payload,
        _replace_predecessor_edges,
        _set_clock_sequence,
        _set_invalid_commit_signature,
    )


class _SQLiteStoreFactory:
    """Typed test-only factory over a private production probe path."""

    @staticmethod
    def open_with_probe(
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: FaultProbe,
    ) -> SQLiteAuthorityStore:
        return SQLiteAuthorityStore._open_with_probe(
            path, config=config, runtime=runtime, probe=probe
        )


class _GCBFactory:
    @staticmethod
    def provision_with_projection_fault(
        bootstrap: _GCBBootstrap,
        path: Path,
        checkpoint: _GCBProjectionCheckpoint,
    ) -> _GCBAdmin:
        return bootstrap._provision_with_projection_fault(path, checkpoint=checkpoint)


def _prepared_gcb_projection_case(
    tmp_path: Path,
) -> tuple[
    _GCBBootstrap,
    _GCBAdmin,
    GovernedCommitRequest,
    _GCBAtomicCommitRequest,
    APCCAuthorityConfig,
    AuthorityRuntime,
]:
    agent_key = Ed25519PrivateKey.from_private_bytes(SEEDS["producer"])
    config = _gcb_config(
        agent_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    runtime = _runtime()
    bootstrap = _GCB_BOOTSTRAP(
        config=config,
        runtime=runtime,
        policy_signer=_DetachedSigner(SEEDS["policy"]),
        registry_signer=_DetachedSigner(SEEDS["authority"]),
        control_signer=_DetachedSigner(_CONTROL_SEED),
    )
    admin = bootstrap.provision(tmp_path / "closed-gcb-projection.sqlite3")
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    dag = TaskDAG(dag_id="dispatcher", goal="g").add_node(
        TaskNode(node_id="root", required_capabilities=("work",))
    )
    provision_executor_workflow(admin, dag, policy_version="1")
    admin.register_agent(
        workflow_id="dispatcher",
        agent_id="agent",
        public_key=agent_key.public_key(),
        capabilities=("work",),
    )
    executor = compose_test_executor(
        registry,
        ArtifactStore(),
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(dag)
    authorization = sign_attempt_authorization(
        executor.prepare_claim("root", "agent"), agent_key
    )
    executor.claim("root", "agent", authorization)
    payload = executor.produce_result(
        "root", Artifact("closed-plan", "root", "agent", "text", "result")
    )
    governed = admin.build_request(sign_governed_receipt(payload, agent_key))
    atomic = admin.commit_port._to_apcc_request(governed)
    assert type(atomic) is _GCBAtomicCommitRequest
    admin.commit_port._prepare_apcc_candidate(atomic)
    return bootstrap, admin, governed, atomic, config, runtime


def test_gcb_projection_has_no_callback_sql_or_connection_capability_surface() -> None:
    assert not hasattr(SQLiteAuthorityStore, "_open_with_projection")
    assert not hasattr(sqlite_store_module, "SQLiteProjectionConnection")
    assert not hasattr(sqlite_store_module, "SQLiteProjectionCursor")
    assert not hasattr(sqlite_store_module, "_RestrictedProjectionConnection")
    assert not hasattr(sqlite_store_module, "_RestrictedProjectionCursor")
    assert not hasattr(sqlite_store_module, "_PROJECTION_ALLOWED_SQL_DIGESTS")


def test_gcb_projection_plan_is_frozen_data_only() -> None:
    annotations = get_type_hints(_GCBProjectionPlan)
    assert set(annotations.values()) <= {str, int}
    assert not any(
        fragment in field_name
        for field_name in annotations
        for fragment in (
            "callback",
            "callable",
            "connection",
            "cursor",
            "operation",
            "sql",
        )
    )


def _tampered_gcb_projection_plan(
    plan: _GCBProjectionPlan, mutation: str
) -> _GCBProjectionPlan:
    if mutation == "predecessor":
        receipt = json.loads(plan.receipt_material)
        receipt["payload"]["predecessor_bindings"] = [
            {
                "node_id": "victim-predecessor",
                "node_version": 1,
                "commit_id": "victim-commit",
                "receipt_digest": "0" * 64,
                "authoritative_result_digest": "1" * 64,
            }
        ]
        material = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        return replace(
            plan,
            receipt_material=material,
            receipt_digest=sha256_digest(material.encode()),
        )
    if mutation == "output_digest":
        receipt = json.loads(plan.receipt_material)
        receipt["payload"]["output_digest"] = "0" * 64
        material = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        return replace(
            plan,
            receipt_material=material,
            receipt_digest=sha256_digest(material.encode()),
        )
    if mutation == "workflow_id":
        return replace(plan, workflow_id="victim-workflow")
    if mutation == "node_id":
        return replace(plan, node_id="victim-node")
    if mutation == "attempt_id":
        return replace(plan, attempt_id="victim-attempt")
    if mutation == "agent_id":
        return replace(plan, agent_id="victim-agent")
    if mutation == "commit_id":
        return replace(plan, commit_id="victim-commit")
    if mutation == "nonce":
        return replace(plan, nonce=_nonce(221))
    if mutation == "expected_node_version":
        return replace(plan, expected_node_version=plan.expected_node_version + 1)
    if mutation == "committed_node_version":
        return replace(plan, committed_node_version=plan.committed_node_version + 1)
    if mutation == "expected_workflow_state_version":
        return replace(
            plan,
            expected_workflow_state_version=plan.expected_workflow_state_version + 1,
        )
    if mutation == "policy_digest":
        return replace(plan, policy_digest="0" * 64)
    if mutation == "request_hash":
        return replace(plan, request_hash="1" * 64)
    if mutation == "receipt_digest":
        return replace(plan, receipt_digest="2" * 64)
    if mutation == "verdict_digest":
        return replace(plan, verdict_digest="3" * 64)
    raise AssertionError(f"unknown GCB projection mutation: {mutation}")


_GCB_PLAN_MUTATIONS = (
    "workflow_id",
    "node_id",
    "attempt_id",
    "agent_id",
    "commit_id",
    "nonce",
    "expected_node_version",
    "committed_node_version",
    "expected_workflow_state_version",
    "policy_digest",
    "request_hash",
    "receipt_digest",
    "verdict_digest",
    "predecessor",
    "output_digest",
)


@pytest.mark.parametrize("mutation", _GCB_PLAN_MUTATIONS)
def test_gcb_projection_rejects_substituted_plan_without_mutation(
    tmp_path: Path, mutation: str
) -> None:
    _bootstrap, admin, _governed, request, _config_value, _runtime_value = (
        _prepared_gcb_projection_case(tmp_path)
    )
    before = _gcb_authority_snapshot(admin)
    tampered = replace(
        request,
        _gcb_projection_plan=_tampered_gcb_projection_plan(
            request._gcb_projection_plan, mutation
        ),
    )
    with pytest.raises(sqlite_store_module._GCBProjectionDenied):
        admin.commit_port._apcc_store.atomic_commit(tampered)
    assert _gcb_authority_snapshot(admin) == before
    reader = SQLiteAuthorityReader.open(Path(admin.commit_port.path))
    assert reader.get_certificate(request.commit_id) is None
    node = reader.read_logical_node("dispatcher", "root")
    assert node.current_node_version == "0"
    assert node.current_certificate_digest is None
    assert admin.node_state("dispatcher", "root").commit_id is None


@pytest.mark.parametrize("mutation", _GCB_PLAN_MUTATIONS)
def test_gcb_replay_rejects_same_commit_id_with_different_plan(
    tmp_path: Path, mutation: str
) -> None:
    _bootstrap, admin, _governed, request, _config_value, _runtime_value = (
        _prepared_gcb_projection_case(tmp_path)
    )
    store = admin.commit_port._apcc_store
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    before = _gcb_authority_snapshot(admin)
    tampered = replace(
        request,
        _gcb_projection_plan=_tampered_gcb_projection_plan(
            request._gcb_projection_plan, mutation
        ),
    )
    with pytest.raises(
        sqlite_store_module._GCBProjectionDenied,
        match="^projection_replay_mismatch$",
    ):
        store.atomic_commit(tampered)
    assert _gcb_authority_snapshot(admin) == before


def test_gcb_attached_store_rejects_unprojected_raw_atomic_commit(
    tmp_path: Path,
) -> None:
    _bootstrap, admin, _governed, request, config, runtime = (
        _prepared_gcb_projection_case(tmp_path)
    )
    assert not hasattr(admin.commit_port, "_fault_injector")
    assert not hasattr(admin.commit_port, "_governed_requests")
    raw_request = AtomicCommitRequest(
        request.subject,
        request.context,
        request.evidence,
        request.bindings,
        request.signatures,
        request.commit_id,
        request.nonce,
        request.request_digest,
    )
    before = _gcb_authority_snapshot(admin)
    with pytest.raises(
        sqlite_store_module._GCBProjectionDenied,
        match="^unprojected_gcb_commit_denied$",
    ):
        admin.commit_port._apcc_store.atomic_commit(raw_request)
    assert _gcb_authority_snapshot(admin) == before
    with pytest.raises(ValueError, match="requires typed governance bootstrap"):
        SQLiteAuthorityStore.open(
            Path(admin.commit_port.path), config=config, runtime=runtime
        )


def test_gcb_concurrent_commit_is_one_atomic_tuple_and_survives_reopen(
    tmp_path: Path,
) -> None:
    bootstrap, admin, governed, request, _config_value, _runtime_value = (
        _prepared_gcb_projection_case(tmp_path)
    )
    store = admin.commit_port._apcc_store
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(lambda _index: store.atomic_commit(request), range(8)))
    assert len({result.certificate_digest for result in results}) == 1
    assert results.count(results[0]) == len(results)
    reopened = bootstrap.open_admin(Path(admin.commit_port.path))
    replay = reopened.commit(governed)
    assert replay.commit_id == request.commit_id
    with sqlite3.connect(admin.commit_port.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM certificates WHERE commit_id=?", (request.commit_id,)
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM decisions WHERE commit_id=?", (request.commit_id,)
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipt_evidence WHERE commit_id=?",
            (request.commit_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM outbox WHERE commit_id=?", (request.commit_id,)
        ).fetchone() == (1,)


def test_gcb_ipc_commit_payload_contains_no_projection_capability(
    tmp_path: Path,
) -> None:
    _bootstrap, _admin, governed, _request_value, _config_value, _runtime_value = (
        _prepared_gcb_projection_case(tmp_path)
    )
    encoded = authority_service_module._encode_commit_request(governed)
    assert set(encoded) == {"receipt", "verdict"}
    payload = json.dumps(encoded, sort_keys=True, separators=(",", ":"))
    assert not any(
        token in payload
        for token in ("projection", "callback", "connection", "cursor", "sql")
    )


def test_public_sqlite_construction_has_no_fault_or_projection_parameter() -> None:
    public_parameters = inspect.signature(SQLiteAuthorityStore.open).parameters
    constructor_parameters = inspect.signature(SQLiteAuthorityStore.__init__).parameters
    assert not {
        "fault_point",
        "fail_controller",
        "_fail_controller",
        "probe",
        "_probe",
        "projection",
    } & set(public_parameters)
    assert not {
        "fault_point",
        "fail_controller",
        "_fail_controller",
        "probe",
        "_probe",
        "projection",
    } & set(constructor_parameters)
    assert object not in get_type_hints(SQLiteAuthorityStore.open).values()
    with pytest.raises(
        ValueError, match="use SQLiteAuthorityStore.open on a provisioned store"
    ):
        SQLiteAuthorityStore(Path("unused.db"), _config(), _runtime())


def test_sqlite_open_never_creates_an_unprovisioned_path_and_reader_is_read_only(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing-authority.db"
    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime()),
    ):
        with pytest.raises(ValueError, match="^APCC SQLite store is not provisioned$"):
            opener()
        assert not path.exists()
        assert not Path(f"{path}-wal").exists()
        assert not Path(f"{path}-shm").exists()

    SQLiteAuthorityStore.provision(
        path, config=_config(), initial_contexts=_initial_contexts()
    )
    reader = SQLiteAuthorityReader.open(path)
    before = _database_file_state(path)
    assert reader.read_logical_node("workflow-1", "root").current_node_version == "0"
    connection = reader._connection()
    try:
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO metadata VALUES ('forbidden', 'write')")
    finally:
        connection.close()
    assert _database_file_state(path) == before


@pytest.mark.parametrize(
    "tamper",
    (
        "version",
        "table",
        "foreign-key",
        "fingerprint",
        "trigger",
        "column",
        "unexpected-index",
    ),
)
def test_sqlite_open_validates_v1_schema_without_mutating_failed_store(
    tmp_path: Path, tamper: str
) -> None:
    path = tmp_path / f"schema-{tamper}.db"
    SQLiteAuthorityStore.provision(
        path, config=_config(), initial_contexts=_initial_contexts()
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (0x41504343,)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        fingerprint = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_fingerprint'"
        ).fetchone()
        assert fingerprint is not None and len(fingerprint[0]) == 43
        trigger_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }
        assert {
            "certificate_dispositions_no_update",
            "certificate_dispositions_no_delete",
            "certificate_dispositions_validate_insert",
        } <= trigger_names
        if tamper == "version":
            connection.execute("PRAGMA user_version=0")
        elif tamper == "table":
            connection.execute("DROP TABLE candidates")
        elif tamper == "foreign-key":
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO request_index VALUES ('orphan-request', 'missing-commit')"
            )
        elif tamper == "fingerprint":
            connection.execute(
                "UPDATE metadata SET value='wrong' WHERE key='schema_fingerprint'"
            )
        elif tamper == "trigger":
            connection.execute("DROP TRIGGER certificate_dispositions_no_delete")
        elif tamper == "column":
            connection.execute("ALTER TABLE candidates ADD COLUMN injected TEXT")
        else:
            connection.execute(
                "CREATE INDEX injected_apcc_index ON certificates(workflow_id)"
            )
    before = _database_file_state(path)
    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime()),
    ):
        with pytest.raises(ValueError):
            opener()
        assert _database_file_state(path) == before


def test_sqlite_apcc_namespace_does_not_collide_with_added_gcb_table_names(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shared-gcb-apcc.db"
    SQLiteAuthorityStore.provision(
        path, config=_config(), initial_contexts=_initial_contexts()
    )
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_meta(singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL);
            INSERT INTO schema_meta VALUES(1,3);
            CREATE TABLE decisions(
                commit_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
                outcome TEXT NOT NULL, reason TEXT NOT NULL,
                workflow_id TEXT NOT NULL, node_id TEXT NOT NULL,
                state_version INTEGER NOT NULL, nonce TEXT NOT NULL);
            CREATE TABLE outbox(
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                commit_id TEXT NOT NULL UNIQUE, workflow_id TEXT NOT NULL,
                node_id TEXT NOT NULL, artifact_json TEXT NOT NULL,
                dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN(0,1)),
                FOREIGN KEY(commit_id) REFERENCES decisions(commit_id));
            CREATE INDEX idx_outbox_pending ON outbox(dispatched,event_id);
            """
        )
    reader = SQLiteAuthorityReader.open(path)
    store = SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime())
    assert reader.authority_store_id == store.authority_store_id
    with sqlite3.connect(path) as connection:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {"decisions", "outbox", "apcc_decisions", "apcc_outbox"} <= names


def test_sqlite_open_rejects_any_unexpected_trigger_even_on_disjoint_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "hostile-gcb-trigger.db"
    store = _open_store(path, None)
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE gcb_decisions(commit_id TEXT PRIMARY KEY);
            CREATE TRIGGER hostile_gcb_trigger AFTER INSERT ON gcb_decisions
            BEGIN UPDATE logical_nodes SET version='999'; END;
            """
        )
    before = _snapshot(store)
    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime()),
    ):
        with pytest.raises(ValueError):
            opener()
    assert _snapshot(store) == before


def test_sqlite_provision_rejects_foreign_file_without_journal_or_byte_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("CREATE TABLE foreign_data(value TEXT)")
    before = _database_file_state(path)
    with pytest.raises(ValueError, match="schema validation failed"):
        SQLiteAuthorityStore.provision(
            path, config=_config(), initial_contexts=_initial_contexts()
        )
    assert _database_file_state(path) == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)


def test_sqlite_provision_is_public_only_one_time_and_changed_config_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bootstrap.db"
    store = _open_store(path, None)
    before = _snapshot(store)
    reopened = _reopen_store(path)
    assert _snapshot(reopened) == before
    changed = _config("different-store")
    with pytest.raises(ValueError):
        SQLiteAuthorityStore.open(path, config=changed, runtime=_runtime())
    with pytest.raises(ValueError):
        SQLiteAuthorityStore.open(
            path,
            config=_config(),
            runtime=_runtime(bytes(reversed(SEEDS["commit"]))),
        )
    with pytest.raises(ValueError):
        SQLiteAuthorityStore.provision(
            path, config=changed, initial_contexts=_initial_contexts()
        )
    assert _snapshot(_reopen_store(path)) == before


@pytest.mark.parametrize(("role", "field_name"), _BINDING_MUTATIONS)
def test_same_store_rejects_every_persisted_role_binding_mutation_without_writes(
    tmp_path: Path, role: TrustRole, field_name: str
) -> None:
    path = tmp_path / f"binding-{role.value}-{field_name}.db"
    store = _open_store(path, None)
    before = _snapshot(store)
    changed, matching_runtime = _config_with_mutated_binding(role, field_name)

    with pytest.raises(ValueError):
        SQLiteAuthorityStore.open(path, config=changed, runtime=matching_runtime)
    assert _snapshot(_reopen_store(path)) == before

    with pytest.raises(ValueError):
        SQLiteAuthorityStore.provision(
            path, config=changed, initial_contexts=_initial_contexts()
        )
    assert _snapshot(_reopen_store(path)) == before


def test_sqlite_provision_and_open_signatures_keep_public_config_and_runtime_apart(
    tmp_path: Path,
) -> None:
    del tmp_path
    provision = inspect.signature(SQLiteAuthorityStore.provision).parameters
    writer_open = inspect.signature(SQLiteAuthorityStore.open).parameters
    reader_open = inspect.signature(SQLiteAuthorityReader.open).parameters
    assert set(provision) == {"path", "config", "initial_contexts"}
    assert (
        get_type_hints(SQLiteAuthorityStore.provision)["config"] is APCCAuthorityConfig
    )
    assert not {
        "runtime",
        "key_provider",
        "signers",
        "private_seed",
        "commit_private_seed",
        "status_private_seed",
    } & set(provision)
    assert writer_open["config"].default is inspect.Parameter.empty
    assert writer_open["runtime"].default is inspect.Parameter.empty
    assert reader_open["path"].default is inspect.Parameter.empty
    assert "runtime" not in reader_open


def test_trusted_gcb_bootstrap_requires_explicit_apcc_config_and_runtime() -> None:
    bootstrap_class = governed_commit_module.TrustedGovernanceBootstrap
    parameters = inspect.signature(bootstrap_class).parameters
    assert parameters["config"].default is inspect.Parameter.empty
    assert parameters["runtime"].default is inspect.Parameter.empty
    assert not {
        "verifier_key",
        "admin_key",
        "policy_id",
        "store_id",
    } & set(parameters)
    public_surfaces = (
        bootstrap_class,
        bootstrap_class.provision,
        bootstrap_class.open_admin,
        SQLiteAuthorityStore.provision,
        SQLiteAuthorityStore.open,
        SQLiteAuthorityReader.open,
    )
    forbidden_fragments = (
        "legacy",
        "sidecar",
        "disable",
        "enable_apcc",
        "use_apcc",
        "optional_apcc",
        "authority_path",
        "apcc_path",
        "projection",
        "fault",
        "probe",
    )
    for surface in public_surfaces:
        parameter_names = inspect.signature(surface).parameters
        assert not any(
            fragment in parameter_name.lower()
            for parameter_name in parameter_names
            for fragment in forbidden_fragments
        ), surface


def test_gcb_config_constructs_with_exact_typed_bindings() -> None:
    producer_public_key = _public_key(SEEDS["producer"])
    config = _gcb_config(producer_public_key)
    assert config.producer_trust[0] == TrustBinding(
        role=TrustRole.PRODUCER,
        scope=(
            "agent",
            "authority:dispatcher:actor-authority",
            _digest(b"dispatcher-authority-root"),
        ),
        key_id="dispatcher-producer-key",
        public_key=producer_public_key,
    )
    assert tuple(binding.role for binding in config.trust_bindings) == tuple(TrustRole)
    assert len({binding.public_key for binding in config.trust_bindings}) == 5


def _assert_all_six_private_seeds_absent(path: Path) -> None:
    persisted_files = tuple(
        candidate
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert path in persisted_files
    for seed in (*SEEDS.values(), _CONTROL_SEED):
        encodings = {
            seed,
            seed.hex().encode("ascii"),
            seed.hex().upper().encode("ascii"),
            base64.b64encode(seed),
            base64.b64encode(seed).rstrip(b"="),
            base64.urlsafe_b64encode(seed),
            base64.urlsafe_b64encode(seed).rstrip(b"="),
        }
        for persisted_file in persisted_files:
            contents = persisted_file.read_bytes()
            assert not any(encoding in contents for encoding in encodings), (
                persisted_file,
                seed,
            )


def _database_file_state(path: Path) -> tuple[tuple[str, bytes], ...]:
    # SQLite read-only WAL clients legitimately update volatile reader marks in
    # the shared-memory file.  Persisted authority bytes and sidecar shape must
    # remain unchanged; SHM lock-slot contents are not durable store state.
    return tuple(
        (
            candidate.name,
            (
                str(candidate.stat().st_size).encode("ascii")
                if candidate.name.endswith("-shm")
                else candidate.read_bytes()
            ),
        )
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )


def test_sqlite_never_persists_any_test_private_seed_or_common_encoding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "no-private-material.db"
    store = _open_store(path, None)
    request = _request(commit_id="no-private-material", nonce_byte=97)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    _assert_all_six_private_seeds_absent(path)


class _ResultSink(Protocol):
    def put(self, item: tuple[object, ...]) -> None: ...


def _spawn_reader_and_fresh_writer(path: str, results: _ResultSink) -> None:
    reader = SQLiteAuthorityReader.open(Path(path))
    logical = reader.read_logical_node("workflow-1", "node-1")
    missing_runtime_failed = False
    try:
        open_without_runtime = cast(
            Callable[..., SQLiteAuthorityStore], SQLiteAuthorityStore.open
        )
        open_without_runtime(Path(path), config=_config())
    except TypeError:
        missing_runtime_failed = True
    provider = _KeyProvider()
    runtime = AuthorityRuntime(provider, _Clock(), _OUTBOX_SINK)
    writer = SQLiteAuthorityStore.open(Path(path), config=_config(), runtime=runtime)
    results.put(
        (
            reader.authority_store_id,
            logical.current_node_version,
            missing_runtime_failed,
            writer.authority_store_id,
            provider.created_pid,
            os.getpid(),
        )
    )


def _spawn_gcb_reader(
    path: str, workflow_id: str, node_id: str, commit_id: str, results: _ResultSink
) -> None:
    reader = SQLiteAuthorityReader.open(Path(path))
    logical = reader.read_logical_node(workflow_id, node_id)
    results.put(
        (
            reader.authority_store_id,
            logical.current_node_version,
            logical.current_certificate_digest,
            reader.get_certificate(commit_id),
            os.getpid(),
        )
    )


def test_spawned_process_has_no_signer_cache_and_requires_a_fresh_runtime(
    tmp_path: Path,
) -> None:
    path = tmp_path / "spawn-reopen.db"
    _open_store(path, None)
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_spawn_reader_and_fresh_writer, args=(str(path), results)
    )
    process.start()
    process.join(timeout=20)
    assert process.exitcode == 0
    store_id, version, missing_runtime, writer_id, provider_pid, child_pid = (
        results.get(timeout=2)
    )
    assert (store_id, writer_id) == ("store-1", "store-1")
    assert version == "0"
    assert missing_runtime
    assert provider_pid == child_pid
    assert child_pid != os.getpid()


def test_sqlite_candidate_lifecycle_persists_and_illegal_order_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "lifecycle.db"
    request = _request(commit_id="lifecycle", nonce_byte=81)
    store = _open_store(path, None)
    with pytest.raises(ValueError, match=FailureCode.RESULT_NOT_STAGED.value):
        store.assemble_evidence(_assemble_evidence_request(request))
    with pytest.raises(ValueError, match=FailureCode.ILLEGAL_NODE_STATE.value):
        store.propose_commit(_propose_commit_request(request))

    staged = store.stage_result(_stage_request(request))
    assert staged.candidate_state.lifecycle is CandidateLifecycle.RESULT_STAGED
    reopened = _reopen_store(path)
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    assert (
        reopened.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.RESULT_STAGED
    )
    assembled = reopened.assemble_evidence(_assemble_evidence_request(request))
    assert assembled.candidate_state.lifecycle is CandidateLifecycle.EVIDENCE_ASSEMBLED
    reopened = _reopen_store(path)
    assert (
        reopened.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.EVIDENCE_ASSEMBLED
    )
    proposed = reopened.propose_commit(_propose_commit_request(request))
    assert proposed.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING
    reopened = _reopen_store(path)
    assert (
        reopened.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.COMMIT_PENDING
    )


def test_sqlite_conflicting_staged_result_quarantines_and_never_becomes_visible(
    tmp_path: Path,
) -> None:
    path = tmp_path / "quarantine.db"
    store = _open_store(path, None)
    request = _request(commit_id="quarantined", nonce_byte=82, node_id="child")
    store.stage_result(_stage_request(request))
    with pytest.raises(ValueError, match=FailureCode.STAGED_RESULT_CONFLICT.value):
        store.stage_result(
            StageResultRequest(
                request.subject,
                request.bindings.expected_node_version,
                b"different-output",
            )
        )
    reopened = _reopen_store(path)
    context = reopened.read_commit_context(
        CommitContextRequest(
            request.subject.workflow_id,
            request.subject.node_id,
            request.subject.attempt_id,
            request.subject.agent_id,
        )
    )
    assert context.candidate_state.lifecycle is CandidateLifecycle.QUARANTINED
    assert context.logical_node_state.current_certificate_digest is None
    assert reopened.get_certificate(request.commit_id) is None
    with pytest.raises(ValueError, match=FailureCode.QUARANTINED.value):
        reopened.assemble_evidence(_assemble_evidence_request(request))


def test_sqlite_real_transaction_conforms_to_backend_neutral_authority_contract(
    tmp_path: Path,
) -> None:
    assert_authority_store_conforms(_harness(), tmp_path)
    assert_authority_store_extended_conforms(_harness(), tmp_path)


def test_sqlite_implementation_review_staged_result_digest_binding(
    tmp_path: Path,
) -> None:
    assert_staged_result_digest_binding_conforms(_harness(), tmp_path)


def test_sqlite_implementation_review_stage_after_pending_cannot_regress(
    tmp_path: Path,
) -> None:
    assert_stage_after_commit_pending_cannot_regress_conforms(_harness(), tmp_path)


@pytest.mark.parametrize("field_name", ("committed_node_version", "output_digest"))
def test_sqlite_implementation_review_binds_every_predecessor_field(
    tmp_path: Path, field_name: str
) -> None:
    assert_predecessor_reference_field_conforms(_harness(), tmp_path, field_name)


def test_sqlite_implementation_review_checks_transitive_ancestor_revocation(
    tmp_path: Path,
) -> None:
    assert_transitive_ancestor_revocation_admission_conforms(_harness(), tmp_path)


@pytest.mark.parametrize(
    "scope",
    (RevocationScope.ACTOR, RevocationScope.WORKFLOW),
    ids=lambda scope: scope.value,
)
def test_sqlite_implementation_review_revocation_generations_are_monotonic(
    tmp_path: Path, scope: RevocationScope
) -> None:
    assert_revocation_generation_monotonicity_conforms(_harness(), tmp_path, scope)


@pytest.mark.parametrize("case", ("unknown", "revoked", "superseded"))
def test_sqlite_implementation_review_certificate_revocation_is_terminal(
    tmp_path: Path, case: str
) -> None:
    assert_certificate_revocation_terminality_conforms(_harness(), tmp_path, case)


@pytest.mark.parametrize("branch", ("committed", "denied", "conflicted"))
def test_sqlite_implementation_review_supersession_replay_identity_is_durable(
    tmp_path: Path, branch: str
) -> None:
    assert_supersession_replay_identity_conforms(_harness(), tmp_path, branch)


def test_sqlite_implementation_review_recomputes_canonical_request_digest(
    tmp_path: Path,
) -> None:
    assert_canonical_request_digest_recomputation_conforms(_harness(), tmp_path)


def test_sqlite_implementation_review_single_event_outbox_recovery_is_unique(
    tmp_path: Path,
) -> None:
    assert_repeated_single_event_outbox_recovery_conforms(_harness(), tmp_path)


def test_sqlite_implementation_review_lifecycle_and_outcome_are_orthogonal(
    tmp_path: Path,
) -> None:
    assert_lifecycle_outcome_orthogonality_conforms(_harness(), tmp_path)


def test_sqlite_implementation_review_records_complete_equivocation_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "complete-equivocation-evidence.db"
    store = _open_store(path, None)
    original = _request(commit_id="complete-conflict", nonce_byte=120)
    conflicting = _request(
        commit_id=original.commit_id,
        workflow_id="other-workflow",
        nonce_byte=121,
    )
    _advance_candidate(store, original)
    store.atomic_commit(original)
    conflict = store.atomic_commit(conflicting)
    assert conflict.decision.outcome.value == "CONFLICTED"
    original_request_digest = sqlite_store_module._operation_identity(original, None)
    conflicting_request_digest = sqlite_store_module._operation_identity(
        conflicting, None
    )

    required_columns = {
        "commit_id",
        "original_request_digest",
        "conflicting_request_digest",
        "original_workflow_id",
        "conflicting_workflow_id",
        "observation_sequence",
        "audit_event_id",
    }
    with sqlite3.connect(path) as connection:
        columns = tuple(
            row[1] for row in connection.execute("PRAGMA table_info(commit_conflicts)")
        )
        assert required_columns <= set(columns)
        row = connection.execute(
            "SELECT commit_id, original_request_digest, conflicting_request_digest, "
            "original_workflow_id, conflicting_workflow_id, observation_sequence, "
            "audit_event_id FROM commit_conflicts WHERE commit_id = ?",
            (original.commit_id,),
        ).fetchone()
    assert row == (
        original.commit_id,
        original_request_digest,
        conflicting_request_digest,
        original.subject.workflow_id,
        conflicting.subject.workflow_id,
        1,
        conflict.audit_event_id,
    )


def test_sqlite_candidate_is_bound_to_staged_result_and_signed_proposal(
    tmp_path: Path,
) -> None:
    path = tmp_path / "candidate-binding.db"
    store = _open_store(path, None)
    staged = _request(commit_id="candidate-good", nonce_byte=123)
    evil = _request(
        commit_id="candidate-evil", nonce_byte=124, result_bytes=b"evil-output"
    )
    store.stage_result(_stage_request(staged))
    before = _snapshot(store)

    with pytest.raises(ValueError, match=FailureCode.STAGED_RESULT_CONFLICT.value):
        store.assemble_evidence(_assemble_evidence_request(evil))
    assert _snapshot(store) == before

    store.assemble_evidence(_assemble_evidence_request(staged))
    store.propose_commit(_propose_commit_request(staged))
    denied = store.atomic_commit(evil)
    assert denied.decision.outcome.value == "DENIED"
    assert denied.decision.reason is FailureCode.STAGED_RESULT_CONFLICT
    assert denied.certificate_digest is None
    assert store.get_certificate(evil.commit_id) is None


def test_sqlite_pending_proposal_identity_is_exact(tmp_path: Path) -> None:
    assert_pending_proposal_identity_is_exact_conforms(_harness(), tmp_path)


def test_sqlite_commit_signer_is_used_only_for_final_authority(tmp_path: Path) -> None:
    assert_commit_signer_is_authority_only_conforms(_harness(), tmp_path)


def test_sqlite_reachable_ancestor_integrity_is_verified(tmp_path: Path) -> None:
    assert_reachable_ancestor_integrity_conforms(_harness(), tmp_path)


def test_sqlite_reachable_adjacency_matches_signed_bindings(tmp_path: Path) -> None:
    assert_reachable_adjacency_matches_signed_bindings_conforms(_harness(), tmp_path)


def test_sqlite_reachable_adjacency_cycle_fails_closed(tmp_path: Path) -> None:
    assert_reachable_adjacency_cycle_fails_closed_conforms(_harness(), tmp_path)


def test_sqlite_default_causal_limits_are_enforced(tmp_path: Path) -> None:
    assert_default_causal_limits_are_enforced_conforms(_harness(), tmp_path)


def test_sqlite_final_certificate_is_the_validated_certificate(tmp_path: Path) -> None:
    assert_final_certificate_is_the_validated_certificate_conforms(_harness(), tmp_path)


def test_sqlite_invalid_final_commit_signature_is_atomic(tmp_path: Path) -> None:
    assert_invalid_final_commit_signature_is_atomic_conforms(_harness(), tmp_path)


@pytest.mark.parametrize(
    "scope",
    (RevocationScope.ACTOR, RevocationScope.WORKFLOW),
    ids=lambda item: item.value,
)
def test_sqlite_root_revocation_generation_is_current(
    tmp_path: Path, scope: RevocationScope
) -> None:
    assert_root_revocation_generation_is_current_conforms(_harness(), tmp_path, scope)


@pytest.mark.parametrize(
    "scope",
    (RevocationScope.ACTOR, RevocationScope.WORKFLOW),
    ids=lambda item: item.value,
)
def test_sqlite_equal_revocation_generation_is_not_retroactive(
    tmp_path: Path, scope: RevocationScope
) -> None:
    assert_equal_revocation_generation_is_not_retroactive_conforms(
        _harness(), tmp_path, scope
    )


def test_sqlite_request_digest_cache_is_not_authority_bearing(tmp_path: Path) -> None:
    assert_request_digest_cache_is_not_authority_bearing_conforms(_harness(), tmp_path)


def test_sqlite_certificate_sequence_is_numeric_unique_and_survives_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "numeric-sequence.db"
    store = _open_store(path, None)
    requests: list[AtomicCommitRequest] = []
    for index in range(12):
        if index == 6:
            store = _reopen_store(path)
        request = _request(
            commit_id=f"numeric-sequence-{index}",
            nonce_byte=228 + index,
            node_id=f"depth-node-{index}",
            attempt_id=f"numeric-sequence-{index}",
        )
        _advance_candidate(store, request)
        requests.append(request)

    def commit(request: AtomicCommitRequest) -> CommitResult:
        return _reopen_store(path).atomic_commit(request)

    with ThreadPoolExecutor(max_workers=12) as executor:
        committed = list(executor.map(commit, requests))
    assert all(result.decision.outcome.value == "COMMITTED" for result in committed)
    with sqlite3.connect(path) as connection:
        columns = {
            row[1]: (row[2], row[3])
            for row in connection.execute("PRAGMA table_info(certificates)")
        }
        assert columns["sequence"] == ("INTEGER", 1)
        sequences = [
            row[0]
            for row in connection.execute(
                "SELECT sequence FROM certificates ORDER BY sequence"
            )
        ]
    assert sequences == list(range(1, 13))
    assert len(sequences) == len(set(sequences))
    digests = [result.certificate_digest for result in committed]
    assert all(digest is not None for digest in digests)
    status_sequences = sorted(
        int(store.current_status(cast(str, digest), _nonce(240)).certificate_sequence)
        for digest in digests
    )
    assert status_sequences == sequences


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("zero", FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE),
        ("wrong-key", FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE),
        ("wrong-id", FailureCode.KEY_ID_MISMATCH),
        ("malformed", FailureCode.INVALID_BASE64URL),
    ),
)
def test_sqlite_status_signer_output_is_verified_before_return(
    tmp_path: Path, mode: str, expected: FailureCode
) -> None:
    path = tmp_path / f"status-signer-{mode}.db"
    runtime = _runtime()
    SQLiteAuthorityStore.provision(
        path, config=_config(), initial_contexts=_initial_contexts()
    )
    store = SQLiteAuthorityStore.open(path, config=_config(), runtime=runtime)
    request = _request(commit_id=f"status-signer-{mode}", nonce_byte=241)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    before = _snapshot(store)
    provider = runtime.key_provider
    assert isinstance(provider, _KeyProvider)
    provider.status_signature_mode = mode
    with pytest.raises(ValueError, match=f"^{expected.value}$"):
        store.current_status(committed.certificate_digest, _nonce(242))
    assert _snapshot(store) == before


def test_sqlite_status_reads_a_consistent_ro_snapshot_while_writer_is_reserved(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status-ro-snapshot.db"
    store = _open_store(path, None)
    request = _request(commit_id="status-ro-snapshot", nonce_byte=245)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    writer = sqlite3.connect(path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")
        status = store.current_status(committed.certificate_digest, _nonce(246))
        assert status.certificate_digest == committed.certificate_digest
    finally:
        writer.rollback()
        writer.close()


def test_sqlite_read_commit_context_never_returns_a_cross_transaction_hybrid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "reader-snapshot.db"
    _open_store(path, None)
    reader = SQLiteAuthorityReader.open(path)
    original_connect = sqlite_store_module._connect_reader
    candidate_read = threading.Event()
    release = threading.Event()

    class InterleavingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(
            self, sql: str, parameters: tuple[object, ...] = ()
        ) -> sqlite3.Cursor:
            cursor = self.connection.execute(sql, parameters)
            if "FROM candidates WHERE" in sql:
                candidate_read.set()
                release.wait(timeout=5)
            return cursor

        def commit(self) -> None:
            self.connection.commit()

        def rollback(self) -> None:
            self.connection.rollback()

        def close(self) -> None:
            self.connection.close()

    monkeypatch.setattr(
        reader,
        "_connection",
        lambda: InterleavingConnection(original_connect(path)),
    )
    contexts: list[CommitContext] = []
    thread = threading.Thread(
        target=lambda: contexts.append(
            reader.read_commit_context(
                CommitContextRequest("workflow-1", "node-1", "attempt-1", "agent-1")
            )
        )
    )
    thread.start()
    assert candidate_read.wait(timeout=5)
    with sqlite3.connect(path) as writer:
        writer.execute(
            "UPDATE candidates SET lifecycle='COMMIT_PENDING' "
            "WHERE workflow_id='workflow-1' AND node_id='node-1' AND attempt_id='attempt-1'"
        )
        writer.execute(
            "UPDATE logical_nodes SET version='1' "
            "WHERE workflow_id='workflow-1' AND node_id='node-1'"
        )
    release.set()
    thread.join(timeout=5)
    assert len(contexts) == 1
    assert contexts[0].candidate_state.lifecycle is CandidateLifecycle.EXECUTING
    assert contexts[0].logical_node_state.current_node_version == "0"


@pytest.mark.parametrize("tamper", ("sequence", "workflow", "payload", "disposition"))
def test_sqlite_status_rejects_persisted_certificate_binding_corruption_before_sign(
    tmp_path: Path, tamper: str
) -> None:
    path = tmp_path / f"status-binding-{tamper}.db"
    store = _open_store(path, None)
    request = _request(commit_id=f"status-binding-{tamper}", nonce_byte=247)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    with sqlite3.connect(path) as connection:
        if tamper == "sequence":
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE certificates SET sequence=1.5 WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
        elif tamper == "workflow":
            connection.execute(
                "UPDATE certificates SET workflow_id='wrong' WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
        elif tamper == "payload":
            connection.execute(
                "UPDATE certificates SET certificate_json=? WHERE certificate_digest=?",
                (b"{}", committed.certificate_digest),
            )
        else:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("DROP TRIGGER certificate_dispositions_no_delete")
            connection.execute(
                "DELETE FROM certificate_dispositions WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
    with pytest.raises(ValueError):
        store.current_status(committed.certificate_digest, _nonce(248))


@pytest.mark.parametrize(
    "tamper", ("dangling-pointer", "mismatched-pointer", "real-sequence")
)
def test_sqlite_open_rejects_semantically_incoherent_authority_state(
    tmp_path: Path, tamper: str
) -> None:
    path = tmp_path / f"semantic-{tamper}.db"
    store = _open_store(path, None)
    request = _request(commit_id=f"semantic-{tamper}", nonce_byte=249)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        if tamper == "dangling-pointer":
            connection.execute(
                "UPDATE logical_nodes SET certificate_digest='missing' "
                "WHERE workflow_id=? AND node_id=?",
                (request.subject.workflow_id, request.subject.node_id),
            )
        elif tamper == "mismatched-pointer":
            connection.execute(
                "UPDATE certificates SET node_id='wrong' WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
        else:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE certificates SET sequence=1.5 WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
    for opener in (
        lambda: SQLiteAuthorityReader.open(path),
        lambda: SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime()),
    ):
        with pytest.raises(ValueError):
            opener()


def test_sqlite_certificate_dispositions_are_append_only_terminal_events(
    tmp_path: Path,
) -> None:
    path = tmp_path / "append-only-dispositions.db"
    store = _open_store(path, None)
    request = _request(commit_id="append-only-disposition", nonce_byte=243)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            request.subject.workflow_id,
            committed.certificate_digest,
            "1",
            "terminal append-only revocation",
        )
    )
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT event_sequence, disposition FROM certificate_dispositions "
            "WHERE certificate_digest=? ORDER BY event_sequence",
            (committed.certificate_digest,),
        ).fetchall()
        assert rows == [(1, "CURRENT"), (2, "REVOKED")]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE certificate_dispositions SET disposition='CURRENT' "
                "WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM certificate_dispositions WHERE certificate_digest=?",
                (committed.certificate_digest,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO certificate_dispositions VALUES (?, 3, 'SUPERSEDED')",
                (committed.certificate_digest,),
            )


def test_sqlite_ordinary_commit_requires_empty_pointer(tmp_path: Path) -> None:
    assert_ordinary_commit_requires_empty_pointer_conforms(_harness(), tmp_path)


def test_sqlite_revoked_current_certificate_cannot_be_superseded(
    tmp_path: Path,
) -> None:
    assert_revoked_current_certificate_cannot_be_superseded_conforms(
        _harness(), tmp_path
    )


def test_sqlite_complete_request_identity_is_guarded(tmp_path: Path) -> None:
    assert_complete_request_identity_is_guarded_conforms(_harness(), tmp_path)


def test_service_changed_unconfigured_scope_reaches_store_equivocation_guard(
    tmp_path: Path,
) -> None:
    path = tmp_path / "service-equivocation-guard.db"
    config = _config()
    runtime = _runtime()
    SQLiteAuthorityStore.provision(
        path, config=config, initial_contexts=_initial_contexts()
    )
    store = SQLiteAuthorityStore.open(path, config=config, runtime=runtime)
    service = APCCCommitService(store=store, config=config, runtime=runtime)
    request = _request(commit_id="service-equivocation-guard", nonce_byte=223)
    service.stage_result(_stage_request(request))
    service.assemble_evidence(_assemble_evidence_request(request))
    service.propose_commit(_propose_commit_request(request))
    committed = service.commit(request)
    assert committed.decision.outcome.value == "COMMITTED"
    statement = dict(request.evidence.policy_statement)
    statement["policy_id"] = "unconfigured-policy"
    conflicting = replace(
        request,
        evidence=replace(request.evidence, policy_statement=statement),
    )
    before = _snapshot(store)
    conflict = service.commit(conflicting)
    assert conflict.decision.outcome.value == "CONFLICTED"
    assert conflict.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
    _only_conflict_and_audit(before, _snapshot(store), request.commit_id)


def test_sqlite_negative_decisions_reserve_nonce(tmp_path: Path) -> None:
    assert_negative_decisions_reserve_nonce_conforms(_harness(), tmp_path)


@pytest.mark.parametrize(
    ("column", "replacement"),
    (
        ("expected_version", "9"),
        ("context_json", '{"policy_id":"tampered"}'),
        ("predecessors_json", '[{"commit_id":"tampered"}]'),
    ),
)
def test_sqlite_lifecycle_advancement_rejects_tampered_durable_candidate_binding(
    tmp_path: Path, column: str, replacement: str
) -> None:
    path = tmp_path / f"candidate-{column}.db"
    store = _open_store(path, None)
    request = _request(commit_id=f"candidate-{column}", nonce_byte=125)
    store.stage_result(_stage_request(request))
    evidence_already_assembled = column in {"context_json", "predecessors_json"}
    if evidence_already_assembled:
        store.assemble_evidence(_assemble_evidence_request(request))
    with sqlite3.connect(path) as connection:
        connection.execute(
            f'UPDATE candidates SET "{column}"=? WHERE workflow_id=? AND node_id=? AND attempt_id=?',
            (
                replacement,
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
    before = _snapshot(store)
    with pytest.raises(ValueError, match=FailureCode.STAGED_RESULT_CONFLICT.value):
        if evidence_already_assembled:
            store.propose_commit(_propose_commit_request(request))
        else:
            store.assemble_evidence(_assemble_evidence_request(request))
    assert _snapshot(store) == before


def test_sqlite_static_proof_failure_precedes_stale_active_state(
    tmp_path: Path,
) -> None:
    store = _open_store(tmp_path / "static-precedence.db", None)
    valid = _request(commit_id="static-valid", nonce_byte=126)
    _advance_candidate(store, valid)
    stale = _request(
        commit_id="static-invalid",
        nonce_byte=127,
        expected_node_version="9",
    )
    invalid = replace(
        stale,
        signatures=replace(
            stale.signatures,
            producer=replace(
                stale.signatures.producer, signature_b64u=_b64u(bytes(64))
            ),
        ),
    )
    denied = store.atomic_commit(invalid)
    assert denied.decision.reason is FailureCode.INVALID_PRODUCER_SIGNATURE
    assert denied.certificate_digest is None


def test_sqlite_predecessor_payload_is_digest_pinned_and_verified(
    tmp_path: Path,
) -> None:
    path = tmp_path / "predecessor-payload-pin.db"
    store = _open_store(path, None)
    parent_request = _request(commit_id="pin-parent", nonce_byte=128, node_id="root")
    _advance_candidate(store, parent_request)
    parent = store.atomic_commit(parent_request)
    assert parent.certificate_digest is not None
    with sqlite3.connect(path) as connection:
        (payload,) = connection.execute(
            "SELECT certificate_json FROM certificates WHERE certificate_digest=?",
            (parent.certificate_digest,),
        ).fetchone()
        certificate = decode_certificate(bytes(payload))
        tampered = replace(
            certificate,
            context=replace(certificate.context, policy_version="999"),
        )
        connection.execute(
            "UPDATE certificates SET certificate_json=? WHERE certificate_digest=?",
            (encode_certificate(tampered), parent.certificate_digest),
        )
    child = _request(
        commit_id="pin-child",
        nonce_byte=129,
        node_id="child",
        predecessors=[_predecessor(parent_request, parent)],
    )
    _advance_candidate(store, child)
    denied = store.atomic_commit(child)
    assert denied.decision.reason is FailureCode.INVALID_PREDECESSOR
    assert denied.certificate_digest is None


def test_sqlite_negative_reservation_preserves_original_workflow_for_equivocation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "negative-workflow-provenance.db"
    store = _open_store(path, None)
    denied_request = _request(commit_id="negative-origin", nonce_byte=1)
    denied = store.atomic_commit(denied_request)
    assert denied.decision.reason is FailureCode.RESULT_NOT_STAGED
    conflicting = _request(
        commit_id=denied_request.commit_id,
        nonce_byte=130,
        workflow_id="workflow-2",
    )
    conflict = store.atomic_commit(conflicting)
    assert conflict.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
    with sqlite3.connect(path) as connection:
        workflows = connection.execute(
            "SELECT original_workflow_id, conflicting_workflow_id "
            "FROM commit_conflicts WHERE commit_id=?",
            (denied_request.commit_id,),
        ).fetchone()
    assert workflows == (
        denied_request.subject.workflow_id,
        conflicting.subject.workflow_id,
    )


def _semantic_tables(
    connection: sqlite3.Connection, required_columns: set[str]
) -> tuple[str, ...]:
    matches = []
    for (table_name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ):
        columns = {
            row[1]
            for row in connection.execute(
                f'PRAGMA table_info("{table_name.replace(chr(34), chr(34) * 2)}")'
            )
        }
        if required_columns <= columns:
            matches.append(table_name)
    assert matches, required_columns
    return tuple(matches)


def _semantic_table(connection: sqlite3.Connection, required_columns: set[str]) -> str:
    matches = _semantic_tables(connection, required_columns)
    assert len(matches) == 1, (required_columns, matches)
    return matches[0]


def _assert_savepoint_update_rejected(
    connection: sqlite3.Connection,
    *,
    identifying_columns: set[str],
    column: str,
    invalid_value: object,
) -> None:
    table = _semantic_table(connection, identifying_columns | {column})
    quoted_table = table.replace('"', '""')
    quoted_column = column.replace('"', '""')
    assert connection.execute(f'SELECT count(*) FROM "{quoted_table}"').fetchone()[0]
    connection.execute("SAVEPOINT defensive_contract_probe")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f'UPDATE "{quoted_table}" SET "{quoted_column}" = ?',
                (invalid_value,),
            )
    finally:
        connection.execute("ROLLBACK TO defensive_contract_probe")
        connection.execute("RELEASE defensive_contract_probe")


def _assert_orphan_commit_reference_rejected(
    connection: sqlite3.Connection,
) -> None:
    rejected = 0
    for table in _semantic_tables(connection, {"request_digest", "commit_id"}):
        quoted_table = table.replace('"', '""')
        connection.execute("SAVEPOINT orphan_contract_probe")
        try:
            try:
                connection.execute(
                    f'UPDATE "{quoted_table}" SET commit_id = ?',
                    ("missing-commit",),
                )
            except sqlite3.IntegrityError:
                rejected += 1
        finally:
            connection.execute("ROLLBACK TO orphan_contract_probe")
            connection.execute("RELEASE orphan_contract_probe")
    assert rejected >= 1


def test_sqlite_implementation_review_schema_rejects_invalid_persisted_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "defensive-schema.db"
    store = _open_store(path, None)
    request = _request(commit_id="defensive-schema", nonce_byte=122)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            RevocationScope.WORKFLOW,
            request.subject.workflow_id,
            request.subject.workflow_id,
            "1",
            "populate generation state",
        )
    )
    store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            request.subject.workflow_id,
            request.subject.agent_id,
            "1",
            "populate actor generation state",
        )
    )
    before = _snapshot(store)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        probes = (
            ({"workflow_id", "node_id", "attempt_id", "agent_id"}, "agent_id", None),
            ({"certificate_digest", "certificate_json"}, "certificate_json", None),
            ({"attempt_id", "lifecycle"}, "lifecycle", "INVALID"),
            ({"outcome", "reason", "nonce"}, "outcome", "INVALID"),
            ({"certificate_digest", "disposition"}, "disposition", "INVALID"),
            ({"event_id", "delivered"}, "delivered", 2),
            ({"workflow_id", "node_id", "version"}, "version", "01"),
            ({"workflow_id", "actor_id", "generation"}, "generation", "01"),
        )
        for identifying_columns, column, invalid_value in probes:
            _assert_savepoint_update_rejected(
                connection,
                identifying_columns=identifying_columns,
                column=column,
                invalid_value=invalid_value,
            )
        _assert_orphan_commit_reference_rejected(connection)
    assert _snapshot(store) == before


def test_sqlite_successful_commit_revoke_and_supersede_have_exact_authority_deltas(
    tmp_path: Path,
) -> None:
    commit_store = _open_store(tmp_path / "exact-commit-delta.db", None)
    commit_request = _request(commit_id="delta-commit", nonce_byte=90)
    _advance_candidate(commit_store, commit_request)
    staged = _snapshot(commit_store)
    committed = commit_store.atomic_commit(commit_request)
    assert committed.certificate_digest
    _assert_exact_authority_delta(
        staged,
        _snapshot(commit_store),
        changed_tables=_commit_write_tables(commit_request),
        pointer_changed=True,
    )

    revocation_store = _open_store(tmp_path / "exact-revocation-delta.db", None)
    revocation_request = _request(commit_id="delta-revoked", nonce_byte=91)
    _advance_candidate(revocation_store, revocation_request)
    revocation_target = revocation_store.atomic_commit(revocation_request)
    assert revocation_target.certificate_digest
    before_revoke = _snapshot(revocation_store)
    revoked = revocation_store.revoke(
        RevocationRequest(
            RevocationScope.WORKFLOW,
            revocation_request.subject.workflow_id,
            revocation_request.subject.workflow_id,
            "1",
            "exercise exact revocation delta",
        )
    )
    assert revoked.audit_event_id
    _assert_exact_authority_delta(
        before_revoke,
        _snapshot(revocation_store),
        changed_tables=_WORKFLOW_REVOCATION_WRITE_TABLES,
        pointer_changed=False,
    )

    certificate_store = _open_store(
        tmp_path / "exact-certificate-revocation-delta.db", None
    )
    certificate_request = _request(commit_id="delta-certificate", nonce_byte=94)
    _advance_candidate(certificate_store, certificate_request)
    certificate_target = certificate_store.atomic_commit(certificate_request)
    assert certificate_target.certificate_digest
    before_certificate_revoke = _snapshot(certificate_store)
    certificate_store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            certificate_request.subject.workflow_id,
            certificate_target.certificate_digest,
            "1",
            "exercise exact certificate revocation delta",
        )
    )
    _assert_exact_authority_delta(
        before_certificate_revoke,
        _snapshot(certificate_store),
        changed_tables=_CERTIFICATE_REVOCATION_WRITE_TABLES,
        pointer_changed=False,
    )

    actor_store = _open_store(tmp_path / "exact-actor-revocation-delta.db", None)
    actor_request = _request(commit_id="delta-actor", nonce_byte=95)
    _advance_candidate(actor_store, actor_request)
    actor_store.atomic_commit(actor_request)
    before_actor_revoke = _snapshot(actor_store)
    actor_store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            actor_request.subject.workflow_id,
            actor_request.subject.agent_id,
            "1",
            "exercise exact actor revocation delta",
        )
    )
    _assert_exact_authority_delta(
        before_actor_revoke,
        _snapshot(actor_store),
        changed_tables=_ACTOR_REVOCATION_WRITE_TABLES,
        pointer_changed=False,
    )

    supersession_store = _open_store(tmp_path / "exact-supersession-delta.db", None)
    original_request = _request(commit_id="delta-original", nonce_byte=92)
    _advance_candidate(supersession_store, original_request)
    original = supersession_store.atomic_commit(original_request)
    assert original.certificate_digest
    replacement = _request(
        commit_id="delta-replacement",
        nonce_byte=93,
        expected_node_version="1",
        attempt_id="delta-replacement-attempt",
    )
    _advance_candidate(supersession_store, replacement)
    before_supersession = _snapshot(supersession_store)
    superseded = supersession_store.supersede(
        SupersessionRequest(original.certificate_digest, replacement)
    )
    assert isinstance(superseded, SupersessionCommitted)
    assert superseded.outbox_event_id
    assert superseded.commit_result.audit_event_id
    _assert_exact_authority_delta(
        before_supersession,
        _snapshot(supersession_store),
        changed_tables=_supersession_write_tables(replacement),
        pointer_changed=True,
    )


@pytest.mark.parametrize(
    "fault_point",
    (
        "before_verification",
        "after_verification",
        "before_commit_index_reservation",
        "after_commit_index_reservation",
        "before_request_index_write",
        "after_request_index_write",
        "before_nonce_ledger",
        "after_nonce_ledger",
        "before_candidate_update",
        "after_candidate_update",
        "before_audit_write",
        "after_audit_write",
        "before_evidence_refs",
        "after_evidence_refs",
        "before_predecessor_edges",
        "after_predecessor_edges",
        "before_seal",
        "after_seal",
        "before_node_write",
        "after_node_write",
        "before_node_pointer_write",
        "after_node_pointer_write",
        "before_certificate_write",
        "after_certificate_write",
        "before_decision_write",
        "after_decision_write",
        "before_disposition_write",
        "after_disposition_write",
        "before_trust_log_write",
        "after_trust_log_write",
        "before_outbox_write",
        "after_outbox_write",
        "before_commit",
    ),
)
def test_sqlite_faults_before_each_authority_write_rollback_everything(
    tmp_path: Path, fault_point: str
) -> None:
    assert_fault_is_atomic(_harness(), tmp_path, fault_point)


@pytest.mark.parametrize(
    "point",
    (
        "before_revocation_fence",
        "after_revocation_fence",
        "before_revocation_trust_log_write",
        "after_revocation_trust_log_write",
        "before_revocation_audit_write",
        "after_revocation_audit_write",
        "before_revocation_outbox_write",
        "after_revocation_outbox_write",
        "before_revocation_commit",
    ),
)
@pytest.mark.parametrize("scope", tuple(RevocationScope))
def test_sqlite_revocation_write_faults_preserve_the_pre_operation_snapshot(
    tmp_path: Path, point: str, scope: RevocationScope
) -> None:
    _assert_revocation_fault_is_atomic(tmp_path, point, scope)


@pytest.mark.parametrize(
    "point",
    (
        "before_revocation_generation_write",
        "after_revocation_generation_write",
    ),
)
@pytest.mark.parametrize("scope", (RevocationScope.ACTOR, RevocationScope.WORKFLOW))
def test_sqlite_generation_revocation_faults_preserve_the_pre_operation_snapshot(
    tmp_path: Path, point: str, scope: RevocationScope
) -> None:
    _assert_revocation_fault_is_atomic(tmp_path, point, scope)


def _assert_revocation_fault_is_atomic(
    tmp_path: Path, point: str, scope: RevocationScope
) -> None:
    path = tmp_path / f"revocation-{scope.value.lower()}-{point}.db"
    setup = _open_store(path, None)
    request = _request(
        commit_id=f"revocation-{scope.value.lower()}-{point}", nonce_byte=60
    )
    _advance_candidate(setup, request)
    committed = setup.atomic_commit(request)
    assert committed.certificate_digest
    target = {
        RevocationScope.CERTIFICATE: committed.certificate_digest,
        RevocationScope.ACTOR: request.subject.agent_id,
        RevocationScope.WORKFLOW: request.subject.workflow_id,
    }[scope]
    store = _open_store(path, _FailController(point))
    before = _snapshot(store)
    with pytest.raises(_InjectedFault):
        store.revoke(
            RevocationRequest(
                scope,
                request.subject.workflow_id,
                target,
                "1",
                "fault",
            )
        )
    assert _snapshot(store) == before
    assert (
        store.get_certificate(request.commit_id) == committed.certificate_envelope_bytes
    )


@pytest.mark.parametrize(
    "point",
    ("before_revocation_disposition_write", "after_revocation_disposition_write"),
)
def test_sqlite_certificate_revocation_disposition_faults_preserve_snapshot(
    tmp_path: Path, point: str
) -> None:
    path = tmp_path / f"certificate-revocation-{point}.db"
    setup = _open_store(path, None)
    request = _request(commit_id=f"certificate-revocation-{point}", nonce_byte=63)
    _advance_candidate(setup, request)
    committed = setup.atomic_commit(request)
    assert committed.certificate_digest
    store = _open_store(path, _FailController(point))
    before = _snapshot(store)
    with pytest.raises(_InjectedFault):
        store.revoke(
            RevocationRequest(
                RevocationScope.CERTIFICATE,
                request.subject.workflow_id,
                committed.certificate_digest,
                "1",
                "certificate fault",
            )
        )
    assert _snapshot(store) == before


@pytest.mark.parametrize(
    "point",
    (
        "before_supersession_commit_index_reservation",
        "after_supersession_commit_index_reservation",
        "before_supersession_request_index_write",
        "after_supersession_request_index_write",
        "before_supersession_verification",
        "after_supersession_verification",
        "before_supersession_nonce_ledger",
        "after_supersession_nonce_ledger",
        "before_supersession_candidate_update",
        "after_supersession_candidate_update",
        "before_supersession_evidence_refs",
        "after_supersession_evidence_refs",
        "before_supersession_predecessor_edges",
        "after_supersession_predecessor_edges",
        "before_supersession_seal",
        "after_supersession_seal",
        "before_supersession_certificate_write",
        "after_supersession_certificate_write",
        "before_supersession_decision_write",
        "after_supersession_decision_write",
        "before_supersession_old_disposition_write",
        "after_supersession_old_disposition_write",
        "before_supersession_new_disposition_write",
        "after_supersession_new_disposition_write",
        "before_supersession_replacement_edge_write",
        "after_supersession_replacement_edge_write",
        "before_supersession_node_pointer_write",
        "after_supersession_node_pointer_write",
        "before_supersession_trust_log_write",
        "after_supersession_trust_log_write",
        "before_supersession_audit_write",
        "after_supersession_audit_write",
        "before_supersession_outbox_write",
        "after_supersession_outbox_write",
        "before_supersession_commit",
    ),
)
def test_sqlite_supersession_write_faults_preserve_old_authority(
    tmp_path: Path, point: str
) -> None:
    assert_supersession_fault_is_atomic(_harness(), tmp_path, point)


def test_sqlite_supersession_response_loss_recovers_one_exact_durable_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supersession-response-loss.db"
    setup = _open_store(path, None)
    original_request = _request(commit_id="lost-old", nonce_byte=92)
    _advance_candidate(setup, original_request)
    original = setup.atomic_commit(original_request)
    assert original.certificate_digest is not None

    crashing = _open_store(
        path, _FailController("after_supersession_commit_before_response")
    )
    replacement_request = _request(
        commit_id="lost-new",
        nonce_byte=93,
        expected_node_version="1",
        attempt_id="lost-replacement-attempt",
    )
    _advance_candidate(crashing, replacement_request)
    with pytest.raises(
        _InjectedFault, match="after_supersession_commit_before_response"
    ):
        crashing.supersede(
            SupersessionRequest(original.certificate_digest, replacement_request)
        )

    reopened = _reopen_store(path)
    persisted = _snapshot(reopened)
    replay = reopened.replay_commit(
        ReplayCommitRequest(
            replacement_request.commit_id, replacement_request.request_digest
        )
    )
    assert replay.decision.commit_id == replacement_request.commit_id
    assert replay.certificate_envelope_bytes == reopened.get_certificate(
        replacement_request.commit_id
    )
    assert replay.certificate_payload_bytes and replay.certificate_digest
    assert (
        reopened.get_certificate(original_request.commit_id)
        == original.certificate_envelope_bytes
    )

    old_status = reopened.current_status(original.certificate_digest, _nonce(94))
    new_status = reopened.current_status(replay.certificate_digest, _nonce(95))
    assert old_status.superseded.value == "yes"
    assert new_status.superseded.value == "no"
    context = reopened.read_commit_context(
        CommitContextRequest(
            replacement_request.subject.workflow_id,
            replacement_request.subject.node_id,
            replacement_request.subject.attempt_id,
            replacement_request.subject.agent_id,
        )
    )
    assert (
        context.logical_node_state.current_certificate_digest
        == replay.certificate_digest
    )
    assert (
        replay.certificate_digest.encode("ascii")
        in persisted.tables["certificate_dispositions"][-1]
    )
    edge = persisted.tables["supersession_edges"][-1]
    assert original.certificate_digest.encode("ascii") in edge
    assert replay.certificate_digest.encode("ascii") in edge
    decision = persisted.tables["decisions"][-1]
    assert replacement_request.commit_id.encode("utf-8") in decision
    assert replacement_request.nonce.encode("ascii") in decision
    outbox = _outbox_event(reopened, replacement_request.commit_id)
    assert outbox.event_id and outbox.payload and outbox.audit_event_id
    assert outbox.pending
    assert _snapshot(reopened) == persisted
    exact = reopened.supersede(
        SupersessionRequest(original.certificate_digest, replacement_request)
    )
    assert isinstance(exact, SupersessionCommitted)
    assert exact.commit_result == replay
    assert _snapshot(reopened) == persisted
    changed_operation = reopened.atomic_commit(replacement_request)
    assert changed_operation.decision.outcome is RequestOutcome.CONFLICTED
    assert changed_operation.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION


def test_sqlite_supersession_preserves_committed_children_and_rejects_stale_pending(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supersession-predecessors.db"
    store = _open_store(path, None)
    root_request = _request(commit_id="pred-root", nonce_byte=83, node_id="root")
    _advance_candidate(store, root_request)
    root = store.atomic_commit(root_request)
    assert root.certificate_digest is not None
    root_ref = _predecessor(root_request, root)

    committed_child_request = _request(
        commit_id="pred-child",
        nonce_byte=84,
        node_id="child",
        predecessors=[root_ref],
    )
    _advance_candidate(store, committed_child_request)
    committed_child = store.atomic_commit(committed_child_request)
    pending_leaf_request = _request(
        commit_id="pred-leaf-pending",
        nonce_byte=85,
        node_id="leaf",
        predecessors=[root_ref],
    )
    _advance_candidate(store, pending_leaf_request)

    replacement_request = _request(
        commit_id="pred-root-v2",
        nonce_byte=86,
        node_id="root",
        expected_node_version="1",
        attempt_id="pred-root-replacement",
    )
    _advance_candidate(store, replacement_request)
    replacement = store.supersede(
        SupersessionRequest(root.certificate_digest, replacement_request)
    )
    terminal = _snapshot(store)
    assert (
        store.supersede(
            SupersessionRequest(root.certificate_digest, replacement_request)
        )
        == replacement
    )
    assert _snapshot(store) == terminal

    assert committed_child.certificate_digest
    child_status = store.current_status(committed_child.certificate_digest, _nonce(87))
    assert child_status.status.value == "current"
    assert child_status.superseded.value == "no"
    rejected = store.atomic_commit(pending_leaf_request)
    assert rejected.decision.outcome.value == "DENIED"
    assert rejected.decision.reason is FailureCode.PREDECESSOR_REPLACED
    assert rejected.certificate_envelope_bytes is None
    rejected_snapshot = _snapshot(store)
    assert store.atomic_commit(pending_leaf_request) == rejected
    assert _snapshot(store) == rejected_snapshot

    # The immutable global commit-id ledger is checked before the now-stale old
    # pointer, candidate version, or predecessor bindings.
    conflicting = _request(
        commit_id=replacement_request.commit_id,
        nonce_byte=88,
        node_id="root",
        expected_node_version="0",
        attempt_id="stale-equivocating-replacement",
    )
    conflicted = store.supersede(
        SupersessionRequest(root.certificate_digest, conflicting)
    )
    assert isinstance(conflicted, SupersessionConflicted)
    assert conflicted.commit_result.decision.outcome.value == "CONFLICTED"
    assert (
        conflicted.commit_result.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
    )
    conflict_snapshot = _snapshot(store)
    assert (
        store.supersede(SupersessionRequest(root.certificate_digest, conflicting))
        == conflicted
    )
    assert _snapshot(store) == conflict_snapshot


def test_sqlite_status_is_nonce_bound_and_reflects_revocation_supersession_and_rollback(
    tmp_path: Path,
) -> None:
    store = _open_store(tmp_path / "status.db", None)
    request = _request(commit_id="status-1", nonce_byte=20)
    _advance_candidate(store, request)
    result = store.atomic_commit(request)
    assert result.certificate_digest is not None and result.certificate_envelope_bytes

    status = store.current_status(result.certificate_digest, _nonce(21))
    assert status.request_nonce == _nonce(21)
    assert int(status.this_update_ms) < int(status.next_update_ms)
    assert status.certificate_digest == result.certificate_digest
    trust = valid_vector().trust
    assert verify_current(
        result.certificate_envelope_bytes,
        trust=trust,
        authority_status=status,
        request_nonce=_nonce(21),
        now_ms=status.this_update_ms,
        highest_trust_log_sequence=status.trust_log_sequence,
        highest_trust_log_head=status.trust_log_head,
        maximum_staleness_ms="5000",
    ).ok
    assert int(status.this_update_ms) + 2 < int(status.next_update_ms)
    assert (
        verify_current(
            result.certificate_envelope_bytes,
            trust=trust,
            authority_status=status,
            request_nonce=_nonce(21),
            now_ms=str(int(status.this_update_ms) + 2),
            highest_trust_log_sequence=status.trust_log_sequence,
            highest_trust_log_head=status.trust_log_head,
            maximum_staleness_ms="1",
        ).code
        is FailureCode.AUTHORITY_STATUS_EXPIRED
    )

    replacement = _request(
        commit_id="status-2",
        nonce_byte=24,
        expected_node_version="1",
        attempt_id="attempt-status-2",
    )
    _advance_candidate(store, replacement)
    superseded = store.supersede(
        SupersessionRequest(result.certificate_digest, replacement)
    )
    assert isinstance(superseded, SupersessionCommitted)
    old_status = store.current_status(result.certificate_digest, _nonce(25))
    assert old_status.superseded.value == "yes"
    assert (
        verify_current(
            result.certificate_envelope_bytes,
            trust=trust,
            authority_status=old_status,
            request_nonce=_nonce(25),
            now_ms=old_status.this_update_ms,
            highest_trust_log_sequence=old_status.trust_log_sequence,
            highest_trust_log_head=old_status.trust_log_head,
            maximum_staleness_ms="5000",
        ).code
        is FailureCode.AUTHORITY_STATUS_SUPERSEDED
    )
    new_status = store.current_status(superseded.new_certificate_digest, _nonce(26))
    assert new_status.superseded.value == "no"
    assert int(new_status.trust_log_sequence) > int(status.trust_log_sequence)
    assert new_status.trust_log_head != status.trust_log_head

    revoked = store.revoke(
        RevocationRequest(
            RevocationScope.WORKFLOW,
            request.subject.workflow_id,
            request.subject.workflow_id,
            "5",
            "conformance revocation",
        )
    )
    assert revoked.resulting_generation == "5"
    after_revoke = store.current_status(result.certificate_digest, _nonce(22))
    assert after_revoke.status.value == "revoked"
    assert (
        verify_current(
            result.certificate_envelope_bytes,
            trust=trust,
            authority_status=after_revoke,
            request_nonce=_nonce(22),
            now_ms=after_revoke.this_update_ms,
            highest_trust_log_sequence=after_revoke.trust_log_sequence,
            highest_trust_log_head=after_revoke.trust_log_head,
            maximum_staleness_ms="5000",
        ).code
        is FailureCode.AUTHORITY_STATUS_REVOKED
    )

    # A later status must never go backwards below a previously observed head.
    reopened = _reopen_store(tmp_path / "status.db")
    after_recovery = reopened.current_status(
        superseded.new_certificate_digest, _nonce(23)
    )
    assert int(after_recovery.trust_log_sequence) > int(new_status.trust_log_sequence)
    assert after_recovery.trust_log_head != new_status.trust_log_head


def test_sqlite_transitive_ancestor_revocation_denies_successor_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "transitive-revocation.db"
    store = _open_store(path, None)
    root_request = _request(commit_id="root", nonce_byte=72, node_id="root")
    _advance_candidate(store, root_request)
    root = store.atomic_commit(root_request)
    assert root.certificate_digest
    middle_request = _request(
        commit_id="middle",
        nonce_byte=73,
        node_id="middle",
        predecessors=[_predecessor(root_request, root)],
    )
    _advance_candidate(store, middle_request)
    middle = store.atomic_commit(middle_request)
    leaf_request = _request(
        commit_id="leaf",
        nonce_byte=74,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _advance_candidate(store, leaf_request)
    leaf = store.atomic_commit(leaf_request)
    assert leaf.certificate_digest and leaf.certificate_envelope_bytes
    pre_revoke = store.current_status(leaf.certificate_digest, _nonce(75))
    reopened = _reopen_store(path)
    reopened.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            leaf_request.subject.workflow_id,
            root.certificate_digest,
            "1",
            "root certificate revoked",
        )
    )
    current = reopened.current_status(leaf.certificate_digest, _nonce(76))
    assert int(current.trust_log_sequence) > int(pre_revoke.trust_log_sequence)
    assert current.trust_log_head != pre_revoke.trust_log_head
    assert (
        verify_current(
            leaf.certificate_envelope_bytes,
            trust=valid_vector().trust,
            authority_status=pre_revoke,
            request_nonce=_nonce(75),
            now_ms=pre_revoke.this_update_ms,
            highest_trust_log_sequence=current.trust_log_sequence,
            highest_trust_log_head=current.trust_log_head,
            maximum_staleness_ms="5000",
        ).code
        is FailureCode.AUTHORITY_STATUS_ROLLBACK
    )
    assert (
        verify_current(
            leaf.certificate_envelope_bytes,
            trust=valid_vector().trust,
            authority_status=current,
            request_nonce=_nonce(76),
            now_ms=current.this_update_ms,
            highest_trust_log_sequence=current.trust_log_sequence,
            highest_trust_log_head=current.trust_log_head,
            maximum_staleness_ms="5000",
        ).code
        is FailureCode.AUTHORITY_STATUS_REVOKED
    )


def test_sqlite_actor_revocation_is_scoped_to_exact_workflow_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "actor-scope.db"
    store = _open_store(path, None)
    first_request = _request(commit_id="actor-w1", nonce_byte=77)
    second_request = _request(
        commit_id="actor-w2", nonce_byte=78, workflow_id="workflow-2"
    )
    for request in (first_request, second_request):
        _advance_candidate(store, request)
    first = store.atomic_commit(first_request)
    second = store.atomic_commit(second_request)
    assert first.certificate_digest and second.certificate_digest

    store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            first_request.subject.workflow_id,
            first_request.subject.agent_id,
            str(int(first_request.context.agent_revocation_generation) + 1),
            "workflow-scoped actor revocation",
        )
    )
    reopened = _reopen_store(path)
    assert (
        reopened.current_status(first.certificate_digest, _nonce(79)).status.value
        == "revoked"
    )
    assert (
        reopened.current_status(second.certificate_digest, _nonce(80)).status.value
        == "current"
    )


@pytest.mark.parametrize(
    ("changes", "nonce", "highest_sequence", "expected"),
    (
        ({}, _nonce(99), None, FailureCode.AUTHORITY_STATUS_NONCE_MISMATCH),
        (
            {"next_update_ms": "0"},
            _nonce(40),
            None,
            FailureCode.AUTHORITY_STATUS_EXPIRED,
        ),
        (
            {"trust_log_sequence": "0"},
            _nonce(40),
            "1",
            FailureCode.AUTHORITY_STATUS_ROLLBACK,
        ),
        ({"status": "revoked"}, _nonce(40), None, FailureCode.AUTHORITY_STATUS_REVOKED),
        (
            {"superseded": "yes"},
            _nonce(40),
            None,
            FailureCode.AUTHORITY_STATUS_SUPERSEDED,
        ),
    ),
)
def test_sqlite_statuses_are_independently_verified_fail_closed(
    tmp_path: Path,
    changes: dict[str, str],
    nonce: str,
    highest_sequence: str | None,
    expected: FailureCode,
) -> None:
    store = _open_store(tmp_path / "status-codes.db", None)
    request = _request(commit_id="status-codes", nonce_byte=40)
    _advance_candidate(store, request)
    result = store.atomic_commit(request)
    assert result.certificate_envelope_bytes and result.certificate_digest
    issued = store.current_status(result.certificate_digest, _nonce(40))
    verdict = verify_current(
        result.certificate_envelope_bytes,
        trust=valid_vector().trust,
        authority_status=_resigned_status(issued, **changes),
        request_nonce=nonce,
        now_ms=issued.this_update_ms,
        highest_trust_log_sequence=highest_sequence or issued.trust_log_sequence,
        highest_trust_log_head=issued.trust_log_head,
        maximum_staleness_ms="5000",
    )
    assert verdict.code is expected


def test_sqlite_status_signature_tamper_is_independently_rejected(
    tmp_path: Path,
) -> None:
    store = _open_store(tmp_path / "status-signature.db", None)
    request = _request(commit_id="status-signature", nonce_byte=41)
    _advance_candidate(store, request)
    result = store.atomic_commit(request)
    assert result.certificate_envelope_bytes and result.certificate_digest
    issued = store.current_status(result.certificate_digest, _nonce(41))
    tampered = issued.to_object()
    signature = tampered["signature"]
    assert isinstance(signature, dict)
    signature["signature_b64u"] = _b64u(bytes(64))
    verdict = verify_current(
        result.certificate_envelope_bytes,
        trust=valid_vector().trust,
        authority_status=tampered,
        request_nonce=_nonce(41),
        now_ms=issued.this_update_ms,
        highest_trust_log_sequence=issued.trust_log_sequence,
        highest_trust_log_head=issued.trust_log_head,
        maximum_staleness_ms="5000",
    )
    assert verdict.code is FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE


@pytest.mark.parametrize(
    ("changes", "expected"),
    (
        (
            {"trust_log_head": _digest(b"other-head")},
            FailureCode.AUTHORITY_STATUS_ROLLBACK,
        ),
        (
            {"actor_revocation_generation": "not-a-decimal"},
            FailureCode.INVALID_DECIMAL_STRING,
        ),
    ),
)
def test_sqlite_status_same_sequence_head_and_decimal_fields_fail_closed(
    tmp_path: Path, changes: dict[str, str], expected: FailureCode
) -> None:
    store = _open_store(tmp_path / "status-extra.db", None)
    request = _request(commit_id="status-extra", nonce_byte=42)
    _advance_candidate(store, request)
    result = store.atomic_commit(request)
    assert result.certificate_envelope_bytes and result.certificate_digest
    issued = store.current_status(result.certificate_digest, _nonce(42))
    verdict = verify_current(
        result.certificate_envelope_bytes,
        trust=valid_vector().trust,
        authority_status=_resigned_status(issued, **changes),
        request_nonce=_nonce(42),
        now_ms=issued.this_update_ms,
        highest_trust_log_sequence=issued.trust_log_sequence,
        highest_trust_log_head=issued.trust_log_head,
        maximum_staleness_ms="5000",
    )
    assert verdict.code is expected


def test_sqlite_post_commit_response_loss_reopens_to_the_exact_authority_tuple(
    tmp_path: Path,
) -> None:
    store = _open_store(
        tmp_path / "response-loss.db", _FailController("after_commit_before_response")
    )
    request = _request(commit_id="response-loss", nonce_byte=30)
    _advance_candidate(store, request)
    with pytest.raises(_InjectedFault):
        store.atomic_commit(request)
    reopened = _reopen_store(tmp_path / "response-loss.db")
    persisted = _snapshot(reopened)
    envelope = reopened.get_certificate(request.commit_id)
    assert envelope is not None
    assert persisted.current_pointers
    assert any(
        b"response-loss" in row for rows in persisted.tables.values() for row in rows
    )
    recovered = reopened.replay_commit(
        ReplayCommitRequest(request.commit_id, request.request_digest)
    )
    assert recovered.certificate_envelope_bytes == envelope
    assert recovered.certificate_payload_bytes
    assert recovered.certificate_digest
    assert recovered.audit_event_id
    assert _snapshot(reopened) == persisted
    assert reopened.atomic_commit(request) == recovered
    assert _snapshot(reopened) == persisted


def test_sqlite_pending_crash_recovery_cannot_manufacture_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pending-crash.db"
    store = _open_store(path, _FailController("before_commit"))
    request = _request(commit_id="pending-crash", nonce_byte=62)
    _advance_candidate(store, request)
    before = _snapshot(store)
    with pytest.raises(_InjectedFault, match="before_commit"):
        store.atomic_commit(request)
    assert _snapshot(store) == before
    reopened = _reopen_store(path)
    before_recovery = _snapshot(reopened)
    recovered = reopened.recover(
        RecoveryRequest(request.commit_id, request.request_digest)
    )
    assert recovered.decision.outcome.value == "DENIED"
    assert recovered.decision.reason is FailureCode.AUTHORITY_FROM_RECOVERY_DENIED
    assert reopened.get_certificate(request.commit_id) is None
    _missing_recovery_delta(before_recovery, _snapshot(reopened))
    assert before_recovery.current_pointers == _snapshot(reopened).current_pointers


def test_sqlite_attempt_mismatch_precedes_coherent_inactive_attempt_replay(
    tmp_path: Path,
) -> None:
    store = _open_store(tmp_path / "attempt-precedence.db", None)
    malformed_base = _request(commit_id="attempt-mismatch", nonce_byte=89)
    mismatched = replace(
        malformed_base,
        subject=replace(malformed_base.subject, attempt_id="subject-only-mismatch"),
    )
    coherent = _request(
        commit_id="inactive-attempt",
        nonce_byte=90,
        attempt_id="inactive-attempt",
    )
    malformed_result = store.atomic_commit(mismatched)
    assert malformed_result.decision.outcome.value == "DENIED"
    assert malformed_result.decision.reason is FailureCode.ATTEMPT_MISMATCH

    inactive_result = store.atomic_commit(coherent)
    assert inactive_result.decision.outcome.value == "DENIED"
    assert inactive_result.decision.reason is FailureCode.CROSS_ATTEMPT_REPLAY


def test_sqlite_outbox_has_one_durable_intent_and_at_least_once_sink_delivery(
    tmp_path: Path,
) -> None:
    _OUTBOX_SINK.delivered.clear()
    _OUTBOX_SINK.fail_after_delivery = False
    store = _open_store(tmp_path / "outbox.db", None)
    request = _request(commit_id="outbox", nonce_byte=61)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    before = _snapshot(store)
    persisted_event = _outbox_event(store, request.commit_id)
    assert persisted_event.event_id
    assert persisted_event.payload
    assert persisted_event.audit_event_id == committed.audit_event_id
    assert persisted_event.pending
    _OUTBOX_SINK.fail_after_delivery = True
    with pytest.raises(_InjectedFault, match="after_sink_delivery_before_mark"):
        store.recover_outbox(OutboxRecoveryRequest(max_items="100"))
    after_sink_failure = _snapshot(store)
    assert len(_OUTBOX_SINK.delivered) == 1
    first_event_id, first_payload = _OUTBOX_SINK.delivered[0]
    assert (first_event_id, first_payload) == (
        persisted_event.event_id,
        persisted_event.payload,
    )
    failed_event = _outbox_event(store, request.commit_id)
    assert failed_event == persisted_event
    assert failed_event.pending
    assert after_sink_failure.current_pointers == before.current_pointers
    _OUTBOX_SINK.fail_after_delivery = False
    delivered = store.recover_outbox(OutboxRecoveryRequest(max_items="100"))
    assert delivered.delivered_count == "1"
    assert delivered.pending_count == "0"
    assert delivered.audit_event_id
    assert len(_OUTBOX_SINK.delivered) == 2
    assert _OUTBOX_SINK.delivered[1] == (first_event_id, first_payload)
    delivered_event = _outbox_event(store, request.commit_id)
    assert delivered_event.event_id == persisted_event.event_id
    assert delivered_event.payload == persisted_event.payload
    assert delivered_event.audit_event_id == persisted_event.audit_event_id
    assert not delivered_event.pending
    assert (
        store.get_certificate(request.commit_id) == committed.certificate_envelope_bytes
    )
    _only_outbox_delivery(after_sink_failure, _snapshot(store))


@pytest.mark.parametrize("scope", (RevocationScope.ACTOR, RevocationScope.WORKFLOW))
def test_sqlite_first_generation_revocation_must_advance_implicit_zero(
    tmp_path: Path, scope: RevocationScope
) -> None:
    store = _open_store(tmp_path / f"generation-zero-{scope.value}.db", None)
    before = _snapshot(store)
    target = "agent-1" if scope is RevocationScope.ACTOR else "workflow-1"
    with pytest.raises(ValueError, match=FailureCode.INVALID_DECIMAL_STRING.value):
        store.revoke(RevocationRequest(scope, "workflow-1", target, "0", "invalid"))
    assert _snapshot(store) == before


def test_sqlite_commit_and_revocation_outbox_identities_are_typed_and_disjoint(
    tmp_path: Path,
) -> None:
    store = _open_store(tmp_path / "typed-outbox.db", None)
    target = _request(commit_id="typed-outbox-target", nonce_byte=250, node_id="root")
    _advance_candidate(store, target)
    committed = store.atomic_commit(target)
    assert committed.certificate_digest is not None
    revoke_audit = sha256_digest(
        (
            "revoke\x00CERTIFICATE\x00workflow-1\x00"
            + committed.certificate_digest
            + "\x001"
        ).encode()
    )
    collision = _request(
        commit_id=revoke_audit,
        nonce_byte=251,
        workflow_id="workflow-2",
        node_id="node-1",
    )
    _advance_candidate(store, collision)
    assert store.atomic_commit(collision).decision.outcome.value == "COMMITTED"
    revoked = store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "workflow-1",
            committed.certificate_digest,
            "1",
            "typed identity",
        )
    )
    assert revoked.audit_event_id == revoke_audit
    assert store.get_outbox_event(collision.commit_id).audit_event_id != revoke_audit


def test_sqlite_concurrent_outbox_recovery_invokes_sink_once_per_pending_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-outbox.db"
    store = _open_store(path, None)
    request = _request(commit_id="concurrent-outbox", nonce_byte=252)
    _advance_candidate(store, request)
    store.atomic_commit(request)

    class BlockingSink:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.started = threading.Event()
            self.release = threading.Event()

        def deliver(self, event_id: str, payload: bytes) -> None:
            del payload
            self.calls.append(event_id)
            self.started.set()
            self.release.wait(timeout=5)

    sink = BlockingSink()
    runtime = replace(_runtime(), outbox_sink=sink)
    stores = [
        SQLiteAuthorityStore.open(path, config=_config(), runtime=runtime)
        for _ in range(2)
    ]
    results: list[OutboxRecoveryResult] = []

    def recover(authority: SQLiteAuthorityStore) -> None:
        results.append(authority.recover_outbox(OutboxRecoveryRequest(max_items="1")))

    first = threading.Thread(target=recover, args=(stores[0],))
    second = threading.Thread(target=recover, args=(stores[1],))
    first.start()
    assert sink.started.wait(timeout=5)
    second.start()
    time.sleep(0.1)
    sink.release.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert len(sink.calls) == 1
    assert sorted(int(result.delivered_count) for result in results) == [0, 1]


def test_sqlite_required_hot_path_indexes_are_used(tmp_path: Path) -> None:
    path = tmp_path / "query-plans.db"
    _open_store(path, None)
    with sqlite3.connect(path) as connection:
        plans = {
            "outbox": connection.execute(
                "EXPLAIN QUERY PLAN SELECT event_id FROM apcc_outbox "
                "WHERE state<>'DELIVERED' ORDER BY event_sequence LIMIT 1"
            ).fetchall(),
            "supersession": connection.execute(
                "EXPLAIN QUERY PLAN SELECT edge_id FROM supersession_edges WHERE new_digest=?",
                ("digest",),
            ).fetchall(),
            "predecessor": connection.execute(
                "EXPLAIN QUERY PLAN SELECT predecessor_digest FROM predecessor_edges "
                "WHERE child_commit_id=? ORDER BY predecessor_digest",
                ("commit",),
            ).fetchall(),
        }
    text = " ".join(str(row) for rows in plans.values() for row in rows).lower()
    assert "idx_apcc_outbox_head" in text
    assert "idx_supersession_new_digest" in text
    assert "sqlite_autoindex_predecessor_edges" in text


@pytest.mark.parametrize(
    "mutation",
    (
        "DELETE FROM nonce_ledger",
        "DELETE FROM apcc_decisions",
        "DELETE FROM evidence_refs",
        "DELETE FROM audit_events",
        "DELETE FROM trust_log",
        "DELETE FROM apcc_outbox WHERE event_kind='COMMIT'",
        "UPDATE nonce_ledger SET commit_id='other'",
        "UPDATE apcc_decisions SET nonce='other'",
        "UPDATE logical_nodes SET certificate_digest=NULL WHERE version<>'0'",
        "INSERT INTO apcc_outbox(event_sequence,event_id,event_kind,operation_id,event_json,audit_event_id,trust_sequence,state,lease_token,lease_until_ms,delivered) VALUES (999,'orphan','CONTROL','orphan',X'00','orphan',999,'PENDING',NULL,NULL,0)",
    ),
)
def test_sqlite_open_attests_the_complete_committed_authority_tuple(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "complete-tuple.db"
    store = _open_store(path, None)
    request = _request(commit_id="complete-tuple", nonce_byte=253)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        table = (
            "trust_log"
            if "trust_log" in mutation
            else "apcc_outbox"
            if "apcc_outbox" in mutation
            else mutation.split()[1]
            if mutation.startswith("UPDATE")
            else mutation.split()[2]
        )
        _force_sql_mutation(connection, table, mutation)
        connection.commit()
    _OUTBOX_SINK.delivered.clear()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityStore.open(path, config=_config(), runtime=_runtime())
    assert _OUTBOX_SINK.delivered == []


@pytest.mark.parametrize("kind", ("negative", "conflict"))
def test_sqlite_open_attests_negative_and_conflict_durable_tuples(
    tmp_path: Path, kind: str
) -> None:
    path = tmp_path / f"{kind}-tuple.db"
    store = _open_store(path, None)
    if kind == "negative":
        request = _request(
            commit_id="negative-tuple", nonce_byte=13, attempt_id="inactive-attempt"
        )
        assert store.atomic_commit(request).decision.outcome.value == "DENIED"
        mutation = "DELETE FROM nonce_ledger"
        table = "nonce_ledger"
    else:
        request = _request(commit_id="conflict-tuple", nonce_byte=14)
        _advance_candidate(store, request)
        store.atomic_commit(request)
        conflicting = replace(request, nonce=_nonce(15))
        conflict = store.atomic_commit(conflicting)
        assert conflict.decision.outcome.value == "CONFLICTED"
        mutation = (
            f"DELETE FROM audit_events WHERE audit_event_id='{conflict.audit_event_id}'"
        )
        table = "audit_events"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        _force_sql_mutation(connection, table, mutation)
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE trust_log SET sequence=2",
        "UPDATE trust_log SET prior_digest='bad'",
        "UPDATE trust_log SET entry_digest='bad'",
        "UPDATE trust_log SET entry_json='{}'",
        "UPDATE trust_log SET audit_event_id='bad'",
    ),
)
def test_sqlite_trust_chain_is_canonical_contiguous_and_audit_linked(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "trust-chain.db"
    store = _open_store(path, None)
    request = _request(commit_id="trust-chain", nonce_byte=254)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        _force_sql_mutation(connection, "trust_log", mutation)
        connection.commit()
    before_status_signatures = _KeyProvider.status_signature_count()
    with pytest.raises(ValueError):
        store.current_status(committed.certificate_digest, _nonce(12))
    assert _KeyProvider.status_signature_count() == before_status_signatures
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "scope",
    (RevocationScope.CERTIFICATE, RevocationScope.ACTOR, RevocationScope.WORKFLOW),
)
def test_sqlite_control_event_projection_trust_and_outbox_are_one_durable_tuple(
    tmp_path: Path, scope: RevocationScope
) -> None:
    path = tmp_path / f"control-tuple-{scope.value}.db"
    store = _open_store(path, None)
    target = "agent-1"
    if scope is RevocationScope.WORKFLOW:
        target = "workflow-1"
    elif scope is RevocationScope.CERTIFICATE:
        request = _request(commit_id="control-target", nonce_byte=9, node_id="root")
        _advance_candidate(store, request)
        committed = store.atomic_commit(request)
        assert committed.certificate_digest is not None
        target = committed.certificate_digest
    result = store.revoke(
        RevocationRequest(scope, "workflow-1", target, "1", "control reason")
    )
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT scope,workflow_id,target_id,generation,reason,audit_event_id,payload,payload_digest FROM control_events"
        ).fetchone()
        assert row is not None
        assert row[:3] == (scope.value, "workflow-1", target)
        assert row[3] == (None if scope is RevocationScope.CERTIFICATE else "1")
        assert row[4] == "control reason"
        assert row[5] == result.audit_event_id
        assert sha256_digest(bytes(row[6])) == row[7]
        connection.execute("PRAGMA foreign_keys=OFF")
        _force_sql_mutation(
            connection,
            "control_events",
            "UPDATE control_events SET payload_digest='bad'",
        )
        connection.commit()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    ("maximum", "code"),
    (
        ("0", FailureCode.INVALID_DECIMAL_STRING),
        ("-1", FailureCode.INVALID_DECIMAL_STRING),
        ("01", FailureCode.INVALID_DECIMAL_STRING),
        ("x", FailureCode.INVALID_DECIMAL_STRING),
        ("1001", FailureCode.SIZE_LIMIT_EXCEEDED),
    ),
)
def test_sqlite_outbox_recovery_validates_canonical_bounded_batch_before_open(
    tmp_path: Path, maximum: str, code: FailureCode
) -> None:
    store = _open_store(tmp_path / "recovery-limit.db", None)
    with pytest.raises(ValueError, match=code.value):
        store.recover_outbox(OutboxRecoveryRequest(max_items=maximum))


def test_sqlite_blocked_outbox_sink_does_not_hold_the_authority_writer_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "outbox-short-transactions.db"
    store = _open_store(path, None)
    first_request = _request(commit_id="outbox-first", nonce_byte=10)
    _advance_candidate(store, first_request)
    store.atomic_commit(first_request)

    class BlockingSink:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def deliver(self, event_id: str, payload: bytes) -> None:
            del event_id, payload
            self.started.set()
            assert self.release.wait(timeout=5)

    sink = BlockingSink()
    recovery_store = SQLiteAuthorityStore.open(
        path, config=_config(), runtime=replace(_runtime(), outbox_sink=sink)
    )
    recovery = threading.Thread(
        target=lambda: recovery_store.recover_outbox(OutboxRecoveryRequest("1"))
    )
    recovery.start()
    assert sink.started.wait(timeout=5)
    second = _request(
        commit_id="outbox-second",
        nonce_byte=11,
        workflow_id="workflow-2",
        node_id="node-1",
    )
    _advance_candidate(store, second)
    assert store.atomic_commit(second).decision.outcome.value == "COMMITTED"
    sink.release.set()
    recovery.join(timeout=5)
    assert not recovery.is_alive()


def test_sqlite_outbox_claim_head_blocks_then_expires_and_stale_token_cannot_finalize(
    tmp_path: Path,
) -> None:
    path = tmp_path / "outbox-lease.db"
    store = _open_store(path, None)
    request = _request(commit_id="lease-head", nonce_byte=16)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    now = _Clock().now_ms()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE apcc_outbox SET state='CLAIMED',lease_token='owner',lease_claimed_ms=?,lease_until_ms=?,delivered=0",
            (now, now + 1000),
        )
        assert (
            connection.execute(
                "UPDATE apcc_outbox SET state='DELIVERED',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=1 WHERE lease_token='stale'"
            ).rowcount
            == 0
        )
        connection.commit()
    _OUTBOX_SINK.delivered.clear()
    blocked = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert blocked.delivered_count == "0"
    assert _OUTBOX_SINK.delivered == []
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE apcc_outbox SET lease_claimed_ms=?,lease_until_ms=?",
            (now - 2, now - 1),
        )
        connection.commit()
    reclaimed = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert reclaimed.delivered_count == "1"
    assert len(_OUTBOX_SINK.delivered) == 1


@pytest.mark.parametrize("generation", (str(9_007_199_254_740_992), "0001"))
def test_sqlite_revocation_generation_requires_canonical_safe_integer(
    tmp_path: Path, generation: str
) -> None:
    store = _open_store(tmp_path / "generation-domain.db", None)
    before = _snapshot(store)
    with pytest.raises(ValueError, match=FailureCode.INVALID_DECIMAL_STRING.value):
        store.revoke(
            RevocationRequest(
                RevocationScope.ACTOR,
                "workflow-1",
                "agent-1",
                generation,
                "invalid generation",
            )
        )
    assert _snapshot(store) == before


def test_sqlite_config_parser_rejects_lossy_or_duplicate_role_bindings(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config-roundtrip.db"
    _open_store(path, None)
    with sqlite3.connect(path) as connection:
        config = json.loads(
            connection.execute(
                "SELECT value FROM metadata WHERE key='config'"
            ).fetchone()[0]
        )
        commit = next(item for item in config["bindings"] if item["role"] == "commit")
        config["bindings"].append(dict(commit))
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='config'",
            (json.dumps(config, sort_keys=True, separators=(",", ":")),),
        )
        connection.commit()
    with pytest.raises(ValueError, match="schema validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_literal_memory_path_is_created_as_a_wal_backed_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = Path(":memory:")
    SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())
    assert path.is_file()
    with sqlite3.connect(path.resolve().as_uri(), uri=True) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE commit_index SET request_digest='coherent-other'",
        "UPDATE commit_index SET workflow_id='workflow-2'",
        "UPDATE request_index SET request_digest='coherent-other'",
        "UPDATE apcc_decisions SET reason='NONCE_REPLAY'",
        "UPDATE nonce_ledger SET nonce='AAAAAAAAAAAAAAAAAAAAAA'; UPDATE apcc_decisions SET nonce='AAAAAAAAAAAAAAAAAAAAAA'",
        "UPDATE audit_events SET event_json='{}'",
    ),
)
def test_sqlite_reopen_recomputes_every_signed_commit_replay_and_audit_binding(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "signed-rewrite.db"
    store = _open_store(path, None)
    request = _request(commit_id="signed-rewrite", nonce_byte=17)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        for statement in mutation.split("; "):
            connection.execute(statement)
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE commit_index SET request_digest='negative-other'",
        "UPDATE commit_index SET workflow_id='workflow-2'",
        "UPDATE apcc_decisions SET outcome='CONFLICTED'",
        "UPDATE apcc_decisions SET reason='POLICY_DENIED'",
        "UPDATE nonce_ledger SET nonce='AQEBAQEBAQEBAQEBAQEBAQ'; UPDATE apcc_decisions SET nonce='AQEBAQEBAQEBAQEBAQEBAQ'",
        "UPDATE audit_events SET event_json='{}'",
    ),
)
def test_sqlite_negative_replay_is_bound_to_persisted_canonical_request(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "negative-rewrite.db"
    store = _open_store(path, None)
    request = _request(
        commit_id="negative-rewrite", nonce_byte=18, attempt_id="inactive-negative"
    )
    denied = store.atomic_commit(request)
    assert denied.decision.outcome.value == "DENIED"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        for statement in mutation.split("; "):
            connection.execute(statement)
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_nonce_replay_observes_one_global_owner_without_duplicate_reservation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "nonce-owner.db"
    store = _open_store(path, None)
    first = _request(
        commit_id="nonce-owner", nonce_byte=19, attempt_id="inactive-owner"
    )
    original = store.atomic_commit(first)
    replay_request = _request(
        commit_id="nonce-observer", nonce_byte=19, attempt_id="inactive-observer"
    )
    observed = store.atomic_commit(replay_request)
    assert observed.decision.reason is FailureCode.NONCE_REPLAY
    assert store.atomic_commit(replay_request) == observed
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT nonce,commit_id FROM nonce_ledger WHERE nonce=?", (first.nonce,)
        ).fetchall()
        assert rows == [(first.nonce, first.commit_id)]
        assert connection.execute(
            "SELECT nonce_owner_commit_id FROM apcc_decisions WHERE commit_id=?",
            (replay_request.commit_id,),
        ).fetchone() == (first.commit_id,)
    assert original.audit_event_id != observed.audit_event_id
    SQLiteAuthorityReader.open(path)


def test_sqlite_coherent_control_retargeting_fails_before_status_signing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control-retarget.db"
    provider = _KeyProvider()
    store = SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())
    del store
    authority = SQLiteAuthorityStore.open(
        path, _config(), AuthorityRuntime(provider, _Clock(), _OUTBOX_SINK)
    )
    request = _request(commit_id="control-retarget", nonce_byte=20)
    _advance_candidate(authority, request)
    committed = authority.atomic_commit(request)
    assert committed.certificate_digest is not None
    authority.revoke(
        RevocationRequest(
            RevocationScope.ACTOR, "workflow-1", "agent-1", "1", "retarget"
        )
    )
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT operation_id,audit_event_id,payload FROM control_events"
        ).fetchone()
        assert row is not None
        body = json.loads(bytes(row[2]))
        body["target_id"] = "agent-2"
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        payload_digest = sha256_digest(payload)
        _force_sql_mutation(
            connection,
            "control_events",
            "UPDATE control_events SET target_id='agent-2',payload=?,payload_digest=?",
            (payload, payload_digest),
        )
        _force_sql_mutation(
            connection,
            "apcc_outbox",
            "UPDATE apcc_outbox SET event_json=?,event_id=? "
            "WHERE event_kind='CONTROL' AND operation_id=?",
            (
                payload,
                sqlite_store_module._audit_id(
                    "outbox", "CONTROL", str(row[0]), payload_digest
                ),
                row[0],
            ),
        )
        connection.execute("DELETE FROM actor_revocations")
        connection.execute(
            "INSERT INTO actor_revocations VALUES ('workflow-1','agent-2','1')"
        )
        connection.commit()
    before = _KeyProvider.status_signature_count()
    with pytest.raises(ValueError):
        authority.current_status(committed.certificate_digest, _nonce(21))
    assert _KeyProvider.status_signature_count() == before
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    ("DELETE FROM supersession_edges", "UPDATE supersession_edges SET nonce='bad'"),
)
def test_sqlite_reopen_attests_exact_supersession_edge_and_audit(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "supersession-attestation.db"
    store = _open_store(path, None)
    first = _request(commit_id="supersession-old", nonce_byte=22)
    _advance_candidate(store, first)
    old = store.atomic_commit(first)
    assert old.certificate_digest is not None
    replacement = _request(
        commit_id="supersession-new",
        nonce_byte=23,
        expected_node_version="1",
        attempt_id="attempt-supersession",
    )
    _advance_candidate(store, replacement)
    store.supersede(SupersessionRequest(old.certificate_digest, replacement))
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(mutation)
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE commit_conflicts SET original_request_digest='bad'",
        "UPDATE commit_conflicts SET original_workflow_id='bad'",
        "UPDATE commit_conflicts SET observation_sequence=2",
        "UPDATE commit_conflicts SET audit_event_id='bad'",
        "UPDATE audit_events SET event_json='{}' WHERE event_json LIKE '%COMMIT_ID_EQUIVOCATION%'",
    ),
)
def test_sqlite_reopen_attests_conflict_identity_sequence_and_canonical_audit(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "conflict-attestation.db"
    store = _open_store(path, None)
    request = _request(commit_id="conflict-attestation", nonce_byte=24)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    store.atomic_commit(replace(request, nonce=_nonce(25)))
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(mutation)
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_reopen_rejects_coherent_fk_reachable_conflict_forgery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "coherent-conflict-forgery.db"
    store = _open_store(path, None)
    request = _request(commit_id="coherent-conflict", nonce_byte=26)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    conflicting = replace(request, nonce=_nonce(27))
    conflict = store.atomic_commit(conflicting)
    forged_original = sha256_digest(b"forged-original-authority-request")
    forged_conflicting = sha256_digest(b"forged-conflicting-authority-request")
    forged_workflow = "forged-workflow"
    forged_audit = sqlite_store_module._audit_id(
        "conflict", request.commit_id, forged_conflicting
    )
    forged_audit_json = json.dumps(
        {
            "kind": FailureCode.COMMIT_ID_EQUIVOCATION.value,
            "subject": request.commit_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "UPDATE commit_index SET request_digest=?,workflow_id=? WHERE commit_id=?",
            (forged_original, forged_workflow, request.commit_id),
        )
        connection.execute(
            "UPDATE audit_events SET audit_event_id=?,event_json=? "
            "WHERE audit_event_id=?",
            (forged_audit, forged_audit_json, conflict.audit_event_id),
        )
        connection.execute(
            "UPDATE commit_conflicts SET original_request_digest=?,"
            "conflicting_request_digest=?,original_workflow_id=?,"
            "conflicting_workflow_id=?,observation_sequence=1,audit_event_id=? "
            "WHERE commit_id=?",
            (
                forged_original,
                forged_conflicting,
                forged_workflow,
                forged_workflow,
                forged_audit,
                request.commit_id,
            ),
        )
        connection.commit()
    with pytest.raises(ValueError, match="validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE candidates SET subject_json='{}'",
        "UPDATE candidates SET context_json='{}'",
        "UPDATE candidates SET predecessors_json='{}'",
        "UPDATE candidates SET result=X'6576696c',lifecycle='RESULT_STAGED'",
        "UPDATE candidates SET proposal_digest='bad',lifecycle='COMMIT_PENDING'",
    ),
)
def test_sqlite_open_semantically_validates_every_candidate_row(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "candidate-scan.db"
    _open_store(path, None)
    with sqlite3.connect(path) as connection:
        connection.execute(mutation)
        connection.commit()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_failed_first_provision_leaves_no_destination_or_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "atomic-provision.db"
    original_schema = sqlite_store_module._schema

    def fail_schema(connection: sqlite3.Connection) -> None:
        original_schema(connection)
        raise RuntimeError("injected initial schema failure")

    monkeypatch.setattr(sqlite_store_module, "_schema", fail_schema)
    with pytest.raises(RuntimeError, match="injected initial schema failure"):
        SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())
    assert not path.exists()
    assert not list(tmp_path.glob("atomic-provision.db*"))


@pytest.mark.parametrize("clock_value", (-1, True, 9_007_199_254_740_992))
def test_sqlite_trusted_clock_bounds_fail_before_signing_or_mutation(
    tmp_path: Path, clock_value: int
) -> None:
    path = tmp_path / "clock-bounds.db"
    SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())

    class BadClock:
        def now_ms(self) -> int:
            return clock_value

    provider = _KeyProvider()
    store = SQLiteAuthorityStore.open(
        path, _config(), AuthorityRuntime(provider, BadClock(), _OUTBOX_SINK)
    )
    request = _request(commit_id="clock-bounds", nonce_byte=26)
    before = _snapshot(store)
    with pytest.raises(ValueError, match=FailureCode.INVALID_DECIMAL_STRING.value):
        store.assemble_evidence(_assemble_evidence_request(request))
    assert _snapshot(store) == before


def test_sqlite_config_exact_roundtrip_supports_multiple_scoped_role_bindings(
    tmp_path: Path,
) -> None:
    base = _config()
    extra = replace(
        base.producer_trust[0],
        scope=("agent-2", "actor-2", "root-2"),
        key_id="producer-key-2",
        public_key=_public_key(bytes([211]) * 32),
    )
    config = replace(base, producer_trust=(*base.producer_trust, extra))
    path = tmp_path / "multi-binding.db"
    SQLiteAuthorityStore.provision(path, config, _initial_contexts())
    assert (
        SQLiteAuthorityReader.open(path).authority_store_id == config.authority_store_id
    )


def test_sqlite_commit_outbox_causally_precedes_its_control_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "commit-control-order.db"
    store = _open_store(path, None)
    request = _request(commit_id="commit-control-order", nonce_byte=27)
    _advance_candidate(store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "workflow-1",
            committed.certificate_digest,
            "1",
            "after commit",
        )
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT event_kind FROM apcc_outbox ORDER BY event_sequence"
        ).fetchall() == [("COMMIT",), ("CONTROL",)]


@pytest.mark.parametrize("projection_checkpoint", tuple(_GCBProjectionCheckpoint))
def test_executor_and_gcb_route_only_once_through_apcc_and_block_legacy_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection_checkpoint: _GCBProjectionCheckpoint,
) -> None:
    """Dispatcher-level RED: ordinary execution has one APCC authority path."""
    calls: list[AtomicCommitRequest] = []
    original_commit = APCCCommitService.commit

    def observed_commit(
        self: APCCCommitService, request: AtomicCommitRequest
    ) -> CommitResult:
        assert isinstance(request, AtomicCommitRequest)
        calls.append(request)
        return original_commit(self, request)

    monkeypatch.setattr(APCCCommitService, "commit", observed_commit)
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    authority_path = tmp_path / "dispatcher.sqlite3"
    agent_key = Ed25519PrivateKey.from_private_bytes(SEEDS["producer"])
    config = _gcb_config(
        agent_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    runtime = _runtime()
    policy_signer = _DetachedSigner(SEEDS["policy"])
    registry_signer = _DetachedSigner(SEEDS["authority"])
    control_signer = _DetachedSigner(_CONTROL_SEED)
    assert (
        len(
            {
                config.producer_trust[0].public_key,
                policy_signer.public_key_bytes(),
                registry_signer.public_key_bytes(),
                control_signer.public_key_bytes(),
                runtime.key_provider.public_key(
                    AuthoritySigningRole.COMMIT, config.commit_trust.key_id
                ),
                runtime.key_provider.public_key(
                    AuthoritySigningRole.STATUS, config.status_trust.key_id
                ),
            }
        )
        == 6
    )
    assert config.policy_trust[0].public_key == policy_signer.public_key_bytes()
    assert config.registry_trust[0].public_key == registry_signer.public_key_bytes()
    bootstrap = _GCB_BOOTSTRAP(
        config=config,
        runtime=runtime,
        policy_signer=policy_signer,
        registry_signer=registry_signer,
        control_signer=control_signer,
    )
    admin = _GCBFactory.provision_with_projection_fault(
        bootstrap, authority_path, projection_checkpoint
    )
    assert Path(admin.commit_port.path) == authority_path
    artifacts = ArtifactStore()
    dag = TaskDAG(dag_id="dispatcher", goal="g").add_node(
        TaskNode(node_id="root", required_capabilities=("work",))
    )
    provision_executor_workflow(admin, dag, policy_version="1")
    authority_lifecycle = TrustedAuthorityLifecycleHarness(admin, dag.dag_id, artifacts)
    executor = compose_test_executor(
        registry,
        artifacts,
        InProcessExecutionClientHarness(admin),
        policy_version="1",
    )
    executor.load_dag(dag)
    assert authority_lifecycle.dispatch_after_commit() == 0
    admin.register_agent(
        workflow_id="dispatcher",
        agent_id="agent",
        public_key=agent_key.public_key(),
        capabilities=("work",),
    )
    claim = sign_attempt_authorization(
        executor.prepare_claim("root", "agent"), agent_key
    )
    executor.claim("root", "agent", claim)
    artifact = Artifact("dispatcher-artifact", "root", "agent", "text", "result")
    payload = executor.produce_result("root", artifact)
    request = admin.build_request(sign_governed_receipt(payload, agent_key))
    before_atomic_commit = _gcb_authority_snapshot(admin)
    failed = executor.commit(request)
    assert failed.outcome.value == "denied"
    assert failed.reason == "persistence_error"
    assert getattr(admin.commit_port, "_apcc_store")._gcb_projection_fault_fired
    after_failed_commit = _gcb_authority_snapshot(admin)
    preparation_tables = {"candidates", "logical_nodes"}
    assert {
        name: rows
        for name, rows in after_failed_commit.tables.items()
        if name not in preparation_tables
    } == {
        name: rows
        for name, rows in before_atomic_commit.tables.items()
        if name not in preparation_tables
    }
    with sqlite3.connect(authority_path) as connection:
        candidate = connection.execute(
            "SELECT lifecycle FROM candidates WHERE workflow_id=? AND node_id=?",
            ("dispatcher", "root"),
        ).fetchone()
    assert candidate == (CandidateLifecycle.COMMIT_PENDING.value,)
    failed_reader = SQLiteAuthorityReader.open(authority_path)
    assert failed_reader.get_certificate(request.commit_id) is None
    failed_node = failed_reader.read_logical_node("dispatcher", "root")
    assert failed_node.current_node_version == "0"
    assert failed_node.current_certificate_digest is None
    assert admin.node_state("dispatcher", "root").commit_id is None
    committed = executor.commit(request)
    assert isinstance(request, GovernedCommitRequest)
    assert isinstance(committed, GovernedCommitDecision)
    assert committed.commit_id == request.commit_id
    assert len(calls) == 2
    assert calls[0] == calls[1]
    apcc_request = calls[-1]
    assert apcc_request.commit_id == request.commit_id
    assert apcc_request.subject.workflow_id == request.receipt.payload.workflow_id
    assert apcc_request.subject.node_id == request.receipt.payload.node_id
    assert apcc_request.subject.attempt_id == request.receipt.payload.attempt_id
    producer = apcc_request.evidence.producer_statement
    policy = apcc_request.evidence.policy_statement
    authority = apcc_request.evidence.authority_statement
    assert config.producer_trust[0].scope == (
        producer["agent_id"],
        producer["actor_authority"],
        authority["authority_root"],
    )
    assert config.policy_trust[0].scope == (
        policy["policy_id"],
        policy["policy_version"],
        policy["policy_epoch"],
    )
    assert config.registry_trust[0].scope == (
        authority["authority_root"],
        authority["authority_epoch"],
    )
    assert apcc_request.signatures.producer.key_id == config.producer_trust[0].key_id
    assert (
        apcc_request.signatures.policy_authority.key_id == config.policy_trust[0].key_id
    )
    assert (
        apcc_request.signatures.authority_registry.key_id
        == config.registry_trust[0].key_id
    )

    canonical_reader = SQLiteAuthorityReader.open(authority_path)
    assert canonical_reader.authority_store_id == "dispatcher-store"
    canonical_node = canonical_reader.read_logical_node("dispatcher", "root")
    assert canonical_node.current_certificate_digest is not None
    certificate_envelope = canonical_reader.get_certificate(request.commit_id)
    assert certificate_envelope is not None
    status_nonce = _nonce(119)
    status = admin.commit_port.current_status(
        canonical_node.current_certificate_digest, status_nonce
    )
    current = verify_current(
        certificate_envelope,
        trust=ScopedTrust(config.trust_bindings),
        authority_status=status,
        request_nonce=status_nonce,
        now_ms=status.this_update_ms,
        highest_trust_log_sequence=status.trust_log_sequence,
        highest_trust_log_head=status.trust_log_head,
        maximum_staleness_ms=config.freshness.maximum_staleness_ms,
    )
    assert current.ok
    _assert_all_six_private_seeds_absent(authority_path)

    authority_before = admin.node_state("dispatcher", "root")
    apcc_before = _gcb_authority_snapshot(admin)
    with pytest.raises(GovernanceBypassDenied):
        executor.submit("root", artifact)
    assert executor._dag is not None
    with pytest.raises(GovernanceBypassDenied):
        executor._dag.complete_node("root", artifact.artifact_id)
    with pytest.raises(GovernanceBypassDenied):
        artifacts.publish(artifact)
    assert admin.node_state("dispatcher", "root") == authority_before
    assert len(calls) == 2

    # Trusted-admin and raw-port replay are compatibility entrypoints over the
    # same adapter, never a second authority path or a legacy store mutation.
    for legacy_commit in (admin.commit, admin.commit_port.commit):
        before_legacy = _gcb_authority_snapshot(admin)
        calls_before = len(calls)
        replay = legacy_commit(request)
        assert replay == committed
        assert len(calls) == calls_before + 1
        assert isinstance(calls[-1], AtomicCommitRequest)
        assert calls[-1] == apcc_request
        assert _gcb_authority_snapshot(admin) == before_legacy
    assert _gcb_authority_snapshot(admin) == apcc_before

    # Legacy rows may be projected for compatibility, but cannot authorize or
    # change canonical node state/readiness.
    with sqlite3.connect(authority_path) as connection:
        connection.execute(
            "UPDATE nodes SET status='ready', commit_id=NULL WHERE workflow_id=? AND node_id=?",
            ("dispatcher", "root"),
        )
    fresh_reader = SQLiteAuthorityReader.open(authority_path)
    assert fresh_reader.read_logical_node("dispatcher", "root") == canonical_node
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_spawn_gcb_reader,
        args=(
            str(authority_path),
            "dispatcher",
            "root",
            request.commit_id,
            results,
        ),
    )
    process.start()
    process.join(timeout=20)
    assert process.exitcode == 0
    child_store, child_version, child_digest, child_certificate, child_pid = (
        results.get(timeout=2)
    )
    assert child_store == config.authority_store_id
    assert child_version == canonical_node.current_node_version
    assert child_digest == canonical_node.current_certificate_digest
    assert child_certificate == certificate_envelope
    assert child_pid != os.getpid()
    assert admin.node_state("dispatcher", "root") == authority_before
    assert not executor.available_tasks("agent")
    allowed_files = {
        authority_path.name,
        f"{authority_path.name}-wal",
        f"{authority_path.name}-shm",
    }
    assert {item.name for item in tmp_path.iterdir()} <= allowed_files


def test_sqlite_repeated_supersession_chain_reopens_at_terminal_head(
    tmp_path: Path,
) -> None:
    assert_repeated_supersession_chain_conforms(_harness(), tmp_path)


@pytest.mark.parametrize(
    "mutation",
    (
        "DELETE FROM supersession_edges WHERE rowid=(SELECT rowid FROM supersession_edges LIMIT 1)",
        "UPDATE supersession_edges SET old_digest=new_digest WHERE rowid=(SELECT rowid FROM supersession_edges LIMIT 1)",
        "UPDATE supersession_edges SET new_digest=(SELECT new_digest FROM supersession_edges ORDER BY rowid DESC LIMIT 1) WHERE rowid=(SELECT rowid FROM supersession_edges LIMIT 1)",
    ),
)
def test_sqlite_repeated_supersession_graph_rejects_missing_cycle_or_branch(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "supersession-graph-corrupt.db"
    store = _open_store(path, None)
    requests = [
        _request(commit_id="graph-a", nonce_byte=201),
        _request(
            commit_id="graph-b",
            nonce_byte=202,
            expected_node_version="1",
            attempt_id="graph-b",
        ),
        _request(
            commit_id="graph-c",
            nonce_byte=203,
            expected_node_version="2",
            attempt_id="graph-c",
        ),
    ]
    _advance_candidate(store, requests[0])
    current = store.atomic_commit(requests[0])
    assert current.certificate_digest is not None
    for request in requests[1:]:
        _advance_candidate(store, request)
        replacement = store.supersede(
            SupersessionRequest(current.certificate_digest, request)
        )
        assert isinstance(replacement, SupersessionCommitted)
        current = replacement.commit_result
        assert current.certificate_digest is not None
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(mutation)
        connection.commit()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE candidates SET expected_version='-1'",
        "UPDATE candidates SET audit_event_id='forged'",
        "UPDATE candidates SET proposal_digest='forged' WHERE proposal_json IS NOT NULL",
    ),
)
def test_sqlite_candidate_immutable_attestation_rejects_corruption(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / "candidate-immutable.db"
    store = _open_store(path, None)
    request = _request(commit_id="candidate-immutable", nonce_byte=204)
    _advance_candidate(store, request)
    with sqlite3.connect(path) as connection:
        connection.execute(mutation)
        connection.commit()
    before = _KeyProvider.status_signature_count()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)
    assert _KeyProvider.status_signature_count() == before


def test_sqlite_recovery_rejects_oversized_persisted_lease(
    tmp_path: Path,
) -> None:
    path = tmp_path / "lease-overflow.db"
    store = _open_store(path, None)
    request = _request(commit_id="lease-overflow", nonce_byte=205)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        _force_sql_mutation(
            connection,
            "apcc_outbox",
            "UPDATE apcc_outbox SET state='CLAIMED',lease_token='bad',lease_until_ms=9007199254740992,delivered=0",
        )
        connection.commit()
    with pytest.raises(ValueError):
        store.recover_outbox(OutboxRecoveryRequest("1"))


def test_sqlite_persisted_request_has_authenticated_operation_provenance(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operation-provenance.db"
    store = _open_store(path, None)
    request = _request(commit_id="operation-provenance", nonce_byte=206)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    with sqlite3.connect(path) as connection:
        persisted = json.loads(
            connection.execute(
                "SELECT request_json FROM commit_index WHERE commit_id=?",
                (request.commit_id,),
            ).fetchone()[0]
        )
    assert persisted["operation_kind"] == "COMMIT"
    assert persisted["old_certificate_digest"] is None


def test_sqlite_busy_wal_checkpoint_never_publishes_poisoned_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "busy-checkpoint.db"
    real_connect = sqlite_store_module._connect_create

    class BusyCursor:
        def fetchone(self) -> tuple[int, int, int]:
            return (1, 70, 0)

    class BusyConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> object:
            if sql == "PRAGMA wal_checkpoint(TRUNCATE)":
                return BusyCursor()
            return self.connection.execute(sql, parameters)

        def __getattr__(self, name: str) -> object:
            return getattr(self.connection, name)

    def busy_connect(candidate: Path) -> BusyConnection:
        return BusyConnection(real_connect(candidate))

    monkeypatch.setattr(sqlite_store_module, "_connect_create", busy_connect)
    with pytest.raises(ValueError, match="WAL checkpoint"):
        SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())
    assert not path.exists()
    assert not tuple(tmp_path.iterdir())


def test_sqlite_post_link_directory_fsync_failure_removes_only_attempt_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "post-link-fsync.db"
    real_fsync = sqlite_store_module.os.fsync
    calls = 0

    def fail_second_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected parent fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(sqlite_store_module.os, "fsync", fail_second_fsync)
    with pytest.raises(OSError, match="injected parent fsync failure"):
        SQLiteAuthorityStore.provision(path, _config(), _initial_contexts())
    assert not path.exists()
    assert not tuple(tmp_path.iterdir())


@pytest.mark.parametrize("mutation", ("zero-signature", "binding-version"))
def test_sqlite_candidate_coherent_proposal_forgery_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / f"candidate-coherent-{mutation}.db"
    store = _open_store(path, None)
    request = _request(commit_id=f"candidate-{mutation}", nonce_byte=207)
    _advance_candidate(store, request)
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT proposal_json FROM candidates").fetchone()
        assert row is not None
        proposal = json.loads(str(row[0]))
        if mutation == "zero-signature":
            proposal["signatures"]["producer"]["signature_b64u"] = _b64u(bytes(64))
        else:
            proposal["bindings"]["expected_node_version"] = "8"
            proposal["bindings"]["committed_node_version"] = "9"
            connection.execute("UPDATE candidates SET expected_version='8'")
        proposal_json = json.dumps(
            proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        proposal_digest = sha256_digest(proposal_json.encode("utf-8"))
        audit = sqlite_store_module._audit_id(
            CandidateLifecycle.COMMIT_PENDING.value,
            request.commit_id,
            proposal_digest,
        )
        connection.execute(
            "UPDATE candidates SET proposal_json=?,proposal_digest=?,audit_event_id=?",
            (proposal_json, proposal_digest, audit),
        )
        connection.commit()
    before = _KeyProvider.status_signature_count()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)
    assert _KeyProvider.status_signature_count() == before


@pytest.mark.parametrize("mutation", ("remove", "forge"))
def test_sqlite_supersession_operation_old_digest_is_authenticated(
    tmp_path: Path, mutation: str
) -> None:
    path = tmp_path / f"supersession-operation-{mutation}.db"
    store = _open_store(path, None)
    original = _request(commit_id="operation-old-a", nonce_byte=208)
    replacement = _request(
        commit_id="operation-old-b",
        nonce_byte=209,
        attempt_id="operation-old-b",
        expected_node_version="1",
    )
    _advance_candidate(store, original)
    committed = store.atomic_commit(original)
    assert committed.certificate_digest is not None
    _advance_candidate(store, replacement)
    superseded = store.supersede(
        SupersessionRequest(committed.certificate_digest, replacement)
    )
    assert isinstance(superseded, SupersessionCommitted)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT request_json FROM commit_index WHERE commit_id=?",
            (replacement.commit_id,),
        ).fetchone()
        assert row is not None
        operation = json.loads(str(row[0]))
        operation["old_certificate_digest"] = (
            None if mutation == "remove" else _digest(b"forged-old")
        )
        operation["operation_kind"] = "COMMIT" if mutation == "remove" else "SUPERSEDE"
        operation_json = json.dumps(
            operation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        connection.execute(
            "UPDATE commit_index SET request_json=?,request_digest=? WHERE commit_id=?",
            (
                operation_json,
                sha256_digest(operation_json.encode("utf-8")),
                replacement.commit_id,
            ),
        )
        connection.commit()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_commit_operation_cannot_gain_old_digest_or_extra_audit_key(
    tmp_path: Path,
) -> None:
    for mutation in ("old-digest", "audit-extra"):
        path = tmp_path / f"commit-operation-{mutation}.db"
        store = _open_store(path, None)
        request = _request(commit_id=f"commit-{mutation}", nonce_byte=210)
        _advance_candidate(store, request)
        result = store.atomic_commit(request)
        assert result.audit_event_id is not None
        with sqlite3.connect(path) as connection:
            if mutation == "old-digest":
                row = connection.execute(
                    "SELECT request_json FROM commit_index WHERE commit_id=?",
                    (request.commit_id,),
                ).fetchone()
                assert row is not None
                operation = json.loads(str(row[0]))
                operation["operation_kind"] = "SUPERSEDE"
                operation["old_certificate_digest"] = _digest(b"forged-old")
                operation_json = json.dumps(
                    operation,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                connection.execute(
                    "UPDATE commit_index SET request_json=?,request_digest=? WHERE commit_id=?",
                    (
                        operation_json,
                        sha256_digest(operation_json.encode("utf-8")),
                        request.commit_id,
                    ),
                )
            else:
                row = connection.execute(
                    "SELECT event_json FROM audit_events WHERE audit_event_id=?",
                    (result.audit_event_id,),
                ).fetchone()
                assert row is not None
                event = json.loads(str(row[0]))
                event["extra"] = "forged"
                connection.execute(
                    "UPDATE audit_events SET event_json=? WHERE audit_event_id=?",
                    (
                        json.dumps(event, sort_keys=True, separators=(",", ":")),
                        result.audit_event_id,
                    ),
                )
            connection.commit()
        with pytest.raises(ValueError, match="semantic validation failed"):
            SQLiteAuthorityReader.open(path)


def test_sqlite_denial_cannot_be_reclassified_as_conflict_coherently(
    tmp_path: Path,
) -> None:
    path = tmp_path / "denial-to-conflict.db"
    store = _open_store(path, None)
    valid = _request(commit_id="denial-to-conflict", nonce_byte=211)
    invalid = replace(
        valid,
        signatures=replace(
            valid.signatures,
            producer=replace(
                valid.signatures.producer, signature_b64u=_b64u(bytes(64))
            ),
        ),
    )
    denied = store.atomic_commit(invalid)
    assert denied.decision.outcome is RequestOutcome.DENIED
    with sqlite3.connect(path) as connection:
        request_digest = connection.execute(
            "SELECT request_digest FROM commit_index WHERE commit_id=?",
            (invalid.commit_id,),
        ).fetchone()[0]
        old_audit = denied.audit_event_id
        reason = FailureCode.NODE_VERSION_CONFLICT.value
        forged_audit = sqlite_store_module._audit_id(
            RequestOutcome.CONFLICTED.value,
            invalid.commit_id,
            request_digest,
            reason,
        )
        event_json = json.dumps(
            {"kind": reason, "subject": invalid.commit_id},
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "UPDATE audit_events SET audit_event_id=?,event_json=? WHERE audit_event_id=?",
            (forged_audit, event_json, old_audit),
        )
        connection.execute(
            "UPDATE apcc_decisions SET outcome=?,reason=?,audit_event_id=? WHERE commit_id=?",
            (
                RequestOutcome.CONFLICTED.value,
                reason,
                forged_audit,
                invalid.commit_id,
            ),
        )
        connection.commit()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)


def test_sqlite_terminal_replacement_can_be_revoked_and_survives_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "terminal-replacement-revoked.db"
    store = _open_store(path, None)
    original = _request(commit_id="terminal-revoke-a", nonce_byte=212)
    replacement = _request(
        commit_id="terminal-revoke-b",
        nonce_byte=213,
        attempt_id="terminal-revoke-b",
        expected_node_version="1",
    )
    _advance_candidate(store, original)
    committed = store.atomic_commit(original)
    assert committed.certificate_digest is not None
    _advance_candidate(store, replacement)
    superseded = store.supersede(
        SupersessionRequest(committed.certificate_digest, replacement)
    )
    assert isinstance(superseded, SupersessionCommitted)
    replacement_digest = superseded.new_certificate_digest
    revoked = store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            replacement.subject.workflow_id,
            replacement_digest,
            "1",
            "terminal replacement revoked",
        )
    )
    assert revoked.target_id == replacement_digest

    reader = SQLiteAuthorityReader.open(path)
    logical = reader.read_logical_node(
        replacement.subject.workflow_id, replacement.subject.node_id
    )
    assert logical.current_certificate_digest == replacement_digest
    reopened = _reopen_store(path)
    before_signatures = _KeyProvider.status_signature_count()
    status = reopened.current_status(replacement_digest, _nonce(214))
    assert status.status.value == "revoked"
    assert status.superseded.value == "no"
    assert _KeyProvider.status_signature_count() == before_signatures + 1
    delivered = reopened.recover_outbox(OutboxRecoveryRequest("3"))
    assert delivered.delivered_count == "3"
    assert reopened.recover_outbox(OutboxRecoveryRequest("3")).delivered_count == "0"
    assert (
        SQLiteAuthorityReader.open(path)
        .read_logical_node(replacement.subject.workflow_id, replacement.subject.node_id)
        .current_certificate_digest
        == replacement_digest
    )


def test_sqlite_rejects_revoked_nonterminal_supersession_endpoint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "revoked-nonterminal.db"
    store = _open_store(path, None)
    requests = (
        _request(commit_id="revoked-nonterminal-a", nonce_byte=215),
        _request(
            commit_id="revoked-nonterminal-b",
            nonce_byte=216,
            attempt_id="revoked-nonterminal-b",
            expected_node_version="1",
        ),
        _request(
            commit_id="revoked-nonterminal-c",
            nonce_byte=217,
            attempt_id="revoked-nonterminal-c",
            expected_node_version="2",
        ),
    )
    _advance_candidate(store, requests[0])
    current = store.atomic_commit(requests[0])
    assert current.certificate_digest is not None
    middle_digest: str | None = None
    for request in requests[1:]:
        _advance_candidate(store, request)
        replacement = store.supersede(
            SupersessionRequest(current.certificate_digest, request)
        )
        assert isinstance(replacement, SupersessionCommitted)
        current = replacement.commit_result
        if middle_digest is None:
            middle_digest = replacement.new_certificate_digest
        assert current.certificate_digest is not None
    assert middle_digest is not None
    with sqlite3.connect(path) as connection:
        _force_sql_mutation(
            connection,
            "certificate_dispositions",
            "UPDATE certificate_dispositions SET disposition='REVOKED' "
            "WHERE certificate_digest=? AND event_sequence=2",
            (middle_digest,),
        )
        connection.commit()
    before_signatures = _KeyProvider.status_signature_count()
    with pytest.raises(ValueError, match="semantic validation failed"):
        SQLiteAuthorityReader.open(path)
    assert _KeyProvider.status_signature_count() == before_signatures
