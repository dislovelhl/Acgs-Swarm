"""Real SQLite APCC authority-store contract (intentionally RED initially)."""

from __future__ import annotations

import base64
import copy
import inspect
import multiprocessing
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Protocol, get_type_hints

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import constitutional_swarm.governed_commit as governed_commit_module
import constitutional_swarm.swarm as swarm_module
from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    CandidateLifecycle,
    CandidateState,
    CommitCertificate,
    FailureCode,
    LogicalNodeState,
    Signature,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AtomicCommitRequest,
    AuthorityRuntime,
    AuthoritySigningRole,
    CommitResult,
    CommitContextRequest,
    CommitContext,
    OutboxRecoveryRequest,
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
    assert_fault_is_atomic,
    assert_supersession_fault_is_atomic,
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

    def commit(self, request: GovernedCommitRequest) -> GovernedCommitDecision: ...

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

    def _provision_with_projection_probe(
        self, path: Path, *, probe: FaultProbe
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
        signature = Ed25519PrivateKey.from_private_bytes(self._seed(role)).sign(
            domain + b"\x00" + canonical_body
        )
        return Signature("Ed25519", key_id, _b64u(signature))


class _Clock:
    def now_ms(self) -> int:
        return 1_760_000_001_000


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
    authority_root = "dispatcher-authority-root"
    return APCCAuthorityConfig(
        authority_store_id=authority_store_id,
        producer_trust=(
            TrustBinding(
                role=TrustRole.PRODUCER,
                scope=("agent", "dispatcher-actor-authority", authority_root),
                key_id="dispatcher-producer-key",
                public_key=producer_public_key,
            ),
        ),
        policy_trust=(
            TrustBinding(
                role=TrustRole.POLICY,
                scope=("dispatcher-policy", "apcc-policy", "1"),
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
        }
    )
    payload["bindings"]["predecessors"] = predecessors or []
    payload["bindings"]["predecessor_root"] = _digest(
        _canonical(payload["bindings"]["predecessors"])
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

    return tuple(
        initial_context(workflow_id, node_id)
        for workflow_id, node_id in (
            ("workflow-1", "node-1"),
            ("workflow-1", "root"),
            ("workflow-1", "middle"),
            ("workflow-1", "leaf"),
            ("workflow-1", "child"),
            ("workflow-2", "node-1"),
        )
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
    with sqlite3.connect(store.database_path) as connection:
        tables = tuple(
            name
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        contents = {
            name: tuple(
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


def _resigned_status(status: AuthorityStatus, **changes: str) -> AuthorityStatus:
    body = status.body_object()
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
    assert changed == {"commit_index", "request_index", "decisions", "audit_events"}
    assert len(after.tables["commit_index"]) == len(before.tables["commit_index"]) + 1
    assert len(after.tables["request_index"]) == len(before.tables["request_index"]) + 1
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
        "candidates",
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
        "trust_log",
        "audit_events",
        "outbox",
    }
)
_CERTIFICATE_REVOCATION_WRITE_TABLES = frozenset(
    {"certificate_dispositions", "trust_log", "audit_events", "outbox"}
)
_ACTOR_REVOCATION_WRITE_TABLES = frozenset(
    {"actor_revocations", "trust_log", "audit_events", "outbox"}
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


def _harness() -> AuthorityStoreHarness:
    return AuthorityStoreHarness(
        _open_store,
        _reopen_store,
        _request,
        valid_vector().trust,
        _snapshot,
        _stage_request,
        _assemble_evidence_request,
        _propose_commit_request,
        _outbox_event,
        _only_conflict_and_audit,
        _only_denied_decision_and_audit,
        _missing_recovery_delta,
        _only_outbox_delivery,
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


class _OneShotProjectionProbe:
    """Private GCB seam proving APCC and compatibility projection are atomic."""

    def __init__(self) -> None:
        self.triggered = False

    def hit(self, point: str) -> None:
        if (
            point == "after_apcc_authority_write_before_legacy_projection"
            and not self.triggered
        ):
            self.triggered = True
            raise _InjectedFault(point)


class _GCBFactory:
    @staticmethod
    def provision_with_projection_probe(
        bootstrap: _GCBBootstrap,
        path: Path,
        probe: FaultProbe,
    ) -> _GCBAdmin:
        return bootstrap._provision_with_projection_probe(path, probe=probe)


def test_public_sqlite_open_has_no_fault_injection_parameter() -> None:
    public_parameters = inspect.signature(SQLiteAuthorityStore.open).parameters
    assert not {
        "fault_point",
        "fail_controller",
        "_fail_controller",
        "probe",
        "_probe",
    } & set(public_parameters)
    assert object not in get_type_hints(SQLiteAuthorityStore.open).values()


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
        "projection_path",
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
            "dispatcher-actor-authority",
            "dispatcher-authority-root",
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
        SQLiteAuthorityStore.open(Path(path), config=_config())
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
    assert reopened.atomic_commit(replacement_request) == replay
    assert _snapshot(reopened) == persisted


def test_sqlite_supersession_preserves_committed_children_and_rejects_stale_pending(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supersession-predecessors.db"
    store = _open_store(path, None)
    root_request = _request(commit_id="pred-root", nonce_byte=83, node_id="root")
    _advance_candidate(store, root_request)
    root = store.atomic_commit(root_request)
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
            "1",
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
    tampered["signature"]["signature_b64u"] = _b64u(bytes(64))
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


def test_executor_and_gcb_route_only_once_through_apcc_and_block_legacy_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    projection_probe = _OneShotProjectionProbe()
    admin = _GCBFactory.provision_with_projection_probe(
        bootstrap, authority_path, projection_probe
    )
    assert Path(admin.commit_port.path) == authority_path
    artifacts = ArtifactStore()
    executor = _SWARM_EXECUTOR(registry, artifacts, admin, policy_version="apcc-policy")
    dag = TaskDAG(dag_id="dispatcher", goal="g").add_node(
        TaskNode(node_id="root", required_capabilities=("work",))
    )
    executor.load_dag(dag)
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
    with pytest.raises(
        _InjectedFault,
        match="after_apcc_authority_write_before_legacy_projection",
    ):
        executor.commit(request)
    assert projection_probe.triggered
    assert _gcb_authority_snapshot(admin) == before_atomic_commit
    failed_reader = SQLiteAuthorityReader.open(authority_path)
    assert failed_reader.get_certificate(request.commit_id) is None
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
