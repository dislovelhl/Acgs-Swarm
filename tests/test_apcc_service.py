"""RED contract for the sole APCC authority-producing service."""

from __future__ import annotations

import inspect
from dataclasses import replace
from typing import Never, get_type_hints

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import decode_envelope
from constitutional_swarm.apcc.model import (
    CommitCertificate,
    CommitDecision,
    RequestOutcome,
)
from constitutional_swarm.apcc.ports import (
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    APCCAuthorityConfig,
    AtomicCommitRequest,
    AuthorityClock,
    AuthorityExecutionStore,
    AuthorityKeyProvider,
    AuthorityOutboxSink,
    AuthorityReader,
    AuthorityRuntime,
    AuthoritySigningRole,
    AuthorityStore,
    CommitResult,
    PersistedOutboxEvent,
    ProposeCommitRequest,
    ProposeCommitResult,
    RevocationRequest,
    RevocationScope,
    StageResultRequest,
    StageResultResult,
    StatusFreshnessPolicy,
)
from constitutional_swarm.apcc.service import APCCCommitService
from constitutional_swarm.apcc.verifier import ScopedTrust, TrustRole
from tests.test_apcc_verifier import _b64u, valid_vector


_SEEDS = tuple(bytes(range(start, start + 32)) for start in range(0, 160, 32))
_AUTHORITY_KEY_IDS = {
    AuthoritySigningRole.COMMIT: next(
        binding.key_id
        for binding in valid_vector().trust.bindings
        if binding.role is TrustRole.COMMIT
    ),
    AuthoritySigningRole.STATUS: next(
        binding.key_id
        for binding in valid_vector().trust.bindings
        if binding.role is TrustRole.STATUS
    ),
}
_AUTHORITY_SCOPE_MUTATIONS = tuple(
    (binding.role, index)
    for binding in valid_vector().trust.bindings
    if binding.role in (TrustRole.COMMIT, TrustRole.STATUS)
    for index in range(len(binding.scope))
)
_REQUEST_SCOPE_MUTATIONS = tuple(
    (binding.role, index)
    for binding in valid_vector().trust.bindings
    if binding.role in (TrustRole.PRODUCER, TrustRole.POLICY, TrustRole.REGISTRY)
    for index in range(len(binding.scope))
)


def _config(trust: ScopedTrust | None = None) -> APCCAuthorityConfig:
    bindings = (trust or valid_vector().trust).bindings
    by_role = {
        role: tuple(binding for binding in bindings if binding.role is role)
        for role in TrustRole
    }
    return APCCAuthorityConfig(
        authority_store_id="store-1",
        producer_trust=by_role[TrustRole.PRODUCER],
        policy_trust=by_role[TrustRole.POLICY],
        registry_trust=by_role[TrustRole.REGISTRY],
        commit_trust=by_role[TrustRole.COMMIT][0],
        status_trust=by_role[TrustRole.STATUS][0],
        freshness=StatusFreshnessPolicy("5000", "1000"),
    )


class _KeyProvider:
    def __init__(self, commit_seed: bytes, status_seed: bytes) -> None:
        self._seeds = {
            AuthoritySigningRole.COMMIT: commit_seed,
            AuthoritySigningRole.STATUS: status_seed,
        }

    def _seed(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        if key_id != _AUTHORITY_KEY_IDS[role]:
            raise ValueError(f"unexpected {role.value} key identity: {key_id}")
        return self._seeds[role]

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        return (
            Ed25519PrivateKey.from_private_bytes(self._seed(role, key_id))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ):
        from constitutional_swarm.apcc.model import Signature

        signature = Ed25519PrivateKey.from_private_bytes(self._seed(role, key_id)).sign(
            domain + b"\x00" + canonical_body
        )
        return Signature("Ed25519", key_id, _b64u(signature))


class _Clock:
    def now_ms(self) -> int:
        return 1_760_000_001_000


class _Sink:
    def deliver(self, event_id: str, payload: bytes) -> None:
        del event_id, payload


def _runtime(
    commit_seed: bytes = _SEEDS[3], status_seed: bytes = _SEEDS[4]
) -> AuthorityRuntime:
    return AuthorityRuntime(_KeyProvider(commit_seed, status_seed), _Clock(), _Sink())


def test_runtime_dependencies_are_typed_and_private_material_is_not_a_port_field() -> (
    None
):
    runtime = _runtime()
    assert isinstance(runtime.key_provider, AuthorityKeyProvider)
    assert isinstance(runtime.clock, AuthorityClock)
    assert isinstance(runtime.outbox_sink, AuthorityOutboxSink)
    assert not {
        "private_seed",
        "commit_private_seed",
        "status_private_seed",
        "signers",
    } & set(inspect.get_annotations(AuthorityRuntime))


@pytest.mark.parametrize("missing_role", tuple(TrustRole))
def test_missing_role_is_rejected_before_store_snapshot_changes(
    missing_role: TrustRole,
) -> None:
    base = valid_vector().trust
    missing = replace(
        base,
        bindings=tuple(
            binding for binding in base.bindings if binding.role is not missing_role
        ),
    )
    store = _SnapshotStore()
    with pytest.raises((ValueError, IndexError)):
        _service(store=store, config=_config(missing), runtime=_runtime())
    assert store.calls == 0


@pytest.mark.parametrize(("role", "scope_index"), _AUTHORITY_SCOPE_MUTATIONS)
def test_commit_and_status_store_scope_fields_are_checked_at_construction(
    role: TrustRole, scope_index: int
) -> None:
    base = valid_vector().trust
    binding = next(item for item in base.bindings if item.role is role)
    wrong_scope = list(binding.scope)
    wrong_scope[scope_index] = f"wrong-{role.value}-{scope_index}"
    wrong = ScopedTrust(
        tuple(
            replace(item, scope=tuple(wrong_scope)) if item is binding else item
            for item in base.bindings
        )
    )
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(store=store, config=_config(wrong), runtime=_runtime())
    assert store.calls == 0


@pytest.mark.parametrize(("role", "scope_index"), _REQUEST_SCOPE_MUTATIONS)
def test_request_scope_validation_is_delegated_to_the_store_guard(
    role: TrustRole, scope_index: int
) -> None:
    base = valid_vector().trust
    binding = next(item for item in base.bindings if item.role is role)
    wrong_scope = list(binding.scope)
    wrong_scope[scope_index] = f"other-{role.value}-{scope_index}"
    wrong = ScopedTrust(
        tuple(
            replace(item, scope=tuple(wrong_scope)) if item is binding else item
            for item in base.bindings
        )
    )
    store = _SnapshotStore()
    service = _service(store=store, config=_config(wrong), runtime=_runtime())
    assert service.commit(_typed_request()) is store.result
    assert store.calls == 1


@pytest.mark.parametrize("reused_role", range(3))
def test_runtime_commit_key_cannot_reuse_any_non_authority_role(
    reused_role: int,
) -> None:
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(
            store=store,
            config=_config(),
            runtime=_runtime(commit_seed=_SEEDS[reused_role]),
        )
    assert store.calls == 0


@pytest.mark.parametrize("role", (TrustRole.COMMIT, TrustRole.STATUS))
def test_commit_and_status_role_scope_and_key_id_are_exact(role: TrustRole) -> None:
    base = valid_vector().trust
    wrong = ScopedTrust(
        tuple(
            replace(binding, key_id="wrong-key") if binding.role is role else binding
            for binding in base.bindings
        )
    )
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(store=store, config=_config(wrong), runtime=_runtime())
    assert store.calls == 0


@pytest.mark.parametrize("role", (TrustRole.COMMIT, TrustRole.STATUS))
def test_authority_store_scope_is_bound_for_commit_and_status_keys(
    role: TrustRole,
) -> None:
    base = valid_vector().trust
    wrong = ScopedTrust(
        tuple(
            replace(binding, scope=("wrong-store",))
            if binding.role is role
            else binding
            for binding in base.bindings
        )
    )
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(store=store, config=_config(wrong), runtime=_runtime())
    assert store.calls == 0


def test_both_authority_roles_cannot_agree_on_the_wrong_store() -> None:
    base = valid_vector().trust
    wrong = ScopedTrust(
        tuple(
            replace(binding, scope=("wrong-store",))
            if binding.role in (TrustRole.COMMIT, TrustRole.STATUS)
            else binding
            for binding in base.bindings
        )
    )
    store = _SnapshotStore(authority_store_id="store-1")
    with pytest.raises(ValueError):
        _service(store=store, config=_config(wrong), runtime=_runtime())
    assert store.calls == 0


def test_commit_and_status_bindings_cannot_be_swapped_or_reused() -> None:
    base = valid_vector().trust
    commit = next(item for item in base.bindings if item.role is TrustRole.COMMIT)
    status = next(item for item in base.bindings if item.role is TrustRole.STATUS)
    swapped = ScopedTrust(
        tuple(
            replace(item, key_id=status.key_id, public_key=status.public_key)
            if item.role is TrustRole.COMMIT
            else replace(item, key_id=commit.key_id, public_key=commit.public_key)
            if item.role is TrustRole.STATUS
            else item
            for item in base.bindings
        )
    )
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(store=store, config=_config(swapped), runtime=_runtime())
    assert store.calls == 0


@pytest.mark.parametrize("reused_seed", _SEEDS[:3])
def test_runtime_status_key_cannot_reuse_any_non_authority_role(
    reused_seed: bytes,
) -> None:
    with pytest.raises(ValueError):
        _service(
            store=_SnapshotStore(),
            config=_config(),
            runtime=_runtime(status_seed=reused_seed),
        )


def test_two_distinct_wrong_authority_signers_are_rejected_together() -> None:
    wrong_commit_seed = bytes(reversed(_SEEDS[3]))
    wrong_status_seed = bytes(reversed(_SEEDS[4]))
    assert wrong_commit_seed != wrong_status_seed
    store = _SnapshotStore()
    with pytest.raises(ValueError):
        _service(
            store=store,
            config=_config(),
            runtime=_runtime(wrong_commit_seed, wrong_status_seed),
        )
    assert store.calls == 0


def test_candidate_transition_ports_are_typed_and_separate_from_atomic_commit() -> None:
    assert get_type_hints(AuthorityStore)["authority_store_id"] is str
    expected = (
        ("stage_result", StageResultRequest, StageResultResult),
        ("assemble_evidence", AssembleEvidenceRequest, AssembleEvidenceResult),
        ("propose_commit", ProposeCommitRequest, ProposeCommitResult),
    )
    operations = {
        name
        for protocol in (AuthorityReader, AuthorityStore)
        for name, member in protocol.__dict__.items()
        if not name.startswith("_") and callable(member)
    }
    annotations_by_operation = {
        "stage_result": (
            get_type_hints(AuthorityStore.stage_result),
            get_type_hints(APCCCommitService.stage_result),
        ),
        "assemble_evidence": (
            get_type_hints(AuthorityStore.assemble_evidence),
            get_type_hints(APCCCommitService.assemble_evidence),
        ),
        "propose_commit": (
            get_type_hints(AuthorityStore.propose_commit),
            get_type_hints(APCCCommitService.propose_commit),
        ),
    }
    for operation, request_type, result_type in expected:
        assert operation in operations
        annotations, service_annotations = annotations_by_operation[operation]
        assert annotations["request"] is request_type
        assert annotations["return"] is result_type
        assert service_annotations["request"] is request_type
        assert service_annotations["return"] is result_type
        assert set(inspect.get_annotations(result_type)) == {
            "candidate_state",
            "audit_event_id",
        }
    assert "atomic_commit" in operations
    assert "get_outbox_event" in operations
    outbox_annotations = get_type_hints(AuthorityStore.get_outbox_event)
    assert outbox_annotations["commit_id"] is str
    assert outbox_annotations["return"] is PersistedOutboxEvent


def test_revocation_targets_are_typed_and_have_exact_scope_semantics() -> None:
    digest = decode_envelope(valid_vector().envelope).payload_sha256
    certificate = RevocationRequest(
        RevocationScope.CERTIFICATE, "workflow-1", digest, "1", "direct"
    )
    actor_one = RevocationRequest(
        RevocationScope.ACTOR, "workflow-1", "agent-1", "1", "actor"
    )
    actor_two = replace(actor_one, workflow_id="workflow-2")
    workflow = RevocationRequest(
        RevocationScope.WORKFLOW, "workflow-1", "workflow-1", "1", "workflow"
    )
    assert certificate.target_id == digest
    assert (actor_one.workflow_id, actor_one.target_id) != (
        actor_two.workflow_id,
        actor_two.target_id,
    )
    assert workflow.target_id == workflow.workflow_id
    with pytest.raises(ValueError, match="SHA-256 digest"):
        RevocationRequest(
            RevocationScope.CERTIFICATE, "workflow-1", "not-a-digest", "1", "bad"
        )
    with pytest.raises(ValueError, match="must equal workflow_id"):
        RevocationRequest(
            RevocationScope.WORKFLOW, "workflow-1", "workflow-2", "1", "bad"
        )


def test_service_delegates_one_commit_to_the_store_once() -> None:
    annotations = get_type_hints(APCCCommitService.commit)
    assert annotations["request"] is AtomicCommitRequest
    assert annotations["return"] is CommitResult
    store = _SnapshotStore()
    assert isinstance(store, AuthorityExecutionStore)
    service = _service(store=store, config=_config(), runtime=_runtime())
    marker = _typed_request()
    assert service.commit(marker) is store.result
    assert store.calls == 1


def _typed_request() -> AtomicCommitRequest:
    certificate = CommitCertificate.from_object(valid_vector().payload)
    return AtomicCommitRequest(
        certificate.subject,
        certificate.context,
        certificate.evidence,
        certificate.bindings,
        certificate.signatures,
        certificate.decision.commit_id,
        certificate.decision.nonce,
        certificate.evidence.producer_statement_digest,
    )


class _SnapshotStore:
    authority_store_id: str

    def __init__(self, authority_store_id: str = "store-1") -> None:
        self.authority_store_id = authority_store_id
        self.calls = 0
        self.result = _committed_result()

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult:
        assert isinstance(request, AtomicCommitRequest)
        self.calls += 1
        return self.result

    @staticmethod
    def _unexpected(operation: str) -> Never:
        raise AssertionError(f"unexpected execution-store operation: {operation}")

    def read_commit_context(self, request: object) -> Never:
        self._unexpected("read_commit_context")

    def read_logical_node(self, workflow_id: object, node_id: object) -> Never:
        self._unexpected("read_logical_node")

    def replay_commit(self, request: object) -> Never:
        self._unexpected("replay_commit")

    def get_certificate(self, commit_id: object) -> Never:
        self._unexpected("get_certificate")

    def get_outbox_event(self, commit_id: object) -> Never:
        self._unexpected("get_outbox_event")

    def stage_result(self, request: object) -> Never:
        self._unexpected("stage_result")

    def assemble_evidence(self, request: object) -> Never:
        self._unexpected("assemble_evidence")

    def propose_commit(self, request: object) -> Never:
        self._unexpected("propose_commit")

    def current_status(
        self, certificate_digest: object, request_nonce: object
    ) -> Never:
        self._unexpected("current_status")

    def current_status_batch(self, requests: object) -> Never:
        self._unexpected("current_status_batch")

    def logical_node_status_batch(self, requests: object) -> Never:
        self._unexpected("logical_node_status_batch")


def _service(
    *,
    store: AuthorityExecutionStore,
    config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
) -> APCCCommitService:
    """Construct the service while keeping the deliberately narrow test double."""
    return APCCCommitService(store=store, config=config, runtime=runtime)


def _committed_result() -> CommitResult:
    vector = valid_vector()
    certificate = CommitCertificate.from_object(vector.payload)
    envelope = decode_envelope(vector.envelope)
    return CommitResult(
        CommitDecision(
            certificate.decision.commit_id,
            RequestOutcome.COMMITTED,
            certificate.decision.reason,
        ),
        envelope.payload,
        vector.envelope,
        envelope.payload_sha256,
        "audit-service-fake",
    )
