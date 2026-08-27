"""Typed, implementation-neutral authority boundary for APCC operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol, TypeAlias, runtime_checkable

from .crypto import b64u_decode
from .model import (
    AuthorityStatus,
    CertificateBindings,
    CertificateContext,
    CertificateEvidence,
    CertificateSignatures,
    CertificateSubject,
    CandidateState,
    CommitDecision,
    LogicalNodeState,
    PredecessorRef,
    RequestOutcome,
    Signature,
)
from .verifier import TrustBinding, TrustRole


_MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _positive_decimal(value: str, field_name: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise ValueError(f"{field_name} must be a canonical decimal string")
    parsed = int(value)
    if parsed <= 0 or parsed > _MAX_SAFE_INTEGER:
        raise ValueError(f"{field_name} must be positive and safely representable")
    return parsed


class AuthoritySigningRole(StrEnum):
    """The only private signing roles held by an APCC authority process."""

    COMMIT = "commit"
    STATUS = "status"


@runtime_checkable
class AuthorityKeyProvider(Protocol):
    """Per-process signer; implementations never expose private key material."""

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes: ...

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature: ...


@runtime_checkable
class AuthorityClock(Protocol):
    """Trusted authority clock used to construct signed decimal timestamps."""

    def now_ms(self) -> int: ...


@runtime_checkable
class AuthorityOutboxSink(Protocol):
    """Idempotent post-commit delivery keyed by the persisted event identity."""

    def deliver(self, event_id: str, payload: bytes) -> None: ...


@dataclass(frozen=True, slots=True)
class AuthorityRuntime:
    """Ephemeral dependencies required by every read-write authority instance."""

    key_provider: AuthorityKeyProvider
    clock: AuthorityClock
    outbox_sink: AuthorityOutboxSink


@dataclass(frozen=True, slots=True)
class StatusFreshnessPolicy:
    """Shared issuer/consumer bounds for one authority-status deployment."""

    maximum_staleness_ms: str
    issued_status_lifetime_ms: str

    def __post_init__(self) -> None:
        maximum = _positive_decimal(self.maximum_staleness_ms, "maximum_staleness_ms")
        lifetime = _positive_decimal(
            self.issued_status_lifetime_ms, "issued_status_lifetime_ms"
        )
        if lifetime > maximum:
            raise ValueError(
                "issued_status_lifetime_ms cannot exceed maximum_staleness_ms"
            )


@dataclass(frozen=True, slots=True)
class APCCAuthorityConfig:
    """One-time, public-only identity and five-role trust configuration."""

    authority_store_id: str
    producer_trust: tuple[TrustBinding, ...]
    policy_trust: tuple[TrustBinding, ...]
    registry_trust: tuple[TrustBinding, ...]
    commit_trust: TrustBinding
    status_trust: TrustBinding
    freshness: StatusFreshnessPolicy

    def __post_init__(self) -> None:
        if not self.authority_store_id:
            raise ValueError("authority_store_id cannot be empty")
        role_groups = (
            (TrustRole.PRODUCER, tuple(self.producer_trust)),
            (TrustRole.POLICY, tuple(self.policy_trust)),
            (TrustRole.REGISTRY, tuple(self.registry_trust)),
            (TrustRole.COMMIT, (self.commit_trust,)),
            (TrustRole.STATUS, (self.status_trust,)),
        )
        for role, bindings in role_groups:
            if not bindings or any(binding.role is not role for binding in bindings):
                raise ValueError(f"complete {role.value} trust is required")
        if self.commit_trust.scope != (self.authority_store_id,):
            raise ValueError("commit trust must be scoped to authority_store_id")
        if self.status_trust.scope != (self.authority_store_id,):
            raise ValueError("status trust must be scoped to authority_store_id")
        all_bindings = tuple(
            binding for _role, bindings in role_groups for binding in bindings
        )
        key_roles: dict[str, TrustRole] = {}
        material_roles: dict[bytes, TrustRole] = {}
        for binding in all_bindings:
            prior_key_role = key_roles.get(binding.key_id)
            prior_material_role = material_roles.get(binding.public_key)
            if prior_key_role is not None and prior_key_role is not binding.role:
                raise ValueError("APCC key IDs cannot be reused across trust roles")
            if (
                prior_material_role is not None
                and prior_material_role is not binding.role
            ):
                raise ValueError("APCC public keys cannot be reused across trust roles")
            key_roles[binding.key_id] = binding.role
            material_roles[binding.public_key] = binding.role
        object.__setattr__(self, "producer_trust", role_groups[0][1])
        object.__setattr__(self, "policy_trust", role_groups[1][1])
        object.__setattr__(self, "registry_trust", role_groups[2][1])

    @property
    def trust_bindings(self) -> tuple[TrustBinding, ...]:
        """Return all persisted public bindings in stable role order."""
        return (
            *self.producer_trust,
            *self.policy_trust,
            *self.registry_trust,
            self.commit_trust,
            self.status_trust,
        )


class RevocationScope(StrEnum):
    CERTIFICATE = "CERTIFICATE"
    ACTOR = "ACTOR"
    WORKFLOW = "WORKFLOW"


@dataclass(frozen=True, slots=True)
class StageResultRequest:
    subject: CertificateSubject
    expected_node_version: str
    result_bytes: bytes


@dataclass(frozen=True, slots=True)
class StageResultResult:
    candidate_state: CandidateState
    audit_event_id: str


@dataclass(frozen=True, slots=True)
class AssembleEvidenceRequest:
    proposal: AtomicCommitRequest


@dataclass(frozen=True, slots=True)
class AssembleEvidenceResult:
    candidate_state: CandidateState
    audit_event_id: str


@dataclass(frozen=True, slots=True)
class ProposeCommitRequest:
    proposal: AtomicCommitRequest


@dataclass(frozen=True, slots=True)
class ProposeCommitResult:
    candidate_state: CandidateState
    audit_event_id: str


@dataclass(frozen=True, slots=True)
class CommitContextRequest:
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str


@dataclass(frozen=True, slots=True)
class CommitContext:
    subject: CertificateSubject
    governance: CertificateContext
    candidate_state: CandidateState
    logical_node_state: LogicalNodeState
    predecessors: tuple[PredecessorRef, ...]
    audit_event_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "predecessors", tuple(self.predecessors))


@dataclass(frozen=True, slots=True)
class AtomicCommitRequest:
    """Typed proposal with authority-store-global ``commit_id`` and nonce."""

    subject: CertificateSubject
    context: CertificateContext
    evidence: CertificateEvidence
    bindings: CertificateBindings
    signatures: CertificateSignatures
    commit_id: str
    nonce: str
    request_digest: str


@dataclass(frozen=True, slots=True)
class ReplayCommitRequest:
    commit_id: str
    request_digest: str


@dataclass(frozen=True, slots=True)
class CommitResult:
    decision: CommitDecision
    certificate_payload_bytes: bytes | None
    certificate_envelope_bytes: bytes | None
    certificate_digest: str | None
    audit_event_id: str

    def __post_init__(self) -> None:
        proof_items = (
            self.certificate_payload_bytes,
            self.certificate_envelope_bytes,
            self.certificate_digest,
        )
        has_certificate = all(item is not None for item in proof_items)
        has_no_certificate = all(item is None for item in proof_items)
        if not has_certificate and not has_no_certificate:
            raise ValueError(
                "certificate payload, envelope, and digest must be present together"
            )
        authoritative = self.decision.outcome is RequestOutcome.COMMITTED
        if authoritative != has_certificate:
            raise ValueError(
                "committed outcomes require exact certificate payload, envelope, and "
                "digest; "
                "other outcomes forbid them"
            )
        if has_certificate:
            assert self.certificate_payload_bytes is not None
            assert self.certificate_envelope_bytes is not None
            assert self.certificate_digest is not None
            from .codec import CodecError, decode_envelope
            from .crypto import sha256_digest

            expected_digest = sha256_digest(self.certificate_payload_bytes)
            if self.certificate_digest != expected_digest:
                raise ValueError(
                    "certificate digest does not match certificate payload"
                )
            try:
                envelope = decode_envelope(self.certificate_envelope_bytes)
            except CodecError as error:
                raise ValueError("certificate envelope is invalid") from error
            if (
                envelope.payload != self.certificate_payload_bytes
                or envelope.payload_sha256 != self.certificate_digest
            ):
                raise ValueError(
                    "certificate envelope does not match the payload and digest"
                )


@dataclass(frozen=True, slots=True)
class RevocationRequest:
    """Typed revocation request.

    ``CERTIFICATE`` targets an exact certificate payload digest. ``ACTOR``
    targets an Agent identifier with canonical workflow-scoped key
    ``(workflow_id, target_id)``. ``WORKFLOW`` targets the workflow itself and
    therefore requires ``target_id == workflow_id``.
    """

    scope: RevocationScope
    workflow_id: str
    target_id: str
    next_generation: str
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", RevocationScope(self.scope))
        if not self.workflow_id or not self.target_id:
            raise ValueError("revocation workflow and target cannot be empty")
        if self.scope is RevocationScope.CERTIFICATE:
            try:
                b64u_decode(self.target_id, expected_length=32)
            except ValueError as error:
                raise ValueError(
                    "certificate revocation target must be a SHA-256 digest"
                ) from error
        if (
            self.scope is RevocationScope.WORKFLOW
            and self.target_id != self.workflow_id
        ):
            raise ValueError("workflow revocation target must equal workflow_id")


@dataclass(frozen=True, slots=True)
class SupersessionRequest:
    old_certificate_digest: str
    new_proposal: AtomicCommitRequest


@dataclass(frozen=True, slots=True)
class RevocationResult:
    scope: RevocationScope
    target_id: str
    resulting_generation: str
    audit_event_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", RevocationScope(self.scope))


@dataclass(frozen=True, slots=True)
class SupersessionCommitted:
    """Durable committed replacement with all authority identities present."""

    commit_result: CommitResult
    old_certificate_digest: str
    new_certificate_digest: str
    replacement_edge_id: str
    outbox_event_id: str
    kind: Literal["COMMITTED"] = field(default="COMMITTED", init=False)

    def __post_init__(self) -> None:
        if not self.old_certificate_digest:
            raise ValueError("supersession requires an old certificate digest")
        if self.commit_result.decision.outcome is not RequestOutcome.COMMITTED:
            raise ValueError("committed supersession requires a COMMITTED decision")
        if not all(
            (
                self.new_certificate_digest,
                self.replacement_edge_id,
                self.outbox_event_id,
            )
        ):
            raise ValueError("committed supersession requires all success identities")
        if self.commit_result.certificate_digest != self.new_certificate_digest:
            raise ValueError(
                "supersession result digest must equal the replacement certificate digest"
            )
        if self.old_certificate_digest == self.new_certificate_digest:
            raise ValueError(
                "supersession replacement digest must differ from old digest"
            )


@dataclass(frozen=True, slots=True)
class SupersessionDenied:
    """Durable denied replacement; replay returns this exact branch."""

    commit_result: CommitResult
    old_certificate_digest: str
    kind: Literal["DENIED"] = field(default="DENIED", init=False)

    def __post_init__(self) -> None:
        if not self.old_certificate_digest:
            raise ValueError("supersession requires an old certificate digest")
        if self.commit_result.decision.outcome is not RequestOutcome.DENIED:
            raise ValueError("denied supersession requires a DENIED decision")


@dataclass(frozen=True, slots=True)
class SupersessionConflicted:
    """Durable commit-id conflict; replay returns this exact branch."""

    commit_result: CommitResult
    old_certificate_digest: str
    kind: Literal["CONFLICTED"] = field(default="CONFLICTED", init=False)

    def __post_init__(self) -> None:
        if not self.old_certificate_digest:
            raise ValueError("supersession requires an old certificate digest")
        if self.commit_result.decision.outcome is not RequestOutcome.CONFLICTED:
            raise ValueError("conflicted supersession requires a CONFLICTED decision")


SupersessionResult: TypeAlias = (
    SupersessionCommitted | SupersessionDenied | SupersessionConflicted
)


@dataclass(frozen=True, slots=True)
class RecoveryRequest:
    commit_id: str
    request_digest: str


@dataclass(frozen=True, slots=True)
class OutboxRecoveryRequest:
    max_items: str


@dataclass(frozen=True, slots=True)
class OutboxRecoveryResult:
    delivered_count: str
    pending_count: str
    audit_event_id: str


@dataclass(frozen=True, slots=True)
class PersistedOutboxEvent:
    event_id: str
    payload: bytes
    audit_event_id: str
    pending: bool


class AuthorityReader(Protocol):
    """Signer-free, non-mutating authority access."""

    authority_store_id: str

    def read_commit_context(self, request: CommitContextRequest) -> CommitContext: ...

    def read_logical_node(self, workflow_id: str, node_id: str) -> LogicalNodeState: ...

    def replay_commit(self, request: ReplayCommitRequest) -> CommitResult: ...

    def get_certificate(self, commit_id: str) -> bytes | None:
        """Return the exact persisted certificate envelope bytes for ``commit_id``."""
        ...

    def get_outbox_event(self, commit_id: str) -> PersistedOutboxEvent: ...


class AuthorityStore(AuthorityReader, Protocol):
    """Capabilities required from a linearizable APCC authority boundary."""

    authority_store_id: str

    def stage_result(self, request: StageResultRequest) -> StageResultResult: ...

    def assemble_evidence(
        self, request: AssembleEvidenceRequest
    ) -> AssembleEvidenceResult: ...

    def propose_commit(self, request: ProposeCommitRequest) -> ProposeCommitResult: ...

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult: ...

    def current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus: ...

    def revoke(self, request: RevocationRequest) -> RevocationResult: ...

    def supersede(self, request: SupersessionRequest) -> SupersessionResult: ...

    def recover(self, request: RecoveryRequest) -> CommitResult: ...

    def recover_outbox(
        self, request: OutboxRecoveryRequest
    ) -> OutboxRecoveryResult: ...
