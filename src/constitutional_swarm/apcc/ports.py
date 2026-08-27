"""Typed, implementation-neutral authority boundary for APCC operations."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

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
)


class RevocationScope(StrEnum):
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
    scope: RevocationScope
    workflow_id: str
    target_id: str
    next_generation: str
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", RevocationScope(self.scope))


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
class SupersessionResult:
    commit_result: CommitResult
    old_certificate_digest: str
    new_certificate_digest: str
    outbox_event_id: str
    audit_event_id: str

    def __post_init__(self) -> None:
        if self.commit_result.decision.outcome is not RequestOutcome.COMMITTED:
            raise ValueError("supersession must return a committed result")
        if self.commit_result.certificate_digest != self.new_certificate_digest:
            raise ValueError(
                "supersession result digest must equal the replacement certificate digest"
            )
        if self.old_certificate_digest == self.new_certificate_digest:
            raise ValueError(
                "supersession replacement digest must differ from old digest"
            )
        if not self.outbox_event_id:
            raise ValueError("supersession requires an outbox event identity")
        if self.audit_event_id != self.commit_result.audit_event_id:
            raise ValueError("supersession audit identity must match its commit result")


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


class AuthorityStore(Protocol):
    """Capabilities required from a linearizable APCC authority boundary."""

    def stage_result(self, request: StageResultRequest) -> StageResultResult: ...

    def read_commit_context(self, request: CommitContextRequest) -> CommitContext: ...

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult: ...

    def replay_commit(self, request: ReplayCommitRequest) -> CommitResult: ...

    def get_certificate(self, commit_id: str) -> bytes | None:
        """Return the exact persisted certificate envelope bytes for ``commit_id``."""
        ...

    def current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus: ...

    def revoke(self, request: RevocationRequest) -> RevocationResult: ...

    def supersede(self, request: SupersessionRequest) -> SupersessionResult: ...

    def recover(self, request: RecoveryRequest) -> CommitResult: ...

    def recover_outbox(
        self, request: OutboxRecoveryRequest
    ) -> OutboxRecoveryResult: ...
