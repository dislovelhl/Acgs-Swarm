"""Immutable, persistence-independent APCC v1 protocol records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, cast


Statement = Mapping[str, str]


def _object(value: object) -> Mapping[str, object]:
    """Validate the object boundary shared by public model constructors."""
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError("APCC object must be a string-keyed mapping")
    return cast("Mapping[str, object]", value)


def _expect_keys(value: Mapping[str, object], expected: tuple[str, ...]) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        missing = sorted(wanted - actual)
        unknown = sorted(actual - wanted)
        raise ValueError(
            f"invalid APCC object keys: missing={missing}, unknown={unknown}"
        )


def _string(value: Mapping[str, object], key: str) -> str:
    item = value[key]
    if not isinstance(item, str):
        raise TypeError(f"APCC field {key!r} must be a string")
    return item


class CandidateLifecycle(StrEnum):
    UNSEEN = "UNSEEN"
    ELIGIBLE = "ELIGIBLE"
    EXECUTING = "EXECUTING"
    RESULT_STAGED = "RESULT_STAGED"
    EVIDENCE_ASSEMBLED = "EVIDENCE_ASSEMBLED"
    COMMIT_PENDING = "COMMIT_PENDING"
    QUARANTINED = "QUARANTINED"


class CertificateDisposition(StrEnum):
    CURRENT = "CURRENT"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


class RequestOutcome(StrEnum):
    COMMITTED = "COMMITTED"
    DENIED = "DENIED"
    CONFLICTED = "CONFLICTED"


class AuthorityStatusValue(StrEnum):
    CURRENT = "current"
    REVOKED = "revoked"


class SupersessionValue(StrEnum):
    NO = "no"
    YES = "yes"


class FailureCode(StrEnum):
    """Stable APCC v1 wire-visible failure codes."""

    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_FIELD = "DUPLICATE_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    CASE_MISMATCHED_FIELD = "CASE_MISMATCHED_FIELD"
    WRONG_JSON_TYPE = "WRONG_JSON_TYPE"
    INVALID_DECIMAL_STRING = "INVALID_DECIMAL_STRING"
    TRAILING_BYTES = "TRAILING_BYTES"
    NONCANONICAL_ENCODING = "NONCANONICAL_ENCODING"
    INVALID_UNICODE = "INVALID_UNICODE"
    INVALID_BASE64URL = "INVALID_BASE64URL"
    SIZE_LIMIT_EXCEEDED = "SIZE_LIMIT_EXCEEDED"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    DUPLICATE_SET_MEMBER = "DUPLICATE_SET_MEMBER"

    UNKNOWN_PROTOCOL_VERSION = "UNKNOWN_PROTOCOL_VERSION"
    UNSUPPORTED_CERTIFICATE_TYPE = "UNSUPPORTED_CERTIFICATE_TYPE"
    UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
    UNSUPPORTED_DIGEST_ALGORITHM = "UNSUPPORTED_DIGEST_ALGORITHM"
    UNSUPPORTED_SIGNATURE_ALGORITHM = "UNSUPPORTED_SIGNATURE_ALGORITHM"
    UNSUPPORTED_STATEMENT_TYPE = "UNSUPPORTED_STATEMENT_TYPE"

    STATEMENT_DIGEST_MISMATCH = "STATEMENT_DIGEST_MISMATCH"
    PROPOSAL_DIGEST_MISMATCH = "PROPOSAL_DIGEST_MISMATCH"
    INVALID_PRODUCER_SIGNATURE = "INVALID_PRODUCER_SIGNATURE"
    INVALID_POLICY_SIGNATURE = "INVALID_POLICY_SIGNATURE"
    INVALID_AUTHORITY_SIGNATURE = "INVALID_AUTHORITY_SIGNATURE"
    INVALID_COMMIT_SEAL = "INVALID_COMMIT_SEAL"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    KEY_ID_MISMATCH = "KEY_ID_MISMATCH"
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"
    ATTESTATION_NOT_YET_VALID = "ATTESTATION_NOT_YET_VALID"

    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    ACTOR_AUTHORITY_MISMATCH = "ACTOR_AUTHORITY_MISMATCH"
    INPUT_DIGEST_MISMATCH = "INPUT_DIGEST_MISMATCH"
    OUTPUT_DIGEST_MISMATCH = "OUTPUT_DIGEST_MISMATCH"
    ATTEMPT_MISMATCH = "ATTEMPT_MISMATCH"
    CROSS_WORKFLOW_REPLAY = "CROSS_WORKFLOW_REPLAY"
    CROSS_NODE_REPLAY = "CROSS_NODE_REPLAY"
    CROSS_ATTEMPT_REPLAY = "CROSS_ATTEMPT_REPLAY"
    STALE_POLICY_EPOCH = "STALE_POLICY_EPOCH"
    STALE_AUTHORITY_EPOCH = "STALE_AUTHORITY_EPOCH"
    STALE_WORKFLOW_EPOCH = "STALE_WORKFLOW_EPOCH"
    ACTOR_REVOKED = "ACTOR_REVOKED"
    WORKFLOW_REVOKED = "WORKFLOW_REVOKED"

    INVALID_PREDECESSOR = "INVALID_PREDECESSOR"
    PREDECESSOR_ROOT_MISMATCH = "PREDECESSOR_ROOT_MISMATCH"
    PREDECESSOR_REPLACED = "PREDECESSOR_REPLACED"
    CROSS_WORKFLOW_PREDECESSOR = "CROSS_WORKFLOW_PREDECESSOR"
    NODE_VERSION_CONFLICT = "NODE_VERSION_CONFLICT"
    ILLEGAL_NODE_STATE = "ILLEGAL_NODE_STATE"
    RESULT_NOT_STAGED = "RESULT_NOT_STAGED"
    STAGED_RESULT_CONFLICT = "STAGED_RESULT_CONFLICT"
    QUARANTINED = "QUARANTINED"

    NONCE_REPLAY = "NONCE_REPLAY"
    COMMIT_ID_EQUIVOCATION = "COMMIT_ID_EQUIVOCATION"
    AUTHORITY_FROM_STAGING_DENIED = "AUTHORITY_FROM_STAGING_DENIED"
    AUTHORITY_FROM_RECOVERY_DENIED = "AUTHORITY_FROM_RECOVERY_DENIED"
    AUTHORITY_FROM_OUTBOX_DENIED = "AUTHORITY_FROM_OUTBOX_DENIED"
    LEGACY_STATUS_NOT_AUTHORITATIVE = "LEGACY_STATUS_NOT_AUTHORITATIVE"

    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    TRANSACTION_ABORTED = "TRANSACTION_ABORTED"
    SERIALIZATION_RETRY_EXHAUSTED = "SERIALIZATION_RETRY_EXHAUSTED"
    OUTBOX_DELIVERY_PENDING = "OUTBOX_DELIVERY_PENDING"

    AUTHORITY_STATUS_REQUIRED = "AUTHORITY_STATUS_REQUIRED"
    AUTHORITY_STATUS_NONCE_MISMATCH = "AUTHORITY_STATUS_NONCE_MISMATCH"
    AUTHORITY_STATUS_CERTIFICATE_MISMATCH = "AUTHORITY_STATUS_CERTIFICATE_MISMATCH"
    AUTHORITY_STATUS_EXPIRED = "AUTHORITY_STATUS_EXPIRED"
    AUTHORITY_STATUS_INVALID_SIGNATURE = "AUTHORITY_STATUS_INVALID_SIGNATURE"
    AUTHORITY_STATUS_REVOKED = "AUTHORITY_STATUS_REVOKED"
    AUTHORITY_STATUS_SUPERSEDED = "AUTHORITY_STATUS_SUPERSEDED"
    AUTHORITY_STATUS_ROLLBACK = "AUTHORITY_STATUS_ROLLBACK"


@dataclass(frozen=True, slots=True)
class Signature:
    algorithm: str
    key_id: str
    signature_b64u: str

    def __post_init__(self) -> None:
        if self.algorithm != "Ed25519":
            raise ValueError("APCC v1 requires Ed25519 signatures")

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> Signature:
        _expect_keys(value, ("algorithm", "key_id", "signature_b64u"))
        return cls(
            _string(value, "algorithm"),
            _string(value, "key_id"),
            _string(value, "signature_b64u"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signature_b64u": self.signature_b64u,
        }


@dataclass(frozen=True, slots=True)
class CertificateHeader:
    protocol_version: str
    certificate_type: str
    encoding_profile: str
    digest_algorithm: str
    signature_algorithm: str
    authority_store_id: str
    commit_authority_key_id: str
    certificate_sequence: str

    def __post_init__(self) -> None:
        required = {
            "protocol_version": "APCC-1.0-draft",
            "certificate_type": "apcc.commit-certificate",
            "encoding_profile": "APCC-CJ1",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
        }
        for field_name, expected in required.items():
            if getattr(self, field_name) != expected:
                raise ValueError(f"APCC v1 requires {field_name}={expected!r}")

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateHeader:
        _expect_keys(
            value,
            (
                "protocol_version",
                "certificate_type",
                "encoding_profile",
                "digest_algorithm",
                "signature_algorithm",
                "authority_store_id",
                "commit_authority_key_id",
                "certificate_sequence",
            ),
        )
        return cls(
            _string(value, "protocol_version"),
            _string(value, "certificate_type"),
            _string(value, "encoding_profile"),
            _string(value, "digest_algorithm"),
            _string(value, "signature_algorithm"),
            _string(value, "authority_store_id"),
            _string(value, "commit_authority_key_id"),
            _string(value, "certificate_sequence"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "protocol_version": self.protocol_version,
            "certificate_type": self.certificate_type,
            "encoding_profile": self.encoding_profile,
            "digest_algorithm": self.digest_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "authority_store_id": self.authority_store_id,
            "commit_authority_key_id": self.commit_authority_key_id,
            "certificate_sequence": self.certificate_sequence,
        }


@dataclass(frozen=True, slots=True)
class CertificateSubject:
    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    actor_authority: str
    input_digest: str
    output_digest: str

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateSubject:
        _expect_keys(
            value,
            (
                "workflow_id",
                "node_id",
                "attempt_id",
                "agent_id",
                "actor_authority",
                "input_digest",
                "output_digest",
            ),
        )
        return cls(
            _string(value, "workflow_id"),
            _string(value, "node_id"),
            _string(value, "attempt_id"),
            _string(value, "agent_id"),
            _string(value, "actor_authority"),
            _string(value, "input_digest"),
            _string(value, "output_digest"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "attempt_id": self.attempt_id,
            "agent_id": self.agent_id,
            "actor_authority": self.actor_authority,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
        }


@dataclass(frozen=True, slots=True)
class CertificateContext:
    policy_id: str
    policy_version: str
    policy_epoch: str
    authority_root: str
    authority_epoch: str
    agent_revocation_generation: str
    workflow_revocation_generation: str
    workflow_epoch: str

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateContext:
        _expect_keys(
            value,
            (
                "policy_id",
                "policy_version",
                "policy_epoch",
                "authority_root",
                "authority_epoch",
                "agent_revocation_generation",
                "workflow_revocation_generation",
                "workflow_epoch",
            ),
        )
        return cls(
            _string(value, "policy_id"),
            _string(value, "policy_version"),
            _string(value, "policy_epoch"),
            _string(value, "authority_root"),
            _string(value, "authority_epoch"),
            _string(value, "agent_revocation_generation"),
            _string(value, "workflow_revocation_generation"),
            _string(value, "workflow_epoch"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "authority_root": self.authority_root,
            "authority_epoch": self.authority_epoch,
            "agent_revocation_generation": self.agent_revocation_generation,
            "workflow_revocation_generation": self.workflow_revocation_generation,
            "workflow_epoch": self.workflow_epoch,
        }


@dataclass(frozen=True, slots=True)
class CertificateEvidence:
    producer_statement: Statement
    producer_statement_digest: str
    policy_statement: Statement
    policy_statement_digest: str
    authority_statement: Statement
    authority_statement_digest: str

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateEvidence:
        _expect_keys(
            value,
            (
                "producer_statement",
                "producer_statement_digest",
                "policy_statement",
                "policy_statement_digest",
                "authority_statement",
                "authority_statement_digest",
            ),
        )
        producer = _object(value["producer_statement"])
        _expect_keys(
            producer,
            (
                "protocol_version",
                "statement_type",
                "producer_key_id",
                "workflow_id",
                "node_id",
                "attempt_id",
                "agent_id",
                "actor_authority",
                "input_digest",
                "output_digest",
                "predecessor_root",
                "expected_node_version",
                "commit_id",
                "nonce",
                "issued_at_ms",
                "expires_at_ms",
            ),
        )
        policy = _object(value["policy_statement"])
        _expect_keys(
            policy,
            (
                "protocol_version",
                "statement_type",
                "policy_key_id",
                "proposal_digest",
                "decision",
                "policy_id",
                "policy_version",
                "policy_epoch",
                "workflow_id",
                "node_id",
                "attempt_id",
                "issued_at_ms",
                "expires_at_ms",
            ),
        )
        authority = _object(value["authority_statement"])
        _expect_keys(
            authority,
            (
                "protocol_version",
                "statement_type",
                "authority_key_id",
                "proposal_digest",
                "agent_id",
                "producer_key_id",
                "actor_authority",
                "authority_root",
                "authority_epoch",
                "agent_revocation_generation",
                "workflow_revocation_generation",
                "workflow_epoch",
                "workflow_id",
                "node_id",
                "attempt_id",
                "issued_at_ms",
                "expires_at_ms",
            ),
        )
        if not all(isinstance(item, str) for item in producer.values()):
            raise TypeError("producer statement values must be strings")
        if not all(isinstance(item, str) for item in policy.values()):
            raise TypeError("policy statement values must be strings")
        if not all(isinstance(item, str) for item in authority.values()):
            raise TypeError("authority statement values must be strings")
        return cls(
            cast("Statement", producer),
            _string(value, "producer_statement_digest"),
            cast("Statement", policy),
            _string(value, "policy_statement_digest"),
            cast("Statement", authority),
            _string(value, "authority_statement_digest"),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "producer_statement", MappingProxyType(dict(self.producer_statement))
        )
        object.__setattr__(
            self, "policy_statement", MappingProxyType(dict(self.policy_statement))
        )
        object.__setattr__(
            self,
            "authority_statement",
            MappingProxyType(dict(self.authority_statement)),
        )
        for statement in (
            self.producer_statement,
            self.policy_statement,
            self.authority_statement,
        ):
            if statement.get("protocol_version") != "APCC-1.0-draft":
                raise ValueError("APCC statement protocol version is unsupported")
        required_literals = (
            (self.producer_statement, "statement_type", "apcc.producer-statement"),
            (self.policy_statement, "statement_type", "apcc.policy-statement"),
            (self.policy_statement, "decision", "allow"),
            (
                self.authority_statement,
                "statement_type",
                "apcc.authority-statement",
            ),
        )
        for statement, field_name, expected in required_literals:
            if statement.get(field_name) != expected:
                raise ValueError(
                    f"APCC v1 requires statement {field_name}={expected!r}"
                )

    def to_object(self) -> dict[str, object]:
        return {
            "producer_statement": dict(self.producer_statement),
            "producer_statement_digest": self.producer_statement_digest,
            "policy_statement": dict(self.policy_statement),
            "policy_statement_digest": self.policy_statement_digest,
            "authority_statement": dict(self.authority_statement),
            "authority_statement_digest": self.authority_statement_digest,
        }


@dataclass(frozen=True, slots=True)
class CertificateDecision:
    outcome: str
    reason: str
    commit_id: str
    nonce: str
    committed_at_ms: str

    def __post_init__(self) -> None:
        if self.outcome != "committed":
            raise ValueError("APCC certificates represent committed outcomes only")

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateDecision:
        _expect_keys(
            value, ("outcome", "reason", "commit_id", "nonce", "committed_at_ms")
        )
        return cls(
            _string(value, "outcome"),
            _string(value, "reason"),
            _string(value, "commit_id"),
            _string(value, "nonce"),
            _string(value, "committed_at_ms"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "commit_id": self.commit_id,
            "nonce": self.nonce,
            "committed_at_ms": self.committed_at_ms,
        }


@dataclass(frozen=True, slots=True)
class PredecessorRef:
    workflow_id: str
    node_id: str
    committed_node_version: str
    commit_id: str
    certificate_digest: str
    output_digest: str

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> PredecessorRef:
        _expect_keys(
            value,
            (
                "workflow_id",
                "node_id",
                "committed_node_version",
                "commit_id",
                "certificate_digest",
                "output_digest",
            ),
        )
        return cls(
            _string(value, "workflow_id"),
            _string(value, "node_id"),
            _string(value, "committed_node_version"),
            _string(value, "commit_id"),
            _string(value, "certificate_digest"),
            _string(value, "output_digest"),
        )

    def to_object(self) -> dict[str, str]:
        return {
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "committed_node_version": self.committed_node_version,
            "commit_id": self.commit_id,
            "certificate_digest": self.certificate_digest,
            "output_digest": self.output_digest,
        }


@dataclass(frozen=True, slots=True)
class CertificateBindings:
    expected_node_version: str
    committed_node_version: str
    predecessor_root: str
    predecessors: tuple[PredecessorRef, ...]

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateBindings:
        _expect_keys(
            value,
            (
                "expected_node_version",
                "committed_node_version",
                "predecessor_root",
                "predecessors",
            ),
        )
        raw_predecessors = value["predecessors"]
        if not isinstance(raw_predecessors, list):
            raise TypeError("APCC predecessors must be an array")
        return cls(
            _string(value, "expected_node_version"),
            _string(value, "committed_node_version"),
            _string(value, "predecessor_root"),
            tuple(
                PredecessorRef.from_object(_object(item)) for item in raw_predecessors
            ),
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "predecessors", tuple(self.predecessors))
        try:
            expected = int(self.expected_node_version)
            committed = int(self.committed_node_version)
        except ValueError as error:
            raise ValueError("node versions must be decimal strings") from error
        if committed != expected + 1:
            raise ValueError("committed node version must advance exactly once")

    def to_object(self) -> dict[str, object]:
        return {
            "expected_node_version": self.expected_node_version,
            "committed_node_version": self.committed_node_version,
            "predecessor_root": self.predecessor_root,
            "predecessors": [item.to_object() for item in self.predecessors],
        }


@dataclass(frozen=True, slots=True)
class CertificateSignatures:
    producer: Signature
    policy_authority: Signature
    authority_registry: Signature

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CertificateSignatures:
        _expect_keys(value, ("producer", "policy_authority", "authority_registry"))
        return cls(
            Signature.from_object(_object(value["producer"])),
            Signature.from_object(_object(value["policy_authority"])),
            Signature.from_object(_object(value["authority_registry"])),
        )

    def to_object(self) -> dict[str, object]:
        return {
            "producer": self.producer.to_object(),
            "policy_authority": self.policy_authority.to_object(),
            "authority_registry": self.authority_registry.to_object(),
        }


@dataclass(frozen=True, slots=True)
class CommitCertificate:
    header: CertificateHeader
    subject: CertificateSubject
    context: CertificateContext
    evidence: CertificateEvidence
    decision: CertificateDecision
    bindings: CertificateBindings
    signatures: CertificateSignatures

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CommitCertificate:
        _expect_keys(
            value,
            (
                "header",
                "subject",
                "context",
                "evidence",
                "decision",
                "bindings",
                "signatures",
            ),
        )
        return cls(
            CertificateHeader.from_object(_object(value["header"])),
            CertificateSubject.from_object(_object(value["subject"])),
            CertificateContext.from_object(_object(value["context"])),
            CertificateEvidence.from_object(_object(value["evidence"])),
            CertificateDecision.from_object(_object(value["decision"])),
            CertificateBindings.from_object(_object(value["bindings"])),
            CertificateSignatures.from_object(_object(value["signatures"])),
        )

    def to_object(self) -> dict[str, object]:
        return {
            "header": self.header.to_object(),
            "subject": self.subject.to_object(),
            "context": self.context.to_object(),
            "evidence": self.evidence.to_object(),
            "decision": self.decision.to_object(),
            "bindings": self.bindings.to_object(),
            "signatures": self.signatures.to_object(),
        }

    @property
    def canonical_digest(self) -> str:
        """Return the digest of the exact canonical seven-object payload."""
        from .codec import encode_certificate
        from .crypto import sha256_digest

        return sha256_digest(encode_certificate(self))


@dataclass(frozen=True, slots=True)
class AuthorityStatus:
    protocol_version: str
    statement_type: str
    authority_store_id: str
    status_key_id: str
    request_nonce: str
    certificate_digest: str
    certificate_sequence: str
    trust_log_sequence: str
    trust_log_head: str
    status: AuthorityStatusValue
    actor_revocation_generation: str
    workflow_revocation_generation: str
    superseded: SupersessionValue
    this_update_ms: str
    next_update_ms: str
    signature: Signature

    def __post_init__(self) -> None:
        if self.protocol_version != "APCC-1.0-draft":
            raise ValueError("APCC authority status protocol version is unsupported")
        if self.statement_type != "apcc.authority-status":
            raise ValueError("APCC authority status statement type is unsupported")
        object.__setattr__(self, "status", AuthorityStatusValue(self.status))
        object.__setattr__(self, "superseded", SupersessionValue(self.superseded))

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> AuthorityStatus:
        _expect_keys(value, ("body", "signature"))
        body = _object(value["body"])
        _expect_keys(
            body,
            (
                "protocol_version",
                "statement_type",
                "authority_store_id",
                "status_key_id",
                "request_nonce",
                "certificate_digest",
                "certificate_sequence",
                "trust_log_sequence",
                "trust_log_head",
                "status",
                "actor_revocation_generation",
                "workflow_revocation_generation",
                "superseded",
                "this_update_ms",
                "next_update_ms",
            ),
        )
        return cls(
            _string(body, "protocol_version"),
            _string(body, "statement_type"),
            _string(body, "authority_store_id"),
            _string(body, "status_key_id"),
            _string(body, "request_nonce"),
            _string(body, "certificate_digest"),
            _string(body, "certificate_sequence"),
            _string(body, "trust_log_sequence"),
            _string(body, "trust_log_head"),
            AuthorityStatusValue(_string(body, "status")),
            _string(body, "actor_revocation_generation"),
            _string(body, "workflow_revocation_generation"),
            SupersessionValue(_string(body, "superseded")),
            _string(body, "this_update_ms"),
            _string(body, "next_update_ms"),
            Signature.from_object(_object(value["signature"])),
        )

    def body_object(self) -> dict[str, str]:
        """Return the exact body covered by the detached status signature."""
        return {
            "protocol_version": self.protocol_version,
            "statement_type": self.statement_type,
            "authority_store_id": self.authority_store_id,
            "status_key_id": self.status_key_id,
            "request_nonce": self.request_nonce,
            "certificate_digest": self.certificate_digest,
            "certificate_sequence": self.certificate_sequence,
            "trust_log_sequence": self.trust_log_sequence,
            "trust_log_head": self.trust_log_head,
            "status": self.status,
            "actor_revocation_generation": self.actor_revocation_generation,
            "workflow_revocation_generation": self.workflow_revocation_generation,
            "superseded": self.superseded,
            "this_update_ms": self.this_update_ms,
            "next_update_ms": self.next_update_ms,
        }

    def to_object(self) -> dict[str, object]:
        return {"body": self.body_object(), "signature": self.signature.to_object()}


@dataclass(frozen=True, slots=True)
class CandidateState:
    workflow_id: str
    node_id: str
    attempt_id: str
    lifecycle: CandidateLifecycle

    def __post_init__(self) -> None:
        object.__setattr__(self, "lifecycle", CandidateLifecycle(self.lifecycle))

    def to_object(self) -> dict[str, str]:
        return {
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "attempt_id": self.attempt_id,
            "lifecycle": self.lifecycle,
        }


@dataclass(frozen=True, slots=True)
class LogicalNodeState:
    workflow_id: str
    node_id: str
    current_node_version: str
    current_certificate_digest: str | None

    def __post_init__(self) -> None:
        try:
            version = int(self.current_node_version)
        except ValueError as error:
            raise ValueError("current node version must be a decimal string") from error
        if version < 0:
            raise ValueError("current node version cannot be negative")
        if (version == 0) != (self.current_certificate_digest is None):
            raise ValueError(
                "only an initial logical node may omit its certificate digest"
            )

    def to_object(self) -> dict[str, str]:
        result = {
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "current_node_version": self.current_node_version,
        }
        if self.current_certificate_digest is not None:
            result["current_certificate_digest"] = self.current_certificate_digest
        return result


@dataclass(frozen=True, slots=True)
class CommitDecision:
    commit_id: str
    outcome: RequestOutcome
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", RequestOutcome(self.outcome))

    def to_object(self) -> dict[str, str]:
        return {
            "commit_id": self.commit_id,
            "outcome": self.outcome,
            "reason": self.reason,
        }
