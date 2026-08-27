"""Historical and current-consumption verification for APCC v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping

from .codec import (
    CodecError,
    canonical_statement,
    decode_certificate,
    decode_envelope,
    encode_authority_status_body,
    normalize_authority_status,
)
from .crypto import (
    AUTHORITY_DOMAIN,
    AUTHORITY_STATUS_DOMAIN,
    COMMIT_DOMAIN,
    POLICY_DOMAIN,
    PROPOSAL_DOMAIN,
    b64u_decode,
    predecessor_root,
    sha256_digest,
    verify_detached,
)
from .model import AuthorityStatus, CommitCertificate, FailureCode, Signature


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """A fail-closed APCC verification result."""

    ok: bool
    code: FailureCode | None = None
    certificate: CommitCertificate | None = None


class TrustRole(StrEnum):
    """Cryptographically distinct APCC verification roles."""

    PRODUCER = "producer"
    POLICY = "policy"
    REGISTRY = "registry"
    COMMIT = "commit"
    STATUS = "status"


_SCOPE_LENGTH = {
    TrustRole.PRODUCER: 3,
    TrustRole.POLICY: 3,
    TrustRole.REGISTRY: 2,
    TrustRole.COMMIT: 1,
    TrustRole.STATUS: 1,
}


@dataclass(frozen=True, slots=True)
class TrustBinding:
    """One raw verification key bound to one role and semantic scope."""

    role: TrustRole
    scope: tuple[str, ...]
    key_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", TrustRole(self.role))
        object.__setattr__(self, "scope", tuple(self.scope))
        object.__setattr__(self, "public_key", bytes(self.public_key))
        if len(self.scope) != _SCOPE_LENGTH[self.role]:
            raise ValueError(f"invalid {self.role.value} trust scope")
        if not self.key_id or any(not item for item in self.scope):
            raise ValueError("trust binding identifiers cannot be empty")
        if len(self.public_key) != 32:
            raise ValueError("Ed25519 trust keys must be 32 raw bytes")


@dataclass(frozen=True, slots=True)
class ScopedTrust:
    """Immutable role- and scope-aware APCC trust resolver."""

    bindings: tuple[TrustBinding, ...]
    _index: Mapping[tuple[TrustRole, tuple[str, ...]], TrustBinding] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        bindings = tuple(self.bindings)
        index: dict[tuple[TrustRole, tuple[str, ...]], TrustBinding] = {}
        key_roles: dict[str, TrustRole] = {}
        material_roles: dict[bytes, TrustRole] = {}
        for binding in bindings:
            if not isinstance(binding, TrustBinding):
                raise TypeError("ScopedTrust accepts TrustBinding records only")
            identity = (binding.role, binding.scope)
            if identity in index:
                raise ValueError("duplicate APCC trust role/scope binding")
            prior_key_role = key_roles.get(binding.key_id)
            if prior_key_role is not None and prior_key_role is not binding.role:
                raise ValueError("APCC key IDs cannot be reused across trust roles")
            prior_material_role = material_roles.get(binding.public_key)
            if (
                prior_material_role is not None
                and prior_material_role is not binding.role
            ):
                raise ValueError("APCC public keys cannot be reused across trust roles")
            index[identity] = binding
            key_roles[binding.key_id] = binding.role
            material_roles[binding.public_key] = binding.role
        object.__setattr__(self, "bindings", bindings)
        object.__setattr__(self, "_index", MappingProxyType(index))

    def resolve(self, role: TrustRole, scope: tuple[str, ...]) -> TrustBinding | None:
        """Resolve exactly one role/scope tuple without fallback."""
        return self._index.get((role, tuple(scope)))


def _failure(code: FailureCode) -> VerificationResult:
    return VerificationResult(False, code)


def _literal(value: str, expected: str, code: FailureCode) -> FailureCode | None:
    return None if value == expected else code


def _key(
    signature: Signature,
    body_key_id: str,
    trust: ScopedTrust,
    role: TrustRole,
    scope: tuple[str, ...],
) -> tuple[bytes | None, FailureCode | None]:
    if signature.algorithm != "Ed25519":
        return None, FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM
    if signature.key_id != body_key_id:
        return None, FailureCode.KEY_ID_MISMATCH
    binding = trust.resolve(role, scope)
    if binding is None or binding.key_id != body_key_id:
        return None, FailureCode.UNKNOWN_KEY
    return binding.public_key, None


def _verify_signature(
    signature: Signature,
    body_key_id: str,
    trust: ScopedTrust,
    role: TrustRole,
    scope: tuple[str, ...],
    domain: bytes,
    body: bytes,
    invalid_code: FailureCode,
) -> FailureCode | None:
    public_key, error = _key(signature, body_key_id, trust, role, scope)
    if error is not None:
        return error
    assert public_key is not None
    if not verify_detached(public_key, domain, body, signature.signature_b64u):
        return invalid_code
    return None


def _header(certificate: CommitCertificate) -> FailureCode | None:
    header = certificate.header
    checks = (
        (
            header.protocol_version,
            "APCC-1.0-draft",
            FailureCode.UNKNOWN_PROTOCOL_VERSION,
        ),
        (
            header.certificate_type,
            "apcc.commit-certificate",
            FailureCode.UNSUPPORTED_CERTIFICATE_TYPE,
        ),
        (header.encoding_profile, "APCC-CJ1", FailureCode.UNSUPPORTED_ENCODING),
        (header.digest_algorithm, "SHA-256", FailureCode.UNSUPPORTED_DIGEST_ALGORITHM),
        (
            header.signature_algorithm,
            "Ed25519",
            FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
        ),
    )
    for value, expected, code in checks:
        error = _literal(value, expected, code)
        if error is not None:
            return error
    if certificate.decision.outcome != "committed":
        return FailureCode.ILLEGAL_NODE_STATE
    return None


def _statement_types(certificate: CommitCertificate) -> FailureCode | None:
    evidence = certificate.evidence
    checks = (
        (evidence.producer_statement, "apcc.producer-statement"),
        (evidence.policy_statement, "apcc.policy-statement"),
        (evidence.authority_statement, "apcc.authority-statement"),
    )
    for body, statement_type in checks:
        if body["protocol_version"] != "APCC-1.0-draft":
            return FailureCode.UNKNOWN_PROTOCOL_VERSION
        if body["statement_type"] != statement_type:
            return FailureCode.UNSUPPORTED_STATEMENT_TYPE
    if evidence.policy_statement["decision"] != "allow":
        return FailureCode.SUBJECT_MISMATCH
    return None


def _evidence(certificate: CommitCertificate, trust: ScopedTrust) -> FailureCode | None:
    evidence = certificate.evidence
    producer = canonical_statement(evidence.producer_statement)
    policy = canonical_statement(evidence.policy_statement)
    authority = canonical_statement(evidence.authority_statement)
    for body, claimed in (
        (producer, evidence.producer_statement_digest),
        (policy, evidence.policy_statement_digest),
        (authority, evidence.authority_statement_digest),
    ):
        if sha256_digest(body) != claimed:
            return FailureCode.STATEMENT_DIGEST_MISMATCH
    proposal_digest = evidence.producer_statement_digest
    if (
        evidence.policy_statement["proposal_digest"] != proposal_digest
        or evidence.authority_statement["proposal_digest"] != proposal_digest
    ):
        return FailureCode.PROPOSAL_DIGEST_MISMATCH
    type_error = _statement_types(certificate)
    if type_error is not None:
        return type_error
    signatures = certificate.signatures
    producer_scope = (
        evidence.producer_statement["agent_id"],
        evidence.producer_statement["actor_authority"],
        evidence.authority_statement["authority_root"],
    )
    policy_scope = (
        evidence.policy_statement["policy_id"],
        evidence.policy_statement["policy_version"],
        evidence.policy_statement["policy_epoch"],
    )
    registry_scope = (
        evidence.authority_statement["authority_root"],
        evidence.authority_statement["authority_epoch"],
    )
    checks = (
        (
            signatures.producer,
            evidence.producer_statement["producer_key_id"],
            TrustRole.PRODUCER,
            producer_scope,
            PROPOSAL_DOMAIN,
            producer,
            FailureCode.INVALID_PRODUCER_SIGNATURE,
        ),
        (
            signatures.policy_authority,
            evidence.policy_statement["policy_key_id"],
            TrustRole.POLICY,
            policy_scope,
            POLICY_DOMAIN,
            policy,
            FailureCode.INVALID_POLICY_SIGNATURE,
        ),
        (
            signatures.authority_registry,
            evidence.authority_statement["authority_key_id"],
            TrustRole.REGISTRY,
            registry_scope,
            AUTHORITY_DOMAIN,
            authority,
            FailureCode.INVALID_AUTHORITY_SIGNATURE,
        ),
    )
    for signature, key_id, role, scope, domain, body, code in checks:
        error = _verify_signature(
            signature, key_id, trust, role, scope, domain, body, code
        )
        if error is not None:
            return error
    return None


def _bindings(certificate: CommitCertificate) -> FailureCode | None:
    subject = certificate.subject
    context = certificate.context
    decision = certificate.decision
    bindings = certificate.bindings
    producer = certificate.evidence.producer_statement
    policy = certificate.evidence.policy_statement
    authority = certificate.evidence.authority_statement

    if producer["workflow_id"] != subject.workflow_id:
        return FailureCode.CROSS_WORKFLOW_REPLAY
    if producer["node_id"] != subject.node_id:
        return FailureCode.CROSS_NODE_REPLAY
    if producer["attempt_id"] != subject.attempt_id:
        return FailureCode.ATTEMPT_MISMATCH
    if producer["agent_id"] != subject.agent_id:
        return FailureCode.SUBJECT_MISMATCH
    if producer["actor_authority"] != subject.actor_authority:
        return FailureCode.ACTOR_AUTHORITY_MISMATCH
    if producer["input_digest"] != subject.input_digest:
        return FailureCode.INPUT_DIGEST_MISMATCH
    if producer["output_digest"] != subject.output_digest:
        return FailureCode.OUTPUT_DIGEST_MISMATCH
    if authority["agent_id"] != subject.agent_id:
        return FailureCode.SUBJECT_MISMATCH
    if authority["producer_key_id"] != producer["producer_key_id"]:
        return FailureCode.KEY_ID_MISMATCH
    if authority["actor_authority"] != subject.actor_authority:
        return FailureCode.ACTOR_AUTHORITY_MISMATCH

    for statement in (policy, authority):
        if statement["workflow_id"] != subject.workflow_id:
            return FailureCode.CROSS_WORKFLOW_REPLAY
        if statement["node_id"] != subject.node_id:
            return FailureCode.CROSS_NODE_REPLAY
        if statement["attempt_id"] != subject.attempt_id:
            return FailureCode.ATTEMPT_MISMATCH

    if context.policy_id != policy["policy_id"]:
        return FailureCode.STALE_POLICY_EPOCH
    if (
        context.policy_version != policy["policy_version"]
        or context.policy_epoch != policy["policy_epoch"]
    ):
        return FailureCode.STALE_POLICY_EPOCH
    if (
        context.authority_root != authority["authority_root"]
        or context.authority_epoch != authority["authority_epoch"]
    ):
        return FailureCode.STALE_AUTHORITY_EPOCH
    if context.workflow_epoch != authority["workflow_epoch"]:
        return FailureCode.STALE_WORKFLOW_EPOCH
    if context.agent_revocation_generation != authority["agent_revocation_generation"]:
        return FailureCode.ACTOR_REVOKED
    if (
        context.workflow_revocation_generation
        != authority["workflow_revocation_generation"]
    ):
        return FailureCode.WORKFLOW_REVOKED

    if (
        decision.commit_id != producer["commit_id"]
        or decision.nonce != producer["nonce"]
    ):
        return FailureCode.SUBJECT_MISMATCH
    if (
        bindings.expected_node_version != producer["expected_node_version"]
        or int(bindings.committed_node_version)
        != int(bindings.expected_node_version) + 1
    ):
        return FailureCode.NODE_VERSION_CONFLICT
    if bindings.predecessor_root != producer["predecessor_root"]:
        return FailureCode.PREDECESSOR_ROOT_MISMATCH
    if predecessor_root(bindings.predecessors) != bindings.predecessor_root:
        return FailureCode.PREDECESSOR_ROOT_MISMATCH
    if any(item.workflow_id != subject.workflow_id for item in bindings.predecessors):
        return FailureCode.CROSS_WORKFLOW_PREDECESSOR

    committed_at = int(decision.committed_at_ms)
    for statement in (producer, policy, authority):
        issued, expires = (
            int(statement["issued_at_ms"]),
            int(statement["expires_at_ms"]),
        )
        if issued >= expires or committed_at < issued:
            return FailureCode.ATTESTATION_NOT_YET_VALID
        if committed_at > expires:
            return FailureCode.ATTESTATION_EXPIRED
    return None


def verify_historical(envelope: bytes, *, trust: ScopedTrust) -> VerificationResult:
    """Verify a canonical certificate as evidence of a historical commit."""
    try:
        detached = decode_envelope(envelope)
        certificate = decode_certificate(detached.payload)
    except CodecError as exc:
        return _failure(exc.code)
    if sha256_digest(detached.payload) != detached.payload_sha256:
        return _failure(FailureCode.INVALID_COMMIT_SEAL)
    header_error = _header(certificate)
    if header_error is not None:
        return _failure(header_error)
    seal_error = _verify_signature(
        detached.seal,
        certificate.header.commit_authority_key_id,
        trust,
        TrustRole.COMMIT,
        (certificate.header.authority_store_id,),
        COMMIT_DOMAIN,
        detached.payload,
        FailureCode.INVALID_COMMIT_SEAL,
    )
    if seal_error is not None:
        return _failure(seal_error)
    evidence_error = _evidence(certificate, trust)
    if evidence_error is not None:
        return _failure(evidence_error)
    binding_error = _bindings(certificate)
    if binding_error is not None:
        return _failure(binding_error)
    return VerificationResult(True, certificate=certificate)


def _status_literals(
    status: AuthorityStatus, certificate: CommitCertificate
) -> FailureCode | None:
    if status.protocol_version != "APCC-1.0-draft":
        return FailureCode.UNKNOWN_PROTOCOL_VERSION
    if status.statement_type != "apcc.authority-status":
        return FailureCode.UNSUPPORTED_STATEMENT_TYPE
    if status.authority_store_id != certificate.header.authority_store_id:
        return FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH
    if status.signature.algorithm != "Ed25519":
        return FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM
    if status.signature.key_id != status.status_key_id:
        return FailureCode.KEY_ID_MISMATCH
    return None


def _decimal_argument(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    if value == "0":
        return 0
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        return None
    if len(value) > 16:
        return None
    parsed = int(value)
    return parsed if parsed <= 9007199254740991 else None


def verify_current(
    envelope: bytes,
    *,
    trust: ScopedTrust,
    authority_status: AuthorityStatus | Mapping[str, object] | bytes | None,
    request_nonce: str,
    now_ms: str,
    highest_trust_log_sequence: str,
    highest_trust_log_head: str,
    maximum_staleness_ms: str,
) -> VerificationResult:
    """Verify history plus the sole APCC v1 current-consumption status."""
    try:
        b64u_decode(request_nonce, expected_length=16)
        b64u_decode(highest_trust_log_head, expected_length=32)
    except ValueError:
        return _failure(FailureCode.INVALID_BASE64URL)
    now = _decimal_argument(now_ms)
    highest = _decimal_argument(highest_trust_log_sequence)
    maximum_staleness = _decimal_argument(maximum_staleness_ms)
    if now is None or highest is None or maximum_staleness is None:
        return _failure(FailureCode.INVALID_DECIMAL_STRING)
    historical = verify_historical(envelope, trust=trust)
    if not historical.ok:
        return historical
    certificate = historical.certificate
    assert certificate is not None
    if authority_status is None:
        return _failure(FailureCode.AUTHORITY_STATUS_REQUIRED)
    try:
        status = normalize_authority_status(authority_status)
    except CodecError as exc:
        return _failure(exc.code)
    literal_error = _status_literals(status, certificate)
    if literal_error is not None:
        return _failure(literal_error)
    public_key, key_error = _key(
        status.signature,
        status.status_key_id,
        trust,
        TrustRole.STATUS,
        (status.authority_store_id,),
    )
    if key_error is not None:
        return _failure(key_error)
    assert public_key is not None
    if not verify_detached(
        public_key,
        AUTHORITY_STATUS_DOMAIN,
        encode_authority_status_body(status),
        status.signature.signature_b64u,
    ):
        return _failure(FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE)
    if status.request_nonce != request_nonce:
        return _failure(FailureCode.AUTHORITY_STATUS_NONCE_MISMATCH)
    if status.certificate_digest != certificate.canonical_digest:
        return _failure(FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH)
    if status.certificate_sequence != certificate.header.certificate_sequence:
        return _failure(FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH)
    if (
        status.actor_revocation_generation
        != certificate.context.agent_revocation_generation
    ):
        return _failure(FailureCode.ACTOR_REVOKED)
    if (
        status.workflow_revocation_generation
        != certificate.context.workflow_revocation_generation
    ):
        return _failure(FailureCode.WORKFLOW_REVOKED)
    this_update, next_update = int(status.this_update_ms), int(status.next_update_ms)
    if this_update > now:
        return _failure(FailureCode.ATTESTATION_NOT_YET_VALID)
    if next_update < now or this_update >= next_update:
        return _failure(FailureCode.AUTHORITY_STATUS_EXPIRED)
    if now - this_update > maximum_staleness:
        return _failure(FailureCode.AUTHORITY_STATUS_EXPIRED)
    sequence = int(status.trust_log_sequence)
    if sequence < highest or (
        sequence == highest and status.trust_log_head != highest_trust_log_head
    ):
        return _failure(FailureCode.AUTHORITY_STATUS_ROLLBACK)
    if status.status != "current":
        return _failure(FailureCode.AUTHORITY_STATUS_REVOKED)
    if status.superseded != "no":
        return _failure(FailureCode.AUTHORITY_STATUS_SUPERSEDED)
    return VerificationResult(True, certificate=certificate)


__all__ = [
    "FailureCode",
    "ScopedTrust",
    "TrustBinding",
    "TrustRole",
    "VerificationResult",
    "verify_current",
    "verify_historical",
]
