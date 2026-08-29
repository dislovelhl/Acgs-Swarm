"""Frozen third-observer protocol records and independent verification."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import b64u_decode, b64u_encode, sha256_digest
from .model import LogicalNodeState, Signature


AUTHORITY_OBSERVATION_DOMAIN = b"APCC-B6-AUTHORITY-OBSERVATION-V1"
CONTROLLER_LAUNCH_DOMAIN = b"APCC-B6-CONTROLLER-LAUNCH-V1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,15})\Z")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_DEPTH = 8
_MAX_OBJECT_BYTES = 1_048_576
_MAX_OUTBOX_RECORD_BYTES = 8192

if TYPE_CHECKING:
    from .verifier import ScopedTrust


class AuthorityObservationSnapshotChanged(RuntimeError):
    """The authority status snapshot did not match the observer read snapshot."""


@dataclass(frozen=True, slots=True)
class AuthorityObservationRequest:
    """Exact APCC-CJ1 request for one independently observed operation."""

    protocol_version: str
    statement_type: str
    authority_store_id: str
    workflow_id: str
    node_id: str
    attempt_id: str
    expected_commit_id: str
    expected_operation_digest: str
    public_request_digest: str
    request_nonce: str

    def __post_init__(self) -> None:
        _validate_request(self)

    def to_object(self) -> dict[str, str]:
        return {
            "protocol_version": self.protocol_version,
            "statement_type": self.statement_type,
            "authority_store_id": self.authority_store_id,
            "workflow_id": self.workflow_id,
            "node_id": self.node_id,
            "attempt_id": self.attempt_id,
            "expected_commit_id": self.expected_commit_id,
            "expected_operation_digest": self.expected_operation_digest,
            "public_request_digest": self.public_request_digest,
            "request_nonce": self.request_nonce,
        }

    @property
    def canonical_digest(self) -> str:
        return sha256_digest(encode_authority_observation_request(self))


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _strict_json(raw: bytes, *, maximum_bytes: int, name: str) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum_bytes:
        raise ValueError(f"{name} exceeds size limit")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"{name} contains duplicate keys")
            result[key] = item
        return result

    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"malformed {name}") from error

    def validate_tree(item: object, depth: int = 1) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError(f"{name} exceeds depth limit")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise ValueError(f"{name} contains non-APCC-CJ1 text")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not key.isascii():
                    raise ValueError(f"{name} contains non-ASCII property name")
                validate_tree(key)
                validate_tree(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                validate_tree(child, depth + 1)
        else:
            raise ValueError(f"{name} contains a non-string scalar")

    validate_tree(value)
    if _canonical_json(value) != raw:
        raise ValueError(f"noncanonical {name}")
    return value


def _canonical_decimal(value: object, *, name: str, positive: bool = False) -> int:
    if (
        type(value) is not str
        or _DECIMAL.fullmatch(value) is None
        or int(value) > _MAX_SAFE_INTEGER
        or (positive and value == "0")
    ):
        raise ValueError(f"{name} is not a bounded canonical decimal")
    return int(value)


def _canonical_identifier(value: object, *, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is not a bounded canonical identifier")
    return value


def _canonical_object_profile(
    raw: bytes,
    *,
    name: str,
    keys: frozenset[str],
    maximum_bytes: int = _MAX_OBJECT_BYTES,
) -> dict[str, object]:
    value = _strict_json(raw, maximum_bytes=maximum_bytes, name=name)
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name} has invalid fields")
    return value


_OUTBOX_RECORD_KEYS = frozenset(
    {
        "event_sequence",
        "event_id",
        "event_kind",
        "operation_id",
        "event_payload_sha256",
        "audit_event_id",
        "trust_sequence",
        "state",
        "lease_token",
        "lease_claimed_ms",
        "lease_until_ms",
        "delivered",
    }
)
_OUTBOX_NULLABLE_FIELDS = frozenset(
    {"lease_token", "lease_claimed_ms", "lease_until_ms"}
)


def _nullable_outbox_record(raw: bytes) -> dict[str, str | None]:
    """Decode the one frozen carrier that permits narrowly scoped JSON nulls."""
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OUTBOX_RECORD_BYTES:
        raise ValueError("outbox record exceeds size limit")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError("outbox record contains duplicate keys")
            result[key] = item
        return result

    def number(_: str) -> object:
        raise ValueError("outbox record contains a non-string scalar")

    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ValueError("outbox record contains a BOM")
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_int=number,
            parse_float=number,
            parse_constant=number,
        )
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("malformed outbox record") from error
    if (
        end != len(text)
        or not isinstance(value, dict)
        or set(value) != _OUTBOX_RECORD_KEYS
    ):
        raise ValueError("outbox record has invalid fields")
    for key, item in value.items():
        if not key.isascii() or (
            item is not None
            and (type(item) is not str or unicodedata.normalize("NFC", item) != item)
        ):
            raise ValueError("outbox record contains invalid values")
        if item is None and key not in _OUTBOX_NULLABLE_FIELDS:
            raise ValueError("outbox record null is outside the frozen carrier")
    if _canonical_json(value) != raw:
        raise ValueError("noncanonical outbox record")
    return value  # type: ignore[return-value]


def _validate_request(value: AuthorityObservationRequest) -> None:
    from .codec import CodecError
    from .model import FailureCode

    if value.protocol_version != "APCC-1.0-draft":
        raise CodecError(FailureCode.UNKNOWN_PROTOCOL_VERSION)
    if value.statement_type != "apcc.authority-observation-request":
        raise CodecError(FailureCode.UNSUPPORTED_STATEMENT_TYPE)
    for name in (
        "authority_store_id",
        "workflow_id",
        "node_id",
        "attempt_id",
        "expected_commit_id",
    ):
        item = getattr(value, name)
        if type(item) is not str or _IDENTIFIER.fullmatch(item) is None:
            raise CodecError(FailureCode.NONCANONICAL_ENCODING)
    for name in ("expected_operation_digest", "public_request_digest"):
        b64u_decode(getattr(value, name), expected_length=32)
    b64u_decode(value.request_nonce, expected_length=16)


def encode_authority_observation_request(value: AuthorityObservationRequest) -> bytes:
    _validate_request(value)
    return _canonical_json(value.to_object())


def decode_authority_observation_request(raw: bytes) -> AuthorityObservationRequest:
    from .codec import CodecError
    from .model import FailureCode

    try:
        value = _strict_json(raw, maximum_bytes=4096, name="observation request")
    except ValueError as error:
        code = (
            FailureCode.SIZE_LIMIT_EXCEEDED
            if type(raw) is not bytes or not raw or len(raw) > 4096
            else FailureCode.NONCANONICAL_ENCODING
        )
        raise CodecError(code) from error
    keys = tuple(AuthorityObservationRequest.__dataclass_fields__)
    if (
        not isinstance(value, dict)
        or set(value) != set(keys)
        or any(type(item) is not str for item in value.values())
    ):
        raise CodecError(FailureCode.NONCANONICAL_ENCODING)
    try:
        return AuthorityObservationRequest(**value)
    except (TypeError, ValueError) as error:
        raise CodecError(FailureCode.NONCANONICAL_ENCODING) from error


class AuthorityObservationState(StrEnum):
    ABSENT = "ABSENT"
    DENIED = "DENIED"
    CONFLICTED = "CONFLICTED"
    COMMITTED = "COMMITTED"


@dataclass(frozen=True, slots=True)
class AuthorityObservationSnapshot:
    request: AuthorityObservationRequest
    state: AuthorityObservationState
    authoritative_commit_digest: str | None
    authoritative_public_request_digest: str | None
    decision_reason: str | None
    audit_event_id: str | None
    audit_event_bytes: bytes | None
    logical_node: LogicalNodeState
    certificate_payload_bytes: bytes | None
    certificate_envelope_bytes: bytes | None
    certificate_digest: str | None
    current_status_evidence: bytes | None
    outbox_event_id: str | None
    outbox_event_bytes: bytes | None
    outbox_state: str | None
    output_digest: str | None
    _legacy_visibility_hint: bool
    persisted_operation_bytes: bytes | None = None
    conflict_claim_bytes: bytes | None = None
    output_bytes: bytes | None = None
    outbox_record_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if type(self.state) is not AuthorityObservationState:
            raise TypeError("observation snapshot state is invalid")
        if type(self._legacy_visibility_hint) is not bool:
            raise TypeError("observation visibility hint is invalid")
        if (self.logical_node.workflow_id, self.logical_node.node_id) != (
            self.request.workflow_id,
            self.request.node_id,
        ):
            raise ValueError("observation logical-node binding mismatch")
        digest_fields = (
            self.authoritative_commit_digest,
            self.authoritative_public_request_digest,
            self.certificate_digest,
            self.output_digest,
        )
        for item in digest_fields:
            if item is not None:
                b64u_decode(item, expected_length=32)
        common = (
            self.authoritative_commit_digest,
            self.authoritative_public_request_digest,
            self.decision_reason,
            self.audit_event_id,
            self.audit_event_bytes,
            self.persisted_operation_bytes,
        )
        authority_artifacts = (
            self.certificate_payload_bytes,
            self.certificate_envelope_bytes,
            self.certificate_digest,
            self.current_status_evidence,
            self.outbox_event_id,
            self.outbox_event_bytes,
            self.outbox_record_bytes,
            self.outbox_state,
            self.output_digest,
            self.output_bytes,
        )
        if self.state is AuthorityObservationState.ABSENT:
            if any(item is not None for item in (*common, *authority_artifacts)) or (
                self.conflict_claim_bytes is not None or self._legacy_visibility_hint
            ):
                raise ValueError("absent observation carries forbidden evidence")
        elif any(item is None for item in common):
            raise ValueError("observation state lacks decision evidence")
        if self.state in {
            AuthorityObservationState.DENIED,
            AuthorityObservationState.CONFLICTED,
        } and (
            any(item is not None for item in authority_artifacts)
            or self._legacy_visibility_hint
        ):
            raise ValueError("non-committed observation carries authority artifacts")
        if (
            self.state is AuthorityObservationState.DENIED
            and self.conflict_claim_bytes is not None
        ):
            raise ValueError("denied observation carries conflict evidence")
        if (
            self.state is AuthorityObservationState.CONFLICTED
            and self.conflict_claim_bytes is None
        ):
            raise ValueError("conflicted observation lacks conflict evidence")
        if self.state is AuthorityObservationState.COMMITTED and (
            self.conflict_claim_bytes is not None
            or any(
                item is None
                for item in (
                    *common,
                    *authority_artifacts,
                )
            )
        ):
            raise ValueError("committed observation has an incomplete authority tuple")

    @property
    def artifact_visible(self) -> bool:
        """Legacy local hint; portable verifiers must derive consumability."""
        return self._legacy_visibility_hint


@dataclass(frozen=True, slots=True)
class SignedAuthorityObservation:
    snapshot: AuthorityObservationSnapshot
    launch_attestation_digest: str
    session_id: str
    sequence: str
    request_digest: str
    observer_key_id: str
    signature: Signature

    def __post_init__(self) -> None:
        b64u_decode(self.launch_attestation_digest, expected_length=32)
        b64u_decode(self.request_digest, expected_length=32)
        _canonical_identifier(self.session_id, name="observation session ID")
        _canonical_decimal(self.sequence, name="observation sequence", positive=True)
        if self.request_digest != self.snapshot.request.canonical_digest:
            raise ValueError("observation request digest binding mismatch")
        b64u_decode(self.observer_key_id, expected_length=32)
        if self.signature.algorithm != "Ed25519":
            raise ValueError("observation signature algorithm is unsupported")
        if self.signature.key_id != self.observer_key_id:
            raise ValueError("observation signature key binding mismatch")
        b64u_decode(self.signature.signature_b64u, expected_length=64)


def _snapshot_object(snapshot: AuthorityObservationSnapshot) -> dict[str, object]:
    logical = {
        "workflow_id": snapshot.logical_node.workflow_id,
        "node_id": snapshot.logical_node.node_id,
        "current_node_version": snapshot.logical_node.current_node_version,
    }
    if snapshot.logical_node.current_certificate_digest is not None:
        logical["current_certificate_digest"] = (
            snapshot.logical_node.current_certificate_digest
        )
    evidence: dict[str, str] = {}
    if snapshot.state is not AuthorityObservationState.ABSENT:
        required = (
            snapshot.authoritative_commit_digest,
            snapshot.authoritative_public_request_digest,
            snapshot.decision_reason,
            snapshot.audit_event_id,
            snapshot.audit_event_bytes,
            snapshot.persisted_operation_bytes,
        )
        if any(item is None for item in required):
            raise ValueError("observation state evidence is incomplete")
        evidence = {
            "authoritative_operation_digest": str(snapshot.authoritative_commit_digest),
            "authoritative_public_request_digest": str(
                snapshot.authoritative_public_request_digest
            ),
            "decision_reason": str(snapshot.decision_reason),
            "audit_event_id": str(snapshot.audit_event_id),
            "audit_event_b64u": b64u_encode(snapshot.audit_event_bytes or b""),
            "persisted_operation_b64u": b64u_encode(
                snapshot.persisted_operation_bytes or b""
            ),
        }
    if snapshot.state is AuthorityObservationState.CONFLICTED:
        if snapshot.conflict_claim_bytes is None:
            raise ValueError("conflict evidence is incomplete")
        evidence["conflict_claim_b64u"] = b64u_encode(snapshot.conflict_claim_bytes)
    if snapshot.state is AuthorityObservationState.COMMITTED:
        committed = {
            "certificate_payload_b64u": snapshot.certificate_payload_bytes,
            "certificate_envelope_b64u": snapshot.certificate_envelope_bytes,
            "certificate_digest": snapshot.certificate_digest,
            "authority_status_b64u": snapshot.current_status_evidence,
            "outbox_event_id": snapshot.outbox_event_id,
            "outbox_event_b64u": snapshot.outbox_event_bytes,
            "outbox_record_b64u": snapshot.outbox_record_bytes,
            "outbox_state": snapshot.outbox_state,
            "output_digest": snapshot.output_digest,
            "output_b64u": snapshot.output_bytes,
        }
        if any(item is None for item in committed.values()):
            raise ValueError("committed observation evidence is incomplete")
        for name, item in committed.items():
            evidence[name] = b64u_encode(item) if isinstance(item, bytes) else str(item)
    return {
        "request": snapshot.request.to_object(),
        "request_digest": snapshot.request.canonical_digest,
        "state": snapshot.state.value,
        "logical_node": logical,
        "evidence": evidence,
    }


def encode_authority_observation_body(
    snapshot: AuthorityObservationSnapshot,
    *,
    launch_attestation_digest: str,
    session_id: str,
    sequence: str,
    request_digest: str,
) -> bytes:
    return _canonical_json(
        {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.signed-authority-observation",
            **_snapshot_object(snapshot),
            "launch_attestation_digest": launch_attestation_digest,
            "session_id": session_id,
            "sequence": sequence,
            "signed_request_digest": request_digest,
        }
    )


def encode_signed_authority_observation(value: SignedAuthorityObservation) -> bytes:
    return _canonical_json(
        {
            "body": json.loads(
                encode_authority_observation_body(
                    value.snapshot,
                    launch_attestation_digest=value.launch_attestation_digest,
                    session_id=value.session_id,
                    sequence=value.sequence,
                    request_digest=value.request_digest,
                )
            ),
            "observer_key_id": value.observer_key_id,
            "signature": value.signature.to_object(),
        }
    )


_BASE_EVIDENCE = {
    "authoritative_operation_digest",
    "authoritative_public_request_digest",
    "decision_reason",
    "audit_event_id",
    "audit_event_b64u",
    "persisted_operation_b64u",
}
_EVIDENCE_KEYS = {
    AuthorityObservationState.ABSENT: set(),
    AuthorityObservationState.DENIED: _BASE_EVIDENCE,
    AuthorityObservationState.CONFLICTED: _BASE_EVIDENCE | {"conflict_claim_b64u"},
    AuthorityObservationState.COMMITTED: _BASE_EVIDENCE
    | {
        "certificate_payload_b64u",
        "certificate_envelope_b64u",
        "certificate_digest",
        "authority_status_b64u",
        "outbox_event_id",
        "outbox_event_b64u",
        "outbox_record_b64u",
        "outbox_state",
        "output_digest",
        "output_b64u",
    },
}


def decode_signed_authority_observation(raw: bytes) -> SignedAuthorityObservation:
    value = _strict_json(
        raw, maximum_bytes=1_048_576, name="signed authority observation"
    )
    if not isinstance(value, dict) or set(value) != {
        "body",
        "observer_key_id",
        "signature",
    }:
        raise ValueError("signed observation is noncanonical")
    body = value["body"]
    body_keys = {
        "protocol_version",
        "statement_type",
        "request",
        "request_digest",
        "state",
        "logical_node",
        "evidence",
        "launch_attestation_digest",
        "session_id",
        "sequence",
        "signed_request_digest",
    }
    if (
        not isinstance(body, dict)
        or set(body) != body_keys
        or (
            body["protocol_version"] != "APCC-1.0-draft"
            or body["statement_type"] != "apcc.signed-authority-observation"
        )
    ):
        raise ValueError("observation body has invalid keys or type")
    request_raw = _canonical_json(body["request"])
    request = decode_authority_observation_request(request_raw)
    if body["request_digest"] != request.canonical_digest:
        raise ValueError("observation request digest mismatch")
    try:
        state = AuthorityObservationState(body["state"])
    except (TypeError, ValueError) as error:
        raise ValueError("observation state is invalid") from error
    logical = body["logical_node"]
    logical_base = {"workflow_id", "node_id", "current_node_version"}
    if (
        not isinstance(logical, dict)
        or set(logical)
        not in (
            logical_base,
            logical_base | {"current_certificate_digest"},
        )
        or any(type(item) is not str for item in logical.values())
    ):
        raise ValueError("observation logical-node evidence is invalid")
    evidence = body["evidence"]
    if (
        not isinstance(evidence, dict)
        or set(evidence) != _EVIDENCE_KEYS[state]
        or any(type(item) is not str for item in evidence.values())
    ):
        raise ValueError("observation evidence does not match state")

    def string(name: str) -> str | None:
        return evidence.get(name)

    def binary(name: str) -> bytes | None:
        return None if name not in evidence else b64u_decode(evidence[name])

    snapshot = AuthorityObservationSnapshot(
        request,
        state,
        string("authoritative_operation_digest"),
        string("authoritative_public_request_digest"),
        string("decision_reason"),
        string("audit_event_id"),
        binary("audit_event_b64u"),
        LogicalNodeState(
            logical["workflow_id"],
            logical["node_id"],
            logical["current_node_version"],
            logical.get("current_certificate_digest"),
        ),
        binary("certificate_payload_b64u"),
        binary("certificate_envelope_b64u"),
        string("certificate_digest"),
        binary("authority_status_b64u"),
        string("outbox_event_id"),
        binary("outbox_event_b64u"),
        string("outbox_state"),
        string("output_digest"),
        False,
        binary("persisted_operation_b64u"),
        binary("conflict_claim_b64u"),
        binary("output_b64u"),
        binary("outbox_record_b64u"),
    )
    if (
        type(value["observer_key_id"]) is not str
        or not isinstance(value["signature"], dict)
        or any(
            type(body[name]) is not str
            for name in (
                "launch_attestation_digest",
                "session_id",
                "sequence",
                "signed_request_digest",
            )
        )
    ):
        raise ValueError("observation signature wrapper is invalid")
    return SignedAuthorityObservation(
        snapshot,
        body["launch_attestation_digest"],
        body["session_id"],
        body["sequence"],
        body["signed_request_digest"],
        value["observer_key_id"],
        Signature.from_object(value["signature"]),
    )


def verify_signed_authority_observation(
    value: SignedAuthorityObservation,
    *,
    pinned_public_key: bytes,
    expected_request: AuthorityObservationRequest,
    expected_launch_attestation_digest: str,
    expected_session_id: str,
    expected_sequence: str,
) -> None:
    if value.observer_key_id != sha256_digest(pinned_public_key):
        raise ValueError("observation response key identity mismatch")
    if (
        value.snapshot.request != expected_request
        or value.request_digest != expected_request.canonical_digest
    ):
        raise ValueError("observation response request binding mismatch")
    if (
        value.launch_attestation_digest != expected_launch_attestation_digest
        or value.session_id != expected_session_id
        or value.sequence != expected_sequence
    ):
        raise ValueError("observation response binding mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(
            b64u_decode(value.signature.signature_b64u, expected_length=64),
            AUTHORITY_OBSERVATION_DOMAIN
            + b"\x00"
            + encode_authority_observation_body(
                value.snapshot,
                launch_attestation_digest=value.launch_attestation_digest,
                session_id=value.session_id,
                sequence=value.sequence,
                request_digest=value.request_digest,
            ),
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("observation response signature mismatch") from error


@dataclass(frozen=True, slots=True)
class ObserverLaunchExpectationsV1:
    """Out-of-band values a verifier must pin for a publishable launch."""

    experiment_id: str
    run_id: str
    authority_store_id: str
    backend_kind: str
    backend_instance_digest: str
    schema_version: str
    schema_fingerprint: str
    status_key_id: str
    observer_pid: str
    session_id: str
    observer_key_id: str
    initial_trust_sequence: str
    initial_trust_head: str


@dataclass(frozen=True, slots=True)
class ObserverLaunchAttestationV1:
    """Portable controller-rooted binding for one isolated observer session."""

    protocol_version: str
    statement_type: str
    experiment_id: str
    run_id: str
    authority_store_id: str
    backend_kind: str
    backend_instance_digest: str
    schema_version: str
    schema_fingerprint: str
    status_key_id: str
    not_before_ms: str
    not_after_ms: str
    observer_pid: str
    launch_nonce: str
    session_id: str
    observer_key_id: str
    observer_public_key: str
    initial_trust_sequence: str
    initial_trust_head: str
    controller_key_id: str
    controller_signature: str

    def __post_init__(self) -> None:
        from .crypto import b64u_decode, sha256_digest

        if self.protocol_version != "APCC-1.0-draft":
            raise ValueError("unsupported observer launch protocol")
        if self.statement_type != "apcc.observer-launch-attestation":
            raise ValueError("unsupported observer launch statement")
        for name in (
            "experiment_id",
            "run_id",
            "authority_store_id",
            "status_key_id",
            "session_id",
        ):
            _canonical_identifier(getattr(self, name), name=f"observer launch {name}")
        if self.backend_kind not in {"sqlite", "postgresql"}:
            raise ValueError("invalid observer launch backend")
        for name in (
            "backend_instance_digest",
            "schema_fingerprint",
            "initial_trust_head",
            "observer_key_id",
            "controller_key_id",
        ):
            b64u_decode(getattr(self, name), expected_length=32)
        b64u_decode(self.launch_nonce, expected_length=32)
        observer_public = b64u_decode(self.observer_public_key, expected_length=32)
        b64u_decode(self.controller_signature, expected_length=64)
        if sha256_digest(observer_public) != self.observer_key_id:
            raise ValueError("observer launch key identity mismatch")
        for name in (
            "schema_version",
            "not_before_ms",
            "not_after_ms",
            "observer_pid",
            "initial_trust_sequence",
        ):
            _canonical_decimal(getattr(self, name), name=f"observer launch {name}")
        if int(self.not_after_ms) <= int(self.not_before_ms):
            raise ValueError("observer launch validity interval is invalid")

    def to_object(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    def unsigned_object(self) -> dict[str, str]:
        return {
            name: value
            for name, value in self.to_object().items()
            if name not in {"controller_key_id", "controller_signature"}
        }

    @property
    def canonical_digest(self) -> str:
        return sha256_digest(encode_observer_launch_attestation(self))

    def verify(
        self,
        *,
        pinned_controller_public_key: bytes,
        expected: ObserverLaunchExpectationsV1,
        now_ms: int,
    ) -> None:
        from .codec import encode_payload
        from .crypto import b64u_decode, sha256_digest

        if (
            self.controller_key_id != sha256_digest(pinned_controller_public_key)
            or any(
                getattr(self, name) != getattr(expected, name)
                for name in expected.__dataclass_fields__
            )
            or not int(self.not_before_ms) <= now_ms <= int(self.not_after_ms)
        ):
            raise ValueError("observer launch trust binding mismatch")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_controller_public_key).verify(
                b64u_decode(self.controller_signature, expected_length=64),
                CONTROLLER_LAUNCH_DOMAIN
                + b"\x00"
                + encode_payload(self.unsigned_object()),
            )
        except (InvalidSignature, ValueError) as error:
            raise ValueError("observer launch controller signature mismatch") from error


def encode_observer_launch_attestation(value: ObserverLaunchAttestationV1) -> bytes:
    """Encode the exact portable controller-rooted launch attestation."""
    if type(value) is not ObserverLaunchAttestationV1:
        raise TypeError("observer launch attestation has the wrong type")
    return _canonical_json(value.to_object())


def decode_observer_launch_attestation(raw: bytes) -> ObserverLaunchAttestationV1:
    """Decode an exact APCC-CJ1 launch attestation."""
    value = _strict_json(raw, maximum_bytes=8192, name="observer launch attestation")
    keys = tuple(ObserverLaunchAttestationV1.__dataclass_fields__)
    if (
        not isinstance(value, dict)
        or set(value) != set(keys)
        or any(type(item) is not str for item in value.values())
    ):
        raise ValueError("observer launch attestation has invalid keys")
    try:
        return ObserverLaunchAttestationV1(**value)
    except (TypeError, ValueError) as error:
        raise ValueError("observer launch attestation is invalid") from error


class ObservationEvidenceProvenance(StrEnum):
    """Who attests an evidence class; observer claims are never authority facts."""

    OBSERVER_ATTESTED_NONAUTHORITATIVE = "OBSERVER_ATTESTED_NONAUTHORITATIVE"


class ObservationAuthorityProof(StrEnum):
    """Authority proof present after independent semantic verification."""

    NO_AUTHORITY_PROOF = "NO_AUTHORITY_PROOF"
    AUTHORITY_CERTIFICATE_STATUS_OUTPUT = "AUTHORITY_CERTIFICATE_STATUS_OUTPUT"


@dataclass(frozen=True, slots=True)
class VerifiedAuthorityObservation:
    """Typed provenance result for experiment measurements.

    The controller-attested observer belongs to the experiment measurement TCB,
    not the authority TCB.  Only a verified certificate, its exact signed
    ``AuthorityStatus``, and the bound output hash form v1 authority proof.
    Logical-pointer and outbox lifecycle claims remain non-authoritative even
    when their internal consistency checks pass.
    """

    state: str
    consumable: bool
    certificate_digest: str | None
    trust_log_sequence: str | None
    trust_log_head: str | None
    authority_proof: ObservationAuthorityProof = (
        ObservationAuthorityProof.NO_AUTHORITY_PROOF
    )
    measurement_provenance: ObservationEvidenceProvenance = (
        ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
    )
    outbox_provenance: ObservationEvidenceProvenance | None = None
    outbox_authority_proof: ObservationAuthorityProof | None = None
    logical_pointer_provenance: ObservationEvidenceProvenance | None = None
    logical_pointer_authority_proof: ObservationAuthorityProof | None = None


@dataclass(slots=True)
class AuthorityObservationVerificationStream:
    """O(1) offline replay/order and trust-log rollback state."""

    session_id: str
    next_sequence: int = 1
    highest_trust_log_sequence: str = "0"
    highest_trust_log_head: str = ""
    launch_attestation_digest: str = ""

    def consume(
        self,
        value: SignedAuthorityObservation,
        *,
        launch: ObserverLaunchAttestationV1,
        pinned_controller_public_key: bytes,
        expected_experiment_id: str,
        expected_run_id: str,
        expected_launch: ObserverLaunchExpectationsV1,
        trust: ScopedTrust,
        now_ms: int,
        maximum_staleness_ms: int,
    ) -> VerifiedAuthorityObservation:
        if (
            value.session_id != self.session_id
            or int(value.sequence) != self.next_sequence
        ):
            raise ValueError("observation stream sequence gap or replay")
        if (
            self.launch_attestation_digest
            and launch.canonical_digest != self.launch_attestation_digest
        ):
            raise ValueError("observation stream launch changed")
        if self.highest_trust_log_head:
            highest_sequence = self.highest_trust_log_sequence
            highest_head = self.highest_trust_log_head
        else:
            highest_sequence = launch.initial_trust_sequence
            highest_head = launch.initial_trust_head
        result = verify_authority_observation(
            value,
            launch=launch,
            pinned_controller_public_key=pinned_controller_public_key,
            expected_experiment_id=expected_experiment_id,
            expected_run_id=expected_run_id,
            expected_launch=expected_launch,
            trust=trust,
            now_ms=now_ms,
            maximum_staleness_ms=maximum_staleness_ms,
            highest_trust_log_sequence=highest_sequence,
            highest_trust_log_head=highest_head,
        )
        self.next_sequence += 1
        if not self.launch_attestation_digest:
            self.launch_attestation_digest = launch.canonical_digest
        if not self.highest_trust_log_head:
            self.highest_trust_log_sequence = launch.initial_trust_sequence
            self.highest_trust_log_head = launch.initial_trust_head
        if result.trust_log_sequence is not None:
            self.highest_trust_log_sequence = result.trust_log_sequence
            assert result.trust_log_head is not None
            self.highest_trust_log_head = result.trust_log_head
        return result


def _operation_object(raw: bytes) -> dict[str, object]:
    """Decode the frozen store wrapper and strictly validate its CJ1 request."""
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OBJECT_BYTES:
        raise ValueError("operation exceeds size limit")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError("operation contains duplicate keys")
            result[key] = item
        return result

    def number(_: str) -> object:
        raise ValueError("operation contains a non-string scalar")

    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_int=number,
            parse_float=number,
            parse_constant=number,
        )
        text = raw.decode("utf-8", errors="strict")
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("malformed operation") from error
    if (
        end != len(text)
        or not isinstance(value, dict)
        or set(value) != {"operation_kind", "old_certificate_digest", "request"}
        or _canonical_json(value) != raw
    ):
        raise ValueError("operation has invalid fields or encoding")
    old = value["old_certificate_digest"]
    if old is not None and type(old) is not str:
        raise ValueError("operation old certificate digest is invalid")
    strict_projection = dict(value)
    strict_projection["old_certificate_digest"] = old or "none"
    _canonical_object_profile(
        _canonical_json(strict_projection),
        name="operation",
        keys=frozenset({"operation_kind", "old_certificate_digest", "request"}),
    )
    operation_kind = value["operation_kind"]
    if (operation_kind == "COMMIT" and old is not None) or (
        operation_kind == "SUPERSEDE" and old is None
    ):
        raise ValueError("operation kind and old certificate disagree")
    if operation_kind not in {"COMMIT", "SUPERSEDE"}:
        raise ValueError("operation kind is invalid")
    if old is not None:
        b64u_decode(old, expected_length=32)
    request = value["request"]
    if not isinstance(request, dict) or set(request) != {
        "subject",
        "context",
        "evidence",
        "bindings",
        "signatures",
        "commit_id",
        "nonce",
    }:
        raise ValueError("operation request profile is invalid")
    return value


def _validate_outbox_semantics(
    outbox: dict[str, str | None], *, status_trust_sequence: str
) -> None:
    b64u_decode(str(outbox["event_id"]), expected_length=32)
    _canonical_identifier(outbox["operation_id"], name="outbox operation ID")
    b64u_decode(str(outbox["event_payload_sha256"]), expected_length=32)
    b64u_decode(str(outbox["audit_event_id"]), expected_length=32)
    event_sequence = _canonical_decimal(
        outbox["event_sequence"], name="outbox event sequence", positive=True
    )
    trust_sequence = _canonical_decimal(
        outbox["trust_sequence"], name="outbox trust sequence", positive=True
    )
    status_sequence = _canonical_decimal(
        status_trust_sequence, name="authority status trust sequence"
    )
    if event_sequence != trust_sequence or trust_sequence > status_sequence:
        raise ValueError("outbox/status trust sequence mismatch")
    state = outbox["state"]
    delivered = outbox["delivered"]
    lease_values = tuple(
        outbox[name] for name in ("lease_token", "lease_claimed_ms", "lease_until_ms")
    )
    if state == "PENDING":
        valid = delivered == "0" and lease_values == (None, None, None)
    elif state == "CLAIMED":
        token, claimed, until = lease_values
        valid = (
            delivered == "0"
            and token is not None
            and claimed is not None
            and until is not None
        )
        if valid:
            _canonical_identifier(token, name="outbox lease token")
            claimed_value = _canonical_decimal(
                claimed, name="outbox lease claimed timestamp"
            )
            until_value = _canonical_decimal(until, name="outbox lease until timestamp")
            valid = until_value >= claimed_value
    elif state == "DELIVERED":
        valid = delivered == "1" and lease_values == (None, None, None)
    else:
        valid = False
    if not valid:
        raise ValueError("outbox lifecycle evidence is inconsistent")


def verify_authority_observation(
    value: SignedAuthorityObservation,
    *,
    launch: ObserverLaunchAttestationV1,
    pinned_controller_public_key: bytes,
    expected_experiment_id: str,
    expected_run_id: str,
    expected_launch: ObserverLaunchExpectationsV1,
    trust: ScopedTrust,
    now_ms: int,
    maximum_staleness_ms: int,
    highest_trust_log_sequence: str,
    highest_trust_log_head: str,
) -> VerifiedAuthorityObservation:
    """Verify controller, observer transport, and the complete frozen authority tuple."""
    from .codec import (
        canonical_statement,
        decode_authority_status,
        decode_certificate,
        decode_envelope,
    )
    from .crypto import b64u_decode, sha256_digest
    from .model import FailureCode
    from .verifier import TrustRole, verify_current, verify_historical

    if (
        expected_experiment_id != expected_launch.experiment_id
        or expected_run_id != expected_launch.run_id
    ):
        raise ValueError("observation experiment/run expectation mismatch")
    launch.verify(
        pinned_controller_public_key=pinned_controller_public_key,
        expected=expected_launch,
        now_ms=now_ms,
    )
    request = value.snapshot.request
    status_trust = trust.resolve(TrustRole.STATUS, (request.authority_store_id,))
    if (
        request.authority_store_id != launch.authority_store_id
        or value.session_id != launch.session_id
        or value.launch_attestation_digest != launch.canonical_digest
        or status_trust is None
        or launch.status_key_id != status_trust.key_id
    ):
        raise ValueError("observation launch/store/status trust mismatch")
    observer_public = b64u_decode(launch.observer_public_key, expected_length=32)
    verify_signed_authority_observation(
        value,
        pinned_public_key=observer_public,
        expected_request=request,
        expected_launch_attestation_digest=launch.canonical_digest,
        expected_session_id=launch.session_id,
        expected_sequence=value.sequence,
    )
    snapshot = value.snapshot
    if snapshot.state is AuthorityObservationState.ABSENT:
        return VerifiedAuthorityObservation("ABSENT", False, None, None, None)
    if snapshot.persisted_operation_bytes is None:
        raise ValueError("observation lacks persisted operation")
    operation = _operation_object(snapshot.persisted_operation_bytes)
    persisted = operation["request"]
    if not isinstance(persisted, dict):
        raise ValueError("persisted request is invalid")
    subject = persisted.get("subject")
    evidence = persisted.get("evidence")
    if not isinstance(subject, dict) or not isinstance(evidence, dict):
        raise ValueError("persisted operation evidence is invalid")
    producer = evidence.get("producer_statement")
    if not isinstance(producer, dict):
        raise ValueError("persisted producer evidence is invalid")
    if snapshot.audit_event_bytes is None or snapshot.audit_event_id is None:
        raise ValueError("observation lacks audit evidence")
    audit_keys = {"kind", "subject"}
    if (
        snapshot.state is AuthorityObservationState.COMMITTED
        and operation["old_certificate_digest"] is not None
    ):
        audit_keys.add("old_certificate_digest")
    audit = _canonical_object_profile(
        snapshot.audit_event_bytes,
        name="audit event",
        keys=frozenset(audit_keys),
        maximum_bytes=8192,
    )
    if audit.get("subject") != request.expected_commit_id:
        raise ValueError("audit event binding mismatch")
    if snapshot.state is AuthorityObservationState.DENIED:
        if (
            sha256_digest(snapshot.persisted_operation_bytes)
            != request.expected_operation_digest
            or snapshot.authoritative_commit_digest != request.expected_operation_digest
            or sha256_digest(canonical_statement(producer))
            != request.public_request_digest
            or snapshot.authoritative_public_request_digest
            != request.public_request_digest
            or persisted.get("commit_id") != request.expected_commit_id
            or subject.get("workflow_id") != request.workflow_id
            or subject.get("node_id") != request.node_id
            or subject.get("attempt_id") != request.attempt_id
            or audit.get("kind") != snapshot.decision_reason
            or set(audit) != {"kind", "subject"}
        ):
            raise ValueError("denied audit binding mismatch")
        expected_audit = sha256_digest(
            (
                "DENIED\x00"
                + request.expected_commit_id
                + "\x00"
                + request.expected_operation_digest
                + "\x00"
                + str(snapshot.decision_reason)
            ).encode("ascii")
        )
        if snapshot.audit_event_id != expected_audit:
            raise ValueError("denied audit identity mismatch")
        return VerifiedAuthorityObservation("DENIED", False, None, None, None)
    if snapshot.state is AuthorityObservationState.CONFLICTED:
        if (
            snapshot.conflict_claim_bytes is None
            or audit.get("kind") != FailureCode.COMMIT_ID_EQUIVOCATION.value
            or snapshot.decision_reason != FailureCode.COMMIT_ID_EQUIVOCATION.value
            or set(audit) != {"kind", "subject"}
        ):
            raise ValueError("conflict evidence binding mismatch")
        required = {
            "commit_id",
            "original_workflow_id",
            "original_node_id",
            "original_attempt_id",
            "original_request_digest",
            "original_public_request_digest",
            "conflicting_workflow_id",
            "conflicting_node_id",
            "conflicting_attempt_id",
            "conflicting_request_digest",
            "conflicting_public_request_digest",
        }
        claim = _canonical_object_profile(
            snapshot.conflict_claim_bytes,
            name="conflict claim",
            keys=frozenset(required),
        )
        if set(claim) != required or any(
            claim[key] != expected
            for key, expected in {
                "commit_id": request.expected_commit_id,
                "conflicting_workflow_id": request.workflow_id,
                "conflicting_node_id": request.node_id,
                "conflicting_attempt_id": request.attempt_id,
                "conflicting_request_digest": request.expected_operation_digest,
                "conflicting_public_request_digest": request.public_request_digest,
            }.items()
        ):
            raise ValueError("conflict claim binding mismatch")
        if (
            sha256_digest(snapshot.persisted_operation_bytes)
            != claim["original_request_digest"]
            or sha256_digest(canonical_statement(producer))
            != claim["original_public_request_digest"]
            or snapshot.authoritative_commit_digest != claim["original_request_digest"]
            or snapshot.authoritative_public_request_digest
            != claim["original_public_request_digest"]
            or persisted.get("commit_id") != request.expected_commit_id
            or subject.get("workflow_id") != claim["original_workflow_id"]
            or subject.get("node_id") != claim["original_node_id"]
            or subject.get("attempt_id") != claim["original_attempt_id"]
        ):
            raise ValueError("conflict original operation binding mismatch")
        expected_audit = sha256_digest(
            (
                "conflict\x00"
                + request.expected_commit_id
                + "\x00"
                + request.expected_operation_digest
            ).encode("ascii")
        )
        if snapshot.audit_event_id != expected_audit:
            raise ValueError("conflict audit identity mismatch")
        return VerifiedAuthorityObservation("CONFLICTED", False, None, None, None)
    if (
        sha256_digest(snapshot.persisted_operation_bytes)
        != request.expected_operation_digest
        or snapshot.authoritative_commit_digest != request.expected_operation_digest
        or sha256_digest(canonical_statement(producer)) != request.public_request_digest
        or snapshot.authoritative_public_request_digest != request.public_request_digest
        or persisted.get("commit_id") != request.expected_commit_id
        or subject.get("workflow_id") != request.workflow_id
        or subject.get("node_id") != request.node_id
        or subject.get("attempt_id") != request.attempt_id
    ):
        raise ValueError("persisted operation binding mismatch")
    if snapshot.state is not AuthorityObservationState.COMMITTED:
        raise ValueError("unknown observation state")
    if audit.get("kind") != "committed" or snapshot.decision_reason != "OK":
        raise ValueError("commit decision/audit binding mismatch")
    expected_audit_id = sha256_digest(
        (
            "commit\x00"
            + request.expected_commit_id
            + "\x00"
            + request.expected_operation_digest
        ).encode("ascii")
    )
    expected_audit_fields = {"kind", "subject"}
    old_certificate_digest = operation["old_certificate_digest"]
    if old_certificate_digest is not None:
        expected_audit_fields.add("old_certificate_digest")
    if (
        set(audit) != expected_audit_fields
        or audit.get("old_certificate_digest") != old_certificate_digest
        or snapshot.audit_event_id != expected_audit_id
    ):
        raise ValueError("commit audit identity mismatch")
    if any(
        item is None
        for item in (
            snapshot.certificate_payload_bytes,
            snapshot.certificate_envelope_bytes,
            snapshot.certificate_digest,
            snapshot.current_status_evidence,
            snapshot.outbox_event_bytes,
            snapshot.outbox_record_bytes,
            snapshot.output_bytes,
            snapshot.output_digest,
        )
    ):
        raise ValueError("committed observation tuple is incomplete")
    assert snapshot.certificate_payload_bytes is not None
    assert snapshot.certificate_envelope_bytes is not None
    assert snapshot.certificate_digest is not None
    detached = decode_envelope(snapshot.certificate_envelope_bytes)
    certificate = decode_certificate(snapshot.certificate_payload_bytes)
    historical = verify_historical(snapshot.certificate_envelope_bytes, trust=trust)
    if (
        not historical.ok
        or detached.payload != snapshot.certificate_payload_bytes
        or detached.payload_sha256 != snapshot.certificate_digest
        or certificate.canonical_digest != snapshot.certificate_digest
        or certificate.header.authority_store_id != request.authority_store_id
        or certificate.decision.commit_id != request.expected_commit_id
        or certificate.decision.outcome != "committed"
        or certificate.decision.reason != snapshot.decision_reason
        or certificate.decision.nonce != persisted.get("nonce")
        or certificate.subject.workflow_id != request.workflow_id
        or certificate.subject.node_id != request.node_id
        or certificate.subject.attempt_id != request.attempt_id
        or certificate.subject.to_object() != subject
        or certificate.bindings.to_object() != persisted.get("bindings")
        or certificate.context.to_object() != persisted.get("context")
        or certificate.evidence.to_object() != persisted.get("evidence")
        or certificate.signatures.to_object() != persisted.get("signatures")
    ):
        raise ValueError("historical certificate binding mismatch")
    assert snapshot.output_bytes is not None and snapshot.output_digest is not None
    if (
        snapshot.output_digest != certificate.subject.output_digest
        or sha256_digest(snapshot.output_bytes) != snapshot.output_digest
    ):
        raise ValueError("observation output binding mismatch")
    assert snapshot.outbox_event_bytes is not None
    assert snapshot.outbox_record_bytes is not None
    outbox = _nullable_outbox_record(snapshot.outbox_record_bytes)
    if (
        any(
            outbox[key] != expected
            for key, expected in {
                "event_id": snapshot.outbox_event_id,
                "event_kind": "COMMIT",
                "operation_id": request.expected_commit_id,
                "event_payload_sha256": sha256_digest(snapshot.outbox_event_bytes),
                "audit_event_id": snapshot.audit_event_id,
                "state": snapshot.outbox_state,
            }.items()
        )
        or snapshot.outbox_event_bytes != snapshot.certificate_payload_bytes
    ):
        raise ValueError("outbox evidence binding mismatch")
    assert snapshot.current_status_evidence is not None
    status = decode_authority_status(snapshot.current_status_evidence)
    _validate_outbox_semantics(outbox, status_trust_sequence=status.trust_log_sequence)
    if int(status.trust_log_sequence) < int(launch.initial_trust_sequence):
        raise ValueError("authority status predates observer launch trust head")
    current = verify_current(
        snapshot.certificate_envelope_bytes,
        trust=trust,
        authority_status=status,
        request_nonce=request.request_nonce,
        now_ms=str(now_ms),
        highest_trust_log_sequence=highest_trust_log_sequence,
        highest_trust_log_head=(
            highest_trust_log_head
            if highest_trust_log_head
            else launch.initial_trust_head
        ),
        maximum_staleness_ms=str(maximum_staleness_ms),
    )
    pointer_current = (
        snapshot.logical_node.current_certificate_digest == snapshot.certificate_digest
        and snapshot.logical_node.current_node_version
        == certificate.bindings.committed_node_version
    )
    if pointer_current != (status.superseded.value == "no"):
        raise ValueError("logical pointer/status supersession mismatch")
    consumable = current.ok
    if not current.ok and current.code not in {
        FailureCode.AUTHORITY_STATUS_REVOKED,
        FailureCode.AUTHORITY_STATUS_SUPERSEDED,
    }:
        raise ValueError(
            f"authority current-status verification failed: {current.code}"
        )
    return VerifiedAuthorityObservation(
        "COMMITTED",
        consumable,
        snapshot.certificate_digest,
        status.trust_log_sequence,
        status.trust_log_head,
        ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT,
        ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE,
        ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE,
        ObservationAuthorityProof.NO_AUTHORITY_PROOF,
        ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE,
        ObservationAuthorityProof.NO_AUTHORITY_PROOF,
    )
