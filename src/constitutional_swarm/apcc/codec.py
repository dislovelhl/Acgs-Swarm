"""Strict APCC-CJ1 parsing and canonical encoding."""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, cast

from .model import AuthorityStatus, CommitCertificate, FailureCode, Signature

MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_ENVELOPE_BYTES = (MAX_PAYLOAD_BYTES * 4 // 3) + 2048
MAX_DEPTH = 8
MAX_PREDECESSORS = 4096
MAX_SAFE_INTEGER = 9007199254740991

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,15})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_AUTHORITY = re.compile(
    r"authority:[A-Za-z0-9][A-Za-z0-9._/-]{0,63}:"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}\Z"
)
_B64U = re.compile(r"[A-Za-z0-9_-]*\Z")


class CodecError(ValueError):
    """An APCC-CJ1 wire failure with a stable protocol code."""

    def __init__(self, code: FailureCode, detail: str = "") -> None:
        super().__init__(detail or code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class DetachedEnvelope:
    """Decoded detached certificate envelope."""

    payload: bytes
    payload_sha256: str
    seal: Signature


_SIG = frozenset({"algorithm", "key_id", "signature_b64u"})
_CERT: dict[str, object] = {
    "header": frozenset(
        {
            "protocol_version",
            "certificate_type",
            "encoding_profile",
            "digest_algorithm",
            "signature_algorithm",
            "authority_store_id",
            "commit_authority_key_id",
            "certificate_sequence",
        }
    ),
    "subject": frozenset(
        {
            "workflow_id",
            "node_id",
            "attempt_id",
            "agent_id",
            "actor_authority",
            "input_digest",
            "output_digest",
        }
    ),
    "context": frozenset(
        {
            "policy_id",
            "policy_version",
            "policy_epoch",
            "authority_root",
            "authority_epoch",
            "agent_revocation_generation",
            "workflow_revocation_generation",
            "workflow_epoch",
        }
    ),
    "evidence": {
        "producer_statement": frozenset(
            {
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
            }
        ),
        "producer_statement_digest": None,
        "policy_statement": frozenset(
            {
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
            }
        ),
        "policy_statement_digest": None,
        "authority_statement": frozenset(
            {
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
            }
        ),
        "authority_statement_digest": None,
    },
    "decision": frozenset(
        {"outcome", "reason", "commit_id", "nonce", "committed_at_ms"}
    ),
    "bindings": {
        "expected_node_version": None,
        "committed_node_version": None,
        "predecessor_root": None,
        "predecessors": [
            frozenset(
                {
                    "workflow_id",
                    "node_id",
                    "committed_node_version",
                    "commit_id",
                    "certificate_digest",
                    "output_digest",
                }
            )
        ],
    },
    "signatures": {
        "producer": _SIG,
        "policy_authority": _SIG,
        "authority_registry": _SIG,
    },
}
_ENVELOPE: dict[str, object] = {
    "envelope_type": None,
    "payload_b64u": None,
    "payload_sha256": None,
    "seal": _SIG,
}
_STATUS: dict[str, object] = {
    "body": frozenset(
        {
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
        }
    ),
    "signature": _SIG,
}
_DECIMALS = frozenset(
    {
        "certificate_sequence",
        "policy_version",
        "policy_epoch",
        "authority_epoch",
        "agent_revocation_generation",
        "actor_revocation_generation",
        "workflow_revocation_generation",
        "workflow_epoch",
        "expected_node_version",
        "committed_node_version",
        "issued_at_ms",
        "expires_at_ms",
        "committed_at_ms",
        "trust_log_sequence",
        "this_update_ms",
        "next_update_ms",
    }
)
_DIGESTS = frozenset(
    {
        "input_digest",
        "output_digest",
        "authority_root",
        "producer_statement_digest",
        "policy_statement_digest",
        "authority_statement_digest",
        "proposal_digest",
        "predecessor_root",
        "certificate_digest",
        "payload_sha256",
        "trust_log_head",
    }
)
_IDS = frozenset(
    {
        "authority_store_id",
        "commit_authority_key_id",
        "workflow_id",
        "node_id",
        "attempt_id",
        "agent_id",
        "policy_id",
        "commit_id",
        "producer_key_id",
        "policy_key_id",
        "authority_key_id",
        "status_key_id",
        "key_id",
    }
)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CodecError(FailureCode.DUPLICATE_FIELD, key)
        result[key] = value
    return result


def _number(_: str) -> object:
    raise CodecError(FailureCode.WRONG_JSON_TYPE, "numbers are forbidden")


def _tree(value: object, depth: int = 1) -> None:
    if depth > MAX_DEPTH:
        raise CodecError(FailureCode.DEPTH_LIMIT_EXCEEDED)
    if isinstance(value, str):
        if not value.isascii():
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise CodecError(FailureCode.INVALID_UNICODE) from exc
            if unicodedata.normalize("NFC", value) != value:
                raise CodecError(FailureCode.INVALID_UNICODE)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise CodecError(FailureCode.UNKNOWN_FIELD, key)
            _tree(key)
            _tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _tree(item, depth + 1)
    else:
        raise CodecError(FailureCode.WRONG_JSON_TYPE)


def _canonical(value: object) -> bytes:
    try:
        _tree(value)
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except RecursionError as exc:
        raise CodecError(FailureCode.DEPTH_LIMIT_EXCEEDED) from exc


def encode_payload(value: object) -> bytes:
    """Encode an object/array/string-only value as canonical APCC-CJ1 bytes."""
    return _canonical(value)


def _scan_depth(text: str) -> None:
    """Enforce structural nesting before invoking the recursive JSON decoder."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise CodecError(FailureCode.DEPTH_LIMIT_EXCEEDED)
        elif char in "]}" and depth > 0:
            depth -= 1


def _parse(raw: bytes, max_bytes: int = MAX_PAYLOAD_BYTES) -> object:
    if len(raw) > max_bytes:
        raise CodecError(FailureCode.SIZE_LIMIT_EXCEEDED)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CodecError(FailureCode.INVALID_UNICODE) from exc
    if text.startswith("\ufeff"):
        raise CodecError(FailureCode.INVALID_UNICODE)
    _scan_depth(text)
    decoder = json.JSONDecoder(
        object_pairs_hook=_pairs,
        parse_int=_number,
        parse_float=_number,
        parse_constant=_number,
    )
    try:
        value, end = decoder.raw_decode(text)
    except CodecError:
        raise
    except RecursionError as exc:
        raise CodecError(FailureCode.DEPTH_LIMIT_EXCEEDED) from exc
    except json.JSONDecodeError as exc:
        raise CodecError(FailureCode.MALFORMED_JSON) from exc
    if end != len(text):
        raise CodecError(FailureCode.TRAILING_BYTES)
    try:
        _tree(value)
    except RecursionError as exc:
        raise CodecError(FailureCode.DEPTH_LIMIT_EXCEEDED) from exc
    return value


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CodecError(FailureCode.WRONG_JSON_TYPE)
    return cast("dict[str, Any]", value)


def _keys(actual: set[str], expected: set[str]) -> None:
    missing, extra = expected - actual, actual - expected
    for key in extra:
        if any(key.lower() == wanted.lower() for wanted in expected):
            raise CodecError(FailureCode.CASE_MISMATCHED_FIELD, key)
    if extra:
        raise CodecError(FailureCode.UNKNOWN_FIELD, min(extra))
    if missing:
        raise CodecError(FailureCode.MISSING_FIELD, min(missing))


def _schema(value: object, schema: object) -> None:
    if schema is None:
        if not isinstance(value, str):
            raise CodecError(FailureCode.WRONG_JSON_TYPE)
    elif isinstance(schema, frozenset):
        obj = _object(value)
        expected = {item for item in schema if isinstance(item, str)}
        if len(expected) != len(schema):
            raise AssertionError("invalid internal schema")
        _keys(set(obj), expected)
        if any(not isinstance(item, str) for item in obj.values()):
            raise CodecError(FailureCode.WRONG_JSON_TYPE)
    elif isinstance(schema, dict):
        obj = _object(value)
        _keys(set(obj), set(schema))
        for key, child in schema.items():
            _schema(obj[key], child)
    elif isinstance(schema, list):
        if not isinstance(value, list):
            raise CodecError(FailureCode.WRONG_JSON_TYPE)
        if len(value) > MAX_PREDECESSORS:
            raise CodecError(FailureCode.SIZE_LIMIT_EXCEEDED)
        for item in value:
            _schema(item, schema[0])
    else:
        raise AssertionError("invalid internal schema")


def _decode_b64u(value: str, length: int | None = None) -> bytes:
    if "=" in value or not _B64U.fullmatch(value):
        raise CodecError(FailureCode.INVALID_BASE64URL)
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise CodecError(FailureCode.INVALID_BASE64URL) from exc
    canonical = base64.urlsafe_b64encode(result).rstrip(b"=").decode("ascii")
    if canonical != value or (length is not None and len(result) != length):
        raise CodecError(FailureCode.INVALID_BASE64URL)
    return result


def _scalars(value: object, name: str | None = None) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _scalars(item, key)
    elif isinstance(value, list):
        for item in value:
            _scalars(item, name)
    elif not isinstance(value, str):
        raise CodecError(FailureCode.WRONG_JSON_TYPE)
    elif name in _DECIMALS:
        if not _DECIMAL.fullmatch(value) or int(value) > MAX_SAFE_INTEGER:
            raise CodecError(FailureCode.INVALID_DECIMAL_STRING, name)
    elif name in _DIGESTS:
        _decode_b64u(value, 32)
    elif name in {"nonce", "request_nonce"}:
        _decode_b64u(value, 16)
    elif name == "signature_b64u":
        _decode_b64u(value, 64)
    elif name == "payload_b64u":
        _decode_b64u(value)
    elif name == "actor_authority" and not _AUTHORITY.fullmatch(value):
        raise CodecError(FailureCode.NONCANONICAL_ENCODING, name)
    elif name in _IDS and not _IDENTIFIER.fullmatch(value):
        raise CodecError(FailureCode.NONCANONICAL_ENCODING, name)


def _decode(
    raw: bytes, schema: object, max_bytes: int = MAX_PAYLOAD_BYTES
) -> dict[str, Any]:
    value = _object(_parse(raw, max_bytes))
    if _canonical(value) != raw:
        raise CodecError(FailureCode.NONCANONICAL_ENCODING)
    _schema(value, schema)
    _scalars(value)
    return value


def _predecessors(value: Mapping[str, Any]) -> None:
    items = cast("list[dict[str, str]]", value["bindings"]["predecessors"])
    members = [_canonical(item) for item in items]
    if members != sorted(members):
        raise CodecError(FailureCode.NONCANONICAL_ENCODING)
    seen_members: set[bytes] = set()
    seen_nodes: set[str] = set()
    seen_digests: set[str] = set()
    for item, member in zip(items, members, strict=True):
        if (
            member in seen_members
            or item["node_id"] in seen_nodes
            or item["certificate_digest"] in seen_digests
        ):
            raise CodecError(FailureCode.DUPLICATE_SET_MEMBER)
        seen_members.add(member)
        seen_nodes.add(item["node_id"])
        seen_digests.add(item["certificate_digest"])


def _required_literal(value: str, expected: str, code: FailureCode) -> None:
    if value != expected:
        raise CodecError(code)


def _certificate_semantics(value: Mapping[str, Any]) -> None:
    header = cast("dict[str, str]", value["header"])
    for field, expected, code in (
        ("protocol_version", "APCC-1.0-draft", FailureCode.UNKNOWN_PROTOCOL_VERSION),
        (
            "certificate_type",
            "apcc.commit-certificate",
            FailureCode.UNSUPPORTED_CERTIFICATE_TYPE,
        ),
        ("encoding_profile", "APCC-CJ1", FailureCode.UNSUPPORTED_ENCODING),
        (
            "digest_algorithm",
            "SHA-256",
            FailureCode.UNSUPPORTED_DIGEST_ALGORITHM,
        ),
        (
            "signature_algorithm",
            "Ed25519",
            FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
        ),
    ):
        _required_literal(header[field], expected, code)

    evidence = cast("dict[str, Any]", value["evidence"])
    for name, expected_type in (
        ("producer_statement", "apcc.producer-statement"),
        ("policy_statement", "apcc.policy-statement"),
        ("authority_statement", "apcc.authority-statement"),
    ):
        statement = cast("dict[str, str]", evidence[name])
        _required_literal(
            statement["protocol_version"],
            "APCC-1.0-draft",
            FailureCode.UNKNOWN_PROTOCOL_VERSION,
        )
        _required_literal(
            statement["statement_type"],
            expected_type,
            FailureCode.UNSUPPORTED_STATEMENT_TYPE,
        )
    policy = cast("dict[str, str]", evidence["policy_statement"])
    _required_literal(policy["decision"], "allow", FailureCode.SUBJECT_MISMATCH)

    decision = cast("dict[str, str]", value["decision"])
    _required_literal(decision["outcome"], "committed", FailureCode.ILLEGAL_NODE_STATE)
    bindings = cast("dict[str, Any]", value["bindings"])
    expected_version = int(cast("str", bindings["expected_node_version"]))
    committed_version = int(cast("str", bindings["committed_node_version"]))
    if committed_version != expected_version + 1:
        raise CodecError(FailureCode.NODE_VERSION_CONFLICT)

    signatures = cast("dict[str, dict[str, str]]", value["signatures"])
    for signature in signatures.values():
        _required_literal(
            signature["algorithm"],
            "Ed25519",
            FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
        )


def _status_semantics(value: Mapping[str, Any]) -> None:
    body = cast("dict[str, str]", value["body"])
    _required_literal(
        body["protocol_version"],
        "APCC-1.0-draft",
        FailureCode.UNKNOWN_PROTOCOL_VERSION,
    )
    _required_literal(
        body["statement_type"],
        "apcc.authority-status",
        FailureCode.UNSUPPORTED_STATEMENT_TYPE,
    )
    if body["status"] not in {"current", "revoked"}:
        raise CodecError(FailureCode.AUTHORITY_STATUS_REVOKED)
    if body["superseded"] not in {"yes", "no"}:
        raise CodecError(FailureCode.AUTHORITY_STATUS_SUPERSEDED)
    signature = cast("dict[str, str]", value["signature"])
    _required_literal(
        signature["algorithm"],
        "Ed25519",
        FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
    )


def encode_certificate(certificate: CommitCertificate) -> bytes:
    """Encode a typed commit certificate in its unique APCC-CJ1 form."""
    value = certificate.to_object()
    bindings = cast("dict[str, object]", value["bindings"])
    items = cast("list[dict[str, str]]", bindings["predecessors"])
    items.sort(key=_canonical)
    encoded = _canonical(value)
    _predecessors(_decode(encoded, _CERT))
    return encoded


def decode_certificate(raw: bytes) -> CommitCertificate:
    """Strictly decode one canonical APCC commit certificate."""
    value = _decode(raw, _CERT)
    _predecessors(value)
    _certificate_semantics(value)
    try:
        return CommitCertificate.from_object(value)
    except (TypeError, ValueError) as exc:
        raise CodecError(FailureCode.NONCANONICAL_ENCODING) from exc


def encode_envelope(
    payload: bytes, *, seal_key_id: str, seal_signature_b64u: str
) -> bytes:
    """Encode a detached envelope around canonical payload bytes."""
    from .crypto import sha256_digest

    decode_certificate(payload)
    value = {
        "envelope_type": "apcc.detached-certificate-envelope",
        "payload_b64u": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
        "payload_sha256": sha256_digest(payload),
        "seal": {
            "algorithm": "Ed25519",
            "key_id": seal_key_id,
            "signature_b64u": seal_signature_b64u,
        },
    }
    encoded = _canonical(value)
    _decode(encoded, _ENVELOPE)
    return encoded


def decode_envelope(raw: bytes) -> DetachedEnvelope:
    """Strictly decode an envelope and its canonical inner certificate."""
    value = _decode(raw, _ENVELOPE, MAX_ENVELOPE_BYTES)
    if value["envelope_type"] != "apcc.detached-certificate-envelope":
        raise CodecError(FailureCode.UNSUPPORTED_CERTIFICATE_TYPE)
    seal = cast("dict[str, str]", value["seal"])
    _required_literal(
        seal["algorithm"],
        "Ed25519",
        FailureCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
    )
    payload = _decode_b64u(value["payload_b64u"])
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise CodecError(FailureCode.SIZE_LIMIT_EXCEEDED)
    decode_certificate(payload)
    try:
        signature = Signature.from_object(value["seal"])
    except (TypeError, ValueError) as exc:
        raise CodecError(FailureCode.NONCANONICAL_ENCODING) from exc
    return DetachedEnvelope(payload, value["payload_sha256"], signature)


def encode_authority_status(status: AuthorityStatus) -> bytes:
    """Encode the full signed AuthorityStatus wrapper."""
    encoded = _canonical(status.to_object())
    _decode(encoded, _STATUS)
    return encoded


def encode_authority_status_body(status: AuthorityStatus) -> bytes:
    """Encode exactly the body covered by the status signature."""
    return _canonical(status.body_object())


def decode_authority_status(raw: bytes) -> AuthorityStatus:
    """Strictly decode a signed AuthorityStatus wrapper."""
    value = _decode(raw, _STATUS)
    _status_semantics(value)
    try:
        return AuthorityStatus.from_object(value)
    except (TypeError, ValueError) as exc:
        raise CodecError(FailureCode.NONCANONICAL_ENCODING) from exc


def normalize_authority_status(
    value: AuthorityStatus | Mapping[str, object] | bytes,
) -> AuthorityStatus:
    """Validate any supported status representation through the strict codec."""
    if isinstance(value, AuthorityStatus):
        return decode_authority_status(encode_authority_status(value))
    if isinstance(value, bytes):
        return decode_authority_status(value)
    return decode_authority_status(_canonical(dict(value)))


def canonical_statement(statement: Mapping[str, str]) -> bytes:
    """Encode an embedded signed statement body."""
    return _canonical(dict(statement))


def canonical_predecessors(predecessors: Sequence[Mapping[str, str]]) -> bytes:
    """Encode a predecessor semantic set in canonical-member order."""
    return _canonical(sorted((dict(item) for item in predecessors), key=_canonical))
