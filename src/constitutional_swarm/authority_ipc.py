"""Authenticated, pathless IPC primitives for the APCC authority process."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = "apcc-authority-ipc-v1"
HEADER_SIZE = 4
_MISSING = object()


class FrameProtocolError(ValueError):
    """Stable fail-closed classification for an untrusted request frame."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FrameSizeError(ValueError):
    """A locally encoded response cannot fit the negotiated frame bound."""


def canonical_json(value: Any) -> bytes:
    """Encode one protocol value canonically and reject non-standard numbers."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical_json(value)).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    while size:
        chunk = connection.recv(size)
        if not chunk:
            raise ConnectionError("incomplete authority frame")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def send_frame(connection: socket.socket, value: Any, max_frame_bytes: int) -> None:
    encoded = canonical_json(value)
    if len(encoded) > max_frame_bytes:
        raise FrameSizeError("authority frame too large")
    connection.sendall(struct.pack("!I", len(encoded)) + encoded)


def recv_frame(connection: socket.socket, max_frame_bytes: int) -> Any:
    size = struct.unpack("!I", recv_exact(connection, HEADER_SIZE))[0]
    if size > max_frame_bytes:
        raise FrameProtocolError("frame_too_large")
    try:
        value = json.loads(
            recv_exact(connection, size).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
        pending: list[tuple[Any, int]] = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 64:
                raise ValueError("json_nesting_too_deep")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        if isinstance(exc, FrameProtocolError):
            raise
        raise FrameProtocolError("malformed_json") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite_json_constant:{value}")


def signed_response(
    *,
    key: Ed25519PrivateKey,
    session: str,
    channel: str,
    sequence: int,
    authority_pid: int,
    request_digest: str,
    result: Any = _MISSING,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (result is _MISSING) == (error is None):
        raise ValueError("response requires exactly one result or error")
    body: dict[str, Any] = {
        "protocol": PROTOCOL,
        "session": session,
        "channel": channel,
        "sequence": sequence,
        "authority_pid": authority_pid,
        "request_digest": request_digest,
        "result_digest": digest(result) if result is not _MISSING else None,
        "error_digest": digest(dict(error)) if error is not None else None,
        "result": None if result is _MISSING else result,
        "error": dict(error) if error is not None else None,
    }
    return {**body, "signature": b64u(key.sign(canonical_json(body)))}


def verify_response(
    response: Any,
    *,
    public_key: Ed25519PublicKey,
    session: str,
    channel: str,
    sequence: int,
    authority_pid: int,
    request_digest: str,
) -> tuple[Any | None, Mapping[str, Any] | None]:
    fields = {
        "protocol",
        "session",
        "channel",
        "sequence",
        "authority_pid",
        "request_digest",
        "result_digest",
        "error_digest",
        "result",
        "error",
        "signature",
    }
    if not isinstance(response, dict) or set(response) != fields:
        raise ValueError("invalid signed response")
    signature = response["signature"]
    body = {key: value for key, value in response.items() if key != "signature"}
    if type(signature) is not str:
        raise ValueError("unsigned authority response")
    expected = (PROTOCOL, session, channel, sequence, authority_pid, request_digest)
    actual = tuple(
        body[key]
        for key in (
            "protocol",
            "session",
            "channel",
            "sequence",
            "authority_pid",
            "request_digest",
        )
    )
    if actual != expected:
        raise ValueError("authority transcript mismatch")
    result = body["result"]
    error = body["error"]
    has_result = body["result_digest"] is not None
    has_error = body["error_digest"] is not None
    if has_result == has_error:
        raise ValueError("invalid authority response outcome")
    if body["result_digest"] != (digest(result) if has_result else None):
        raise ValueError("authority result digest mismatch")
    if body["error_digest"] != (digest(error) if has_error else None):
        raise ValueError("authority error digest mismatch")
    try:
        public_key.verify(b64u_decode(signature), canonical_json(body))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("invalid authority response signature") from exc
    if error is not None and not isinstance(error, dict):
        raise ValueError("invalid authority error")
    return result, error if has_error else None
