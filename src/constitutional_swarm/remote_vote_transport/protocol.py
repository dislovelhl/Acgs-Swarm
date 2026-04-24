"""Wire schema and transport helpers for remote vote exchange."""

from __future__ import annotations

import json
import ssl
from dataclasses import asdict, dataclass
from typing import Literal
from urllib.parse import urlsplit

from constitutional_swarm.mesh import RemoteVoteRequest

TransportSecurity = Literal["plaintext", "tls", "auto"]

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _is_loopback_host(host: str) -> bool:
    return host in _LOOPBACK_HOSTS


def _format_uri_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _parse_ws_endpoint(host: str) -> tuple[str | None, str, int | None]:
    if "://" not in host:
        return None, host, None
    parsed = urlsplit(host)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError(f"Unsupported remote vote URL scheme: {parsed.scheme!r}")
    if parsed.hostname is None:
        raise ValueError("Remote vote URL must include a hostname")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Remote vote URL may not include a path, query, or fragment")
    return parsed.scheme, parsed.hostname, parsed.port


def _resolve_transport_security(
    *,
    transport_security: TransportSecurity,
    scheme: str | None,
    host: str,
) -> Literal["plaintext", "tls"]:
    if transport_security == "auto":
        if scheme == "wss":
            return "tls"
        if scheme == "ws":
            return "plaintext"
        return "plaintext" if _is_loopback_host(host) else "tls"
    return transport_security


def _build_ssl_context(
    mode: Literal["plaintext", "tls"],
    *,
    server_side: bool = False,
) -> ssl.SSLContext | None:
    if mode == "plaintext":
        return None
    if server_side:
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    return ssl.create_default_context()


@dataclass(frozen=True, slots=True)
class RemoteVoteResponse:
    """Detached signed vote decision returned by a remote peer."""

    assignment_id: str
    voter_id: str
    approved: bool
    reason: str
    constitutional_hash: str
    content_hash: str
    signature: str


def encode_remote_vote_request(request: RemoteVoteRequest) -> str:
    return json.dumps(asdict(request), separators=(",", ":"))


def decode_remote_vote_request(message: str) -> RemoteVoteRequest:
    try:
        payload = json.loads(message)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed remote vote request: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Malformed remote vote request: expected object, got {type(payload)}")
    try:
        return RemoteVoteRequest(
            assignment_id=str(payload["assignment_id"]),
            voter_id=str(payload["voter_id"]),
            producer_id=str(payload["producer_id"]),
            artifact_id=str(payload["artifact_id"]),
            content=str(payload["content"]),
            content_hash=str(payload["content_hash"]),
            constitutional_hash=str(payload["constitutional_hash"]),
            voter_public_key=str(payload["voter_public_key"]),
            nonce=str(payload["nonce"]),
            timestamp=float(payload["timestamp"]),
            request_signer_public_key=str(payload["request_signer_public_key"]),
            request_signature=str(payload["request_signature"]),
        )
    except KeyError as exc:
        raise ValueError(f"Malformed remote vote request: missing {exc.args[0]}") from exc


def encode_remote_vote_response(response: RemoteVoteResponse) -> str:
    return json.dumps(asdict(response), separators=(",", ":"))


def decode_remote_vote_response(message: str) -> RemoteVoteResponse:
    try:
        payload = json.loads(message)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed remote vote response: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Malformed remote vote response: expected object, got {type(payload)}")
    approved = payload.get("approved")
    if not isinstance(approved, bool):
        raise ValueError("Malformed remote vote response: approved must be a boolean")
    try:
        return RemoteVoteResponse(
            assignment_id=str(payload["assignment_id"]),
            voter_id=str(payload["voter_id"]),
            approved=approved,
            reason=str(payload.get("reason", "")),
            constitutional_hash=str(payload["constitutional_hash"]),
            content_hash=str(payload["content_hash"]),
            signature=str(payload["signature"]),
        )
    except KeyError as exc:
        raise ValueError(f"Malformed remote vote response: missing {exc.args[0]}") from exc


__all__ = [
    "_LOOPBACK_HOSTS",
    "RemoteVoteResponse",
    "TransportSecurity",
    "_build_ssl_context",
    "_format_uri_host",
    "_is_loopback_host",
    "_parse_ws_endpoint",
    "_resolve_transport_security",
    "decode_remote_vote_request",
    "decode_remote_vote_response",
    "encode_remote_vote_request",
    "encode_remote_vote_response",
]
