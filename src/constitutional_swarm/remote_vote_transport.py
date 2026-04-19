"""Remote vote transport/runtime for constitutional mesh peers.

This module closes the gap between:
1. ``ConstitutionalMesh.prepare_remote_vote()`` producing a signable request, and
2. public-key-only peers validating/signing that request outside the producer process.

The default transport is WebSocket-based and uses the existing optional
``transport`` extra (``websockets``). A remote peer runs a lightweight
``RemoteVoteServer`` with a ``LocalRemotePeer`` handler that:
- validates content via AgentDNA
- signs the vote decision with its Ed25519 private key
- returns a detached signature + decision payload
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution
from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteRequest


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


class RemoteVoteClient:
    """WebSocket client for one-shot remote vote requests."""

    async def request_vote(
        self,
        host: str,
        port: int,
        request: RemoteVoteRequest,
        *,
        timeout: float = 5.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> RemoteVoteResponse:
        is_local = host in {"127.0.0.1", "localhost", "::1"}
        if ssl_context is None and not is_local:
            raise ValueError("Non-local remote vote transport requires TLS ssl_context")

        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        uri = f"{'wss' if ssl_context is not None else 'ws'}://{host}:{port}"
        async with asyncio.timeout(timeout):
            async with websockets.connect(uri, ssl=ssl_context) as ws:
                await ws.send(encode_remote_vote_request(request))
                message = await ws.recv()
        return decode_remote_vote_response(str(message))


class RemoteVoteServer:
    """WebSocket server that handles one request-response remote vote RPCs."""

    def __init__(
        self,
        handler: Callable[[RemoteVoteRequest], RemoteVoteResponse | Awaitable[RemoteVoteResponse]],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._handler = handler
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self._server: Any = None
        self._actual_port: int = port

    async def start(self) -> None:
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc
        is_local = self.host in {"127.0.0.1", "localhost", "::1"}
        if self.ssl_context is None and not is_local:
            raise ValueError("Non-local remote vote server requires TLS ssl_context")
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ssl=self.ssl_context,
        )
        sockets = self._server.sockets
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> RemoteVoteServer:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    @property
    def actual_port(self) -> int:
        return self._actual_port

    async def _handle_connection(self, websocket: Any) -> None:
        async for message in websocket:
            request = decode_remote_vote_request(str(message))
            response = self._handler(request)
            if asyncio.iscoroutine(response):
                response = await response
            await websocket.send(encode_remote_vote_response(response))


class LocalRemotePeer:
    """Runtime for a public-key-only remote peer that validates/signs votes."""

    def __init__(
        self,
        *,
        agent_id: str,
        constitution: Constitution,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
        strict: bool = False,
        trusted_request_signers: set[str] | None = None,
        allow_untrusted_request_signers: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.constitution = constitution
        self.strict = strict
        self._dna = AgentDNA(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )
        self._private_key = self._coerce_private_key(vote_private_key)
        self._public_key = self._private_key.public_key()
        self._trusted_request_signers = set(trusted_request_signers or set())
        self._allow_untrusted_request_signers = allow_untrusted_request_signers

    @property
    def public_key_hex(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def handle_vote_request(self, request: RemoteVoteRequest) -> RemoteVoteResponse:
        if request.voter_id != self.agent_id:
            raise ValueError(
                f"Vote request intended for {request.voter_id}, but peer is {self.agent_id}"
            )
        if request.voter_public_key != self.public_key_hex:
            raise ValueError("Vote request public key does not match remote peer identity")
        if not ConstitutionalMesh.verify_remote_vote_request(request):
            raise ValueError("Remote vote request signature is invalid")
        if (
            not self._allow_untrusted_request_signers
            and request.request_signer_public_key not in self._trusted_request_signers
        ):
            raise ValueError("Remote vote request signer is not trusted")
        if hashlib.sha256(request.content.encode("utf-8")).hexdigest()[:32] != request.content_hash:
            raise ValueError("Remote vote request content does not match content hash")

        result = self._dna.validate(request.content)
        approved = result.valid
        reason = (
            "constitutional check passed"
            if result.valid
            else "; ".join(result.violations)
        )
        signature = self._private_key.sign(
            ConstitutionalMesh.build_vote_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                approved=approved,
                reason=reason,
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
            )
        ).hex()
        return RemoteVoteResponse(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=approved,
            reason=reason,
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature=signature,
        )

    @staticmethod
    def _coerce_private_key(
        value: Ed25519PrivateKey | bytes | str | None,
    ) -> Ed25519PrivateKey:
        if value is None:
            return Ed25519PrivateKey.generate()
        if isinstance(value, Ed25519PrivateKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PrivateKey.from_private_bytes(raw)


__all__ = [
    "LocalRemotePeer",
    "RemoteVoteClient",
    "RemoteVoteResponse",
    "RemoteVoteServer",
    "decode_remote_vote_request",
    "decode_remote_vote_response",
    "encode_remote_vote_request",
    "encode_remote_vote_response",
]
