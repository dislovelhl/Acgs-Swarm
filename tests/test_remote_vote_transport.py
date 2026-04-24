"""Tests for remote_vote_transport.py — remote peer vote collection/runtime."""

from __future__ import annotations

import builtins
import json
import ssl
from dataclasses import asdict
from typing import Any

import pytest
from constitutional_swarm import (
    ConstitutionalMesh,
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteRequest,
    RemoteVoteResponse,
    RemoteVoteServer,
)
from constitutional_swarm.remote_vote_transport import (
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution

websockets = pytest.importorskip(
    "websockets", reason="websockets not installed — skip remote vote transport tests"
)


@pytest.fixture
def remote_transport_context() -> dict[str, Any]:
    """Remote-vote setup with one local signer and one remote peer."""
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, peers_per_validation=2, quorum=2, seed=23)
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=remote_peer.public_key_hex)
    mesh.register_local_signer("peer-local")
    assignment = mesh.request_validation("producer", "fixture content", "art-fixture")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-remote")
    return {
        "mesh": mesh,
        "peer": remote_peer,
        "assignment": assignment,
        "request": request,
    }


class _FakeServerWebSocket:
    def __init__(self, incoming: list[str]) -> None:
        self._incoming = list(incoming)
        self.sent: list[str] = []

    def __aiter__(self) -> _FakeServerWebSocket:
        return self

    async def __anext__(self) -> str:
        if self._incoming:
            return self._incoming.pop(0)
        raise StopAsyncIteration

    async def send(self, message: str) -> None:
        self.sent.append(message)


class _FakeClientWebSocket:
    def __init__(
        self, *, recv_value: str | None = None, recv_error: BaseException | None = None
    ) -> None:
        self.sent: list[str] = []
        self._recv_value = recv_value
        self._recv_error = recv_error

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str:
        if self._recv_error is not None:
            raise self._recv_error
        assert self._recv_value is not None
        return self._recv_value


class _FakeConnectContext:
    def __init__(self, websocket: _FakeClientWebSocket) -> None:
        self.websocket = websocket

    async def __aenter__(self) -> _FakeClientWebSocket:
        return self.websocket

    async def __aexit__(self, *_: Any) -> None:
        return None


def test_remote_vote_request_round_trip() -> None:
    request = RemoteVoteRequest(
        assignment_id="assign-1",
        voter_id="peer-1",
        producer_id="producer-1",
        artifact_id="art-1",
        content="safe content",
        content_hash="abc123",
        constitutional_hash="const-hash",
        voter_public_key="deadbeef",
        nonce="nonce-1",
        timestamp=1234.5,
        request_signer_public_key="feedface",
        request_signature="cafebabe",
    )
    decoded = decode_remote_vote_request(encode_remote_vote_request(request))
    assert decoded == request


def test_remote_vote_response_round_trip() -> None:
    response = RemoteVoteResponse(
        assignment_id="assign-1",
        voter_id="peer-1",
        approved=True,
        reason="ok",
        constitutional_hash="const-hash",
        content_hash="abc123",
        signature="cafebabe",
    )
    decoded = decode_remote_vote_response(encode_remote_vote_response(response))
    assert decoded == response


def test_remote_vote_response_rejects_non_boolean_approved() -> None:
    with pytest.raises(ValueError, match="approved must be a boolean"):
        decode_remote_vote_response(
            '{"assignment_id":"assign-1","voter_id":"peer-1","approved":"false",'
            '"reason":"ok","constitutional_hash":"const-hash","content_hash":"abc123",'
            '"signature":"cafebabe"}'
        )


@pytest.mark.asyncio
async def test_remote_vote_server_round_trip() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=7)
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-1")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket([encode_remote_vote_request(request)])
    await server._handle_connection(websocket)
    response = decode_remote_vote_response(websocket.sent[0])

    assert response.assignment_id == request.assignment_id
    assert response.voter_id == "peer-1"
    assert response.approved is True
    assert ConstitutionalMesh.verify_vote_signature(
        public_key=request.voter_public_key,
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        approved=response.approved,
        reason=response.reason,
        constitutional_hash=response.constitutional_hash,
        content_hash=response.content_hash,
        signature=response.signature,
    )


@pytest.mark.asyncio
async def test_full_validation_remote_collects_remote_and_local_votes() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=11)
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )

    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=remote_peer.public_key_hex)
    mesh.register_local_signer("peer-local-1")
    mesh.register_local_signer("peer-local-2")

    class InMemoryRemoteVoteClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return remote_peer.handle_vote_request(request)

    result = await mesh.full_validation_remote(
        "producer",
        "safe remote-reviewed content",
        "art-remote",
        peer_routes={"peer-remote": ("localhost", 1)},
        client=InMemoryRemoteVoteClient(),
    )

    assert result.accepted is True
    assert result.quorum_met is True
    assert result.proof is not None
    assert result.proof.verify() is True


def test_remote_peer_rejects_tampered_content_hash() -> None:
    constitution = Constitution.default()
    request_signer = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        constitution,
        seed=13,
        request_signing_private_key=request_signer,
    )
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-2")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    tampered_content = "tampered content"
    tampered = RemoteVoteRequest(
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        producer_id=request.producer_id,
        artifact_id=request.artifact_id,
        content=tampered_content,
        content_hash=request.content_hash,
        constitutional_hash=request.constitutional_hash,
        voter_public_key=request.voter_public_key,
        nonce=request.nonce,
        timestamp=request.timestamp,
        request_signer_public_key=request.request_signer_public_key,
        request_signature=request_signer.sign(
            ConstitutionalMesh.build_remote_vote_request_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                producer_id=request.producer_id,
                artifact_id=request.artifact_id,
                content=tampered_content,
                content_hash=request.content_hash,
                constitutional_hash=request.constitutional_hash,
                voter_public_key=request.voter_public_key,
                nonce=request.nonce,
                timestamp=request.timestamp,
            )
        ).hex(),
    )
    with pytest.raises(ValueError, match="content does not match"):
        peer.handle_vote_request(tampered)


def test_remote_peer_rejects_untrusted_request_signer() -> None:
    constitution = Constitution.default()
    trusted_mesh = ConstitutionalMesh(constitution, seed=17)
    untrusted_mesh = ConstitutionalMesh(constitution, seed=18)
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={trusted_mesh.get_request_signing_public_key()},
    )
    untrusted_mesh.register_local_signer("producer")
    untrusted_mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    untrusted_mesh.register_local_signer("peer-2")
    untrusted_mesh.register_local_signer("peer-3")
    assignment = untrusted_mesh.request_validation("producer", "safe content", "art-3")
    request = untrusted_mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    with pytest.raises(ValueError, match="not trusted"):
        peer.handle_vote_request(request)


# ---------------------------------------------------------------------------
# Phase 6: Remote vote transport failure-path tests
# ---------------------------------------------------------------------------


class TestDecodeRemoteVoteRequestErrors:
    """Failure paths in decode_remote_vote_request (lines 50-71)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote request"):
            decode_remote_vote_request("{not-json!")

    def test_non_dict_json_array(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request("[1,2,3]")

    def test_non_dict_json_string(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request('"just a string"')

    @pytest.mark.parametrize(
        "missing_field",
        [
            "assignment_id",
            "voter_id",
            "producer_id",
            "artifact_id",
            "content",
            "content_hash",
            "constitutional_hash",
            "voter_public_key",
            "nonce",
            "timestamp",
            "request_signer_public_key",
            "request_signature",
        ],
    )
    def test_missing_required_field(self, missing_field: str) -> None:
        full_payload = {
            "assignment_id": "a",
            "voter_id": "v",
            "producer_id": "p",
            "artifact_id": "art",
            "content": "c",
            "content_hash": "ch",
            "constitutional_hash": "const",
            "voter_public_key": "vpk",
            "nonce": "nonce-1",
            "timestamp": 1234.5,
            "request_signer_public_key": "rspk",
            "request_signature": "rs",
        }
        del full_payload[missing_field]
        import json

        with pytest.raises(ValueError, match=f"missing {missing_field}"):
            decode_remote_vote_request(json.dumps(full_payload))


class TestDecodeRemoteVoteResponseErrors:
    """Failure paths in decode_remote_vote_response (lines 78-99)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote response"):
            decode_remote_vote_response("not-json{")

    def test_non_dict_json(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_response("[1]")

    def test_missing_required_field(self) -> None:
        import json

        payload = {
            "assignment_id": "a",
            "voter_id": "v",
            "approved": True,
            "reason": "ok",
            "constitutional_hash": "ch",
            # missing content_hash
            "signature": "sig",
        }
        with pytest.raises(ValueError, match="missing content_hash"):
            decode_remote_vote_response(json.dumps(payload))


class TestLocalRemotePeerValidation:
    """Explicit tests for LocalRemotePeer.handle_vote_request guard clauses."""

    def _make_peer_and_request(self) -> tuple[LocalRemotePeer, RemoteVoteRequest]:
        """Create a valid peer + request pair for mutation tests."""
        constitution = Constitution.default()
        mesh = ConstitutionalMesh(constitution, seed=42)
        peer = LocalRemotePeer(
            agent_id="peer-1",
            constitution=constitution,
            trusted_request_signers={mesh.get_request_signing_public_key()},
        )
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
        mesh.register_local_signer("peer-2")
        mesh.register_local_signer("peer-3")
        assignment = mesh.request_validation("producer", "safe content", "art-val")
        request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
        return peer, request

    def test_rejects_wrong_voter_id(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_voter = RemoteVoteRequest(
            assignment_id=request.assignment_id,
            voter_id="wrong-peer",
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content=request.content,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            voter_public_key=request.voter_public_key,
            nonce=request.nonce,
            timestamp=request.timestamp,
            request_signer_public_key=request.request_signer_public_key,
            request_signature=request.request_signature,
        )
        with pytest.raises(ValueError, match="intended for wrong-peer"):
            peer.handle_vote_request(wrong_voter)

    def test_rejects_mismatched_pubkey(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_key = RemoteVoteRequest(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content=request.content,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            voter_public_key="0000000000000000000000000000000000000000000000000000000000000000",
            nonce=request.nonce,
            timestamp=request.timestamp,
            request_signer_public_key=request.request_signer_public_key,
            request_signature=request.request_signature,
        )
        with pytest.raises(ValueError, match="public key does not match"):
            peer.handle_vote_request(wrong_key)


@pytest.mark.asyncio
async def test_remote_vote_client_connection_timeout_propagates() -> None:
    """RemoteVoteClient.request_vote() must propagate TimeoutError when the server is unresponsive."""
    import asyncio

    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=42)
    mesh.register_local_signer("producer")
    mesh.register_local_signer("peer-1")
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "content", "art-timeout")

    # Build a valid request (voter_id is just needed for the dataclass; server ignores it here).
    request = RemoteVoteRequest(
        assignment_id=assignment.assignment_id,
        voter_id="peer-1",
        producer_id="producer",
        artifact_id="art-timeout",
        content="content",
        content_hash=assignment.content_hash,
        constitutional_hash=assignment.constitutional_hash,
        voter_public_key="00" * 32,
        nonce="nonce-timeout",
        timestamp=1234.5,
        request_signer_public_key="00" * 32,
        request_signature="00" * 64,
    )

    fake_ws = _FakeClientWebSocket(recv_error=TimeoutError())
    client = RemoteVoteClient()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            websockets,
            "connect",
            lambda uri, ssl=None: _FakeConnectContext(fake_ws),
        )
        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await client.request_vote("localhost", 9999, request, timeout=0.1)


@pytest.mark.asyncio
async def test_remote_vote_server_malformed_json_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    peer = remote_transport_context["peer"]
    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket(["{not-json!"])

    with pytest.raises(ValueError, match="Malformed remote vote request"):
        await server._handle_connection(websocket)


@pytest.mark.asyncio
async def test_remote_vote_client_malformed_response_json_raises_value_error(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = remote_transport_context["request"]
    fake_ws = _FakeClientWebSocket(recv_value="{not-json!")
    monkeypatch.setattr(
        websockets,
        "connect",
        lambda uri, ssl=None: _FakeConnectContext(fake_ws),
    )

    client = RemoteVoteClient()
    with pytest.raises(ValueError, match="Malformed remote vote response"):
        await client.request_vote("localhost", 9999, request)


@pytest.mark.asyncio
async def test_remote_vote_server_pubkey_mismatch_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    peer = remote_transport_context["peer"]
    request = remote_transport_context["request"]
    bad_request = RemoteVoteRequest(
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        producer_id=request.producer_id,
        artifact_id=request.artifact_id,
        content=request.content,
        content_hash=request.content_hash,
        constitutional_hash=request.constitutional_hash,
        voter_public_key="00" * 32,
        nonce=request.nonce,
        timestamp=request.timestamp,
        request_signer_public_key=request.request_signer_public_key,
        request_signature=request.request_signature,
    )

    server = RemoteVoteServer(peer.handle_vote_request)
    websocket = _FakeServerWebSocket([json.dumps(asdict(bad_request), separators=(",", ":"))])

    with pytest.raises(ValueError, match="public key does not match"):
        await server._handle_connection(websocket)


@pytest.mark.asyncio
async def test_collect_remote_votes_missing_route_raises_key_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    with pytest.raises(KeyError, match="No route found for remote peer 'peer-remote'"):
        await mesh.collect_remote_votes(assignment.assignment_id, peer_routes={})


@pytest.mark.asyncio
async def test_collect_remote_votes_wrong_assignment_id_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class WrongAssignmentClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return RemoteVoteResponse(
                assignment_id="wrong-assignment",
                voter_id=request.voter_id,
                approved=True,
                reason="ok",
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
                signature="00" * 64,
            )

    with pytest.raises(ValueError, match="assignment mismatch"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=WrongAssignmentClient(),
        )


@pytest.mark.asyncio
async def test_collect_remote_votes_wrong_voter_id_raises_value_error(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class WrongVoterClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            return RemoteVoteResponse(
                assignment_id=request.assignment_id,
                voter_id="wrong-peer",
                approved=True,
                reason="ok",
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
                signature="00" * 64,
            )

    with pytest.raises(ValueError, match="voter mismatch"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=WrongVoterClient(),
        )


@pytest.mark.asyncio
async def test_collect_remote_votes_timeout_propagates(
    remote_transport_context: dict[str, Any],
) -> None:
    mesh = remote_transport_context["mesh"]
    assignment = remote_transport_context["assignment"]

    class TimeoutClient:
        async def request_vote(
            self,
            host: str,
            port: int,
            request: RemoteVoteRequest,
            *,
            timeout: float = 5.0,
            ssl_context: Any = None,
        ) -> RemoteVoteResponse:
            raise TimeoutError("timed out")

    with pytest.raises(TimeoutError, match="timed out"):
        await mesh.collect_remote_votes(
            assignment.assignment_id,
            peer_routes={"peer-remote": ("localhost", 1)},
            client=TimeoutClient(),
            timeout=0.1,
        )


@pytest.mark.asyncio
async def test_remote_vote_client_missing_websockets_dependency_raises_import_error(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = remote_transport_context["request"]
    original_import = builtins.__import__

    def _missing_websockets(
        name: str,
        globals_: dict[str, Any] | None = None,
        locals_: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "websockets":
            raise ImportError("No module named 'websockets'")
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _missing_websockets)

    client = RemoteVoteClient()
    with pytest.raises(
        ImportError,
        match=r"Remote vote transport requires 'websockets>=12\.0'",
    ):
        await client.request_vote("localhost", 9000, request)


def test_transport_security_plaintext_rejects_explicit_ssl_context() -> None:
    with pytest.raises(ValueError, match="cannot specify both transport_security and ssl_context"):
        RemoteVoteServer(
            lambda request: RemoteVoteResponse(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                approved=True,
                reason="ok",
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
                signature="00" * 64,
            ),
            transport_security="plaintext",
            ssl_context=ssl.create_default_context(),
        )


def test_transport_security_tls_forces_ssl_context_creation() -> None:
    server = RemoteVoteServer(
        lambda request: RemoteVoteResponse(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=True,
            reason="ok",
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature="00" * 64,
        ),
        transport_security="tls",
    )

    assert isinstance(server.ssl_context, ssl.SSLContext)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "expects_tls"),
    [
        ("ws://localhost", False),
        ("wss://localhost", True),
    ],
)
async def test_transport_security_auto_derives_from_endpoint_scheme(
    remote_transport_context: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    expects_tls: bool,
) -> None:
    request = remote_transport_context["request"]
    response = RemoteVoteResponse(
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        approved=True,
        reason="ok",
        constitutional_hash=request.constitutional_hash,
        content_hash=request.content_hash,
        signature="00" * 64,
    )
    fake_ws = _FakeClientWebSocket(recv_value=encode_remote_vote_response(response))
    captured: dict[str, Any] = {}

    def _connect(uri: str, ssl: Any = None) -> _FakeConnectContext:
        captured["uri"] = uri
        captured["ssl"] = ssl
        return _FakeConnectContext(fake_ws)

    monkeypatch.setattr(websockets, "connect", _connect)

    client = RemoteVoteClient(transport_security="auto")
    await client.request_vote(host, 9443, request)

    assert captured["uri"] == f"{host}:9443"
    assert (captured["ssl"] is not None) is expects_tls


def test_remote_vote_server_auto_derives_ssl_context_from_host_scheme() -> None:
    tls_server = RemoteVoteServer(
        lambda request: RemoteVoteResponse(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=True,
            reason="ok",
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature="00" * 64,
        ),
        host="wss://localhost",
        transport_security="auto",
    )
    plaintext_server = RemoteVoteServer(
        lambda request: RemoteVoteResponse(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=True,
            reason="ok",
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature="00" * 64,
        ),
        host="ws://localhost",
        transport_security="auto",
    )

    assert isinstance(tls_server.ssl_context, ssl.SSLContext)
    assert plaintext_server.ssl_context is None
