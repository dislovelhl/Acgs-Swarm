"""Stable cross-package contracts for constitutional_swarm."""

from __future__ import annotations

from typing import Any

import pytest
from constitutional_swarm import (
    AgentDNA,
    ConstitutionalMesh,
    LocalRemotePeer,
    MeshProof,
    MeshResult,
    PeerAssignment,
    RemoteVoteClient,
    RemoteVoteServer,
)

from acgs_lite import Constitution

pytestmark = pytest.mark.contract


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


class _LoopbackClientWebSocket:
    def __init__(self, server: RemoteVoteServer) -> None:
        self._server = server
        self.sent: list[str] = []

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str:
        websocket = _FakeServerWebSocket([self.sent[-1]])
        await self._server._handle_connection(websocket)
        return websocket.sent[-1]


class _FakeConnectContext:
    def __init__(self, websocket: _LoopbackClientWebSocket) -> None:
        self.websocket = websocket

    async def __aenter__(self) -> _LoopbackClientWebSocket:
        return self.websocket

    async def __aexit__(self, *_: Any) -> None:
        return None


def _register_mesh_agents(mesh: ConstitutionalMesh, count: int = 5) -> None:
    for index in range(count):
        mesh.register_local_signer(f"agent-{index}", domain=f"domain-{index % 2}")


def test_public_api_accepts_acgs_lite_constitution_instances() -> None:
    constitution = Constitution.default()
    dna = AgentDNA(constitution=constitution, agent_id="contract-agent")
    mesh = ConstitutionalMesh(constitution, seed=13)

    assert dna.hash == constitution.hash
    assert mesh.constitutional_hash == constitution.hash


def test_assignment_and_result_preserve_constitutional_hash_contract() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=17)
    _register_mesh_agents(mesh)

    assignment = mesh.request_validation("agent-0", "safe governance contract check", "art-4")
    result = mesh.full_validation("agent-1", "safe governance contract verification", "art-5")

    assert isinstance(assignment, PeerAssignment)
    assert assignment.constitutional_hash == constitution.hash
    assert isinstance(result, MeshResult)
    assert result.constitutional_hash == constitution.hash
    assert isinstance(result.proof, MeshProof)
    assert result.proof.constitutional_hash == constitution.hash
    assert result.proof.verify() is True


@pytest.mark.asyncio
async def test_top_level_remote_validation_contract_returns_verified_mesh_result() -> None:
    websockets = pytest.importorskip(
        "websockets",
        reason="websockets not installed — skip remote validation contract test",
    )

    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, peers_per_validation=3, quorum=3, seed=37)
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )

    mesh.register_local_signer("producer", domain="contract")
    mesh.register_remote_agent(
        "peer-remote",
        domain="contract",
        vote_public_key=remote_peer.public_key_hex,
    )
    mesh.register_local_signer("peer-local-1", domain="contract")
    mesh.register_local_signer("peer-local-2", domain="contract")

    server = RemoteVoteServer(remote_peer.handle_vote_request)
    client = RemoteVoteClient()
    original_connect = websockets.connect
    websockets.connect = lambda uri, ssl=None: _FakeConnectContext(  # type: ignore[assignment]
        _LoopbackClientWebSocket(server)
    )
    try:
        result = await mesh.full_validation_remote(
            "producer",
            "safe governance contract verification over remote transport",
            "art-remote-contract",
            peer_routes={"peer-remote": ("127.0.0.1", 443)},
            client=client,
        )
    finally:
        websockets.connect = original_connect  # type: ignore[assignment]

    assert isinstance(result, MeshResult)
    assert result.accepted is True
    assert result.votes_for == 3
    assert result.quorum_met is True
    assert result.constitutional_hash == constitution.hash
    assert isinstance(result.proof, MeshProof)
    assert result.proof.constitutional_hash == constitution.hash
    assert result.proof.verify() is True
