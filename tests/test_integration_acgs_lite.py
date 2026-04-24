"""Cross-package integration tests for constitutional_swarm and acgs_lite."""

from __future__ import annotations

from typing import Any

import pytest
from constitutional_swarm import (
    AgentDNA,
    ConstitutionalMesh,
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteServer,
)

from acgs_lite import Constitution, Rule

pytestmark = pytest.mark.integration


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


def test_default_constitution_flows_through_dna_and_mesh() -> None:
    constitution = Constitution.default()
    dna = AgentDNA(constitution=constitution, agent_id="dna-agent", strict=False)
    mesh = ConstitutionalMesh(constitution, seed=7)
    _register_mesh_agents(mesh)

    validation = dna.validate("safe collaborative planning update")
    assignment = mesh.request_validation("agent-0", "safe governance planning update", "art-1")
    result = mesh.full_validation("agent-1", "safe peer-reviewed governance note", "art-2")

    assert validation.constitutional_hash == constitution.hash
    assert assignment.constitutional_hash == constitution.hash
    assert result.constitutional_hash == constitution.hash
    assert result.proof is not None
    assert result.proof.constitutional_hash == constitution.hash


def test_custom_acgs_lite_rules_drive_mesh_validation_flow() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="SWARM-001",
                text="Outputs must not omit provenance",
                severity="high",
                keywords=["missing provenance"],
            ),
            Rule(
                id="SWARM-002",
                text="Outputs must not propose unsafe bypasses",
                severity="critical",
                keywords=["unsafe bypass"],
            ),
        ],
        name="constitutional-swarm-integration",
    )
    mesh = ConstitutionalMesh(constitution, seed=11)
    _register_mesh_agents(mesh)

    result = mesh.full_validation(
        "agent-0",
        "safe governance review with clear provenance",
        "art-3",
    )

    assert result.accepted is True
    assert result.quorum_met is True
    assert result.proof is not None
    assert result.proof.constitutional_hash == constitution.hash
    assert result.proof.verify() is True


@pytest.mark.asyncio
async def test_remote_validation_e2e_preserves_acgs_lite_constitution_contract() -> None:
    websockets = pytest.importorskip(
        "websockets",
        reason="websockets not installed — skip remote validation integration test",
    )

    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, peers_per_validation=3, quorum=3, seed=31)
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )

    mesh.register_local_signer("producer", domain="governance")
    mesh.register_remote_agent(
        "peer-remote",
        domain="governance",
        vote_public_key=remote_peer.public_key_hex,
    )
    mesh.register_local_signer("peer-local-1", domain="governance")
    mesh.register_local_signer("peer-local-2", domain="governance")

    server = RemoteVoteServer(remote_peer.handle_vote_request)
    client = RemoteVoteClient()
    original_connect = websockets.connect
    websockets.connect = lambda uri, ssl=None: _FakeConnectContext(  # type: ignore[assignment]
        _LoopbackClientWebSocket(server)
    )
    try:
        result = await mesh.full_validation_remote(
            "producer",
            "safe governance integration note with provenance",
            "art-remote-integration",
            peer_routes={"peer-remote": ("127.0.0.1", 443)},
            client=client,
        )
    finally:
        websockets.connect = original_connect  # type: ignore[assignment]

    assert result.accepted is True
    assert result.votes_for == 3
    assert result.quorum_met is True
    assert result.constitutional_hash == constitution.hash
    assert result.proof is not None
    assert result.proof.constitutional_hash == constitution.hash
    assert result.proof.verify() is True
