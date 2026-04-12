"""
Tests for gossip_protocol.py — MCFS Phase 5 WebSocket transport.

Test tiers:
1. Wire serialization (encode/decode round-trip, Byzantine rejection)
2. GossipPeerRegistry (add, remove, sample, self-exclusion)
3. GossipServer + GossipClient (local WebSocket round-trip)
4. SwarmNode (context manager, gossip_round, n-node convergence)
5. Multi-node real convergence (5 nodes, localhost WebSockets)

WebSocket dependency: skip if websockets not installed.
"""

from __future__ import annotations

import asyncio

import pytest
from constitutional_swarm.gossip_protocol import (
    GossipClient,
    GossipPeerRegistry,
    GossipServer,
    SwarmNode,
    decode_batch,
    encode_batch,
    simulate_ws_gossip_convergence,
    spin_up_swarm,
)
from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT, compute_cid

websockets = pytest.importorskip("websockets", reason="websockets not installed — skip transport tests")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _make_node(agent_id: str = "agent-0", payload: str = "test") -> DAGNode:
    cid = compute_cid(agent_id, payload, ())
    return DAGNode(cid=cid, agent_id=agent_id, payload=payload)


def _make_crdt_with_nodes(agent_id: str, n: int) -> MerkleCRDT:
    crdt = MerkleCRDT(agent_id)
    for i in range(n):
        crdt.append(payload=f"node-{i}", bodes_passed=True)
    return crdt


# ──────────────────────────────────────────────────────────────────────────────
# Wire serialization
# ──────────────────────────────────────────────────────────────────────────────


def test_encode_decode_roundtrip() -> None:
    """encode_batch → decode_batch must reproduce all node fields."""
    nodes = [_make_node(payload=f"payload-{i}") for i in range(5)]
    decoded = decode_batch(encode_batch(nodes))
    assert len(decoded) == 5
    for original, decoded_node in zip(nodes, decoded):
        assert decoded_node.cid == original.cid
        assert decoded_node.agent_id == original.agent_id
        assert decoded_node.payload == original.payload
        assert decoded_node.parent_cids == original.parent_cids


def test_encode_decode_preserves_cid() -> None:
    """Decoded CIDs must match original (CID integrity is content-addressed)."""
    crdt = _make_crdt_with_nodes("agent-0", 3)
    nodes = [crdt.get(cid) for cid in crdt.all_cids()]
    nodes = [n for n in nodes if n is not None]
    decoded = decode_batch(encode_batch(nodes))
    for original, d in zip(
        sorted(nodes, key=lambda n: n.cid),
        sorted(decoded, key=lambda n: n.cid),
    ):
        assert d.cid == original.cid
        assert d.verify_cid(), f"Decoded node {d.cid} failed CID verification"


def test_decode_rejects_malformed_json() -> None:
    """Malformed JSON must raise ValueError, not crash."""
    with pytest.raises(ValueError, match="Malformed gossip batch"):
        decode_batch("not json {{{")


def test_decode_rejects_non_array() -> None:
    """A JSON object (not array) must raise ValueError."""
    import json
    with pytest.raises(ValueError, match="Expected JSON array"):
        decode_batch(json.dumps({"cid": "abc"}))


def test_encode_empty_batch() -> None:
    """Empty node list encodes to empty JSON array."""
    assert decode_batch(encode_batch([])) == []


def test_tampered_node_rejected_by_crdt() -> None:
    """A tampered node (CID mismatch) decoded from wire must be rejected on merge."""
    import json
    node = _make_node(payload="original")
    wire = json.loads(encode_batch([node]))
    wire[0]["payload"] = "TAMPERED"  # CID no longer matches
    batch_str = json.dumps(wire)

    decoded = decode_batch(batch_str)
    assert len(decoded) == 1
    assert not decoded[0].verify_cid(), "Tampered node should fail CID check"

    crdt = MerkleCRDT("honest", reject_unverified=True)
    added = crdt.merge_nodes(decoded)
    assert added == 0, "Honest CRDT must reject tampered node"


# ──────────────────────────────────────────────────────────────────────────────
# GossipPeerRegistry
# ──────────────────────────────────────────────────────────────────────────────


def test_registry_add_and_list() -> None:
    reg = GossipPeerRegistry()
    reg.add("127.0.0.1", 8765)
    reg.add("127.0.0.1", 8766)
    assert len(reg) == 2
    assert ("127.0.0.1", 8765) in reg.all_peers
    assert ("127.0.0.1", 8766) in reg.all_peers


def test_registry_excludes_self() -> None:
    reg = GossipPeerRegistry(self_addr=("127.0.0.1", 8765))
    reg.add("127.0.0.1", 8765)  # self — should be ignored
    reg.add("127.0.0.1", 8766)
    assert len(reg) == 1
    assert ("127.0.0.1", 8766) in reg.all_peers


def test_registry_no_duplicates() -> None:
    reg = GossipPeerRegistry()
    reg.add("127.0.0.1", 8765)
    reg.add("127.0.0.1", 8765)
    assert len(reg) == 1


def test_registry_remove() -> None:
    reg = GossipPeerRegistry()
    reg.add("127.0.0.1", 8765)
    reg.add("127.0.0.1", 8766)
    reg.remove("127.0.0.1", 8765)
    assert len(reg) == 1
    assert ("127.0.0.1", 8765) not in reg.all_peers


def test_registry_sample_empty() -> None:
    reg = GossipPeerRegistry()
    assert reg.sample(5) == []


def test_registry_sample_bounded() -> None:
    import random
    reg = GossipPeerRegistry()
    for p in range(10):
        reg.add("127.0.0.1", 8760 + p)
    samples = reg.sample(3, rng=random.Random(0))
    assert len(samples) == 3
    assert len(set(samples)) == 3  # no duplicates


# ──────────────────────────────────────────────────────────────────────────────
# GossipServer + GossipClient (single connection)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_receives_nodes() -> None:
    """Client sends a batch; server merges it into its CRDT."""
    crdt = MerkleCRDT("server")
    server = GossipServer(crdt, host="127.0.0.1", port=0)
    await server.start()
    try:
        # Create source nodes
        source = MerkleCRDT("client")
        n1 = source.append(payload="hello-from-client")
        n2 = source.append(payload="second-node")

        client = GossipClient()
        success = await client.send_batch(
            "127.0.0.1", server.actual_port, [n1, n2]
        )
        assert success, "send_batch should return True on success"

        # Small wait for server to process
        await asyncio.sleep(0.05)

        assert crdt.size == 2
        assert crdt.get(n1.cid) is not None
        assert crdt.get(n2.cid) is not None
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_server_rejects_tampered_nodes() -> None:
    """Server must not merge nodes with invalid CIDs (Byzantine rejection)."""
    import json

    crdt = MerkleCRDT("server", reject_unverified=True)
    server = GossipServer(crdt, host="127.0.0.1", port=0)
    await server.start()
    try:
        node = _make_node()
        wire = json.loads(encode_batch([node]))
        wire[0]["payload"] = "TAMPERED"
        import websockets as ws
        uri = f"ws://127.0.0.1:{server.actual_port}"
        async with ws.connect(uri) as websocket:
            await websocket.send(json.dumps(wire))
        await asyncio.sleep(0.05)
        assert crdt.size == 0, "Server accepted tampered node"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_server_ignores_malformed_json() -> None:
    """Server must not crash on malformed JSON messages."""
    import websockets as ws

    crdt = MerkleCRDT("server")
    server = GossipServer(crdt, host="127.0.0.1", port=0)
    await server.start()
    try:
        uri = f"ws://127.0.0.1:{server.actual_port}"
        async with ws.connect(uri) as websocket:
            await websocket.send("not valid json {{{")
        await asyncio.sleep(0.05)
        assert crdt.size == 0
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_client_handles_unreachable_peer() -> None:
    """GossipClient.send_batch must return False (not raise) when peer is down."""
    client = GossipClient()
    nodes = [_make_node()]
    result = await client.send_batch("127.0.0.1", 19999, nodes, timeout=1.0)
    assert result is False


@pytest.mark.asyncio
async def test_client_empty_batch_is_noop() -> None:
    """Sending empty batch returns True without attempting connection."""
    client = GossipClient()
    result = await client.send_batch("127.0.0.1", 19999, [])
    assert result is True


# ──────────────────────────────────────────────────────────────────────────────
# SwarmNode
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_swarm_node_context_manager() -> None:
    """SwarmNode as async context manager must start and stop cleanly."""
    async with SwarmNode("agent-0") as node:
        assert node.actual_port > 0
        assert node._running is True
    assert node._running is False


@pytest.mark.asyncio
async def test_swarm_node_gossip_round_no_peers() -> None:
    """gossip_round with no registered peers returns 0 successes."""
    async with SwarmNode("agent-0") as node:
        node.crdt.append(payload="hello")
        result = await node.gossip_round(n_peers=2)
    assert result["peers_contacted"] == 0
    assert result["successes"] == 0


@pytest.mark.asyncio
async def test_two_node_gossip() -> None:
    """Two SwarmNodes gossip; both should converge to the same CID set."""
    async with SwarmNode("agent-0") as a:
        async with SwarmNode("agent-1") as b:
            # Register each other
            a.registry.add(b.host, b.actual_port)
            b.registry.add(a.host, a.actual_port)

            # Each appends unique artifacts
            a.crdt.append(payload="from-a")
            b.crdt.append(payload="from-b")

            # Gossip: a → b, b → a
            await asyncio.gather(
                a.gossip_round(n_peers=1),
                b.gossip_round(n_peers=1),
            )
            await asyncio.sleep(0.1)

            # Both should have 2 nodes
            assert a.crdt.size == 2, f"a has {a.crdt.size} nodes (expected 2)"
            assert b.crdt.size == 2, f"b has {b.crdt.size} nodes (expected 2)"
            assert a.crdt.all_cids() == b.crdt.all_cids()


@pytest.mark.asyncio
async def test_swarm_node_registry_excludes_self() -> None:
    """SwarmNode sets self_addr correctly after start()."""
    async with SwarmNode("agent-0") as node:
        assert node.registry.self_addr == ("127.0.0.1", node.actual_port)
        # Adding self should be ignored
        node.registry.add("127.0.0.1", node.actual_port)
        assert len(node.registry) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Multi-node convergence (real WebSocket gossip)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_five_node_convergence() -> None:
    """5 nodes, 10 rounds → all replicas must converge over real WebSockets."""
    result = await simulate_ws_gossip_convergence(
        n_nodes=5,
        n_rounds=10,
        artifacts_per_round=2,
        n_peers=2,
        seed=42,
    )
    assert result["converged"], (
        f"WebSocket gossip did not converge: sizes={result['sizes']}"
    )
    assert result["unique_cids"] == result["total_artifacts"], (
        f"CID count mismatch: unique={result['unique_cids']}, "
        f"total={result['total_artifacts']}"
    )
    print("\nWebSocket gossip convergence (5 nodes, 10 rounds)")
    print(f"  total artifacts: {result['total_artifacts']}")
    print(f"  unique CIDs: {result['unique_cids']}")
    print(f"  converged: {result['converged']}")


@pytest.mark.asyncio
async def test_spin_up_swarm_full_mesh() -> None:
    """spin_up_swarm creates n nodes all registered with each other."""
    nodes = await spin_up_swarm(4)
    try:
        for i, node in enumerate(nodes):
            assert len(node.registry) == 3, (
                f"node-{i} should know 3 peers, knows {len(node.registry)}"
            )
    finally:
        await asyncio.gather(*[n.stop() for n in nodes])


@pytest.mark.asyncio
async def test_byzantine_node_does_not_corrupt_swarm() -> None:
    """A Byzantine node injecting tampered CIDs must not corrupt honest replicas."""
    import random

    honest_nodes = await spin_up_swarm(4)
    byzantine_crdt = MerkleCRDT("byzantine", reject_unverified=False)
    byzantine_server = GossipServer(byzantine_crdt, host="127.0.0.1", port=0)
    await byzantine_server.start()
    byz_port = byzantine_server.actual_port

    try:
        # Honest nodes also know about Byzantine (but will reject its tampered nodes)
        for node in honest_nodes:
            node.registry.add("127.0.0.1", byz_port)

        # Byzantine generates tampered nodes
        for i in range(3):
            node = byzantine_crdt.append(payload=f"will-tamper-{i}")
            tampered = DAGNode(
                cid=node.cid,
                agent_id="byzantine",
                payload=f"TAMPERED-{node.payload}",
            )
            byzantine_crdt._nodes[node.cid] = tampered

        # Honest nodes gossip (including one round to/from Byzantine port)
        rng = random.Random(77)
        for _ in range(5):
            for node in honest_nodes:
                node.crdt.append(payload=f"honest-{node.agent_id}")
            await asyncio.gather(*[n.gossip_round(n_peers=2, rng=rng) for n in honest_nodes])
            await asyncio.sleep(0.02)

        # Final full mesh among honest nodes
        for a in honest_nodes:
            for b in honest_nodes:
                if b is not a:
                    a.registry.add(b.host, b.actual_port)
        await asyncio.gather(*[n.gossip_round(n_peers=len(honest_nodes)) for n in honest_nodes])
        await asyncio.sleep(0.1)

        # All honest nodes must agree
        cid_sets = [n.crdt.all_cids() for n in honest_nodes]
        assert all(s == cid_sets[0] for s in cid_sets), "Honest nodes diverged"

        # No tampered payloads in honest replicas
        for node in honest_nodes:
            for _cid, n in node.crdt._nodes.items():
                assert "TAMPERED" not in n.payload, (
                    f"Byzantine payload leaked into {node.agent_id}: {n.payload}"
                )
    finally:
        await asyncio.gather(*[n.stop() for n in honest_nodes])
        await byzantine_server.stop()
