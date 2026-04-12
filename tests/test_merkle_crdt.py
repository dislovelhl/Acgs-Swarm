"""
Tests for merkle_crdt.py — MCFS Phase 3 decentralized artifact store.

Test tiers:
1. DAGNode integrity (CID computation, verification, immutability)
2. MerkleCRDT operations (append, heads, merge)
3. CRDT properties (commutativity, associativity, idempotency)
4. Byzantine rejection (tampered CIDs, missing parents)
5. Async gossip convergence (Eventual Epistemic Convergence)

No torch dependency — pure Python, runs everywhere.
"""

from __future__ import annotations

import pytest
from constitutional_swarm.merkle_crdt import (
    DAGNode,
    MerkleCRDT,
    compute_cid,
    simulate_gossip_convergence,
)

# ──────────────────────────────────────────────────────────────────────────────
# DAGNode integrity
# ──────────────────────────────────────────────────────────────────────────────


def test_cid_deterministic() -> None:
    """Same inputs must produce same CID."""
    cid1 = compute_cid("agent-0", "hello", ("abc",))
    cid2 = compute_cid("agent-0", "hello", ("abc",))
    assert cid1 == cid2


def test_cid_differs_on_content_change() -> None:
    """Different payload must produce different CID."""
    cid1 = compute_cid("agent-0", "hello", ())
    cid2 = compute_cid("agent-0", "world", ())
    assert cid1 != cid2


def test_cid_differs_on_parent_change() -> None:
    """Different parents must produce different CID."""
    cid1 = compute_cid("agent-0", "hello", ("parent-a",))
    cid2 = compute_cid("agent-0", "hello", ("parent-b",))
    assert cid1 != cid2


def test_node_verify_cid_valid() -> None:
    """A correctly constructed node must pass CID verification."""
    cid = compute_cid("agent-0", "test payload", ())
    node = DAGNode(cid=cid, agent_id="agent-0", payload="test payload")
    assert node.verify_cid() is True


def test_node_verify_cid_tampered() -> None:
    """A node with tampered CID must fail verification."""
    node = DAGNode(cid="tampered_cid", agent_id="agent-0", payload="test")
    assert node.verify_cid() is False


# ──────────────────────────────────────────────────────────────────────────────
# MerkleCRDT: append and heads
# ──────────────────────────────────────────────────────────────────────────────


def test_append_creates_node() -> None:
    """append() must create a node with valid CID and store it."""
    crdt = MerkleCRDT("agent-0")
    node = crdt.append(payload="first artifact")
    assert node.verify_cid()
    assert crdt.size == 1
    assert crdt.get(node.cid) is node


def test_append_links_to_heads() -> None:
    """Second append must have the first node as parent."""
    crdt = MerkleCRDT("agent-0")
    n1 = crdt.append(payload="first")
    n2 = crdt.append(payload="second")
    assert n1.cid in n2.parent_cids


def test_heads_returns_tips() -> None:
    """Heads must be the DAG frontier (nodes with no children)."""
    crdt = MerkleCRDT("agent-0")
    n1 = crdt.append(payload="first")
    # After first append: heads = {n1}
    assert crdt.heads == frozenset({n1.cid})

    n2 = crdt.append(payload="second")
    # After second append: heads = {n2} (n1 is now a parent)
    assert crdt.heads == frozenset({n2.cid})


def test_initial_node_has_no_parents() -> None:
    """First node in an empty DAG must have no parent_cids."""
    crdt = MerkleCRDT("agent-0")
    node = crdt.append(payload="genesis")
    assert node.parent_cids == ()


# ──────────────────────────────────────────────────────────────────────────────
# MerkleCRDT: merge
# ──────────────────────────────────────────────────────────────────────────────


def test_merge_adds_remote_nodes() -> None:
    """merge() must add nodes from the remote replica."""
    a = MerkleCRDT("agent-a")
    b = MerkleCRDT("agent-b")

    a.append(payload="from-a")
    b.append(payload="from-b")

    added = a.merge(b)
    assert added == 1
    assert a.size == 2


def test_merge_idempotent() -> None:
    """Merging the same replica twice must not add duplicate nodes."""
    a = MerkleCRDT("agent-a")
    b = MerkleCRDT("agent-b")

    b.append(payload="from-b")

    a.merge(b)
    added = a.merge(b)
    assert added == 0
    assert a.size == 1


def test_merge_commutative() -> None:
    """merge(A, B) and merge(B, A) must produce the same CID set."""
    a = MerkleCRDT("agent-a")
    b = MerkleCRDT("agent-b")

    a.append(payload="a-artifact")
    b.append(payload="b-artifact")

    # Create copies and merge in both directions
    a1 = MerkleCRDT("agent-a1")
    a1.merge(a)
    a1.merge(b)

    b1 = MerkleCRDT("agent-b1")
    b1.merge(b)
    b1.merge(a)

    assert a1.all_cids() == b1.all_cids(), "Merge is not commutative"


def test_merge_associative() -> None:
    """merge(merge(A, B), C) == merge(A, merge(B, C))."""
    a = MerkleCRDT("agent-a")
    b = MerkleCRDT("agent-b")
    c = MerkleCRDT("agent-c")

    a.append(payload="from-a")
    b.append(payload="from-b")
    c.append(payload="from-c")

    # (A merge B) merge C
    left = MerkleCRDT("left")
    left.merge(a)
    left.merge(b)
    left.merge(c)

    # A merge (B merge C)
    right = MerkleCRDT("right")
    bc = MerkleCRDT("bc")
    bc.merge(b)
    bc.merge(c)
    right.merge(a)
    right.merge(bc)

    assert left.all_cids() == right.all_cids(), "Merge is not associative"


# ──────────────────────────────────────────────────────────────────────────────
# Byzantine fault tolerance
# ──────────────────────────────────────────────────────────────────────────────


def test_byzantine_rejection_tampered_node() -> None:
    """Nodes with invalid CIDs must be rejected during merge."""
    honest = MerkleCRDT("honest")
    byzantine = MerkleCRDT("byzantine", reject_unverified=False)

    # Create a valid node, then tamper with it
    node = byzantine.append(payload="legitimate")
    tampered = DAGNode(
        cid=node.cid,  # Keep original CID
        agent_id="byzantine",
        payload="TAMPERED PAYLOAD",  # Changed payload → CID mismatch
    )
    # Force-insert the tampered node into byzantine's store
    byzantine._nodes[node.cid] = tampered

    # Merge into honest replica — tampered node should be rejected
    added = honest.merge(byzantine)
    assert added == 0, "Honest replica accepted tampered node"


def test_verify_integrity_detects_corruption() -> None:
    """verify_integrity() must return CIDs of corrupted nodes."""
    crdt = MerkleCRDT("agent-0", reject_unverified=False)
    good = crdt.append(payload="good")

    # Force-insert a bad node
    bad = DAGNode(cid="bad_cid", agent_id="agent-0", payload="corrupted")
    crdt._nodes["bad_cid"] = bad

    invalid = crdt.verify_integrity()
    assert "bad_cid" in invalid
    assert good.cid not in invalid


# ──────────────────────────────────────────────────────────────────────────────
# Topological ordering
# ──────────────────────────────────────────────────────────────────────────────


def test_topological_order_preserves_causality() -> None:
    """Parents must appear before children in topological order."""
    crdt = MerkleCRDT("agent-0")
    n1 = crdt.append(payload="first")
    n2 = crdt.append(payload="second")
    n3 = crdt.append(payload="third")

    order = crdt.topological_order()
    cid_positions = {node.cid: i for i, node in enumerate(order)}

    assert cid_positions[n1.cid] < cid_positions[n2.cid]
    assert cid_positions[n2.cid] < cid_positions[n3.cid]


def test_topological_order_deterministic() -> None:
    """Two replicas with same nodes must produce same topological order."""
    a = MerkleCRDT("agent-a")
    b = MerkleCRDT("agent-b")

    a.append(payload="a-1")
    b.append(payload="b-1")

    combined1 = MerkleCRDT("c1")
    combined1.merge(a)
    combined1.merge(b)

    combined2 = MerkleCRDT("c2")
    combined2.merge(b)
    combined2.merge(a)

    order1 = [n.cid for n in combined1.topological_order()]
    order2 = [n.cid for n in combined2.topological_order()]
    assert order1 == order2, "Topological order is not deterministic"


# ──────────────────────────────────────────────────────────────────────────────
# Async gossip convergence (EEC)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gossip_convergence_small() -> None:
    """5 agents, 10 rounds → all replicas must converge to identical CID sets."""
    result = await simulate_gossip_convergence(
        n_agents=5, n_rounds=10, artifacts_per_round=2, gossip_partners=2,
    )
    assert result["converged"], (
        f"Gossip did not converge: sizes={result['sizes']}"
    )
    assert result["unique_cids"] == result["total_artifacts"]
    print("\nGossip convergence (5 agents, 10 rounds)")
    print(f"  total artifacts: {result['total_artifacts']}")
    print(f"  unique CIDs: {result['unique_cids']}")
    print(f"  converged: {result['converged']}")


@pytest.mark.asyncio
async def test_gossip_convergence_large() -> None:
    """20 agents, 20 rounds → eventual convergence even with sparse gossip."""
    result = await simulate_gossip_convergence(
        n_agents=20, n_rounds=20, artifacts_per_round=3, gossip_partners=3,
    )
    assert result["converged"], (
        f"Gossip did not converge with 20 agents: sizes={result['sizes']}"
    )
    expected_total = 20 * 20 * 3
    assert result["unique_cids"] == expected_total
    print("\nGossip convergence (20 agents, 20 rounds)")
    print(f"  total artifacts: {result['total_artifacts']}")
    print(f"  unique CIDs: {result['unique_cids']}")


@pytest.mark.asyncio
async def test_gossip_byzantine_agent_excluded() -> None:
    """A Byzantine agent injecting tampered nodes must not corrupt honest replicas."""
    import random

    rng = random.Random(99)
    agents = [MerkleCRDT(f"agent-{i}") for i in range(5)]
    byzantine = MerkleCRDT("byzantine", reject_unverified=False)

    # Honest agents generate artifacts
    for agent in agents:
        for _ in range(5):
            agent.append(payload=f"honest-{agent.agent_id}", bodes_passed=True)

    # Byzantine agent generates tampered artifacts
    for _ in range(5):
        node = byzantine.append(payload="will-tamper")
        tampered = DAGNode(
            cid=node.cid,
            agent_id="byzantine",
            payload="TAMPERED-" + node.payload,
        )
        byzantine._nodes[node.cid] = tampered

    # Gossip including Byzantine agent
    all_agents = [*agents, byzantine]
    for _ in range(5):
        for agent in agents:  # Only honest agents gossip
            peers = rng.sample(all_agents, 2)
            for peer in peers:
                agent.merge(peer)

    # Full convergence among honest agents
    for a in agents:
        for b in agents:
            a.merge(b)

    # All honest agents must have same CIDs
    cid_sets = [a.all_cids() for a in agents]
    assert all(s == cid_sets[0] for s in cid_sets), "Honest agents diverged"

    # Byzantine tampered nodes must NOT be in honest replicas
    for agent in agents:
        for _cid, node in agent._nodes.items():
            assert "TAMPERED" not in node.payload, (
                f"Byzantine payload leaked into {agent.agent_id}: {node.payload}"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Summary and metadata
# ──────────────────────────────────────────────────────────────────────────────


def test_summary_keys() -> None:
    crdt = MerkleCRDT("agent-0")
    crdt.append(payload="x", bodes_passed=True, constitutional_hash="608508a9bd224290")
    s = crdt.summary()
    for key in ("total_nodes", "heads", "agents", "bodes_validated"):
        assert key in s
    assert s["bodes_validated"] == 1


def test_merge_nodes_from_list() -> None:
    """merge_nodes() must accept a raw list of DAGNode objects."""
    source = MerkleCRDT("source")
    n1 = source.append(payload="node-1")
    n2 = source.append(payload="node-2")

    target = MerkleCRDT("target")
    added = target.merge_nodes([n1, n2])
    assert added == 2
    assert target.size == 2
