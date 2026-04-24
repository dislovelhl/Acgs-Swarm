"""Deterministic interleaved fuzz test for MerkleCRDT convergence."""

from __future__ import annotations

import asyncio
import random

import pytest
from constitutional_swarm import MerkleCRDT

N_PEERS = 3
N_OPS = 75
SEED = 20260423


@pytest.mark.asyncio
async def test_merkle_crdt_seeded_interleaved_convergence_fuzz() -> None:
    rng = random.Random(SEED)
    peers = [MerkleCRDT(f"peer-{idx}") for idx in range(N_PEERS)]
    expected_union: set[str] = set()

    async def run_op(op_index: int) -> None:
        actor_idx = rng.randrange(N_PEERS)
        actor = peers[actor_idx]

        if op_index < N_PEERS or rng.random() < 0.62:
            node = actor.append(
                payload=f"seed={SEED} op={op_index} actor={actor.agent_id}",
                payload_type="fuzz_artifact",
                bodes_passed=(op_index % 2 == 0),
                constitutional_hash="608508a9bd224290",
                metadata={"op": op_index, "actor_idx": actor_idx},
            )
            expected_union.add(node.cid)
        else:
            source_idx = rng.randrange(N_PEERS)
            if source_idx == actor_idx:
                source_idx = (source_idx + 1) % N_PEERS
            actor.merge(peers[source_idx])

        await asyncio.sleep(0)

    for op_index in range(N_OPS):
        await run_op(op_index)

    # Deterministic final full-mesh gossip forces eventual CRDT convergence.
    # Keep this sequential: reciprocal concurrent merge() calls can acquire
    # replica locks in opposite order and deadlock, which is not the behavior
    # under test here.
    for _ in range(N_PEERS):
        for peer in peers:
            for other in peers:
                if peer is not other:
                    peer.merge(other)
                await asyncio.sleep(0)

    cid_sets = [peer.all_cids() for peer in peers]
    assert all(cid_set == cid_sets[0] for cid_set in cid_sets)
    assert cid_sets[0] == frozenset(expected_union)

    ordered_payloads = [
        [node.payload for node in peer.topological_order()]
        for peer in peers
    ]
    assert ordered_payloads[0] == ordered_payloads[1] == ordered_payloads[2]
    assert peers[0].summary()["total_nodes"] == len(expected_union)
    assert len(expected_union) >= 50
