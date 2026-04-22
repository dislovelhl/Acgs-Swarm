"""SwarmCoordinator — multi-agent SWE-bench task distribution via MerkleCRDT.

Each agent node solves its assigned task and appends its :class:`SWEPatch`
to a :class:`~constitutional_swarm.merkle_crdt.MerkleCRDT`.  The CRDT is
replicated across all nodes via the :class:`~constitutional_swarm.gossip_protocol.SwarmNode`
WebSocket gossip layer — once all nodes converge, the coordinator harvests
the final set of patches.

Architecture overview::

    SwarmCoordinator
    ├── N SwarmNode   (WebSocket gossip, CRDT replication)
    │   └── SWEBenchAgent   (patch generation)
    └── convergence poll → harvest patches from CRDT DAG

This module provides a scaffold; the integration with live WebSocket nodes
is async and requires the ``websockets`` extra (``pip install constitutional-swarm[transport]``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from typing import Any

from constitutional_swarm.merkle_crdt import MerkleCRDT
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch

log = logging.getLogger(__name__)


class SwarmCoordinator:
    """Coordinate multiple SWEBenchAgent instances via MerkleCRDT gossip.

    Parameters
    ----------
    agents:
        One agent per swarm node.  The coordinator assigns tasks round-robin.
    n_gossip_rounds:
        Gossip rounds to run after all agents finish solving. Default 5.
    gossip_peers:
        Number of random peers each node gossips with per round. Default 2.
    """

    def __init__(
        self,
        agents: list[SWEBenchAgent],
        *,
        n_gossip_rounds: int = 5,
        gossip_peers: int = 2,
    ) -> None:
        if not agents:
            raise ValueError("SwarmCoordinator requires at least one agent.")
        self.agents = agents
        self.n_gossip_rounds = n_gossip_rounds
        self.gossip_peers = gossip_peers

    # ──────────────────────────────────────────────────────────────────────
    # In-memory (no WebSocket) variant — for testing
    # ──────────────────────────────────────────────────────────────────────

    def run_in_memory(
        self,
        tasks: list[dict[str, Any]],
        *,
        max_tasks: int | None = None,
        routing_weights: list[list[float]] | None = None,
    ) -> dict[str, Any]:
        """Run all agents in-process and merge results via a shared CRDT.

        This variant skips WebSocket transport — the CRDT is shared in memory.
        Useful for unit tests and single-machine benchmarks.

        Parameters
        ----------
        tasks:
            SWE-bench task list.
        max_tasks:
            Cap on tasks to assign.
        routing_weights:
            Optional ``n_agents × n_tasks`` matrix of non-negative weights.
            When provided, task ``j`` is assigned to the agent with the highest
            ``routing_weights[i][j]`` (ties broken by lower index). This is how
            a trust matrix / competency estimate from the swarm mesh is wired
            into task distribution. ``None`` preserves the round-robin default.

        Returns
        -------
        dict with keys: ``patches``, ``total``, ``resolved``, ``resolve_rate``,
        ``crdt_size``, ``governed_count``, ``mean_intervention``.
        """
        subset = tasks if max_tasks is None else tasks[:max_tasks]
        n_agents = len(self.agents)

        if routing_weights is not None:
            if len(routing_weights) != n_agents or any(
                len(row) != len(subset) for row in routing_weights
            ):
                raise ValueError(
                    f"routing_weights must be {n_agents}×{len(subset)}, "
                    f"got {len(routing_weights)}×"
                    f"{len(routing_weights[0]) if routing_weights else 0}"
                )
            assignments: list[tuple[SWEBenchAgent, dict[str, Any]]] = []
            for j, task in enumerate(subset):
                # argmax over agents for task j (ties -> lower index)
                best_i = 0
                best_w = routing_weights[0][j]
                for i in range(1, n_agents):
                    if routing_weights[i][j] > best_w:
                        best_w = routing_weights[i][j]
                        best_i = i
                assignments.append((self.agents[best_i], task))
        else:
            # Round-robin default
            assignments = [(self.agents[i % n_agents], task) for i, task in enumerate(subset)]

        # Shared CRDT — all agents write to it
        shared_crdt = MerkleCRDT("coordinator")

        patches: list[SWEPatch] = []
        for agent, task in assignments:
            result = agent.solve(task)
            patches.append(result)
            # Serialize patch result into CRDT as a DAG node
            payload = json.dumps(asdict(result))
            shared_crdt.append(payload=payload, bodes_passed=result.governed)

        return self._aggregate(patches, shared_crdt)

    # ──────────────────────────────────────────────────────────────────────
    # WebSocket gossip variant (requires websockets extra)
    # ──────────────────────────────────────────────────────────────────────

    async def run_gossip(
        self,
        tasks: list[dict[str, Any]],
        *,
        max_tasks: int | None = None,
    ) -> dict[str, Any]:
        """Run agents over WebSocket gossip transport.

        Each agent gets its own :class:`~constitutional_swarm.gossip_protocol.SwarmNode`.
        After all agents finish solving, ``n_gossip_rounds`` of gossip are run
        to fully replicate the CRDT across all nodes, then results are harvested
        from the converged DAG.

        Requires: ``pip install constitutional-swarm[transport]``
        """
        try:
            from constitutional_swarm.gossip_protocol import spin_up_swarm
        except ImportError as exc:
            raise ImportError(
                "WebSocket gossip requires: pip install constitutional-swarm[transport]"
            ) from exc

        subset = tasks if max_tasks is None else tasks[:max_tasks]
        n_nodes = len(self.agents)

        nodes = await spin_up_swarm(n_nodes)
        patches: list[SWEPatch] = []

        try:
            # Solve in parallel
            assignments = [(self.agents[i % n_nodes], task) for i, task in enumerate(subset)]
            solve_tasks = [
                asyncio.get_event_loop().run_in_executor(None, agent.solve, task)
                for agent, task in assignments
            ]
            results = await asyncio.gather(*solve_tasks)

            for i, result in enumerate(results):
                patches.append(result)
                payload = json.dumps(asdict(result))
                nodes[i % n_nodes].crdt.append(payload=payload, bodes_passed=result.governed)

            # Gossip rounds to converge
            for _ in range(self.n_gossip_rounds):
                await asyncio.gather(*[n.gossip_round(n_peers=self.gossip_peers) for n in nodes])
                await asyncio.sleep(0.05)

            # Harvest from first converged node
            crdt = nodes[0].crdt
        finally:
            await asyncio.gather(*[n.stop() for n in nodes])

        return self._aggregate(patches, crdt)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(patches: list[SWEPatch], crdt: MerkleCRDT) -> dict[str, Any]:
        total = len(patches)
        resolved = sum(1 for p in patches if p.success)
        governed = [p for p in patches if p.governed]
        mean_intervention = (
            sum(p.intervention_rate for p in governed) / len(governed) if governed else 0.0
        )
        return {
            "patches": patches,
            "total": total,
            "resolved": resolved,
            "resolve_rate": resolved / total if total > 0 else 0.0,
            "crdt_size": crdt.size,
            "governed_count": len(governed),
            "mean_intervention": mean_intervention,
        }
