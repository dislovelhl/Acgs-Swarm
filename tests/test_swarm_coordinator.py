"""Tests for SwarmCoordinator — in-memory variant only (no Docker/WebSocket)."""

from __future__ import annotations

import pytest

from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch
from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────


def _make_tasks(n: int = 5) -> list[dict]:
    return [
        {
            "instance_id": f"repo-{i}",
            "problem_statement": f"Bug {i}",
            "patch": "--- a/f.py\n+++ b/f.py",
            "FAIL_TO_PASS": [],
        }
        for i in range(n)
    ]


class _SuccessAgent(SWEBenchAgent):
    """Agent that always returns a non-empty patch."""

    def _generate_patch(self, task: dict) -> tuple[str, dict]:
        return "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n", {
            "intervention_rate": 0.0,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Constructor
# ──────────────────────────────────────────────────────────────────────────────


def test_coordinator_rejects_empty_agents() -> None:
    with pytest.raises(ValueError, match="at least one agent"):
        SwarmCoordinator([])


def test_coordinator_accepts_single_agent() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    assert len(coord.agents) == 1


# ──────────────────────────────────────────────────────────────────────────────
# run_in_memory — basic
# ──────────────────────────────────────────────────────────────────────────────


def test_run_in_memory_returns_expected_keys() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(3))
    assert set(result.keys()) >= {
        "patches", "total", "resolved", "resolve_rate",
        "crdt_size", "governed_count", "mean_intervention",
    }


def test_run_in_memory_total_matches_tasks() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(5))
    assert result["total"] == 5


def test_run_in_memory_crdt_size_equals_total() -> None:
    """Each solved task appends one node to the CRDT."""
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(4))
    assert result["crdt_size"] == 4


def test_run_in_memory_max_tasks_truncates() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(10), max_tasks=3)
    assert result["total"] == 3
    assert result["crdt_size"] == 3


def test_run_in_memory_empty_tasks() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory([])
    assert result["total"] == 0
    assert result["crdt_size"] == 0
    assert result["resolve_rate"] == pytest.approx(0.0)


# ──────────────────────────────────────────────────────────────────────────────
# run_in_memory — resolve rate
# ──────────────────────────────────────────────────────────────────────────────


def test_run_in_memory_resolve_rate_with_success_agent() -> None:
    coord = SwarmCoordinator([_SuccessAgent()])
    result = coord.run_in_memory(_make_tasks(4))
    assert result["resolved"] == 4
    assert result["resolve_rate"] == pytest.approx(1.0)


def test_run_in_memory_resolve_rate_with_stub_agent() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(4))
    assert result["resolved"] == 0
    assert result["resolve_rate"] == pytest.approx(0.0)


# ──────────────────────────────────────────────────────────────────────────────
# run_in_memory — multi-agent round-robin
# ──────────────────────────────────────────────────────────────────────────────


def test_run_in_memory_round_robin_distribution() -> None:
    """Tasks are distributed round-robin across agents."""
    calls: list[int] = []

    class _TrackingAgent(SWEBenchAgent):
        def __init__(self, agent_id: int) -> None:
            super().__init__()
            self.agent_id = agent_id

        def _generate_patch(self, task: dict) -> tuple[str, dict]:
            calls.append(self.agent_id)
            return "", {}

    agents = [_TrackingAgent(i) for i in range(3)]
    coord = SwarmCoordinator(agents)
    coord.run_in_memory(_make_tasks(6))

    # Each of 3 agents should be called exactly twice
    assert calls.count(0) == 2
    assert calls.count(1) == 2
    assert calls.count(2) == 2


def test_run_in_memory_single_agent_handles_all_tasks() -> None:
    coord = SwarmCoordinator([_SuccessAgent()])
    result = coord.run_in_memory(_make_tasks(7))
    assert result["total"] == 7
    assert result["crdt_size"] == 7


# ──────────────────────────────────────────────────────────────────────────────
# run_in_memory — patches list
# ──────────────────────────────────────────────────────────────────────────────


def test_run_in_memory_patches_are_swe_patch() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(3))
    assert all(isinstance(p, SWEPatch) for p in result["patches"])


def test_run_in_memory_task_ids_preserved() -> None:
    coord = SwarmCoordinator([SWEBenchAgent()])
    result = coord.run_in_memory(_make_tasks(3))
    ids = [p.task_id for p in result["patches"]]
    assert ids == ["repo-0", "repo-1", "repo-2"]


# ──────────────────────────────────────────────────────────────────────────────
# run_gossip — requires websockets; skip otherwise
# ──────────────────────────────────────────────────────────────────────────────


websockets = pytest.importorskip(
    "websockets", reason="websockets not installed — skip gossip coordinator test"
)


@pytest.mark.asyncio
async def test_run_gossip_basic() -> None:
    """Smoke test: gossip coordinator converges 3 nodes over 2 tasks."""
    coord = SwarmCoordinator(
        [_SuccessAgent(), _SuccessAgent(), _SuccessAgent()],
        n_gossip_rounds=3,
        gossip_peers=2,
    )
    result = await coord.run_gossip(_make_tasks(2))
    assert result["total"] == 2
    # CRDT must have replicated all nodes across gossip rounds
    assert result["crdt_size"] >= 2


@pytest.mark.asyncio
async def test_run_gossip_resolve_rate() -> None:
    coord = SwarmCoordinator(
        [_SuccessAgent(), _SuccessAgent()],
        n_gossip_rounds=2,
    )
    result = await coord.run_gossip(_make_tasks(4))
    assert result["resolve_rate"] == pytest.approx(1.0)
