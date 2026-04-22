"""Synthetic downstream evaluator for the constitutional swarm on SWE-bench-shaped tasks.

Why synthetic?
--------------
The real SWE-bench Lite harness requires Docker, a patched model, and ~tens of
GB of images — out of scope for in-process autoresearch. This evaluator is a
faithful stand-in that exercises the *plumbing* we actually want to optimize:

  - agents have hidden, domain-specific competencies (π_a(d) → success probability)
  - tasks carry a synthetic ``domain`` tag derived from instance_id
  - the swarm learns a per-(agent,domain) trust estimate via ``ConstitutionalMesh``
    and projects it onto the ``SpectralSphereManifold``
  - the projected trust matrix drives task routing via
    ``SwarmCoordinator.run_in_memory(routing_weights=...)``

The evaluator reports the ``swarm_resolve_rate`` against a ``round_robin``
baseline, plus the *improvement lift* as the headline fitness. This means a
mutation that improves trust-matrix dynamics (e.g. the EMA smoothing added in
commits 56f1b9f / 64a87d1) will produce a measurable downstream signal — the
plumbing gap documented in .omc/specs/deep-interview-autoresearch-trust-convergence.md
is closed.

Fitness = mean lift over seeds. Pass = lift >= 0 on every seed (no regression).
"""

# ruff: noqa: S311
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from constitutional_swarm.spectral_sphere import SpectralSphereManifold
from constitutional_swarm.swe_bench.agent import SWEBenchAgent
from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator

_DOMAINS = ("django", "numpy", "sympy", "flask")


def _domain_of(instance_id: str) -> str:
    return instance_id.split("-", 1)[0]


class _CompetencyAgent(SWEBenchAgent):
    """Agent with hidden per-domain success probabilities.

    ``competency[d]`` is the probability of solving a task from domain ``d``.
    Success is drawn deterministically from ``rng``.
    """

    def __init__(self, agent_id: int, competency: dict[str, float], rng: random.Random) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.competency = competency
        self._rng = rng

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        d = _domain_of(task.get("instance_id", ""))
        p = self.competency.get(d, 0.0)
        if self._rng.random() < p:
            return "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n", {"intervention_rate": 0.0}
        return "", {"intervention_rate": 0.0}


def _make_tasks(n: int, rng: random.Random) -> list[dict[str, Any]]:
    tasks = []
    for i in range(n):
        d = _DOMAINS[rng.randrange(len(_DOMAINS))]
        tasks.append(
            {
                "instance_id": f"{d}-{i}",
                "problem_statement": f"Task {i} in {d}",
                "patch": "",
                "FAIL_TO_PASS": [],
            }
        )
    return tasks


def _make_agents(n_agents: int, rng: random.Random) -> list[_CompetencyAgent]:
    """Each agent is a specialist: high competency in one domain, low elsewhere."""
    agents = []
    for i in range(n_agents):
        primary = _DOMAINS[i % len(_DOMAINS)]
        competency = {d: 0.15 for d in _DOMAINS}
        competency[primary] = 0.90
        agents.append(_CompetencyAgent(i, competency, rng))
    return agents


def _warmup_trust(
    agents: list[_CompetencyAgent],
    manifold: SpectralSphereManifold,
    warmup_rng: random.Random,
    *,
    warmup_tasks_per_agent: int = 8,
) -> None:
    """Populate the manifold with observed (agent, task) success signal.

    Each agent solves a handful of tasks from each domain; per-domain success
    rates are accumulated into the raw trust matrix (agent i vs ``task_domain``
    pseudo-agent j := domain index). We then project onto the spectral sphere.
    """
    for i, agent in enumerate(agents):
        for d_idx, domain in enumerate(_DOMAINS):
            if d_idx >= manifold.num_agents or i >= manifold.num_agents:
                continue
            successes = 0
            for _ in range(warmup_tasks_per_agent):
                task = {
                    "instance_id": f"{domain}-warm",
                    "problem_statement": "",
                    "patch": "",
                    "FAIL_TO_PASS": [],
                }
                result = agent._generate_patch(task)
                if result[0].strip():
                    successes += 1
            rate = successes / warmup_tasks_per_agent
            manifold.update_trust(i, d_idx, rate)
    _ = manifold.project()


def _trust_to_routing_weights(
    manifold: SpectralSphereManifold,
    tasks: list[dict[str, Any]],
    n_agents: int,
) -> list[list[float]]:
    """Project the trust matrix onto an n_agents × n_tasks routing matrix.

    weight[i][j] = projected_trust[i][domain_index(task_j)].
    """
    projection = manifold.project()
    # Tuple-of-tuples; index it directly.
    matrix = projection.matrix
    weights: list[list[float]] = []
    for i in range(n_agents):
        row = []
        for task in tasks:
            d_idx = _DOMAINS.index(_domain_of(task["instance_id"]))
            if d_idx < manifold.num_agents and i < manifold.num_agents:
                row.append(matrix[i][d_idx])
            else:
                row.append(0.0)
        weights.append(row)
    return weights


def run(seed: int, n_agents: int, n_tasks: int, warmup: int) -> dict[str, Any]:
    rng_tasks = random.Random(seed)
    rng_agents = random.Random(seed + 1000)

    # Two parallel agent populations so round-robin and swarm evaluations are
    # drawn from the same underlying distribution but independent RNG streams.
    agents_swarm = _make_agents(n_agents, random.Random(seed + 2000))
    agents_rr = _make_agents(n_agents, random.Random(seed + 3000))

    tasks = _make_tasks(n_tasks, rng_tasks)

    # Manifold size must cover both agents and domains.
    manifold = SpectralSphereManifold(num_agents=max(n_agents, len(_DOMAINS)))
    _warmup_trust(agents_swarm, manifold, rng_agents, warmup_tasks_per_agent=warmup)
    weights = _trust_to_routing_weights(manifold, tasks, n_agents)

    coord_swarm = SwarmCoordinator(agents_swarm)
    coord_rr = SwarmCoordinator(agents_rr)

    swarm_result = coord_swarm.run_in_memory(tasks, routing_weights=weights)
    rr_result = coord_rr.run_in_memory(tasks)

    swarm_rate = swarm_result["resolve_rate"]
    rr_rate = rr_result["resolve_rate"]
    lift = swarm_rate - rr_rate
    return {
        "lift": lift,
        "swarm_resolve_rate": swarm_rate,
        "round_robin_resolve_rate": rr_rate,
        "spectral_norm": manifold.spectral_norm,
        "is_stable": manifold.is_stable,
        "params": {"seed": seed, "agents": n_agents, "tasks": n_tasks, "warmup": warmup},
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=str, default="42,7,13")
    p.add_argument("--agents", type=int, default=4)
    p.add_argument("--tasks", type=int, default=64)
    p.add_argument("--warmup", type=int, default=8)
    args = p.parse_args()

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    runs = [run(s, args.agents, args.tasks, args.warmup) for s in seeds]

    mean_lift = sum(r["lift"] for r in runs) / len(runs)
    all_non_negative = all(r["lift"] >= -1e-9 for r in runs)
    mean_swarm = sum(r["swarm_resolve_rate"] for r in runs) / len(runs)
    mean_rr = sum(r["round_robin_resolve_rate"] for r in runs) / len(runs)

    print(
        json.dumps(
            {
                "pass": bool(all_non_negative),
                "score": mean_lift,
                "mean_swarm_resolve_rate": mean_swarm,
                "mean_round_robin_resolve_rate": mean_rr,
                "per_seed": runs,
                "seeds": seeds,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
