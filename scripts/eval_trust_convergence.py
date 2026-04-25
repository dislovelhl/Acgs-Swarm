"""Autoresearch evaluator: trust-convergence fitness for constitutional-mesh.

Reads the current source tree (no pip install needed — runs from repo root),
drives a deterministic synthetic trust-signal workload through
``SpectralSphereManifold``, and emits a single-line JSON score on stdout.

Exit code is 0 on success. Any non-zero exit signals the candidate mutation
broke the module and should be culled by autoresearch.

Score shape
-----------
Higher is better. The composite score rewards:
  * fast convergence (fewer rounds until trust-matrix L2 delta < ``--tol``)
  * low steady-state variance (converges tight, not fuzzy)
  * stability flag set (``is_stable == True``) at termination

Usage
-----
    python scripts/eval_trust_convergence.py --seed 42 --agents 8 --steps 200

Autoresearch invocation
-----------------------
    omc autoresearch \
        --mission "improve constitutional-mesh trust convergence on SWE-bench" \
        --eval "python scripts/eval_trust_convergence.py --seed 42 --agents 8 --steps 200"
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path

# Allow running from repo root without editable install.
_REPO_SRC = Path(__file__).resolve().parent.parent / "src"
if _REPO_SRC.exists() and str(_REPO_SRC) not in sys.path:
    sys.path.insert(0, str(_REPO_SRC))

from constitutional_swarm.spectral_sphere import SpectralSphereManifold


def _l2_delta(
    a: tuple[tuple[float, ...], ...],
    b: tuple[tuple[float, ...], ...],
) -> float:
    return math.sqrt(sum((a[i][j] - b[i][j]) ** 2 for i in range(len(a)) for j in range(len(a))))


def _variance(matrix: tuple[tuple[float, ...], ...]) -> float:
    values = [v for row in matrix for v in row]
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def run(seed: int, agents: int, steps: int, tol: float) -> dict:
    rng = random.Random(seed)  # noqa: S311
    manifold = SpectralSphereManifold(num_agents=agents)

    prev: tuple[tuple[float, ...], ...] | None = None
    convergence_rounds = steps
    for step in range(steps):
        # Synthetic signal: reproducible ground-truth trustworthy subset
        # (first half of agents) emits small positive deltas,
        # adversarial half emits negative deltas.
        i = rng.randrange(agents)
        j = rng.randrange(agents)
        if i == j:
            continue
        honest = j < agents // 2
        delta = rng.uniform(0.01, 0.05) * (1.0 if honest else -1.0)
        manifold.update_trust(i, j, delta)
        manifold.project()
        cur = manifold.trust_matrix
        if prev is not None and _l2_delta(prev, cur) < tol:
            convergence_rounds = step + 1
            break
        prev = cur

    final = manifold.trust_matrix
    variance = _variance(final)
    stable = bool(manifold.is_stable)
    spectral = float(manifold.spectral_norm)

    # Composite score (higher is better):
    #   * reward fast convergence:  (steps - rounds) / steps   in [0, 1)
    #   * penalize variance:        1 / (1 + variance)         in (0, 1]
    #   * stability bonus:          +0.2 if stable
    fast = max(0.0, (steps - convergence_rounds) / steps)
    tight = 1.0 / (1.0 + variance)
    score = 0.5 * fast + 0.4 * tight + (0.2 if stable else 0.0)

    return {
        "score": score,
        "convergence_rounds": convergence_rounds,
        "variance": variance,
        "spectral_norm": spectral,
        "is_stable": stable,
        "params": {"seed": seed, "agents": agents, "steps": steps, "tol": tol},
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--seeds",
        type=str,
        default="42,7,13",
        help="Comma-separated seeds; score is the mean across seeds (guards against single-seed overfit).",
    )
    p.add_argument("--seed", type=int, default=None, help="Deprecated; use --seeds.")
    p.add_argument("--agents", type=int, default=8)
    p.add_argument("--steps", type=int, default=200)
    p.add_argument("--tol", type=float, default=1e-4)
    args = p.parse_args()

    seeds = (
        [args.seed]
        if args.seed is not None
        else [int(s) for s in args.seeds.split(",") if s.strip()]
    )
    runs = [run(s, args.agents, args.steps, args.tol) for s in seeds]
    mean_score = sum(r["score"] for r in runs) / len(runs)
    all_stable = all(r["is_stable"] for r in runs)
    print(
        json.dumps(
            {
                "pass": bool(all_stable),
                "score": mean_score,
                "per_seed": runs,
                "seeds": seeds,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
