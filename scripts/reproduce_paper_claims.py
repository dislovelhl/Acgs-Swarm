#!/usr/bin/env python3
"""Local reproducibility harness for ICLR/NDSS paper claims.

The harness intentionally stays local and deterministic: it exercises source
modules and lightweight synthetic evaluators, then emits one JSON object with
claim-oriented metrics.  It does not run official SWE-bench or networked gossip.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

DELTA = 1e-5
RADIUS = 1.0


def _parse_ints(raw: str) -> list[int]:
    values = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("expected at least one integer")
    return values


def _parse_floats(raw: str) -> list[float]:
    values = [float(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("expected at least one float")
    return values


def _matrix_variance(matrix: tuple[tuple[float, ...], ...]) -> float:
    flat = [value for row in matrix for value in row]
    mean = sum(flat) / len(flat)
    return sum((value - mean) ** 2 for value in flat) / len(flat)


def _load_ode_modules() -> dict[str, Any] | None:
    try:
        import torch
        from constitutional_swarm.swarm_ode import (
            TrustDecayField,
            _spectral_norm_torch,
            calibrate_sigma,
            integrate,
            spectral_project_torch,
        )
    except ImportError:  # pragma: no cover - exercised only on minimal installs.
        return None

    return {
        "TrustDecayField": TrustDecayField,
        "_spectral_norm_torch": _spectral_norm_torch,
        "calibrate_sigma": calibrate_sigma,
        "integrate": integrate,
        "spectral_project_torch": spectral_project_torch,
        "torch": torch,
    }


def _make_governance(n: int, seed: int) -> Any:
    from constitutional_swarm.manifold import GovernanceManifold

    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark seed
    manifold = GovernanceManifold(num_agents=n)
    for i in range(n):
        for j in range(n):
            if i != j:
                manifold.update_trust(i, j, rng.uniform(0.0, 1.0))
    return manifold


def _make_spectral(n: int, seed: int, *, r: float = RADIUS) -> Any:
    from constitutional_swarm.spectral_sphere import SpectralSphereManifold

    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark seed
    manifold = SpectralSphereManifold(num_agents=n, r=r)
    for i in range(n):
        for j in range(n):
            if i != j:
                manifold.update_trust(i, j, rng.uniform(0.0, 1.0))
    return manifold


def _retention_series(
    *,
    kind: str,
    n: int,
    seed: int,
    cycles: list[int],
    residual_alpha: float,
    r: float = RADIUS,
) -> dict[str, float]:
    if kind == "birkhoff":
        base = _make_governance(n, seed)
        current = base
        initial_variance = _matrix_variance(base.trust_matrix)
    elif kind == "spectral":
        base = _make_spectral(n, seed, r=r)
        current = base
        initial_variance = _matrix_variance(base.trust_matrix)
    else:
        raise ValueError(f"unknown manifold kind: {kind}")

    checkpoints = set(cycles)
    results: dict[str, float] = {}
    for cycle in range(1, max(cycles) + 1):
        if kind == "birkhoff":
            current = current.compose(base)
        else:
            current = current.compose(base, residual_alpha=residual_alpha)
        if cycle in checkpoints:
            retention = _matrix_variance(current.trust_matrix) / initial_variance
            results[str(cycle)] = retention
    return results


def trust_variance_benchmark(
    *, seeds: list[int], sizes: list[int], cycles: list[int]
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for n in sizes:
        for kind, residual_alpha in (
            ("birkhoff", 0.0),
            ("spectral", 0.0),
            ("spectral_residual", 0.1),
        ):
            per_seed = [
                _retention_series(
                    kind="spectral" if kind == "spectral_residual" else kind,
                    n=n,
                    seed=seed,
                    cycles=cycles,
                    residual_alpha=residual_alpha,
                )
                for seed in seeds
            ]
            mean_by_cycle = {
                str(cycle): statistics.fmean(row[str(cycle)] for row in per_seed)
                for cycle in cycles
            }
            rows.append(
                {
                    "n": n,
                    "manifold": kind,
                    "residual_alpha": residual_alpha,
                    "mean_retention": mean_by_cycle,
                    "per_seed": per_seed,
                }
            )

    return {
        "pass": all(
            row["mean_retention"][str(min(cycles))] > 0.0
            for row in rows
            if row["manifold"] != "birkhoff"
        )
        and all(
            row["mean_retention"][str(min(cycles))] < 0.01
            for row in rows
            if row["manifold"] == "birkhoff"
        ),
        "seeds": seeds,
        "sizes": sizes,
        "cycles": cycles,
        "rows": rows,
    }


def ablation_benchmark(
    *,
    seeds: list[int],
    n: int,
    cycles: int,
    radii: list[float],
    residual_alphas: list[float],
) -> dict[str, Any]:
    rows = []
    for radius in radii:
        for alpha in residual_alphas:
            retentions = [
                _retention_series(
                    kind="spectral",
                    n=n,
                    seed=seed,
                    cycles=[cycles],
                    residual_alpha=alpha,
                    r=radius,
                )[str(cycles)]
                for seed in seeds
            ]
            rows.append(
                {
                    "n": n,
                    "cycles": cycles,
                    "radius": radius,
                    "residual_alpha": alpha,
                    "mean_retention": statistics.fmean(retentions),
                    "per_seed": retentions,
                }
            )

    residual_rows = [row for row in rows if row["residual_alpha"] > 0.0]
    return {
        "pass": bool(residual_rows and all(row["mean_retention"] > 0.0 for row in residual_rows)),
        "rows": rows,
    }


def ode_stability_benchmark(*, n: int, steps: int, seed: int) -> dict[str, Any]:
    ode_modules = _load_ode_modules()
    if ode_modules is None:
        return {"available": False, "pass": False, "reason": "torch unavailable"}

    torch = ode_modules["torch"]
    trust_decay_field = ode_modules["TrustDecayField"]
    integrate_fn = ode_modules["integrate"]
    spectral_project = ode_modules["spectral_project_torch"]
    spectral_norm = ode_modules["_spectral_norm_torch"]

    torch.manual_seed(seed)
    h0 = spectral_project(torch.rand(n, n), r=RADIUS)
    initial_variance = ((h0 - h0.mean()) ** 2).mean().item()
    field = trust_decay_field(n, decay=0.05, seed=seed)
    result = integrate_fn(
        field,
        h0,
        t_span=(0.0, 10.0),
        n_steps=steps,
        r=RADIUS,
        residual_alpha=0.1,
        record_every=max(1, steps // 10),
    )
    h_final = result["H_final"]
    final_variance = ((h_final - h_final.mean()) ** 2).mean().item()
    max_sigma = max(spectral_norm(h) for _t, h, _var in result["trajectory"])
    retention = final_variance / initial_variance if initial_variance else 0.0
    return {
        "available": True,
        "pass": bool(retention > 0.0 and max_sigma <= RADIUS + 0.03),
        "n": n,
        "steps": steps,
        "seed": seed,
        "initial_variance": initial_variance,
        "final_variance": final_variance,
        "retention": retention,
        "max_spectral_norm": max_sigma,
    }


def dp_calibration_table() -> dict[str, Any]:
    ode_modules = _load_ode_modules()
    if ode_modules is None:
        return {"available": False, "pass": False, "reason": "torch unavailable"}

    calibrate_sigma = ode_modules["calibrate_sigma"]
    rows = []
    for epsilon in (1.0, 2.0, 4.0, 8.0):
        baseline = 2.0 * RADIUS * math.sqrt(2.0 * math.log(1.25 / DELTA)) / epsilon
        residual = calibrate_sigma(RADIUS, 0.1, epsilon, DELTA)
        rows.append(
            {
                "epsilon": epsilon,
                "baseline_sigma": baseline,
                "alpha_0_1_sigma": residual,
                "reduction": 1.0 - residual / baseline,
            }
        )
    return {
        "available": True,
        "pass": all(abs(row["reduction"] - 0.1) < 1e-12 for row in rows),
        "rows": rows,
    }


async def crdt_gossip_benchmark(
    *, agents: int, rounds: int, artifacts_per_round: int, gossip_partners: int
) -> dict[str, Any]:
    from constitutional_swarm.merkle_crdt import simulate_gossip_convergence

    result = await simulate_gossip_convergence(
        n_agents=agents,
        n_rounds=rounds,
        artifacts_per_round=artifacts_per_round,
        gossip_partners=gossip_partners,
    )
    expected_total = agents * rounds * artifacts_per_round
    result["pass"] = bool(result["converged"] and result["unique_cids"] == expected_total)
    return result


def byzantine_rejection_benchmark() -> dict[str, Any]:
    from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT

    honest = MerkleCRDT("honest")
    byzantine = MerkleCRDT("byzantine", reject_unverified=False)
    for idx in range(8):
        honest.append(payload=f"honest-{idx}", bodes_passed=True)
        node = byzantine.append(payload=f"tamper-target-{idx}")
        byzantine._nodes[node.cid] = DAGNode(
            cid=node.cid,
            agent_id="byzantine",
            payload=f"TAMPERED-{idx}",
        )

    added = honest.merge(byzantine)
    tampered_payloads = [
        node.payload for node in honest.topological_order() if "TAMPERED" in node.payload
    ]
    return {
        "pass": bool(added == 0 and not tampered_payloads),
        "tampered_attempts": 8,
        "accepted_tampered": len(tampered_payloads),
        "merge_added": added,
    }


def _load_synthetic_swe_module() -> Any:
    script_path = REPO_ROOT / "scripts" / "eval_swe_bench_synthetic.py"
    spec = importlib.util.spec_from_file_location("eval_swe_bench_synthetic", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_swe_bench_benchmark(
    *, seeds: list[int], agents: int, tasks: int, warmup: int
) -> dict[str, Any]:
    module = _load_synthetic_swe_module()
    runs = [module.run(seed, agents, tasks, warmup) for seed in seeds]
    mean_lift = statistics.fmean(run["lift"] for run in runs)
    return {
        "pass": bool(all(run["lift"] >= -1e-9 for run in runs)),
        "official_swe_bench_claimed": False,
        "reason": "local synthetic SWE-bench-shaped evaluator only",
        "mean_lift": mean_lift,
        "per_seed": runs,
    }


def latency_microbenchmarks(*, iterations: int, n: int, seed: int) -> dict[str, Any]:
    from constitutional_swarm.merkle_crdt import MerkleCRDT
    from constitutional_swarm.spectral_sphere import spectral_sphere_project

    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark seed
    matrix = [[rng.uniform(-1.0, 1.0) for _ in range(n)] for _ in range(n)]

    def measure(operation: Any) -> float:
        start = time.perf_counter_ns()
        for _ in range(iterations):
            operation()
        return (time.perf_counter_ns() - start) / iterations

    spectral_ns = measure(lambda: spectral_sphere_project(matrix, r=RADIUS))
    residual_ns = measure(
        lambda: [
            [0.9 * matrix[i][j] + (0.1 if i == j else 0.0) for j in range(n)] for i in range(n)
        ]
    )
    cid_ns = measure(
        lambda: MerkleCRDT("bench").append(
            payload="payload",
            bodes_passed=True,
            constitutional_hash="608508a9bd224290",
        )
    )
    return {
        "pass": bool(spectral_ns > 0 and residual_ns > 0 and cid_ns > 0),
        "iterations": iterations,
        "n": n,
        "ns_per_operation": {
            "spectral_projection": spectral_ns,
            "residual_injection": residual_ns,
            "cid_append": cid_ns,
        },
    }


def run_reproducibility_suite(args: argparse.Namespace) -> dict[str, Any]:
    seeds = args.seeds
    suite = {
        "trust_variance": trust_variance_benchmark(
            seeds=seeds,
            sizes=args.sizes,
            cycles=args.cycles,
        ),
        "ablation": ablation_benchmark(
            seeds=seeds,
            n=args.ablation_n,
            cycles=args.ablation_cycles,
            radii=args.ablation_radii,
            residual_alphas=args.ablation_alphas,
        ),
        "ode_stability": ode_stability_benchmark(
            n=args.ode_n,
            steps=args.ode_steps,
            seed=seeds[0],
        ),
        "dp_calibration": dp_calibration_table(),
        "crdt_gossip": asyncio.run(
            crdt_gossip_benchmark(
                agents=args.gossip_agents,
                rounds=args.gossip_rounds,
                artifacts_per_round=args.gossip_artifacts,
                gossip_partners=args.gossip_partners,
            )
        ),
        "byzantine_rejection": byzantine_rejection_benchmark(),
        "synthetic_swe_bench": synthetic_swe_bench_benchmark(
            seeds=seeds,
            agents=args.swe_agents,
            tasks=args.swe_tasks,
            warmup=args.swe_warmup,
        ),
        "latency_microbenchmarks": latency_microbenchmarks(
            iterations=args.microbench_iterations,
            n=args.microbench_n,
            seed=seeds[0],
        ),
    }
    suite["pass"] = all(section.get("pass") for section in suite.values())
    return suite


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit JSON metrics for local paper-claim reproducibility checks."
    )
    parser.add_argument("--seeds", type=_parse_ints, default=[42])
    parser.add_argument("--sizes", type=_parse_ints, default=[10, 50])
    parser.add_argument("--cycles", type=_parse_ints, default=[10, 50])
    parser.add_argument("--ablation-n", type=int, default=10)
    parser.add_argument("--ablation-cycles", type=int, default=10)
    parser.add_argument("--ablation-radii", type=_parse_floats, default=[0.5, 1.0, 1.5])
    parser.add_argument("--ablation-alphas", type=_parse_floats, default=[0.0, 0.1, 0.2])
    parser.add_argument("--ode-n", type=int, default=10)
    parser.add_argument("--ode-steps", type=int, default=200)
    parser.add_argument("--gossip-agents", type=int, default=20)
    parser.add_argument("--gossip-rounds", type=int, default=20)
    parser.add_argument("--gossip-artifacts", type=int, default=3)
    parser.add_argument("--gossip-partners", type=int, default=3)
    parser.add_argument("--swe-agents", type=int, default=4)
    parser.add_argument("--swe-tasks", type=int, default=64)
    parser.add_argument("--swe-warmup", type=int, default=8)
    parser.add_argument("--microbench-iterations", type=int, default=5)
    parser.add_argument("--microbench-n", type=int, default=50)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    payload = run_reproducibility_suite(args)
    encoded = json.dumps(payload, sort_keys=True)
    if args.output is not None:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if payload["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
