"""Run a Codex/Claude SWE-bench Lite swarm with local validation.

This is the swarm-backed counterpart to ``run_swe_bench_lite.py``:

1. Load SWE-bench Lite instances from HuggingFace or a local JSONL file.
2. Instantiate N real LLM-backed ``SWEBenchAgent`` instances.
3. Route tasks through ``SwarmCoordinator`` using in-memory or WebSocket gossip mode.
4. Evaluate each generated patch with ``LocalSWEBenchHarness``.

The local harness is real: it checks out the target repo, applies the patch,
and runs the listed tests. It is not Docker-isolated unless ``--env-isolation``
is enabled.

Examples
--------
Codex swarm over the first 3 instances::

    python scripts/run_swe_bench_swarm_lite.py --limit 3 --agents 3

Offline JSONL smoke run with tighter timeouts::

    python scripts/run_swe_bench_swarm_lite.py --jsonl /tmp/lite.jsonl --limit 1 --agents 1

Gossip transport mode over 2 agents::

    python scripts/run_swe_bench_swarm_lite.py --limit 1 --agents 2 --mode gossip
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT / "scripts"))


def _make_agent(
    *,
    model: str | None,
    timeout_s: float,
    agent_cls: type[Any],
) -> Any:
    return agent_cls(model=model, timeout_s=timeout_s)


def _import_runtime(backend: str) -> dict[str, Any]:
    """Import package runtime after argparse owns CLI parsing.

    The repository's top-level package imports optional Bittensor surfaces with
    argparse side effects. Temporarily hiding this script's argv keeps
    ``--help`` and runner-specific flags owned by this script.
    """
    saved_argv = sys.argv[:]
    sys.argv = [saved_argv[0]]
    try:
        from constitutional_swarm.swe_bench.local_harness import (
            LocalSWEBenchHarness,
            load_instances,
        )
        from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator

        if backend == "claude":
            from constitutional_swarm.swe_bench.claude_agent import ClaudeSWEBenchAgent

            agent_cls = ClaudeSWEBenchAgent
        else:
            from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

            agent_cls = CodexSWEBenchAgent
    finally:
        sys.argv = saved_argv

    return {
        "LocalSWEBenchHarness": LocalSWEBenchHarness,
        "SwarmCoordinator": SwarmCoordinator,
        "agent_cls": agent_cls,
        "load_instances": load_instances,
    }


def _make_agents(
    *,
    model: str | None,
    timeout_s: float,
    count: int,
    agent_cls: type[Any],
) -> list[Any]:
    if count < 1:
        raise ValueError("--agents must be at least 1")
    return [
        _make_agent(
            model=model,
            timeout_s=timeout_s,
            agent_cls=agent_cls,
        )
        for _ in range(count)
    ]


def _run_swarm(
    *,
    coordinator: Any,
    instances: list[dict[str, Any]],
    mode: str,
) -> dict[str, Any]:
    if mode == "gossip":
        return asyncio.run(coordinator.run_gossip(instances))
    return coordinator.run_in_memory(instances)


def _evaluate_patch(
    *,
    harness: Any,
    instance: dict[str, Any],
    patch_result: Any,
    env_fallback_mode: str,
) -> dict[str, Any]:
    if not patch_result.success:
        return {
            "instance_id": instance.get("instance_id"),
            "repo": instance.get("repo"),
            "patch_generated": False,
            "applied": False,
            "resolved": False,
            "fail_to_pass_passed": 0,
            "fail_to_pass_failed": 0,
            "pass_to_pass_passed": 0,
            "pass_to_pass_failed": 0,
            "stage": "patch_generation",
            "error": patch_result.metadata.get("error", "no_patch"),
            "log_tail": "",
            "patch": patch_result.patch,
            "agent_duration_s": patch_result.duration_s,
            "harness_duration_s": 0.0,
            "duration_s": patch_result.duration_s,
            "patch_metadata": patch_result.metadata,
        }

    harness_result = harness.evaluate(instance, patch_result.patch)
    stage = harness_result.stage
    error = harness_result.error
    native_build_blocked = False
    failure_class = harness_result.metadata.get("env_failure_class")
    if (
        env_fallback_mode == "report-native-build-blocked"
        and harness_result.applied
        and not harness_result.resolved
        and failure_class == "native-build-incompatibility"
    ):
        stage = "env_native_build_blocked"
        error = "patch applied, env blocked by native build incompatibility"
        native_build_blocked = True
    return {
        "instance_id": harness_result.instance_id,
        "repo": instance.get("repo"),
        "patch_generated": True,
        "applied": harness_result.applied,
        "resolved": harness_result.resolved,
        "native_build_blocked": native_build_blocked,
        "fail_to_pass_passed": harness_result.fail_to_pass_passed,
        "fail_to_pass_failed": harness_result.fail_to_pass_failed,
        "pass_to_pass_passed": harness_result.pass_to_pass_passed,
        "pass_to_pass_failed": harness_result.pass_to_pass_failed,
        "stage": stage,
        "error": error,
        "log_tail": harness_result.log_tail,
        "patch": patch_result.patch,
        "agent_duration_s": patch_result.duration_s,
        "harness_duration_s": harness_result.duration_s,
        "duration_s": patch_result.duration_s + harness_result.duration_s,
        "patch_metadata": patch_result.metadata,
        "harness_metadata": harness_result.metadata,
    }


def _print_progress(index: int, total: int, row: dict[str, Any]) -> None:
    fail_total = row["fail_to_pass_passed"] + row["fail_to_pass_failed"]
    pass_total = row["pass_to_pass_passed"] + row["pass_to_pass_failed"]
    print(
        f"[{index}/{total}] {row['instance_id']} "
        f"stage={row['stage']} patch={row['patch_generated']} "
        f"applied={row['applied']} resolved={row['resolved']} "
        f"F2P={row['fail_to_pass_passed']}/{fail_total} "
        f"P2P={row['pass_to_pass_passed']}/{pass_total} "
        f"dur={row['duration_s']:.1f}s",
        flush=True,
    )


def _summarize_known_native_build_blockers(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    blocked: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not row.get("native_build_blocked"):
            continue
        repo = str(row.get("repo") or "unknown")
        info = blocked.setdefault(
            repo,
            {"count": 0, "instances": [], "failure_classes": set()},
        )
        info["count"] += 1
        instance_id = row.get("instance_id")
        if instance_id and instance_id not in info["instances"]:
            info["instances"].append(instance_id)
        failure_class = (row.get("harness_metadata") or {}).get("env_failure_class")
        if failure_class:
            info["failure_classes"].add(failure_class)
    return {
        repo: {
            "count": data["count"],
            "instances": data["instances"],
            "failure_classes": sorted(data["failure_classes"]),
        }
        for repo, data in blocked.items()
    }


def _write_predictions_output(
    rows: list[dict[str, Any]],
    output_path: Path,
    *,
    default_model_name: str | None,
) -> None:
    from convert_swarm_output_to_swebench_predictions import (
        convert_rows_to_predictions,
        write_predictions,
    )

    predictions = convert_rows_to_predictions(
        rows,
        default_model_name=default_model_name,
    )
    write_predictions(predictions, output_path, output_format="jsonl")


def _summarize(
    *,
    rows: list[dict[str, Any]],
    swarm_result: dict[str, Any],
    agents: int,
    mode: str,
    gossip_rounds: int,
    gossip_peers: int,
) -> dict[str, Any]:
    n = len(rows)
    patch_generated = sum(1 for r in rows if r["patch_generated"])
    applied = sum(1 for r in rows if r["applied"])
    resolved = sum(1 for r in rows if r["resolved"])
    native_build_blocked = sum(1 for r in rows if r.get("native_build_blocked"))
    known_native_build_blocked_by_repo = _summarize_known_native_build_blockers(rows)
    coordinator_patch_successes = int(swarm_result.get("resolved", 0))

    return {
        "instances": n,
        "swarm_agents": agents,
        "swarm_mode": mode,
        "gossip_rounds": gossip_rounds if mode == "gossip" else 0,
        "gossip_peers": gossip_peers if mode == "gossip" else 0,
        "patch_generated": patch_generated,
        "applied": applied,
        "resolved": resolved,
        "native_build_blocked": native_build_blocked,
        "known_native_build_blocked_by_repo": known_native_build_blocked_by_repo,
        "patch_rate": patch_generated / n if n else 0.0,
        "apply_rate": applied / n if n else 0.0,
        "resolve_rate": resolved / n if n else 0.0,
        "coordinator_crdt_size": swarm_result.get("crdt_size", 0),
        "coordinator_patch_successes": coordinator_patch_successes,
        "coordinator_patch_success_rate": coordinator_patch_successes / n if n else 0.0,
        "coordinator_governed_count": swarm_result.get("governed_count", 0),
        "coordinator_mean_intervention": swarm_result.get("mean_intervention", 0.0),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Local JSONL file; if omitted, loads princeton-nlp/SWE-bench_Lite[test].",
    )
    parser.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite")
    parser.add_argument("--split", default="test")
    parser.add_argument(
        "--backend",
        default="codex",
        choices=["codex", "claude"],
        help="Agent backend: 'codex' (Codex CLI / GPT) or 'claude' (Anthropic Messages API).",
    )
    parser.add_argument(
        "--agents",
        type=int,
        default=3,
        help="Number of LLM-backed agents to instantiate for the swarm.",
    )
    parser.add_argument(
        "--mode",
        default="in-memory",
        choices=["in-memory", "gossip"],
        help="Swarm execution mode: local in-memory routing or WebSocket gossip transport.",
    )
    parser.add_argument(
        "--gossip-rounds",
        type=int,
        default=5,
        help="Gossip rounds to run after solve completion when --mode gossip is selected.",
    )
    parser.add_argument(
        "--gossip-peers",
        type=int,
        default=2,
        help="Random peers contacted per gossip round when --mode gossip is selected.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model identifier for the chosen backend. "
            "codex default: Codex CLI default; claude default: claude-sonnet-4-5."
        ),
    )
    parser.add_argument("--agent-timeout", type=float, default=240.0)
    parser.add_argument("--harness-timeout", type=float, default=600.0)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--predictions-output",
        type=Path,
        default=None,
        help="Optional path to write official SWE-bench predictions JSONL converted from the swarm rows.",
    )
    parser.add_argument(
        "--env-isolation",
        action="store_true",
        help="Create a per-instance venv and pip-install the patched worktree before tests.",
    )
    parser.add_argument(
        "--env-timeout",
        type=float,
        default=900.0,
        help="Timeout for venv creation + pip install (seconds).",
    )
    parser.add_argument(
        "--python-version",
        default=None,
        help=(
            "Target Python X.Y for env isolation (uses `uv python install` "
            "+ `uv venv --python`). Per-instance `python_version` keys "
            "override this; auto-detected from pyproject.toml if unset."
        ),
    )
    parser.add_argument(
        "--env-fallback-mode",
        default="strict",
        choices=["strict", "report-native-build-blocked"],
        help="How to report env failures after a patch applies. 'report-native-build-blocked' rewrites native compile/toolchain failures into an explicit blocked stage.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    runtime = _import_runtime(args.backend)
    load_instances = runtime["load_instances"]
    LocalSWEBenchHarness = runtime["LocalSWEBenchHarness"]
    SwarmCoordinator = runtime["SwarmCoordinator"]
    agent_cls = runtime["agent_cls"]

    instances = load_instances(
        jsonl_path=args.jsonl,
        dataset=args.dataset,
        split=args.split,
        limit=args.limit,
    )

    agents = _make_agents(
        model=args.model,
        timeout_s=args.agent_timeout,
        count=args.agents,
        agent_cls=agent_cls,
    )
    coordinator = SwarmCoordinator(
        agents,
        n_gossip_rounds=args.gossip_rounds,
        gossip_peers=args.gossip_peers,
    )
    harness = LocalSWEBenchHarness(
        timeout_s=args.harness_timeout,
        env_isolation=args.env_isolation,
        env_timeout_s=args.env_timeout,
        python_version=args.python_version,
    )

    swarm_result = _run_swarm(
        coordinator=coordinator,
        instances=instances,
        mode=args.mode,
    )
    patch_results = list(swarm_result["patches"])

    rows: list[dict[str, Any]] = []
    for index, (instance, patch_result) in enumerate(
        zip(instances, patch_results, strict=True),
        start=1,
    ):
        row = _evaluate_patch(
            harness=harness,
            instance=instance,
            patch_result=patch_result,
            env_fallback_mode=args.env_fallback_mode,
        )
        rows.append(row)
        _print_progress(index, len(instances), row)

    summary = _summarize(
        rows=rows,
        swarm_result=swarm_result,
        agents=args.agents,
        mode=args.mode,
        gossip_rounds=args.gossip_rounds,
        gossip_peers=args.gossip_peers,
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=2))
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2))
    if args.predictions_output:
        _write_predictions_output(
            rows,
            args.predictions_output,
            default_model_name=args.model,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
