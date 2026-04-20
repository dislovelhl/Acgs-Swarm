"""Run the CodexSWEBenchAgent against SWE-bench Lite with local validation.

This is the first end-to-end wire: real GPT-generated patches evaluated by a
Docker-less harness that clones, checks out, applies, and pytests each instance
in the current Python interpreter.

Usage
-----
Single-agent baseline over the first 10 instances::

    python scripts/run_swe_bench_lite.py --limit 10

From a local JSONL dump (offline)::

    python scripts/run_swe_bench_lite.py --jsonl ~/data/swe_bench_lite.jsonl --limit 5

Output
------
Per-instance line to stdout, then a JSON summary with fields:

  {"instances": N, "applied": a, "resolved": r, "apply_rate": ..., "resolve_rate": ...}
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent
from constitutional_swarm.swe_bench.local_harness import (
    LocalSWEBenchHarness,
    load_instances,
)


def _evaluate_one(
    agent: CodexSWEBenchAgent,
    harness: LocalSWEBenchHarness,
    instance: dict[str, Any],
) -> dict[str, Any]:
    patch_result = agent.solve(instance)
    if not patch_result.success:
        return {
            "instance_id": instance.get("instance_id"),
            "patch_generated": False,
            "applied": False,
            "resolved": False,
            "stage": "patch_generation",
            "error": patch_result.metadata.get("error", "no_patch"),
            "duration_s": patch_result.duration_s,
        }
    harness_result = harness.evaluate(instance, patch_result.patch)
    return {
        "instance_id": harness_result.instance_id,
        "patch_generated": True,
        "applied": harness_result.applied,
        "resolved": harness_result.resolved,
        "fail_to_pass_passed": harness_result.fail_to_pass_passed,
        "fail_to_pass_failed": harness_result.fail_to_pass_failed,
        "pass_to_pass_passed": harness_result.pass_to_pass_passed,
        "pass_to_pass_failed": harness_result.pass_to_pass_failed,
        "stage": harness_result.stage,
        "error": harness_result.error,
        "log_tail": harness_result.log_tail,
        "patch": patch_result.patch,
        "duration_s": patch_result.duration_s + harness_result.duration_s,
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
    parser.add_argument("--model", default=None, help="Codex model (e.g. gpt-5.4)")
    parser.add_argument("--agent-timeout", type=float, default=240.0)
    parser.add_argument("--harness-timeout", type=float, default=600.0)
    parser.add_argument("--output", type=Path, default=None)
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
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    instances = load_instances(
        jsonl_path=args.jsonl,
        dataset=args.dataset,
        split=args.split,
        limit=args.limit,
    )

    agent = CodexSWEBenchAgent(model=args.model, timeout_s=args.agent_timeout)
    harness = LocalSWEBenchHarness(
        timeout_s=args.harness_timeout,
        env_isolation=args.env_isolation,
        env_timeout_s=args.env_timeout,
        python_version=args.python_version,
    )

    rows: list[dict[str, Any]] = []
    for i, inst in enumerate(instances):
        row = _evaluate_one(agent, harness, inst)
        rows.append(row)
        print(
            f"[{i + 1}/{len(instances)}] {row['instance_id']} "
            f"stage={row['stage']} applied={row['applied']} "
            f"resolved={row['resolved']} "
            f"F2P={row.get('fail_to_pass_passed', 0)}/{row.get('fail_to_pass_passed', 0) + row.get('fail_to_pass_failed', 0)} "
            f"P2P={row.get('pass_to_pass_passed', 0)}/{row.get('pass_to_pass_passed', 0) + row.get('pass_to_pass_failed', 0)} "
            f"dur={row['duration_s']:.1f}s",
            flush=True,
        )

    n = len(rows)
    applied = sum(1 for r in rows if r["applied"])
    resolved = sum(1 for r in rows if r["resolved"])
    patch_generated = sum(1 for r in rows if r["patch_generated"])
    summary = {
        "instances": n,
        "patch_generated": patch_generated,
        "applied": applied,
        "resolved": resolved,
        "patch_rate": patch_generated / n if n else 0.0,
        "apply_rate": applied / n if n else 0.0,
        "resolve_rate": resolved / n if n else 0.0,
        "rows": rows,
    }
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=2))
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
