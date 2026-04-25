"""Run swarm generation, convert predictions, then invoke official SWE-bench evaluation.

Examples
--------
Run a 2-agent Codex swarm and evaluate the produced predictions with the official harness::

    python scripts/run_official_swarm_swebench.py \
        --limit 2 \
        --agents 2 \
        --backend codex \
        --run-id demo-run
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def load_instance_ids(predictions_path: Path) -> list[str]:
    rows = [json.loads(line) for line in predictions_path.read_text().splitlines() if line.strip()]
    instance_ids = [str(row["instance_id"]) for row in rows]
    if not instance_ids:
        raise ValueError(f"No predictions found in {predictions_path}")
    return instance_ids


def load_predictions(predictions_path: Path) -> list[dict[str, object]]:
    rows = [json.loads(line) for line in predictions_path.read_text().splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"No predictions found in {predictions_path}")
    return rows


def get_official_report_path(predictions_path: Path, run_id: str) -> Path:
    predictions = load_predictions(predictions_path)
    model_name = str(predictions[0]["model_name_or_path"]).replace("/", "__")
    return Path(f"{model_name}.{run_id}.json")


def build_per_instance_comparison(
    swarm_rows: list[dict[str, object]],
    official_summary: dict[str, object],
) -> list[dict[str, object]]:
    submitted_ids = set(map(str, official_summary.get("submitted_ids", [])))
    resolved_ids = set(map(str, official_summary.get("resolved_ids", [])))
    unresolved_ids = set(map(str, official_summary.get("unresolved_ids", [])))
    error_ids = set(map(str, official_summary.get("error_ids", [])))

    comparisons: list[dict[str, object]] = []
    for row in swarm_rows:
        instance_id = str(row.get("instance_id"))
        was_submitted = instance_id in submitted_ids
        official_resolved = instance_id in resolved_ids
        if instance_id in resolved_ids:
            official_status = "resolved"
        elif instance_id in unresolved_ids:
            official_status = "unresolved"
        elif instance_id in error_ids:
            official_status = "error"
        else:
            official_status = "not_submitted"

        local_resolved = bool(row.get("resolved", False))
        disagreement = None
        if not local_resolved and official_resolved:
            disagreement = "local_unresolved_but_official_resolved"
        elif local_resolved and instance_id in unresolved_ids:
            disagreement = "local_resolved_but_official_unresolved"
        elif local_resolved and instance_id in error_ids:
            disagreement = "local_resolved_but_official_error"

        comparisons.append(
            {
                "instance_id": instance_id,
                "repo": row.get("repo"),
                "was_submitted": was_submitted,
                "local_stage": row.get("stage"),
                "local_patch_generated": row.get("patch_generated"),
                "local_applied": row.get("applied"),
                "local_resolved": local_resolved,
                "official_resolved": official_resolved,
                "official_status": official_status,
                "disagreement": disagreement,
            }
        )
    return comparisons


def disagreement_severity(disagreement: str | None) -> tuple[str, str]:
    if disagreement == "local_unresolved_but_official_resolved":
        return "🔴 HIGH", "high"
    if disagreement in {
        "local_resolved_but_official_unresolved",
        "local_resolved_but_official_error",
    }:
        return "🟠 MEDIUM", "medium"
    return "⚪ NONE", "none"


def summarize_disagreements_by_severity(
    rows: list[dict[str, object]],
) -> list[tuple[str, int]]:
    order = [("🔴 HIGH", 0), ("🟠 MEDIUM", 0), ("⚪ NONE", 0)]
    counts = {label: count for label, count in order}
    for row in rows:
        label, _key = disagreement_severity(row.get("disagreement"))
        counts[label] += 1
    return [(label, counts[label]) for label, _count in order]


def render_markdown_bundle(bundle: dict[str, object]) -> str:
    run_id = str(bundle.get("run_id", "unknown"))
    comparison = bundle.get("comparison", {})
    rows = bundle.get("per_instance_comparison", [])
    severity_counts = summarize_disagreements_by_severity(rows)

    lines = [
        "# Final SWE-bench Report Bundle",
        "",
        f"Run ID: `{run_id}`",
        "",
        "## Summary",
        "",
        f"- Submitted predictions: {comparison.get('submitted_predictions', 0)}",
        f"- Local patch generated: {comparison.get('local_patch_generated', 0)}",
        f"- Local applied: {comparison.get('local_applied', 0)}",
        f"- Local resolved: {comparison.get('local_resolved', 0)}",
        f"- Official resolved: {comparison.get('official_resolved', 0)}",
        f"- Official unresolved: {comparison.get('official_unresolved', 0)}",
        f"- Official errors: {comparison.get('official_errors', 0)}",
        "",
        "## Disagreement summary",
        "",
    ]

    for label, count in severity_counts:
        lines.append(f"- {label}: {count}")

    lines.extend(
        [
            "",
            "## Per-instance comparison",
            "",
            "| Severity | Instance | Repo | Local stage | Local resolved | Official status | Disagreement |",
            "|---|---|---|---|---:|---|---|",
        ]
    )

    for row in rows:
        severity_label, _severity_key = disagreement_severity(row.get("disagreement"))
        lines.append(
            "| {severity} | `{instance}` | `{repo}` | `{stage}` | `{local_resolved}` | `{official_status}` | `{disagreement}` |".format(
                severity=severity_label,
                instance=row.get("instance_id", ""),
                repo=row.get("repo", ""),
                stage=row.get("local_stage", ""),
                local_resolved=row.get("local_resolved", False),
                official_status=row.get("official_status", ""),
                disagreement=row.get("disagreement", "None"),
            )
        )

    return "\n".join(lines) + "\n"


def write_final_report_bundle(
    *,
    swarm_output_path: Path,
    predictions_output_path: Path,
    official_report_path: Path,
    bundle_output_path: Path,
    markdown_output_path: Path | None = None,
    run_id: str,
) -> None:
    swarm_summary = json.loads(swarm_output_path.read_text())
    official_summary = json.loads(official_report_path.read_text())
    per_instance_comparison = build_per_instance_comparison(
        swarm_summary.get("rows", []),
        official_summary,
    )

    bundle = {
        "run_id": run_id,
        "paths": {
            "swarm_output": str(swarm_output_path),
            "predictions_output": str(predictions_output_path),
            "official_report": str(official_report_path),
        },
        "local_swarm": {
            "instances": swarm_summary.get("instances", 0),
            "patch_generated": swarm_summary.get("patch_generated", 0),
            "applied": swarm_summary.get("applied", 0),
            "resolved": swarm_summary.get("resolved", 0),
            "native_build_blocked": swarm_summary.get("native_build_blocked", 0),
            "rows": swarm_summary.get("rows", []),
        },
        "official_harness": official_summary,
        "comparison": {
            "submitted_predictions": official_summary.get("submitted_instances", 0),
            "local_patch_generated": swarm_summary.get("patch_generated", 0),
            "local_applied": swarm_summary.get("applied", 0),
            "local_resolved": swarm_summary.get("resolved", 0),
            "official_resolved": official_summary.get("resolved_instances", 0),
            "official_unresolved": official_summary.get("unresolved_instances", 0),
            "official_errors": official_summary.get("error_instances", 0),
        },
        "per_instance_comparison": per_instance_comparison,
    }
    bundle_output_path.write_text(json.dumps(bundle, indent=2))
    if markdown_output_path is not None:
        markdown_output_path.write_text(render_markdown_bundle(bundle))


def build_swarm_command(
    *,
    swarm_script: Path,
    backend: str,
    agents: int,
    limit: int,
    dataset: str,
    split: str,
    jsonl: Path | None,
    mode: str,
    gossip_rounds: int,
    gossip_peers: int,
    model: str | None,
    agent_timeout: float,
    harness_timeout: float,
    env_isolation: bool,
    env_timeout: float,
    python_version: str | None,
    env_fallback_mode: str,
    verbose: bool,
    swarm_output: Path,
    predictions_output: Path,
) -> list[str]:
    cmd = [
        sys.executable,
        str(swarm_script),
        "--backend",
        backend,
        "--limit",
        str(limit),
        "--agents",
        str(agents),
        "--dataset",
        dataset,
        "--split",
        split,
        "--mode",
        mode,
        "--gossip-rounds",
        str(gossip_rounds),
        "--gossip-peers",
        str(gossip_peers),
        "--agent-timeout",
        str(agent_timeout),
        "--harness-timeout",
        str(harness_timeout),
        "--env-timeout",
        str(env_timeout),
        "--env-fallback-mode",
        env_fallback_mode,
        "--output",
        str(swarm_output),
        "--predictions-output",
        str(predictions_output),
    ]
    if jsonl is not None:
        cmd.extend(["--jsonl", str(jsonl)])
    if model is not None:
        cmd.extend(["--model", model])
    if env_isolation:
        cmd.append("--env-isolation")
    if python_version is not None:
        cmd.extend(["--python-version", python_version])
    if verbose:
        cmd.append("--verbose")
    return cmd


def build_official_eval_command(
    *,
    predictions_path: Path,
    dataset_name: str,
    split: str,
    run_id: str,
    max_workers: int,
    timeout: int,
    cache_level: str,
    clean: bool,
    namespace: str,
    report_dir: Path,
) -> list[str]:
    instance_ids = load_instance_ids(predictions_path)
    return [
        sys.executable,
        "-m",
        "swebench.harness.run_evaluation",
        "-d",
        dataset_name,
        "-s",
        split,
        "-i",
        *instance_ids,
        "-p",
        str(predictions_path),
        "--max_workers",
        str(max_workers),
        "-t",
        str(timeout),
        "--cache_level",
        cache_level,
        "--clean",
        str(clean).lower(),
        "-id",
        run_id,
        "-n",
        namespace,
        "--report_dir",
        str(report_dir),
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--jsonl", type=Path, default=None)
    parser.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite")
    parser.add_argument("--split", default="test")
    parser.add_argument("--backend", choices=["codex", "claude"], default="codex")
    parser.add_argument("--agents", type=int, default=2)
    parser.add_argument("--mode", choices=["in-memory", "gossip"], default="in-memory")
    parser.add_argument("--gossip-rounds", type=int, default=5)
    parser.add_argument("--gossip-peers", type=int, default=2)
    parser.add_argument("--model", default=None)
    parser.add_argument("--agent-timeout", type=float, default=240.0)
    parser.add_argument("--harness-timeout", type=float, default=600.0)
    parser.add_argument("--env-isolation", action="store_true")
    parser.add_argument("--env-timeout", type=float, default=900.0)
    parser.add_argument("--python-version", default="3.10")
    parser.add_argument(
        "--env-fallback-mode",
        default="report-native-build-blocked",
        choices=["strict", "report-native-build-blocked"],
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dataset-name", default="SWE-bench/SWE-bench_Lite")
    parser.add_argument("--max-workers", type=int, default=1)
    parser.add_argument("--official-timeout", type=int, default=1800)
    parser.add_argument("--cache-level", choices=["none", "base", "env", "instance"], default="env")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--namespace", default="swebench")
    parser.add_argument("--report-dir", type=Path, default=Path("."))
    parser.add_argument("--swarm-output", type=Path, default=None)
    parser.add_argument("--predictions-output", type=Path, default=None)
    parser.add_argument(
        "--final-report-output",
        type=Path,
        default=None,
        help="Optional path for a combined bundle summarizing local swarm output and official harness results.",
    )
    parser.add_argument(
        "--final-report-markdown-output",
        type=Path,
        default=None,
        help="Optional path for a markdown version of the final report bundle with emoji-tagged severity.",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tmp_dir = Path(tempfile.gettempdir())
    swarm_output = args.swarm_output or (tmp_dir / f"{args.run_id}_swarm.json")
    predictions_output = args.predictions_output or (tmp_dir / f"{args.run_id}_predictions.jsonl")
    final_report_output = args.final_report_output or (
        tmp_dir / f"{args.run_id}_final_report_bundle.json"
    )
    final_report_markdown_output = args.final_report_markdown_output or (
        tmp_dir / f"{args.run_id}_final_report_bundle.md"
    )

    swarm_cmd = build_swarm_command(
        swarm_script=_REPO_ROOT / "scripts" / "run_swe_bench_swarm_lite.py",
        backend=args.backend,
        agents=args.agents,
        limit=args.limit,
        dataset=args.dataset,
        split=args.split,
        jsonl=args.jsonl,
        mode=args.mode,
        gossip_rounds=args.gossip_rounds,
        gossip_peers=args.gossip_peers,
        model=args.model,
        agent_timeout=args.agent_timeout,
        harness_timeout=args.harness_timeout,
        env_isolation=args.env_isolation,
        env_timeout=args.env_timeout,
        python_version=args.python_version,
        env_fallback_mode=args.env_fallback_mode,
        verbose=args.verbose,
        swarm_output=swarm_output,
        predictions_output=predictions_output,
    )
    subprocess.run(swarm_cmd, check=True, cwd=_REPO_ROOT)  # noqa: S603

    eval_cmd = build_official_eval_command(
        predictions_path=predictions_output,
        dataset_name=args.dataset_name,
        split=args.split,
        run_id=args.run_id,
        max_workers=args.max_workers,
        timeout=args.official_timeout,
        cache_level=args.cache_level,
        clean=args.clean,
        namespace=args.namespace,
        report_dir=args.report_dir,
    )
    subprocess.run(eval_cmd, check=True, cwd=_REPO_ROOT)  # noqa: S603
    official_report_path = _REPO_ROOT / get_official_report_path(predictions_output, args.run_id)
    write_final_report_bundle(
        swarm_output_path=swarm_output,
        predictions_output_path=predictions_output,
        official_report_path=official_report_path,
        bundle_output_path=final_report_output,
        markdown_output_path=final_report_markdown_output,
        run_id=args.run_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
