from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "run_official_swarm_swebench.py"
_SPEC = importlib.util.spec_from_file_location("run_official_swarm_swebench", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_build_swarm_command_includes_predictions_output_and_output_paths(tmp_path: Path) -> None:
    swarm_output = tmp_path / "swarm.json"
    predictions_output = tmp_path / "predictions.jsonl"

    cmd = _MODULE.build_swarm_command(
        swarm_script=Path("scripts/run_swe_bench_swarm_lite.py"),
        backend="codex",
        agents=2,
        limit=3,
        dataset="princeton-nlp/SWE-bench_Lite",
        split="test",
        jsonl=None,
        mode="in-memory",
        gossip_rounds=5,
        gossip_peers=2,
        model=None,
        agent_timeout=240.0,
        harness_timeout=600.0,
        env_isolation=True,
        env_timeout=900.0,
        python_version="3.10",
        env_fallback_mode="report-native-build-blocked",
        verbose=False,
        swarm_output=swarm_output,
        predictions_output=predictions_output,
    )

    joined = " ".join(cmd)
    assert str(swarm_output) in joined
    assert str(predictions_output) in joined
    assert "--predictions-output" in joined
    assert "--env-isolation" in joined
    assert "--python-version 3.10" in joined


def test_build_official_eval_command_uses_instance_ids_from_predictions(tmp_path: Path) -> None:
    predictions_path = tmp_path / "predictions.jsonl"
    predictions_path.write_text(
        '{"instance_id": "astropy__astropy-12907", "model_patch": "diff", "model_name_or_path": "codex-default"}\n'
        '{"instance_id": "django__django-10914", "model_patch": "diff", "model_name_or_path": "codex-default"}\n'
    )

    cmd = _MODULE.build_official_eval_command(
        predictions_path=predictions_path,
        dataset_name="SWE-bench/SWE-bench_Lite",
        split="test",
        run_id="demo-run",
        max_workers=1,
        timeout=1800,
        cache_level="env",
        clean=False,
        namespace="swebench",
        report_dir=tmp_path,
    )

    joined = " ".join(cmd)
    assert "python -m swebench.harness.run_evaluation" in joined
    assert "-i astropy__astropy-12907 django__django-10914" in joined
    assert f"-p {predictions_path}" in joined
    assert "-id demo-run" in joined


def test_load_instance_ids_fails_for_empty_predictions_file(tmp_path: Path) -> None:
    predictions_path = tmp_path / "predictions.jsonl"
    predictions_path.write_text("")

    with pytest.raises(ValueError, match="No predictions found"):
        _MODULE.load_instance_ids(predictions_path)


def test_write_final_report_bundle_combines_local_and_official_results(tmp_path: Path) -> None:
    swarm_output = tmp_path / "swarm.json"
    official_report = tmp_path / "official.json"
    bundle_path = tmp_path / "bundle.json"
    markdown_path = tmp_path / "bundle.md"

    swarm_output.write_text(
        json.dumps(
            {
                "instances": 3,
                "patch_generated": 2,
                "applied": 2,
                "resolved": 0,
                "native_build_blocked": 1,
                "rows": [
                    {
                        "instance_id": "astropy__astropy-12907",
                        "repo": "astropy/astropy",
                        "stage": "env_native_build_blocked",
                        "patch_generated": True,
                        "applied": True,
                        "resolved": False,
                    },
                    {
                        "instance_id": "django__django-10914",
                        "repo": "django/django",
                        "stage": "done",
                        "patch_generated": True,
                        "applied": True,
                        "resolved": False,
                    },
                    {
                        "instance_id": "psf__requests-1963",
                        "repo": "psf/requests",
                        "stage": "patch_generation",
                        "patch_generated": False,
                        "applied": False,
                        "resolved": False,
                    },
                ],
            }
        )
    )
    official_report.write_text(
        json.dumps(
            {
                "total_instances": 2,
                "submitted_instances": 2,
                "completed_instances": 2,
                "resolved_instances": 2,
                "unresolved_instances": 0,
                "error_instances": 0,
                "resolved_ids": ["astropy__astropy-12907", "django__django-10914"],
                "submitted_ids": ["astropy__astropy-12907", "django__django-10914"],
            }
        )
    )

    _MODULE.write_final_report_bundle(
        swarm_output_path=swarm_output,
        predictions_output_path=tmp_path / "predictions.jsonl",
        official_report_path=official_report,
        bundle_output_path=bundle_path,
        markdown_output_path=markdown_path,
        run_id="demo-run",
    )

    bundle = json.loads(bundle_path.read_text())
    markdown = markdown_path.read_text()
    assert bundle["run_id"] == "demo-run"
    assert bundle["paths"]["swarm_output"] == str(swarm_output)
    assert bundle["paths"]["official_report"] == str(official_report)
    assert bundle["local_swarm"]["instances"] == 3
    assert bundle["local_swarm"]["native_build_blocked"] == 1
    assert bundle["official_harness"]["resolved_instances"] == 2
    assert bundle["comparison"] == {
        "submitted_predictions": 2,
        "local_patch_generated": 2,
        "local_applied": 2,
        "local_resolved": 0,
        "official_resolved": 2,
        "official_unresolved": 0,
        "official_errors": 0,
    }
    assert bundle["per_instance_comparison"] == [
        {
            "instance_id": "astropy__astropy-12907",
            "repo": "astropy/astropy",
            "was_submitted": True,
            "local_stage": "env_native_build_blocked",
            "local_patch_generated": True,
            "local_applied": True,
            "local_resolved": False,
            "official_resolved": True,
            "official_status": "resolved",
            "disagreement": "local_unresolved_but_official_resolved",
        },
        {
            "instance_id": "django__django-10914",
            "repo": "django/django",
            "was_submitted": True,
            "local_stage": "done",
            "local_patch_generated": True,
            "local_applied": True,
            "local_resolved": False,
            "official_resolved": True,
            "official_status": "resolved",
            "disagreement": "local_unresolved_but_official_resolved",
        },
        {
            "instance_id": "psf__requests-1963",
            "repo": "psf/requests",
            "was_submitted": False,
            "local_stage": "patch_generation",
            "local_patch_generated": False,
            "local_applied": False,
            "local_resolved": False,
            "official_resolved": False,
            "official_status": "not_submitted",
            "disagreement": None,
        },
    ]
    assert "# Final SWE-bench Report Bundle" in markdown
    assert "🔴 HIGH" in markdown
    assert "⚪ NONE" in markdown


def test_render_markdown_bundle_adds_emoji_severity_tags() -> None:
    bundle = {
        "run_id": "demo-run",
        "comparison": {
            "submitted_predictions": 2,
            "local_patch_generated": 2,
            "local_applied": 2,
            "local_resolved": 0,
            "official_resolved": 2,
            "official_unresolved": 0,
            "official_errors": 0,
        },
        "per_instance_comparison": [
            {
                "instance_id": "astropy__astropy-12907",
                "repo": "astropy/astropy",
                "local_stage": "env",
                "local_resolved": False,
                "official_status": "resolved",
                "disagreement": "local_unresolved_but_official_resolved",
            },
            {
                "instance_id": "psf__requests-1963",
                "repo": "psf/requests",
                "local_stage": "patch_generation",
                "local_resolved": False,
                "official_status": "not_submitted",
                "disagreement": None,
            },
        ],
    }

    markdown = _MODULE.render_markdown_bundle(bundle)

    assert "# Final SWE-bench Report Bundle" in markdown
    assert "🔴 HIGH" in markdown
    assert "⚪ NONE" in markdown
    assert "astropy__astropy-12907" in markdown
    assert "psf__requests-1963" in markdown
    assert "local_unresolved_but_official_resolved" in markdown
    assert "## Disagreement summary" in markdown
    assert "- 🔴 HIGH: 1" in markdown
    assert "- ⚪ NONE: 1" in markdown
