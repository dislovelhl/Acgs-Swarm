from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "run_swe_bench_swarm_lite.py"
_SPEC = importlib.util.spec_from_file_location("run_swe_bench_swarm_lite", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_summarize_reports_known_native_build_blockers_by_repo() -> None:
    rows = [
        {
            "instance_id": "astropy__astropy-12907",
            "repo": "astropy/astropy",
            "patch_generated": True,
            "applied": True,
            "resolved": False,
            "native_build_blocked": True,
            "harness_metadata": {
                "env_failure_class": "native-build-incompatibility",
            },
        },
        {
            "instance_id": "astropy__astropy-14309",
            "repo": "astropy/astropy",
            "patch_generated": True,
            "applied": True,
            "resolved": False,
            "native_build_blocked": True,
            "harness_metadata": {
                "env_failure_class": "native-build-incompatibility",
            },
        },
        {
            "instance_id": "psf__requests-1",
            "repo": "psf/requests",
            "patch_generated": True,
            "applied": True,
            "resolved": True,
            "native_build_blocked": False,
            "harness_metadata": {},
        },
    ]

    summary = _MODULE._summarize(
        rows=rows,
        swarm_result={"resolved": 2, "crdt_size": 3},
        agents=2,
        mode="in-memory",
        gossip_rounds=0,
        gossip_peers=0,
    )

    assert summary["native_build_blocked"] == 2
    assert summary["known_native_build_blocked_by_repo"] == {
        "astropy/astropy": {
            "count": 2,
            "instances": ["astropy__astropy-12907", "astropy__astropy-14309"],
            "failure_classes": ["native-build-incompatibility"],
        }
    }


def test_write_predictions_output_filters_empty_patches(tmp_path: Path) -> None:
    rows = [
        {
            "instance_id": "astropy__astropy-12907",
            "patch": "diff --git a/a b/a\n+fix\n",
            "patch_metadata": {"model": "codex-default"},
        },
        {
            "instance_id": "psf__requests-1963",
            "patch": "",
            "patch_metadata": {"error": "timeout"},
        },
    ]
    output_path = tmp_path / "predictions.jsonl"

    _MODULE._write_predictions_output(
        rows,
        output_path,
        default_model_name=None,
    )

    lines = [json.loads(line) for line in output_path.read_text().splitlines() if line.strip()]
    assert lines == [
        {
            "instance_id": "astropy__astropy-12907",
            "model_patch": "diff --git a/a b/a\n+fix\n",
            "model_name_or_path": "codex-default",
        }
    ]
