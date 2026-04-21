from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "scripts"
    / "convert_swarm_output_to_swebench_predictions.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "convert_swarm_output_to_swebench_predictions",
    _SCRIPT_PATH,
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


@pytest.fixture
def swarm_output() -> dict[str, object]:
    return {
        "rows": [
            {
                "instance_id": "astropy__astropy-12907",
                "patch_generated": True,
                "patch": "diff --git a/file.py b/file.py\n+fix\n",
                "patch_metadata": {"model": "codex-default"},
            },
            {
                "instance_id": "psf__requests-1963",
                "patch_generated": False,
                "patch": "",
                "patch_metadata": {"error": "timeout"},
            },
            {
                "instance_id": "django__django-10914",
                "patch_generated": True,
                "patch": "   ",
                "patch_metadata": {"model": "claude-sonnet-4-5"},
            },
        ]
    }


def test_convert_rows_skips_empty_patches_by_default(
    swarm_output: dict[str, object],
) -> None:
    predictions = _MODULE.convert_rows_to_predictions(swarm_output["rows"])

    assert predictions == [
        {
            "instance_id": "astropy__astropy-12907",
            "model_patch": "diff --git a/file.py b/file.py\n+fix\n",
            "model_name_or_path": "codex-default",
        }
    ]


def test_convert_rows_can_include_empty_patches(
    swarm_output: dict[str, object],
) -> None:
    predictions = _MODULE.convert_rows_to_predictions(
        swarm_output["rows"],
        include_empty=True,
        default_model_name="fallback-model",
    )

    assert predictions == [
        {
            "instance_id": "astropy__astropy-12907",
            "model_patch": "diff --git a/file.py b/file.py\n+fix\n",
            "model_name_or_path": "codex-default",
        },
        {
            "instance_id": "psf__requests-1963",
            "model_patch": "",
            "model_name_or_path": "fallback-model",
        },
        {
            "instance_id": "django__django-10914",
            "model_patch": "   ",
            "model_name_or_path": "claude-sonnet-4-5",
        },
    ]


def test_main_writes_jsonl_predictions_file(tmp_path: Path) -> None:
    input_path = tmp_path / "swarm_output.json"
    output_path = tmp_path / "predictions.jsonl"
    input_path.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "instance_id": "django__django-10914",
                        "patch": "diff --git a/django/conf/global_settings.py b/django/conf/global_settings.py\n",
                        "patch_metadata": {"model": "codex-default"},
                    }
                ]
            }
        )
    )

    exit_code = _MODULE.main([str(input_path), str(output_path)])

    assert exit_code == 0
    assert output_path.read_text().splitlines() == [
        json.dumps(
            {
                "instance_id": "django__django-10914",
                "model_patch": "diff --git a/django/conf/global_settings.py b/django/conf/global_settings.py\n",
                "model_name_or_path": "codex-default",
            }
        )
    ]


def test_main_requires_model_name_when_missing_from_rows(tmp_path: Path) -> None:
    input_path = tmp_path / "swarm_output.json"
    output_path = tmp_path / "predictions.json"
    input_path.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "instance_id": "psf__requests-1963",
                        "patch": "diff --git a/requests/models.py b/requests/models.py\n",
                        "patch_metadata": {},
                    }
                ]
            }
        )
    )

    with pytest.raises(SystemExit, match="model_name_or_path"):
        _MODULE.main([str(input_path), str(output_path)])
