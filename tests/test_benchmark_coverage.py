from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "benchmark_coverage.py"
_SPEC = importlib.util.spec_from_file_location("benchmark_coverage", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_successful_pytest_run_exits_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_covered": 95.01,
                    "covered_lines": 95,
                    "num_statements": 100,
                    "missing_lines": 5,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(_MODULE, "COVERAGE_OUT", coverage_path)
    monkeypatch.setattr(
        _MODULE.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )

    with pytest.raises(SystemExit) as exc:
        _MODULE.main()

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "ok"
    assert payload["sub_scores"]["tests_exit_code"] == 0


def test_main_exits_one_when_pytest_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_covered": 80.0,
                    "covered_lines": 80,
                    "num_statements": 100,
                    "missing_lines": 20,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(_MODULE, "COVERAGE_OUT", coverage_path)
    monkeypatch.setattr(
        _MODULE.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2),
    )

    with pytest.raises(SystemExit) as exc:
        _MODULE.main()

    assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "error"
    assert payload["sub_scores"]["tests_exit_code"] == 2
