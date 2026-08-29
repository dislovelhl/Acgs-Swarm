"""Shared four-case B6 store negatives on PostgreSQL.

Uses the existing PostgreSQL fixture generator (unwrapped) and the same four
qualification-live cases already run on SQLite. This is not a new protocol
and does not modify the frozen B2 pair.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from tests.test_apcc_postgres import postgres_environment


def _ql_runner():
    path = (
        Path(__file__).resolve().parents[1]
        / "experiments"
        / "apcc-1"
        / "run_qualification_live.py"
    )
    spec = importlib.util.spec_from_file_location("run_qualification_live", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ql_b6_postgres_four_planned_negatives(tmp_path: Path) -> None:
    if not os.getenv("APCC_POSTGRES_DSN"):
        pytest.skip("set APCC_POSTGRES_DSN to run real PostgreSQL APCC contracts")
    runner = _ql_runner()
    report = runner.run_b6_postgres_negatives(tmp_path, "pytest-ql-b6-pg")
    assert report.get("status") == "LIVE_MEASURED", report
    records = {item["case_id"]: item for item in report["records"]}
    assert set(records) >= {
        "valid-first-commit",
        "exact-replay",
        "commit-id-equivocation",
        "invalid-commit-request",
    }
    assert records["valid-first-commit"]["outcome"] == "COMMITTED"
    assert records["valid-first-commit"]["authoritative"] is True
    assert records["exact-replay"]["outcome"] == "COMMITTED"
    assert records["exact-replay"]["second_authority"] is False
    assert records["commit-id-equivocation"]["authoritative"] is False
    assert records["invalid-commit-request"]["authoritative"] is False
    assert report["invalid_authoritative_commits"] == 0


def test_postgres_environment_fixture_is_not_called_directly() -> None:
    with pytest.raises(BaseException, match="called directly"):
        postgres_environment()
