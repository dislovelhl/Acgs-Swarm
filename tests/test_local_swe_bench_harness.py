"""Tests for LocalSWEBenchHarness (git/pytest subprocess mocked)."""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import patch

import pytest
from constitutional_swarm.swe_bench.local_harness import (
    HarnessResult,
    LocalSWEBenchHarness,
    _as_list,
    _parse_pytest_summary,
)

_INSTANCE = {
    "instance_id": "demo__demo-1",
    "repo": "demo/demo",
    "base_commit": "deadbeef",
    "FAIL_TO_PASS": ["tests/test_demo.py::test_thing"],
    "PASS_TO_PASS": ["tests/test_demo.py::test_other"],
}

_PATCH = """\
--- a/src/demo.py
+++ b/src/demo.py
@@ -1 +1 @@
-broken
+fixed
"""


class _FakeRunner:
    """Scriptable ``subprocess.run`` replacement keyed by command prefix."""

    def __init__(self, scripts: list[tuple[list[str], int, str]]):
        self.scripts = list(scripts)
        self.calls: list[list[str]] = []

    def __call__(
        self,
        cmd: list[str],
        *,
        cwd: Any = None,
        input: Any = None,
        capture_output: bool = False,
        text: bool = False,
        timeout: Any = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        for i, (prefix, rc, out) in enumerate(self.scripts):
            if _matches(cmd, prefix):
                self.scripts.pop(i)
                return subprocess.CompletedProcess(cmd, rc, out, "")
        # Unmatched → treat as success no-op (keeps tests tolerant to extras).
        return subprocess.CompletedProcess(cmd, 0, "", "")


def _matches(cmd: list[str], prefix: list[str]) -> bool:
    joined = " ".join(cmd)
    return all(tok in joined for tok in prefix)


def test_parse_pytest_summary_mixed_counts() -> None:
    out = "====== 3 passed, 1 failed in 0.42s ======"
    assert _parse_pytest_summary(out) == (3, 1)


def test_parse_pytest_summary_only_passed() -> None:
    out = "============ 5 passed in 0.10s ============"
    assert _parse_pytest_summary(out) == (5, 0)


def test_parse_pytest_summary_errors_count_as_failed() -> None:
    out = "==== 1 failed, 2 errors in 0.03s ===="
    assert _parse_pytest_summary(out) == (0, 3)


def test_parse_pytest_summary_empty_output() -> None:
    assert _parse_pytest_summary("nothing here") == (0, 0)


def test_as_list_handles_json_encoded_string() -> None:
    assert _as_list('["a::b", "c::d"]') == ["a::b", "c::d"]


def test_as_list_handles_plain_string() -> None:
    assert _as_list("solo::test") == ["solo::test"]


def test_as_list_handles_list_and_none() -> None:
    assert _as_list(["x", "y"]) == ["x", "y"]
    assert _as_list(None) == []


def test_harness_empty_patch_short_circuits(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    result = harness.evaluate(_INSTANCE, patch="")
    assert isinstance(result, HarnessResult)
    assert result.applied is False
    assert result.resolved is False
    assert result.error == "empty patch"


def test_harness_missing_base_commit(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    bad = {**_INSTANCE, "base_commit": ""}
    result = harness.evaluate(bad, patch=_PATCH)
    assert result.applied is False
    assert result.error == "missing repo or base_commit"


def test_harness_resolves_when_all_tests_pass(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True
    assert result.fail_to_pass_passed == 1
    assert result.fail_to_pass_failed == 0
    assert result.pass_to_pass_passed == 1
    assert result.pass_to_pass_failed == 0


def test_harness_not_resolved_when_fail_to_pass_still_failing(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["pytest", "test_thing"], 1, "== 1 failed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is False
    assert result.fail_to_pass_failed == 1


def test_harness_apply_failure_falls_back_to_3way(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 1, "strict apply rejected"),
            (["apply", "--3way"], 0, ""),
            (["pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True


def test_harness_apply_failure_reports_cleanly(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 1, "rej1"),
            (["apply", "--3way"], 1, "rej2"),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is False
    assert result.resolved is False
    assert result.stage == "apply"
    assert result.error == "patch did not apply"


def test_harness_env_error_counts_requested_tests_as_failed(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["pytest", "test_thing"], 2, "ERROR: no module named 'django'"),
            (["pytest", "test_other"], 2, "ERROR: no module named 'django'"),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is False
    assert result.fail_to_pass_failed == 1
    assert result.pass_to_pass_failed == 1


def test_harness_checkout_retries_after_fetching_commit(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 1, "unknown revision"),
            (["fetch", "origin", "deadbeef"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True


def test_harness_clone_failure_stops_pipeline(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "--filter=blob:none"], 128, "fatal: repository not found"),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.stage == "clone"
    assert result.applied is False
    assert result.error is not None and "clone failed" in result.error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
