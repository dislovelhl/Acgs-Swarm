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
            (["clone", "https://github.com"], 0, ""),
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
            (["clone", "https://github.com"], 0, ""),
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
            (["clone", "https://github.com"], 0, ""),
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


def test_harness_apply_falls_back_to_recount(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 1, "error: corrupt patch at line 11"),
            (["apply", "--index", "--recount"], 0, ""),
            (["pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True


def test_harness_apply_falls_back_to_patch1(tmp_path) -> None:
    """When all `git apply` variants fail (context drift), patch(1) with fuzz saves us."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 1, "error: patch failed"),
            (["apply", "--index", "--recount"], 1, "error: patch failed"),
            (["apply", "--3way"], 1, "error: patch failed"),
            (["patch", "-p1", "--forward", "--fuzz=3"], 0, "patching file foo.py\n"),
            (["git", "add", "-A"], 0, ""),
            (["pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with (
        patch("subprocess.run", side_effect=runner),
        patch(
            "constitutional_swarm.swe_bench.local_harness.shutil.which",
            return_value="/usr/bin/patch",
        ),
    ):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True


def test_harness_apply_failure_reports_cleanly(tmp_path) -> None:
    harness = LocalSWEBenchHarness(work_dir=tmp_path)
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 1, "rej1"),
            (["apply", "--index", "--recount"], 1, "rej_recount"),
            (["apply", "--3way"], 1, "rej2"),
            (["patch", "-p1"], 1, "patch1 rejected"),
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
            (["clone", "https://github.com"], 0, ""),
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
            (["clone", "https://github.com"], 0, ""),
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
            (["clone", "https://github.com"], 128, "fatal: repository not found"),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.stage == "clone"
    assert result.applied is False
    assert result.error is not None and "clone failed" in result.error


def test_harness_env_isolation_uses_venv_python(tmp_path) -> None:
    """With env_isolation=True, pytest runs through the venv's python, not the host interpreter."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path, env_isolation=True)
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["-m", "venv"], 0, ""),
            (["pip", "install", "--quiet", "--upgrade"], 0, ""),
            (["pip", "install", "--quiet"], 0, ""),
            (["/bin/python", "-m", "pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["/bin/python", "-m", "pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True
    # Venv python path should be recorded in metadata and contain "/venvs/"
    assert "env_python" in result.metadata
    assert "venvs" in result.metadata["env_python"]


def test_harness_env_isolation_install_failure_is_reported(tmp_path) -> None:
    """If pip install fails, the instance fails at the env stage (not tests)."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path, env_isolation=True)
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["-m", "venv"], 0, ""),
            (["pip", "install", "--quiet", "--upgrade"], 0, ""),
            (["pip", "install", "--quiet"], 1, "ERROR: could not build wheel"),
        ]
    )
    with patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is False
    assert result.stage == "env"
    assert result.error is not None and "pip install target failed" in result.error
    assert result.metadata.get("env_stage") == "pip-install"


def test_harness_env_isolation_uses_uv_for_python_version(tmp_path) -> None:
    """With python_version set, harness uses `uv python install` + `uv venv --python`."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path, env_isolation=True, python_version="3.10")
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["uv", "python", "install", "3.10"], 0, ""),
            (["uv", "venv", "--seed", "--python", "3.10"], 0, ""),
            (["pip", "install", "--quiet", "--upgrade"], 0, ""),
            (["pip", "install", "--quiet"], 0, ""),
            (["/bin/python", "-m", "pytest", "test_thing"], 0, "== 1 passed in 0.01s =="),
            (["/bin/python", "-m", "pytest", "test_other"], 0, "== 1 passed in 0.01s =="),
        ]
    )
    with (
        patch(
            "constitutional_swarm.swe_bench.local_harness.shutil.which",
            return_value="/usr/bin/uv",
        ),
        patch("subprocess.run", side_effect=runner),
    ):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is True
    assert result.metadata.get("env_python_version") == "3.10"
    # Confirm the uv install + uv venv subcommands actually ran.
    cmds = [" ".join(c) for c in runner.calls]
    assert any("uv python install 3.10" in c for c in cmds)
    assert any("uv venv --seed --python 3.10" in c for c in cmds)


def test_harness_env_isolation_uv_missing_is_reported(tmp_path) -> None:
    """If python_version is requested but uv is not on PATH, surface env-stage failure."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path, env_isolation=True, python_version="3.10")
    runner = _FakeRunner(
        [
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
        ]
    )
    with (
        patch(
            "constitutional_swarm.swe_bench.local_harness.shutil.which",
            return_value=None,
        ),
        patch("subprocess.run", side_effect=runner),
    ):
        result = harness.evaluate(_INSTANCE, patch=_PATCH)
    assert result.applied is True
    assert result.resolved is False
    assert result.stage == "env"
    assert result.metadata.get("env_stage") == "uv-missing"
    assert "uv" in (result.error or "")


def test_detect_python_version_reads_requires_python(tmp_path) -> None:
    """_detect_python_version extracts lower bound from pyproject requires-python."""
    from constitutional_swarm.swe_bench.local_harness import _detect_python_version

    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\nrequires-python = ">=3.9,<3.11"\n'
    )
    assert _detect_python_version(wt) == "3.9"

    # Caret form
    (wt / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\nrequires-python = "^3.10"\n'
    )
    assert _detect_python_version(wt) == "3.10"

    # Missing file / missing field
    assert _detect_python_version(tmp_path / "does-not-exist") is None
    (wt / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    assert _detect_python_version(wt) is None


def test_detect_test_runner_django_vs_pytest(tmp_path) -> None:
    from constitutional_swarm.swe_bench.local_harness import _detect_test_runner

    # Bare worktree → pytest default
    wt = tmp_path / "bare"
    wt.mkdir()
    assert _detect_test_runner(wt) == "pytest"

    # django/django layout → django runner
    wt2 = tmp_path / "dj"
    (wt2 / "tests").mkdir(parents=True)
    (wt2 / "tests" / "runtests.py").write_text("# django runtests\n")
    assert _detect_test_runner(wt2) == "django"


def test_parse_django_summary_ok_and_failed() -> None:
    from constitutional_swarm.swe_bench.local_harness import _parse_django_summary

    ok = "......\n----------------------------------------------------------------------\nRan 6 tests in 0.123s\n\nOK\n"
    assert _parse_django_summary(ok) == (6, 0)

    mixed = ".F.E..\n----------\nRan 6 tests in 0.42s\n\nFAILED (failures=1, errors=1, skipped=2)\n"
    # 6 total - (1 failure + 1 error) = 4 passed
    assert _parse_django_summary(mixed) == (4, 2)

    # No summary block (crash) → (0, 0), caller decides
    assert _parse_django_summary("segfault!\n") == (0, 0)

    # OK with skips — skipped are not failures
    ok_skip = "Ran 5 tests in 0.10s\n\nOK (skipped=2)\n"
    assert _parse_django_summary(ok_skip) == (5, 0)


def test_harness_django_instance_uses_runtests_not_pytest(tmp_path) -> None:
    """On a django-layout worktree, _run_tests routes through tests/runtests.py."""
    harness = LocalSWEBenchHarness(work_dir=tmp_path)

    # Make the worktree look like django/django BEFORE clone happens —
    # the FakeRunner doesn't actually execute git, so we pre-create the
    # worktree path the harness will then adopt.
    worktree = harness.work_dir / "django__django-10914"
    worktree.mkdir(parents=True)
    (worktree / "tests").mkdir()
    (worktree / "tests" / "runtests.py").write_text("# django\n")

    instance = {
        "instance_id": "django__django-10914",
        "repo": "django/django",
        "base_commit": "cafef00d",
        "FAIL_TO_PASS": ["test_utils.tests.OverrideSettingsTests.test_foo"],
        "PASS_TO_PASS": ["test_utils.tests.OverrideSettingsTests.test_bar"],
    }

    django_ok = "Ran 1 test in 0.10s\n\nOK\n"

    runner = _FakeRunner(
        [
            # The harness rmtree's the existing worktree, then clones — so
            # the runtests.py stub will be gone. Re-create it after clone
            # via a matcher that runs as a side effect: easiest is to let
            # the clone no-op (FakeRunner returns rc=0 with no fs change)
            # and re-seed after. Instead, short-circuit: set keep_worktree
            # and pre-seed, then make the clone & checkout pass by matching.
            (["clone", "https://github.com"], 0, ""),
            (["clone", "--no-hardlinks"], 0, ""),
            (["checkout", "--detach"], 0, ""),
            (["apply", "--index"], 0, ""),
            (["tests/runtests.py", "test_foo"], 0, django_ok),
            (["tests/runtests.py", "test_bar"], 0, django_ok),
        ]
    )
    # Pre-seed will be wiped by evaluate's rmtree; we work around by
    # patching shutil.rmtree to preserve the worktree and by keeping the
    # FakeRunner tolerant so unmatched calls are no-ops.
    import constitutional_swarm.swe_bench.local_harness as lh

    with patch.object(lh.shutil, "rmtree"), patch("subprocess.run", side_effect=runner):
        result = harness.evaluate(instance, patch=_PATCH)

    assert result.applied is True
    assert result.resolved is True
    assert result.metadata.get("test_runner") == "django"
    # Confirm runtests.py was actually invoked, and pytest was not.
    joined = [" ".join(c) for c in runner.calls]
    assert any("tests/runtests.py" in c for c in joined)
    assert not any("-m pytest" in c for c in joined)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
