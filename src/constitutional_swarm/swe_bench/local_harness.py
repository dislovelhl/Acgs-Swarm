"""Local (Docker-less) SWE-bench validation harness.

Pipeline per instance:

1. Clone ``repo`` into a shared cache (once per repo).
2. Hard-reset a scratch worktree to ``base_commit``.
3. ``git apply`` the candidate patch.
4. Run the instance's ``FAIL_TO_PASS`` and ``PASS_TO_PASS`` tests with
   pytest in the *current* Python interpreter.
5. Report a structured :class:`HarnessResult`; ``resolved=True`` iff every
   required test passed.

Scope / honesty
---------------
This is a mechanical scaffold. When ``env_isolation=True``, a per-instance
venv is created and ``pip install <worktree>`` bootstraps the target repo's
dependencies; this handles most pure-Python SWE-bench Lite instances but
does NOT reproduce repo-specific build pinning (no Docker image, no exact
CI environment). When ``env_isolation=False`` (the default), the caller
must ensure the target repo's deps are importable from the active
interpreter. Full Docker-based isolation remains a separate iteration.

Inputs
------
An "instance" is a ``dict`` with the SWE-bench Lite schema fields used
here: ``instance_id``, ``repo``, ``base_commit``, ``FAIL_TO_PASS``,
``PASS_TO_PASS``. Test IDs follow pytest's ``path::TestClass::test`` form.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_DEFAULT_WORK_DIR = Path.home() / ".cache" / "constitutional_swarm" / "swe_bench"
_PYTEST_SUMMARY = re.compile(
    r"(?m)^=*\s*(?P<summary>(?:\d+\s+(?:passed|failed|error|errors|skipped|xfailed|xpassed|deselected)"
    r"(?:,\s*)?)+)\s+in\s+[0-9.]+\s*s(?:\s*\([^)]*\))?\s*=*\s*$"
)


@dataclass
class HarnessResult:
    """Outcome of a single instance evaluation.

    Fields
    ------
    instance_id:
        SWE-bench instance id.
    applied:
        True iff ``git apply`` accepted the patch cleanly.
    resolved:
        True iff every FAIL_TO_PASS and PASS_TO_PASS test passed after
        applying the patch.
    fail_to_pass_passed / fail_to_pass_failed:
        Counts from the FAIL_TO_PASS phase.
    pass_to_pass_passed / pass_to_pass_failed:
        Counts from the PASS_TO_PASS phase.
    stage:
        One of ``clone``, ``checkout``, ``apply``, ``tests``, ``done`` —
        identifies where the pipeline exited.
    error:
        Short human-readable diagnostic on failure (``None`` on success).
    log_tail:
        Last ~2000 chars of combined stdout/stderr from the failing stage
        (empty when ``resolved``).
    duration_s:
        Wall-clock seconds for the entire evaluation.
    """

    instance_id: str
    applied: bool = False
    resolved: bool = False
    fail_to_pass_passed: int = 0
    fail_to_pass_failed: int = 0
    pass_to_pass_passed: int = 0
    pass_to_pass_failed: int = 0
    stage: str = "clone"
    error: str | None = None
    log_tail: str = ""
    duration_s: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class LocalSWEBenchHarness:
    """Docker-less SWE-bench evaluation harness.

    Parameters
    ----------
    work_dir:
        Root for scratch worktrees. One subdir per run, cleaned afterwards
        unless ``keep_worktree=True``.
    repo_cache_dir:
        Persistent cache for bare-ish clones. Reused across instances so
        we pay clone cost once per repo.
    python_bin:
        Python interpreter used to invoke pytest when env isolation is off.
        Defaults to the current interpreter.
    timeout_s:
        Per-stage timeout (clone, checkout, apply, each pytest phase).
    keep_worktree:
        If True, leave the scratch worktree in place after evaluation —
        useful for debugging a single instance.
    env_isolation:
        If True, create a per-instance venv and ``pip install`` the patched
        worktree into it before running tests. Pytest then runs with the
        venv's interpreter so the target project's dependencies don't
        collide with the host interpreter. If venv creation or install
        fails, the instance is reported as an env error (resolved=False)
        rather than silently falling back.
    env_cache_dir:
        Root for per-instance venvs. Each evaluation creates a fresh
        ``<env_cache_dir>/<instance_id>`` venv and removes it afterwards
        unless ``keep_worktree`` is also set.
    env_timeout_s:
        Timeout for venv creation and ``pip install`` (installing packages
        like astropy / scipy can take several minutes on first run).
    """

    def __init__(
        self,
        *,
        work_dir: Path | str | None = None,
        repo_cache_dir: Path | str | None = None,
        python_bin: str | None = None,
        timeout_s: float = 600.0,
        keep_worktree: bool = False,
        env_isolation: bool = False,
        env_cache_dir: Path | str | None = None,
        env_timeout_s: float = 900.0,
    ) -> None:
        base = Path(work_dir) if work_dir else _DEFAULT_WORK_DIR
        self.work_dir = base / "worktrees"
        self.repo_cache_dir = Path(repo_cache_dir) if repo_cache_dir else base / "repos"
        self.env_cache_dir = Path(env_cache_dir) if env_cache_dir else base / "venvs"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)
        self.env_cache_dir.mkdir(parents=True, exist_ok=True)
        self.python_bin = python_bin or _current_python()
        self.timeout_s = timeout_s
        self.keep_worktree = keep_worktree
        self.env_isolation = env_isolation
        self.env_timeout_s = env_timeout_s

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, instance: dict[str, Any], patch: str) -> HarnessResult:
        """Run clone → checkout → apply → pytest for ``instance`` with ``patch``.

        Always returns a :class:`HarnessResult` — exceptions in subprocesses
        are caught and surfaced via ``error`` / ``log_tail``.
        """
        import time

        t0 = time.monotonic()
        instance_id = str(instance.get("instance_id", "unknown"))
        repo = str(instance.get("repo", "")).strip()
        base_commit = str(instance.get("base_commit", "")).strip()
        fail_to_pass = _as_list(instance.get("FAIL_TO_PASS"))
        pass_to_pass = _as_list(instance.get("PASS_TO_PASS"))
        result = HarnessResult(instance_id=instance_id)

        if not repo or not base_commit:
            result.stage = "clone"
            result.error = "missing repo or base_commit"
            result.duration_s = time.monotonic() - t0
            return result
        if not patch.strip():
            result.stage = "apply"
            result.error = "empty patch"
            result.duration_s = time.monotonic() - t0
            return result

        worktree = self.work_dir / _safe_id(instance_id)
        venv_path: Path | None = None
        try:
            if worktree.exists():
                shutil.rmtree(worktree)
            self._clone_to_worktree(repo, worktree, result)
            if result.error:
                return result
            self._checkout(worktree, base_commit, result)
            if result.error:
                return result
            self._apply_patch(worktree, patch, result)
            if not result.applied:
                return result
            test_python = self.python_bin
            if self.env_isolation:
                venv_path, test_python = self._ensure_env(instance_id, worktree, result)
                if test_python is None:
                    return result
            self._run_tests(worktree, fail_to_pass, pass_to_pass, result, test_python)
            result.stage = "done"
            result.resolved = (
                result.fail_to_pass_failed == 0
                and result.pass_to_pass_failed == 0
                and (result.fail_to_pass_passed + result.pass_to_pass_passed) > 0
            )
            return result
        finally:
            result.duration_s = time.monotonic() - t0
            if not self.keep_worktree and worktree.exists():
                shutil.rmtree(worktree, ignore_errors=True)
            if not self.keep_worktree and venv_path is not None and venv_path.exists():
                shutil.rmtree(venv_path, ignore_errors=True)

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _clone_to_worktree(self, repo: str, worktree: Path, result: HarnessResult) -> None:
        result.stage = "clone"
        cache = self.repo_cache_dir / _safe_id(repo)
        url = f"https://github.com/{repo}.git"
        if not cache.exists():
            # Full clone (not --filter=blob:none) so the --shared worktree below
            # has all blobs available for `git apply --index` / --3way merges.
            rc, out = _run(
                ["git", "clone", url, str(cache)],
                timeout=self.timeout_s,
            )
            if rc != 0:
                result.error = f"clone failed (rc={rc})"
                result.log_tail = out[-2000:]
                return
        else:
            _run(
                ["git", "-C", str(cache), "fetch", "--tags", "--prune", "origin"],
                timeout=self.timeout_s,
            )

        rc, out = _run(
            ["git", "clone", "--no-hardlinks", "--shared", str(cache), str(worktree)],
            timeout=self.timeout_s,
        )
        if rc != 0:
            result.error = f"worktree clone failed (rc={rc})"
            result.log_tail = out[-2000:]

    def _checkout(self, worktree: Path, base_commit: str, result: HarnessResult) -> None:
        result.stage = "checkout"
        rc, out = _run(
            ["git", "-C", str(worktree), "checkout", "--detach", base_commit],
            timeout=self.timeout_s,
        )
        if rc != 0:
            # Try fetching the specific commit then retrying — SWE-bench commits
            # are occasionally not reachable without a full fetch.
            _run(
                ["git", "-C", str(worktree), "fetch", "origin", base_commit],
                timeout=self.timeout_s,
            )
            rc, out = _run(
                ["git", "-C", str(worktree), "checkout", "--detach", base_commit],
                timeout=self.timeout_s,
            )
        if rc != 0:
            result.error = f"checkout failed (rc={rc})"
            result.log_tail = out[-2000:]

    def _apply_patch(self, worktree: Path, patch: str, result: HarnessResult) -> None:
        result.stage = "apply"
        # Strict → --recount (fix LLM hunk-count errors) → 3-way → patch(1) with
        # fuzz (tolerant of LLM context drift, if `patch` is installed). After a
        # successful `patch`, stage changes so downstream git tooling sees them.
        out = ""
        for flags in (["--index"], ["--index", "--recount"], ["--3way", "--recount"]):
            rc, out = _run(
                ["git", "-C", str(worktree), "apply", *flags, "-"],
                input_text=patch,
                timeout=self.timeout_s,
            )
            if rc == 0:
                result.applied = True
                return
        if shutil.which("patch"):
            rc, out2 = _run(
                ["patch", "-p1", "--forward", "--fuzz=3", "--no-backup-if-mismatch"],
                cwd=worktree,
                input_text=patch,
                timeout=self.timeout_s,
            )
            if rc == 0:
                _run(["git", "-C", str(worktree), "add", "-A"], timeout=self.timeout_s)
                result.applied = True
                return
            out = out + "\n---patch(1)---\n" + out2
        result.applied = False
        result.error = "patch did not apply"
        result.log_tail = out[-2000:]

    def _run_tests(
        self,
        worktree: Path,
        fail_to_pass: list[str],
        pass_to_pass: list[str],
        result: HarnessResult,
        python_bin: str,
    ) -> None:
        result.stage = "tests"
        if fail_to_pass:
            passed, failed, log = self._pytest(worktree, fail_to_pass, python_bin)
            result.fail_to_pass_passed = passed
            result.fail_to_pass_failed = failed
            if failed > 0:
                result.log_tail = log[-2000:]
        if pass_to_pass:
            passed, failed, log = self._pytest(worktree, pass_to_pass, python_bin)
            result.pass_to_pass_passed = passed
            result.pass_to_pass_failed = failed
            if failed > 0 and not result.log_tail:
                result.log_tail = log[-2000:]

    def _pytest(
        self, worktree: Path, test_ids: list[str], python_bin: str
    ) -> tuple[int, int, str]:
        cmd = [
            python_bin,
            "-m",
            "pytest",
            "--no-header",
            "-q",
            "--disable-warnings",
            *test_ids,
        ]
        rc, out = _run(cmd, cwd=worktree, timeout=self.timeout_s)
        passed, failed = _parse_pytest_summary(out)
        # If pytest returned non-zero but reported zero counts, it was a
        # collection/env error — count every requested test as failed so
        # the instance cannot be considered resolved.
        if rc != 0 and passed == 0 and failed == 0:
            failed = len(test_ids)
        return passed, failed, out

    def _ensure_env(
        self, instance_id: str, worktree: Path, result: HarnessResult
    ) -> tuple[Path | None, str | None]:
        """Create a per-instance venv and ``pip install`` the patched worktree.

        Returns ``(venv_path, python_bin)``. On failure, records an env
        error on ``result`` and returns ``(venv_path_or_None, None)`` so
        the caller can short-circuit without running tests.
        """
        result.stage = "env"
        venv_path = self.env_cache_dir / _safe_id(instance_id)
        if venv_path.exists():
            shutil.rmtree(venv_path, ignore_errors=True)
        rc, out = _run(
            [self.python_bin, "-m", "venv", str(venv_path)],
            timeout=self.env_timeout_s,
        )
        if rc != 0:
            result.error = f"venv creation failed (rc={rc})"
            result.log_tail = out[-2000:]
            result.metadata["env_stage"] = "venv"
            return venv_path, None
        venv_py = str(venv_path / "bin" / "python")
        rc, out = _run(
            [venv_py, "-m", "pip", "install", "--quiet", "--upgrade", "pip", "pytest"],
            timeout=self.env_timeout_s,
        )
        if rc != 0:
            result.error = f"pip bootstrap failed (rc={rc})"
            result.log_tail = out[-2000:]
            result.metadata["env_stage"] = "pip-bootstrap"
            return venv_path, None
        rc, out = _run(
            [venv_py, "-m", "pip", "install", "--quiet", str(worktree)],
            timeout=self.env_timeout_s,
        )
        if rc != 0:
            result.error = f"pip install target failed (rc={rc})"
            result.log_tail = out[-2000:]
            result.metadata["env_stage"] = "pip-install"
            return venv_path, None
        result.metadata["env_python"] = venv_py
        return venv_path, venv_py


# ----------------------------------------------------------------------
# Dataset loading helpers
# ----------------------------------------------------------------------


def load_instances(
    *,
    jsonl_path: Path | str | None = None,
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    split: str = "test",
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Load SWE-bench instances from a local JSONL file or a HuggingFace dataset.

    A local ``jsonl_path`` wins if provided. Otherwise the harness attempts
    to import ``datasets`` and load the named dataset/split.
    """
    if jsonl_path is not None:
        path = Path(jsonl_path)
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return rows[:limit] if limit else rows
    try:
        from datasets import load_dataset  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "datasets library not installed; pass jsonl_path or install `datasets`"
        ) from exc
    ds = load_dataset(dataset, split=split)
    rows = [dict(r) for r in ds]
    return rows[:limit] if limit else rows


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------


def _current_python() -> str:
    import sys

    return sys.executable


def _safe_id(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (json.JSONDecodeError, ValueError):
            pass
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    return [str(value)]


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    timeout: float = 600.0,
) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 — commands are constructed from trusted args
            cmd,
            cwd=str(cwd) if cwd else None,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout after {timeout}s: {exc}"
    except FileNotFoundError as exc:
        return 127, f"missing binary: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _parse_pytest_summary(output: str) -> tuple[int, int]:
    """Return (passed, failed) counts parsed from pytest's final summary."""
    passed = failed = 0
    for match in _PYTEST_SUMMARY.finditer(output):
        summary = match.group("summary")
        for token in re.finditer(r"(\d+)\s+(passed|failed|error|errors)", summary):
            count = int(token.group(1))
            kind = token.group(2)
            if kind == "passed":
                passed += count
            elif kind in {"failed", "error", "errors"}:
                failed += count
    return passed, failed


__all__ = [
    "HarnessResult",
    "LocalSWEBenchHarness",
    "load_instances",
]
