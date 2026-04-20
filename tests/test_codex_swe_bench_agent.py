"""Tests for CodexSWEBenchAgent (subprocess mocked)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from constitutional_swarm.swe_bench.codex_agent import (
    CodexSWEBenchAgent,
    _extract_diff,
)

_FAKE_DIFF = """\
--- a/src/foo.py
+++ b/src/foo.py
@@ -1 +1 @@
-hello
+goodbye
"""

_TASK = {
    "instance_id": "django__django-11099",
    "repo": "django/django",
    "base_commit": "abc123",
    "problem_statement": "UsernameValidator allows trailing newline in usernames",
    "FAIL_TO_PASS": [
        "tests/auth_tests/test_validators.py::UsernameValidatorTestCase::test_unicode"
    ],
    "hints_text": "",
}


def _fake_codex(diff: str, returncode: int = 0):
    """Build a fake subprocess.run that writes ``diff`` to the last-message file."""

    def _run(cmd, input=None, capture_output=False, text=False, timeout=None, check=False):
        # The agent passes --output-last-message <path>; find it and write the diff there.
        idx = cmd.index("--output-last-message")
        last_path = Path(cmd[idx + 1])
        last_path.write_text(diff, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout="", stderr="")

    return _run


def test_extract_diff_accepts_plain_diff() -> None:
    out = _extract_diff(_FAKE_DIFF)
    assert "--- a/src/foo.py" in out
    assert out.endswith("\n")


def test_extract_diff_strips_markdown_fence() -> None:
    fenced = "```diff\n" + _FAKE_DIFF + "```\n"
    out = _extract_diff(fenced)
    assert "--- a/src/foo.py" in out
    assert "```" not in out


def test_extract_diff_rejects_non_diff_text() -> None:
    assert _extract_diff("Sorry, I cannot help with that.") == ""
    assert _extract_diff("") == ""


def test_agent_requires_codex_binary() -> None:
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="codex CLI not found"):
            CodexSWEBenchAgent()


def test_agent_returns_patch_on_success() -> None:
    with patch("shutil.which", return_value="/usr/bin/codex"):
        agent = CodexSWEBenchAgent(model="gpt-5.4", timeout_s=30.0)
    with patch("subprocess.run", side_effect=_fake_codex(_FAKE_DIFF)):
        result = agent.solve(_TASK)
    assert result.success is True
    assert "--- a/src/foo.py" in result.patch
    assert result.metadata["model"] == "gpt-5.4"
    assert result.metadata["exit_code"] == 0
    assert result.metadata["patch_length"] > 0


def test_agent_returns_empty_on_non_diff_reply() -> None:
    with patch("shutil.which", return_value="/usr/bin/codex"):
        agent = CodexSWEBenchAgent(timeout_s=30.0)
    with patch(
        "subprocess.run",
        side_effect=_fake_codex("I'm sorry, I don't know how to fix this."),
    ):
        result = agent.solve(_TASK)
    assert result.success is False
    assert result.patch == ""


def test_agent_handles_nonzero_exit() -> None:
    with patch("shutil.which", return_value="/usr/bin/codex"):
        agent = CodexSWEBenchAgent(timeout_s=30.0)
    with patch("subprocess.run", side_effect=_fake_codex("", returncode=1)):
        result = agent.solve(_TASK)
    assert result.success is False
    assert result.metadata["exit_code"] == 1


def test_agent_handles_timeout() -> None:
    with patch("shutil.which", return_value="/usr/bin/codex"):
        agent = CodexSWEBenchAgent(timeout_s=1.0)

    def _boom(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="codex", timeout=1.0)

    with patch("subprocess.run", side_effect=_boom):
        result = agent.solve(_TASK)
    assert result.success is False
    assert result.metadata.get("error") == "timeout"


def test_prompt_includes_task_context() -> None:
    with patch("shutil.which", return_value="/usr/bin/codex"):
        agent = CodexSWEBenchAgent()
    prompt = agent._build_prompt(_TASK)
    assert "django__django-11099" in prompt
    assert "django/django" in prompt
    assert "UsernameValidator" in prompt
    assert "test_unicode" in prompt
