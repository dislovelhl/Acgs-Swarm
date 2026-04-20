"""CodexSWEBenchAgent — SWEBenchAgent backed by the Codex CLI (GPT).

Wires :class:`SWEBenchAgent._generate_patch()` to ``codex exec`` so a real
LM produces unified diffs for SWE-bench-shaped tasks. Patch shape is
validated (non-empty, ``diff``/``---``/``+++`` markers) but **not** applied
or tested — full benchmark scoring still requires a Docker harness with the
instance repo checked out.

Usage
-----
>>> agent = CodexSWEBenchAgent(model="gpt-5.4", timeout_s=180)
>>> result = agent.solve(task)  # task from SWEBenchHarness

Requires the ``codex`` binary on ``$PATH`` (npm i -g @openai/codex) and a
logged-in ChatGPT/OpenAI account (``codex login``).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench.agent import SWEBenchAgent

_log = logging.getLogger(__name__)

_DIFF_MARKER = re.compile(r"(?m)^(?:diff --git |--- [ab]?/|\+\+\+ [ab]?/|@@ )")

_PROMPT_TEMPLATE = """\
You are solving a SWE-bench task. Produce a unified diff that fixes the bug.

Output rules:
- Reply with ONLY the unified diff, no prose, no code fences, no explanation.
- Use standard ``--- a/<path>`` and ``+++ b/<path>`` headers.
- Paths must be relative to the repository root.
- Do not modify tests unless the task explicitly requires it.

Instance: {instance_id}
Repository: {repo}
Base commit: {base_commit}

Tests that should flip from FAIL to PASS:
{fail_to_pass}

Problem statement:
{problem_statement}

{hints_section}Produce the patch now."""


class CodexSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates patch generation to ``codex exec``.

    Parameters
    ----------
    model:
        Codex model identifier passed via ``-m``. ``None`` uses the Codex
        default (typically ``gpt-5.4``).
    codex_binary:
        Override path to the ``codex`` CLI. Defaults to ``shutil.which("codex")``.
    timeout_s:
        Hard timeout for the subprocess (also returned in ``SWEPatch``).
    sandbox:
        Codex sandbox mode. ``read-only`` is safest; generation does not need
        to edit files.
    extra_args:
        Additional CLI args appended after the prompt (e.g. ``["--json"]``).
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        codex_binary: str | None = None,
        timeout_s: float = 180.0,
        sandbox: str = "read-only",
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            model_name=model or kwargs.pop("model_name", "codex-default"),
            timeout_s=timeout_s,
            **kwargs,
        )
        resolved = codex_binary or shutil.which("codex")
        if resolved is None:
            raise RuntimeError(
                "codex CLI not found on PATH. Install with `npm i -g @openai/codex` "
                "and authenticate with `codex login`."
            )
        self.codex_binary = resolved
        self.model = model
        self.sandbox = sandbox
        self.extra_args: list[str] = list(extra_args or [])

    # ------------------------------------------------------------------
    # Overrides
    # ------------------------------------------------------------------

    def _build_prompt(self, task: dict[str, Any]) -> str:
        fail_to_pass = task.get("FAIL_TO_PASS") or []
        if isinstance(fail_to_pass, str):
            fail_to_pass = [fail_to_pass]
        hints = task.get("hints_text") or ""
        hints_section = f"Hints:\n{hints.strip()}\n\n" if hints.strip() else ""
        return _PROMPT_TEMPLATE.format(
            instance_id=task.get("instance_id", "unknown"),
            repo=task.get("repo", "unknown"),
            base_commit=task.get("base_commit", "unknown"),
            fail_to_pass="\n".join(f"- {t}" for t in fail_to_pass) or "(none listed)",
            problem_statement=(task.get("problem_statement") or "").strip(),
            hints_section=hints_section,
        )

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        prompt = self._build_prompt(task)
        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            last_path = Path(tmp.name)
        try:
            cmd = [
                self.codex_binary,
                "exec",
                "--sandbox",
                self.sandbox,
                "--skip-git-repo-check",
                "--output-last-message",
                str(last_path),
            ]
            if self.model:
                cmd.extend(["-m", self.model])
            cmd.extend(self.extra_args)

            try:
                proc = subprocess.run(  # noqa: S603 — trusted binary path
                    cmd,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"codex exec timed out after {self.timeout_s}s") from exc

            stats: dict[str, Any] = {
                "model": self.model or "codex-default",
                "sandbox": self.sandbox,
                "exit_code": proc.returncode,
                "intervention_rate": 0.0,
            }
            if proc.returncode != 0:
                _log.warning("codex exec failed (%s): %s", proc.returncode, proc.stderr[-500:])
                stats["stderr_tail"] = proc.stderr[-500:]
                return "", stats

            try:
                last_message = last_path.read_text(encoding="utf-8")
            except OSError:
                last_message = ""
            patch = _extract_diff(last_message) or _extract_diff(proc.stdout)
            stats["raw_length"] = len(last_message)
            stats["patch_length"] = len(patch)
            return patch, stats
        finally:
            try:
                last_path.unlink()
            except OSError:
                pass


def _extract_diff(text: str) -> str:
    """Extract a unified diff from ``text``.

    Strips markdown code fences and requires at least one diff marker
    (``diff --git``, ``---``, ``+++``, or ``@@``). Returns empty string if no
    diff-shaped content is present.
    """
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("```"):
        # Remove leading/trailing code fence lines
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    if not _DIFF_MARKER.search(stripped):
        return ""
    return stripped + ("\n" if not stripped.endswith("\n") else "")


__all__ = ["CodexSWEBenchAgent"]
