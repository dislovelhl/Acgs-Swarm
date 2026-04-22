"""ClaudeSWEBenchAgent — SWEBenchAgent backed by the Anthropic Messages API.

Wires :class:`SWEBenchAgent._generate_patch()` to ``anthropic.Anthropic``
so Claude (e.g. ``claude-sonnet-4-5``) produces unified diffs for
SWE-bench-shaped tasks.

Requirements
------------
- ``anthropic>=0.84`` installed (``pip install anthropic``)
- ``ANTHROPIC_API_KEY`` set in the environment (or pass ``api_key`` kwarg)

Usage
-----
>>> agent = ClaudeSWEBenchAgent(model="claude-sonnet-4-5", timeout_s=180)
>>> result = agent.solve(task)   # task dict from load_instances()
"""

from __future__ import annotations

import logging
import re
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


class ClaudeSWEBenchAgent(SWEBenchAgent):
    """SWEBenchAgent that delegates patch generation to the Anthropic Messages API.

    Parameters
    ----------
    model:
        Anthropic model identifier. Defaults to ``claude-sonnet-4-5``.
    api_key:
        Anthropic API key. Falls back to ``ANTHROPIC_API_KEY`` env var.
    timeout_s:
        Hard timeout passed to the HTTP client; also recorded in ``SWEPatch``.
    max_new_tokens:
        Maximum tokens for the completion (``max_tokens`` in the API).
    system_prompt:
        Optional system-turn content. Defaults to a concise coding persona.
    extra_kwargs:
        Additional kwargs forwarded to ``client.messages.create()``.
    """

    _DEFAULT_MODEL = "claude-sonnet-4-5"
    _DEFAULT_SYSTEM = (
        "You are an expert software engineer. "
        "When asked to fix a bug, output only the unified diff — "
        "no explanation, no code fences, no markdown."
    )

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        timeout_s: float = 180.0,
        max_new_tokens: int = 2048,
        system_prompt: str | None = None,
        extra_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._model = model or self._DEFAULT_MODEL
        super().__init__(
            model_name=self._model,
            timeout_s=timeout_s,
            max_new_tokens=max_new_tokens,
            **kwargs,
        )
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required. Install with `pip install anthropic`."
            ) from exc
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self._system = system_prompt or self._DEFAULT_SYSTEM
        self._extra_kwargs: dict[str, Any] = dict(extra_kwargs or {})

    # ------------------------------------------------------------------
    # Internal helpers
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
        import anthropic

        prompt = self._build_prompt(task)
        stats: dict[str, Any] = {
            "model": self._model,
            "intervention_rate": 0.0,
        }
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self.max_new_tokens,
                system=self._system,
                messages=[{"role": "user", "content": prompt}],
                **self._extra_kwargs,
            )
        except anthropic.APIStatusError as exc:
            _log.warning("Anthropic API error %s: %s", exc.status_code, exc.message)
            stats["error"] = f"api_status_{exc.status_code}"
            stats["stderr_tail"] = str(exc.message)[:500]
            return "", stats
        except anthropic.APIConnectionError as exc:
            _log.warning("Anthropic connection error: %s", exc)
            stats["error"] = "connection_error"
            stats["stderr_tail"] = str(exc)[:500]
            return "", stats
        except anthropic.APITimeoutError:
            _log.warning("Anthropic request timed out after %.0fs", self.timeout_s)
            stats["error"] = "timeout"
            return "", stats

        raw = ""
        if response.content:
            raw = response.content[0].text if hasattr(response.content[0], "text") else ""

        usage = response.usage
        stats["input_tokens"] = usage.input_tokens if usage else 0
        stats["output_tokens"] = usage.output_tokens if usage else 0
        stats["stop_reason"] = response.stop_reason

        patch = _extract_diff(raw)
        stats["raw_length"] = len(raw)
        stats["patch_length"] = len(patch)
        return patch, stats


def _extract_diff(text: str) -> str:
    """Extract a unified diff from *text*, stripping markdown code fences."""
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    if not _DIFF_MARKER.search(stripped):
        return ""
    return stripped + ("\n" if not stripped.endswith("\n") else "")


__all__ = ["ClaudeSWEBenchAgent"]
