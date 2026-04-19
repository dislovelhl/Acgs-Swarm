"""SWEBenchAgent — single-agent solver scaffold for SWE-bench Lite.

This module defines the protocol for solving a SWE-bench task under optional
BODES governance.  It intentionally avoids Docker, network calls, or real code
execution so that the interface can be tested deterministically.

Integration points
------------------
- ``SWEBenchAgent.solve()`` calls ``_generate_patch()`` which in production
  would invoke an LLM.  Swap in a real model client by subclassing and
  overriding ``_generate_patch()``.
- The ``wrapper`` parameter wires in a :class:`LatentDNAWrapper` for BODES
  steering during generation.  Pass ``None`` to run ungoverned (baseline).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from constitutional_swarm.latent_dna import LatentDNAWrapper

_log = logging.getLogger(__name__)


@dataclass
class SWEPatch:
    """Output of a single SWE-bench solve attempt.

    Fields
    ------
    task_id:
        SWE-bench instance_id (e.g. ``"django__django-11099"``).
    patch:
        Unified diff string, or empty string if the agent failed.
    success:
        True when the agent produced a non-empty patch without timing out.
    governed:
        True when a :class:`LatentDNAWrapper` was active during generation.
    intervention_rate:
        Fraction of generated tokens where BODES steered the hidden state.
        0.0 when ``governed=False``.
    duration_s:
        Wall-clock seconds spent in ``solve()``.
    metadata:
        Any extra diagnostics (model name, token counts, etc.).
    """

    task_id: str
    patch: str
    success: bool
    governed: bool = False
    intervention_rate: float = 0.0
    duration_s: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class SWEBenchAgent:
    """Single-agent SWE-bench solver with optional BODES governance.

    In the baseline (``wrapper=None``) the agent is ungoverned.  Pass a
    :class:`~constitutional_swarm.latent_dna.LatentDNAWrapper` to activate
    BODES steering during every forward pass of generation.

    Parameters
    ----------
    wrapper:
        Optional BODES wrapper.  When provided, ``generate_governed()`` is
        called instead of a bare forward pass.
    model_name:
        String identifier recorded in result metadata.
    max_new_tokens:
        Token budget for patch generation.
    timeout_s:
        Hard timeout; ``SWEPatch.success`` will be False if exceeded.
    """

    def __init__(
        self,
        *,
        wrapper: LatentDNAWrapper | None = None,
        model_name: str = "constitutional-swarm-agent",
        max_new_tokens: int = 512,
        timeout_s: float = 60.0,
    ) -> None:
        self.wrapper = wrapper
        self.model_name = model_name
        self.max_new_tokens = max_new_tokens
        self.timeout_s = timeout_s

    # ──────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────

    def solve(self, task: dict[str, Any]) -> SWEPatch:
        """Attempt to solve a SWE-bench task.

        Parameters
        ----------
        task:
            A single SWE-bench Lite record.  Expected keys:
            - ``instance_id``: str — unique task identifier
            - ``problem_statement``: str — natural-language bug description
            - ``FAIL_TO_PASS``: list[str] — test IDs that should flip
            - ``patch``: str — ground-truth diff (for oracle comparison)

        Returns
        -------
        SWEPatch
            Structured result; ``success=False`` on timeout or empty patch.
        """
        task_id = task.get("instance_id", "unknown")
        t0 = time.monotonic()

        try:
            patch, stats = self._generate_patch(task)
        except TimeoutError:
            return SWEPatch(
                task_id=task_id,
                patch="",
                success=False,
                governed=self.wrapper is not None,
                duration_s=time.monotonic() - t0,
                metadata={"error": "timeout"},
            )
        except Exception as exc:  # noqa: BLE001
            err_id = uuid.uuid4().hex[:12]
            _log.error("solve failed [%s]: %s", err_id, exc, exc_info=True)
            return SWEPatch(
                task_id=task_id,
                patch="",
                success=False,
                governed=self.wrapper is not None,
                duration_s=time.monotonic() - t0,
                metadata={"error": type(exc).__name__, "error_id": err_id},
            )

        duration = time.monotonic() - t0
        return SWEPatch(
            task_id=task_id,
            patch=patch,
            success=bool(patch.strip()),
            governed=self.wrapper is not None,
            intervention_rate=stats.get("intervention_rate", 0.0),
            duration_s=duration,
            metadata={"model": self.model_name, **stats},
        )

    # ──────────────────────────────────────────────────────────────────────
    # Extension point: override in subclasses or test doubles
    # ──────────────────────────────────────────────────────────────────────

    def _generate_patch(
        self, task: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Generate a unified-diff patch for ``task``.

        Default implementation is a no-op stub that returns an empty patch.
        Override to wire in a real LLM call.

        If ``self.wrapper`` is set, production subclasses should call::

            output_ids, stats = self.wrapper.generate_governed(
                input_ids, tokenizer=tokenizer,
                max_new_tokens=self.max_new_tokens
            )

        Returns
        -------
        (patch_str, stats_dict)
        """
        # Stub: real implementation would tokenize the problem_statement,
        # call model.generate (or wrapper.generate_governed), and decode.
        stats: dict[str, Any] = {
            "total_tokens": 0,
            "steered_tokens": 0,
            "intervention_rate": 0.0,
        }
        if self.wrapper is not None:
            # Production path would be:
            # output_ids, stats = self.wrapper.generate_governed(...)
            stats["governed"] = True
        return "", stats
