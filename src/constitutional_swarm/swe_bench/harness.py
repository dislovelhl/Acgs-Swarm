"""SWEBenchHarness — task loading, agent orchestration, and result aggregation.

The harness intentionally avoids Docker or live test execution so that its
core logic is unit-testable with injected task lists and mock agents.

Typical usage
-------------
.. code-block:: python

    harness = SWEBenchHarness(tasks=load_swe_bench_lite())
    agent = SWEBenchAgent()
    results = harness.run(agent, max_tasks=10)
    print(harness.summary(results))
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch

log = logging.getLogger(__name__)

# Default SWE-bench Lite dataset split path when swebench is not installed.
_DEFAULT_SPLIT = "princeton-nlp/SWE-bench_Lite"


def load_swe_bench_lite(
    *,
    split: str = "test",
    max_tasks: int | None = None,
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Load SWE-bench Lite tasks.

    Tries three strategies in order:

    1. Load from a local JSONL file at ``data_dir / f"{split}.jsonl"``
    2. Use the ``swebench`` Python package (``pip install swebench``)
    3. Fall back to an empty list (harness still functional for unit tests)

    Parameters
    ----------
    split:
        Dataset split — ``"test"`` (300 tasks) or ``"dev"`` (23 tasks).
    max_tasks:
        Truncate to this many tasks.  ``None`` = all.
    data_dir:
        Directory containing ``{split}.jsonl``.  Defaults to
        ``~/.cache/swebench/``.

    Returns
    -------
    list of task dicts with at minimum the keys:
    ``instance_id``, ``problem_statement``, ``patch``, ``FAIL_TO_PASS``.
    """
    # Strategy 1: local JSONL
    root = data_dir or Path.home() / ".cache" / "swebench"
    jsonl_path = root / f"{split}.jsonl"
    if jsonl_path.exists():
        tasks = _load_jsonl(jsonl_path)
        log.info("Loaded %d tasks from %s", len(tasks), jsonl_path)
        if max_tasks is not None:
            tasks = tasks[:max_tasks]
        return tasks

    # Strategy 2: swebench package
    try:
        from swebench.harness.utils import load_swebench_dataset  # type: ignore[import]

        dataset = load_swebench_dataset(_DEFAULT_SPLIT, split)
        tasks = list(dataset)
        log.info("Loaded %d tasks via swebench package", len(tasks))
        if max_tasks is not None:
            tasks = tasks[:max_tasks]
        return tasks
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        log.warning("swebench load failed: %s", type(exc).__name__)

    # Strategy 3: empty fallback
    log.warning(
        "SWE-bench dataset not found. Returning empty task list. "
        "Install swebench (pip install swebench) or place %s on disk.",
        jsonl_path,
    )
    return []


class SWEBenchHarness:
    """Run a :class:`SWEBenchAgent` against a list of SWE-bench tasks.

    Parameters
    ----------
    tasks:
        List of task dicts (from :func:`load_swe_bench_lite` or injected
        directly for testing).
    """

    def __init__(self, tasks: list[dict[str, Any]]) -> None:
        self.tasks = tasks

    # ──────────────────────────────────────────────────────────────────────
    # Running
    # ──────────────────────────────────────────────────────────────────────

    def run(
        self,
        agent: SWEBenchAgent,
        *,
        max_tasks: int | None = None,
    ) -> list[SWEPatch]:
        """Run ``agent`` on (up to) ``max_tasks`` tasks.

        Parameters
        ----------
        agent:
            Solver to evaluate.
        max_tasks:
            Cap on number of tasks to run.  ``None`` = all tasks.

        Returns
        -------
        list of :class:`SWEPatch` results in task order.
        """
        subset = self.tasks if max_tasks is None else self.tasks[:max_tasks]
        results: list[SWEPatch] = []
        for i, task in enumerate(subset):
            log.debug("Task %d/%d: %s", i + 1, len(subset), task.get("instance_id"))
            result = agent.solve(task)
            results.append(result)
        return results

    def iter_results(
        self,
        agent: SWEBenchAgent,
        *,
        max_tasks: int | None = None,
    ) -> Iterator[SWEPatch]:
        """Streaming variant of :meth:`run` — yields one :class:`SWEPatch` at a time."""
        subset = self.tasks if max_tasks is None else self.tasks[:max_tasks]
        for task in subset:
            yield agent.solve(task)

    # ──────────────────────────────────────────────────────────────────────
    # Aggregation
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def summary(results: list[SWEPatch]) -> dict[str, Any]:
        """Aggregate a list of results into a summary dict.

        Keys
        ----
        total:              Number of tasks attempted.
        resolved:           Tasks where success=True (non-empty patch).
        resolve_rate:       resolved / total.
        governed_count:     Tasks where wrapper was active.
        mean_intervention:  Mean intervention_rate across governed tasks.
        mean_duration_s:    Mean wall-clock time per task.
        """
        if not results:
            return {
                "total": 0,
                "resolved": 0,
                "resolve_rate": 0.0,
                "governed_count": 0,
                "mean_intervention": 0.0,
                "mean_duration_s": 0.0,
            }

        total = len(results)
        resolved = sum(1 for r in results if r.success)
        governed = [r for r in results if r.governed]
        mean_intervention = (
            sum(r.intervention_rate for r in governed) / len(governed) if governed else 0.0
        )
        mean_duration = sum(r.duration_s for r in results) / total

        return {
            "total": total,
            "resolved": resolved,
            "resolve_rate": resolved / total,
            "governed_count": len(governed),
            "mean_intervention": mean_intervention,
            "mean_duration_s": mean_duration,
        }

    @staticmethod
    def to_jsonl(results: list[SWEPatch], path: Path) -> None:
        """Serialize results to a JSONL file for downstream analysis."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as fh:
            for r in results:
                fh.write(json.dumps(asdict(r)) + "\n")

    @staticmethod
    def from_jsonl(path: Path) -> list[SWEPatch]:
        """Deserialize results from a JSONL file."""
        results = []
        for record in _load_jsonl(path):
            results.append(SWEPatch(**record))
        return results


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
