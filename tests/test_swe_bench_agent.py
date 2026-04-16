"""Tests for the SWE-bench scaffolding (agent + harness).

All tests are mock-based — no Docker, no network, no LLM calls.
They verify the protocol contracts, not execution outcomes.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch
from constitutional_swarm.swe_bench.harness import (
    SWEBenchHarness,
    _load_jsonl,
    load_swe_bench_lite,
)

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────


def _make_task(instance_id: str = "repo__repo-1") -> dict:
    return {
        "instance_id": instance_id,
        "problem_statement": f"Fix bug in {instance_id}",
        "patch": "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n",
        "FAIL_TO_PASS": ["tests/test_x.py::test_y"],
    }


def _make_tasks(n: int = 5) -> list[dict]:
    return [_make_task(f"repo__repo-{i}") for i in range(n)]


# ──────────────────────────────────────────────────────────────────────────────
# SWEPatch dataclass
# ──────────────────────────────────────────────────────────────────────────────


def test_swe_patch_defaults() -> None:
    p = SWEPatch(task_id="t1", patch="diff", success=True)
    assert p.governed is False
    assert p.intervention_rate == 0.0
    assert p.duration_s == 0.0
    assert p.metadata == {}


def test_swe_patch_governed_fields() -> None:
    p = SWEPatch(
        task_id="t1",
        patch="diff",
        success=True,
        governed=True,
        intervention_rate=0.35,
        duration_s=1.2,
        metadata={"model": "test"},
    )
    assert p.governed is True
    assert p.intervention_rate == pytest.approx(0.35)
    assert p.metadata["model"] == "test"


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchAgent — baseline (no wrapper)
# ──────────────────────────────────────────────────────────────────────────────


def test_agent_solve_stub_returns_patch() -> None:
    """Default stub returns an empty patch with success=False."""
    agent = SWEBenchAgent()
    result = agent.solve(_make_task())
    assert isinstance(result, SWEPatch)
    assert result.task_id == "repo__repo-1"
    assert result.governed is False
    assert result.patch == ""
    assert result.success is False


def test_agent_solve_uses_instance_id() -> None:
    agent = SWEBenchAgent()
    result = agent.solve(_make_task("myrepo__123"))
    assert result.task_id == "myrepo__123"


def test_agent_solve_missing_instance_id() -> None:
    """Missing instance_id falls back to 'unknown'."""
    agent = SWEBenchAgent()
    result = agent.solve({"problem_statement": "no id"})
    assert result.task_id == "unknown"


def test_agent_duration_is_positive() -> None:
    agent = SWEBenchAgent()
    result = agent.solve(_make_task())
    assert result.duration_s >= 0.0


def test_agent_metadata_contains_model() -> None:
    agent = SWEBenchAgent(model_name="my-model")
    result = agent.solve(_make_task())
    assert result.metadata.get("model") == "my-model"


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchAgent — with wrapper mock
# ──────────────────────────────────────────────────────────────────────────────


def test_agent_governed_flag_set_when_wrapper_present() -> None:
    """When a wrapper is provided, result.governed must be True."""
    wrapper = MagicMock()
    agent = SWEBenchAgent(wrapper=wrapper)
    result = agent.solve(_make_task())
    assert result.governed is True


def test_agent_governed_metadata_key_set() -> None:
    wrapper = MagicMock()
    agent = SWEBenchAgent(wrapper=wrapper)
    result = agent.solve(_make_task())
    assert result.metadata.get("governed") is True


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchAgent — custom _generate_patch override
# ──────────────────────────────────────────────────────────────────────────────


class _PatchingAgent(SWEBenchAgent):
    """Test double that always returns a fixed patch."""

    def _generate_patch(
        self, task: dict
    ) -> tuple[str, dict]:
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-bad\n+good\n"
        return diff, {"intervention_rate": 0.1, "total_tokens": 100, "steered_tokens": 10}


def test_custom_agent_success_true() -> None:
    agent = _PatchingAgent()
    result = agent.solve(_make_task())
    assert result.success is True
    assert result.patch.startswith("---")


def test_custom_agent_intervention_rate() -> None:
    agent = _PatchingAgent()
    result = agent.solve(_make_task())
    assert result.intervention_rate == pytest.approx(0.1)


def test_agent_handles_exception_gracefully() -> None:
    """_generate_patch exception must return success=False without re-raising."""

    class _BrokenAgent(SWEBenchAgent):
        def _generate_patch(self, task: dict) -> tuple[str, dict]:
            raise RuntimeError("LLM exploded")

    agent = _BrokenAgent()
    result = agent.solve(_make_task())
    assert result.success is False
    assert result.metadata["error"] == "RuntimeError"


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchHarness — run
# ──────────────────────────────────────────────────────────────────────────────


def test_harness_run_returns_all_results() -> None:
    tasks = _make_tasks(3)
    harness = SWEBenchHarness(tasks)
    agent = SWEBenchAgent()
    results = harness.run(agent)
    assert len(results) == 3


def test_harness_run_max_tasks() -> None:
    harness = SWEBenchHarness(_make_tasks(10))
    agent = SWEBenchAgent()
    results = harness.run(agent, max_tasks=4)
    assert len(results) == 4


def test_harness_run_empty_tasks() -> None:
    harness = SWEBenchHarness([])
    results = harness.run(SWEBenchAgent())
    assert results == []


def test_harness_iter_results_yields_patches() -> None:
    tasks = _make_tasks(3)
    harness = SWEBenchHarness(tasks)
    patches = list(harness.iter_results(SWEBenchAgent()))
    assert len(patches) == 3
    assert all(isinstance(p, SWEPatch) for p in patches)


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchHarness — summary
# ──────────────────────────────────────────────────────────────────────────────


def test_summary_empty() -> None:
    s = SWEBenchHarness.summary([])
    assert s["total"] == 0
    assert s["resolve_rate"] == 0.0


def test_summary_all_failed() -> None:
    results = [
        SWEPatch(task_id=f"t{i}", patch="", success=False) for i in range(5)
    ]
    s = SWEBenchHarness.summary(results)
    assert s["total"] == 5
    assert s["resolved"] == 0
    assert s["resolve_rate"] == pytest.approx(0.0)


def test_summary_partial_success() -> None:
    results = [
        SWEPatch(task_id="t0", patch="diff", success=True),
        SWEPatch(task_id="t1", patch="", success=False),
        SWEPatch(task_id="t2", patch="diff", success=True),
        SWEPatch(task_id="t3", patch="", success=False),
    ]
    s = SWEBenchHarness.summary(results)
    assert s["resolved"] == 2
    assert s["resolve_rate"] == pytest.approx(0.5)


def test_summary_governed_mean_intervention() -> None:
    results = [
        SWEPatch("t0", "d", True, governed=True, intervention_rate=0.2),
        SWEPatch("t1", "d", True, governed=True, intervention_rate=0.4),
        SWEPatch("t2", "d", True, governed=False, intervention_rate=0.0),
    ]
    s = SWEBenchHarness.summary(results)
    assert s["governed_count"] == 2
    assert s["mean_intervention"] == pytest.approx(0.3)


# ──────────────────────────────────────────────────────────────────────────────
# SWEBenchHarness — serialization
# ──────────────────────────────────────────────────────────────────────────────


def test_to_and_from_jsonl_round_trip() -> None:
    results = [
        SWEPatch("t0", "diff_a", True, governed=True, intervention_rate=0.1),
        SWEPatch("t1", "", False),
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "results.jsonl"
        SWEBenchHarness.to_jsonl(results, path)
        loaded = SWEBenchHarness.from_jsonl(path)

    assert len(loaded) == 2
    assert loaded[0].task_id == "t0"
    assert loaded[0].governed is True
    assert loaded[0].intervention_rate == pytest.approx(0.1)
    assert loaded[1].success is False


def test_to_jsonl_creates_parent_dir() -> None:
    results = [SWEPatch("t0", "d", True)]
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "nested" / "dir" / "results.jsonl"
        SWEBenchHarness.to_jsonl(results, path)
        assert path.exists()


# ──────────────────────────────────────────────────────────────────────────────
# load_swe_bench_lite — fallback path (no swebench installed)
# ──────────────────────────────────────────────────────────────────────────────


def test_load_from_local_jsonl(tmp_path: Path) -> None:
    """When a local JSONL file is present, load_swe_bench_lite uses it."""
    tasks = [_make_task(f"repo-{i}") for i in range(4)]
    jsonl = tmp_path / "test.jsonl"
    jsonl.write_text("\n".join(json.dumps(t) for t in tasks))

    loaded = load_swe_bench_lite(split="test", data_dir=tmp_path)
    assert len(loaded) == 4
    assert loaded[0]["instance_id"] == "repo-0"


def test_load_from_local_jsonl_max_tasks(tmp_path: Path) -> None:
    tasks = [_make_task(f"repo-{i}") for i in range(10)]
    jsonl = tmp_path / "test.jsonl"
    jsonl.write_text("\n".join(json.dumps(t) for t in tasks))

    loaded = load_swe_bench_lite(split="test", data_dir=tmp_path, max_tasks=3)
    assert len(loaded) == 3


def test_load_returns_empty_when_no_source(tmp_path: Path) -> None:
    """Missing JSONL + no swebench → empty list, no exception."""
    # Patch import to simulate swebench not installed
    with patch.dict("sys.modules", {"swebench": None, "swebench.harness": None, "swebench.harness.utils": None}):
        loaded = load_swe_bench_lite(split="test", data_dir=tmp_path)
    assert loaded == []


# ──────────────────────────────────────────────────────────────────────────────
# _load_jsonl helper
# ──────────────────────────────────────────────────────────────────────────────


def test_load_jsonl_skips_blank_lines(tmp_path: Path) -> None:
    content = '{"a": 1}\n\n{"b": 2}\n\n'
    path = tmp_path / "data.jsonl"
    path.write_text(content)
    records = _load_jsonl(path)
    assert len(records) == 2
    assert records[0] == {"a": 1}
    assert records[1] == {"b": 2}
