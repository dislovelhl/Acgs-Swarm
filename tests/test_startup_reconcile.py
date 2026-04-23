"""Focused startup reconciliation tests for ConstitutionalMesh."""

from __future__ import annotations

from dataclasses import replace

import pytest
from constitutional_swarm import (
    ConstitutionalMesh,
    JSONLSettlementStore,
    ReconciliationReport,
    SettlementRecord,
)

from acgs_lite import Constitution


class _SelectiveFailingSettlementStore:
    """In-memory settlement store that can fail selected Phase 2 commits."""

    def __init__(self, *, failing_assignment_ids: set[str] | None = None) -> None:
        self._failing_assignment_ids = (
            set() if failing_assignment_ids is None else set(failing_assignment_ids)
        )
        self._settled: dict[str, SettlementRecord] = {}
        self._pending: dict[str, SettlementRecord] = {}

    def append(self, record: SettlementRecord) -> None:
        assignment_id = str(record.assignment["assignment_id"])
        if assignment_id in self._failing_assignment_ids:
            raise OSError(f"phase 2 commit failed for {assignment_id}")
        self._settled[assignment_id] = record

    def load_all(self) -> list[SettlementRecord]:
        return list(self._settled.values())

    def mark_pending(self, record: SettlementRecord) -> None:
        self._pending[str(record.assignment["assignment_id"])] = record

    def clear_pending(self, assignment_id: str) -> None:
        self._pending.pop(assignment_id, None)

    def load_pending(self) -> list[SettlementRecord]:
        return list(self._pending.values())

    def pending_count(self) -> int:
        return len(self._pending)

    def describe(self) -> dict[str, str]:
        return {"backend": "test-double"}


def _build_pending_record(
    artifact_id: str,
    *,
    seed: int,
    is_recovered: bool = False,
) -> tuple[Constitution, SettlementRecord]:
    constitution = Constitution.default()
    source_mesh = ConstitutionalMesh(constitution, seed=seed)
    for i in range(5):
        source_mesh.register_local_signer(f"agent-{i:02d}")

    result = source_mesh.full_validation("agent-00", "safe output", artifact_id)
    assignment = source_mesh._assignments[result.assignment_id]
    record = SettlementRecord(
        assignment=source_mesh._serialize_assignment(assignment),
        result=source_mesh._serialize_result(result),
        constitutional_hash=result.constitutional_hash,
        is_recovered=is_recovered,
    )
    if not is_recovered:
        record = replace(
            record,
            assignment={**record.assignment, "is_recovered": False},
        )
    return constitution, record


def test_reconcile_pending_settlements_reports_empty_store(tmp_path) -> None:
    store = JSONLSettlementStore(tmp_path / "mesh-empty.jsonl")
    mesh = ConstitutionalMesh(Constitution.default(), seed=201, settlement_store=store)

    report = mesh.reconcile_pending_settlements()

    assert report == ReconciliationReport()


def test_reconcile_pending_settlements_skips_recovered_pending_record(tmp_path) -> None:
    constitution, record = _build_pending_record(
        "art-reconcile-recovered",
        seed=202,
        is_recovered=True,
    )
    store = _SelectiveFailingSettlementStore()
    store.mark_pending(record)

    mesh = ConstitutionalMesh(
        constitution,
        seed=203,
        settlement_store=store,
        auto_reconcile=False,
    )
    report = mesh.reconcile_pending_settlements()

    assert report.attempted == 0
    assert report.settled == 0
    assert report.skipped_recovered == 1
    assert report.failed == 0
    assert report.errors == []
    assert store.load_pending() == []
    assert store.load_all() == []


def test_reconcile_pending_settlements_settles_unrecovered_pending_record(tmp_path) -> None:
    constitution, record = _build_pending_record(
        "art-reconcile-unrecovered",
        seed=204,
        is_recovered=False,
    )
    store = JSONLSettlementStore(tmp_path / "mesh-unrecovered.jsonl")
    store.mark_pending(record)

    mesh = ConstitutionalMesh(
        constitution,
        seed=205,
        settlement_store=store,
        auto_reconcile=False,
    )
    report = mesh.reconcile_pending_settlements()
    restored = mesh.get_result(str(record.assignment["assignment_id"]))

    assert report.attempted == 1
    assert report.settled == 1
    assert report.skipped_recovered == 0
    assert report.failed == 0
    assert report.errors == []
    assert restored.settled is True
    assert restored.proof is not None
    assert restored.proof.verify() is True
    assert store.load_pending() == []
    loaded = store.load_all()
    assert len(loaded) == 1
    assert loaded[0].is_recovered is True


def test_auto_reconcile_false_defers_until_manual_call(tmp_path) -> None:
    constitution, record = _build_pending_record(
        "art-reconcile-manual",
        seed=206,
        is_recovered=False,
    )
    store = JSONLSettlementStore(tmp_path / "mesh-manual.jsonl")
    store.mark_pending(record)

    mesh = ConstitutionalMesh(
        constitution,
        seed=207,
        settlement_store=store,
        auto_reconcile=False,
    )

    with pytest.raises(KeyError):
        mesh.get_result(str(record.assignment["assignment_id"]))

    report = mesh.reconcile_pending_settlements()
    restored = mesh.get_result(str(record.assignment["assignment_id"]))

    assert report.attempted == 1
    assert report.settled == 1
    assert report.skipped_recovered == 0
    assert report.failed == 0
    assert report.errors == []
    assert restored.settled is True
    assert store.load_pending() == []


def test_reconcile_pending_settlements_captures_failures_and_continues() -> None:
    constitution, failing_record = _build_pending_record(
        "art-reconcile-fail",
        seed=208,
        is_recovered=False,
    )
    _, succeeding_record = _build_pending_record(
        "art-reconcile-success",
        seed=209,
        is_recovered=False,
    )
    store = _SelectiveFailingSettlementStore(
        failing_assignment_ids={str(failing_record.assignment["assignment_id"])}
    )
    store.mark_pending(failing_record)
    store.mark_pending(succeeding_record)

    mesh = ConstitutionalMesh(
        constitution,
        seed=210,
        settlement_store=store,
        auto_reconcile=False,
    )

    report = mesh.reconcile_pending_settlements()
    restored = mesh.get_result(str(succeeding_record.assignment["assignment_id"]))

    assert report.attempted == 2
    assert report.settled == 1
    assert report.skipped_recovered == 0
    assert report.failed == 1
    assert len(report.errors) == 1
    assert "phase 2 commit failed" in report.errors[0]
    assert restored.settled is True
    assert store.pending_count() == 1


def test_reconcile_pending_settlements_is_idempotent(tmp_path) -> None:
    constitution, record = _build_pending_record(
        "art-reconcile-idempotent",
        seed=211,
        is_recovered=False,
    )
    store = JSONLSettlementStore(tmp_path / "mesh-idempotent.jsonl")
    store.mark_pending(record)
    mesh = ConstitutionalMesh(
        constitution,
        seed=212,
        settlement_store=store,
        auto_reconcile=False,
    )

    first_report = mesh.reconcile_pending_settlements()
    second_report = mesh.reconcile_pending_settlements()

    assert first_report.attempted == 1
    assert first_report.settled == 1
    assert second_report == ReconciliationReport()
