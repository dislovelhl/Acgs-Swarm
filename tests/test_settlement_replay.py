from dataclasses import replace

import pytest
from constitutional_swarm import (
    ConstitutionalMesh,
    JSONLSettlementStore,
    RecoveredAssignmentError,
    SQLiteSettlementStore,
)

from acgs_lite import Constitution


def _jsonl_store(tmp_path):
    return JSONLSettlementStore(tmp_path / "mesh-settlements.jsonl")


def _sqlite_store(tmp_path):
    return SQLiteSettlementStore(tmp_path / "mesh-settlements.db")


def _make_mesh(
    constitution: Constitution,
    *,
    store: JSONLSettlementStore | SQLiteSettlementStore,
    seed: int,
) -> ConstitutionalMesh:
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=3,
        quorum=2,
        seed=seed,
        settlement_store=store,
    )
    for index in range(5):
        mesh.register_local_signer(f"agent-{index:02d}")
    return mesh


def _settle_assignment(mesh: ConstitutionalMesh, artifact_id: str) -> str:
    assignment = mesh.request_validation("agent-00", "safe output", artifact_id)
    for peer_id in assignment.peers[:2]:
        signature = mesh.sign_vote(
            assignment.assignment_id,
            peer_id,
            approved=True,
            reason="constitutional check passed",
        )
        mesh.submit_vote(
            assignment.assignment_id,
            peer_id,
            approved=True,
            reason="constitutional check passed",
            signature=signature,
        )
    result = mesh.get_result(assignment.assignment_id)
    assert result.settled is True
    return assignment.assignment_id


@pytest.mark.parametrize("store_factory", [_jsonl_store, _sqlite_store], ids=["jsonl", "sqlite"])
def test_settling_assignment_marks_recovered(tmp_path, store_factory) -> None:
    constitution = Constitution.default()
    store = store_factory(tmp_path)
    mesh = _make_mesh(constitution, store=store, seed=41)

    assignment_id = _settle_assignment(mesh, "art-recovered-flag")

    assert mesh._assignments[assignment_id].is_recovered is True
    records = store.load_all()
    assert len(records) == 1
    assert records[0].is_recovered is True
    assert store.load_pending() == []


@pytest.mark.parametrize("store_factory", [_jsonl_store, _sqlite_store], ids=["jsonl", "sqlite"])
def test_resettling_recovered_assignment_raises(tmp_path, store_factory) -> None:
    constitution = Constitution.default()
    store = store_factory(tmp_path)
    mesh = _make_mesh(constitution, store=store, seed=43)

    assignment_id = _settle_assignment(mesh, "art-recovered-error")

    with pytest.raises(RecoveredAssignmentError, match="durably settled"):
        mesh.settle(assignment_id)


@pytest.mark.parametrize("store_factory", [_jsonl_store, _sqlite_store], ids=["jsonl", "sqlite"])
def test_retry_pending_settlements_skips_recovered_entries(tmp_path, store_factory) -> None:
    constitution = Constitution.default()
    store = store_factory(tmp_path)
    writer = _make_mesh(constitution, store=store, seed=47)

    assignment_id = _settle_assignment(writer, "art-retry-skip")
    recovered_record = store.load_all()[0]

    reader = ConstitutionalMesh(constitution, seed=53, settlement_store=store)
    store.mark_pending(replace(recovered_record, is_recovered=False))

    report = reader.retry_pending_settlements()

    assert report.attempted == 0
    assert report.settled == 0
    assert report.skipped_recovered == 1
    assert report.failed == 0
    assert report.errors == []
    assert len(store.load_all()) == 1
    assert reader._assignments[assignment_id].is_recovered is True
    assert store.load_pending() == []


@pytest.mark.parametrize("store_factory", [_jsonl_store, _sqlite_store], ids=["jsonl", "sqlite"])
def test_recovered_assignment_round_trips_from_store(tmp_path, store_factory) -> None:
    constitution = Constitution.default()
    store = store_factory(tmp_path)
    writer = _make_mesh(constitution, store=store, seed=59)

    assignment_id = _settle_assignment(writer, "art-round-trip")

    reader = ConstitutionalMesh(constitution, seed=61, settlement_store=store)
    restored = reader.get_result(assignment_id)

    assert restored.settled is True
    assert reader._assignments[assignment_id].is_recovered is True
