import json
import threading
import warnings

import constitutional_swarm.settlement_store as settlement_store
from constitutional_swarm import JSONLSettlementStore, SettlementRecord


def _make_record(assignment_id: str, *, schema_version: int = 1) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "agent": f"agent-{assignment_id}"},
        result={"ok": True, "assignment_id": assignment_id},
        constitutional_hash="abc123",
        schema_version=schema_version,
    )


class TestJSONLSettlementStoreLocking:
    """P2: JSONLSettlementStore must be safe under concurrent writes."""

    def test_concurrent_appends_no_duplicates(self, tmp_path):
        """Concurrent appends with different IDs should all succeed."""
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        errors = []

        def _append(i):
            try:
                store.append(_make_record(str(i)))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_append, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, f"Concurrent appends produced errors: {errors}"
        records = store.load_all()
        ids = [record.assignment["assignment_id"] for record in records]
        assert len(ids) == len(set(ids)), "No duplicate assignment IDs should be in the log"
        assert len(ids) == 20

    def test_truncated_terminal_line_repaired_on_load(self, tmp_path):
        """A truncated last line must be skipped with a warning, not a crash."""
        path = tmp_path / "settlements.jsonl"
        good = {
            "assignment": {"assignment_id": "1"},
            "result": {},
            "constitutional_hash": "",
            "schema_version": 1,
        }
        path.write_text(
            json.dumps(good) + "\n" + '{"assignment":{"assignment_id":"2","age',
            encoding="utf-8",
        )

        store = JSONLSettlementStore(path)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            records = store.load_all()

        assert len(records) == 1
        assert records[0].assignment["assignment_id"] == "1"
        assert any("truncated" in str(warning.message).lower() for warning in caught)
        assert path.read_text(encoding="utf-8").endswith("\n")

    def test_msvcrt_file_lock_used_when_fcntl_disabled(self, tmp_path, monkeypatch):
        """Module import must remain usable on Windows-style runtimes."""
        calls: list[tuple[int, int]] = []

        class _FakeMSVCRT:
            LK_LOCK = 1
            LK_UNLCK = 2

            @staticmethod
            def locking(fd: int, mode: int, length: int) -> None:
                calls.append((mode, length))

        store = settlement_store.JSONLSettlementStore(tmp_path / "settlements.jsonl")
        monkeypatch.setattr(settlement_store, "_fcntl", None)
        monkeypatch.setattr(settlement_store, "_msvcrt", _FakeMSVCRT)

        with store._file_lock():
            pass

        assert calls == [(_FakeMSVCRT.LK_LOCK, 1), (_FakeMSVCRT.LK_UNLCK, 1)]
