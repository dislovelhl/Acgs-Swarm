

# ── Security regression tests ─────────────────────────────────────────────────


class TestJSONLSettlementStoreLocking:
    """P2: JSONLSettlementStore must be safe under concurrent writes."""

    def test_concurrent_appends_no_duplicates(self, tmp_path):
        """Concurrent appends with different IDs should all succeed."""
        import threading
        from constitutional_swarm.settlement_store import (
            JSONLSettlementStore, SettlementRecord,
        )

        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        errors = []

        def _append(i):
            try:
                record = SettlementRecord(
                    assignment={"assignment_id": str(i), "agent": f"agent-{i}"},
                    result={"ok": True},
                    constitutional_hash="abc123",
                )
                store.append(record)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_append, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Concurrent appends produced errors: {errors}"
        records = store.load_all()
        ids = [r.assignment["assignment_id"] for r in records]
        assert len(ids) == len(set(ids)), "No duplicate assignment IDs should be in the log"
        assert len(ids) == 20

    def test_truncated_terminal_line_repaired_on_load(self, tmp_path):
        """A truncated last line must be skipped with a warning, not a crash."""
        import warnings
        from constitutional_swarm.settlement_store import JSONLSettlementStore
        import json

        p = tmp_path / "settlements.jsonl"
        good = {"assignment": {"assignment_id": "1"}, "result": {}, "constitutional_hash": ""}
        # Write a valid line followed by a truncated line (no newline, incomplete JSON)
        p.write_text(json.dumps(good) + "\n" + '{"assignment":{"assignment_id":"2","age', encoding="utf-8")

        store = JSONLSettlementStore(p)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            records = store.load_all()
        assert len(records) == 1
        assert records[0].assignment["assignment_id"] == "1"
        assert any("truncated" in str(warning.message).lower() for warning in w)
        # After load, the file must be truncated (partial line removed)
        assert p.read_text(encoding="utf-8").endswith("\n")

    def test_msvcrt_file_lock_used_when_fcntl_disabled(self, tmp_path, monkeypatch):
        """Module import must remain usable on Windows-style runtimes."""
        import constitutional_swarm.settlement_store as settlement_store

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
