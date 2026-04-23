import json
import sqlite3

from constitutional_swarm import JSONLSettlementStore, SettlementRecord, SQLiteSettlementStore


def _make_record(assignment_id: str, *, schema_version: int = 1) -> SettlementRecord:
    return SettlementRecord(
        assignment={"assignment_id": assignment_id, "agent": f"agent-{assignment_id}"},
        result={"ok": True, "assignment_id": assignment_id},
        constitutional_hash="abc123",
        schema_version=schema_version,
    )


def _drop_schema_version_column(db_path, table_name: str) -> None:
    if table_name == "mesh_settlements":
        create_legacy_table = """
            CREATE TABLE mesh_settlements_legacy (
                assignment_id TEXT PRIMARY KEY,
                assignment_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                constitutional_hash TEXT NOT NULL DEFAULT ''
            )
        """
        copy_rows = """
            INSERT INTO mesh_settlements_legacy (
                assignment_id,
                assignment_json,
                result_json,
                constitutional_hash
            )
            SELECT
                assignment_id,
                assignment_json,
                result_json,
                constitutional_hash
            FROM mesh_settlements
        """
        drop_table = "DROP TABLE mesh_settlements"
        rename_table = "ALTER TABLE mesh_settlements_legacy RENAME TO mesh_settlements"
    elif table_name == "pending_settlements":
        create_legacy_table = """
            CREATE TABLE pending_settlements_legacy (
                assignment_id TEXT PRIMARY KEY,
                assignment_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                constitutional_hash TEXT NOT NULL DEFAULT ''
            )
        """
        copy_rows = """
            INSERT INTO pending_settlements_legacy (
                assignment_id,
                assignment_json,
                result_json,
                constitutional_hash
            )
            SELECT
                assignment_id,
                assignment_json,
                result_json,
                constitutional_hash
            FROM pending_settlements
        """
        drop_table = "DROP TABLE pending_settlements"
        rename_table = "ALTER TABLE pending_settlements_legacy RENAME TO pending_settlements"
    else:  # pragma: no cover - test helper guard
        raise ValueError(f"Unsupported settlement table: {table_name}")

    with sqlite3.connect(db_path) as conn:
        conn.execute(create_legacy_table)
        conn.execute(copy_rows)
        conn.execute(drop_table)
        conn.execute(rename_table)
        conn.commit()


class TestSettlementSchemaVersion:
    def test_new_records_default_to_schema_version_one(self):
        record = SettlementRecord(
            assignment={"assignment_id": "default", "agent": "agent-default"},
            result={"ok": True},
            constitutional_hash="abc123",
        )

        assert record.schema_version == 1

    def test_old_jsonl_records_without_schema_version_load_as_v1(self, tmp_path):
        path = tmp_path / "settlements.jsonl"
        path.write_text(
            json.dumps(
                {
                    "assignment": {"assignment_id": "legacy", "agent": "agent-legacy"},
                    "result": {"ok": True},
                    "constitutional_hash": "abc123",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        store = JSONLSettlementStore(path)

        records = store.load_all()

        assert len(records) == 1
        assert records[0].schema_version == 1

    def test_explicit_schema_version_two_round_trips_via_jsonl(self, tmp_path):
        store = JSONLSettlementStore(tmp_path / "settlements.jsonl")
        record = _make_record("jsonl-v2", schema_version=2)

        store.append(record)
        store.mark_pending(record)

        assert store.load_all() == [record]
        assert store.load_pending() == [record]

    def test_old_sqlite_dbs_migrate_and_read_back_as_v1(self, tmp_path):
        path = tmp_path / "settlements.db"
        initial_store = SQLiteSettlementStore(path)
        finalized_record = _make_record("sqlite-finalized")
        pending_record = _make_record("sqlite-pending")

        initial_store.append(finalized_record)
        initial_store.mark_pending(pending_record)
        _drop_schema_version_column(path, "mesh_settlements")
        _drop_schema_version_column(path, "pending_settlements")

        migrated_store = SQLiteSettlementStore(path)

        with sqlite3.connect(path) as conn:
            mesh_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(mesh_settlements)").fetchall()
            }
            pending_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(pending_settlements)").fetchall()
            }

        assert "schema_version" in mesh_columns
        assert "schema_version" in pending_columns
        assert migrated_store.load_all() == [finalized_record]
        assert migrated_store.load_pending() == [pending_record]

    def test_explicit_schema_version_two_round_trips_via_sqlite(self, tmp_path):
        store = SQLiteSettlementStore(tmp_path / "settlements.db")
        record = _make_record("sqlite-v2", schema_version=2)

        store.append(record)
        store.mark_pending(record)

        assert store.load_all() == [record]
        assert store.load_pending() == [record]
