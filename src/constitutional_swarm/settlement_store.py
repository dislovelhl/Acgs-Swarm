"""Settlement storage adapters for finalized mesh results.

The mesh only persists finalized assignment/result snapshots. Storage backends
implement a tiny append/load contract so future SQLite or object-store adapters
can slot in without changing mesh finality logic.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class SettlementRecord:
    """Serialized settled assignment/result snapshot."""

    assignment: dict[str, Any]
    result: dict[str, Any]


class SettlementStore(Protocol):
    """Minimal append/load interface for settled mesh records."""

    def append(self, record: SettlementRecord) -> None: ...

    def load_all(self) -> list[SettlementRecord]: ...

    def describe(self) -> dict[str, Any]: ...


class JSONLSettlementStore:
    """Append-only JSONL settlement store.

    Each line stores exactly one settled assignment/result snapshot. This is the
    default adapter for local development and single-node deployments.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, record: SettlementRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "assignment": record.assignment,
            "result": record.result,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def load_all(self) -> list[SettlementRecord]:
        if not self.path.exists():
            return []

        records: list[SettlementRecord] = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                records.append(
                    SettlementRecord(
                        assignment=dict(payload["assignment"]),
                        result=dict(payload["result"]),
                    )
                )
        return records

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "jsonl",
            "path": str(self.path),
        }


class SQLiteSettlementStore:
    """SQLite-backed settlement store.

    Stores one row per settled assignment/result snapshot. Uses only the Python
    standard library so it remains available in minimal environments.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mesh_settlements (
                    assignment_id TEXT PRIMARY KEY,
                    assignment_json TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def append(self, record: SettlementRecord) -> None:
        assignment_id = str(record.assignment["assignment_id"])
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO mesh_settlements (
                    assignment_id,
                    assignment_json,
                    result_json
                ) VALUES (?, ?, ?)
                """,
                (
                    assignment_id,
                    json.dumps(record.assignment, separators=(",", ":")),
                    json.dumps(record.result, separators=(",", ":")),
                ),
            )
            conn.commit()

    def load_all(self) -> list[SettlementRecord]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT assignment_json, result_json
                FROM mesh_settlements
                ORDER BY assignment_id
                """
            ).fetchall()
        return [
            SettlementRecord(
                assignment=dict(json.loads(assignment_json)),
                result=dict(json.loads(result_json)),
            )
            for assignment_json, result_json in rows
        ]

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "sqlite",
            "path": str(self.path),
        }


__all__ = [
    "JSONLSettlementStore",
    "SQLiteSettlementStore",
    "SettlementRecord",
    "SettlementStore",
]
