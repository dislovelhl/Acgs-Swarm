"""Settlement storage adapters for finalized mesh results.

The mesh only persists finalized assignment/result snapshots. Storage backends
implement a tiny append/load contract so future SQLite or object-store adapters
can slot in without changing mesh finality logic.
"""

from __future__ import annotations

import json
import os
import sqlite3
import warnings
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None

try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    _msvcrt = None


class DuplicateSettlementError(ValueError):
    """Raised when an append-only settlement store receives a duplicate key."""


@dataclass(frozen=True, slots=True)
class SettlementRecord:
    """Serialized settled assignment/result snapshot.

    ``constitutional_hash`` captures the governance document SHA256 that was
    active when the record was finalized.  This allows post-hoc audits to
    verify that each settlement operated under the correct constitutional
    version even if the constitution has been updated since.
    """

    assignment: dict[str, Any]
    result: dict[str, Any]
    constitutional_hash: str = ""


class SettlementStore(Protocol):
    """Minimal append/load interface for settled mesh records."""

    def append(self, record: SettlementRecord) -> None: ...

    def load_all(self) -> list[SettlementRecord]: ...

    def mark_pending(self, record: SettlementRecord) -> None: ...

    def clear_pending(self, assignment_id: str) -> None: ...

    def load_pending(self) -> list[SettlementRecord]: ...

    def pending_count(self) -> int: ...

    def describe(self) -> dict[str, Any]: ...


class JSONLSettlementStore:
    """Append-only JSONL settlement store.

    Each line stores exactly one settled assignment/result snapshot. This is the
    default adapter for local development and single-node deployments.

    File-level locking (``fcntl.LOCK_EX``) serialises concurrent ``append``
    and pending-update calls so that duplicate-detection and read-modify-write
    operations are atomic.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.pending_path = self.path.with_name(f"{self.path.name}.pending")
        self._lock_path = self.path.with_name(f"{self.path.name}.lock")

    @contextmanager
    def _file_lock(self) -> Generator[None, None, None]:
        """Acquire an exclusive advisory lock around the settlement log."""
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
            elif _msvcrt is not None:
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_LOCK, 1)
            else:  # pragma: no cover - platform fallback of last resort
                warnings.warn(
                    "No supported file-locking primitive available; settlement log lock disabled",
                    RuntimeWarning,
                    stacklevel=2,
                )
            yield
        finally:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
            elif _msvcrt is not None:
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
            os.close(fd)

    def append(self, record: SettlementRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        assignment_id = str(record.assignment["assignment_id"])
        with self._file_lock():
            for existing in self.load_all():
                if str(existing.assignment.get("assignment_id", "")) == assignment_id:
                    raise DuplicateSettlementError(f"Settlement {assignment_id} already exists")
            payload = {
                "assignment": record.assignment,
                "result": record.result,
                "constitutional_hash": record.constitutional_hash,
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def load_all(self) -> list[SettlementRecord]:
        if not self.path.exists():
            return []

        records: list[SettlementRecord] = []
        with self.path.open(encoding="utf-8") as fh:
            lines = fh.readlines()

        for lineno, line in enumerate(lines, start=1):
            raw_line = line
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                is_terminal_line = lineno == len(lines)
                # Salvage only the final truncated append. Earlier corruption
                # remains fail-loud because it indicates a damaged log, not an
                # interrupted final write.
                if is_terminal_line and not raw_line.endswith("\n"):
                    warnings.warn(
                        f"{self.path}:{lineno}: terminal truncated JSON line skipped",
                        stacklevel=2,
                    )
                    # Truncate the file to remove the partial line so the next
                    # append doesn't produce a permanently unreadable log.
                    with self.path.open("r+b") as fh_trunc:
                        fh_trunc.seek(-(len(raw_line.encode())), 2)
                        fh_trunc.truncate()
                    continue
                raise
            records.append(
                SettlementRecord(
                    assignment=dict(payload.get("assignment", {})),
                    result=dict(payload.get("result", {})),
                    constitutional_hash=payload.get("constitutional_hash", ""),
                )
            )
        return records

    def mark_pending(self, record: SettlementRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._file_lock():
            payloads = self._load_pending_payloads()
            assignment_id = str(record.assignment["assignment_id"])
            payloads[assignment_id] = self._payload_from_record(record)
            self._write_pending_payloads(payloads)

    def clear_pending(self, assignment_id: str) -> None:
        with self._file_lock():
            payloads = self._load_pending_payloads()
            if assignment_id not in payloads:
                return
            payloads.pop(assignment_id, None)
            self._write_pending_payloads(payloads)

    def load_pending(self) -> list[SettlementRecord]:
        return [
            self._record_from_payload(payload) for payload in self._load_pending_payloads().values()
        ]

    def pending_count(self) -> int:
        return len(self._load_pending_payloads())

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "jsonl",
            "path": str(self.path),
        }

    def _load_pending_payloads(self) -> dict[str, dict[str, Any]]:
        if not self.pending_path.exists():
            return {}
        with self.pending_path.open(encoding="utf-8") as fh:
            payloads = json.load(fh)
        return {str(key): dict(value) for key, value in dict(payloads).items()}

    def _write_pending_payloads(self, payloads: dict[str, dict[str, Any]]) -> None:
        if not payloads:
            self.pending_path.unlink(missing_ok=True)
            return
        tmp_path = self.pending_path.with_name(f"{self.pending_path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payloads, fh, separators=(",", ":"))
        tmp_path.replace(self.pending_path)

    @staticmethod
    def _payload_from_record(record: SettlementRecord) -> dict[str, Any]:
        return {
            "assignment": record.assignment,
            "result": record.result,
            "constitutional_hash": record.constitutional_hash,
        }

    @classmethod
    def _record_from_payload(cls, payload: dict[str, Any]) -> SettlementRecord:
        return SettlementRecord(
            assignment=dict(payload.get("assignment", {})),
            result=dict(payload.get("result", {})),
            constitutional_hash=payload.get("constitutional_hash", ""),
        )


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
                    result_json TEXT NOT NULL,
                    constitutional_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_settlements (
                    assignment_id TEXT PRIMARY KEY,
                    assignment_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    constitutional_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
            # Idempotently add constitutional_hash to databases created before
            # this column was introduced (ALTER TABLE IF NOT EXISTS requires
            # SQLite 3.37; use a try/except for broader compatibility).
            try:
                conn.execute(
                    "ALTER TABLE mesh_settlements ADD COLUMN "
                    "constitutional_hash TEXT NOT NULL DEFAULT ''"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                conn.execute(
                    "ALTER TABLE pending_settlements ADD COLUMN "
                    "constitutional_hash TEXT NOT NULL DEFAULT ''"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            conn.commit()

    def append(self, record: SettlementRecord) -> None:
        """Append a settlement record.

        Finalized records are immutable. Duplicate ``assignment_id`` values
        raise a deterministic error instead of replacing or silently ignoring
        the original settlement.
        """
        assignment_id = str(record.assignment["assignment_id"])
        with sqlite3.connect(self.path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO mesh_settlements (
                        assignment_id,
                        assignment_json,
                        result_json,
                        constitutional_hash
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        assignment_id,
                        json.dumps(record.assignment, separators=(",", ":")),
                        json.dumps(record.result, separators=(",", ":")),
                        record.constitutional_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateSettlementError(
                    f"Settlement {assignment_id} already exists"
                ) from exc
            conn.commit()

    def load_all(self) -> list[SettlementRecord]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT assignment_json, result_json, constitutional_hash
                FROM mesh_settlements
                ORDER BY assignment_id
                """
            ).fetchall()
        return [
            SettlementRecord(
                assignment=dict(json.loads(assignment_json)),
                result=dict(json.loads(result_json)),
                constitutional_hash=constitutional_hash,
            )
            for assignment_json, result_json, constitutional_hash in rows
        ]

    def mark_pending(self, record: SettlementRecord) -> None:
        assignment_id = str(record.assignment["assignment_id"])
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_settlements (
                    assignment_id,
                    assignment_json,
                    result_json,
                    constitutional_hash
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    assignment_id,
                    json.dumps(record.assignment, separators=(",", ":")),
                    json.dumps(record.result, separators=(",", ":")),
                    record.constitutional_hash,
                ),
            )
            conn.commit()

    def clear_pending(self, assignment_id: str) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "DELETE FROM pending_settlements WHERE assignment_id = ?",
                (assignment_id,),
            )
            conn.commit()

    def load_pending(self) -> list[SettlementRecord]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT assignment_json, result_json, constitutional_hash
                FROM pending_settlements
                ORDER BY assignment_id
                """
            ).fetchall()
        return [
            SettlementRecord(
                assignment=dict(json.loads(assignment_json)),
                result=dict(json.loads(result_json)),
                constitutional_hash=constitutional_hash,
            )
            for assignment_json, result_json, constitutional_hash in rows
        ]

    def pending_count(self) -> int:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM pending_settlements").fetchone()
        return int(row[0]) if row is not None else 0

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "sqlite",
            "path": str(self.path),
        }


__all__ = [
    "DuplicateSettlementError",
    "JSONLSettlementStore",
    "SQLiteSettlementStore",
    "SettlementRecord",
    "SettlementStore",
]
