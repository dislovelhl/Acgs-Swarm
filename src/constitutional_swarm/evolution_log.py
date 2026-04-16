"""Declarative Evolution Log — strict monotonicity + acceleration invariants.

Enforces five invariants at write time, mirroring the SQL/Prolog specification
in the declarative-evolution-guide:

1. Strict monotonicity:  value(N) > value(N-1)          — no plateaus, no regression
2. Strict acceleration:  delta(N) > delta(N-1)           — rate of improvement must grow
3. Contiguous history:   epoch N requires epoch N-1       — no gaps
4. Uniqueness:           (epoch, metric) appears once     — no overwrites
5. Minimum evidence:     ≥2 epochs for monotonicity claim; ≥3 for acceleration claim

The table is append-only: UPDATE and DELETE are blocked by triggers.
Derived quantities (delta, accel) are computed on-the-fly via a view — never stored.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvolutionViolationError(ValueError):
    """Base for all write-time invariant violations."""


class MissingPriorEpochError(EvolutionViolationError):
    """Raised when the prior epoch does not exist (contiguity violation)."""


class NonIncreasingValueError(EvolutionViolationError):
    """Raised when the new value does not strictly exceed the prior value."""


class DecelerationBlockedError(EvolutionViolationError):
    """Raised when the new delta does not strictly exceed the prior delta."""


class DuplicateRecordError(EvolutionViolationError):
    """Raised when the (epoch, metric) pair already exists."""


class MutationBlockedError(EvolutionViolationError):
    """Raised when an UPDATE or DELETE is attempted on the append-only table."""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegressionRecord:
    metric: str
    epoch: int
    delta: float


@dataclass(frozen=True, slots=True)
class DecelerationRecord:
    metric: str
    epoch: int
    accel: float


@dataclass(frozen=True, slots=True)
class GapRecord:
    metric: str
    epoch: int  # the epoch that has no predecessor


@dataclass(frozen=True, slots=True)
class DashboardRow:
    metric: str
    baseline: float
    current_best: float
    epoch_count: int
    total_gain: float
    avg_rate: float | None
    strictly_increasing: str   # 'YES' | 'NO' | 'INSUFFICIENT DATA'
    strictly_accelerating: str  # 'YES' | 'NO' | 'INSUFFICIENT DATA'


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS evolution_log (
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    metric      TEXT    NOT NULL,
    value       REAL    NOT NULL,
    recorded_at TEXT    DEFAULT (datetime('now')),
    PRIMARY KEY (epoch, metric)
) STRICT;
"""

_DDL_VIEW = """
CREATE VIEW IF NOT EXISTS evolution_derived AS
WITH deltas AS (
    SELECT epoch,
           metric,
           value,
           value - LAG(value) OVER (
               PARTITION BY metric
               ORDER BY epoch
           ) AS delta
    FROM evolution_log
)
SELECT epoch,
       metric,
       value,
       delta,
       delta - LAG(delta) OVER (
           PARTITION BY metric
           ORDER BY epoch
       ) AS accel
FROM deltas;
"""

_DDL_TRIGGER_INSERT = """
CREATE TRIGGER IF NOT EXISTS validate_evolution_insert
BEFORE INSERT ON evolution_log
FOR EACH ROW
BEGIN
    -- 1. Require contiguous history
    SELECT RAISE(ABORT, 'MISSING PRIOR EPOCH')
    WHERE NEW.epoch > 1
      AND NOT EXISTS (
          SELECT 1
          FROM evolution_log
          WHERE metric = NEW.metric
            AND epoch  = NEW.epoch - 1
      );

    -- 2. Strict improvement
    SELECT RAISE(ABORT, 'NON-INCREASING VALUE')
    WHERE EXISTS (
        SELECT 1
        FROM evolution_log
        WHERE metric = NEW.metric
          AND epoch  = NEW.epoch - 1
          AND NEW.value <= value
    );

    -- 3. Strict acceleration (when two prior points exist)
    SELECT RAISE(ABORT, 'DECELERATION BLOCKED')
    WHERE EXISTS (
        SELECT 1
        FROM evolution_log AS cur
        JOIN evolution_log AS prev
          ON prev.metric = cur.metric
         AND prev.epoch  = cur.epoch - 1
        WHERE cur.metric = NEW.metric
          AND cur.epoch  = NEW.epoch - 1
          AND (NEW.value - cur.value) <= (cur.value - prev.value)
    );
END;
"""

_DDL_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS block_evolution_update
BEFORE UPDATE ON evolution_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'UPDATES BLOCKED: table is append-only');
END;
"""

_DDL_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS block_evolution_delete
BEFORE DELETE ON evolution_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'DELETES BLOCKED: table is append-only');
END;
"""

# ---------------------------------------------------------------------------
# Invariant queries
# ---------------------------------------------------------------------------

_Q_REGRESSION = """
SELECT metric, epoch AS regressed_at, delta
FROM evolution_derived
WHERE delta IS NOT NULL AND delta <= 0;
"""

_Q_DECELERATION = """
SELECT metric, epoch AS decel_at, accel
FROM evolution_derived
WHERE accel IS NOT NULL AND accel <= 0;
"""

_Q_GAPS = """
SELECT cur.metric, cur.epoch AS has_no_predecessor
FROM evolution_log AS cur
LEFT JOIN evolution_log AS prev
  ON prev.metric = cur.metric
 AND prev.epoch  = cur.epoch - 1
WHERE cur.epoch > 1
  AND prev.epoch IS NULL;
"""

_Q_DASHBOARD = """
SELECT metric,
       MIN(value)  AS baseline,
       MAX(value)  AS current_best,
       COUNT(*)    AS epoch_count,
       ROUND(MAX(value) - MIN(value), 2) AS total_gain,
       ROUND(AVG(delta), 2)              AS avg_rate,
       CASE
           WHEN COUNT(CASE WHEN delta IS NOT NULL THEN 1 END) < 1
               THEN 'INSUFFICIENT DATA'
           WHEN MIN(CASE WHEN delta IS NOT NULL THEN delta END) > 0
               THEN 'YES'
           ELSE 'NO'
       END AS strictly_increasing,
       CASE
           WHEN COUNT(CASE WHEN accel IS NOT NULL THEN 1 END) < 1
               THEN 'INSUFFICIENT DATA'
           WHEN MIN(CASE WHEN accel IS NOT NULL THEN accel END) > 0
               THEN 'YES'
           ELSE 'NO'
       END AS strictly_accelerating
FROM evolution_derived
GROUP BY metric;
"""


# ---------------------------------------------------------------------------
# EvolutionLog
# ---------------------------------------------------------------------------


class EvolutionLog:
    """SQLite-backed append-only log enforcing the declarative evolution contract.

    Usage::

        with EvolutionLog(":memory:") as log:
            log.record(1, "capability", 10.0)
            log.record(2, "capability", 12.0)
            assert log.dashboard()[0].strictly_increasing == "YES"

    Parameters
    ----------
    path:
        File path for the SQLite database, or ``":memory:"`` for an in-memory DB.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Context manager / lifecycle
    # ------------------------------------------------------------------

    def open(self) -> EvolutionLog:
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._setup()
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> EvolutionLog:
        return self.open()

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup(self) -> None:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute(_DDL_TABLE)
        cur.execute(_DDL_VIEW)
        cur.execute(_DDL_TRIGGER_INSERT)
        cur.execute(_DDL_TRIGGER_UPDATE)
        cur.execute(_DDL_TRIGGER_DELETE)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, epoch: int, metric: str, value: float) -> None:
        """Insert a new (epoch, metric, value) data point.

        Raises
        ------
        MissingPriorEpochError
            If epoch > 1 and the prior epoch does not exist.
        NonIncreasingValueError
            If the new value does not strictly exceed the prior value.
        DecelerationBlockedError
            If the new delta does not strictly exceed the prior delta.
        DuplicateRecordError
            If the (epoch, metric) pair already exists.
        """
        assert self._conn is not None
        try:
            self._conn.execute(
                "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                (epoch, metric, value),
            )
            self._conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as exc:
            msg = str(exc)
            if "MISSING PRIOR EPOCH" in msg:
                raise MissingPriorEpochError(
                    f"epoch {epoch} for metric '{metric}' requires epoch {epoch - 1}"
                ) from exc
            if "NON-INCREASING VALUE" in msg:
                raise NonIncreasingValueError(
                    f"value {value} for metric '{metric}' epoch {epoch} "
                    "does not strictly exceed the prior value"
                ) from exc
            if "DECELERATION BLOCKED" in msg:
                raise DecelerationBlockedError(
                    f"delta for metric '{metric}' epoch {epoch} "
                    "does not strictly exceed the prior delta"
                ) from exc
            if "UPDATES BLOCKED" in msg or "DELETES BLOCKED" in msg:
                raise MutationBlockedError(msg) from exc
            if "UNIQUE constraint failed" in msg:
                raise DuplicateRecordError(
                    f"(epoch={epoch}, metric='{metric}') already exists in evolution_log"
                ) from exc
            raise

    # ------------------------------------------------------------------
    # Invariant queries
    # ------------------------------------------------------------------

    def detect_regression(self) -> list[RegressionRecord]:
        """Return rows where value failed to strictly increase."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_REGRESSION).fetchall()
        return [RegressionRecord(metric=r["metric"], epoch=r["regressed_at"], delta=r["delta"]) for r in rows]

    def detect_deceleration(self) -> list[DecelerationRecord]:
        """Return rows where the rate of improvement failed to strictly increase."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_DECELERATION).fetchall()
        return [DecelerationRecord(metric=r["metric"], epoch=r["decel_at"], accel=r["accel"]) for r in rows]

    def detect_gaps(self) -> list[GapRecord]:
        """Return epochs that exist but whose predecessor does not."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_GAPS).fetchall()
        return [GapRecord(metric=r["metric"], epoch=r["has_no_predecessor"]) for r in rows]

    def dashboard(self) -> list[DashboardRow]:
        """Return per-metric summary with strictly_increasing / strictly_accelerating flags."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_DASHBOARD).fetchall()
        return [
            DashboardRow(
                metric=r["metric"],
                baseline=r["baseline"],
                current_best=r["current_best"],
                epoch_count=r["epoch_count"],
                total_gain=r["total_gain"],
                avg_rate=r["avg_rate"],
                strictly_increasing=r["strictly_increasing"],
                strictly_accelerating=r["strictly_accelerating"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Admission gate (pure Python, mirrors admit/3 from guide §2.6)
    # ------------------------------------------------------------------

    def admit(self, metric: str, epoch: int, value: float) -> bool:
        """Return True iff inserting (epoch, metric, value) would satisfy all invariants.

        Does not write to the database. Mirrors Prolog's ``admit/3``.
        """
        assert self._conn is not None
        cur = self._conn.cursor()

        # Uniqueness: reject if already exists
        exists = cur.execute(
            "SELECT 1 FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch, metric),
        ).fetchone()
        if exists:
            return False

        if epoch == 1:
            # First epoch: no prior to check
            return True

        # Strict increase
        prior = cur.execute(
            "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch - 1, metric),
        ).fetchone()
        if prior is None:
            return False  # missing predecessor
        prior_value: float = prior[0]
        if value <= prior_value:
            return False

        if epoch >= 3:
            # Strict acceleration
            prev = cur.execute(
                "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
                (epoch - 2, metric),
            ).fetchone()
            if prev is None:
                return False
            new_delta = value - prior_value
            prior_delta = prior_value - prev[0]
            if new_delta <= prior_delta:
                return False

        return True

    # ------------------------------------------------------------------
    # Minimum admissible value (mirrors admissible_min/3 from guide §2.7)
    # ------------------------------------------------------------------

    def admissible_min(self, metric: str, epoch: int) -> float:
        """Return the minimum value for ``epoch`` that satisfies all invariants.

        For epoch 2: prior_value + 1 (strict increase, integer domain).
        For epoch >= 3: prior_value + prior_delta + 1 (strict acceleration).

        Raises
        ------
        ValueError
            If the required prior epochs are not present.
        """
        assert self._conn is not None
        cur = self._conn.cursor()

        if epoch < 2:
            raise ValueError("admissible_min requires epoch >= 2")

        prior = cur.execute(
            "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch - 1, metric),
        ).fetchone()
        if prior is None:
            raise ValueError(f"epoch {epoch - 1} for metric '{metric}' not found")

        prior_value: float = prior[0]

        if epoch == 2:
            return prior_value + 1.0

        # epoch >= 3: need two prior points to compute prior_delta
        prev = cur.execute(
            "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch - 2, metric),
        ).fetchone()
        if prev is None:
            raise ValueError(f"epoch {epoch - 2} for metric '{metric}' not found")

        prior_delta = prior_value - prev[0]
        return prior_value + prior_delta + 1.0

    # ------------------------------------------------------------------
    # Full-path validation (mirrors valid_trajectory/3 from guide §2.8)
    # ------------------------------------------------------------------

    def valid_trajectory(self, metric: str, from_epoch: int, to_epoch: int) -> bool:
        """Return True iff every step in [from_epoch..to_epoch] satisfies the contract.

        Checks contiguity, strict increase at every consecutive pair, and strict
        acceleration at every triple (where defined). A single-epoch range is
        trivially valid if that epoch exists.
        """
        assert self._conn is not None
        cur = self._conn.cursor()

        if from_epoch > to_epoch:
            return False

        # Check all epochs exist contiguously
        rows = cur.execute(
            "SELECT epoch, value FROM evolution_log "
            "WHERE metric = ? AND epoch BETWEEN ? AND ? "
            "ORDER BY epoch",
            (metric, from_epoch, to_epoch),
        ).fetchall()

        epochs_found = [r[0] for r in rows]
        expected = list(range(from_epoch, to_epoch + 1))
        if epochs_found != expected:
            return False  # gap or missing epochs

        values = [r[1] for r in rows]

        # Strict increase at every consecutive pair
        for i in range(1, len(values)):
            delta = values[i] - values[i - 1]
            if delta <= 0:
                return False

        # Strict acceleration at every triple
        for i in range(2, len(values)):
            d_cur = values[i] - values[i - 1]
            d_prev = values[i - 1] - values[i - 2]
            if d_cur <= d_prev:
                return False

        return True
