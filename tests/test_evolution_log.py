"""Tests for evolution_log.py — declarative evolution invariants.

All tests use :memory: SQLite databases so they are fast and isolated.
"""

from __future__ import annotations

import sqlite3

import pytest
from constitutional_swarm.evolution_log import (
    DecelerationBlockedError,
    DuplicateRecordError,
    EvolutionLog,
    MissingPriorEpochError,
    NonIncreasingValueError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_log() -> EvolutionLog:
    """Open log pre-loaded with guide §1.2 seed data; closed after each test.

    capability:  10, 12, 16, 22, 30  (deltas 2,4,6,8; accels 2,2,2)
    reliability: 80, 83, 88, 95      (deltas 3,5,7;   accels 2,2)
    """
    log = EvolutionLog(":memory:").open()
    try:
        for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0)]:
            log.record(epoch, "capability", value)
        for epoch, value in [(1, 80.0), (2, 83.0), (3, 88.0), (4, 95.0)]:
            log.record(epoch, "reliability", value)
        yield log
    finally:
        log.close()


# ---------------------------------------------------------------------------
# Schema and basic insertion
# ---------------------------------------------------------------------------


class TestSchemaAndBasicInsert:
    def test_context_manager_opens_and_closes(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 1.0)
        # Connection should be closed after exit
        assert log._conn is None

    def test_first_epoch_always_accepted(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 0.0)
            log.record(1, "y", -999.0)  # any value allowed for epoch 1

    def test_uniqueness_blocks_duplicate(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            with pytest.raises(DuplicateRecordError):
                log.record(1, "x", 99.0)

    def test_epoch_zero_rejected_by_check_constraint(self) -> None:
        with EvolutionLog(":memory:") as log:
            with pytest.raises(sqlite3.IntegrityError):
                log.record(0, "x", 1.0)

    def test_negative_epoch_rejected(self) -> None:
        with EvolutionLog(":memory:") as log:
            with pytest.raises(sqlite3.IntegrityError):
                log.record(-1, "x", 1.0)


# ---------------------------------------------------------------------------
# Trigger: contiguity
# ---------------------------------------------------------------------------


class TestContiguity:
    def test_epoch_2_requires_epoch_1(self) -> None:
        with EvolutionLog(":memory:") as log:
            with pytest.raises(MissingPriorEpochError):
                log.record(2, "x", 20.0)

    def test_epoch_3_requires_epoch_2(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            with pytest.raises(MissingPriorEpochError):
                log.record(3, "x", 30.0)

    def test_contiguous_insertion_accepted(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            log.record(2, "x", 15.0)
            log.record(3, "x", 25.0)


# ---------------------------------------------------------------------------
# Trigger: strict monotonicity
# ---------------------------------------------------------------------------


class TestStrictMonotonicity:
    def test_regression_blocked(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            log.record(2, "x", 15.0)
            with pytest.raises(NonIncreasingValueError):
                log.record(3, "x", 14.0)

    def test_plateau_blocked(self) -> None:
        """Equal consecutive value is not strict increase."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            with pytest.raises(NonIncreasingValueError):
                log.record(2, "x", 10.0)

    def test_strict_increase_accepted(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            log.record(2, "x", 11.0)


# ---------------------------------------------------------------------------
# Trigger: strict acceleration
# ---------------------------------------------------------------------------


class TestStrictAcceleration:
    def test_deceleration_blocked(self) -> None:
        """Guide §1.5: new delta=7 < prior delta=10 → DECELERATION BLOCKED."""
        with EvolutionLog(":memory:") as log:
            # capability series up to epoch 6: 10,12,16,22,30,40 (delta=10)
            for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0), (6, 40.0)]:
                log.record(epoch, "capability", value)
            with pytest.raises(DecelerationBlockedError):
                log.record(7, "capability", 47.0)  # delta=7 < prior delta=10

    def test_constant_rate_blocked_correctly(self) -> None:
        """delta(3) = delta(2) should be blocked."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 0.0)
            log.record(2, "x", 5.0)  # delta=5
            with pytest.raises(DecelerationBlockedError):
                log.record(3, "x", 10.0)  # delta=5 = prior delta → not strictly greater

    def test_strict_acceleration_accepted(self) -> None:
        """Guide §1.5: epoch 6 value=40, delta=10 > prior delta=8 → accepted."""
        with EvolutionLog(":memory:") as log:
            for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0)]:
                log.record(epoch, "capability", value)
            log.record(6, "capability", 40.0)  # delta=10 > prior delta=8

    def test_epoch_2_no_acceleration_check(self) -> None:
        """Only strict increase is checked at epoch 2 (no prior delta exists)."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 0.0)
            log.record(2, "x", 1.0)  # delta=1; no prior delta to compare


# ---------------------------------------------------------------------------
# Trigger: append-only enforcement
# ---------------------------------------------------------------------------


class TestAppendOnly:
    def test_update_blocked(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            with pytest.raises(sqlite3.IntegrityError, match="UPDATES BLOCKED"):
                log._conn.execute(  # type: ignore[union-attr]
                    "UPDATE evolution_log SET value = 99 WHERE epoch = 1 AND metric = 'x'"
                )

    def test_delete_blocked(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            with pytest.raises(sqlite3.IntegrityError, match="DELETES BLOCKED"):
                log._conn.execute(  # type: ignore[union-attr]
                    "DELETE FROM evolution_log WHERE epoch = 1 AND metric = 'x'"
                )


# ---------------------------------------------------------------------------
# Invariant queries (detect_regression, detect_deceleration, detect_gaps)
# ---------------------------------------------------------------------------


class TestInvariantQueries:
    def test_no_regression_in_clean_log(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.detect_regression() == []

    def test_no_deceleration_in_clean_log(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.detect_deceleration() == []

    def test_no_gaps_in_clean_log(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.detect_gaps() == []


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    def test_seed_data_dashboard(self, seeded_log: EvolutionLog) -> None:
        rows = {r.metric: r for r in seeded_log.dashboard()}

        cap = rows["capability"]
        assert cap.baseline == 10.0
        assert cap.current_best == 30.0
        assert cap.epoch_count == 5
        assert cap.total_gain == 20.0
        assert cap.strictly_increasing == "YES"
        assert cap.strictly_accelerating == "YES"

        rel = rows["reliability"]
        assert rel.baseline == 80.0
        assert rel.current_best == 95.0
        assert rel.epoch_count == 4
        assert rel.strictly_increasing == "YES"
        assert rel.strictly_accelerating == "YES"

    def test_single_epoch_insufficient_data(self) -> None:
        """A single-epoch metric cannot claim monotonicity or acceleration."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "solo", 42.0)
            rows = {r.metric: r for r in log.dashboard()}
            solo = rows["solo"]
            assert solo.strictly_increasing == "INSUFFICIENT DATA"
            assert solo.strictly_accelerating == "INSUFFICIENT DATA"

    def test_two_epoch_metric(self) -> None:
        """Two epochs: monotonicity decidable, acceleration not."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "m", 10.0)
            log.record(2, "m", 15.0)
            rows = {r.metric: r for r in log.dashboard()}
            m = rows["m"]
            assert m.strictly_increasing == "YES"
            assert m.strictly_accelerating == "INSUFFICIENT DATA"

    def test_empty_log_returns_empty_dashboard(self) -> None:
        with EvolutionLog(":memory:") as log:
            assert log.dashboard() == []


# ---------------------------------------------------------------------------
# Admission gate (admit)
# ---------------------------------------------------------------------------


class TestAdmit:
    """Guide §2.6 — admission gate cases."""

    @pytest.fixture
    def loaded(self) -> EvolutionLog:
        log = EvolutionLog(":memory:").open()
        try:
            for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0)]:
                log.record(epoch, "capability", value)
            yield log
        finally:
            log.close()

    def test_admit_valid_epoch_6(self, loaded: EvolutionLog) -> None:
        assert loaded.admit("capability", 6, 40.0) is True  # delta=10 > prior=8

    def test_admit_accept_boundary(self, loaded: EvolutionLog) -> None:
        """admit(capability, 6, 39) → true (admissible_min boundary, delta=9 > prior=8)."""
        assert loaded.admit("capability", 6, 39.0) is True

    def test_reject_equal_delta(self, loaded: EvolutionLog) -> None:
        """admit(capability, 6, 38) → false (delta=8 = prior delta=8)."""
        assert loaded.admit("capability", 6, 38.0) is False

    def test_reject_regression(self, loaded: EvolutionLog) -> None:
        """admit(capability, 6, 30) → false (30 not > 30)."""
        assert loaded.admit("capability", 6, 30.0) is False

    def test_reject_deceleration(self, loaded: EvolutionLog) -> None:
        """admit(capability, 6, 37) → false (delta=7 < prior delta=8)."""
        assert loaded.admit("capability", 6, 37.0) is False

    def test_reject_duplicate(self, loaded: EvolutionLog) -> None:
        """After recording epoch 6, admit(capability, 6, 99) → false."""
        loaded.record(6, "capability", 40.0)
        assert loaded.admit("capability", 6, 99.0) is False

    def test_reject_missing_predecessor(self) -> None:
        with EvolutionLog(":memory:") as log:
            assert log.admit("x", 2, 10.0) is False  # no epoch 1

    def test_first_epoch_always_admitted(self) -> None:
        with EvolutionLog(":memory:") as log:
            assert log.admit("new_metric", 1, 0.0) is True


# ---------------------------------------------------------------------------
# admissible_min
# ---------------------------------------------------------------------------


class TestAdmissibleMin:
    def test_capability_epoch_6(self, seeded_log: EvolutionLog) -> None:
        """Guide §2.7: PriorValue=30, PriorDelta=8, min=30+8+1=39."""
        assert seeded_log.admissible_min("capability", 6) == 39.0

    def test_epoch_2_is_prior_plus_1(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 100.0)
            assert log.admissible_min("x", 2) == 101.0

    def test_epoch_1_raises(self) -> None:
        with EvolutionLog(":memory:") as log:
            with pytest.raises(ValueError, match="epoch >= 2"):
                log.admissible_min("x", 1)

    def test_missing_prior_raises(self) -> None:
        with EvolutionLog(":memory:") as log:
            with pytest.raises(ValueError, match="not found"):
                log.admissible_min("x", 3)


# ---------------------------------------------------------------------------
# valid_trajectory
# ---------------------------------------------------------------------------


class TestValidTrajectory:
    def test_full_trajectory_capability(self, seeded_log: EvolutionLog) -> None:
        """Guide §2.8: valid_trajectory(capability, 1, 5) → true."""
        assert seeded_log.valid_trajectory("capability", 1, 5) is True

    def test_full_trajectory_reliability(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.valid_trajectory("reliability", 1, 4) is True

    def test_single_epoch_trajectory(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.valid_trajectory("capability", 3, 3) is True

    def test_inverted_range_returns_false(self, seeded_log: EvolutionLog) -> None:
        assert seeded_log.valid_trajectory("capability", 5, 1) is False

    def test_missing_epoch_in_range_returns_false(self) -> None:
        with EvolutionLog(":memory:") as log:
            log.record(1, "x", 10.0)
            log.record(2, "x", 15.0)
            # epoch 3 not present
            assert log.valid_trajectory("x", 1, 3) is False

    def test_partial_sub_trajectory(self, seeded_log: EvolutionLog) -> None:
        """Sub-range of a valid series should also be valid."""
        assert seeded_log.valid_trajectory("capability", 2, 4) is True


# ---------------------------------------------------------------------------
# Multiple independent metrics don't interfere
# ---------------------------------------------------------------------------


class TestMetricIsolation:
    def test_separate_metrics_independent(self) -> None:
        """Inserting for metric 'a' does not affect invariant checks for metric 'b'."""
        with EvolutionLog(":memory:") as log:
            log.record(1, "a", 5.0)
            log.record(2, "a", 10.0)
            log.record(1, "b", 100.0)
            log.record(2, "b", 110.0)
            assert log.detect_regression() == []
            assert log.detect_gaps() == []

    def test_gap_in_one_metric_does_not_flag_other(self) -> None:
        """The gap query is per-metric."""
        with EvolutionLog(":memory:") as log:
            # 'a' is contiguous
            log.record(1, "a", 5.0)
            log.record(2, "a", 10.0)
            # 'b' only has epoch 1 — no gap because there's no epoch > 1
            log.record(1, "b", 100.0)
            assert log.detect_gaps() == []
