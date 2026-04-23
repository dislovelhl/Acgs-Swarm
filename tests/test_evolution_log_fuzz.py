"""Seeded adversarial fuzz tests for EvolutionLog write-time invariants."""

from __future__ import annotations

import random
import sqlite3
from collections import Counter
from pathlib import Path

import pytest
from constitutional_swarm import (
    DecelerationBlockedError,
    EvolutionLog,
    EvolutionViolationError,
    MissingPriorEpochError,
    NonIncreasingValueError,
)

ITERATIONS = 240
SEED = 20260423


def _valid_sequence(rng: random.Random, length: int = 6) -> list[float]:
    value = rng.uniform(-20.0, 20.0)
    delta = rng.uniform(0.25, 3.0)
    values = [value]
    for _ in range(1, length):
        value += delta
        values.append(round(value, 6))
        delta += rng.uniform(0.25, 3.0)
    return values


def _record_sequence(log: EvolutionLog, metric: str, values: list[float]) -> None:
    for epoch, value in enumerate(values, start=1):
        log.record(epoch, metric, value)


def test_evolution_log_seeded_adversarial_fuzzer(tmp_path: Path) -> None:
    """Valid accelerating series persist; invalid writes raise public exceptions."""
    rng = random.Random(SEED)
    db_path = tmp_path / "evolution-fuzz.sqlite"
    outcomes: Counter[str] = Counter()
    valid_metrics: dict[str, list[float]] = {}

    with EvolutionLog(db_path) as log:
        for iteration in range(ITERATIONS):
            case_type = iteration % 4

            if case_type == 0:
                metric = f"valid-{iteration}"
                values = _valid_sequence(rng)
                _record_sequence(log, metric, values)
                valid_metrics[metric] = values
                outcomes["valid"] += 1
                continue

            if case_type == 1:
                metric = f"gap-{iteration}"
                with pytest.raises(MissingPriorEpochError) as exc_info:
                    log.record(2 + rng.randrange(4), metric, rng.uniform(1.0, 20.0))
                assert "requires epoch" in str(exc_info.value)
                outcomes["gap"] += 1
                continue

            if case_type == 2:
                metric = f"nonmonotonic-{iteration}"
                first = rng.uniform(0.0, 50.0)
                log.record(1, metric, first)
                with pytest.raises(NonIncreasingValueError) as exc_info:
                    log.record(2, metric, first - rng.uniform(0.0, 5.0))
                assert "does not strictly exceed" in str(exc_info.value)
                valid_metrics[metric] = [first]
                outcomes["nonmonotonic"] += 1
                continue

            metric = f"deceleration-{iteration}"
            first = rng.uniform(0.0, 50.0)
            first_delta = rng.uniform(3.0, 8.0)
            second_delta = rng.uniform(0.1, first_delta)
            log.record(1, metric, first)
            log.record(2, metric, first + first_delta)
            with pytest.raises(DecelerationBlockedError) as exc_info:
                log.record(3, metric, first + first_delta + second_delta)
            assert "does not strictly exceed the prior delta" in str(exc_info.value)
            valid_metrics[metric] = [first, first + first_delta]
            outcomes["deceleration"] += 1

        # All rejected writes must be user-facing domain exceptions, not raw sqlite.
        with pytest.raises(EvolutionViolationError):
            log.record(2, "final-gap-check", 1.0)

        rows = {row.metric: row for row in log.dashboard()}
        assert set(rows) == set(valid_metrics)
        assert log.detect_gaps() == []
        assert log.detect_regression() == []
        assert log.detect_deceleration() == []

        for metric, values in valid_metrics.items():
            row = rows[metric]
            assert row.epoch_count == len(values)
            assert row.baseline == pytest.approx(values[0])
            assert row.current_best == pytest.approx(values[-1])
            if len(values) >= 2:
                assert row.strictly_increasing == "YES"
            if len(values) >= 3:
                assert row.strictly_accelerating == "YES"

    expected_valid_rows = sum(len(values) for values in valid_metrics.values())
    with sqlite3.connect(db_path) as conn:
        row_count, max_epoch = conn.execute(
            "SELECT COUNT(*), MAX(epoch) FROM evolution_log"
        ).fetchone()
    assert row_count == expected_valid_rows
    assert max_epoch == 6
    assert outcomes == {
        "valid": 60,
        "gap": 60,
        "nonmonotonic": 60,
        "deceleration": 60,
    }
