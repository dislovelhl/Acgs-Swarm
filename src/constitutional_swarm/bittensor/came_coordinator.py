"""CAME Coordinator — Coverage-Aware MAP-Elites governance loop.

Wires together three subsystems:

- ``MinerQualityGrid``        — MAP-Elites quality-diversity grid
- ``RuleCodifier``            — proposes YAML governance rules from precedent clusters
- ``EvolutionLog``            — audit-grade, append-only record of governance evolution

The coordinator runs ``evolve_cycle(approaches)`` which:

1. Submits each :class:`~constitutional_swarm.bittensor.map_elites.MinerApproach`
   to the quality grid via ``grid.challenge()``.
2. Checks ``grid.ceiling_detected()`` — if the grid has stalled for
   ``ceiling_window`` consecutive challenges, triggers rule codification.
3. Respects a ``codification_cooldown`` (cycles) to avoid proposing rules
   every time a transient ceiling is detected.
4. Logs every evolution event to the ``EvolutionLog``.
5. Returns a :class:`CAMECycleResult` with grid stats, any newly proposed
   rules, and the log entry identifier.

All ``EvolutionLog`` writes are best-effort: the log enforces strict monotonicity
and acceleration invariants that may reject entries; violations are caught and
recorded in ``CAMECycleResult.log_id`` as an error token rather than crashing
the evolution loop.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Lazy imports — be robust to API variations and partial installations
# ---------------------------------------------------------------------------

try:
    from constitutional_swarm.bittensor.map_elites import MinerQualityGrid
except ImportError:  # pragma: no cover
    MinerQualityGrid = None  # type: ignore[assignment,misc]

try:
    from constitutional_swarm.bittensor.rule_codifier import RuleCodifier
except ImportError:  # pragma: no cover
    RuleCodifier = None  # type: ignore[assignment,misc]

try:
    from constitutional_swarm.evolution_log import EvolutionLog
except ImportError:  # pragma: no cover
    EvolutionLog = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Public result / config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CAMECycleResult:
    """Structured result returned by :meth:`CAMECoordinator.evolve_cycle`.

    Attributes
    ----------
    grid_coverage:
        Fraction of MAP-Elites cells filled (0.0 – 1.0).
    ceiling_detected:
        Whether the grid stalled (no improvements in last N challenges).
    rules_proposed:
        List of newly proposed rule candidates (may be empty).
    log_id:
        Identifier for the EvolutionLog entry, or an error token prefixed
        with ``"err:"`` when the log write was rejected by an invariant.
    exploration_bonus:
        Aggregate exploration bonus across all miner_uids seen this cycle.
    """

    grid_coverage: float
    ceiling_detected: bool
    rules_proposed: list[Any]
    log_id: str
    exploration_bonus: float


@dataclass
class CAMECoordinatorConfig:
    """Tunable parameters for :class:`CAMECoordinator`.

    Attributes
    ----------
    coverage_threshold:
        Grid coverage fraction above which the coordinator considers the
        exploration phase complete.  Not yet used for hard gating, but
        exposed in :meth:`~CAMECoordinator.summary`.
    codification_cooldown:
        Minimum number of cycles that must elapse between rule codification
        proposals triggered by ceiling detection.
    """

    coverage_threshold: float = 0.8
    codification_cooldown: int = 5


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


class CAMECoordinator:
    """Orchestrates the Coverage-Aware MAP-Elites governance loop.

    Parameters
    ----------
    config:
        Optional :class:`CAMECoordinatorConfig`; defaults are used if *None*.
    grid:
        A :class:`~constitutional_swarm.bittensor.map_elites.MinerQualityGrid`
        instance.  A default grid is created if not provided.
    codifier:
        A :class:`~constitutional_swarm.bittensor.rule_codifier.RuleCodifier`
        instance.  If *None* and ``RuleCodifier`` is available, a default
        instance is constructed with a placeholder constitutional hash.
    evolution_log:
        An already-*opened* :class:`~constitutional_swarm.evolution_log.EvolutionLog`
        instance.  If *None* and ``EvolutionLog`` is available, an in-memory
        database is opened automatically.
    """

    def __init__(
        self,
        config: CAMECoordinatorConfig | None = None,
        *,
        grid: Any | None = None,
        codifier: Any | None = None,
        evolution_log: Any | None = None,
    ) -> None:
        self._config: CAMECoordinatorConfig = config or CAMECoordinatorConfig()

        # ---- quality grid ------------------------------------------------
        if grid is not None:
            self._grid = grid
        elif MinerQualityGrid is not None:
            self._grid = MinerQualityGrid()
        else:
            self._grid = None  # type: ignore[assignment]

        # ---- rule codifier -----------------------------------------------
        if codifier is not None:
            self._codifier = codifier
        elif RuleCodifier is not None:
            # Use a placeholder hash; real deployments should inject a codifier
            # with the live constitutional hash.
            self._codifier: Any = RuleCodifier(constitutional_hash="came-placeholder-00000000")
        else:
            self._codifier = None

        # ---- evolution log -----------------------------------------------
        if evolution_log is not None:
            self._log = evolution_log
            self._owns_log = False
        elif EvolutionLog is not None:
            self._log = EvolutionLog(":memory:")
            self._log.open()
            self._owns_log = True
        else:
            self._log = None
            self._owns_log = False

        # ---- internal state ----------------------------------------------
        self._cycle: int = 0
        self._last_codification_cycle: int = -(self._config.codification_cooldown + 1)
        self._coverage_history: list[float] = []

        # Per-metric epoch tracking for the EvolutionLog (strict monotonicity).
        # Maps metric_name → (last_epoch, last_value).
        self._log_state: dict[str, tuple[int, float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evolve_cycle(self, approaches: list[Any]) -> CAMECycleResult:
        """Run one CAME evolution cycle.

        Parameters
        ----------
        approaches:
            List of
            :class:`~constitutional_swarm.bittensor.map_elites.MinerApproach`
            instances to submit to the quality grid.

        Returns
        -------
        CAMECycleResult
            Grid statistics, proposed rules, and log entry reference for this
            cycle.
        """
        self._cycle += 1
        t_start = time.monotonic()

        # 1. Submit all approaches to the grid ---------------------------------
        improved_count = 0
        seen_uids: set[str] = set()

        if self._grid is not None:
            for approach in approaches:
                try:
                    replaced = self._grid.challenge(approach)
                    if replaced:
                        improved_count += 1
                    uid = getattr(approach, "miner_uid", None)
                    if uid is not None:
                        seen_uids.add(uid)
                except Exception:  # noqa: BLE001
                    pass  # Be robust to individual bad approaches

        # 2. Read grid stats ---------------------------------------------------
        grid_coverage = 0.0
        ceiling = False

        if self._grid is not None:
            if hasattr(self._grid, "coverage"):
                cov = self._grid.coverage
                # coverage may be a property or a method
                grid_coverage = cov() if callable(cov) else float(cov)
            if hasattr(self._grid, "ceiling_detected"):
                try:
                    ceiling = bool(self._grid.ceiling_detected())
                except Exception:  # noqa: BLE001
                    ceiling = False

        self._coverage_history.append(grid_coverage)

        # 3. Compute aggregate exploration bonus --------------------------------
        bonus = 0.0
        if self._grid is not None and seen_uids and hasattr(self._grid, "exploration_bonus"):
            for uid in seen_uids:
                try:
                    bonus += self._grid.exploration_bonus(uid)
                except Exception:  # noqa: BLE001
                    pass

        # 4. Trigger rule codification when ceiling detected --------------------
        rules_proposed: list[Any] = []
        cooldown_elapsed = (self._cycle - self._last_codification_cycle) > self._config.codification_cooldown

        if ceiling and cooldown_elapsed and self._codifier is not None:
            try:
                if hasattr(self._codifier, "find_clusters") and hasattr(self._codifier, "propose_rules"):
                    clusters = self._codifier.find_clusters([])
                    rules_proposed = self._codifier.propose_rules(clusters)
                elif hasattr(self._codifier, "propose_rules"):
                    rules_proposed = self._codifier.propose_rules([])
                elif hasattr(self._codifier, "codify"):
                    rules_proposed = self._codifier.codify([]) or []
            except Exception:  # noqa: BLE001
                pass
            if rules_proposed:
                self._last_codification_cycle = self._cycle

        # 5. Log evolution event -----------------------------------------------
        log_id = self._write_log(grid_coverage, improved_count, len(rules_proposed))

        return CAMECycleResult(
            grid_coverage=round(grid_coverage, 4),
            ceiling_detected=ceiling,
            rules_proposed=rules_proposed,
            log_id=log_id,
            exploration_bonus=round(bonus, 4),
        )

    def coverage_history(self) -> list[float]:
        """Ordered list of grid coverage values, one per completed cycle."""
        return list(self._coverage_history)

    def summary(self) -> dict[str, Any]:
        """High-level coordinator statistics."""
        grid_summary: dict[str, Any] = {}
        if self._grid is not None and hasattr(self._grid, "summary"):
            try:
                grid_summary = self._grid.summary()
            except Exception:  # noqa: BLE001
                pass

        return {
            "cycle": self._cycle,
            "config": {
                "coverage_threshold": self._config.coverage_threshold,
                "codification_cooldown": self._config.codification_cooldown,
            },
            "coverage_history": self._coverage_history,
            "last_codification_cycle": self._last_codification_cycle,
            "grid": grid_summary,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release resources (closes the EvolutionLog if owned by this coordinator)."""
        if self._owns_log and self._log is not None and hasattr(self._log, "close"):
            try:
                self._log.close()
            except Exception:  # noqa: BLE001
                pass

    def __repr__(self) -> str:  # pragma: no cover
        cov = self._coverage_history[-1] if self._coverage_history else 0.0
        return (
            f"<CAMECoordinator cycle={self._cycle} coverage={cov:.2%} "
            f"config={self._config!r}>"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_log(self, coverage: float, improved: int, rules: int) -> str:
        """Write a single evolution event to the EvolutionLog.

        Returns a log_id string — either a UUID on success or an ``"err:…"``
        token when an invariant violation prevents the write.

        The EvolutionLog enforces strict monotonicity *and* strict acceleration,
        meaning both the value and the rate of improvement must increase each
        epoch.  Because coverage can plateau (especially early on), we track
        each metric independently and only write when the new value strictly
        exceeds the last.
        """
        if self._log is None:
            return f"no-log:{uuid.uuid4().hex[:8]}"

        entries_written = 0
        last_error: str = ""

        for metric, value in (
            ("coverage", coverage),
            ("improved_cells", float(improved)),
            ("rules_proposed", float(rules)),
        ):
            last_epoch, last_value = self._log_state.get(metric, (0, -1.0))
            # Only write if value strictly increases (log invariant)
            if value <= last_value:
                continue
            next_epoch = last_epoch + 1
            try:
                if hasattr(self._log, "record"):
                    self._log.record(next_epoch, metric, value)
                    self._log_state[metric] = (next_epoch, value)
                    entries_written += 1
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)[:80]

        if entries_written > 0:
            return f"log:{self._cycle}:{uuid.uuid4().hex[:8]}"
        if last_error:
            return f"err:{last_error}"
        return f"noop:{self._cycle}"
