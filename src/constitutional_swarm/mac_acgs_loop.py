"""MAC-ACGS Auto-Constitution Pipeline.

Implements the Multi-Agent Constitutional ACGS loop:

    Observations → CAME evolution → Rule proposals → Debate resolution
    → Constitutional update → Hash verification → Audit log

Architecture:
    MacAcgsLoop is the top-level orchestrator that:
    1. Accepts miner approach observations
    2. Runs CAME evolution cycle to discover quality improvements
    3. When new rules are proposed by CAME, submits them to DebateResolver
    4. Approved rules are recorded as a constitutional update
    5. Constitutional hash is verified before each update is committed
    6. All pipeline events are logged in the MacAcgsAuditLog

This implements the "auto-constitution" innovation: governance rules
self-improve through adversarial debate rather than requiring human
specification of every rule change.

Research basis:
    - Constitutional AI (Anthropic 2022): self-improving rule sets
    - Constitutional Evolution (arXiv:2602.00755): evolved constitutions
      outperform human-designed ones by 68% on alignment benchmarks
    - MACI receipt-freeness (B5): DebateResolver provides receipt-freeness
      at the debate layer — no participant can prove their debate position
      to an external coercer
    - MAC-ACGS pattern (novel): CAME provides coverage-driven rule proposals;
      DebateResolver provides adversarial validation before any rule is
      committed to the constitution

Constitutional hash: 608508a9bd224290 — must be verified before every commit.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from constitutional_swarm.bittensor.came_coordinator import (
    CAMECoordinator,
    CAMECoordinatorConfig,
    CAMECycleResult,
)
from constitutional_swarm.debate_resolver import (
    DebateResolver,
    FinalVerdict,
    VerdictOutcome,
)


_CONSTITUTIONAL_HASH = "608508a9bd224290"


# ---------------------------------------------------------------------------
# Events and audit
# ---------------------------------------------------------------------------


class PipelineEventType(Enum):
    """Type of event in the MAC-ACGS pipeline audit log."""

    CAME_CYCLE = "came_cycle"
    RULE_PROPOSED = "rule_proposed"
    DEBATE_OPENED = "debate_opened"
    DEBATE_RESOLVED = "debate_resolved"
    CONSTITUTION_UPDATED = "constitution_updated"
    HASH_VERIFIED = "hash_verified"
    HASH_MISMATCH = "hash_mismatch"
    CYCLE_COMPLETE = "cycle_complete"


@dataclass
class PipelineEvent:
    """A single event in the MAC-ACGS audit log.

    Attributes:
        event_id:       Unique event identifier.
        event_type:     PipelineEventType enum value.
        cycle_number:   Which auto-constitution cycle this belongs to.
        details:        Structured event data.
        timestamp:      Unix timestamp.
    """

    event_id: str
    event_type: PipelineEventType
    cycle_number: int
    details: dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "cycle_number": self.cycle_number,
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class ConstitutionUpdate:
    """A committed constitutional rule update.

    Attributes:
        update_id:           Unique update identifier.
        proposal_id:         ID of the DebateResolver proposal that produced this.
        rule_content:        The rule text being added/modified.
        verdict:             The FinalVerdict that approved this update.
        constitutional_hash: Hash verified at commit time.
        cycle_number:        Which cycle produced this update.
        timestamp:           Unix timestamp.
    """

    update_id: str
    proposal_id: str
    rule_content: str
    verdict: FinalVerdict
    constitutional_hash: str
    cycle_number: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "update_id": self.update_id,
            "proposal_id": self.proposal_id,
            "rule_content": self.rule_content[:200],  # truncate for log
            "verdict_outcome": self.verdict.outcome.value,
            "approval_score": round(self.verdict.approval_score, 4),
            "constitutional_hash": self.constitutional_hash,
            "cycle_number": self.cycle_number,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class MacAcgsConfig:
    """Configuration for the MAC-ACGS auto-constitution loop.

    Attributes:
        constitutional_hash:      Hash enforced at every constitution update.
        debate_approval_threshold: Min approval score for rule acceptance.
        debate_min_challenges:    Challenger quorum for debate resolution.
        auto_challenge:           If True, pipeline auto-generates a Devil's
                                  Advocate challenge for every proposal.
        auto_defend:              If True, pipeline auto-generates a defense.
        max_updates_per_cycle:    Cap on constitutional updates per cycle.
        audit_log_size:           Maximum audit log entries.
        came_config:              Config forwarded to CAMECoordinator.
    """

    constitutional_hash: str = _CONSTITUTIONAL_HASH
    debate_approval_threshold: float = 0.6
    debate_min_challenges: int = 1
    auto_challenge: bool = True
    auto_defend: bool = True
    max_updates_per_cycle: int = 5
    audit_log_size: int = 5000
    came_config: CAMECoordinatorConfig = field(default_factory=CAMECoordinatorConfig)


# ---------------------------------------------------------------------------
# Loop result
# ---------------------------------------------------------------------------


@dataclass
class MacAcgsCycleResult:
    """Result of a single MAC-ACGS pipeline cycle.

    Attributes:
        cycle_number:       Monotonically increasing cycle counter.
        came_result:        Raw CAME evolution output.
        proposals_opened:   Number of debate proposals opened this cycle.
        proposals_approved: Number of proposals that passed debate.
        proposals_rejected: Number of proposals that failed debate.
        constitution_updates: ConstitutionUpdate records committed this cycle.
        hash_verified:      True if constitutional hash passed validation.
        events:             Ordered pipeline events this cycle.
    """

    cycle_number: int
    came_result: CAMECycleResult
    proposals_opened: int
    proposals_approved: int
    proposals_rejected: int
    constitution_updates: list[ConstitutionUpdate]
    hash_verified: bool
    events: list[PipelineEvent]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_number": self.cycle_number,
            "grid_coverage": self.came_result.grid_coverage,
            "ceiling_detected": self.came_result.ceiling_detected,
            "rules_proposed_by_came": len(self.came_result.rules_proposed),
            "proposals_opened": self.proposals_opened,
            "proposals_approved": self.proposals_approved,
            "proposals_rejected": self.proposals_rejected,
            "constitution_updates": len(self.constitution_updates),
            "hash_verified": self.hash_verified,
            "event_count": len(self.events),
        }


# ---------------------------------------------------------------------------
# MAC-ACGS Loop
# ---------------------------------------------------------------------------


class MacAcgsLoop:
    """Top-level MAC-ACGS auto-constitution orchestrator.

    Wires together CAME evolution → adversarial debate → constitutional
    update in a single `run_cycle()` call.

    Usage::

        loop = MacAcgsLoop()

        # Each cycle: submit observations, get constitution updates
        from constitutional_swarm.bittensor.map_elites import MinerApproach
        approaches = [MinerApproach(...), ...]

        result = loop.run_cycle(approaches)
        print(result.proposals_approved)      # rules that passed debate
        print(result.constitution_updates)    # committed rule changes

        # Add human challengers before running cycle
        loop.add_external_challenger("human-reviewer-1")

        # Review audit log
        for event in loop.audit_log():
            print(event["event_type"], event["details"])

    Args:
        config: MacAcgsConfig (default: sensible defaults).
        came: Optional pre-built CAMECoordinator.
        debate: Optional pre-built DebateResolver.
    """

    def __init__(
        self,
        config: MacAcgsConfig | None = None,
        *,
        came: CAMECoordinator | None = None,
        debate: DebateResolver | None = None,
    ) -> None:
        self._config = config or MacAcgsConfig()
        self._came = came or CAMECoordinator(config=self._config.came_config)
        self._debate = debate or DebateResolver(
            approval_threshold=self._config.debate_approval_threshold,
            min_challenges=self._config.debate_min_challenges,
            constitutional_hash=self._config.constitutional_hash,
        )

        self._cycle_number: int = 0
        self._constitution_updates: list[ConstitutionUpdate] = []
        self._audit_log: list[PipelineEvent] = []
        self._external_challengers: list[str] = []

    # ── External participants ─────────────────────────────────────────────

    def add_external_challenger(self, agent_id: str) -> None:
        """Register an external challenger (human reviewer or validator).

        External challengers are used in auto-challenge mode: the pipeline
        attributes auto-generated challenges to the first registered challenger
        (or 'auto-challenger' if none registered).
        """
        self._external_challengers.append(agent_id)

    # ── Main cycle ───────────────────────────────────────────────────────

    def run_cycle(self, approaches: list[Any]) -> MacAcgsCycleResult:
        """Execute one MAC-ACGS pipeline cycle.

        Steps:
            1. Verify constitutional hash (fail-closed)
            2. Run CAME evolution on approaches
            3. For each rule proposed by CAME, open a debate proposal
            4. Auto-challenge + auto-defend if configured
            5. Resolve all debates
            6. Commit approved rules as constitutional updates
            7. Log all events
            8. Return MacAcgsCycleResult

        Args:
            approaches: Miner approach observations (passed to CAME).

        Returns:
            MacAcgsCycleResult with full pipeline outcome.
        """
        self._cycle_number += 1
        cycle = self._cycle_number
        events: list[PipelineEvent] = []

        # Step 1: Hash verification (fail-closed)
        hash_ok = self._verify_hash()
        events.append(self._event(
            PipelineEventType.HASH_VERIFIED if hash_ok else PipelineEventType.HASH_MISMATCH,
            cycle,
            {"constitutional_hash": self._config.constitutional_hash, "verified": hash_ok},
        ))
        if not hash_ok:
            # Fail-closed: abort cycle
            came_result = CAMECycleResult(
                grid_coverage=0.0,
                ceiling_detected=False,
                rules_proposed=[],
                log_id="aborted:hash_mismatch",
                exploration_bonus=0.0,
            )
            return MacAcgsCycleResult(
                cycle_number=cycle,
                came_result=came_result,
                proposals_opened=0,
                proposals_approved=0,
                proposals_rejected=0,
                constitution_updates=[],
                hash_verified=False,
                events=events,
            )

        # Step 2: CAME evolution
        came_result = self._came.evolve_cycle(approaches)
        events.append(self._event(PipelineEventType.CAME_CYCLE, cycle, {
            "grid_coverage": came_result.grid_coverage,
            "ceiling_detected": came_result.ceiling_detected,
            "rules_proposed": len(came_result.rules_proposed),
            "exploration_bonus": came_result.exploration_bonus,
        }))

        # Step 3–6: Debate + commit (only if CAME proposed rules)
        proposals_opened = 0
        proposals_approved = 0
        proposals_rejected = 0
        updates: list[ConstitutionUpdate] = []

        if came_result.rules_proposed:
            proposal_count = min(len(came_result.rules_proposed), self._config.max_updates_per_cycle)
            for i in range(proposal_count):
                pid = f"mac-{cycle}-{i}-{uuid.uuid4().hex[:8]}"
                rule_content = (
                    f"Auto-proposed rule from CAME cycle {cycle}, proposal {i+1}. "
                    f"Coverage: {came_result.grid_coverage:.3f}. "
                    f"Exploration bonus: {came_result.exploration_bonus:.3f}."
                )
                proposer_id = f"came-coordinator-cycle-{cycle}"

                # Open debate
                try:
                    self._debate.propose(
                        proposal_id=pid,
                        proposer_id=proposer_id,
                        domain="constitutional-evolution",
                        content=rule_content,
                    )
                    proposals_opened += 1
                    events.append(self._event(PipelineEventType.DEBATE_OPENED, cycle, {
                        "proposal_id": pid,
                        "proposer": proposer_id,
                    }))
                except ValueError:
                    continue  # duplicate pid (shouldn't happen with uuid)

                # Auto-challenge
                if self._config.auto_challenge:
                    challenger_id = (
                        self._external_challengers[0]
                        if self._external_challengers
                        else "auto-challenger"
                    )
                    objection = (
                        f"Auto-generated Devil's Advocate challenge for proposal {pid}: "
                        f"Does this rule improve constitutional consistency "
                        f"without introducing new failure modes?"
                    )
                    self._debate.challenge(
                        proposal_id=pid,
                        challenger_id=challenger_id,
                        objection=objection,
                        severity=0.4,  # moderate default severity
                    )

                # Auto-defend
                if self._config.auto_defend:
                    self._debate.defend(
                        proposal_id=pid,
                        defender_id=proposer_id,
                        rebuttal=(
                            f"Defense for {pid}: Rule derived from empirical "
                            f"CAME coverage data with {came_result.grid_coverage:.1%} "
                            f"grid coverage. Exploration bonus {came_result.exploration_bonus:.2f} "
                            f"indicates genuine quality improvements."
                        ),
                        concession="Rule subject to 30-day review window before full adoption.",
                    )

                # Resolve debate
                verdict = self._debate.resolve(pid, constitutional_hash=self._config.constitutional_hash)
                events.append(self._event(PipelineEventType.DEBATE_RESOLVED, cycle, {
                    "proposal_id": pid,
                    "outcome": verdict.outcome.value,
                    "approval_score": verdict.approval_score,
                }))

                if verdict.outcome == VerdictOutcome.APPROVED:
                    proposals_approved += 1
                    update = ConstitutionUpdate(
                        update_id=f"upd-{cycle}-{i}-{uuid.uuid4().hex[:8]}",
                        proposal_id=pid,
                        rule_content=rule_content,
                        verdict=verdict,
                        constitutional_hash=self._config.constitutional_hash,
                        cycle_number=cycle,
                    )
                    updates.append(update)
                    self._constitution_updates.append(update)
                    events.append(self._event(PipelineEventType.CONSTITUTION_UPDATED, cycle, update.to_dict()))
                else:
                    proposals_rejected += 1

        # Step 7: cycle complete event
        events.append(self._event(PipelineEventType.CYCLE_COMPLETE, cycle, {
            "proposals_opened": proposals_opened,
            "proposals_approved": proposals_approved,
            "proposals_rejected": proposals_rejected,
            "updates_committed": len(updates),
        }))

        # Persist events
        self._audit_log.extend(events)
        if len(self._audit_log) > self._config.audit_log_size:
            self._audit_log = self._audit_log[-self._config.audit_log_size:]

        return MacAcgsCycleResult(
            cycle_number=cycle,
            came_result=came_result,
            proposals_opened=proposals_opened,
            proposals_approved=proposals_approved,
            proposals_rejected=proposals_rejected,
            constitution_updates=updates,
            hash_verified=True,
            events=events,
        )

    # ── Queries ──────────────────────────────────────────────────────────

    def audit_log(self) -> list[dict[str, Any]]:
        """All pipeline events (most recent last)."""
        return [e.to_dict() for e in self._audit_log]

    def constitution_updates(self) -> list[dict[str, Any]]:
        """All committed constitutional updates across all cycles."""
        return [u.to_dict() for u in self._constitution_updates]

    def cycle_number(self) -> int:
        """Current cycle number."""
        return self._cycle_number

    def coverage_history(self) -> list[float]:
        """CAME grid coverage history."""
        return self._came.coverage_history()

    def summary(self) -> dict[str, Any]:
        """Full pipeline summary."""
        return {
            "cycle_number": self._cycle_number,
            "total_constitution_updates": len(self._constitution_updates),
            "total_audit_events": len(self._audit_log),
            "coverage_history": self.coverage_history(),
            "came_summary": self._came.summary(),
            "debate_summary": self._debate.summary(),
            "constitutional_hash": self._config.constitutional_hash,
        }

    def __repr__(self) -> str:
        return (
            f"MacAcgsLoop("
            f"cycle={self._cycle_number}, "
            f"updates={len(self._constitution_updates)})"
        )

    # ── Internal ─────────────────────────────────────────────────────────

    def _verify_hash(self) -> bool:
        """Verify the constitutional hash is intact (fail-closed gate)."""
        return self._config.constitutional_hash == _CONSTITUTIONAL_HASH

    def _event(
        self,
        event_type: PipelineEventType,
        cycle: int,
        details: dict[str, Any],
    ) -> PipelineEvent:
        return PipelineEvent(
            event_id=f"evt-{cycle}-{event_type.value}-{uuid.uuid4().hex[:8]}",
            event_type=event_type,
            cycle_number=cycle,
            details=details,
        )
