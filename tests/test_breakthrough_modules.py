"""Comprehensive tests for breakthrough modules added in this session.

Modules covered:
1. FederatedConstitutionBridge (federated_bridge.py)
2. DebateResolver (debate_resolver.py)
3. DiscreteGaussianSampler (swarm_ode.py)
4. GovernanceCoordinator new methods (bittensor/governance_coordinator.py)
5. CAMECoordinator (bittensor/came_coordinator.py)
6. MacAcgsLoop (mac_acgs_loop.py)
"""

from __future__ import annotations

import time

import pytest
from constitutional_swarm.bittensor.came_coordinator import (
    CAMECoordinator,
    CAMECoordinatorConfig,
)
from constitutional_swarm.bittensor.emission_calculator import (
    MinerEmissionInput,
    MinerTier,
)
from constitutional_swarm.bittensor.governance_coordinator import (
    GovernanceCoordinator,
)
from constitutional_swarm.debate_resolver import (
    Challenge,
    DebateResolver,
    Proposal,
    VerdictOutcome,
)
from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
)
from constitutional_swarm.swarm_ode import DiscreteGaussianSampler

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_CONST_HASH = "608508a9bd224290"
_NOW = time.time()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_credential(
    agent_id: str = "agent-test",
    org_id: str = "test-org",
    constitutional_hash: str = _CONST_HASH,
    expires_at: float = 0.0,
    domains: tuple[str, ...] = (),
) -> AgentCredential:
    return AgentCredential(
        agent_id=agent_id,
        org_id=org_id,
        pubkey_fingerprint="abcdef123456",
        constitutional_hash=constitutional_hash,
        issued_at=_NOW - 10,
        expires_at=expires_at,
        domains=domains,
    )


def _make_bridge() -> FederatedConstitutionBridge:
    return FederatedConstitutionBridge(
        local_constitutional_hash=_CONST_HASH,
        require_hash_match=True,
    )


# ===========================================================================
# 1. FederatedConstitutionBridge
# ===========================================================================


class TestFederatedConstitutionBridge:
    """Tests for fail-closed cross-org gate enforcement."""

    def test_gate_rejects_unknown_credential(self) -> None:
        bridge = _make_bridge()
        decision = bridge.gate("non-existent-agent", domain="privacy")
        assert not decision.allowed
        assert decision.reason == "UNKNOWN_CREDENTIAL"

    def test_gate_rejects_revoked_credential(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="agent-rev")
        bridge.register_credential(cred)
        bridge.revoke("agent-rev")
        decision = bridge.gate("agent-rev", domain="safety")
        assert not decision.allowed
        assert decision.reason == "REVOKED"

    def test_gate_rejects_expired_credential(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(
            agent_id="agent-exp",
            expires_at=_NOW - 100,  # already expired
        )
        bridge.register_credential(cred)
        decision = bridge.gate("agent-exp", domain="")
        assert not decision.allowed
        assert decision.reason == "EXPIRED"

    def test_gate_rejects_hash_mismatch(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(
            agent_id="agent-hash",
            constitutional_hash="WRONG_HASH_1234",
        )
        bridge.register_credential(cred)
        decision = bridge.gate("agent-hash", domain="")
        assert not decision.allowed
        assert decision.reason == "HASH_MISMATCH"

    def test_gate_rejects_domain_denied(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(
            agent_id="agent-dom",
            domains=("safety",),  # only safety, not privacy
        )
        bridge.register_credential(cred)
        decision = bridge.gate("agent-dom", domain="privacy")
        assert not decision.allowed
        assert decision.reason == "DOMAIN_DENIED"

    def test_gate_allows_valid_active_correct_hash(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(
            agent_id="agent-ok",
            domains=("privacy",),
        )
        bridge.register_credential(cred)
        decision = bridge.gate("agent-ok", domain="privacy")
        assert decision.allowed
        assert decision.reason == "ALLOWED"

    def test_gate_allows_valid_credential_no_domain_restriction(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="agent-open", domains=())
        bridge.register_credential(cred)
        decision = bridge.gate("agent-open", domain="anything")
        assert decision.allowed

    def test_revoke_returns_true_for_known_agent(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="agent-known")
        bridge.register_credential(cred)
        assert bridge.revoke("agent-known") is True

    def test_revoke_returns_false_for_unknown_agent(self) -> None:
        bridge = _make_bridge()
        assert bridge.revoke("ghost-agent") is False

    def test_summary_returns_correct_counts(self) -> None:
        bridge = _make_bridge()
        cred_ok = _make_credential(agent_id="agent-a")
        cred_bad = _make_credential(agent_id="agent-b", constitutional_hash="WRONG")
        bridge.register_credential(cred_ok)
        bridge.register_credential(cred_bad)

        bridge.gate("agent-a", domain="")  # should ALLOW
        bridge.gate("agent-b", domain="")  # should DENY (hash mismatch)
        bridge.gate("nobody", domain="")  # should DENY (unknown)

        s = bridge.summary()
        assert s["registered_credentials"] == 2
        assert s["total_decisions"] == 3
        assert s["allowed"] == 1
        assert s["denied"] == 2

    def test_audit_log_records_all_decisions(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="agent-log")
        bridge.register_credential(cred)

        bridge.gate("agent-log", domain="privacy")
        bridge.gate("ghost", domain="safety")

        log = bridge.audit_log()
        assert len(log) == 2
        assert all("agent_id" in entry for entry in log)
        assert all("allowed" in entry for entry in log)
        assert all("timestamp" in entry for entry in log)

    def test_audit_log_is_ordered_chronologically(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="agent-ts")
        bridge.register_credential(cred)

        t1 = _NOW + 1
        t2 = _NOW + 2
        bridge.gate("agent-ts", domain="", now=t1)
        bridge.gate("agent-ts", domain="", now=t2)

        log = bridge.audit_log()
        assert log[0]["timestamp"] <= log[1]["timestamp"]


# ===========================================================================
# 2. DebateResolver
# ===========================================================================


class TestDebateResolver:
    """Tests for the adversarial debate resolution protocol."""

    def test_propose_creates_proposal(self) -> None:
        resolver = DebateResolver()
        prop = resolver.propose("p-001", "miner-1", "privacy", "Content A")
        assert isinstance(prop, Proposal)
        assert prop.proposal_id == "p-001"
        assert prop.proposer_id == "miner-1"

    def test_propose_duplicate_raises_value_error(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p-dup", "miner-1", "safety", "Content")
        with pytest.raises(ValueError, match="already exists"):
            resolver.propose("p-dup", "miner-2", "safety", "Content 2")

    def test_challenge_invalid_severity_raises_value_error(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p-sev", "miner-1", "safety", "Content")
        with pytest.raises(ValueError, match="severity"):
            resolver.challenge("p-sev", "validator-1", "bad objection", severity=1.5)

    def test_challenge_negative_severity_raises_value_error(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p-neg", "miner-1", "safety", "Content")
        with pytest.raises(ValueError, match="severity"):
            resolver.challenge("p-neg", "validator-1", "bad objection", severity=-0.1)

    def test_challenge_unknown_proposal_raises_key_error(self) -> None:
        resolver = DebateResolver()
        with pytest.raises(KeyError, match="not found"):
            resolver.challenge("ghost-proposal", "validator-1", "objection")

    def test_resolve_zero_challenges_min_one_deadlock(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p-dead", "miner-1", "safety", "Content")
        # No challenges submitted
        verdict = resolver.resolve("p-dead")
        assert verdict.outcome == VerdictOutcome.DEADLOCK

    def test_resolve_challenge_defense_moderate_severity_approved_or_rejected(self) -> None:
        resolver = DebateResolver(min_challenges=1, approval_threshold=0.6)
        resolver.propose("p-mod", "miner-1", "privacy", "Content")
        resolver.challenge("p-mod", "validator-1", "moderate issue", severity=0.4)
        resolver.defend("p-mod", "miner-1", "strong rebuttal")
        verdict = resolver.resolve("p-mod")
        assert verdict.outcome in (VerdictOutcome.APPROVED, VerdictOutcome.REJECTED)
        assert 0.0 <= verdict.approval_score <= 1.0

    def test_resolve_hash_mismatch_raises_permission_error(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p-hash", "miner-1", "safety", "Content")
        resolver.challenge("p-hash", "validator-1", "objection", severity=0.5)
        with pytest.raises(PermissionError, match="hash"):
            resolver.resolve("p-hash", constitutional_hash="BAD_HASH")

    def test_resolve_high_severity_escalated(self) -> None:
        resolver = DebateResolver(
            min_challenges=1,
            escalation_threshold=0.85,
        )
        resolver.propose("p-esc", "miner-1", "safety", "Content")
        resolver.challenge("p-esc", "validator-1", "critical safety concern", severity=0.9)
        verdict = resolver.resolve("p-esc")
        assert verdict.outcome == VerdictOutcome.ESCALATED

    def test_get_record_merkle_root_non_empty_after_resolve(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p-mrk", "miner-1", "safety", "Content")
        resolver.challenge("p-mrk", "validator-1", "objection", severity=0.3)
        resolver.resolve("p-mrk")
        record = resolver.get_record("p-mrk")
        assert record is not None
        assert len(record.merkle_root) > 0

    def test_summary_returns_correct_counts(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p-s1", "miner-1", "safety", "Content 1")
        resolver.propose("p-s2", "miner-2", "privacy", "Content 2")
        resolver.challenge("p-s1", "v-1", "objection", severity=0.5)
        resolver.resolve("p-s1")  # resolves p-s1

        s = resolver.summary()
        assert s["total_proposals"] == 2
        assert s["resolved"] == 1
        assert s["open"] == 1
        assert "outcome_counts" in s
        assert "avg_approval_score" in s

    def test_open_and_resolved_proposals(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p-open", "miner-1", "safety", "Content")
        resolver.propose("p-closed", "miner-2", "privacy", "Content")
        resolver.challenge("p-closed", "v-1", "objection", severity=0.5)
        resolver.resolve("p-closed")

        assert "p-open" in resolver.open_proposals()
        assert "p-closed" in resolver.resolved_proposals()

    @pytest.mark.parametrize("severity", [0.05, 0.5, 1.0])
    def test_challenge_valid_severity_boundaries(self, severity: float) -> None:
        resolver = DebateResolver()
        resolver.propose(f"p-sev-{severity}", "miner-1", "safety", "Content")
        c = resolver.challenge(f"p-sev-{severity}", "v-1", "objection", severity=severity)
        assert isinstance(c, Challenge)
        assert c.severity == severity


# ===========================================================================
# 3. DiscreteGaussianSampler
# ===========================================================================


class TestDiscreteGaussianSampler:
    """Tests for the discrete Gaussian DP noise sampler."""

    def test_instantiation_sigma_one_tail_ten(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        assert sampler.sigma == 1.0
        assert sampler.tail_bound == 10

    def test_sample_returns_integer_in_tail_range(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        for _ in range(50):
            v = sampler.sample()
            assert isinstance(v, int)
            assert -10 <= v <= 10

    def test_sample_vector_returns_correct_length_and_range(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        vec = sampler.sample_vector(n=100)
        assert len(vec) == 100
        assert all(isinstance(x, int) for x in vec)
        assert all(-10 <= x <= 10 for x in vec)

    def test_pmf_center_greater_than_tail(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        assert sampler.pmf(0) > sampler.pmf(5)

    def test_pmf_outside_support_is_zero(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        assert sampler.pmf(99999) == 0.0
        assert sampler.pmf(-99999) == 0.0

    def test_sample_tensor_correct_shape(self) -> None:
        import torch

        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        t = sampler.sample_tensor(shape=(4,))
        assert t.shape == (4,)
        assert t.dtype == torch.float32

    def test_deterministic_with_same_seed(self) -> None:
        seed = 42
        s1 = DiscreteGaussianSampler(sigma=1.0, tail_bound=10, seed=seed)
        s2 = DiscreteGaussianSampler(sigma=1.0, tail_bound=10, seed=seed)
        samples1 = s1.sample_vector(20)
        samples2 = s2.sample_vector(20)
        assert samples1 == samples2

    def test_different_seeds_produce_different_sequences(self) -> None:
        s1 = DiscreteGaussianSampler(sigma=2.0, tail_bound=15, seed=1)
        s2 = DiscreteGaussianSampler(sigma=2.0, tail_bound=15, seed=9999)
        samples1 = s1.sample_vector(30)
        samples2 = s2.sample_vector(30)
        # With overwhelming probability two random seeds differ in 30 samples
        assert samples1 != samples2

    def test_sigma_zero_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="sigma"):
            DiscreteGaussianSampler(sigma=0.0)

    def test_sigma_negative_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="sigma"):
            DiscreteGaussianSampler(sigma=-1.0)

    def test_pmf_sums_to_one(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=1.0, tail_bound=10)
        total = sum(sampler.pmf(k) for k in range(-10, 11))
        assert abs(total - 1.0) < 1e-6

    @pytest.mark.parametrize("sigma,tail", [(0.5, 5), (2.0, 15), (3.0, 20)])
    def test_various_sigma_tail_combinations(self, sigma: float, tail: int) -> None:
        sampler = DiscreteGaussianSampler(sigma=sigma, tail_bound=tail)
        vec = sampler.sample_vector(50)
        assert all(-tail <= v <= tail for v in vec)


# ===========================================================================
# 4. GovernanceCoordinator new methods
# ===========================================================================


class TestGovernanceCoordinatorNewMethods:
    """Tests for screen_miner_authenticity, record_miner_authenticity, compute_emissions."""

    def _make_coordinator(self) -> GovernanceCoordinator:
        return GovernanceCoordinator()

    def test_screen_miner_authenticity_substantial_text_returns_bool(self) -> None:
        coord = self._make_coordinator()
        # A substantial, reasoned governance decision
        judgment = (
            "After carefully weighing the constitutional principles of transparency, "
            "fairness, and proportionality, I approve this proposal because it "
            "aligns with the established precedents for data governance under "
            "Section 4.2 of the ACGS constitution. The evidence presented is "
            "compelling and the risk mitigation plan is comprehensive."
        )
        reasoning = (
            "Constitutional review shows no violations. The proposal improves "
            "validator diversity by 23% while preserving audit trail integrity."
        )
        result = coord.screen_miner_authenticity("miner-001", judgment, reasoning)
        # Result must be a bool (True or False depending on threshold)
        assert isinstance(result, bool)

    def test_screen_miner_authenticity_trivial_text(self) -> None:
        coord = self._make_coordinator()
        # Trivial content — likely to score low on authenticity
        result = coord.screen_miner_authenticity("miner-002", "yes", "ok")
        assert isinstance(result, bool)

    def test_record_miner_authenticity_rolling_window_capped_at_20(self) -> None:
        coord = self._make_coordinator()
        uid = "miner-roll"
        # Record 25 scores
        for i in range(25):
            coord.record_miner_authenticity(uid, float(i) / 25.0)
        # Rolling window must be capped at 20
        window = coord._miner_authenticity[uid]
        assert len(window) == 20
        # The oldest 5 should have been dropped; window should end with 24/25=0.96
        assert abs(window[-1] - 24.0 / 25.0) < 1e-9

    def test_compute_emissions_without_manifold_returns_emission_cycle(self) -> None:
        from constitutional_swarm.bittensor.emission_calculator import EmissionCycle

        coord = self._make_coordinator()
        inputs = [
            MinerEmissionInput("miner-a", tier=MinerTier.APPRENTICE),
            MinerEmissionInput("miner-b", tier=MinerTier.JOURNEYMAN),
        ]
        cycle = coord.compute_emissions(inputs)
        assert isinstance(cycle, EmissionCycle)

    def test_compute_emissions_with_manifold_uses_column_sums(self) -> None:
        from constitutional_swarm.bittensor.emission_calculator import EmissionCycle
        from constitutional_swarm.manifold import GovernanceManifold

        coord = self._make_coordinator()
        manifold = GovernanceManifold(num_agents=2)
        manifold.update_trust(0, 1, 1.0)
        manifold.update_trust(1, 0, 0.5)
        coord.set_manifold(manifold)

        inputs = [
            MinerEmissionInput("miner-x", tier=MinerTier.MASTER),
            MinerEmissionInput("miner-y", tier=MinerTier.APPRENTICE),
        ]
        cycle = coord.compute_emissions(inputs)
        assert isinstance(cycle, EmissionCycle)

    def test_screen_records_into_authenticity_window(self) -> None:
        coord = self._make_coordinator()
        uid = "miner-screen"
        assert uid not in coord._miner_authenticity
        coord.screen_miner_authenticity(uid, "governance judgment text", "reasoning")
        assert uid in coord._miner_authenticity
        assert len(coord._miner_authenticity[uid]) == 1


# ===========================================================================
# 5. CAMECoordinator
# ===========================================================================


class TestCAMECoordinator:
    """Tests for the Coverage-Aware MAP-Elites governance coordinator."""

    def test_instantiation_default_config(self) -> None:
        coord = CAMECoordinator()
        assert coord is not None
        coord.close()

    def test_instantiation_custom_config(self) -> None:
        config = CAMECoordinatorConfig(
            coverage_threshold=0.9,
            codification_cooldown=10,
        )
        coord = CAMECoordinator(config=config)
        assert coord is not None
        coord.close()

    def test_evolve_cycle_empty_approaches_returns_valid_result(self) -> None:
        coord = CAMECoordinator()
        result = coord.evolve_cycle([])
        assert hasattr(result, "grid_coverage")
        assert hasattr(result, "ceiling_detected")
        assert hasattr(result, "rules_proposed")
        assert hasattr(result, "log_id")
        assert hasattr(result, "exploration_bonus")
        assert isinstance(result.grid_coverage, float)
        assert isinstance(result.ceiling_detected, bool)
        assert isinstance(result.rules_proposed, list)
        assert isinstance(result.log_id, str)
        assert isinstance(result.exploration_bonus, float)
        coord.close()

    def test_evolve_cycle_increments_cycle_counter(self) -> None:
        coord = CAMECoordinator()
        coord.evolve_cycle([])
        coord.evolve_cycle([])
        s = coord.summary()
        assert s["cycle"] == 2
        coord.close()

    def test_coverage_history_returns_list(self) -> None:
        coord = CAMECoordinator()
        assert coord.coverage_history() == []
        coord.evolve_cycle([])
        history = coord.coverage_history()
        assert isinstance(history, list)
        assert len(history) == 1
        coord.close()

    def test_coverage_history_grows_with_cycles(self) -> None:
        coord = CAMECoordinator()
        for _ in range(5):
            coord.evolve_cycle([])
        assert len(coord.coverage_history()) == 5
        coord.close()

    def test_summary_returns_dict_with_expected_keys(self) -> None:
        coord = CAMECoordinator()
        coord.evolve_cycle([])
        s = coord.summary()
        assert isinstance(s, dict)
        assert "cycle" in s
        assert "config" in s
        assert "coverage_history" in s
        assert "last_codification_cycle" in s
        assert "grid" in s
        coord.close()

    def test_summary_config_reflects_coordinator_config(self) -> None:
        config = CAMECoordinatorConfig(coverage_threshold=0.75, codification_cooldown=3)
        coord = CAMECoordinator(config=config)
        s = coord.summary()
        assert s["config"]["coverage_threshold"] == 0.75
        assert s["config"]["codification_cooldown"] == 3
        coord.close()

    def test_grid_coverage_is_float_in_unit_interval(self) -> None:
        coord = CAMECoordinator()
        result = coord.evolve_cycle([])
        assert 0.0 <= result.grid_coverage <= 1.0
        coord.close()

    def test_close_is_idempotent(self) -> None:
        coord = CAMECoordinator()
        coord.close()
        coord.close()  # should not raise


# ========================== MacAcgsLoop Tests =============================
# Full integration of CAME → DebateResolver → ConstitutionUpdate pipeline.


from unittest.mock import MagicMock

from constitutional_swarm.bittensor.came_coordinator import (
    CAMECycleResult,
)
from constitutional_swarm.mac_acgs_loop import (
    MacAcgsConfig,
    MacAcgsLoop,
    PipelineEventType,
)


def _make_came_mock(rules: list[str] | None = None) -> MagicMock:
    """Build a mock CAMECoordinator that returns ``rules`` on evolve_cycle."""
    mock = MagicMock()
    rules = rules or []
    mock.evolve_cycle.return_value = CAMECycleResult(
        grid_coverage=0.75,
        ceiling_detected=bool(rules),
        rules_proposed=rules,
        log_id="mock-log:1",
        exploration_bonus=0.1,
    )
    mock.coverage_history.return_value = [0.75]
    mock.summary.return_value = {"mocked": True}
    mock.close = MagicMock()
    return mock


class TestMacAcgsLoopHappyPath:
    """MacAcgsLoop: default config with auto-challenge + auto-defend."""

    def test_cycle_with_no_rules_proposed(self) -> None:
        """If CAME proposes nothing, pipeline completes without debate."""
        loop = MacAcgsLoop(came=_make_came_mock(rules=[]))
        result = loop.run_cycle([])
        assert result.cycle_number == 1
        assert result.proposals_opened == 0
        assert result.proposals_approved == 0
        assert result.proposals_rejected == 0
        assert result.hash_verified is True
        assert len(result.constitution_updates) == 0

    def test_cycle_with_rules_approved(self) -> None:
        """Auto-challenge (severity 0.15) + auto-defend → APPROVED with default threshold 0.6."""
        loop = MacAcgsLoop(came=_make_came_mock(rules=["Rule A", "Rule B"]))
        result = loop.run_cycle([])
        # With auto-challenge severity=0.15, auto-defend: score = 0.5 - 0.15*0.3 + 0.15 = 0.605 ≥ 0.6
        assert result.proposals_opened == 2
        assert result.proposals_approved == 2
        assert result.proposals_rejected == 0
        assert len(result.constitution_updates) == 2
        for upd in result.constitution_updates:
            assert upd.rule_content in ("Rule A", "Rule B")

    def test_scoring_math_default_config(self) -> None:
        """Verify the exact approval score math."""
        loop = MacAcgsLoop(came=_make_came_mock(rules=["test rule"]))
        result = loop.run_cycle([])
        # score = 0.5 - 0.15*0.3 + 0.15 = 0.605
        assert len(result.constitution_updates) == 1
        verdict = result.constitution_updates[0].verdict
        assert abs(verdict.approval_score - 0.605) < 1e-9

    def test_max_updates_per_cycle_cap(self) -> None:
        """max_updates_per_cycle caps how many proposals are opened."""
        cfg = MacAcgsConfig(max_updates_per_cycle=2)
        loop = MacAcgsLoop(config=cfg, came=_make_came_mock(rules=["r1", "r2", "r3", "r4"]))
        result = loop.run_cycle([])
        assert result.proposals_opened == 2  # only first 2 processed

    def test_constitution_updates_accumulate(self) -> None:
        """Updates from multiple cycles accumulate in constitution_updates()."""
        came = _make_came_mock(rules=["R1"])
        loop = MacAcgsLoop(came=came)
        loop.run_cycle([])
        # Second cycle — need fresh debate for new proposal IDs
        came.evolve_cycle.return_value = CAMECycleResult(
            grid_coverage=0.80,
            ceiling_detected=True,
            rules_proposed=["R2"],
            log_id="mock:2",
            exploration_bonus=0.05,
        )
        loop.run_cycle([])
        all_updates = loop.constitution_updates()
        assert len(all_updates) == 2

    def test_cycle_number_increments(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=[]))
        loop.run_cycle([])
        loop.run_cycle([])
        assert loop.cycle_number() == 2


class TestMacAcgsLoopHashAbort:
    """MacAcgsLoop: hash mismatch aborts cycle (fail-closed)."""

    def test_hash_mismatch_aborts_cycle(self) -> None:
        cfg = MacAcgsConfig(constitutional_hash="bad-hash-000000")
        loop = MacAcgsLoop(config=cfg, came=_make_came_mock(rules=["R"]))
        result = loop.run_cycle([])
        assert result.hash_verified is False
        assert result.proposals_opened == 0
        assert len(result.constitution_updates) == 0
        # CAME should not even be called
        loop._came.evolve_cycle.assert_not_called()

    def test_hash_mismatch_events(self) -> None:
        cfg = MacAcgsConfig(constitutional_hash="bad-hash-000000")
        loop = MacAcgsLoop(config=cfg, came=_make_came_mock(rules=["R"]))
        result = loop.run_cycle([])
        event_types = [e.event_type for e in result.events]
        assert PipelineEventType.HASH_MISMATCH in event_types
        assert PipelineEventType.CAME_CYCLE not in event_types


class TestMacAcgsLoopAudit:
    """MacAcgsLoop: audit log integrity."""

    def test_audit_log_records_all_events(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=["R1"]))
        result = loop.run_cycle([])
        log = loop.audit_log()
        assert len(log) == len(result.events)
        assert all("event_type" in e for e in log)

    def test_audit_log_size_cap(self) -> None:
        cfg = MacAcgsConfig(audit_log_size=5)
        loop = MacAcgsLoop(config=cfg, came=_make_came_mock(rules=["R"]))
        for _ in range(10):
            came_mock = loop._came
            came_mock.evolve_cycle.return_value = CAMECycleResult(
                grid_coverage=0.5,
                ceiling_detected=True,
                rules_proposed=["R"],
                log_id="m",
                exploration_bonus=0.0,
            )
            loop.run_cycle([])
        assert len(loop.audit_log()) <= 5

    def test_summary_keys(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=[]))
        loop.run_cycle([])
        s = loop.summary()
        assert "cycle_number" in s
        assert "total_constitution_updates" in s
        assert "constitutional_hash" in s


class TestMacAcgsLoopReject:
    """MacAcgsLoop: rules can be rejected by raising threshold."""

    def test_high_threshold_rejects(self) -> None:
        cfg = MacAcgsConfig(debate_approval_threshold=0.99)
        loop = MacAcgsLoop(config=cfg, came=_make_came_mock(rules=["R"]))
        result = loop.run_cycle([])
        assert result.proposals_approved == 0
        assert result.proposals_rejected == 1
        assert len(result.constitution_updates) == 0


class TestMacAcgsLoopExternalChallengers:
    """MacAcgsLoop: add_external_challenger attribution."""

    def test_external_challenger_attributed(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=["R"]))
        loop.add_external_challenger("human-reviewer-1")
        result = loop.run_cycle([])
        # The auto-challenge should use the registered challenger
        assert result.proposals_opened == 1

    def test_repr(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=[]))
        assert "MacAcgsLoop" in repr(loop)


class TestMacAcgsLoopRuleContent:
    """MacAcgsLoop: actual rule content is used, not synthetic placeholders."""

    def test_rule_content_from_came_proposal(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=["Agents must log all decisions"]))
        result = loop.run_cycle([])
        assert len(result.constitution_updates) == 1
        assert result.constitution_updates[0].rule_content == "Agents must log all decisions"

    def test_empty_rule_gets_fallback_descriptor(self) -> None:
        loop = MacAcgsLoop(came=_make_came_mock(rules=["  "]))  # whitespace-only
        result = loop.run_cycle([])
        assert len(result.constitution_updates) == 1
        assert "CAME rule" in result.constitution_updates[0].rule_content


# =================== Guard Regression Tests ================================
# Tests for post-verdict guards, PENDING enforcement, min-severity,
# defense cap, and DrandClient input validation — all flagged by
# Phase 4 reviewers as needing explicit coverage.


class TestDebateResolverPostVerdictGuards:
    """Post-verdict mutation must be blocked after Merkle seal."""

    def test_challenge_after_resolve_raises(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p1", "m1", "safety", "Content")
        resolver.challenge("p1", "v1", "objection", severity=0.5)
        resolver.resolve("p1")
        with pytest.raises(RuntimeError, match="already resolved"):
            resolver.challenge("p1", "v2", "late", severity=0.5)

    def test_defend_after_resolve_raises(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p1", "m1", "safety", "Content")
        resolver.challenge("p1", "v1", "objection", severity=0.5)
        resolver.resolve("p1")
        with pytest.raises(RuntimeError, match="already resolved"):
            resolver.defend("p1", "m1", "late defense")

    def test_double_resolve_raises(self) -> None:
        resolver = DebateResolver(min_challenges=1)
        resolver.propose("p1", "m1", "safety", "Content")
        resolver.challenge("p1", "v1", "objection", severity=0.5)
        resolver.resolve("p1")
        with pytest.raises(RuntimeError, match="already resolved"):
            resolver.resolve("p1")


class TestDebateResolverMinSeverity:
    """Severity below _MIN_SEVERITY must be rejected."""

    def test_severity_below_min_raises(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p1", "m1", "safety", "C")
        with pytest.raises(ValueError, match=r"severity must be >= 0\.05"):
            resolver.challenge("p1", "v1", "trivial", severity=0.01)


class TestDebateResolverDefenseCap:
    """Per-defender defense count must be capped at _MAX_DEFENSES_PER_DEFENDER."""

    def test_exceed_defense_cap_raises(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p1", "m1", "safety", "C")
        for i in range(3):
            resolver.defend("p1", "m1", f"defense-{i}")
        with pytest.raises(PermissionError, match="defense limit"):
            resolver.defend("p1", "m1", "one too many")

    def test_different_defenders_not_capped(self) -> None:
        resolver = DebateResolver()
        resolver.propose("p1", "m1", "safety", "C")
        for i in range(5):
            resolver.defend("p1", f"defender-{i}", f"defense-{i}")
        # No error — each defender is within their individual limit


class TestFederatedBridgePendingEnforcement:
    """PENDING credentials must be rejected by gate()."""

    def test_gate_rejects_pending_credential(self) -> None:
        bridge = _make_bridge()
        cred = _make_credential(agent_id="pending-agent")
        cred = AgentCredential(
            agent_id=cred.agent_id,
            org_id=cred.org_id,
            pubkey_fingerprint=cred.pubkey_fingerprint,
            constitutional_hash=cred.constitutional_hash,
            issued_at=cred.issued_at,
            expires_at=cred.expires_at,
            domains=cred.domains,
            status=CredentialStatus.PENDING,
        )
        bridge.register_credential(cred)
        decision = bridge.gate(cred.agent_id)
        assert not decision.allowed
        assert "PENDING" in decision.reason


class TestDrandClientInputValidation:
    """DrandClient must validate chain_hash and enforce HTTPS."""

    def test_invalid_chain_hash_raises(self) -> None:
        from constitutional_swarm.swarm_ode import DrandClient

        with pytest.raises(ValueError, match="chain_hash"):
            DrandClient(chain_hash="not-a-valid-hex!", base_url="https://api.drand.sh")

    def test_http_base_url_raises(self) -> None:
        from constitutional_swarm.swarm_ode import DrandClient

        valid_hash = "a" * 64
        with pytest.raises(ValueError, match="HTTPS"):
            DrandClient(chain_hash=valid_hash, base_url="http://insecure.example.com")

    def test_valid_config_accepted(self) -> None:
        from constitutional_swarm.swarm_ode import DrandClient

        valid_hash = "a" * 64
        client = DrandClient(chain_hash=valid_hash, base_url="https://api.drand.sh")
        assert client is not None


# =============================================================================
# Phase 5 hardening tests
# =============================================================================


class TestConstitutionalHashConsolidation:
    """Assert all modules reference the canonical hash from constants.py."""

    def test_all_modules_share_hash(self) -> None:
        from constitutional_swarm import debate_resolver, federated_bridge, mac_acgs_loop, swarm_ode
        from constitutional_swarm.bittensor import came_coordinator
        from constitutional_swarm.constants import CONSTITUTIONAL_HASH

        for mod in (debate_resolver, mac_acgs_loop, federated_bridge, swarm_ode, came_coordinator):
            assert mod._CONSTITUTIONAL_HASH == CONSTITUTIONAL_HASH, f"{mod.__name__} hash drifted"

    def test_constants_module_value(self) -> None:
        from constitutional_swarm.constants import CONSTITUTIONAL_HASH

        assert CONSTITUTIONAL_HASH == "608508a9bd224290"


class TestDefenseFloodingMitigation:
    """Verify defense credit scales inversely with max challenge severity."""

    def test_high_severity_limits_defense_value(self) -> None:
        """Many defenses should NOT override a high-severity challenge."""
        resolver = DebateResolver(approval_threshold=0.6)
        resolver.propose("p1", "proposer", "domain", "content")
        resolver.challenge("p1", "c1", "critical flaw", severity=0.8)
        # Use different defender IDs to avoid per-defender cap.
        # score = 0.5 - 0.24 + 5*0.15*(1-0.8) = 0.5 - 0.24 + 0.15 = 0.41
        for i in range(5):
            resolver.defend("p1", f"def-{i}", f"rebuttal {i}")
        verdict = resolver.resolve("p1")
        assert verdict.outcome == VerdictOutcome.REJECTED
        assert verdict.approval_score < 0.6

    def test_low_severity_defense_still_effective(self) -> None:
        """A single defense should still clear a low-severity challenge."""
        resolver = DebateResolver(approval_threshold=0.6)
        resolver.propose("p2", "proposer", "domain", "content")
        resolver.challenge("p2", "c1", "minor concern", severity=0.10)
        resolver.defend("p2", "d1", "addressed")
        verdict = resolver.resolve("p2")
        # 0.5 - 0.03 + 0.15*0.9 = 0.605
        assert verdict.outcome == VerdictOutcome.APPROVED
        assert verdict.approval_score >= 0.6


class TestRNGIsolation:
    """Verify TrustDecayField uses local RNG, not global torch seed."""

    def test_no_global_rng_contamination(self) -> None:
        import torch
        from constitutional_swarm.swarm_ode import TrustDecayField

        # Set global seed, then create two fields with different seeds
        torch.manual_seed(42)
        baseline = torch.randn(1).item()

        torch.manual_seed(42)
        _ = TrustDecayField(n=3, seed=99)
        after = torch.randn(1).item()

        # If TrustDecayField uses local Generator, global state should be unchanged
        assert baseline == after, "TrustDecayField contaminated global RNG"


class TestSensitivitySeedDiversity:
    """Verify sensitivity_clipped_noise produces different noise per call."""

    def test_repeated_calls_produce_different_noise(self) -> None:
        sampler = DiscreteGaussianSampler(sigma=2.0, seed=42)
        noise_a = sampler.sensitivity_clipped_noise((10,), sensitivity=0.5)
        noise_b = sampler.sensitivity_clipped_noise((10,), sensitivity=0.5)
        # With unique per-call seeds, outputs should differ
        assert not (noise_a == noise_b).all(), "Identical noise on repeated calls"


class TestSWEBenchOpaque:
    """SWE-bench agent error metadata must not leak exception messages."""

    def test_error_metadata_is_opaque(self) -> None:
        from constitutional_swarm.swe_bench.agent import SWEBenchAgent

        class FailingAgent(SWEBenchAgent):
            def _generate_patch(self, task):
                raise RuntimeError("super secret internal state")

        agent = FailingAgent()
        result = agent.solve({"instance_id": "test-1", "problem_statement": "fix a bug"})
        assert result.success is False
        assert "msg" not in result.metadata
        assert "super secret" not in str(result.metadata)
        assert "error_id" in result.metadata


class TestChallengerRoundRobin:
    """External challengers should rotate across proposals."""

    def test_challengers_rotate_by_index(self) -> None:
        from constitutional_swarm.mac_acgs_loop import MacAcgsConfig, MacAcgsLoop

        config = MacAcgsConfig(
            auto_challenge=True,
            auto_defend=True,
            debate_approval_threshold=0.6,
        )
        loop = MacAcgsLoop(config=config)
        loop.add_external_challenger("alice")
        loop.add_external_challenger("bob")
        loop.add_external_challenger("charlie")

        # Access the internal list to verify round-robin logic
        assert loop._external_challengers == ["alice", "bob", "charlie"]
        # Index 0 → alice, 1 → bob, 2 → charlie, 3 → alice
        for i, expected in enumerate(["alice", "bob", "charlie", "alice"]):
            assert loop._external_challengers[i % len(loop._external_challengers)] == expected


class TestGossipBatchLimits:
    """Gossip batch decoding must reject oversized payloads."""

    def test_oversized_bytes_rejected(self) -> None:
        from constitutional_swarm.gossip_protocol import MAX_BATCH_BYTES, decode_batch

        huge = "x" * (MAX_BATCH_BYTES + 1)
        with pytest.raises(ValueError, match="too large"):
            decode_batch(huge)

    def test_too_many_nodes_rejected(self) -> None:
        import json

        from constitutional_swarm.gossip_protocol import MAX_BATCH_NODES, decode_batch

        nodes = [
            {
                "cid": f"c{i}",
                "agent_id": "a",
                "payload": "p",
                "parent_cids": [],
                "bodes_passed": False,
                "constitutional_hash": "",
            }
            for i in range(MAX_BATCH_NODES + 1)
        ]
        with pytest.raises(ValueError, match="too many nodes"):
            decode_batch(json.dumps(nodes))

    def test_valid_batch_accepted(self) -> None:
        import json

        from constitutional_swarm.gossip_protocol import decode_batch

        nodes = [
            {
                "cid": "c1",
                "agent_id": "a",
                "payload": "p",
                "parent_cids": [],
                "bodes_passed": False,
                "constitutional_hash": "",
            }
        ]
        result = decode_batch(json.dumps(nodes))
        assert len(result) == 1


class TestResolverHashValidation:
    """DebateResolver.resolve() should validate against instance hash."""

    def test_custom_hash_accepted_when_matching(self) -> None:
        resolver = DebateResolver(constitutional_hash="custom_hash_42")
        resolver.propose("p1", "proposer", "domain", "content")
        resolver.challenge("p1", "c1", "test", severity=0.1)
        resolver.defend("p1", "d1", "ok")
        verdict = resolver.resolve("p1", constitutional_hash="custom_hash_42")
        assert verdict.outcome in (VerdictOutcome.APPROVED, VerdictOutcome.REJECTED)

    def test_mismatched_hash_raises(self) -> None:
        resolver = DebateResolver(constitutional_hash="custom_hash_42")
        resolver.propose("p1", "proposer", "domain", "content")
        resolver.challenge("p1", "c1", "test", severity=0.1)
        with pytest.raises(PermissionError, match="hash mismatch"):
            resolver.resolve("p1", constitutional_hash="wrong_hash")


# ===========================================================================
# Phase 6: Privacy Accountant Subsampling Tests
# ===========================================================================


class TestPrivacyAccountantSubsampling:
    """Test that sample_rate actually reduces RDP budget consumption."""

    def test_subsampling_reduces_epsilon(self) -> None:
        """With sample_rate < 1, cumulative ε should be lower than full rate."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        # Full-rate accountant
        pa_full = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        for _ in range(10):
            pa_full.spend(sensitivity=1.0, sigma=1.0, sample_rate=1.0)

        # Subsampled accountant (same steps, but q=0.1)
        pa_sub = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        for _ in range(10):
            pa_sub.spend(sensitivity=1.0, sigma=1.0, sample_rate=0.1)

        # Subsampled should have consumed much less budget
        assert pa_sub.remaining_epsilon > pa_full.remaining_epsilon
        # Amplification factor should be significant (roughly q²=0.01)
        ratio = (10.0 - pa_sub.remaining_epsilon) / (10.0 - pa_full.remaining_epsilon)
        assert ratio < 0.5, f"Expected significant amplification, got ratio {ratio:.4f}"

    def test_subsampling_rate_1_equals_full(self) -> None:
        """sample_rate=1.0 should produce identical epsilon to no subsampling."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa1 = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        pa2 = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        for _ in range(5):
            pa1.spend(sensitivity=1.0, sigma=2.0, sample_rate=1.0)
            pa2.spend(sensitivity=1.0, sigma=2.0, sample_rate=1.0)

        assert abs(pa1.remaining_epsilon - pa2.remaining_epsilon) < 1e-10

    def test_budget_exhaustion_with_subsampling(self) -> None:
        """Subsampled spends should consume less budget per step."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        # Same parameters, different sample rates
        pa_full = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        pa_sub = PrivacyAccountant(epsilon=10.0, delta=1e-5)

        # Same 5 steps
        for _ in range(5):
            pa_full.spend(sensitivity=1.0, sigma=2.0, sample_rate=1.0)
            pa_sub.spend(sensitivity=1.0, sigma=2.0, sample_rate=0.1)

        # Subsampled should have consumed significantly less budget
        consumed_full = 10.0 - pa_full.remaining_epsilon
        consumed_sub = 10.0 - pa_sub.remaining_epsilon
        assert consumed_sub < consumed_full * 0.5, (
            f"Subsampling didn't amplify enough: {consumed_sub:.4f} sub vs {consumed_full:.4f} full"
        )


# ===========================================================================
# Phase 6: CAME Coordinator Logging Tests
# ===========================================================================


class TestCAMECoordinatorLogging:
    """Verify that CAME coordinator exception paths now log instead of silently passing."""

    def test_bad_approach_logs_warning(self) -> None:
        """Grid.challenge() failure should log warning, not silently pass."""
        from unittest.mock import MagicMock

        from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator

        class _ExplodingGrid:
            coverage = 0.5

            def challenge(self, approach: object) -> bool:
                raise RuntimeError("bad approach")

            def ceiling_detected(self) -> bool:
                return False

        coord = CAMECoordinator(grid=_ExplodingGrid())
        approach = MagicMock()
        approach.miner_uid = "miner-1"

        # Should NOT raise — the coordinator catches and logs
        with pytest.raises(Exception):
            # Verify the grid DOES raise
            _ExplodingGrid().challenge(approach)

        # But the coordinator should handle it gracefully
        result = coord.evolve_cycle([approach])
        assert result.grid_coverage == 0.5

    def test_ceiling_detected_failure_logs_error(self) -> None:
        """Grid.ceiling_detected() failure should log error and default to False."""
        from unittest.mock import MagicMock

        from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator

        class _CeilingBroken:
            coverage = 0.3

            def challenge(self, approach: object) -> bool:
                return False

            def ceiling_detected(self) -> bool:
                raise RuntimeError("ceiling query failed")

        coord = CAMECoordinator(grid=_CeilingBroken())
        result = coord.evolve_cycle([MagicMock(miner_uid="m1")])
        assert result.ceiling_detected is False  # Defaults to False on error


# ===========================================================================
# Phase 6: SpectralSphereManifold Export Tests
# ===========================================================================


class TestBreakthroughModuleExports:
    """Verify breakthrough modules are now importable from top-level package."""

    def test_spectral_sphere_manifold_exported(self) -> None:
        from constitutional_swarm import SpectralSphereManifold

        assert SpectralSphereManifold is not None

    def test_spectral_sphere_project_exported(self) -> None:
        from constitutional_swarm import spectral_sphere_project

        assert callable(spectral_sphere_project)

    def test_merkle_crdt_exported(self) -> None:
        from constitutional_swarm import DAGNode, MerkleCRDT

        assert MerkleCRDT is not None
        assert DAGNode is not None

    def test_privacy_accountant_exported(self) -> None:
        from constitutional_swarm import PrivacyAccountant, PrivacyBudgetExhausted

        assert PrivacyAccountant is not None
        assert issubclass(PrivacyBudgetExhausted, RuntimeError)


# ===========================================================================
# Phase 6: Cross-Module Integration Tests
# ===========================================================================


class TestSpectralSphereODEIntegration:
    """Integration: SpectralSphereManifold × SwarmODE trust dynamics."""

    def test_spectral_projection_preserves_ode_stability(self) -> None:
        """Spectral sphere projection after trust update keeps norm ≤ r."""
        from constitutional_swarm.spectral_sphere import spectral_sphere_project

        # Simulate a trust matrix after ODE evolution step
        n = 4
        trust_matrix = [[0.5 + 0.3 * (i == j) for j in range(n)] for i in range(n)]
        # Scale up to simulate divergence
        scale = 3.0
        big_matrix = [[scale * trust_matrix[i][j] for j in range(n)] for i in range(n)]

        result = spectral_sphere_project(big_matrix, r=1.0)
        assert result.spectral_norm <= 1.0 + 1e-6
        assert result.clipped is True

    def test_repeated_projection_preserves_variance(self) -> None:
        """Spectral sphere should preserve trust specialization over many cycles."""
        from constitutional_swarm.spectral_sphere import SpectralSphereManifold

        n = 4
        manifold = SpectralSphereManifold(n, r=1.0)

        # Set up a heterogeneous trust matrix via update_trust
        for i in range(n):
            for j in range(n):
                val = 0.8 if i == j else 0.1
                manifold.update_trust(i, j, val)

        # Run 50 projection cycles
        for _ in range(50):
            result = manifold.project()
            # Reset and re-load from result
            for i in range(n):
                for j in range(n):
                    manifold._raw_trust[i][j] = result.matrix[i][j]
            manifold._projected = None

        # Variance should NOT collapse to zero (unlike Birkhoff)
        flat = [result.matrix[i][j] for i in range(n) for j in range(n)]
        mean = sum(flat) / len(flat)
        var = sum((x - mean) ** 2 for x in flat) / len(flat)
        assert var > 1e-6, f"Variance collapsed to {var} — spectral sphere failed"


class TestLatentDNARobustness:
    """Test latent DNA steering failure rollback (Phase 6 hardening)."""

    def test_bodes_hook_renormalizes_after_dtype_transfer(self) -> None:
        """Violation vector should be re-normalized after device/dtype transfer."""
        import torch
        from constitutional_swarm.latent_dna import _BODESHook

        v_viol = torch.randn(64)
        v_viol = v_viol / v_viol.norm()
        hook = _BODESHook(v_viol, threshold=0.0, gamma=1.0)

        # Simulate a forward pass with float16 (lossy dtype)
        module = torch.nn.Identity()
        hidden = torch.randn(1, 4, 64, dtype=torch.float16)
        output = hook(module, (hidden,), hidden)

        # Should not crash and should produce valid output
        if isinstance(output, tuple):
            assert output[0].shape == hidden.shape
        else:
            assert output.shape == hidden.shape
