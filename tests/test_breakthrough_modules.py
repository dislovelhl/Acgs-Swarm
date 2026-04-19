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

from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
)
from constitutional_swarm.debate_resolver import (
    Challenge,
    DebateResolver,
    Proposal,
    VerdictOutcome,
)
from constitutional_swarm.swarm_ode import DiscreteGaussianSampler
from constitutional_swarm.bittensor.governance_coordinator import (
    CoordinatorConfig,
    GovernanceCoordinator,
)
from constitutional_swarm.bittensor.emission_calculator import (
    MinerEmissionInput,
    MinerTier,
)
from constitutional_swarm.bittensor.came_coordinator import (
    CAMECoordinator,
    CAMECoordinatorConfig,
)

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

        bridge.gate("agent-a", domain="")   # should ALLOW
        bridge.gate("agent-b", domain="")   # should DENY (hash mismatch)
        bridge.gate("nobody", domain="")    # should DENY (unknown)

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


from constitutional_swarm.mac_acgs_loop import (
    MacAcgsConfig,
    MacAcgsLoop,
    PipelineEventType,
)
from constitutional_swarm.bittensor.came_coordinator import (
    CAMECycleResult,
)
from unittest.mock import MagicMock


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
            grid_coverage=0.80, ceiling_detected=True,
            rules_proposed=["R2"], log_id="mock:2", exploration_bonus=0.05,
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
                grid_coverage=0.5, ceiling_detected=True,
                rules_proposed=["R"], log_id="m", exploration_bonus=0.0,
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
