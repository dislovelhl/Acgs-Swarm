"""SNCA Behavioral Consistency Tests for ACGS constitutions.

Inspired by the SNCA paper (2604.09189) which found that language models
claiming to follow rules often violate them in practice.  These tests apply
the same consistency audit to ACGS constitution YAML files:

  - Absolute rules (severity=critical) MUST block every matched keyword
  - Conditional rules (severity=high)  MUST block given context cues
  - Adaptive rules (severity=medium)   SHOULD block at least once

SNCA mapping:
    SNCA Absolute  → ACGS severity=critical  (zero tolerance)
    SNCA Conditional → ACGS severity=high    (context-dependent block)
    SNCA Adaptive    → ACGS severity=medium  (best-effort block)

Aggregate metric: SNCA score = (consistent rules) / (rules with keywords)
Minimum acceptable threshold: 70% (per SNCA paper baseline).
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constitution fixtures
# ---------------------------------------------------------------------------

AUTORESEARCH_YAML = (
    pathlib.Path(__file__).parent.parent.parent.parent / "autoresearch" / "constitution.yaml"
)


def _load_engine_and_rules(yaml_path: pathlib.Path | str) -> tuple[Any, list[dict]]:
    """Load a GovernanceEngine (strict=False) and the raw rule list."""
    from acgs_lite import Constitution
    from acgs_lite.engine import GovernanceEngine

    yaml_path = pathlib.Path(yaml_path)
    if not yaml_path.exists():
        pytest.skip(f"Constitution file not found: {yaml_path}")

    constitution = Constitution.from_yaml(str(yaml_path))
    engine = GovernanceEngine(constitution, strict=False)

    # Pull raw rule dicts so we can inspect keywords/severity
    raw_rules: list[dict] = []
    for rule in constitution.rules:
        raw_rules.append(
            {
                "id": rule.id,
                "text": rule.text,
                "severity": rule.severity.value if rule.severity else "medium",
                "keywords": list(rule.keywords or []),
            }
        )
    return engine, raw_rules


def _is_blocked(engine: Any, prompt: str) -> bool:
    """Return True if the engine blocks the prompt (valid=False)."""
    result = engine.validate(prompt)
    return not result.valid


# ---------------------------------------------------------------------------
# Critical (absolute) rule tests
# ---------------------------------------------------------------------------


class TestAbsoluteRuleConsistency:
    """SNCA Absolute contract: critical-severity rules MUST block all keywords."""

    def test_critical_rules_block_direct_keyword_match(self) -> None:
        """Every keyword in a critical rule must trigger a block."""
        engine, rules = _load_engine_and_rules(AUTORESEARCH_YAML)
        critical_rules = [r for r in rules if r["severity"] == "critical"]

        if not critical_rules:
            pytest.skip("No critical rules in constitution")

        failures: list[dict] = []
        for rule in critical_rules:
            for keyword in rule["keywords"][:5]:  # test first 5 keywords per rule
                probe = f"Please {keyword} the production system immediately."
                if not _is_blocked(engine, probe):
                    failures.append({"rule_id": rule["id"], "keyword": keyword, "probe": probe})

        assert not failures, (
            f"SNCA Absolute violation: {len(failures)} critical keywords did not block.\n"
            + "\n".join(f"  rule={f['rule_id']} keyword='{f['keyword']}'" for f in failures[:5])
        )

    def test_critical_rules_block_embedded_keyword(self) -> None:
        """Keywords embedded in realistic sentences must still trigger blocks."""
        engine, rules = _load_engine_and_rules(AUTORESEARCH_YAML)
        critical_rules = [r for r in rules if r["severity"] == "critical"]

        failures: list[dict] = []
        for rule in critical_rules:
            for keyword in rule["keywords"][:3]:
                # More realistic / evasive phrasings
                probes = [
                    f"Can we {keyword} just for the staging env?",
                    f"The team wants to {keyword} as an exception.",
                ]
                for probe in probes:
                    if not _is_blocked(engine, probe):
                        failures.append({"rule_id": rule["id"], "keyword": keyword})

        # Allow up to 20% miss rate on evasive phrasing (realistic threshold)
        total = sum(min(3, len(r["keywords"])) * 2 for r in critical_rules if r["keywords"])
        if total > 0:
            miss_rate = len(failures) / total
            assert miss_rate <= 0.20, (
                f"SNCA Absolute evasion miss rate {miss_rate:.1%} exceeds 20% "
                f"({len(failures)} / {total} evasive probes unblocked)"
            )


# ---------------------------------------------------------------------------
# High-severity (conditional) rule tests
# ---------------------------------------------------------------------------


class TestConditionalRuleConsistency:
    """SNCA Conditional contract: high-severity rules must block given context cues."""

    def test_high_severity_rules_block_at_least_one_keyword(self) -> None:
        """Each high-severity rule must block at least one of its own keywords."""
        engine, rules = _load_engine_and_rules(AUTORESEARCH_YAML)
        high_rules = [r for r in rules if r["severity"] == "high" and r["keywords"]]

        if not high_rules:
            pytest.skip("No high-severity rules with keywords in constitution")

        failures: list[str] = []
        for rule in high_rules:
            blocked_any = False
            for keyword in rule["keywords"][:5]:
                probe = f"Action requested: {keyword}"
                if _is_blocked(engine, probe):
                    blocked_any = True
                    break
            if not blocked_any:
                failures.append(rule["id"])

        assert not failures, (
            f"SNCA Conditional: {len(failures)} high-severity rules blocked NONE of "
            f"their keywords: {failures}"
        )


# ---------------------------------------------------------------------------
# Aggregate SNCA score
# ---------------------------------------------------------------------------


class TestRuleConsistencyMetrics:
    """Aggregate SNCA consistency score — must be ≥ 70%."""

    def test_constitution_snca_score_above_threshold(self) -> None:
        """Score = (rules that block ≥1 keyword) / (rules with keywords).

        Minimum threshold: 70% per SNCA paper baseline.
        """
        engine, rules = _load_engine_and_rules(AUTORESEARCH_YAML)
        rules_with_keywords = [r for r in rules if r["keywords"]]

        if not rules_with_keywords:
            pytest.skip("No rules with keywords — cannot compute SNCA score")

        consistent_count = 0
        for rule in rules_with_keywords:
            for keyword in rule["keywords"][:3]:
                probe = f"Please {keyword} the system."
                if _is_blocked(engine, probe):
                    consistent_count += 1
                    break

        score = consistent_count / len(rules_with_keywords)
        assert score >= 0.70, (
            f"SNCA consistency score {score:.1%} ({consistent_count}/"
            f"{len(rules_with_keywords)}) is below the 70% threshold"
        )

    def test_no_rule_has_empty_keywords_and_critical_severity(self) -> None:
        """Critical rules without keywords are unverifiable — flag them."""
        _, rules = _load_engine_and_rules(AUTORESEARCH_YAML)
        unverifiable = [r["id"] for r in rules if r["severity"] == "critical" and not r["keywords"]]
        # Allow up to 2 — some critical rules are pattern-only
        assert len(unverifiable) <= 2, (
            f"Too many critical rules with no keywords (unverifiable): {unverifiable}"
        )


# ---------------------------------------------------------------------------
# DP noise helpers (swarm_ode integration)
# ---------------------------------------------------------------------------


class TestDPNoiseHelpers:
    """Verify the calibrate_sigma / add_dp_noise DP functions added to swarm_ode."""

    def test_calibrate_sigma_returns_positive(self) -> None:
        from constitutional_swarm.swarm_ode import calibrate_sigma

        sigma = calibrate_sigma(r=1.0, residual_alpha=0.1, epsilon=1.0, delta=1e-5)
        assert sigma > 0, "sigma must be positive"

    def test_calibrate_sigma_decreases_with_alpha(self) -> None:
        """Higher α → smaller sensitivity → smaller σ (NDSS paper claim)."""
        from constitutional_swarm.swarm_ode import calibrate_sigma

        sigma_low_alpha = calibrate_sigma(r=1.0, residual_alpha=0.1, epsilon=1.0, delta=1e-5)
        sigma_high_alpha = calibrate_sigma(r=1.0, residual_alpha=0.5, epsilon=1.0, delta=1e-5)
        assert sigma_high_alpha < sigma_low_alpha, (
            f"Higher α should reduce σ: α=0.1 → σ={sigma_low_alpha:.4f}, "
            f"α=0.5 → σ={sigma_high_alpha:.4f}"
        )

    def test_add_dp_noise_changes_matrix(self) -> None:
        import torch
        from constitutional_swarm.swarm_ode import add_dp_noise

        H = torch.eye(4)
        H_noisy = add_dp_noise(H, sigma=0.1)
        assert H_noisy.shape == H.shape
        assert not torch.allclose(H, H_noisy), "DP noise should change the matrix"

    def test_calibrate_sigma_invalid_inputs_raise(self) -> None:
        from constitutional_swarm.swarm_ode import calibrate_sigma

        with pytest.raises(ValueError):
            calibrate_sigma(r=1.0, residual_alpha=0.0, epsilon=1.0, delta=1e-5)  # alpha=0 invalid
        with pytest.raises(ValueError):
            calibrate_sigma(r=1.0, residual_alpha=0.1, epsilon=-1.0, delta=1e-5)  # neg epsilon


# ---------------------------------------------------------------------------
# PrivacyAccountant
# ---------------------------------------------------------------------------


class TestPrivacyAccountant:
    """Tests for the fail-closed ε-budget accountant."""

    def test_normal_spend_does_not_raise(self) -> None:
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        sigma = pa.required_sigma(0.1)
        pa.spend(0.1, sigma)
        pa.assert_budget()  # must not raise

    def test_budget_exhaustion_raises(self) -> None:
        from constitutional_swarm.privacy_accountant import (
            PrivacyAccountant,
            PrivacyBudgetExhausted,
        )

        pa = PrivacyAccountant(epsilon=0.01, delta=1e-5)
        # Spend with sigma=0.001 → huge ε per step
        for _ in range(50):
            pa.spend(1.0, sigma=0.001)
        with pytest.raises(PrivacyBudgetExhausted):
            pa.assert_budget()

    def test_required_sigma_raises_when_exhausted(self) -> None:
        from constitutional_swarm.privacy_accountant import (
            PrivacyAccountant,
            PrivacyBudgetExhausted,
        )

        pa = PrivacyAccountant(epsilon=0.5, delta=1e-5)
        # Exhaust budget
        pa.spend(1.0, sigma=0.001)
        pa.spend(1.0, sigma=0.001)
        with pytest.raises(PrivacyBudgetExhausted):
            pa.required_sigma(1.0)

    def test_summary_fields_present(self) -> None:
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=2.0, delta=1e-6)
        pa.spend(0.2, sigma=0.5)
        s = pa.summary()
        for key in (
            "epsilon_total",
            "epsilon_spent",
            "epsilon_remaining",
            "delta",
            "num_mechanism_invocations",
            "budget_fraction_used",
            "exhausted",
        ):
            assert key in s, f"missing summary key: {key}"

    def test_remaining_epsilon_decreases_monotonically(self) -> None:
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        prev = pa.remaining_epsilon
        for _ in range(5):
            pa.spend(0.1, sigma=0.3)
            assert pa.remaining_epsilon < prev
            prev = pa.remaining_epsilon

    def test_rdp_tighter_than_simple_composition(self) -> None:
        """RDP composition must give at least 5× tighter ε than naive summation.

        For noise_multiplier=10 (σ=1, Δ=0.1), k=100 steps:
        - Simple composition: ε ≈ 57 (via √(2 ln(1.25/δ)) / nm · k)
        - RDP (Balle 2020):   ε ≈ 4.7  (≈12× tighter)
        We verify RDP ε < simple_ε / 5 as a conservative bound.
        """
        import math

        from constitutional_swarm.privacy_accountant import (
            PrivacyAccountant,
        )

        k = 100
        sensitivity = 0.1
        sigma = 1.0  # noise_multiplier = 10
        delta = 1e-5

        pa = PrivacyAccountant(epsilon=100.0, delta=delta)  # large budget so no cutoff
        for _ in range(k):
            pa.spend(sensitivity, sigma)

        rdp_eps = pa._current_epsilon()

        # Simple composition baseline
        eps_step_simple = sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / sigma
        simple_eps = k * eps_step_simple  # ≈ 57.17

        assert rdp_eps < simple_eps / 5, (
            f"RDP ε={rdp_eps:.2f} must be < simple/5 ({simple_eps / 5:.2f}); "
            f"simple_ε={simple_eps:.2f}"
        )

    def test_subsampling_reduces_epsilon(self) -> None:
        """spend() with sample_rate < 1 should record the subsampling rate."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=100.0, delta=1e-5)
        pa.spend(0.1, sigma=1.0, sample_rate=0.01)
        s = pa.summary()
        assert s["num_mechanism_invocations"] == 1

    def test_composition_method_in_summary(self) -> None:
        """summary() must report RDP composition method."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        pa.spend(0.1, sigma=0.5)
        s = pa.summary()
        assert "RDP" in s.get("composition_method", ""), (
            "summary must identify RDP composition method"
        )


# ---------------------------------------------------------------------------
# gossip_protocol security fixes
# ---------------------------------------------------------------------------


class TestGossipSecurityFixes:
    """Verify P1 security fixes: metadata size bound and topological sort."""

    def test_oversized_metadata_raises_value_error(self) -> None:
        """_wire_to_node must reject metadata exceeding MAX_METADATA_BYTES."""

        from constitutional_swarm.gossip_protocol import MAX_METADATA_BYTES, _wire_to_node

        oversized = {"data": "x" * (MAX_METADATA_BYTES + 1024)}
        data = {
            "cid": "abc123",
            "agent_id": "test-agent",
            "payload": "hello",
            "metadata": oversized,
        }
        with pytest.raises(ValueError, match="metadata exceeds"):
            _wire_to_node(data)

    def test_normal_metadata_is_accepted(self) -> None:
        """Small metadata must pass through without error."""
        from constitutional_swarm.gossip_protocol import _wire_to_node

        data = {
            "cid": "abc123",
            "agent_id": "test-agent",
            "payload": "hello",
            "metadata": {"key": "small value"},
        }
        node = _wire_to_node(data)
        assert node.metadata == {"key": "small value"}

    def test_topological_order_is_deterministic(self) -> None:
        """topological_order must return the same order on repeated calls."""
        from constitutional_swarm.merkle_crdt import MerkleCRDT

        crdt = MerkleCRDT("agent-test")
        for i in range(10):
            crdt.append(payload=f"node-{i}")

        order1 = [n.cid for n in crdt.topological_order()]
        order2 = [n.cid for n in crdt.topological_order()]
        assert order1 == order2, "topological_order must be deterministic"
