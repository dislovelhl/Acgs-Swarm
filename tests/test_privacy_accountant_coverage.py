"""Tests for edge cases in privacy_accountant.py — overflow safety, validation, introspection."""
import math
import pytest
from unittest.mock import patch


# ── _rdp_subsampled_gaussian branches ───────────────────────────────────────

class TestRdpSubsampledGaussianBranches:
    def test_alpha_lte_1_returns_zero(self):
        """Line 83: alpha <= 1.0 returns 0.0."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        assert _rdp_subsampled_gaussian(alpha=0.5, noise_multiplier=1.0, sample_rate=0.5) == 0.0
        assert _rdp_subsampled_gaussian(alpha=1.0, noise_multiplier=1.0, sample_rate=0.5) == 0.0

    def test_sample_rate_gte_1_delegates_to_gaussian(self):
        """Line 80-81: sample_rate >= 1.0 delegates to _rdp_gaussian."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian, _rdp_gaussian

        result = _rdp_subsampled_gaussian(alpha=3.0, noise_multiplier=2.0, sample_rate=1.0)
        assert result == pytest.approx(_rdp_gaussian(3.0, 2.0))

    def test_large_exponent_overflow_safe_path(self):
        """Lines 91-93: exponent > 50 uses overflow-safe log form."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        # alpha=20, nm=0.01 → eps_base = 20/(2*0.0001) = 100000
        # exponent = 19 * 100000 = 1.9e6 >> 50 → overflow-safe branch
        result = _rdp_subsampled_gaussian(alpha=20.0, noise_multiplier=0.01, sample_rate=0.001)
        assert math.isfinite(result)
        assert result > 0

    def test_inner_nonpositive_returns_eps_base(self):
        """Lines 96-97: inner <= 0 falls back to eps_base."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        # alpha=3.0, nm=2.0 → eps_base = 3.0/(2*4) = 0.375
        # Patch expm1 to return -1e18 → inner = 1 + q^2 * (-1e18) << 0
        with patch("math.expm1", return_value=-1e18):
            result = _rdp_subsampled_gaussian(alpha=3.0, noise_multiplier=2.0, sample_rate=0.1)
        assert result == pytest.approx(0.375)

    def test_overflow_error_caught_returns_eps_base(self):
        """Lines 99-100: OverflowError in expm1 falls back to eps_base."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        with patch("math.expm1", side_effect=OverflowError):
            result = _rdp_subsampled_gaussian(alpha=3.0, noise_multiplier=2.0, sample_rate=0.1)
        assert math.isfinite(result)
        # Fallback is eps_base = 3.0 / (2 * 4) = 0.375
        assert result == pytest.approx(0.375)

    def test_value_error_caught_returns_eps_base(self):
        """Lines 99-100: ValueError in math ops falls back to eps_base."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        with patch("math.expm1", side_effect=ValueError):
            result = _rdp_subsampled_gaussian(alpha=3.0, noise_multiplier=2.0, sample_rate=0.1)
        assert math.isfinite(result)


# ── _rdp_to_epsilon_balle2020 error guards ───────────────────────────────────

class TestRdpToEpsilonBalle2020:
    def test_all_alphas_skipped_returns_inf(self):
        """Lines 121-126: all alphas <= 1.01 → best_eps stays inf."""
        from constitutional_swarm.privacy_accountant import _rdp_to_epsilon_balle2020

        eps, alpha = _rdp_to_epsilon_balle2020([0.1], [1.005], delta=1e-5)
        assert eps == math.inf

    def test_normal_path_returns_finite(self):
        """Sanity: normal alpha > 1.01 path returns finite epsilon."""
        from constitutional_swarm.privacy_accountant import _rdp_to_epsilon_balle2020

        eps, alpha = _rdp_to_epsilon_balle2020([0.5, 1.0], [2.0, 3.0], delta=1e-5)
        assert math.isfinite(eps)


# ── PrivacyAccountant __post_init__ validation ───────────────────────────────

class TestPrivacyAccountantValidation:
    def test_epsilon_zero_raises(self):
        """Lines 160-161: epsilon=0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        with pytest.raises(ValueError, match="epsilon"):
            PrivacyAccountant(epsilon=0.0, delta=1e-5)

    def test_epsilon_negative_raises(self):
        """Lines 160-161: epsilon<0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        with pytest.raises(ValueError, match="epsilon"):
            PrivacyAccountant(epsilon=-1.0, delta=1e-5)

    def test_delta_zero_raises(self):
        """Lines 162-163: delta=0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        with pytest.raises(ValueError, match="delta"):
            PrivacyAccountant(epsilon=1.0, delta=0.0)

    def test_delta_one_raises(self):
        """Lines 162-163: delta=1 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        with pytest.raises(ValueError, match="delta"):
            PrivacyAccountant(epsilon=1.0, delta=1.0)

    def test_delta_gt_one_raises(self):
        """Lines 162-163: delta > 1 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        with pytest.raises(ValueError, match="delta"):
            PrivacyAccountant(epsilon=1.0, delta=2.0)


# ── PrivacyAccountant spend() validation ─────────────────────────────────────

class TestPrivacyAccountantSpendValidation:
    def test_spend_zero_sensitivity_raises(self):
        """Lines 235-236: sensitivity=0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sensitivity"):
            pa.spend(sensitivity=0.0, sigma=1.0)

    def test_spend_negative_sensitivity_raises(self):
        """Lines 235-236: sensitivity<0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sensitivity"):
            pa.spend(sensitivity=-1.0, sigma=1.0)

    def test_spend_zero_sigma_raises(self):
        """Lines 237-238: sigma=0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sigma"):
            pa.spend(sensitivity=1.0, sigma=0.0)

    def test_spend_negative_sigma_raises(self):
        """Lines 237-238: sigma<0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sigma"):
            pa.spend(sensitivity=1.0, sigma=-0.5)

    def test_spend_sample_rate_zero_raises(self):
        """Lines 239-240: sample_rate=0 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sample_rate"):
            pa.spend(sensitivity=1.0, sigma=1.0, sample_rate=0.0)

    def test_spend_sample_rate_above_one_raises(self):
        """Lines 239-240: sample_rate=1.1 raises ValueError."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
        with pytest.raises(ValueError, match="sample_rate"):
            pa.spend(sensitivity=1.0, sigma=1.0, sample_rate=1.1)


# ── PrivacyAccountant introspection ──────────────────────────────────────────

class TestPrivacyAccountantIntrospection:
    def test_budget_fraction_used_after_spends(self):
        """Lines 281-282: budget_fraction_used returns (0, 1] after spending."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        pa.spend(sensitivity=1.0, sigma=5.0)
        pa.spend(sensitivity=1.0, sigma=5.0)
        fraction = pa.budget_fraction_used
        assert 0.0 < fraction <= 1.0

    def test_budget_fraction_used_zero_before_spends(self):
        """budget_fraction_used is 0 (or very close) on fresh accountant."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        fraction = pa.budget_fraction_used
        assert fraction == 0.0

    def test_summary_has_required_keys(self):
        """summary() dict contains all expected keys."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        summary = pa.summary()
        for key in [
            "epsilon_total", "epsilon_spent", "epsilon_remaining", "delta",
            "num_mechanism_invocations", "budget_fraction_used", "exhausted",
        ]:
            assert key in summary

    def test_summary_values_consistent(self):
        """summary() values are internally consistent."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=10.0, delta=1e-5)
        pa.spend(sensitivity=1.0, sigma=5.0)
        summary = pa.summary()
        assert summary["epsilon_total"] == 10.0
        assert summary["delta"] == 1e-5
        assert summary["num_mechanism_invocations"] == 1
        assert math.isclose(
            summary["epsilon_spent"] + summary["epsilon_remaining"],
            summary["epsilon_total"],
            rel_tol=1e-9,
        )


# ── Security regression tests ─────────────────────────────────────────────────


class TestRdpOverflowBranchNonNegative:
    """P1: overflow branch must return ≥ 0 even with tiny sample_rate."""

    def test_tiny_sample_rate_returns_non_negative(self):
        """Regression: large exponent + tiny q must not produce negative RDP."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian

        # q = 1e-20 → log(q) ≈ -46, exponent > 50 → overflow branch
        result = _rdp_subsampled_gaussian(alpha=20.0, noise_multiplier=0.01, sample_rate=1e-20)
        assert result >= 0.0, f"RDP must be non-negative; got {result}"

    def test_returns_at_most_eps_base(self):
        """Privacy amplification can only reduce RDP, never increase it."""
        from constitutional_swarm.privacy_accountant import _rdp_subsampled_gaussian, _rdp_gaussian

        nm, alpha = 0.01, 20.0
        eps_base = _rdp_gaussian(alpha, nm)
        result = _rdp_subsampled_gaussian(alpha=alpha, noise_multiplier=nm, sample_rate=1e-20)
        assert result <= eps_base + 1e-10


class TestComputeRdpTotalThreadSafety:
    """P2: _compute_rdp_total must read history under lock."""

    def test_rdp_total_consistent_under_concurrent_spend(self):
        """Concurrent spend + total computation should not raise."""
        import threading
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa = PrivacyAccountant(epsilon=1000.0, delta=1e-5)
        errors = []

        def spender():
            for _ in range(50):
                try:
                    pa.spend(sensitivity=1.0, sigma=10.0)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

        threads = [threading.Thread(target=spender) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Must not raise; total RDP should be non-negative
        assert all(v >= 0 for v in pa._compute_rdp_total())
        assert not errors


class TestSpendTelemetryUsesSubsampledRdp:
    """P3: spend() per-step ε telemetry should use subsampled RDP."""

    def test_per_step_eps_reflects_sample_rate(self):
        """Lower sample_rate should yield lower per-step ε (privacy amplification)."""
        from constitutional_swarm.privacy_accountant import PrivacyAccountant

        pa_full = PrivacyAccountant(epsilon=100.0, delta=1e-5)
        pa_sub = PrivacyAccountant(epsilon=100.0, delta=1e-5)

        eps_full = pa_full.spend(sensitivity=1.0, sigma=2.0, sample_rate=1.0)
        eps_sub = pa_sub.spend(sensitivity=1.0, sigma=2.0, sample_rate=0.01)
        assert eps_sub < eps_full, (
            f"subsampled ε ({eps_sub}) should be less than full-batch ε ({eps_full})"
        )
