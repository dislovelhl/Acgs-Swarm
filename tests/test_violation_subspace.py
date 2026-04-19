"""Tests for violation_subspace.py (Phase 7.4 — LEACE-style subspace)."""

from __future__ import annotations

import numpy as np
import pytest

from constitutional_swarm.violation_subspace import (
    DimensionMismatchError,
    InsufficientSamplesError,
    RiskAdaptiveSteering,
    ViolationSubspace,
    adversarial_score,
    fit_leace,
    fit_subspace,
)


# ---------------------------------------------------------------------------
# Synthetic data generators
# ---------------------------------------------------------------------------


def _rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


def _make_clusters(
    *,
    d: int = 16,
    n: int = 80,
    separation: float = 3.0,
    axis: int = 0,
    seed: int = 0,
):
    """Return (safe, unsafe) point clouds separated along ``axis``."""
    r = _rng(seed)
    safe = r.normal(0, 1, size=(n, d))
    unsafe = r.normal(0, 1, size=(n, d))
    unsafe[:, axis] += separation
    return safe, unsafe


# ---------------------------------------------------------------------------
# ViolationSubspace basic invariants
# ---------------------------------------------------------------------------


class TestViolationSubspaceConstruction:
    def test_rank1_unit_vector_roundtrip(self):
        d = 8
        v = np.zeros(d)
        v[2] = 1.0
        mean = np.zeros(d)
        sub = ViolationSubspace(basis=v.reshape(1, -1), mean=mean)
        assert sub.rank == 1
        assert sub.dim == d
        assert not sub.is_leace

    def test_non_orthonormal_basis_rejected(self):
        basis = np.array([[1.0, 0.0], [1.0, 0.0]])  # duplicate rows
        with pytest.raises(ValueError, match="orthonormal"):
            ViolationSubspace(basis=basis, mean=np.zeros(2))

    def test_mean_shape_validation(self):
        with pytest.raises(DimensionMismatchError):
            ViolationSubspace(
                basis=np.eye(1, 4),
                mean=np.zeros(3),  # wrong dim
            )

    def test_basis_shape_validation(self):
        with pytest.raises(DimensionMismatchError):
            ViolationSubspace(
                basis=np.array([1.0, 0.0]),  # 1D, not 2D
                mean=np.zeros(2),
            )

    def test_whitener_without_dewhitener_rejected(self):
        with pytest.raises(ValueError, match="together"):
            ViolationSubspace(
                basis=np.eye(1, 4),
                mean=np.zeros(4),
                whitener=np.eye(4),
                # no dewhitener
            )

    def test_project_wrong_dim_raises(self):
        sub = ViolationSubspace(basis=np.eye(1, 4), mean=np.zeros(4))
        with pytest.raises(DimensionMismatchError):
            sub.project_component(np.zeros(5))


class TestProjection:
    def _axis_sub(self, d=8, axis=0):
        v = np.zeros(d)
        v[axis] = 1.0
        return ViolationSubspace(basis=v.reshape(1, -1), mean=np.zeros(d))

    def test_project_component_extracts_axis(self):
        sub = self._axis_sub(d=4, axis=0)
        h = np.array([2.0, 3.0, 4.0, 5.0])
        out = sub.project_component(h)
        # Only axis-0 component should survive
        assert np.allclose(out, np.array([2.0, 0.0, 0.0, 0.0]))

    def test_orthogonal_component_removes_axis(self):
        sub = self._axis_sub(d=4, axis=0)
        h = np.array([2.0, 3.0, 4.0, 5.0])
        out = sub.orthogonal_component(h)
        assert np.allclose(out, np.array([0.0, 3.0, 4.0, 5.0]))

    def test_steer_no_op_below_tau(self):
        sub = self._axis_sub(d=4, axis=0)
        h = np.array([-1.0, 3.0, 4.0, 5.0])  # coord in subspace = -1
        out = sub.steer(h, gamma=1.0, tau=0.0)
        np.testing.assert_allclose(out, h)

    def test_steer_zeros_bad_component_at_gamma_1(self):
        sub = self._axis_sub(d=4, axis=0)
        h = np.array([5.0, 3.0, 4.0, 5.0])
        out = sub.steer(h, gamma=1.0, tau=0.0)
        # axis-0 should drop to 0; others unchanged
        assert out[0] == pytest.approx(0.0, abs=1e-9)
        np.testing.assert_allclose(out[1:], h[1:])

    def test_steer_partial_retreat_at_gamma_half(self):
        sub = self._axis_sub(d=4, axis=0)
        h = np.array([4.0, 3.0, 4.0, 5.0])
        out = sub.steer(h, gamma=0.5, tau=0.0)
        assert out[0] == pytest.approx(2.0, abs=1e-9)  # 4 - 0.5*4

    def test_steer_invalid_gamma_rejected(self):
        sub = self._axis_sub(d=4, axis=0)
        with pytest.raises(ValueError, match="gamma"):
            sub.steer(np.zeros(4), gamma=0.0)
        with pytest.raises(ValueError, match="gamma"):
            sub.steer(np.zeros(4), gamma=1.5)

    def test_batched_steer(self):
        sub = self._axis_sub(d=3, axis=0)
        H = np.array([[2.0, 0.0, 0.0], [4.0, 1.0, 1.0]])
        out = sub.steer(H, gamma=1.0, tau=0.0)
        assert out.shape == H.shape
        np.testing.assert_allclose(out[:, 0], 0.0, atol=1e-9)


# ---------------------------------------------------------------------------
# fit_subspace — contrastive SVD
# ---------------------------------------------------------------------------


class TestFitSubspace:
    def test_rank1_recovers_mean_difference_direction(self):
        safe, unsafe = _make_clusters(axis=2, separation=5.0, seed=1)
        sub = fit_subspace(safe, unsafe, rank=1)
        # The dominant direction should align with axis 2
        expected = np.zeros(safe.shape[1])
        expected[2] = 1.0
        cos = abs(float(sub.basis[0] @ expected))
        assert cos > 0.8  # robustly aligned

    def test_rank_k_is_orthonormal(self):
        safe, unsafe = _make_clusters(d=12, seed=2)
        sub = fit_subspace(safe, unsafe, rank=3)
        assert sub.rank == 3
        gram = sub.basis @ sub.basis.T
        np.testing.assert_allclose(gram, np.eye(3), atol=1e-6)

    def test_dim_mismatch_raises(self):
        with pytest.raises(DimensionMismatchError):
            fit_subspace(
                [np.zeros(4)], [np.zeros(5)], rank=1
            )

    def test_insufficient_samples_raises(self):
        with pytest.raises(InsufficientSamplesError):
            fit_subspace([np.zeros(4)], [], rank=1)

    def test_rank_must_be_positive(self):
        safe, unsafe = _make_clusters(seed=3)
        with pytest.raises(ValueError, match="rank"):
            fit_subspace(safe, unsafe, rank=0)

    def test_unsafe_activations_get_steered_toward_safe(self):
        """Key adversarial property: after fitting on train, steering
        new unsafe samples reduces their residual violation mass
        significantly."""
        safe, unsafe = _make_clusters(
            d=16, n=100, axis=5, separation=4.0, seed=7
        )
        # Split train/eval
        sub = fit_subspace(safe[:80], unsafe[:80], rank=1)
        score_before = adversarial_score(
            sub, unsafe[80:], gamma=1.0, tau=0.0
        )
        # With full gamma=1, residual mass in subspace should collapse
        assert score_before < 0.1


# ---------------------------------------------------------------------------
# fit_leace — oblique projection
# ---------------------------------------------------------------------------


class TestFitLeace:
    def test_fits_and_erases_label_signal(self):
        safe, unsafe = _make_clusters(
            d=12, n=60, axis=3, separation=3.0, seed=11
        )
        sub = fit_leace(safe, unsafe, ridge=1e-3)
        assert sub.is_leace
        # After erasure: mean unsafe minus mean safe in the erased
        # coordinates should be ~0
        safe_coords = sub.coordinates(safe)
        unsafe_coords = sub.coordinates(unsafe)
        # Before erasure (raw coords) the class means differ
        assert abs(float(unsafe_coords.mean() - safe_coords.mean())) > 0.5
        # After one-sided steering (gamma=1, tau=0): positive violation
        # coordinates collapse to 0; negative coords pass through.
        steered = np.asarray(
            [sub.steer(u, gamma=1.0, tau=0.0) for u in unsafe]
        )
        steered_coords = sub.coordinates(steered)
        assert float(steered_coords.max()) <= 1e-6

    def test_insufficient_samples_per_class(self):
        with pytest.raises(InsufficientSamplesError):
            fit_leace([np.zeros(4)], [np.zeros(4), np.zeros(4)])

    def test_identical_classes_rejected(self):
        r = _rng(0)
        points = r.normal(0, 1, size=(10, 6))
        # safe == unsafe → no signal
        with pytest.raises(InsufficientSamplesError, match="cross-covariance"):
            fit_leace(points.tolist(), points.tolist(), ridge=1e-4)

    def test_higher_rank_extension(self):
        r = _rng(0)
        d = 10
        n = 50
        safe = r.normal(0, 1, size=(n, d))
        unsafe = r.normal(0, 1, size=(n, d))
        unsafe[:, 0] += 3.0
        unsafe[:, 1] += 2.0
        sub = fit_leace(safe, unsafe, rank=3, ridge=1e-4)
        assert sub.rank == 3
        gram = sub.basis @ sub.basis.T
        np.testing.assert_allclose(gram, np.eye(3), atol=1e-5)

    def test_projector_is_consistent(self):
        safe, unsafe = _make_clusters(d=8, seed=4)
        sub = fit_leace(safe, unsafe, ridge=1e-3)
        P = sub.projector()
        # Applying the LEACE projector should be idempotent-ish: twice
        # gives the same residual as once (within tolerance).
        h = np.asarray(unsafe[0], dtype=np.float64)
        centered = h - sub.mean
        once = centered @ P.T
        twice = once @ P.T
        np.testing.assert_allclose(once, twice, atol=1e-6)


# ---------------------------------------------------------------------------
# Risk-adaptive steering
# ---------------------------------------------------------------------------


class TestRiskAdaptiveSteering:
    def test_config_validation(self):
        sub = ViolationSubspace(basis=np.eye(1, 4), mean=np.zeros(4))
        with pytest.raises(ValueError, match="gamma"):
            RiskAdaptiveSteering(subspace=sub, gamma=0.0)
        with pytest.raises(ValueError, match="gamma"):
            RiskAdaptiveSteering(subspace=sub, gamma=2.0)

    def test_apply_is_steer(self):
        v = np.zeros(4)
        v[0] = 1.0
        sub = ViolationSubspace(basis=v.reshape(1, -1), mean=np.zeros(4))
        cfg = RiskAdaptiveSteering(subspace=sub, gamma=1.0, tau=0.0)
        h = np.array([3.0, 1.0, 0.0, 0.0])
        out = cfg.apply(h)
        np.testing.assert_allclose(out, np.array([0.0, 1.0, 0.0, 0.0]), atol=1e-9)


# ---------------------------------------------------------------------------
# Adversarial eval harness
# ---------------------------------------------------------------------------


class TestAdversarialScore:
    def test_score_reduces_with_larger_gamma(self):
        safe, unsafe = _make_clusters(
            d=16, n=80, axis=4, separation=4.0, seed=9
        )
        sub = fit_subspace(safe, unsafe, rank=1)
        low = adversarial_score(sub, unsafe, gamma=0.2, tau=0.0)
        high = adversarial_score(sub, unsafe, gamma=1.0, tau=0.0)
        # Stronger steering => smaller residual
        assert high < low

    def test_score_bounds(self):
        safe, unsafe = _make_clusters(seed=10)
        sub = fit_subspace(safe, unsafe, rank=1)
        s = adversarial_score(sub, unsafe, gamma=1.0)
        # Always non-negative; <= 1.0 within numerical slack
        assert 0.0 <= s <= 1.0 + 1e-9

    def test_empty_eval_set_raises(self):
        sub = ViolationSubspace(basis=np.eye(1, 4), mean=np.zeros(4))
        with pytest.raises(InsufficientSamplesError):
            adversarial_score(sub, [])

    def test_rank2_captures_two_violation_modes(self):
        """Evidence for subspace over single-vector: with two
        orthogonal violation modes, rank-2 steering drives max
        positive coordinate to 0 across both modes. A rank-1
        approximation can only cover one direction at a time, so
        its per-mode residual will be larger for at least one mode.
        """
        r = _rng(42)
        d = 20
        n = 80
        safe = r.normal(0, 1, size=(n, d))
        unsafe = r.normal(0, 1, size=(n, d))
        unsafe[: n // 2, 3] += 4.0
        unsafe[n // 2 :, 7] += 4.0
        sub1 = fit_subspace(safe, unsafe, rank=1)
        sub2 = fit_subspace(safe, unsafe, rank=2)
        # One-sided steering drives positive coords to 0
        steered1 = np.asarray(
            [sub1.steer(u, gamma=1.0, tau=0.0) for u in unsafe]
        )
        steered2 = np.asarray(
            [sub2.steer(u, gamma=1.0, tau=0.0) for u in unsafe]
        )
        # Measure residual projection along each individual mode axis
        mode_a = np.zeros(d); mode_a[3] = 1.0
        mode_b = np.zeros(d); mode_b[7] = 1.0
        # Rank-2 subspace should reduce projection along BOTH modes
        # Rank-1 can only reduce one. The sum of post-steer
        # positive projections along mode_a and mode_b should be
        # smaller for rank-2.
        def pos_mass(H, axis):
            return float(np.clip(H @ axis, 0, None).mean())
        mass1 = pos_mass(steered1, mode_a) + pos_mass(steered1, mode_b)
        mass2 = pos_mass(steered2, mode_a) + pos_mass(steered2, mode_b)
        assert mass2 <= mass1 + 1e-6
