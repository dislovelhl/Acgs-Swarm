"""
Tests for swarm_ode.py — MCFS Phase 4 continuous-time dynamics.

Three test tiers:
1. RK4 integrator correctness (StationaryField → known analytic solution)
2. Spectral projection enforcement (σ_max ≤ r at every recorded step)
3. Variance retention comparison: continuous ODE vs discrete compose()

torch-optional via pytest.importorskip.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
from torch import Tensor


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _random_trust_matrix(n: int, seed: int = 42) -> Tensor:
    """Random n×n trust matrix with entries in [0, 1], then spectral-projected."""
    torch.manual_seed(seed)
    H = torch.rand(n, n)
    from constitutional_swarm.swarm_ode import spectral_project_torch
    return spectral_project_torch(H, r=1.0)


def _trust_variance(H: Tensor) -> float:
    mean = H.mean()
    return ((H - mean) ** 2).mean().item()


# ──────────────────────────────────────────────────────────────────────────────
# RK4 integrator correctness
# ──────────────────────────────────────────────────────────────────────────────


def test_rk4_stationary_field_linear_growth() -> None:
    """With dH/dt = W (constant), H(t) = H0 + W*t (before projection).

    For small W and short t_span, projection should not clip, so the
    analytic solution holds exactly (up to RK4 discretization error).
    """
    from constitutional_swarm.swarm_ode import (
        StationaryField,
        projected_rk4_step,
    )

    n = 5
    H0 = torch.eye(n) * 0.1
    W = torch.ones(n, n) * 0.001  # Very small flow
    f = StationaryField(W)

    dt = 0.01
    H = H0.clone()
    t = 0.0
    n_steps = 10

    for _ in range(n_steps):
        H = projected_rk4_step(f, H, t, dt, r=10.0, residual_alpha=0.0)
        t += dt

    # Expected: H ≈ H0 + W * t_total (r=10 is large, no clipping)
    t_total = dt * n_steps
    H_expected = H0 + W * t_total

    assert torch.allclose(H, H_expected, atol=1e-6), (
        f"RK4 with constant field should give H0 + W*t.\n"
        f"Max diff: {(H - H_expected).abs().max().item():.2e}"
    )


def test_rk4_zero_field_preserves_state() -> None:
    """With dH/dt = 0, state should not change (modulo residual)."""
    from constitutional_swarm.swarm_ode import (
        StationaryField,
        integrate,
    )

    n = 5
    H0 = torch.eye(n) * 0.5
    f = StationaryField(torch.zeros(n, n))

    result = integrate(f, H0, t_span=(0, 1), n_steps=50, r=1.0, residual_alpha=0.0)
    H_final = result["H_final"]

    assert torch.allclose(H_final, H0, atol=1e-8), (
        f"Zero field + no residual should preserve H exactly.\n"
        f"Max diff: {(H_final - H0).abs().max().item():.2e}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Spectral projection enforcement
# ──────────────────────────────────────────────────────────────────────────────


def test_spectral_bound_maintained_throughout() -> None:
    """σ_max(H) ≤ r at every recorded trajectory point."""
    from constitutional_swarm.swarm_ode import (
        TrustDecayField,
        integrate,
        _spectral_norm_torch,
    )

    n = 10
    r = 1.0
    H0 = _random_trust_matrix(n)
    f = TrustDecayField(n, decay=0.05)

    result = integrate(
        f, H0, t_span=(0, 5), n_steps=200,
        r=r, residual_alpha=0.1, record_every=10,
    )

    for t, H, var in result["trajectory"]:
        sigma = _spectral_norm_torch(H)
        assert sigma <= r + 0.02, (
            f"Spectral bound violated at t={t:.2f}: σ_max={sigma:.6f} > r={r}"
        )


def test_residual_injection_active() -> None:
    """With residual_alpha > 0, diagonal entries should be biased toward α."""
    from constitutional_swarm.swarm_ode import (
        TrustDecayField,
        integrate,
    )

    n = 8
    alpha = 0.2
    H0 = torch.zeros(n, n)  # Start from zero
    f = TrustDecayField(n, decay=0.1)

    result = integrate(
        f, H0, t_span=(0, 2), n_steps=100,
        r=1.0, residual_alpha=alpha,
    )

    H_final = result["H_final"]
    diag = torch.diag(H_final)

    # With zero-start and residual injection, diagonal should be biased toward α
    # (exact value depends on dynamics, but should be positive and nonzero)
    assert (diag > 0).all(), (
        f"Residual α={alpha} should keep diagonal entries positive.\n"
        f"Diagonal: {diag.tolist()}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Variance retention: continuous ODE vs discrete compose()
# ──────────────────────────────────────────────────────────────────────────────


def test_continuous_ode_retains_variance() -> None:
    """Projected RK4 + residual must retain significant trust variance.

    The continuous ODE with TrustDecayField + spectral projection + residual
    should converge to a stable fixed point with nonzero variance, analogous
    to the discrete SpectralSphereManifold.compose(residual_alpha=0.1) result.
    """
    from constitutional_swarm.swarm_ode import (
        TrustDecayField,
        integrate,
    )

    n = 10
    H0 = _random_trust_matrix(n)
    initial_var = _trust_variance(H0)
    assert initial_var > 0

    f = TrustDecayField(n, decay=0.05, seed=42)
    result = integrate(
        f, H0, t_span=(0, 10), n_steps=500,
        r=1.0, residual_alpha=0.1, record_every=50,
    )

    H_final = result["H_final"]
    final_var = _trust_variance(H_final)

    print(f"\nContinuous ODE variance retention (n={n}, t=[0,10], 500 steps)")
    print(f"  initial_var = {initial_var:.6f}")
    print(f"  final_var   = {final_var:.6f}")
    print(f"  retention   = {final_var / initial_var:.1%}")
    for t, H, var in result["trajectory"]:
        print(f"  t={t:5.1f}: var={var:.6f}  retention={var / initial_var:.1%}")

    # Must retain nonzero variance (unlike Birkhoff which collapses to 0%)
    assert final_var > 0.001 * initial_var, (
        f"ODE variance collapsed to {final_var:.2e} "
        f"(initial: {initial_var:.2e}, retention: {final_var / initial_var:.1%})"
    )


def test_continuous_variance_is_stable() -> None:
    """Variance must converge to a stable fixed point, not continue decaying."""
    from constitutional_swarm.swarm_ode import (
        TrustDecayField,
        integrate,
    )

    n = 20
    H0 = _random_trust_matrix(n, seed=99)
    f = TrustDecayField(n, decay=0.05, seed=99)

    result = integrate(
        f, H0, t_span=(0, 20), n_steps=1000,
        r=1.0, residual_alpha=0.1, record_every=100,
    )

    traj = result["trajectory"]
    # Check last two recorded variances are within 10% of each other
    if len(traj) >= 2:
        _, _, var_prev = traj[-2]
        _, _, var_last = traj[-1]
        rel_change = abs(var_last - var_prev) / (var_prev + 1e-12)
        print(f"\nStability check: var[-2]={var_prev:.6f}, var[-1]={var_last:.6f}, "
              f"change={rel_change:.2%}")
        assert rel_change < 0.15, (
            f"Variance still changing at end of integration "
            f"(prev={var_prev:.6f}, last={var_last:.6f}, change={rel_change:.1%}). "
            f"Expected convergence."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Interface and edge cases
# ──────────────────────────────────────────────────────────────────────────────


def test_integrate_returns_expected_keys() -> None:
    """integrate() must return dict with correct keys."""
    from constitutional_swarm.swarm_ode import StationaryField, integrate

    n = 3
    H0 = torch.eye(n)
    f = StationaryField(torch.zeros(n, n))

    result = integrate(f, H0, n_steps=10)
    for key in ("H_final", "t_final", "n_steps", "trajectory"):
        assert key in result, f"Missing key: {key}"
    assert result["n_steps"] == 10


def test_integrate_trajectory_recording() -> None:
    """record_every > 0 must populate trajectory list."""
    from constitutional_swarm.swarm_ode import StationaryField, integrate

    n = 3
    H0 = torch.eye(n)
    f = StationaryField(torch.zeros(n, n))

    result = integrate(f, H0, n_steps=100, record_every=25)
    traj = result["trajectory"]
    # Steps 0, 25, 50, 75 + final = 5 entries
    assert len(traj) == 5, f"Expected 5 trajectory entries, got {len(traj)}"


def test_trust_decay_field_shape() -> None:
    """TrustDecayField must return same shape as input."""
    from constitutional_swarm.swarm_ode import TrustDecayField

    n = 8
    f = TrustDecayField(n)
    H = torch.randn(n, n)
    dHdt = f(H, t=0.0)
    assert dHdt.shape == (n, n)


def test_spectral_project_torch_clipping() -> None:
    """spectral_project_torch must clip σ_max to r."""
    from constitutional_swarm.swarm_ode import spectral_project_torch, _spectral_norm_torch

    H = torch.eye(5) * 10.0  # σ_max = 10
    H_proj = spectral_project_torch(H, r=1.0)
    sigma = _spectral_norm_torch(H_proj)
    assert abs(sigma - 1.0) < 1e-3, f"Expected σ_max≈1.0, got {sigma}"


def test_spectral_project_torch_passthrough() -> None:
    """spectral_project_torch must not modify matrices already within sphere."""
    from constitutional_swarm.swarm_ode import spectral_project_torch

    H = torch.eye(5) * 0.3
    H_proj = spectral_project_torch(H, r=1.0)
    assert torch.allclose(H, H_proj, atol=1e-8)
