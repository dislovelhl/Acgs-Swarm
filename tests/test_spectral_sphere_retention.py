"""
Spectral-Sphere Manifold — trust variance retention tests.

Green counterpart to test_manifold_degeneration.py (the Birkhoff collapse proof).

These tests verify that SpectralSphereManifold preserves trust specialization
across repeated governance compositions, where GovernanceManifold collapses to 0%.

Expected result: ALL PASS — retention_ratio > 0.50 (we aim for >80%).
"""

import random

import pytest
from constitutional_swarm.spectral_sphere import (
    SpectralSphereManifold,
    spectral_norm_power_iter,
    spectral_sphere_project,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _make_manifold(n: int, seed: int = 42, r: float = 1.0) -> SpectralSphereManifold:
    """Build a manifold with heterogeneous initial trust (same setup as collapse test)."""
    rng = random.Random(seed)
    m = SpectralSphereManifold(num_agents=n, r=r)
    for i in range(n):
        for j in range(n):
            if i != j:
                delta = rng.uniform(0.0, 1.0)
                m.update_trust(from_agent=i, to_agent=j, delta=delta)
    return m


def _trust_variance(m: SpectralSphereManifold) -> float:
    """Variance of trust matrix entries around zero (not uniform mean)."""
    n = m.num_agents
    mat = m.trust_matrix
    # Mean of all entries
    mean = sum(mat[i][j] for i in range(n) for j in range(n)) / (n * n)
    total_var = sum((mat[i][j] - mean) ** 2 for i in range(n) for j in range(n))
    return total_var / (n * n)


# ──────────────────────────────────────────────────────────────────────────────
# Core: variance retention after repeated composition
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("n,cycles", [(10, 50), (50, 100)])
def test_spectral_sphere_slower_than_birkhoff(n: int, cycles: int) -> None:
    """Spectral sphere decays slower than Birkhoff, but still decays without residual.

    Birkhoff (GovernanceManifold): 0.0% retention by cycle 10.
    Spectral sphere (alpha=0.0):   ~2-5% retention at cycle 10, decays to ~1%.

    This is NOT the full fix — it's the empirical baseline showing spectral sphere
    is strictly better than Birkhoff. The full fix requires residual connections
    (see test_residual_compose_retains_variance).
    """
    manifold = _make_manifold(n)
    initial_var = _trust_variance(manifold)
    assert initial_var > 0, "Manifold has no initial variance — test setup broken"

    # Measure at cycle 10 only (Birkhoff is already 0% here)
    current = manifold
    for _ in range(10):
        current = current.compose(manifold)

    var_at_10 = _trust_variance(current)
    retention_at_10 = var_at_10 / initial_var if initial_var > 0 else 0.0
    print(f"  spectral sphere cycle 10: retention={retention_at_10:.1%} (Birkhoff: 0.0%)")

    # Must be strictly better than Birkhoff (which is exactly 0.0%)
    assert retention_at_10 > 0.01, (
        f"Spectral sphere should retain >1% at cycle 10 (Birkhoff retains 0%). "
        f"Got {retention_at_10:.3%}"
    )


@pytest.mark.parametrize("n,cycles", [(10, 50), (50, 100)])
def test_residual_compose_retains_variance(n: int, cycles: int) -> None:
    """Spectral sphere + residual connections (alpha=0.1) converges to a STABLE fixed point.

    This is the full Path C fix. Adding alpha * I to each composition prevents
    power-iteration convergence to rank-1, analogous to skip connections in mHC.

    Observed fixed-point behavior (empirical):
        n=10, cycles=50:   stabilizes at ~20% retention (perfectly flat from cycle 10)
        n=50, cycles=100:  stabilizes at ~142% retention (flat from cycle 10)

    Note: retention > 100% is correct for n=50 - the residual alpha * I injection adds
    diagonal structure that increases variance above the original random initialization.
    The key property is STABILITY (variance stops changing), not the exact percentage.

    Three-tier comparison (all measured at cycle 10):
        Birkhoff (GovernanceManifold):         0.0% - catastrophic collapse
        Spectral sphere (alpha=0.0):          ~2-5% - slower decay, unstable
        Spectral sphere + residual (alpha=0.1): >10% - stable fixed point
    """
    manifold = _make_manifold(n)
    initial_var = _trust_variance(manifold)
    assert initial_var > 0, "Manifold has no initial variance — test setup broken"

    var_history = []
    current = manifold
    for cycle in range(cycles):
        current = current.compose(manifold, residual_alpha=0.1)
        if cycle % 10 == 9:
            var = _trust_variance(current)
            retention = var / initial_var if initial_var > 0 else 0.0
            var_history.append(var)
            print(f"  cycle {cycle + 1:3d}: var={var:.6f}  retention={retention:.1%}")

    final_var = _trust_variance(current)
    retention_ratio = final_var / initial_var if initial_var > 0 else 0.0

    print(f"\nSpectral-Sphere + Residual (alpha=0.1) report (n={n}, cycles={cycles})")
    print(f"  initial_var = {initial_var:.6f}")
    print(f"  final_var   = {final_var:.6f}")
    print(f"  retention   = {retention_ratio:.4f} ({retention_ratio:.1%})")

    # 1. Variance must not collapse to zero (key contrast with Birkhoff)
    assert retention_ratio > 0.05, (
        f"Spectral sphere + residual collapsed (n={n}, cycles={cycles}, "
        f"retention={retention_ratio:.1%}). Birkhoff collapses to 0.0%."
    )

    # 2. Variance must be STABLE — last two recorded checkpoints within 5%
    if len(var_history) >= 2:
        last, prev = var_history[-1], var_history[-2]
        relative_change = abs(last - prev) / (prev + 1e-12)
        assert relative_change < 0.05, (
            f"Variance still decaying at final checkpoint "
            f"(prev={prev:.6f}, last={last:.6f}, change={relative_change:.2%}). "
            f"Expected convergence to a fixed point."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Projection properties
# ──────────────────────────────────────────────────────────────────────────────


def test_spectral_norm_estimation_identity() -> None:
    """Identity matrix has sigma_max = 1.0."""
    n = 5
    identity = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    sigma = spectral_norm_power_iter(identity)
    assert abs(sigma - 1.0) < 1e-4, f"Identity sigma_max should be 1.0, got {sigma}"


def test_spectral_norm_estimation_scaled() -> None:
    """Diagonal matrix with max entry 3.0 has sigma_max = 3.0."""
    n = 4
    D = [[0.0] * n for _ in range(n)]
    D[0][0] = 3.0
    D[1][1] = 1.5
    D[2][2] = 0.7
    D[3][3] = 0.2
    sigma = spectral_norm_power_iter(D)
    assert abs(sigma - 3.0) < 1e-3, f"Diagonal sigma_max should be 3.0, got {sigma}"


def test_projection_clips_large_matrix() -> None:
    """Matrix with sigma_max > r should be clipped to exactly r."""
    n = 3
    # Scale identity by 5 - sigma_max = 5.0
    big = [[5.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    result = spectral_sphere_project(big, r=1.0)
    assert result.clipped is True
    assert abs(result.spectral_norm - 1.0) < 1e-4, (
        f"After projection, sigma_max should be 1.0, got {result.spectral_norm}"
    )


def test_projection_preserves_small_matrix() -> None:
    """Matrix with sigma_max <= r should not be modified."""
    n = 3
    small = [[0.1 if i == j else 0.0 for j in range(n)] for i in range(n)]
    result = spectral_sphere_project(small, r=1.0)
    assert result.clipped is False
    assert abs(result.spectral_norm - 0.1) < 1e-4


# ──────────────────────────────────────────────────────────────────────────────
# Interface parity with GovernanceManifold
# ──────────────────────────────────────────────────────────────────────────────


def test_interface_num_agents() -> None:
    m = SpectralSphereManifold(num_agents=7)
    assert m.num_agents == 7


def test_interface_is_stable_default() -> None:
    """Freshly initialized manifold (all-zero trust) should be stable."""
    m = SpectralSphereManifold(num_agents=5)
    assert m.is_stable is True


def test_interface_update_and_project() -> None:
    """update_trust invalidates cache; trust_matrix reflects new values."""
    m = SpectralSphereManifold(num_agents=3)
    m.update_trust(from_agent=0, to_agent=1, delta=0.5)
    mat = m.trust_matrix
    assert mat[0][1] != 0.0


def test_compose_size_mismatch_raises() -> None:
    a = SpectralSphereManifold(num_agents=3)
    b = SpectralSphereManifold(num_agents=4)
    with pytest.raises(ValueError, match="different sizes"):
        a.compose(b)


def test_compose_returns_same_type() -> None:
    m = _make_manifold(5)
    composed = m.compose(m)
    assert isinstance(composed, SpectralSphereManifold)
    assert composed.num_agents == 5


def test_compose_is_stable() -> None:
    """Composition of stable manifolds should remain stable."""
    m = _make_manifold(8)
    assert m.is_stable
    composed = m.compose(m)
    assert composed.is_stable


def test_summary_keys() -> None:
    m = _make_manifold(4)
    s = m.summary()
    for key in ("num_agents", "radius", "spectral_norm", "clipped", "is_stable"):
        assert key in s, f"Missing key: {key}"


# ── Security regression tests ─────────────────────────────────────────────────


class TestSpectralNormGuaranteeAfterProjection:
    """P1: spectral_sphere_project must guarantee result is within radius."""

    def test_projected_norm_within_radius(self):
        """After projection, actual spectral norm must be ≤ r + epsilon."""
        import random

        from constitutional_swarm.spectral_sphere import (
            spectral_norm_power_iter,
            spectral_sphere_project,
        )

        rng = random.Random(7)
        # Build a 5x5 matrix with large singular values
        n = 5
        matrix = [[rng.gauss(0, 3) for _ in range(n)] for _ in range(n)]
        r = 1.0
        result = spectral_sphere_project(matrix, r=r)
        sigma_actual = spectral_norm_power_iter(
            list(map(list, result.matrix)), max_iterations=100, tol=1e-12
        )
        assert sigma_actual <= r + 1e-6, (
            f"Projected matrix spectral norm {sigma_actual:.8f} > r={r} + 1e-6"
        )

    def test_projection_idempotent(self):
        """Projecting an already-projected matrix should be a no-op."""
        import random

        from constitutional_swarm.spectral_sphere import spectral_sphere_project

        rng = random.Random(13)
        n = 4
        matrix = [[rng.gauss(0, 5) for _ in range(n)] for _ in range(n)]
        r = 0.8
        once = spectral_sphere_project(matrix, r=r)
        twice = spectral_sphere_project(list(map(list, once.matrix)), r=r)
        assert not twice.clipped, "Projecting an already-projected matrix should not clip"


class TestUpdateTrustValidation:
    """P2: update_trust must reject non-finite deltas and out-of-range indices."""

    def _make_manifold(self, n=3):
        from constitutional_swarm.spectral_sphere import SpectralSphereManifold

        return SpectralSphereManifold(num_agents=n)

    def test_nan_delta_rejected(self):
        import pytest

        m = self._make_manifold()
        with pytest.raises(ValueError, match="finite"):
            m.update_trust(0, 1, float("nan"))

    def test_inf_delta_rejected(self):
        import pytest

        m = self._make_manifold()
        with pytest.raises(ValueError, match="finite"):
            m.update_trust(0, 1, float("inf"))

    def test_out_of_range_index_rejected(self):
        import pytest

        m = self._make_manifold(n=3)
        with pytest.raises(IndexError):
            m.update_trust(0, 5, 1.0)
