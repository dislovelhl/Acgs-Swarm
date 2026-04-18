"""
Empirical proof of Birkhoff Uniformity Collapse in constitutional_swarm.

The Perron-Frobenius theorem dictates that repeated composition of strictly positive
doubly stochastic (DS) matrices converges to J = (1/N) * ones(N,N) — the uniform
matrix — NOT the identity I. This destroys specialized trust structure.

For Path C (ICLR 2027): this test provides the empirical motivation for replacing
the Birkhoff polytope constraint with a Spectral-Sphere constraint (sHC-style),
which allows negative entries and breaks the Perron-Frobenius attractor.

Expected result: FAIL — retention_ratio < 0.10 by cycle 50-100.
"""

import random

import pytest
from constitutional_swarm.manifold import GovernanceManifold


def _make_collaborative_manifold(n: int, seed: int = 42) -> GovernanceManifold:
    """Build a manifold with heterogeneous (non-uniform) initial trust."""
    rng = random.Random(seed)
    m = GovernanceManifold(num_agents=n)
    # Inject varied trust deltas so agents start with distinct specializations
    for i in range(n):
        for j in range(n):
            if i != j:
                delta = rng.uniform(0.0, 1.0)
                m.update_trust(from_agent=i, to_agent=j, delta=delta)
    return m


def _trust_variance(m: GovernanceManifold) -> float:
    """Variance of trust matrix entries around the uniform mean 1/N."""
    n = m.num_agents
    mat = m.trust_matrix
    mean = 1.0 / n
    total_var = 0.0
    for i in range(n):
        for j in range(n):
            total_var += (mat[i][j] - mean) ** 2
    return total_var / (n * n)


@pytest.mark.research
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Birkhoff Uniformity Collapse: Sinkhorn re-projection drives variance→0 "
        "(Perron-Frobenius). This failure is the empirical proof of the phenomenon. "
        "See §3.1 of MCFS whitepaper and test_spectral_sphere_retention.py for the fix."
    ),
)
@pytest.mark.parametrize("n,cycles", [(10, 50), (50, 100)])
def test_birkhoff_uniformity_collapse(n: int, cycles: int) -> None:
    """
    Compose the governance manifold with itself `cycles` times.

    A healthy swarm should retain >10% of its initial trust variance — indicating
    that agent specialization is preserved across governance rounds.

    Under Birkhoff constraints (Sinkhorn-Knopp re-projection after each compose),
    Perron-Frobenius guarantees convergence to J, so retention_ratio → 0.
    This test is EXPECTED TO FAIL under the current implementation.
    """
    manifold = _make_collaborative_manifold(n)
    initial_var = _trust_variance(manifold)

    current = manifold
    for cycle in range(cycles):
        current = current.compose(manifold)
        if cycle % 10 == 9:
            var = _trust_variance(current)
            retention = var / initial_var if initial_var > 0 else 0.0
            print(f"  cycle {cycle + 1:3d}: var={var:.6f}  retention={retention:.1%}")

    final_var = _trust_variance(current)
    retention_ratio = final_var / initial_var if initial_var > 0 else 0.0

    print(f"\nBirkhoff Uniformity Collapse report (n={n}, cycles={cycles})")
    print(f"  initial_var = {initial_var:.6f}")
    print(f"  final_var   = {final_var:.6f}")
    print(f"  retention   = {retention_ratio:.4f} ({retention_ratio:.1%})")

    assert retention_ratio > 0.10, (
        f"Birkhoff Uniformity Collapse confirmed (n={n}, cycles={cycles}): "
        f"swarm lost {(1 - retention_ratio):.1%} of specialized trust variance. "
        f"Perron-Frobenius convergence to J = (1/N)·11ᵀ destroys agent specialization. "
        f"Fix: replace Birkhoff constraint with Spectral-Sphere projection (Path C)."
    )
