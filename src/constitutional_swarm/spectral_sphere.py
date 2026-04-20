"""
Spectral-Sphere Manifold — Path C replacement for the Birkhoff constraint.

The Birkhoff constraint (doubly stochastic + Sinkhorn re-projection) causes
*Uniformity Collapse*: by the Perron-Frobenius theorem, repeated composition of
strictly positive DS matrices converges to J = (1/N)·11ᵀ, destroying specialized
trust structure in O(10) governance cycles. See test_manifold_degeneration.py for
the empirical proof.

This module replaces the Sinkhorn projection with a **Spectral-Sphere projection**:

    H_proj = H * min(1, r / sigma_max(H))

where sigma_max(H) is the largest singular value (spectral norm) and r is the sphere
radius (default 1.0). This allows negative entries, breaks the Perron-Frobenius
attractor, and preserves the r-bounded spectral norm stability guarantee.

Theoretical grounding:
  - sHC paper (arXiv:2603.20896): spectral norm sphere as manifold constraint
  - mHC paper (arXiv:2512.24880): manifold constraints prevent gradient explosion
  - MCFS Phase 2: non-Euclidean swarm topology for trust preservation

API mirrors GovernanceManifold exactly so existing code can swap in SpectralSphereManifold
by changing one import.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpectralProjectionResult:
    """Result of a spectral-sphere projection step."""

    matrix: tuple[tuple[float, ...], ...]
    spectral_norm: float  # sigma_max of the projected matrix - always <= r
    clipped: bool  # True if projection actually changed the matrix
    power_iterations: int


def _mat_mul(a: list[list[float]], b: list[list[float]], n: int) -> list[list[float]]:
    """O(n³) matrix multiply — pure Python, no numpy required."""
    return [[sum(a[i][k] * b[k][j] for k in range(n)) for j in range(n)] for i in range(n)]


def _mat_vec(m: list[list[float]], v: list[float], n: int) -> list[float]:
    """Matrix-vector product."""
    return [sum(m[i][j] * v[j] for j in range(n)) for i in range(n)]


def _mat_T_vec(m: list[list[float]], v: list[float], n: int) -> list[float]:
    """Transpose-vector product (for power iteration on M^T * M)."""
    return [sum(m[j][i] * v[j] for j in range(n)) for i in range(n)]


def _l2_norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def spectral_norm_power_iter(
    matrix: list[list[float]],
    *,
    max_iterations: int = 30,
    seed: int = 0,
    tol: float = 1e-8,
) -> float:
    """Estimate sigma_max(matrix) via power iteration on M^T * M.

    Converges to the largest singular value. O(n²) per iteration, O(n²·k) total.
    No numpy dependency — designed for the pure-Python swarm runtime.

    Args:
        matrix: nxn matrix as list-of-lists.
        max_iterations: Maximum power iterations (30 is generous for n<=200).
        seed: RNG seed for reproducible initialization.
        tol: Convergence threshold on relative sigma change.

    Returns:
        Largest singular value (spectral norm) of matrix.
    """
    n = len(matrix)
    if n == 0:
        return 0.0

    rng = random.Random(seed)  # noqa: S311 - deterministic numerical initialization
    v = [rng.gauss(0, 1) for _ in range(n)]
    norm_v = _l2_norm(v)
    if norm_v < 1e-12:
        return 0.0
    v = [x / norm_v for x in v]

    sigma = 0.0
    for _ in range(max_iterations):
        # v_{k+1} = Mᵀ·(M·v_k)
        mv = _mat_vec(matrix, v, n)
        mtmv = _mat_T_vec(matrix, mv, n)
        new_norm = _l2_norm(mtmv)
        if new_norm < 1e-14:
            return 0.0
        new_sigma = math.sqrt(new_norm)  # sigma ~= ||M^T * M * v||^0.5 / ||v||
        v = [x / new_norm for x in mtmv]
        if abs(new_sigma - sigma) / (sigma + 1e-12) < tol:
            return new_sigma
        sigma = new_sigma

    return sigma


def spectral_sphere_project(
    matrix: list[list[float]],
    *,
    r: float = 1.0,
    max_power_iter: int = 30,
) -> SpectralProjectionResult:
    """Project matrix onto the spectral-norm sphere of radius r.

    Computes H_proj = H * min(1, r / sigma_max(H)).

    If sigma_max(H) <= r, no clipping occurs and the matrix is returned unchanged.
    This is the key difference from Sinkhorn: no row/column normalization, so
    negative entries and non-uniform structure are preserved.

    Args:
        matrix: nxn trust matrix.
        r: Spectral-sphere radius (default 1.0).
        max_power_iter: Power iterations for sigma_max estimation.

    Returns:
        SpectralProjectionResult with projected matrix and diagnostics.
    """
    n = len(matrix)

    sigma = spectral_norm_power_iter(matrix, max_iterations=max_power_iter)

    if sigma <= r + 1e-10:
        # Already inside the sphere — no projection needed
        projected = matrix
        clipped = False
    else:
        scale = r / sigma
        projected = [[matrix[i][j] * scale for j in range(n)] for i in range(n)]
        clipped = True
        sigma = r  # By construction

    return SpectralProjectionResult(
        matrix=tuple(tuple(row) for row in projected),
        spectral_norm=sigma,
        clipped=clipped,
        power_iterations=max_power_iter,
    )


class SpectralSphereManifold:
    """Governance manifold constrained to a spectral-norm sphere.

    Drop-in replacement for GovernanceManifold. The key behavioral difference:

        GovernanceManifold.compose() → sinkhorn_knopp re-projection
                                      → Perron-Frobenius collapse by cycle 10

        SpectralSphereManifold.compose() → spectral_sphere_project
                                          → trust variance preserved (>80% retention)

    The manifold relaxes the doubly-stochastic constraint entirely, keeping only
    ‖H‖₂ ≤ r. This allows agents to hold negative trust entries (representing
    explicit distrust or adversarial flags), which the Birkhoff polytope prohibits.

    Args:
        num_agents: Number of agents in the swarm.
        r: Spectral-sphere radius. r=1.0 preserves contractiveness (compositions
           never amplify signals). r<1.0 adds damping. r>1.0 allows amplification
           (useful for hierarchical swarms where planners have broader influence).
        max_power_iter: Power iterations for sigma_max estimation in each projection.
    """

    def __init__(
        self,
        num_agents: int,
        *,
        r: float = 1.0,
        max_power_iter: int = 30,
        smoothing: float = 0.999,
    ) -> None:
        self._n = num_agents
        self._r = r
        self._max_power_iter = max_power_iter
        if not 0.0 <= smoothing < 1.0:
            raise ValueError(f"smoothing must be in [0, 1), got {smoothing}")
        self._smoothing = smoothing
        self._raw_trust: list[list[float]] = [[0.0] * num_agents for _ in range(num_agents)]
        self._projected: SpectralProjectionResult | None = None
        self._smoothed: SpectralProjectionResult | None = None

    @property
    def num_agents(self) -> int:
        return self._n

    @property
    def radius(self) -> float:
        """Spectral-sphere radius constraint."""
        return self._r

    def update_trust(self, from_agent: int, to_agent: int, delta: float) -> None:
        """Update the raw trust weight from from_agent toward to_agent."""
        self._raw_trust[from_agent][to_agent] += delta
        self._projected = None  # Invalidate cache

    def project(self) -> SpectralProjectionResult:
        """Project current raw trust matrix onto the spectral sphere.

        Applies EMA smoothing across sequential projections (hysteresis) to
        stabilize trust-matrix dynamics under noisy incremental updates. The
        smoothing is skipped on the first projection (so a single update is
        visible immediately) and whenever ``smoothing == 0.0`` (back-compat).
        """
        if self._projected is not None:
            return self._projected

        new_proj = spectral_sphere_project(
            self._raw_trust,
            r=self._r,
            max_power_iter=self._max_power_iter,
        )

        if self._smoothing > 0.0 and self._smoothed is not None:
            alpha = self._smoothing
            n = self._n
            prev_mat = self._smoothed.matrix
            new_mat = new_proj.matrix
            blended = tuple(
                tuple(
                    alpha * prev_mat[i][j] + (1.0 - alpha) * new_mat[i][j]
                    for j in range(n)
                )
                for i in range(n)
            )
            sigma = spectral_norm_power_iter(
                [list(row) for row in blended],
                max_iterations=self._max_power_iter,
            )
            if sigma > self._r + 1e-10:
                scale = self._r / sigma
                blended = tuple(
                    tuple(v * scale for v in row) for row in blended
                )
                sigma = self._r
                clipped = True
            else:
                clipped = new_proj.clipped
            new_proj = SpectralProjectionResult(
                matrix=blended,
                spectral_norm=sigma,
                clipped=clipped,
                power_iterations=self._max_power_iter,
            )

        self._smoothed = new_proj
        self._projected = new_proj
        return self._projected

    @property
    def trust_matrix(self) -> tuple[tuple[float, ...], ...]:
        """The spectral-sphere-projected trust matrix."""
        return self.project().matrix

    @property
    def spectral_norm(self) -> float:
        """sigma_max of the projected matrix. Always <= r."""
        return self.project().spectral_norm

    @property
    def is_stable(self) -> bool:
        """True if spectral norm ≤ r (i.e., compositions are contractive)."""
        return self.spectral_norm <= self._r + 1e-6

    def compose(
        self,
        other: SpectralSphereManifold,
        *,
        residual_alpha: float = 0.0,
    ) -> SpectralSphereManifold:
        """Compose two spectral-sphere manifolds.

        Key difference from GovernanceManifold.compose():
        - No sinkhorn_knopp re-projection → no Perron-Frobenius attractor
        - Only spectral clipping → trust specialization decays more slowly

        Args:
            other: The manifold to compose with (right-hand side).
            residual_alpha: Fraction of identity matrix added to the composed
                product before projection. 0.0 = pure composition (default,
                backward compatible). Values in [0.05, 0.20] stabilize variance
                by preventing power-iteration convergence to a rank-1 limit.

                Formally: result = spectral_project(alpha * I + (1 - alpha) * (A @ B))

                This is the mHC residual-connection analog for governance matrices.
                With alpha > 0, H^k never converges to rank-1 because each composition
                injects alpha * I of identity structure back into the product.

        Birkhoff (GovernanceManifold): 0% retention at cycle 10.
        Spectral sphere (alpha=0.0):  ~5% retention at cycle 10, decays slowly.
        Spectral sphere (alpha=0.1):  >80% retention across 100+ cycles.
        """
        if self._n != other._n:
            raise ValueError("Cannot compose manifolds of different sizes")
        if abs(self._r - other._r) > 1e-10:
            raise ValueError(f"Spectral sphere radii must match: {self._r} != {other._r}")
        if not 0.0 <= residual_alpha < 1.0:
            raise ValueError(f"residual_alpha must be in [0, 1), got {residual_alpha}")

        a = list(list(row) for row in self.trust_matrix)
        b = list(list(row) for row in other.trust_matrix)
        n = self._n

        product = _mat_mul(a, b, n)

        if residual_alpha > 0.0:
            # Inject residual identity: alpha * I + (1 - alpha) * (A @ B)
            beta = 1.0 - residual_alpha
            product = [
                [beta * product[i][j] + (residual_alpha if i == j else 0.0) for j in range(n)]
                for i in range(n)
            ]

        result = SpectralSphereManifold(n, r=self._r, max_power_iter=self._max_power_iter)
        result._raw_trust = product
        # Project immediately so trust_matrix is always valid
        result._projected = spectral_sphere_project(
            product, r=self._r, max_power_iter=self._max_power_iter
        )
        return result

    def influence_vector(self, agent_idx: int) -> tuple[float, ...]:
        """Trust row for agent_idx (may contain negative entries — explicit distrust)."""
        return self.trust_matrix[agent_idx]

    def summary(self) -> dict[str, Any]:
        proj = self.project()
        return {
            "num_agents": self._n,
            "radius": self._r,
            "spectral_norm": proj.spectral_norm,
            "clipped": proj.clipped,
            "is_stable": self.is_stable,
        }
