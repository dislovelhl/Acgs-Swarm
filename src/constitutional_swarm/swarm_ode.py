"""
Continuous-Time Swarm Dynamics — MCFS Phase 4.

Replaces the discrete `GovernanceManifold.compose()` loop with a continuous ODE
on the trust matrix H(t) ∈ ℝⁿˣⁿ, integrated via a custom Projected RK4 solver.

State variable: S(t) = H(t), the nxn trust/routing matrix (Candidate A).

At each RK4 step, the derivative dH/dt = f_θ(H, t) is evaluated in Euclidean
space, then the result is projected back onto the spectral sphere and injected
with the residual alpha * I. This guarantees BIBO stability without computing tangent
spaces of the spectral norm ball (which requires differentiating through SVD).

The approach directly extends Phase 2:
    Discrete:   H_{k+1} = spectral_project(alpha * I + (1 - alpha) * (H_k @ H_0))
    Continuous: H(t+dt) = spectral_project(alpha * I + (1 - alpha) * RK4_step(f, H, t, dt))

Dependencies: torch (optional, same isolation as latent_dna.py).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from constitutional_swarm.merkle_crdt import MerkleCRDT

try:
    import torch
    import torch.nn as nn
    from torch import Tensor
except ImportError as exc:
    raise ImportError(
        "swarm_ode requires torch. Install with: pip install torch>=2.0"
    ) from exc

from constitutional_swarm.constants import CONSTITUTIONAL_HASH as _CONSTITUTIONAL_HASH

_DRAND_CHAIN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class SwarmVectorField(Protocol):
    """Protocol for the vector field f_θ(H, t) → dH/dt.

    Any nn.Module or callable that accepts (H: Tensor[n,n], t: float) and
    returns dH/dt: Tensor[n,n] satisfies this protocol.
    """

    def __call__(self, H: Tensor, t: float) -> Tensor: ...


class TrustDecayField(nn.Module):
    """Default vector field: learned task-pressure with exponential decay.

    dH/dt = tanh(W @ H) - lambda * H

    W is a learnable nxn matrix representing how each agent's trust influences
    others' evolution. lambda controls the natural decay rate - without reinforcement,
    trust fades. tanh prevents unbounded growth.

    Args:
        n: Number of agents.
        decay: Decay coefficient λ. Default 0.1.
        seed: Random seed for W initialization.
    """

    def __init__(self, n: int, *, decay: float = 0.1, seed: int = 0) -> None:
        super().__init__()
        gen = torch.Generator().manual_seed(seed)
        self.W = nn.Parameter(torch.randn(n, n, generator=gen) * 0.1)
        self.decay = decay

    def forward(self, H: Tensor, t: float) -> Tensor:
        return torch.tanh(self.W @ H) - self.decay * H


class StationaryField(nn.Module):
    """Trivial vector field for testing: dH/dt = W (constant flow).

    Useful for verifying the RK4 integrator independently of learned dynamics.

    Args:
        W: Constant flow matrix [n, n].
    """

    def __init__(self, W: Tensor) -> None:
        super().__init__()
        self.register_buffer("W", W)

    def forward(self, H: Tensor, t: float) -> Tensor:
        return self.W


def _spectral_norm_torch(M: Tensor, max_iter: int = 20) -> float:
    """Estimate sigma_max(M) via power iteration on M^T @ M. GPU-friendly."""
    n = M.shape[0]
    v = torch.randn(n, device=M.device, dtype=M.dtype)
    v = v / v.norm()

    sigma = 0.0
    for _ in range(max_iter):
        Mv = M @ v
        MTMv = M.T @ Mv
        new_norm = MTMv.norm().item()
        if new_norm < 1e-14:
            return 0.0
        new_sigma = new_norm ** 0.5
        v = MTMv / new_norm
        if abs(new_sigma - sigma) / (sigma + 1e-12) < 1e-8:
            return new_sigma
        sigma = new_sigma
    return sigma


def spectral_project_torch(
    H: Tensor,
    r: float = 1.0,
    max_power_iter: int = 20,
) -> Tensor:
    """Project H onto the spectral sphere ‖H‖₂ ≤ r. Differentiable-safe."""
    sigma = _spectral_norm_torch(H, max_iter=max_power_iter)
    if sigma <= r + 1e-10:
        return H
    return H * (r / sigma)


def projected_rk4_step(
    f: SwarmVectorField,
    H: Tensor,
    t: float,
    dt: float,
    *,
    r: float = 1.0,
    residual_alpha: float = 0.1,
    max_power_iter: int = 20,
) -> Tensor:
    """Single Projected RK4 step with spectral-sphere projection + residual.

    Computes:
        k1 = f(H, t)
        k2 = f(H + dt/2 · k1, t + dt/2)
        k3 = f(H + dt/2 · k2, t + dt/2)
        k4 = f(H + dt · k3, t + dt)
        H_unprojected = H + dt/6 · (k1 + 2k2 + 2k3 + k4)
        H_projected = spectral_project(H_unprojected, r)
        H_next = (1 - alpha) * H_projected + alpha * I

    Args:
        f: Vector field dH/dt = f(H, t).
        H: Current trust matrix [n, n].
        t: Current time.
        dt: Step size.
        r: Spectral sphere radius.
        residual_alpha: Identity injection coefficient.
        max_power_iter: Power iterations for spectral norm estimation.

    Returns:
        H at time t + dt, projected onto the spectral sphere with residual.
    """
    k1 = f(H, t)
    k2 = f(H + 0.5 * dt * k1, t + 0.5 * dt)
    k3 = f(H + 0.5 * dt * k2, t + 0.5 * dt)
    k4 = f(H + dt * k3, t + dt)

    H_unprojected = H + (dt / 6.0) * (k1 + 2.0 * k2 + 2.0 * k3 + k4)

    if residual_alpha > 0.0:
        n = H.shape[0]
        identity = torch.eye(n, device=H.device, dtype=H.dtype)
        H_unprojected = (1.0 - residual_alpha) * H_unprojected + residual_alpha * identity

    # Project AFTER residual injection to guarantee sigma_max <= r
    H_next = spectral_project_torch(H_unprojected, r=r, max_power_iter=max_power_iter)

    return H_next


def integrate(
    f: SwarmVectorField,
    H0: Tensor,
    *,
    t_span: tuple[float, float] = (0.0, 1.0),
    n_steps: int = 100,
    r: float = 1.0,
    residual_alpha: float = 0.1,
    max_power_iter: int = 20,
    record_every: int = 0,
    crdt: MerkleCRDT | None = None,
) -> dict[str, Any]:
    """Integrate the swarm ODE from t_span[0] to t_span[1].

    Args:
        f: Vector field dH/dt = f(H, t).
        H0: Initial trust matrix [n, n].
        t_span: (t_start, t_end).
        n_steps: Number of RK4 steps.
        r: Spectral sphere radius.
        residual_alpha: Identity injection coefficient.
        max_power_iter: Power iterations for spectral norm.
        record_every: If > 0, record H and variance every k steps.
            If 0, only return the final state.
        crdt: Optional MerkleCRDT replica that receives compact ODE snapshot
            metadata at the same recording points as trajectory entries.

    Returns:
        dict with keys:
            "H_final": Final trust matrix [n, n].
            "t_final": Final time.
            "n_steps": Total steps taken.
            "trajectory": list of (t, H, variance) tuples if record_every > 0.
    """
    t_start, t_end = t_span
    dt = (t_end - t_start) / n_steps
    H = H0.clone()
    t = t_start

    trajectory: list[tuple[float, Tensor, float]] = []

    for step in range(n_steps):
        if record_every > 0 and step % record_every == 0:
            var = _trust_variance_torch(H)
            trajectory.append((t, H.clone().detach(), var))
            if crdt is not None:
                import json

                crdt.append(
                    payload=json.dumps({"step": step, "t": t, "variance": var}),
                    payload_type="ode_snapshot",
                    bodes_passed=True,
                    constitutional_hash=_CONSTITUTIONAL_HASH,
                )

        H = projected_rk4_step(
            f, H, t, dt,
            r=r,
            residual_alpha=residual_alpha,
            max_power_iter=max_power_iter,
        )
        t += dt

    # Record final state
    if record_every > 0:
        var = _trust_variance_torch(H)
        trajectory.append((t, H.clone().detach(), var))
        if crdt is not None:
            import json

            crdt.append(
                payload=json.dumps({"step": n_steps, "t": t, "variance": var}),
                payload_type="ode_snapshot",
                bodes_passed=True,
                constitutional_hash=_CONSTITUTIONAL_HASH,
            )

    return {
        "H_final": H,
        "t_final": t,
        "n_steps": n_steps,
        "trajectory": trajectory,
    }


def _trust_variance_torch(H: Tensor) -> float:
    """Variance of trust matrix entries around their mean."""
    mean = H.mean()
    return ((H - mean) ** 2).mean().item()


# ---------------------------------------------------------------------------
# Differential Privacy helpers (NDSS 2027, §3.4)
# ---------------------------------------------------------------------------


def calibrate_sigma(
    r: float,
    residual_alpha: float,
    epsilon: float,
    delta: float,
) -> float:
    """Compute Gaussian noise std-dev for (ε,δ)-DP gossip (NDSS Lemma 4.3).

    Global sensitivity Δg = 2·(1-α)·r, derived from the fact that the
    residual injection reduces the Lipschitz constant of the update map
    from 2r (plain projection) to 2(1-α)r.

    Args:
        r: Spectral radius bound (SpectralSphere parameter).
        residual_alpha: Identity injection coefficient α ∈ (0,1).
        epsilon: Privacy budget ε > 0.
        delta: Privacy failure probability δ ∈ (0,1).

    Returns:
        σ such that the Gaussian mechanism H̃ = H_proj + N(0,σ²I) satisfies
        (ε,δ)-DP per round.
    """
    if not (0 < residual_alpha < 1):
        raise ValueError(f"residual_alpha must be in (0,1), got {residual_alpha}")
    if epsilon <= 0 or delta <= 0 or delta >= 1:
        raise ValueError(f"Invalid DP parameters: ε={epsilon}, δ={delta}")

    sensitivity = 2.0 * (1.0 - residual_alpha) * r
    return sensitivity * math.sqrt(2.0 * math.log(1.25 / delta)) / epsilon


def add_dp_noise(H_proj: Tensor, sigma: float) -> Tensor:
    """Add calibrated Gaussian noise for DP gossip broadcast (NDSS Eq. 3).

    Step 4 of Algorithm 1: Z ~ N(0, σ²·I_{n×n}), H̃ = H_proj + Z.

    This must be called AFTER spectral projection and BEFORE broadcast.
    The noise is additive; the receiver re-projects to maintain the
    spectral-sphere constraint (post-processing does not hurt DP).

    Args:
        H_proj: Projected trust matrix (already on spectral sphere).
        sigma: Noise standard deviation from calibrate_sigma().

    Returns:
        Noisy matrix H̃ with the same shape as H_proj.
    """
    if sigma <= 0:
        raise ValueError(f"sigma must be positive, got {sigma}")
    noise = torch.randn_like(H_proj) * sigma
    return H_proj + noise


# ---------------------------------------------------------------------------
# Discrete Gaussian Sampler (Canonne, Kamath & Steinke 2020)
# ---------------------------------------------------------------------------
# Circuit-friendly DP noise: exact integer output verifiable via PMF table.
# Replaces continuous Gaussian for zk-SNARK compatibility (Noir circuits).
# Reference: arXiv:2004.00010 — "The Discrete Gaussian for Differential Privacy"
# ---------------------------------------------------------------------------


class DiscreteGaussianSampler:
    """Discrete Gaussian distribution N_Z(0, sigma^2) over the integers.

    Samples from the truncated discrete Gaussian using the alias method
    with a CDT (Cumulative Distribution Table) lookup — exact integer
    output with no floating-point rounding artifacts.

    Properties:
    - Output is an integer in [-tail_bound, +tail_bound]
    - PMF: Pr[X=k] ∝ exp(-k²/(2σ²))
    - The PMF table is pre-computed at construction time; each sample
      is O(tail_bound) for the CDT scan (acceptable for small sigma).
    - Verifiable: any prover can reconstruct the CDT and check the sample.

    Args:
        sigma: Standard deviation (sensitivity / noise_multiplier).
        tail_bound: Truncation at ±tail_bound (default = ceil(6σ)).
        seed: Optional integer seed for reproducibility.

    Example::

        sampler = DiscreteGaussianSampler(sigma=1.0)
        noise = sampler.sample()            # single integer
        noise_vec = sampler.sample_vector(n=8)  # list of n integers
    """

    def __init__(
        self,
        sigma: float,
        tail_bound: int | None = None,
        seed: int | None = None,
    ) -> None:
        if sigma <= 0:
            raise ValueError(f"sigma must be positive, got {sigma}")
        self._sigma = sigma
        self._seed = seed
        self._noise_call_counter = 0
        self._tail = tail_bound if tail_bound is not None else max(6, math.ceil(6 * sigma))
        self._rng = torch.Generator()
        if seed is not None:
            self._rng.manual_seed(seed)

        # Build CDT (Cumulative Distribution Table)
        self._support = list(range(-self._tail, self._tail + 1))
        log_unnorm = torch.tensor(
            [-k * k / (2.0 * sigma * sigma) for k in self._support],
            dtype=torch.float64,
        )
        # numerically stable softmax-style normalization
        log_z = torch.logsumexp(log_unnorm, dim=0)
        self._pmf = (log_unnorm - log_z).exp()
        self._cdf = torch.cumsum(self._pmf, dim=0)

    @property
    def sigma(self) -> float:
        return self._sigma

    @property
    def tail_bound(self) -> int:
        return self._tail

    def pmf(self, k: int) -> float:
        """Probability mass at integer k (0.0 outside support)."""
        idx = k + self._tail
        if idx < 0 or idx >= len(self._support):
            return 0.0
        return float(self._pmf[idx].item())

    def sample(self) -> int:
        """Draw a single sample from N_Z(0, σ²)."""
        u = torch.rand(1, generator=self._rng, dtype=torch.float64).item()
        for i, cdf_val in enumerate(self._cdf):
            if u <= cdf_val.item():
                return self._support[i]
        return self._support[-1]  # numerical safety

    def sample_vector(self, n: int) -> list[int]:
        """Draw n independent samples."""
        return [self.sample() for _ in range(n)]

    def sample_tensor(self, shape: tuple[int, ...]) -> Tensor:
        """Draw samples into a torch Tensor of the given shape (float32)."""
        total = 1
        for s in shape:
            total *= s
        raw = [float(self.sample()) for _ in range(total)]
        return torch.tensor(raw, dtype=torch.float32).reshape(shape)

    def sensitivity_clipped_noise(
        self,
        shape: tuple[int, ...],
        sensitivity: float = 1.0,
    ) -> Tensor:
        """Add sensitivity-scaled discrete Gaussian noise to a zero tensor.

        Equivalent to continuous Gaussian but with integer-valued output.
        Used as drop-in for add_dp_noise() when zk-SNARK verifiability matters.

        Args:
            shape: Output shape.
            sensitivity: L2 sensitivity of the mechanism (default 1.0).

        Returns:
            Float tensor of shape ``shape`` containing integer noise values.
        """
        scaled_sigma = self._sigma * sensitivity
        # Derive a unique seed per call to avoid identical noise vectors.
        self._noise_call_counter += 1
        derived_seed = (
            (self._seed * 2654435761 + self._noise_call_counter) & 0xFFFFFFFF
            if self._seed is not None
            else None
        )
        sampler = self if sensitivity == 1.0 else DiscreteGaussianSampler(
            sigma=scaled_sigma,
            tail_bound=self._tail,
            seed=derived_seed,
        )
        return sampler.sample_tensor(shape)


# ---------------------------------------------------------------------------
# drand VRF Client — threshold VRF-seeded DP noise
# ---------------------------------------------------------------------------
# Uses drand's publicly verifiable randomness beacon as a VRF seed for
# DiscreteGaussianSampler. This makes DP noise generation auditable:
# any verifier can confirm the noise was seeded from the public beacon.
# Reference: drand.love — League of Entropy threshold VRF
# API: https://api.drand.sh/public/{round}
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DrandBeaconEntry:
    """A single drand randomness beacon entry.

    Attributes:
        round_number: Beacon round (monotonically increasing).
        randomness_hex: 64-char hex string — the public randomness.
        signature_hex: BLS12-381 threshold signature.
        previous_sig_hex: Previous round's signature (chain link).
    """

    round_number: int
    randomness_hex: str
    signature_hex: str
    previous_sig_hex: str


class DrandClient:
    """Thin client for the drand League of Entropy randomness beacon.

    Fetches publicly verifiable threshold VRF randomness from the drand
    HTTP API.  The randomness field is a BLS12-381 aggregate signature
    over the round number — verifiable by any party with the chain's
    public key.

    Usage::

        client = DrandClient()
        entry = client.latest()
        seed = client.seed_from_entry(entry)
        sampler = DiscreteGaussianSampler(sigma=1.0, seed=seed)
        noise = sampler.sample_vector(n=10)

    Args:
        chain_hash: drand chain hash (default = unchained mainnet).
        base_url: drand API base URL.
        timeout: HTTP request timeout seconds.
    """

    DEFAULT_BASE_URL = "https://api.drand.sh"
    DEFAULT_CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"

    def __init__(
        self,
        chain_hash: str = DEFAULT_CHAIN,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
    ) -> None:
        if not _DRAND_CHAIN_HASH_RE.match(chain_hash):
            raise ValueError(
                f"chain_hash must be a 64-char lowercase hex string, got {chain_hash!r}"
            )
        if not base_url.startswith("https://"):
            raise ValueError(f"base_url must use HTTPS, got {base_url!r}")
        self._chain = chain_hash
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _fetch(self, round_spec: str) -> DrandBeaconEntry:
        """Fetch a beacon entry by round spec ('latest' or round number)."""
        import urllib.error
        import urllib.request

        url = f"{self._base}/{self._chain}/public/{round_spec}"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
                import json
                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"drand fetch failed for {url}: {exc}") from exc

        return DrandBeaconEntry(
            round_number=int(data["round"]),
            randomness_hex=data["randomness"],
            signature_hex=data.get("signature", ""),
            previous_sig_hex=data.get("previous_signature", ""),
        )

    def latest(self) -> DrandBeaconEntry:
        """Fetch the latest beacon entry."""
        return self._fetch("latest")

    def at_round(self, round_number: int) -> DrandBeaconEntry:
        """Fetch the beacon entry at a specific round."""
        return self._fetch(str(round_number))

    @staticmethod
    def seed_from_entry(entry: DrandBeaconEntry) -> int:
        """Convert a beacon randomness hex string to an integer seed.

        Takes the first 8 bytes of randomness as a big-endian integer.
        This deterministic derivation lets any verifier reproduce the seed.
        """
        raw = bytes.fromhex(entry.randomness_hex[:16])  # first 8 bytes
        return int.from_bytes(raw, byteorder="big")

    def seeded_sampler(
        self,
        sigma: float,
        round_number: int | None = None,
        tail_bound: int | None = None,
    ) -> tuple[DiscreteGaussianSampler, DrandBeaconEntry]:
        """Create a DiscreteGaussianSampler seeded from a drand beacon.

        Args:
            sigma: Noise standard deviation.
            round_number: Specific round (None = latest).
            tail_bound: Truncation bound (None = 6σ).

        Returns:
            (sampler, beacon_entry) — entry for audit/verification.
        """
        entry = self.at_round(round_number) if round_number is not None else self.latest()
        seed = self.seed_from_entry(entry)
        sampler = DiscreteGaussianSampler(sigma=sigma, tail_bound=tail_bound, seed=seed)
        return sampler, entry
