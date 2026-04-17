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

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from constitutional_swarm.merkle_crdt import MerkleCRDT

try:
    import torch
    import torch.nn as nn
    from torch import Tensor
except ImportError as exc:
    raise ImportError("swarm_ode requires torch. Install with: pip install torch>=2.0") from exc


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
        torch.manual_seed(seed)
        self.W = nn.Parameter(torch.randn(n, n) * 0.1)
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
        new_sigma = new_norm**0.5
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
                    constitutional_hash="608508a9bd224290",
                )

        H = projected_rk4_step(
            f,
            H,
            t,
            dt,
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
                constitutional_hash="608508a9bd224290",
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
