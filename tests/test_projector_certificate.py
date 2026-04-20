"""Phase 7.3 — Projector certificate for the BODES latent steering hook.

The hook claims that after steering with strength ``gamma`` against a unit
violation vector ``v_viol`` and threshold ``tau``, the post-steering hidden
state ``h'`` satisfies the closed-form bound::

    h' · v_viol  <=  max(tau, (1 - gamma) * (h · v_viol))

This module turns that claim into machine-checked property tests. The
bound is the formal safety property referenced in Phase 7.3 of the
breakthrough plan; together with ``specs/mesh.tla`` and
``specs/constitution_reconfig.tla`` it replaces the previously vague
"latent steering keeps h in the safe set" language with a calculable
certificate.

The tests are pure-torch and do not require HuggingFace transformers.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from constitutional_swarm.latent_dna import _BODESHook


def _random_unit(dim: int, seed: int) -> torch.Tensor:
    gen = torch.Generator().manual_seed(seed)
    v = torch.randn(dim, generator=gen)
    return v / v.norm()


def _run_hook(hidden: torch.Tensor, v: torch.Tensor, gamma: float, tau: float) -> torch.Tensor:
    hook = _BODESHook(v_viol=v, threshold=tau, gamma=gamma)
    return hook(module=None, input=(), output=hidden)


class TestProjectorCertificate:
    """|h'·v| must obey the closed-form bound for every token."""

    @pytest.mark.parametrize("gamma", [1.0, 0.75, 0.5, 0.25])
    def test_above_threshold_bound_is_tight(self, gamma: float) -> None:
        dim = 64
        v = _random_unit(dim, seed=17)

        # Construct a hidden state with a deliberately large positive
        # projection onto v_viol.
        gen = torch.Generator().manual_seed(42)
        hidden = torch.randn(2, 5, dim, generator=gen)
        hidden = hidden + 3.0 * v.view(1, 1, dim)  # force proj > 0

        before = hidden @ v
        tau = 0.0
        out = _run_hook(hidden.clone(), v, gamma=gamma, tau=tau)
        after = out @ v

        # All tokens here are above threshold (proj ≈ before > 0).
        expected = (1.0 - gamma) * before

        # The steered projection equals (1-gamma)*before above threshold.
        torch.testing.assert_close(after, expected, rtol=1e-5, atol=1e-5)

        # And the certificate bound holds: after ≤ max(tau, (1-γ)·before).
        bound = torch.maximum(torch.full_like(before, tau), expected)
        assert torch.all(after <= bound + 1e-5)

    def test_below_threshold_pass_through(self) -> None:
        dim = 32
        v = _random_unit(dim, seed=5)

        # Construct hidden states with projection strictly below tau.
        gen = torch.Generator().manual_seed(3)
        hidden = torch.randn(1, 4, dim, generator=gen)
        # Push onto the negative side of v.
        hidden = hidden - 5.0 * v.view(1, 1, dim)
        tau = 0.0

        before = hidden @ v
        assert torch.all(before <= tau)  # precondition

        out = _run_hook(hidden.clone(), v, gamma=0.9, tau=tau)
        after = out @ v

        # No steering should have occurred.
        torch.testing.assert_close(after, before, rtol=0.0, atol=0.0)

    @pytest.mark.parametrize("seed", range(10))
    def test_random_activations_satisfy_bound(self, seed: int) -> None:
        """Fuzz: for random hidden states, the certificate always holds."""
        dim = 48
        v = _random_unit(dim, seed=seed * 7 + 1)
        gamma = 0.6
        tau = 0.1

        gen = torch.Generator().manual_seed(seed)
        hidden = torch.randn(3, 6, dim, generator=gen) * 2.0

        before = hidden @ v
        out = _run_hook(hidden.clone(), v, gamma=gamma, tau=tau)
        after = out @ v

        # Certificate: after ≤ max(tau, (1-gamma)*before)
        #   above threshold: after = (1-γ)·before; below: after = before ≤ τ.
        tau_t = torch.full_like(before, tau)
        bound = torch.maximum(tau_t, (1.0 - gamma) * before)
        violations = after - bound
        assert torch.all(violations <= 1e-5), (
            f"projector certificate violated: max violation={violations.max().item():.2e}"
        )

    def test_safe_set_invariance(self) -> None:
        """Once steered, a second pass should not move h further."""
        dim = 24
        v = _random_unit(dim, seed=11)
        gamma = 1.0  # full orthogonal projection
        tau = 0.0

        gen = torch.Generator().manual_seed(99)
        hidden = torch.randn(2, 3, dim, generator=gen) + 2.0 * v.view(1, 1, dim)

        once = _run_hook(hidden.clone(), v, gamma=gamma, tau=tau)
        twice = _run_hook(once.clone(), v, gamma=gamma, tau=tau)

        # After full projection, h·v ≈ 0; a second projection is a no-op.
        torch.testing.assert_close(once, twice, rtol=1e-5, atol=1e-5)

        # And the projection is ≤ 0 (in the safe set).
        assert torch.all((once @ v) <= tau + 1e-5)

    def test_orthogonal_component_preserved(self) -> None:
        """Steering only moves h along v_viol; orthogonal components invariant."""
        dim = 40
        v = _random_unit(dim, seed=23)
        gamma = 0.5
        tau = 0.0

        gen = torch.Generator().manual_seed(7)
        hidden = torch.randn(1, 2, dim, generator=gen) + v.view(1, 1, dim)

        # Orthogonal complement projector: P_perp = I - v vᵀ
        before_perp = hidden - (hidden @ v).unsqueeze(-1) * v.view(1, 1, dim)

        out = _run_hook(hidden.clone(), v, gamma=gamma, tau=tau)
        after_perp = out - (out @ v).unsqueeze(-1) * v.view(1, 1, dim)

        torch.testing.assert_close(before_perp, after_perp, rtol=1e-5, atol=1e-5)
