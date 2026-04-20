"""
Tests for ``_BODESSubspaceHook`` and ``LatentDNAWrapper(subspace=...)`` —
the Phase 7.4 activation that wires ``ViolationSubspace`` into the torch
forward-hook path.

The tests use a tiny identity-layer stub so no HuggingFace weights are
downloaded. Skipped cleanly when torch is not present.
"""

from __future__ import annotations

import numpy as np
import pytest

torch = pytest.importorskip("torch")
import torch.nn as nn
from constitutional_swarm.latent_dna import (
    LatentDNAWrapper,
    _BODESHook,
    _BODESSubspaceHook,
)
from constitutional_swarm.violation_subspace import ViolationSubspace
from torch import Tensor

# ── Minimal stubs (mirror tests/test_latent_dna.py) ────────────────────────


class _FakeLayer(nn.Module):
    def forward(self, x: Tensor) -> tuple[Tensor, None]:
        return x, None


class _FakeConfig:
    model_type = "llama"


class _NS(nn.Module):
    """nn.Module used as namespace for `.layers`."""


class _FakeModel(nn.Module):
    def __init__(self, n_layers: int = 4, hidden_dim: int = 8) -> None:
        super().__init__()
        self.config = _FakeConfig()
        self.model = _NS()
        self.model.layers = nn.ModuleList([_FakeLayer() for _ in range(n_layers)])
        self.hidden_dim = hidden_dim


# ── Helpers ────────────────────────────────────────────────────────────────


def _rank1_subspace(dim: int, direction_idx: int = 0) -> ViolationSubspace:
    """Single-direction subspace aligned with a standard basis axis, mean 0."""
    basis = np.zeros((1, dim))
    basis[0, direction_idx] = 1.0
    mean = np.zeros(dim)
    return ViolationSubspace(basis=basis, mean=mean)


def _rankk_subspace(dim: int, k: int = 2) -> ViolationSubspace:
    basis = np.zeros((k, dim))
    for i in range(k):
        basis[i, i] = 1.0
    mean = np.zeros(dim)
    return ViolationSubspace(basis=basis, mean=mean)


# ── _BODESSubspaceHook standalone ──────────────────────────────────────────


class TestSubspaceHookConstruction:
    def test_rejects_non_subspace(self) -> None:
        with pytest.raises(TypeError):
            _BODESSubspaceHook("not a subspace")  # type: ignore[arg-type]

    def test_accepts_leace_subspace(self) -> None:
        """Phase 10: LEACE subspaces are now supported (was NotImplementedError)."""
        d = 4
        basis = np.eye(1, d)
        mean = np.zeros(d)
        W = np.eye(d)
        sub = ViolationSubspace(basis=basis, mean=mean, whitener=W, dewhitener=W)
        hook = _BODESSubspaceHook(sub)
        assert hook.is_leace
        assert hook.whitener is not None
        assert hook.dewhitener is not None

    def test_rejects_invalid_gamma(self) -> None:
        sub = _rank1_subspace(8)
        with pytest.raises(ValueError):
            _BODESSubspaceHook(sub, gamma=0.0)
        with pytest.raises(ValueError):
            _BODESSubspaceHook(sub, gamma=1.5)

    def test_metadata(self) -> None:
        sub = _rankk_subspace(8, k=3)
        hook = _BODESSubspaceHook(sub, threshold=0.1, gamma=0.5)
        assert hook.rank == 3
        assert hook.dim == 8
        assert hook.threshold == 0.1
        assert hook.gamma == 0.5
        assert hook.interventions == 0
        assert hook.total_tokens == 0


class TestSubspaceHookSteering:
    def test_no_steering_below_threshold(self) -> None:
        """Tokens with all coords ≤ τ pass through untouched."""
        sub = _rank1_subspace(4)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        # Negative projection along axis 0 → below threshold
        hidden = torch.tensor([[[-1.0, 2.0, 3.0, 4.0]]])  # [1, 1, 4]
        out = hook(nn.Identity(), (), hidden)
        assert torch.allclose(out, hidden)
        assert hook.interventions == 0
        assert hook.total_tokens == 1

    def test_steers_positive_projection(self) -> None:
        """Tokens with positive projection get the offending component zeroed (γ=1)."""
        sub = _rank1_subspace(4)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        hidden = torch.tensor([[[5.0, 2.0, 3.0, 4.0]]])
        out = hook(nn.Identity(), (), hidden)
        # Axis-0 coord zeroed; other axes unchanged.
        assert torch.allclose(out, torch.tensor([[[0.0, 2.0, 3.0, 4.0]]]))
        assert hook.interventions == 1

    def test_partial_gamma_attenuates(self) -> None:
        sub = _rank1_subspace(4)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=0.5)
        hidden = torch.tensor([[[4.0, 0.0, 0.0, 0.0]]])
        out = hook(nn.Identity(), (), hidden)
        # h' = h - 0.5 * 4 * e0 = [2, 0, 0, 0]
        assert torch.allclose(out, torch.tensor([[[2.0, 0.0, 0.0, 0.0]]]))

    def test_rank1_matches_legacy_hook(self) -> None:
        """Rank-1 subspace (zero mean, unit axis) must match _BODESHook output."""
        d = 6
        v = torch.zeros(d)
        v[2] = 1.0
        legacy = _BODESHook(v, threshold=0.0, gamma=0.7)
        sub = _rank1_subspace(d, direction_idx=2)
        new = _BODESSubspaceHook(sub, threshold=0.0, gamma=0.7)

        torch.manual_seed(7)
        hidden = torch.randn(2, 3, d)

        out_legacy = legacy(nn.Identity(), (), hidden.clone())
        out_new = new(nn.Identity(), (), hidden.clone())
        assert torch.allclose(out_legacy, out_new, atol=1e-5)

    def test_rankk_steers_multiple_directions(self) -> None:
        sub = _rankk_subspace(4, k=2)  # axes 0 and 1
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        # Token 1: positive on axis 0 only. Token 2: positive on both 0 and 1.
        hidden = torch.tensor([[
            [3.0, -1.0, 2.0, 5.0],
            [4.0,  2.0, 7.0, 1.0],
        ]])
        out = hook(nn.Identity(), (), hidden)
        # Token 1: only axis 0 zeroed; axis 1 untouched (was negative).
        assert torch.allclose(out[0, 0], torch.tensor([0.0, -1.0, 2.0, 5.0]))
        # Token 2: both axes 0 and 1 zeroed.
        assert torch.allclose(out[0, 1], torch.tensor([0.0, 0.0, 7.0, 1.0]))
        assert hook.interventions == 2

    def test_mean_offset_is_respected(self) -> None:
        """Non-zero subspace mean shifts the threshold decision."""
        dim = 4
        mean = np.array([10.0, 0.0, 0.0, 0.0])
        basis = np.zeros((1, dim))
        basis[0, 0] = 1.0
        sub = ViolationSubspace(basis=basis, mean=mean)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)

        # coord = (h - mean) · e0 = h[0] - 10
        # Token A: h[0] = 5 → coord = -5 ≤ 0 → no steer
        # Token B: h[0] = 15 → coord = +5 > 0 → steer, delta = 5 * e0
        hidden = torch.tensor([[[5.0, 1.0, 1.0, 1.0], [15.0, 1.0, 1.0, 1.0]]])
        out = hook(nn.Identity(), (), hidden)
        assert torch.allclose(out[0, 0], torch.tensor([5.0, 1.0, 1.0, 1.0]))
        assert torch.allclose(out[0, 1], torch.tensor([10.0, 1.0, 1.0, 1.0]))
        assert hook.interventions == 1

    def test_threshold_margin(self) -> None:
        sub = _rank1_subspace(3)
        hook = _BODESSubspaceHook(sub, threshold=2.0, gamma=1.0)
        # coord=1 is below τ=2 → no steer; coord=3 is above → steer
        hidden = torch.tensor([[[1.0, 0.0, 0.0], [3.0, 0.0, 0.0]]])
        out = hook(nn.Identity(), (), hidden)
        assert torch.allclose(out[0, 0], torch.tensor([1.0, 0.0, 0.0]))
        # delta = gamma * (coord) * e0 = 1.0 * 3.0 = 3  → 3 - 3 = 0
        assert torch.allclose(out[0, 1], torch.tensor([0.0, 0.0, 0.0]))

    def test_tuple_output_preserved(self) -> None:
        sub = _rank1_subspace(3)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        hidden = torch.tensor([[[5.0, 0.0, 0.0]]])
        extra = torch.tensor([42])
        out = hook(nn.Identity(), (), (hidden, extra))
        assert isinstance(out, tuple)
        assert len(out) == 2
        assert out[1] is extra

    def test_shape_mismatch_fails_open(self) -> None:
        """Dim mismatch should not raise — hook returns output unchanged."""
        sub = _rank1_subspace(4)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        # hidden has hidden_dim=5 ≠ subspace dim=4
        hidden = torch.zeros(1, 2, 5)
        out = hook(nn.Identity(), (), hidden)
        assert out is hidden  # pass-through
        # total_tokens still incremented
        assert hook.total_tokens == 2
        assert hook.interventions == 0

    def test_dtype_device_robust(self) -> None:
        """Runs on float32 and float64 hidden states without error."""
        sub = _rank1_subspace(4)
        hook = _BODESSubspaceHook(sub)
        for dtype in (torch.float32, torch.float64):
            hidden = torch.tensor([[[2.0, 0.0, 0.0, 0.0]]], dtype=dtype)
            out = hook(nn.Identity(), (), hidden)
            assert out.dtype == dtype


# ── LatentDNAWrapper integration ───────────────────────────────────────────


class TestWrapperSubspaceIntegration:
    def test_rejects_both_v_viol_and_subspace(self) -> None:
        model = _FakeModel(n_layers=2, hidden_dim=4)
        v = torch.tensor([1.0, 0.0, 0.0, 0.0])
        sub = _rank1_subspace(4)
        with pytest.raises(ValueError):
            LatentDNAWrapper(model, v_viol=v, layer_idx=0, subspace=sub)

    def test_rejects_neither(self) -> None:
        model = _FakeModel(n_layers=2, hidden_dim=4)
        with pytest.raises(ValueError):
            LatentDNAWrapper(model, layer_idx=0)

    def test_subspace_path_builds_subspace_hook(self) -> None:
        model = _FakeModel(n_layers=2, hidden_dim=4)
        sub = _rankk_subspace(4, k=2)
        wrapper = LatentDNAWrapper(model, subspace=sub, layer_idx=0, gamma=0.5)
        assert isinstance(wrapper._hook_impl, _BODESSubspaceHook)
        assert wrapper._hook_impl.rank == 2

    def test_v_viol_path_still_uses_legacy_hook(self) -> None:
        model = _FakeModel(n_layers=2, hidden_dim=4)
        v = torch.tensor([1.0, 0.0, 0.0, 0.0])
        wrapper = LatentDNAWrapper(model, v_viol=v, layer_idx=0)
        assert isinstance(wrapper._hook_impl, _BODESHook)

    def test_intervention_stats_work_with_subspace_hook(self) -> None:
        model = _FakeModel(n_layers=2, hidden_dim=4)
        sub = _rank1_subspace(4)
        wrapper = LatentDNAWrapper(model, subspace=sub, layer_idx=0)
        stats = wrapper.intervention_stats()
        # Keys expected by existing callers must all be present.
        assert set(stats) >= {
            "total_tokens", "steered_tokens", "intervention_rate",
            "layer_idx", "threshold", "gamma",
        }

    def test_end_to_end_steering_through_wrapper(self) -> None:
        """Enable wrapper, run a forward pass, confirm steering took effect."""
        model = _FakeModel(n_layers=2, hidden_dim=4)
        sub = _rank1_subspace(4)
        wrapper = LatentDNAWrapper(model, subspace=sub, layer_idx=0, gamma=1.0)

        # positive coord on axis 0 — should be zeroed
        hidden = torch.tensor([[[5.0, 1.0, 2.0, 3.0]]])
        with wrapper:
            out, _ = model.model.layers[0](hidden)
            # forward-hook applies after layer's forward completes via
            # registered hook, so re-run through the hook path manually:
            # we validate via intervention_stats instead.
        # The hook fires on layer 0 only. Simulate by running layer 0 with hook enabled.
        wrapper.enable()
        out, _ = model.model.layers[0](hidden)
        wrapper.disable()
        # After steering, axis-0 component should be gone.
        assert torch.allclose(out[0, 0], torch.tensor([0.0, 1.0, 2.0, 3.0]))
        assert wrapper._hook_impl.interventions >= 1
