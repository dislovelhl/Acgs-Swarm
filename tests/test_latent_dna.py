"""
Tests for LatentDNAWrapper and _BODESHook.

These tests use only torch (no transformers, no GPU, no real model).
They stub the PreTrainedModel interface with minimal nn.Module mocks so the
test suite passes in CI without downloading any model weights.

Marked as optional with pytest.importorskip so the full suite still passes
when torch is not installed.
"""

from __future__ import annotations

import math
import pytest

torch = pytest.importorskip("torch")
import torch.nn as nn
from torch import Tensor

# ──────────────────────────────────────────────────────────────────────────────
# Minimal model stub (no transformers required)
# ──────────────────────────────────────────────────────────────────────────────


class _FakeLayer(nn.Module):
    """Identity layer that returns a (hidden_states, None) tuple."""

    def forward(self, x: Tensor) -> tuple[Tensor, None]:
        return x, None


class _FakeConfig:
    model_type = "llama"


class _FakeModel(nn.Module):
    """Minimal stub that looks enough like a LlamaModel for LatentDNAWrapper."""

    def __init__(self, n_layers: int = 24, hidden_dim: int = 64) -> None:
        super().__init__()
        self.config = _FakeConfig()
        self.model = nn.ModuleNamespace()
        self.model.layers = nn.ModuleList([_FakeLayer() for _ in range(n_layers)])
        self._hidden_dim = hidden_dim

    def forward(self, hidden_states: Tensor) -> tuple[Tensor, None]:
        for layer in self.model.layers:
            hidden_states, _ = layer(hidden_states)
        return hidden_states, None


class nn_ModuleNamespace(nn.Module):
    """Shim: plain nn.Module used as a namespace for .layers attribute."""
    pass


# Patch nn.ModuleNamespace onto nn for the stub above
nn.ModuleNamespace = nn_ModuleNamespace  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────────────
# Import the module under test (skip if torch missing, handled by importorskip)
# ──────────────────────────────────────────────────────────────────────────────


def _make_v_viol(hidden_dim: int = 64, seed: int = 0) -> Tensor:
    """Unit-normalized random violation vector."""
    torch.manual_seed(seed)
    v = torch.randn(hidden_dim)
    return v / v.norm()


def _make_hidden(
    batch: int = 2,
    seq_len: int = 8,
    hidden_dim: int = 64,
    seed: int = 1,
) -> Tensor:
    torch.manual_seed(seed)
    return torch.randn(batch, seq_len, hidden_dim)


# ──────────────────────────────────────────────────────────────────────────────
# _BODESHook unit tests
# ──────────────────────────────────────────────────────────────────────────────


def test_bodes_hook_noop_when_safe() -> None:
    """Hook must NOT modify hidden states when all projections are ≤ threshold."""
    from constitutional_swarm.latent_dna import _BODESHook

    v = _make_v_viol()
    # Set threshold very high so nothing triggers
    hook = _BODESHook(v, threshold=1e9, gamma=1.0)

    hidden = _make_hidden()
    output = (hidden.clone(), None)
    result = hook(module=None, input=(), output=output)

    modified = result[0]
    assert torch.allclose(modified, hidden), "Hook modified safe tokens — should be no-op"
    assert hook.interventions == 0


def test_bodes_hook_steers_violating_tokens() -> None:
    """Hook must reduce projection of violating tokens onto v_viol."""
    from constitutional_swarm.latent_dna import _BODESHook

    hidden_dim = 64
    v = _make_v_viol(hidden_dim)

    # Construct hidden state with large positive projection on v_viol
    # h = 10 * v (projection = 10.0, well above threshold 0.0)
    hidden = (10.0 * v).unsqueeze(0).unsqueeze(0)  # [1, 1, hidden_dim]

    hook = _BODESHook(v, threshold=0.0, gamma=1.0)
    output = (hidden.clone(), None)
    result = hook(module=None, input=(), output=output)

    modified = result[0]
    proj_after = (modified[0, 0] @ v).item()

    # Full orthogonal projection (gamma=1): projection should be ~0
    assert abs(proj_after) < 1e-4, (
        f"After full steering, projection should be ~0, got {proj_after:.6f}"
    )
    assert hook.interventions == 1


def test_bodes_hook_partial_gamma() -> None:
    """gamma=0.5 should reduce projection by 50%."""
    from constitutional_swarm.latent_dna import _BODESHook

    hidden_dim = 64
    v = _make_v_viol(hidden_dim)
    proj_initial = 8.0

    hidden = (proj_initial * v).unsqueeze(0).unsqueeze(0)  # [1, 1, 64]

    hook = _BODESHook(v, threshold=0.0, gamma=0.5)
    output = (hidden.clone(), None)
    result = hook(module=None, input=(), output=output)

    modified = result[0]
    proj_after = (modified[0, 0] @ v).item()

    expected = proj_initial * (1.0 - 0.5)  # = 4.0
    assert abs(proj_after - expected) < 1e-4, (
        f"gamma=0.5 should give proj={expected:.1f}, got {proj_after:.6f}"
    )


def test_bodes_hook_batch_safe() -> None:
    """Hook must process batched input [batch, seq_len, hidden_dim] correctly."""
    from constitutional_swarm.latent_dna import _BODESHook

    hidden_dim = 64
    v = _make_v_viol(hidden_dim)
    hook = _BODESHook(v, threshold=0.0, gamma=1.0)

    # batch=4, seq_len=16 — all tokens have positive projection on v
    batch, seq_len = 4, 16
    hidden = torch.abs(torch.randn(batch, seq_len, hidden_dim))
    # Ensure all projections are positive by adding v component
    hidden = hidden + 2.0 * v.unsqueeze(0).unsqueeze(0)

    proj_before = (hidden @ v)  # [batch, seq_len]
    assert (proj_before > 0).all(), "Test setup: all projections should be positive"

    output = (hidden.clone(), None)
    result = hook(module=None, input=(), output=output)
    modified = result[0]

    proj_after = (modified @ v)  # [batch, seq_len]
    assert (proj_after <= 1e-3).all(), (
        "After full steering, all projections should be ≤ 0"
    )
    assert hook.total_tokens == batch * seq_len


def test_bodes_hook_rejects_unnormalized_vector() -> None:
    """Hook init must reject un-normalized v_viol."""
    from constitutional_swarm.latent_dna import _BODESHook

    v = torch.randn(64)  # NOT normalized
    with pytest.raises(ValueError, match="unit-normalized"):
        _BODESHook(v)


def test_bodes_hook_rejects_2d_vector() -> None:
    """Hook init must reject 2D input."""
    from constitutional_swarm.latent_dna import _BODESHook

    v = torch.randn(4, 64)
    with pytest.raises(ValueError, match="1D"):
        _BODESHook(v)


# ──────────────────────────────────────────────────────────────────────────────
# LatentDNAWrapper integration tests
# ──────────────────────────────────────────────────────────────────────────────


def test_wrapper_enable_disable() -> None:
    """enable/disable must register and remove the hook."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    v = _make_v_viol()
    wrapper = LatentDNAWrapper(model, v, layer_idx=15)

    assert not wrapper.enabled
    wrapper.enable()
    assert wrapper.enabled
    wrapper.disable()
    assert not wrapper.enabled


def test_wrapper_context_manager() -> None:
    """Context manager must enable on enter and disable on exit."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    v = _make_v_viol()
    wrapper = LatentDNAWrapper(model, v, layer_idx=10)

    with wrapper:
        assert wrapper.enabled
    assert not wrapper.enabled


def test_wrapper_idempotent_enable() -> None:
    """Calling enable() twice must not raise or double-register."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    v = _make_v_viol()
    wrapper = LatentDNAWrapper(model, v, layer_idx=5)

    wrapper.enable()
    wrapper.enable()  # Should not raise
    assert wrapper.enabled
    wrapper.disable()


def test_wrapper_intervention_stats() -> None:
    """intervention_stats must return accurate counts after a forward pass."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    hidden_dim = 64
    model = _FakeModel(hidden_dim=hidden_dim)
    v = _make_v_viol(hidden_dim)
    wrapper = LatentDNAWrapper(model, v, layer_idx=0, threshold=0.0, gamma=1.0)

    batch, seq_len = 2, 8
    x = torch.randn(batch, seq_len, hidden_dim)

    with wrapper:
        model(x)

    stats = wrapper.intervention_stats()
    assert stats["total_tokens"] == batch * seq_len
    assert "steered_tokens" in stats
    assert "intervention_rate" in stats
    assert 0.0 <= stats["intervention_rate"] <= 1.0


def test_wrapper_layer_idx_out_of_range() -> None:
    """Wrapper must raise IndexError for layer_idx beyond model depth."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel(n_layers=24)
    v = _make_v_viol()
    with pytest.raises(IndexError, match="out of range"):
        LatentDNAWrapper(model, v, layer_idx=99)


def test_wrapper_unknown_architecture_raises() -> None:
    """Wrapper must raise ValueError for unrecognized model_type without explicit path."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    model.config.model_type = "totally_unknown_arch"
    v = _make_v_viol()
    with pytest.raises(ValueError, match="Cannot auto-detect"):
        LatentDNAWrapper(model, v, layer_idx=0)


def test_wrapper_explicit_layer_path() -> None:
    """Wrapper must accept explicit layer_attr_path for unknown architectures."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    model.config.model_type = "custom_arch"
    v = _make_v_viol()
    # Should not raise
    wrapper = LatentDNAWrapper(model, v, layer_idx=5, layer_attr_path="model.layers")
    assert not wrapper.enabled
