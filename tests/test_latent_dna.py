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


# ──────────────────────────────────────────────────────────────────────────────
# Contrastive PCA extraction tests
# ──────────────────────────────────────────────────────────────────────────────


def _collect_activations(
    model: _FakeModel, inputs: list[Tensor], layer_idx: int
) -> Tensor:
    """Helper: collect mean-pooled activations at a layer for a batch of inputs."""
    target = model.model.layers[layer_idx]
    acts: list[Tensor] = []

    def _hook(mod: nn.Module, inp: tuple, out: tuple) -> None:
        h = out[0] if isinstance(out, tuple) else out
        acts.append(h.mean(dim=1).detach().cpu())

    handle = target.register_forward_hook(_hook)
    try:
        model.eval()
        with torch.no_grad():
            for x in inputs:
                acts.clear()
                model(x)
                # Only keep last
    finally:
        handle.remove()
    return acts[-1] if acts else torch.empty(0)


def test_pca_extracts_unit_vector() -> None:
    """PCA extraction must return a unit-normalized 1D vector."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    hidden_dim = 64
    model = _FakeModel(n_layers=24, hidden_dim=hidden_dim)
    torch.manual_seed(99)

    n_pairs = 10
    # Simulate contrastive pairs: safe inputs are random, unsafe shift along a known direction
    known_direction = torch.randn(hidden_dim)
    known_direction = known_direction / known_direction.norm()

    safe_inputs = [torch.randn(1, 4, hidden_dim) for _ in range(n_pairs)]
    unsafe_inputs = [s + 5.0 * known_direction for s in safe_inputs]

    # Wrap inputs as dicts with 'hidden_states' key — but our _FakeModel takes positional
    # We need to use the actual wrapper infrastructure, so wrap as kwargs the model accepts
    # The extract_violation_vector_pca calls model(**inp), so we need dict-like inputs.
    # Our _FakeModel.forward takes hidden_states as positional. Wrap as dict.
    safe_dicts = [{"hidden_states": s} for s in safe_inputs]
    unsafe_dicts = [{"hidden_states": u} for u in unsafe_inputs]

    v = LatentDNAWrapper.extract_violation_vector_pca(
        model, safe_dicts, unsafe_dicts,
        layer_idx=0,
        layer_attr_path="model.layers",
    )

    assert v.dim() == 1
    assert v.shape[0] == hidden_dim
    norm = v.norm().item()
    assert abs(norm - 1.0) < 1e-4, f"v_viol should be unit-normalized, got ‖v‖={norm}"


def test_pca_multi_component() -> None:
    """n_components > 1 must return [n_components, hidden_dim] matrix."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    hidden_dim = 64
    model = _FakeModel(n_layers=24, hidden_dim=hidden_dim)
    torch.manual_seed(42)

    n_pairs = 20
    safe_inputs = [torch.randn(1, 4, hidden_dim) for _ in range(n_pairs)]
    unsafe_inputs = [s + torch.randn(1, 1, hidden_dim) for s in safe_inputs]

    safe_dicts = [{"hidden_states": s} for s in safe_inputs]
    unsafe_dicts = [{"hidden_states": u} for u in unsafe_inputs]

    components = LatentDNAWrapper.extract_violation_vector_pca(
        model, safe_dicts, unsafe_dicts,
        layer_idx=0,
        layer_attr_path="model.layers",
        n_components=3,
    )

    assert components.shape == (3, hidden_dim)
    # Each row should be unit-normalized
    for i in range(3):
        norm = components[i].norm().item()
        assert abs(norm - 1.0) < 1e-4, f"Component {i} ‖v‖={norm}"


def test_pca_rejects_unpaired_inputs() -> None:
    """PCA must raise ValueError if safe and unsafe lists differ in length."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    with pytest.raises(ValueError, match="paired"):
        LatentDNAWrapper.extract_violation_vector_pca(
            model,
            [{"hidden_states": torch.randn(1, 4, 64)}] * 5,
            [{"hidden_states": torch.randn(1, 4, 64)}] * 3,
            layer_idx=0,
            layer_attr_path="model.layers",
        )


def test_pca_rejects_single_pair() -> None:
    """PCA needs at least 2 pairs for meaningful variance computation."""
    from constitutional_swarm.latent_dna import LatentDNAWrapper

    model = _FakeModel()
    with pytest.raises(ValueError, match="at least 2"):
        LatentDNAWrapper.extract_violation_vector_pca(
            model,
            [{"hidden_states": torch.randn(1, 4, 64)}],
            [{"hidden_states": torch.randn(1, 4, 64)}],
            layer_idx=0,
            layer_attr_path="model.layers",
        )
