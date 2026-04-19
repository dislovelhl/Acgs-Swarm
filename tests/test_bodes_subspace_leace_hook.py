"""Phase 10 — LEACE-whitened subspace steering in the torch hook.

Validates that :class:`_BODESSubspaceHook` correctly handles
``ViolationSubspace`` instances in LEACE mode (``is_leace=True``) by
comparing its forward-pass output against the pure-numpy reference
:meth:`ViolationSubspace.steer`.
"""

from __future__ import annotations

import numpy as np
import torch
from constitutional_swarm.latent_dna import _BODESSubspaceHook
from constitutional_swarm.violation_subspace import ViolationSubspace


def _identity_leace(dim: int) -> ViolationSubspace:
    """Construct a LEACE subspace whose whitener is the identity.

    With W = I, LEACE output must equal the plain-orthogonal output
    (the whitening is a no-op). This is the canonical first-check —
    any LEACE math bug makes this test fail.
    """
    basis = np.eye(dim, dtype=np.float64)[:1]  # rank-1 axis-aligned
    mean = np.zeros(dim, dtype=np.float64)
    W = np.eye(dim, dtype=np.float64)
    return ViolationSubspace(
        basis=basis, mean=mean, whitener=W, dewhitener=W.copy()
    )


def _diag_leace(dim: int, scales: np.ndarray) -> ViolationSubspace:
    """LEACE subspace with a diagonal whitener (each dim scaled independently).

    Real LEACE whiteners are full PSD square roots, but a diagonal
    whitener is enough to exercise the whitener/dewhitener round-trip
    separately from mean/basis logic. Each ``scales[i]`` scales axis i
    under whitening; dewhiten uses ``1/scales``.
    """
    basis = np.eye(dim, dtype=np.float64)[:1]
    mean = np.zeros(dim, dtype=np.float64)
    W = np.diag(scales).astype(np.float64)
    Winv = np.diag(1.0 / scales).astype(np.float64)
    return ViolationSubspace(
        basis=basis, mean=mean, whitener=W, dewhitener=Winv
    )


class TestLeaceHookConstruction:
    def test_leace_subspace_accepted(self):
        """LEACE subspace must no longer be rejected at construction."""
        sub = _identity_leace(dim=4)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        assert hook.is_leace
        assert hook.whitener is not None
        assert hook.dewhitener is not None

    def test_non_leace_flag_is_false(self):
        basis = np.eye(4, dtype=np.float64)[:1]
        mean = np.zeros(4, dtype=np.float64)
        sub = ViolationSubspace(basis=basis, mean=mean)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        assert not hook.is_leace
        assert hook.whitener is None
        assert hook.dewhitener is None


class TestLeaceMatchesNumpyReference:
    """Torch hook must match :meth:`ViolationSubspace.steer` byte-for-byte.

    Reference path (numpy, from ``ViolationSubspace.steer`` with default
    ``tau=0``, identical to ``threshold=0.0`` in the hook):
      centered = h - mean
      centered_w = centered @ W.T
      coords = centered_w @ basis.T
      active = max(coords - 0, 0)  # == max(coords, 0)
      bad = (active @ basis) @ Winv.T
      return h - gamma * bad
    """

    def test_identity_whitener_matches_plain_subspace(self):
        """W = I ⇒ LEACE output = plain orthogonal output for same basis."""
        dim = 4
        hook_leace = _BODESSubspaceHook(_identity_leace(dim), gamma=1.0)
        basis = np.eye(dim, dtype=np.float64)[:1]
        mean = np.zeros(dim, dtype=np.float64)
        plain = ViolationSubspace(basis=basis, mean=mean)
        hook_plain = _BODESSubspaceHook(plain, gamma=1.0)

        hidden = torch.tensor([[[1.0, 0.0, 0.0, 0.0]]])
        out_leace = hook_leace(None, (), hidden)
        out_plain = hook_plain(None, (), hidden)
        assert torch.allclose(out_leace, out_plain, atol=1e-6)

    def test_diag_whitener_matches_numpy_steer(self):
        """Non-trivial diagonal whitener — hook must match ``steer()``."""
        dim = 4
        scales = np.array([2.0, 1.0, 1.0, 1.0])  # stretch axis 0 under whitening
        sub = _diag_leace(dim, scales)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=0.8)

        # Above threshold along axis 0 after whitening.
        hidden_np = np.array([[[1.5, 0.0, 0.0, 0.0]]], dtype=np.float64)
        hidden = torch.from_numpy(hidden_np).to(torch.float32)
        out = hook(None, (), hidden).cpu().numpy().astype(np.float64)

        expected = sub.steer(hidden_np, gamma=0.8, tau=0.0)
        assert np.allclose(out, expected, atol=1e-4)

    def test_below_threshold_passes_through(self):
        """Negative whitened coordinate ⇒ no-op."""
        dim = 4
        sub = _diag_leace(dim, np.array([2.0, 1.0, 1.0, 1.0]))
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)

        hidden_np = np.array([[[-0.5, 0.1, 0.0, 0.0]]], dtype=np.float64)
        hidden = torch.from_numpy(hidden_np).to(torch.float32)
        out = hook(None, (), hidden).cpu().numpy().astype(np.float64)

        # coords = (-0.5*2) = -1.0 < 0 ⇒ no steering
        assert np.allclose(out, hidden_np, atol=1e-6)

    def test_leace_with_nonzero_mean(self):
        """Mean offset must be applied before whitening."""
        dim = 4
        basis = np.eye(dim, dtype=np.float64)[:1]
        mean = np.array([0.3, -0.2, 0.0, 0.0], dtype=np.float64)
        W = np.diag([1.5, 1.0, 1.0, 1.0]).astype(np.float64)
        Winv = np.diag([1.0 / 1.5, 1.0, 1.0, 1.0]).astype(np.float64)
        sub = ViolationSubspace(basis=basis, mean=mean, whitener=W, dewhitener=Winv)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=0.5)

        hidden_np = np.array([[[1.0, 0.0, 0.0, 0.0]]], dtype=np.float64)
        hidden = torch.from_numpy(hidden_np).to(torch.float32)
        out = hook(None, (), hidden).cpu().numpy().astype(np.float64)

        expected = sub.steer(hidden_np, gamma=0.5, tau=0.0)
        assert np.allclose(out, expected, atol=1e-4)

    def test_leace_threshold_margin(self):
        """Threshold τ > 0 gates steering on whitened coords."""
        dim = 4
        sub = _diag_leace(dim, np.array([1.0, 1.0, 1.0, 1.0]))  # identity-like
        # Whitened coord = 0.5; threshold 1.0 ⇒ below margin, no steer.
        hook = _BODESSubspaceHook(sub, threshold=1.0, gamma=1.0)
        hidden_np = np.array([[[0.5, 0.0, 0.0, 0.0]]], dtype=np.float64)
        hidden = torch.from_numpy(hidden_np).to(torch.float32)
        out = hook(None, (), hidden).cpu().numpy().astype(np.float64)
        assert np.allclose(out, hidden_np, atol=1e-6)
        assert hook.interventions == 0


class TestLeaceHookStats:
    def test_intervention_counter_increments_in_leace_mode(self):
        dim = 4
        sub = _diag_leace(dim, np.array([2.0, 1.0, 1.0, 1.0]))
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        hidden = torch.tensor([[[1.0, 0.0, 0.0, 0.0], [-1.0, 0.0, 0.0, 0.0]]])
        hook(None, (), hidden)
        # Token 0 has whitened coord 2.0 > 0 ⇒ intervened.
        # Token 1 has whitened coord -2.0 ⇒ skipped.
        assert hook.interventions == 1
        assert hook.total_tokens == 2

    def test_leace_tuple_output_preserved(self):
        dim = 4
        sub = _identity_leace(dim)
        hook = _BODESSubspaceHook(sub, threshold=0.0, gamma=1.0)
        hidden = torch.tensor([[[1.0, 0.0, 0.0, 0.0]]])
        out = hook(None, (), (hidden, "aux"))
        assert isinstance(out, tuple)
        assert len(out) == 2
        assert out[1] == "aux"
