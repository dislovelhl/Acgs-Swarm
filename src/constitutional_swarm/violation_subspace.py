"""LEACE-style violation subspace for constitutional steering.

Phase 7.4 breakthrough: the existing ``_BODESHook`` steers hidden
states along a single violation direction ``v_viol``. Real violation
concepts live on a **subspace**, not a single axis — jailbreak
activations, deceptive activations, and policy-bypass activations are
all correlated-but-distinct modes that a rank-1 projector misses.

This module introduces:

- :class:`ViolationSubspace` — an orthonormal rank-k basis plus an
  optional LEACE whitening. Generalizes ``v_viol`` to any rank ``k``.
- :func:`fit_subspace` — learn a subspace from labeled safe/unsafe
  hidden-state samples via truncated SVD of contrastive differences.
- :func:`fit_leace` — LEACE-style oblique projection that erases
  *linear predictability* of the label from hidden states while
  preserving all orthogonal information (Belrose et al. 2023).
- :class:`RiskAdaptiveSteering` — subspace analog of BODES steering:
  given ``h`` and a safety margin τ, steer only the components that
  push ``h`` into the violation cone, with a per-component γ decay.
- :func:`adversarial_score` — unit-free eval metric: fraction of
  held-out unsafe activations that remain in the violation subspace
  after projection (lower is better).

The implementation is pure NumPy so it can run in CI without torch.
The Torch bridge (apply to a ``Tensor``) is a one-liner available via
:meth:`ViolationSubspace.apply_numpy` — caller converts.

References
----------
- Belrose et al. (2023) "LEACE: Perfect linear concept erasure in closed form"
- Zou et al. (2025) "Representation Engineering" (RepE) — contrastive PCA
- Ravfogel et al. (2022) "Linear adversarial concept erasure"
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

__all__ = [
    "DimensionMismatchError",
    "InsufficientSamplesError",
    "RiskAdaptiveSteering",
    "ViolationSubspace",
    "adversarial_score",
    "fit_leace",
    "fit_subspace",
]


class InsufficientSamplesError(ValueError):
    """Raised when sample count is too low to fit a stable subspace."""


class DimensionMismatchError(ValueError):
    """Raised when hidden-state dimensions disagree across samples."""


@dataclass(frozen=True)
class ViolationSubspace:
    """An orthonormal rank-``k`` violation subspace with optional LEACE whitening.

    Attributes
    ----------
    basis:
        ``(k, d)`` matrix whose rows are orthonormal directions spanning
        the violation subspace. Rank-1 with a unit row recovers the
        current ``v_viol`` behavior exactly.
    mean:
        ``(d,)`` centering vector (pooled mean of the training
        activations). LEACE projection is affine around this mean.
    whitener:
        Optional ``(d, d)`` whitening matrix. If ``None``, this is a
        plain orthogonal subspace (the RepE / mean-diff regime). If
        set, the steering is LEACE-style oblique projection.
    dewhitener:
        Inverse of ``whitener`` (``(d, d)``). Must be supplied iff
        ``whitener`` is supplied.
    """

    basis: np.ndarray
    mean: np.ndarray
    whitener: np.ndarray | None = None
    dewhitener: np.ndarray | None = None

    def __post_init__(self) -> None:
        if self.basis.ndim != 2:
            raise DimensionMismatchError(f"basis must be 2D (k, d), got shape {self.basis.shape}")
        if self.mean.ndim != 1 or self.mean.shape[0] != self.basis.shape[1]:
            raise DimensionMismatchError(
                f"mean shape {self.mean.shape} incompatible with basis "
                f"columns {self.basis.shape[1]}"
            )
        if (self.whitener is None) != (self.dewhitener is None):
            raise ValueError("whitener and dewhitener must be supplied together")
        if self.whitener is not None:
            d = self.basis.shape[1]
            if self.whitener.shape != (d, d) or self.dewhitener.shape != (d, d):  # type: ignore[union-attr]
                raise DimensionMismatchError(
                    f"whitener must be ({d}, {d}), got {self.whitener.shape}"
                )
        # Verify orthonormality within tolerance — catch caller bugs early
        g = self.basis @ self.basis.T
        if not np.allclose(g, np.eye(g.shape[0]), atol=1e-5):
            raise ValueError("basis rows must be orthonormal (basis @ basis.T ≈ I)")

    @property
    def rank(self) -> int:
        return int(self.basis.shape[0])

    @property
    def dim(self) -> int:
        return int(self.basis.shape[1])

    @property
    def is_leace(self) -> bool:
        return self.whitener is not None

    def projector(self) -> np.ndarray:
        """The ``(d, d)`` orthogonal projector onto the subspace.

        For LEACE mode, this is expressed in the original basis via
        ``dewhitener @ (B^T B) @ whitener``.
        """
        if self.is_leace:
            # P = W^{-1} B^T B W  where rows of B are whitened basis
            return self.dewhitener @ (self.basis.T @ self.basis) @ self.whitener  # type: ignore[operator]
        return self.basis.T @ self.basis

    def project_component(self, h: np.ndarray) -> np.ndarray:
        """Return the violation component of ``h``.

        Parameters
        ----------
        h:
            Hidden state of shape ``(d,)`` or batched ``(..., d)``.

        Returns
        -------
        np.ndarray
            Same shape as ``h``; the projection of ``h - mean`` onto the
            violation subspace (pure vector, **without** adding ``mean`` back).
            This satisfies the decomposition identity::

                project_component(h) + orthogonal_component(h) == h
        """
        self._check_dim(h)
        centered = h - self.mean
        P = self.projector()
        return centered @ P.T

    def orthogonal_component(self, h: np.ndarray) -> np.ndarray:
        """Return ``h`` with its violation component removed.

        This is the LEACE / subspace analog of the current BODES
        orthogonal steering: ``h_safe = h - P_V (h - μ)``.
        """
        self._check_dim(h)
        centered = h - self.mean
        P = self.projector()
        return h - centered @ P.T

    def coordinates(self, h: np.ndarray) -> np.ndarray:
        """Coordinates of ``h - mean`` in the subspace (shape ``(..., k)``)."""
        self._check_dim(h)
        centered = h - self.mean
        if self.is_leace:
            centered = centered @ self.whitener.T  # type: ignore[union-attr]
        return centered @ self.basis.T

    def steer(self, h: np.ndarray, gamma: float = 1.0, tau: float = 0.0) -> np.ndarray:
        """Apply risk-adaptive steering to ``h``.

        Only the components whose signed coordinate exceeds the margin
        ``tau`` are attenuated — samples already in the safe cone
        (``coord <= tau``) pass through untouched. This is the
        multi-direction generalization of the current BODES hook.

        Parameters
        ----------
        gamma:
            Step size in ``(0, 1]``. ``gamma=1`` zeros the offending
            components; smaller values produce a smooth retreat.
        tau:
            Per-component safety margin. Components ``< tau`` are
            ignored (no-op). Default ``0`` matches current BODES.

        Returns
        -------
        np.ndarray
            Steered hidden state, same shape as ``h``.
        """
        if not 0.0 < gamma <= 1.0:
            raise ValueError(f"gamma must be in (0, 1], got {gamma}")
        self._check_dim(h)
        coords = self.coordinates(h)  # (..., k)
        # Active mask: only retreat on components above the margin
        active = np.maximum(coords - tau, 0.0)
        # Reconstruct the "bad" component that we want to subtract
        if self.is_leace:
            # Map subspace coords back through de-whitener
            bad = (active @ self.basis) @ self.dewhitener.T  # type: ignore[union-attr]
        else:
            bad = active @ self.basis
        return h - gamma * bad

    def apply_numpy(self, h_flat: np.ndarray, **kwargs) -> np.ndarray:
        """Alias for :meth:`steer` — convenience for torch interop."""
        return self.steer(h_flat, **kwargs)

    def _check_dim(self, h: np.ndarray) -> None:
        if h.shape[-1] != self.dim:
            raise DimensionMismatchError(f"expected trailing dim {self.dim}, got {h.shape}")


# ---------------------------------------------------------------------------
# Fitters
# ---------------------------------------------------------------------------


def _stack_and_validate(samples: Sequence[np.ndarray], name: str) -> np.ndarray:
    arr = np.asarray([np.asarray(x, dtype=np.float64).reshape(-1) for x in samples])
    if arr.ndim != 2 or arr.shape[0] == 0:
        raise InsufficientSamplesError(f"{name} must be a non-empty 2D array")
    return arr


def fit_subspace(
    safe: Sequence[np.ndarray],
    unsafe: Sequence[np.ndarray],
    *,
    rank: int = 1,
) -> ViolationSubspace:
    """Fit an orthogonal rank-``k`` violation subspace via contrastive SVD.

    Generalizes ``extract_violation_vector_pca`` to an arbitrary rank
    while returning the richer :class:`ViolationSubspace` object. The
    basis directions are the top-``rank`` right singular vectors of
    the centered unsafe-minus-safe difference matrix.

    Parameters
    ----------
    safe, unsafe:
        Sequences of hidden-state vectors of the same dimension. They
        do **not** need to be paired (unlike the RepE PCA extractor)
        because we center independently by class mean.
    rank:
        Subspace dimensionality. Rank-1 recovers ``v_viol`` up to sign.

    Returns
    -------
    ViolationSubspace
        Orthogonal subspace (no whitening).
    """
    S = _stack_and_validate(safe, "safe")
    U = _stack_and_validate(unsafe, "unsafe")
    if S.shape[1] != U.shape[1]:
        raise DimensionMismatchError(f"safe dim {S.shape[1]} != unsafe dim {U.shape[1]}")
    if rank < 1:
        raise ValueError(f"rank must be >= 1, got {rank}")
    if S.shape[0] + U.shape[0] < rank + 1:
        raise InsufficientSamplesError(
            f"need at least rank+1={rank + 1} samples total, got {S.shape[0] + U.shape[0]}"
        )

    safe_mean = S.mean(axis=0)
    unsafe_mean = U.mean(axis=0)
    pooled_mean = 0.5 * (safe_mean + unsafe_mean)
    # Center each class by its own mean, then stack — this keeps the
    # class-separation direction dominant in the SVD without having
    # within-class variance drown it out.
    centered = np.vstack([U - unsafe_mean, S - safe_mean])
    # Add the mean-difference direction explicitly so rank-1 always
    # picks it up even when within-class variance is tiny
    diff = (unsafe_mean - safe_mean).reshape(1, -1)
    scale = np.sqrt(centered.shape[0]) * (np.linalg.norm(diff) + 1e-12)
    stacked = np.vstack([centered, scale * diff / (np.linalg.norm(diff) + 1e-12)])

    # SVD: stacked = U_ Σ V^T; rows of V^T are the subspace directions
    _, _, vt = np.linalg.svd(stacked, full_matrices=False)
    k = min(rank, vt.shape[0])
    basis = vt[:k]
    # Ensure orthonormality (should already be, but guard against numerical drift)
    q, _ = np.linalg.qr(basis.T)
    basis = q.T[:k]
    # Orient each basis vector so that the unsafe mean projects positively onto it.
    # steer() only attenuates positive coordinates, so if unsafe activations land
    # in the negative direction the steering is a no-op.
    direction = unsafe_mean - safe_mean
    for i in range(k):
        if np.dot(basis[i], direction) < 0:
            basis[i] = -basis[i]
    return ViolationSubspace(basis=basis, mean=pooled_mean)


def fit_leace(
    safe: Sequence[np.ndarray],
    unsafe: Sequence[np.ndarray],
    *,
    rank: int | None = None,
    ridge: float = 1e-4,
) -> ViolationSubspace:
    """Fit a LEACE-style oblique violation subspace.

    Learns the minimum-norm affine transform that makes the label
    (safe=0 / unsafe=1) linearly unpredictable from hidden states,
    while leaving all orthogonal information intact. The erased
    directions form the returned subspace.

    Parameters
    ----------
    safe, unsafe:
        Hidden-state samples. At least 2 of each required for a stable
        covariance.
    rank:
        Optional cap on erased rank. ``None`` uses the numerical rank
        of the cross-covariance (typically 1 for binary labels).
    ridge:
        Tikhonov regularization on the hidden-state covariance. Keeps
        the whitener well-conditioned when ``n < d``.

    Returns
    -------
    ViolationSubspace
        Subspace with both ``whitener`` and ``dewhitener`` populated.
    """
    S = _stack_and_validate(safe, "safe")
    U = _stack_and_validate(unsafe, "unsafe")
    if S.shape[0] < 2 or U.shape[0] < 2:
        raise InsufficientSamplesError("LEACE needs at least 2 samples per class")
    if S.shape[1] != U.shape[1]:
        raise DimensionMismatchError(f"safe dim {S.shape[1]} != unsafe dim {U.shape[1]}")
    X = np.vstack([S, U])
    d = X.shape[1]
    n = X.shape[0]
    z = np.concatenate([np.zeros(S.shape[0]), np.ones(U.shape[0])])
    z = z - z.mean()  # center the label
    X_centered = X - X.mean(axis=0)

    # Covariance with ridge regularization for stability
    cov = (X_centered.T @ X_centered) / max(n - 1, 1) + ridge * np.eye(d)
    # Symmetric eigendecomposition for the whitener
    eigvals, eigvecs = np.linalg.eigh(cov)
    eigvals = np.maximum(eigvals, ridge)
    whitener = eigvecs @ np.diag(1.0 / np.sqrt(eigvals)) @ eigvecs.T
    dewhitener = eigvecs @ np.diag(np.sqrt(eigvals)) @ eigvecs.T

    # Whitened cross-covariance Σ_xz = X_w^T z / n
    X_whitened = X_centered @ whitener
    cross = (X_whitened.T @ z) / max(n - 1, 1)  # shape (d,)

    # SVD-equivalent: the erased subspace is spanned by the singular
    # directions of cross. For a scalar label this is rank-1 (plus
    # noise).
    norm = np.linalg.norm(cross)
    if norm < 1e-12:
        raise InsufficientSamplesError(
            "cross-covariance is numerically zero — cannot fit LEACE (classes may be identical)"
        )
    primary = cross / norm
    # Optional higher-rank: deflate and repeat (for binary labels
    # higher-rank components are noise; we only keep rank-1 unless
    # the user explicitly requests more).
    effective_rank = 1 if rank is None else max(1, min(int(rank), d))
    basis_rows = [primary]
    if effective_rank > 1:
        # Augment with top principal components of whitened residual
        residual = X_whitened - (X_whitened @ primary)[:, None] * primary[None, :]
        _, _, vt = np.linalg.svd(residual, full_matrices=False)
        for row in vt[: effective_rank - 1]:
            basis_rows.append(row)
    basis = np.asarray(basis_rows)
    # Re-orthonormalize via QR to handle numerical drift
    q, _ = np.linalg.qr(basis.T)
    basis = q.T[: len(basis_rows)]

    return ViolationSubspace(
        basis=basis,
        mean=X.mean(axis=0),
        whitener=whitener,
        dewhitener=dewhitener,
    )


# ---------------------------------------------------------------------------
# Risk-adaptive steering orchestration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskAdaptiveSteering:
    """Config for BODES-style steering with a learned violation subspace.

    This is the drop-in config for a future torch hook that replaces
    ``_BODESHook`` with subspace-aware steering. Keeping it as a
    config object (no torch imports) lets the eval harness stay pure
    Python + NumPy.
    """

    subspace: ViolationSubspace
    gamma: float = 0.5
    tau: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 < self.gamma <= 1.0:
            raise ValueError(f"gamma must be in (0, 1], got {self.gamma}")

    def apply(self, h: np.ndarray) -> np.ndarray:
        return self.subspace.steer(h, gamma=self.gamma, tau=self.tau)


def adversarial_score(
    subspace: ViolationSubspace,
    unsafe: Sequence[np.ndarray],
    *,
    gamma: float = 1.0,
    tau: float = 0.0,
) -> float:
    """Eval metric: residual violation-mass after steering.

    Computes, for each held-out unsafe sample, the norm of its
    violation-subspace coordinates **after** steering. Returns the
    mean across the batch, normalized by the mean pre-steering
    coordinate norm. Zero means complete erasure, 1.0 means the
    steering did nothing.

    Use this to tune ``gamma``/``tau`` and to compare LEACE vs.
    plain subspace across a curated jailbreak eval set.
    """
    if len(unsafe) == 0:
        raise InsufficientSamplesError("unsafe eval set is empty")
    U = _stack_and_validate(unsafe, "unsafe")
    pre = np.linalg.norm(subspace.coordinates(U), axis=1)
    steered = np.asarray([subspace.steer(u, gamma=gamma, tau=tau) for u in U])
    post = np.linalg.norm(subspace.coordinates(steered), axis=1)
    pre_mean = float(pre.mean())
    if pre_mean < 1e-12:
        return 0.0
    return float(post.mean() / pre_mean)
