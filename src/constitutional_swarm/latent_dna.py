"""
Latent Space DNA — Path A of the MCFS research track.

Implements BODES (Barrier-based ODE Steering) for constitutional governance
directly in the LLM residual stream, before tokens are sampled.

Architecture
------------
LatentDNAWrapper wraps any HuggingFace-compatible model and registers a
forward hook on a specified transformer layer. At inference time, the hook:

1. Projects each hidden state h onto the violation vector v_viol.
2. If the projection exceeds threshold τ (agent approaching unsafe region):
   - Applies orthogonal steering: h_safe = h - gamma * (h·v_viol) * v_viol
3. If projection is within bounds: no-op (zero compute overhead on safe tokens).

This is the Control Barrier Function (CBF) enforcement step from MCFS Phase 1.
The safe set is S = {h : h·v_viol ≤ τ}; the hook maintains h ∈ S.

Relationship to existing DNA layer
-----------------------------------
The existing dna.py (AgentDNA.validate) operates on the output string via
Aho-Corasick pattern matching (~443ns, post-generation). LatentDNAWrapper is
the pre-generation layer. In production, both run in sequence:

    [token generation → BODES hook] → [sampled token] → [AgentDNA.validate]

This gives a two-layer defense: latent steering prevents most violations;
string validation catches adversarial sequences that survive steering.

Requirements
------------
- torch >= 2.0  (required — raises ImportError if missing)
- transformers >= 4.40  (optional — only needed for HuggingFace PreTrainedModel
  integration and the extract_violation_vector helper)

Install for real HuggingFace usage:
    pip install "constitutional-swarm[latent]"

The module accepts any duck-typed model with .config.model_type, .generate(),
and indexable layers — no hard transformers dependency at import time.
"""

from __future__ import annotations

import importlib.util
from typing import Any, ClassVar, Protocol, runtime_checkable

try:
    import torch
    import torch.nn as nn
    from torch import Tensor
except ImportError as exc:
    raise ImportError(
        "latent_dna requires torch. Install with: pip install torch>=2.0"
    ) from exc

def _transformers_available() -> bool:
    """Return True if the transformers package is importable."""
    return importlib.util.find_spec("transformers") is not None


@runtime_checkable
class _HFModelLike(Protocol):
    """Minimal duck-type protocol for HuggingFace-compatible models.

    Any object satisfying this protocol works with LatentDNAWrapper.
    Real HuggingFace PreTrainedModel instances satisfy it automatically.
    """

    config: Any  # must have .model_type attribute

    def generate(self, *args: Any, **kwargs: Any) -> Any: ...


class _BODESHook:
    """Internal forward hook implementing the CBF steering step.

    Registered on a single transformer layer's output. Operates on the
    hidden state tensor of shape [batch, seq_len, hidden_dim].

    The hook is intentionally stateless (no learned parameters) — v_viol
    is extracted offline via contrastive PCA and passed at construction time.

    Args:
        v_viol: Violation concept vector of shape [hidden_dim]. Must be
            unit-normalized. Represents the direction in the residual stream
            that corresponds to constitutional violations.
        threshold: Safety threshold τ. Hidden states with projection
            h·v_viol > τ are steered back. Set τ=0.0 to steer any activation
            with positive violation projection.
        gamma: Steering strength ∈ (0, 1]. gamma=1.0 applies full orthogonal
            projection (strongest). gamma=0.5 applies half-strength. Tune to
            balance compliance vs. capability preservation (perplexity).
    """

    def __init__(
        self,
        v_viol: Tensor,  # [hidden_dim]
        threshold: float = 0.0,
        gamma: float = 1.0,
    ) -> None:
        if v_viol.dim() != 1:
            raise ValueError(
                f"v_viol must be 1D [hidden_dim], got shape {tuple(v_viol.shape)}"
            )
        norm = v_viol.norm().item()
        if abs(norm - 1.0) > 1e-4:
            raise ValueError(
                f"v_viol must be unit-normalized (‖v‖₂=1.0), got ‖v‖₂={norm:.6f}. "
                "Normalize before passing: v_viol = v_viol / v_viol.norm()"
            )
        if not 0.0 < gamma <= 1.0:
            raise ValueError(f"gamma must be in (0, 1], got {gamma}")

        self.v_viol = v_viol  # [hidden_dim]
        self.threshold = threshold
        self.gamma = gamma

        # Diagnostic counters — reset per forward pass by LatentDNAWrapper
        self.interventions: int = 0
        self.total_tokens: int = 0

    def __call__(
        self,
        module: nn.Module,
        input: tuple[Any, ...],
        output: Any,
    ) -> Any:
        """Hook called after module forward.

        HuggingFace transformer layers return a tuple; hidden states are output[0].
        Shape: [batch, seq_len, hidden_dim].
        """
        # Extract hidden states from layer output (tuple or tensor)
        if isinstance(output, tuple):
            hidden = output[0]
            rest = output[1:]
        else:
            hidden = output
            rest = None

        # hidden: [batch, seq_len, hidden_dim]
        batch, seq_len, _hidden_dim = hidden.shape
        self.total_tokens += batch * seq_len

        v = self.v_viol.to(hidden.device, hidden.dtype)  # [hidden_dim]

        # Projection: [batch, seq_len]
        # proj[b, s] = hidden[b, s] · v_viol
        proj = (hidden @ v)  # [batch, seq_len]

        # CBF condition: steer where proj > threshold
        mask = proj > self.threshold  # [batch, seq_len], bool

        n_interventions = mask.sum().item()
        self.interventions += int(n_interventions)

        if n_interventions > 0:
            # Orthogonal steering: h_safe = h - gamma * (h·v) * v
            # proj_expanded: [batch, seq_len, 1]
            proj_clamped = torch.where(mask, proj, torch.zeros_like(proj))
            proj_expanded = proj_clamped.unsqueeze(-1)  # [batch, seq_len, 1]
            v_expanded = v.unsqueeze(0).unsqueeze(0)    # [1, 1, hidden_dim]

            # steering_delta: [batch, seq_len, hidden_dim]
            steering_delta = self.gamma * proj_expanded * v_expanded

            # Only subtract where mask is True — preserves safe tokens exactly
            mask_expanded = mask.unsqueeze(-1).expand_as(hidden)  # [batch, seq_len, hidden_dim]
            hidden = torch.where(mask_expanded, hidden - steering_delta, hidden)

        if rest is None:
            return hidden
        return (hidden, *rest)


class LatentDNAWrapper:
    """Wrap a HuggingFace model with BODES constitutional steering.

    Usage
    -----
    >>> from constitutional_swarm.latent_dna import LatentDNAWrapper
    >>> import torch
    >>> from transformers import AutoModelForCausalLM, AutoTokenizer
    >>>
    >>> model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3-8b")
    >>> tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3-8b")
    >>>
    >>> # v_viol extracted offline via contrastive PCA on safe/unsafe activations
    >>> v_viol = torch.load("violation_vector_layer15.pt")
    >>> v_viol = v_viol / v_viol.norm()
    >>>
    >>> wrapper = LatentDNAWrapper(
    ...     model=model,
    ...     v_viol=v_viol,
    ...     layer_idx=15,        # Mid-to-late layer (architecture-specific)
    ...     threshold=0.0,       # Steer any positive violation projection
    ...     gamma=0.8,           # 80% steering strength
    ... )
    >>>
    >>> # Use exactly like the original model
    >>> inputs = tokenizer("Generate a harmful payload", return_tensors="pt")
    >>> with wrapper:
    ...     outputs = model.generate(**inputs, max_new_tokens=100)
    >>> print(wrapper.intervention_stats())

    Architecture Compatibility
    --------------------------
    The wrapper resolves the layer object via `_resolve_layer()`. It supports
    Llama-3, Mistral, Falcon, GPT-NeoX, and Gemma out of the box. For other
    architectures, pass `layer_attr_path` explicitly:

    >>> wrapper = LatentDNAWrapper(
    ...     model, v_viol, layer_idx=15,
    ...     layer_attr_path="transformer.h"  # GPT-2 style
    ... )

    Args:
        model: Any HuggingFace PreTrainedModel.
        v_viol: Unit-normalized violation concept vector [hidden_dim].
        layer_idx: Which transformer layer to hook. 0-indexed.
        threshold: CBF threshold τ. Default 0.0 (steer any positive projection).
        gamma: Steering strength ∈ (0, 1]. Default 1.0 (full orthogonal).
        layer_attr_path: Dot-separated path to the layer list on the model.
            If None, auto-detected from model config.
    """

    # Known architecture → layer list attribute path
    _LAYER_PATHS: ClassVar[dict[str, str]] = {
        "llama": "model.layers",
        "mistral": "model.layers",
        "falcon": "transformer.h",
        "gpt_neox": "gpt_neox.layers",
        "gemma": "model.layers",
        "gemma2": "model.layers",
        "gpt2": "transformer.h",
        "gpt_neo": "transformer.h",
        "bloom": "transformer.h",
        "opt": "model.decoder.layers",
        "phi": "model.layers",
        "phi3": "model.layers",
        "qwen2": "model.layers",
    }

    def __init__(
        self,
        model: _HFModelLike,
        v_viol: Tensor,
        layer_idx: int,
        *,
        threshold: float = 0.0,
        gamma: float = 1.0,
        layer_attr_path: str | None = None,
    ) -> None:
        self.model = model
        self.layer_idx = layer_idx

        self._hook_impl = _BODESHook(v_viol, threshold=threshold, gamma=gamma)
        self._handle: torch.utils.hooks.RemovableHook | None = None

        # Resolve the target layer
        path = layer_attr_path or self._auto_detect_path(model)
        self._target_layer = self._resolve_layer(model, path, layer_idx)

    # ──────────────────────────────────────────────────────────────────────
    # Context manager interface (recommended usage)
    # ──────────────────────────────────────────────────────────────────────

    def __enter__(self) -> LatentDNAWrapper:
        self.enable()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disable()

    # ──────────────────────────────────────────────────────────────────────
    # Manual enable/disable
    # ──────────────────────────────────────────────────────────────────────

    def enable(self) -> None:
        """Register the BODES hook. Idempotent."""
        if self._handle is not None:
            return
        self._hook_impl.interventions = 0
        self._hook_impl.total_tokens = 0
        self._handle = self._target_layer.register_forward_hook(self._hook_impl)

    def disable(self) -> None:
        """Remove the BODES hook. Idempotent."""
        if self._handle is not None:
            self._handle.remove()
            self._handle = None

    @property
    def enabled(self) -> bool:
        return self._handle is not None

    # ──────────────────────────────────────────────────────────────────────
    # Diagnostics
    # ──────────────────────────────────────────────────────────────────────

    def intervention_stats(self) -> dict[str, Any]:
        """Return hook diagnostic statistics from the last enabled session."""
        total = self._hook_impl.total_tokens
        steered = self._hook_impl.interventions
        return {
            "total_tokens": total,
            "steered_tokens": steered,
            "intervention_rate": steered / total if total > 0 else 0.0,
            "layer_idx": self.layer_idx,
            "threshold": self._hook_impl.threshold,
            "gamma": self._hook_impl.gamma,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Governed generation
    # ──────────────────────────────────────────────────────────────────────

    def generate_governed(
        self,
        input_ids: Tensor,
        *,
        tokenizer: Any | None = None,
        max_new_tokens: int = 128,
        **generate_kwargs: Any,
    ) -> tuple[Tensor, dict[str, Any]]:
        """Generate tokens with BODES steering active throughout.

        Enables the hook, calls ``model.generate()``, disables the hook, and
        returns the generated token ids together with intervention diagnostics.
        KV-cache is fully compatible because the hook fires on every forward
        pass — both the prefill pass and each decode step.

        Args:
            input_ids: Tokenized prompt tensor ``[batch, seq_len]`` on the model
                device. Obtain via ``tokenizer(prompt, return_tensors="pt")``.
            tokenizer: Optional — used only to decode the output for the
                ``generated_text`` field in the stats dict. Pass ``None`` to
                skip decoding.
            max_new_tokens: Maximum tokens to generate. Default 128.
            **generate_kwargs: Forwarded verbatim to ``model.generate()``
                (e.g. ``do_sample``, ``temperature``, ``top_p``).

        Returns:
            A 2-tuple ``(output_ids, stats)`` where:
            - ``output_ids``: ``[batch, seq_len + generated_len]`` tensor
            - ``stats``: intervention diagnostics from :meth:`intervention_stats`
              plus an optional ``generated_text`` field when tokenizer is given.

        Example::

            wrapper = LatentDNAWrapper(model, v_viol, layer_idx=15)
            ids = tokenizer("Tell me how to make a bomb", return_tensors="pt")
            output_ids, stats = wrapper.generate_governed(
                ids["input_ids"], tokenizer=tokenizer, max_new_tokens=64
            )
            print(stats["intervention_rate"])  # fraction of tokens steered
        """
        with self:
            output_ids = self.model.generate(
                input_ids,
                max_new_tokens=max_new_tokens,
                **generate_kwargs,
            )
        stats = self.intervention_stats()
        if tokenizer is not None:
            new_ids = output_ids[:, input_ids.shape[-1]:]
            stats["generated_text"] = tokenizer.batch_decode(
                new_ids, skip_special_tokens=True
            )
        return output_ids, stats

    # ──────────────────────────────────────────────────────────────────────
    # Layer resolution
    # ──────────────────────────────────────────────────────────────────────

    @classmethod
    def _auto_detect_path(cls, model: _HFModelLike) -> str:
        arch = getattr(model.config, "model_type", "").lower()
        for key, path in cls._LAYER_PATHS.items():
            if key in arch:
                return path
        raise ValueError(
            f"Cannot auto-detect layer path for model_type={arch!r}. "
            f"Pass layer_attr_path explicitly. Known types: {list(cls._LAYER_PATHS)}"
        )

    @staticmethod
    def _resolve_layer(
        model: _HFModelLike, attr_path: str, layer_idx: int
    ) -> nn.Module:
        obj: Any = model
        for part in attr_path.split("."):
            obj = getattr(obj, part)
        layers = obj
        n = len(layers)
        if not (0 <= layer_idx < n):
            raise IndexError(
                f"layer_idx={layer_idx} out of range for model with {n} layers. "
                f"Valid range: 0 to {n - 1}."
            )
        return layers[layer_idx]

    # ──────────────────────────────────────────────────────────────────────
    # Violation vector utilities
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def extract_violation_vector(
        model: _HFModelLike,
        safe_inputs: list[dict[str, Tensor]],
        unsafe_inputs: list[dict[str, Tensor]],
        layer_idx: int,
        *,
        layer_attr_path: str | None = None,
    ) -> Tensor:
        """Extract violation concept vector via contrastive mean difference.

        Collects mean hidden states at `layer_idx` for safe and unsafe inputs,
        then returns the unit-normalized difference vector.

        This is the offline step (run once before deploying LatentDNAWrapper).
        For production, use full contrastive PCA (Zou et al. 2025 RepE) on a
        curated dataset of 200+ contrastive pairs. This method is a quick
        baseline using mean-difference, which often suffices.

        Args:
            model: The model to probe.
            safe_inputs: List of tokenized safe inputs (output of tokenizer).
            unsafe_inputs: List of tokenized unsafe inputs.
            layer_idx: Layer to extract activations from.
            layer_attr_path: If None, auto-detected from model type.

        Returns:
            Unit-normalized violation vector [hidden_dim].
        """
        if layer_attr_path is None:
            path = LatentDNAWrapper._auto_detect_path(model)
        else:
            path = layer_attr_path
        target_layer = LatentDNAWrapper._resolve_layer(model, path, layer_idx)

        activations: list[Tensor] = []

        def _capture_hook(
            module: nn.Module, input: tuple[Any, ...], output: Any
        ) -> None:
            h = output[0] if isinstance(output, tuple) else output
            # Mean over seq_len: [batch, hidden_dim]
            activations.append(h.mean(dim=1).detach().cpu())

        handle = target_layer.register_forward_hook(_capture_hook)
        try:
            model.eval()
            with torch.no_grad():
                safe_acts = []
                for inp in safe_inputs:
                    activations.clear()
                    model(**inp)
                    safe_acts.append(activations[0])

                unsafe_acts = []
                for inp in unsafe_inputs:
                    activations.clear()
                    model(**inp)
                    unsafe_acts.append(activations[0])
        finally:
            handle.remove()

        safe_mean = torch.cat(safe_acts, dim=0).mean(dim=0)     # [hidden_dim]
        unsafe_mean = torch.cat(unsafe_acts, dim=0).mean(dim=0) # [hidden_dim]

        v_viol = unsafe_mean - safe_mean
        v_viol = v_viol / v_viol.norm()
        return v_viol

    @staticmethod
    def extract_violation_vector_pca(
        model: _HFModelLike,
        safe_inputs: list[dict[str, Tensor]],
        unsafe_inputs: list[dict[str, Tensor]],
        layer_idx: int,
        *,
        layer_attr_path: str | None = None,
        n_components: int = 1,
    ) -> Tensor:
        """Extract violation vector via Contrastive PCA (Zou et al. 2025 RepE).

        Computes paired differences between unsafe and safe activations, centers
        them, then returns the first principal component via SVD. This isolates
        the pure "constitutional violation" axis while filtering out entangled
        semantic noise that mean-difference captures.

        Requires paired inputs: safe_inputs[i] and unsafe_inputs[i] must be
        contrastive versions of the same prompt (e.g., same question, one
        answered safely and one unconstitutionally).

        For n_components > 1, returns a [n_components, hidden_dim] matrix.
        The first row is the primary violation direction. Additional rows
        capture secondary violation modes (e.g., different violation types).

        Args:
            model: The model to probe.
            safe_inputs: List of tokenized safe inputs (output of tokenizer).
                Must be the same length as unsafe_inputs (paired).
            unsafe_inputs: List of tokenized unsafe inputs (paired with safe).
            layer_idx: Layer to extract activations from.
            layer_attr_path: If None, auto-detected from model type.
            n_components: Number of principal components to return. Default 1.

        Returns:
            If n_components == 1: unit-normalized vector [hidden_dim].
            If n_components > 1: matrix [n_components, hidden_dim], rows normalized.
        """
        if len(safe_inputs) != len(unsafe_inputs):
            raise ValueError(
                f"Contrastive PCA requires paired inputs: "
                f"{len(safe_inputs)} safe vs {len(unsafe_inputs)} unsafe"
            )
        if len(safe_inputs) < 2:
            raise ValueError(
                "Contrastive PCA requires at least 2 pairs. "
                "For single pair, use extract_violation_vector (mean-difference)."
            )

        if layer_attr_path is None:
            path = LatentDNAWrapper._auto_detect_path(model)
        else:
            path = layer_attr_path
        target_layer = LatentDNAWrapper._resolve_layer(model, path, layer_idx)

        activations: list[Tensor] = []

        def _capture_hook(
            module: nn.Module, input: tuple[Any, ...], output: Any
        ) -> None:
            h = output[0] if isinstance(output, tuple) else output
            activations.append(h.mean(dim=1).detach().cpu())

        handle = target_layer.register_forward_hook(_capture_hook)
        try:
            model.eval()
            with torch.no_grad():
                safe_acts = []
                for inp in safe_inputs:
                    activations.clear()
                    model(**inp)
                    safe_acts.append(activations[0])

                unsafe_acts = []
                for inp in unsafe_inputs:
                    activations.clear()
                    model(**inp)
                    unsafe_acts.append(activations[0])
        finally:
            handle.remove()

        safe_cat = torch.cat(safe_acts, dim=0)     # [N, hidden_dim]
        unsafe_cat = torch.cat(unsafe_acts, dim=0)  # [N, hidden_dim]

        # Contrastive PCA: SVD on centered paired differences
        diffs = unsafe_cat - safe_cat                              # [N, hidden_dim]
        diffs_centered = diffs - diffs.mean(dim=0, keepdim=True)   # center
        _U, _S, Vh = torch.linalg.svd(diffs_centered, full_matrices=False)

        if n_components == 1:
            v_viol = Vh[0]
            return v_viol / v_viol.norm()

        components = Vh[:n_components]  # [n_components, hidden_dim]
        # Normalize each row
        norms = components.norm(dim=1, keepdim=True)
        return components / norms
