"""Sybil-resilient validator set with VRF-based committee selection.

Phase 7.1 breakthrough: current ``ConstitutionalMesh`` assumes Byzantine
tolerance at < 1/3 of *identities*. Under sybil attack, a single
adversary can inflate raw identity count cheaply and break that bound.

This module introduces:

- :class:`ValidatorIdentity` — a validator with stake, reputation, and
  a fault-domain tag (IP prefix, AS number, organization, credential
  issuer, etc.) used to bound per-domain influence.
- :class:`FaultDomainPolicy` — caps the effective weight contributed
  by any single fault domain. This is the key sybil defense: raw
  identity count no longer dominates.
- :class:`ValidatorSet` — the membership with total weights and
  per-domain weights.
- :class:`CommitteeSelector` — VRF-style deterministic committee
  sampling from a public seed.

References
----------
- Lamport, Shostak, Pease (1982) "The Byzantine Generals Problem"
- Generalized Byzantine Quorums (Alchieri et al. 2020) — asymmetric trust
- Sybil-Resilient Reality-Aware Social Choice (Shahaf et al. 2018)

This is a tractable MVP — we use ``hashlib.sha256(seed || validator_id)``
as the VRF surrogate. A production deployment would swap in RFC 9381
ECVRF or BLS-based sortition. The committee selection contract
(deterministic from public seed + verifiable by anyone with the seed)
is preserved under either implementation.
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

__all__ = [
    "ValidatorIdentity",
    "FaultDomainPolicy",
    "ValidatorSet",
    "CommitteeSelector",
    "SybilBoundViolation",
    "CommitteeSelection",
]


class SybilBoundViolation(ValueError):
    """Raised when a committee would exceed the fault-domain weight cap."""


@dataclass(frozen=True)
class ValidatorIdentity:
    """A single validator with stake, reputation, and fault-domain tag.

    Parameters
    ----------
    agent_id:
        Canonical agent identifier (matches ``ConstitutionalMesh``).
    stake:
        Non-negative stake weight. Raw weight in quorum calculations.
    reputation:
        Multiplier in ``[0.0, 1.0]`` — recent good behavior amplifies
        effective weight; misbehavior shrinks it.
    fault_domain:
        Opaque tag identifying the validator's independence class
        (e.g. ``"as:AS15169"``, ``"org:ourcorp"``, ``"issuer:acme-ca"``).
        Multiple validators sharing a fault_domain are not independent
        fault domains and must be collectively capped.
    """

    agent_id: str
    stake: float
    reputation: float = 1.0
    fault_domain: str = ""

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ValueError("agent_id must be non-empty")
        if self.stake < 0.0:
            raise ValueError(f"stake must be non-negative, got {self.stake}")
        if not 0.0 <= self.reputation <= 1.0:
            raise ValueError(
                f"reputation must be in [0, 1], got {self.reputation}"
            )

    @property
    def effective_weight(self) -> float:
        """Raw effective weight before fault-domain capping."""
        return self.stake * self.reputation


@dataclass(frozen=True)
class FaultDomainPolicy:
    """Cap on per-fault-domain contribution to committee weight.

    ``max_fraction`` is the ceiling on any single fault_domain's share
    of the total effective committee weight. Setting
    ``max_fraction=0.2`` means no single AS / issuer / org can hold more
    than 20 % of voting power no matter how many validator identities
    they register. This is what makes the scheme sybil-resistant: an
    attacker must actually spread across independent fault domains.

    ``untagged_policy`` controls how validators with empty
    ``fault_domain`` are treated:

    - ``"strict"`` (default) — treat every untagged validator as its
      own domain ``"__untagged__:<agent_id>"``; safest when tags are
      optional but incomplete.
    - ``"lenient"`` — treat all untagged validators as a single
      shared domain ``"__untagged__"``. Useful for backward-compat
      with pre-Phase-7 agent registrations.
    """

    max_fraction: float = 0.34
    untagged_policy: str = "strict"

    def __post_init__(self) -> None:
        if not 0.0 < self.max_fraction <= 1.0:
            raise ValueError(
                f"max_fraction must be in (0, 1], got {self.max_fraction}"
            )
        if self.untagged_policy not in ("strict", "lenient"):
            raise ValueError(
                f"untagged_policy must be 'strict' or 'lenient', "
                f"got {self.untagged_policy!r}"
            )

    def resolve_domain(self, validator: ValidatorIdentity) -> str:
        """Resolve the effective fault-domain tag for a validator."""
        if validator.fault_domain:
            return validator.fault_domain
        if self.untagged_policy == "strict":
            return f"__untagged__:{validator.agent_id}"
        return "__untagged__"


@dataclass(frozen=True)
class CommitteeSelection:
    """Result of :meth:`CommitteeSelector.select`.

    ``members`` is the committee (subset of validator ids). ``weight``
    is the total raw effective weight (before fault-domain capping).
    ``capped_weight`` applies the policy cap per domain — this is the
    value that matters for the safety threshold. ``domain_weights``
    maps fault_domain → the weight actually counted (post-cap).
    """

    members: tuple[str, ...]
    weight: float
    capped_weight: float
    domain_weights: Mapping[str, float]
    seed: str

    def has_quorum(self, threshold_fraction: float = 2 / 3) -> bool:
        """True if capped weight meets the threshold fraction of raw weight.

        A committee ``has_quorum(2/3)`` when the honest lower bound,
        computed under the fault-domain cap, is at least 2/3 of the
        raw uncapped weight.
        """
        if self.weight <= 0:
            return False
        return self.capped_weight / self.weight >= threshold_fraction


class ValidatorSet:
    """A sybil-aware validator membership with fault-domain caps.

    The set maintains:

    - all registered validators
    - per-domain weight totals
    - a total raw effective weight

    Add / remove validators as membership changes; committee selection
    is then performed against the current set.
    """

    def __init__(
        self,
        validators: Iterable[ValidatorIdentity] = (),
        *,
        policy: FaultDomainPolicy | None = None,
    ) -> None:
        self._policy = policy or FaultDomainPolicy()
        self._validators: dict[str, ValidatorIdentity] = {}
        for v in validators:
            self.add(v)

    @property
    def policy(self) -> FaultDomainPolicy:
        return self._policy

    def __len__(self) -> int:
        return len(self._validators)

    def __contains__(self, agent_id: object) -> bool:
        return isinstance(agent_id, str) and agent_id in self._validators

    def __iter__(self):
        return iter(self._validators.values())

    def add(self, validator: ValidatorIdentity) -> None:
        """Register a validator. Overwrites any existing entry with the same agent_id."""
        self._validators[validator.agent_id] = validator

    def remove(self, agent_id: str) -> None:
        """Remove a validator. Silent if not registered."""
        self._validators.pop(agent_id, None)

    def get(self, agent_id: str) -> ValidatorIdentity | None:
        return self._validators.get(agent_id)

    def total_weight(self) -> float:
        return sum(v.effective_weight for v in self._validators.values())

    def domain_weights(self) -> dict[str, float]:
        """Weight totals per fault-domain across the full set."""
        out: dict[str, float] = {}
        for v in self._validators.values():
            domain = self._policy.resolve_domain(v)
            out[domain] = out.get(domain, 0.0) + v.effective_weight
        return out

    def effective_total_weight(self) -> float:
        """Total weight *after* applying the per-domain cap.

        This is the honest upper bound the validator set as a whole can
        contribute. If the cap is 1/3 and any one domain holds >1/3 of
        raw weight, the excess is discarded — that's the sybil defense.
        """
        cap_frac = self._policy.max_fraction
        raw_total = self.total_weight()
        if raw_total <= 0:
            return 0.0
        ceiling = cap_frac * raw_total
        domain_w = self.domain_weights()
        capped_total = 0.0
        for w in domain_w.values():
            capped_total += min(w, ceiling)
        return capped_total

    def snapshot(self) -> tuple[ValidatorIdentity, ...]:
        """Deterministic ordered tuple of all validators (by agent_id)."""
        return tuple(
            self._validators[k] for k in sorted(self._validators)
        )


class CommitteeSelector:
    """VRF-style deterministic committee sampling.

    Given a public ``seed`` (e.g. ``assignment_id`` or an epoch beacon)
    and a ``committee_size``, this produces a committee deterministically
    — any other party with the same validator set and seed reproduces
    the same committee. Each validator's selection score is
    :math:`h(\\mathrm{seed} \\| \\mathrm{agent\\_id})` adjusted by
    effective weight.

    We use SHA-256 as a stand-in VRF (not verifiable by a non-operator).
    To upgrade, swap in RFC 9381 ECVRF: the ``_score`` method is the
    only coupling point.
    """

    def __init__(self, validator_set: ValidatorSet) -> None:
        self._set = validator_set

    @staticmethod
    def _score(seed: str, agent_id: str, weight: float) -> float:
        """Weighted VRF score — lower is "sooner-picked".

        Implements the standard weighted sortition transform
        ``-ln(u) / w`` where ``u ~ Uniform(0, 1)``. Equivalent to
        Poisson process priority sampling: the smallest k scores form
        a weighted sample without replacement.
        """
        if weight <= 0:
            return float("inf")
        digest = hashlib.sha256(
            f"{seed}\x00{agent_id}".encode("utf-8")
        ).digest()
        # Uniform in (0, 1] — avoid 0 to keep log defined
        raw = int.from_bytes(digest[:8], "big") + 1
        u = raw / (1 << 64)
        # -ln(u)/w priority → weighted sample without replacement
        import math

        return -math.log(u) / weight

    def select(
        self,
        seed: str,
        committee_size: int,
        *,
        exclude: Sequence[str] = (),
    ) -> CommitteeSelection:
        """Select a committee of ``committee_size`` validators.

        Parameters
        ----------
        seed:
            Public, reproducible entropy source (e.g. assignment id,
            epoch hash). Same seed + same set => same committee.
        committee_size:
            Target committee size. If the set has fewer eligible
            validators than requested, the full eligible set is used.
        exclude:
            Validator ids to exclude (e.g. the producer under MACI).

        Returns
        -------
        CommitteeSelection
            Committee members, total raw weight, capped weight (per
            fault-domain policy), and per-domain weight breakdown.
        """
        if committee_size <= 0:
            raise ValueError(
                f"committee_size must be positive, got {committee_size}"
            )
        excluded = frozenset(exclude)
        candidates = [
            v for v in self._set if v.agent_id not in excluded
        ]
        if not candidates:
            return CommitteeSelection(
                members=(),
                weight=0.0,
                capped_weight=0.0,
                domain_weights={},
                seed=seed,
            )
        # Priority-sample the k lowest-score validators
        k = min(committee_size, len(candidates))
        scored = [
            (self._score(seed, v.agent_id, v.effective_weight), v)
            for v in candidates
        ]
        chosen = heapq.nsmallest(k, scored, key=lambda t: t[0])
        picked = [v for _, v in chosen]
        # Sort deterministically by agent_id so serialized committees
        # are independent of Python's heap stability quirks
        picked.sort(key=lambda v: v.agent_id)

        # Compute raw + capped weights
        policy = self._set.policy
        raw_weight = sum(v.effective_weight for v in picked)
        per_domain: dict[str, float] = {}
        for v in picked:
            domain = policy.resolve_domain(v)
            per_domain[domain] = per_domain.get(domain, 0.0) + v.effective_weight
        # Cap each domain at max_fraction * raw_weight
        capped_weight = 0.0
        capped_domain_weights: dict[str, float] = {}
        if raw_weight > 0:
            ceiling = policy.max_fraction * raw_weight
            for domain, w in per_domain.items():
                capped = min(w, ceiling)
                capped_domain_weights[domain] = capped
                capped_weight += capped

        return CommitteeSelection(
            members=tuple(v.agent_id for v in picked),
            weight=raw_weight,
            capped_weight=capped_weight,
            domain_weights=capped_domain_weights,
            seed=seed,
        )

    def select_until_independent(
        self,
        seed: str,
        committee_size: int,
        *,
        exclude: Sequence[str] = (),
        max_retries: int = 8,
        threshold_fraction: float = 2 / 3,
    ) -> CommitteeSelection:
        """Select a committee with enough fault-domain independence.

        Calls :meth:`select` with seed variants (``seed\\x00<k>``) until
        the committee's capped/raw ratio meets ``threshold_fraction``,
        or ``max_retries`` is exhausted. If all retries fail, raises
        :class:`SybilBoundViolation` — meaning the validator set itself
        is too sybil-concentrated to produce a safe committee of the
        requested size.
        """
        for attempt in range(max_retries):
            probe_seed = seed if attempt == 0 else f"{seed}\x00{attempt}"
            result = self.select(
                probe_seed, committee_size, exclude=exclude
            )
            if result.has_quorum(threshold_fraction):
                return result
        raise SybilBoundViolation(
            f"Could not assemble a committee of size {committee_size} "
            f"with capped/raw ≥ {threshold_fraction:.3f} after "
            f"{max_retries} retries. The validator set is sybil-concentrated."
        )
