"""Phase 7.5 — versioned constitutional reconfiguration.

Replaces hash-equality sync with epoch-stamped constitutions and
joint-consensus transition certificates. Gives the swarm a safe,
auditable way to evolve its constitution without fracturing the
network into permanent hash forks.

Design
------
A ``ConstitutionVersion`` is a content-addressed snapshot of the
constitution at a specific epoch. Each version points backward at its
parent via ``parent_digest`` so the chain of amendments is a Merkle
chain; replay attacks at an old epoch cannot disguise themselves as
fresh transitions.

An ``AmendmentProposal`` is a typed diff that carries:

* the intended transition ``(from_epoch -> to_epoch)``
* the full target ``ConstitutionVersion``
* an optional ``drift_budget`` capping how far a single amendment may
  move the governance surface (number of rules changed, numeric
  threshold deltas, etc.).

A ``TransitionCertificate`` ratifies the proposal. The certificate is
valid only when it carries **joint consensus**: quorum from BOTH the
pre-transition validator set and the post-transition validator set.
This mirrors Raft joint consensus (see ``specs/constitution_reconfig.tla``)
and prevents a retiring validator set from committing their successor
unilaterally, or vice versa.

The module is transport-agnostic. Integration with
``bittensor/constitution_sync.py`` is a follow-up wire-up; the
primitives and invariants live here so the logic can be tested
without a bittensor runtime.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

__all__ = [
    "AmendmentProposal",
    "ConstitutionVersion",
    "DriftBudget",
    "DriftBudgetExceeded",
    "EpochMismatchError",
    "InvalidTransitionError",
    "JointQuorumNotMetError",
    "TransitionCertificate",
    "compute_version_digest",
    "evaluate_drift",
    "verify_transition",
]


_DOMAIN = b"acgs-swarm/epoch-reconfig/v1"


class InvalidTransitionError(ValueError):
    """Transition metadata is internally inconsistent."""


class EpochMismatchError(InvalidTransitionError):
    """Proposal epoch does not match the expected predecessor."""


class JointQuorumNotMetError(InvalidTransitionError):
    """Either the old or new validator set failed to ratify."""


class DriftBudgetExceeded(InvalidTransitionError):
    """Amendment diff exceeds the declared drift budget."""


def compute_version_digest(
    *,
    epoch: int,
    rules: tuple[str, ...],
    parent_digest: bytes,
) -> bytes:
    """Deterministic content digest for a ConstitutionVersion.

    ``rules`` is the canonical sorted tuple of rule strings; callers are
    responsible for sorting and deduplicating before calling.
    """
    if epoch < 0:
        raise ValueError(f"epoch must be non-negative, got {epoch}")
    if len(parent_digest) not in (0, 32):
        raise ValueError(f"parent_digest must be 0 or 32 bytes, got {len(parent_digest)}")
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(b"version")
    h.update(epoch.to_bytes(8, "big"))
    h.update(len(parent_digest).to_bytes(1, "big"))
    h.update(parent_digest)
    h.update(len(rules).to_bytes(4, "big"))
    for rule in rules:
        data = rule.encode("utf-8")
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
    return h.digest()


@dataclass(frozen=True)
class ConstitutionVersion:
    """Content-addressed snapshot of the constitution at one epoch."""

    epoch: int
    rules: tuple[str, ...]
    parent_digest: bytes = b""

    def __post_init__(self) -> None:
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")
        if tuple(sorted(self.rules)) != self.rules:
            raise ValueError("rules must be sorted (canonical form)")
        if len(self.parent_digest) not in (0, 32):
            raise ValueError("parent_digest must be 0 or 32 bytes")

    @property
    def digest(self) -> bytes:
        return compute_version_digest(
            epoch=self.epoch,
            rules=self.rules,
            parent_digest=self.parent_digest,
        )


@dataclass(frozen=True)
class DriftBudget:
    """Per-amendment governance-drift cap.

    The budget is a safety rail: an amendment that adds or removes more
    than ``max_rule_delta`` rules in a single step is auto-rejected
    even if it carries a valid joint-consensus certificate. This makes
    "boiling-frog" governance capture materially harder — attacking the
    constitution requires multiple detectable transitions, not one
    sweeping rewrite.
    """

    max_rule_delta: int = 16

    def __post_init__(self) -> None:
        if self.max_rule_delta < 0:
            raise ValueError("max_rule_delta must be non-negative")


def evaluate_drift(
    prior: ConstitutionVersion,
    proposed: ConstitutionVersion,
) -> int:
    """Return symmetric-difference rule count between two versions."""
    prior_set = set(prior.rules)
    proposed_set = set(proposed.rules)
    added = proposed_set - prior_set
    removed = prior_set - proposed_set
    return len(added) + len(removed)


@dataclass(frozen=True)
class AmendmentProposal:
    """Typed diff from ``prior`` to ``proposed`` at ``to_epoch``."""

    prior: ConstitutionVersion
    proposed: ConstitutionVersion
    drift_budget: DriftBudget = field(default_factory=DriftBudget)

    def __post_init__(self) -> None:
        if self.proposed.epoch != self.prior.epoch + 1:
            raise EpochMismatchError(
                "proposed epoch must be prior.epoch + 1 "
                f"(prior={self.prior.epoch}, proposed={self.proposed.epoch})"
            )
        if self.proposed.parent_digest != self.prior.digest:
            raise InvalidTransitionError("proposed.parent_digest must equal prior.digest")

    @property
    def drift(self) -> int:
        return evaluate_drift(self.prior, self.proposed)


@dataclass(frozen=True)
class TransitionCertificate:
    """Joint-consensus ratification of an AmendmentProposal.

    ``old_side_signers`` and ``new_side_signers`` are the sets of
    validator identifiers that signed the proposal under the outgoing
    and incoming validator sets respectively. Quorum thresholds are
    expressed as stake counts to stay agnostic of BFT weight schemes.
    """

    proposal: AmendmentProposal
    old_side_signers: frozenset[str]
    new_side_signers: frozenset[str]
    old_side_threshold: int
    new_side_threshold: int

    def __post_init__(self) -> None:
        if self.old_side_threshold <= 0 or self.new_side_threshold <= 0:
            raise InvalidTransitionError("thresholds must be positive")


def _stake_sum(
    signers: Iterable[str],
    stake: dict[str, int],
) -> int:
    total = 0
    for s in signers:
        if s not in stake:
            raise InvalidTransitionError(f"signer {s!r} not in validator set")
        if stake[s] <= 0:
            raise InvalidTransitionError(f"signer {s!r} has non-positive stake")
        total += stake[s]
    return total


def verify_transition(
    certificate: TransitionCertificate,
    *,
    old_stake: dict[str, int],
    new_stake: dict[str, int],
) -> None:
    """Validate a transition certificate under joint consensus.

    Raises one of the :class:`InvalidTransitionError` subclasses if the
    certificate is not admissible. Returns ``None`` on success.
    """
    proposal = certificate.proposal

    # Drift budget is evaluated before quorum: cheap reject first.
    drift = proposal.drift
    if drift > proposal.drift_budget.max_rule_delta:
        raise DriftBudgetExceeded(
            f"rule drift {drift} exceeds budget {proposal.drift_budget.max_rule_delta}"
        )

    # Signers must live in their respective validator sets.
    unknown_old = certificate.old_side_signers - old_stake.keys()
    if unknown_old:
        raise JointQuorumNotMetError(
            f"old-side signers not in old validator set: {sorted(unknown_old)}"
        )
    unknown_new = certificate.new_side_signers - new_stake.keys()
    if unknown_new:
        raise JointQuorumNotMetError(
            f"new-side signers not in new validator set: {sorted(unknown_new)}"
        )

    old_support = _stake_sum(certificate.old_side_signers, old_stake)
    new_support = _stake_sum(certificate.new_side_signers, new_stake)

    if old_support < certificate.old_side_threshold:
        raise JointQuorumNotMetError(
            f"old-side stake {old_support} < threshold {certificate.old_side_threshold}"
        )
    if new_support < certificate.new_side_threshold:
        raise JointQuorumNotMetError(
            f"new-side stake {new_support} < threshold {certificate.new_side_threshold}"
        )
