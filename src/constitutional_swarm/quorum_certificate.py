"""Quorum certificates with accountable safety (slashable conflicting votes).

Phase 7.1 breakthrough: a :class:`QuorumCertificate` bundles signed
votes from a committee on a single artifact. Two conflicting QCs over
the same (assignment_id, epoch) constitute slashable evidence — the
signers in the intersection equivocated.

Accountable safety: if safety is violated (two conflicting artifacts
finalize in the same epoch), the protocol can identify a set of
validators whose signatures prove the equivocation, and slash them.
This is the Byzantine-safe fallback when the 1/3 bound is crossed —
we cannot prevent conflicting finalizations under majority adversary,
but we *can* guarantee there is always a slashable proof.

References
----------
- HotStuff (Yin et al. 2019) — accountable safety via quorum certificates
- Casper FFG (Buterin & Griffith 2017) — slashing conditions
- Ethereum 2.0 accountable safety spec

This module is transport-agnostic: QCs are built from Ed25519-signed
votes and can be serialized to JSON for wire / merkle_crdt storage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.validator_set import (
    CommitteeSelection,
    ValidatorSet,
)

__all__ = [
    "SignedVote",
    "QuorumCertificate",
    "ConflictEvidence",
    "InsufficientQuorumError",
    "InvalidCertificateError",
    "build_certificate",
    "detect_conflict",
    "verify_certificate",
]


class InsufficientQuorumError(ValueError):
    """Raised when votes do not meet the quorum threshold."""


class InvalidCertificateError(ValueError):
    """Raised when a certificate fails verification (bad signature, etc.)."""


@dataclass(frozen=True)
class SignedVote:
    """An Ed25519-signed vote on ``(assignment_id, artifact_hash, epoch)``.

    The tuple is the vote's domain-separated payload: a single signer
    cannot produce two votes with the same ``(assignment_id, epoch)``
    but different ``artifact_hash`` without exposing themselves to
    slashing.
    """

    voter_id: str
    assignment_id: str
    artifact_hash: str
    epoch: int
    signature: bytes
    public_key_bytes: bytes  # raw Ed25519 public key (32 bytes)

    def message(self) -> bytes:
        """Canonical signable message for this vote."""
        return build_vote_message(
            self.assignment_id, self.artifact_hash, self.epoch
        )

    def verify(self) -> bool:
        """Verify the Ed25519 signature. Returns False on any failure."""
        try:
            pk = Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
            pk.verify(self.signature, self.message())
            return True
        except (InvalidSignature, ValueError):
            return False


def build_vote_message(
    assignment_id: str, artifact_hash: str, epoch: int
) -> bytes:
    """Canonical signable message.

    Domain-separated: the ``"cs-qc-v1"`` prefix prevents replay of
    signatures into other protocols. Epoch is included so the same
    artifact in a later epoch requires a fresh signature.
    """
    payload = {
        "v": 1,
        "kind": "cs-qc-v1",
        "assignment_id": assignment_id,
        "artifact_hash": artifact_hash,
        "epoch": int(epoch),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class QuorumCertificate:
    """Immutable bundle of signed votes meeting a weight threshold.

    Attributes
    ----------
    assignment_id, artifact_hash, epoch:
        Identify the vote subject.
    votes:
        Tuple of :class:`SignedVote` entries (one per signer).
    threshold_weight, achieved_weight:
        Threshold required, and total capped weight achieved.
    committee_seed:
        The VRF seed that selected the committee — required for
        independent verifiers to reconstruct the expected committee.
    """

    assignment_id: str
    artifact_hash: str
    epoch: int
    votes: tuple[SignedVote, ...]
    threshold_weight: float
    achieved_weight: float
    committee_seed: str = ""

    @property
    def voter_ids(self) -> frozenset[str]:
        return frozenset(v.voter_id for v in self.votes)

    def qc_id(self) -> str:
        """Stable SHA-256 hash identifying the QC (for dedup / indexing)."""
        body = json.dumps(
            {
                "assignment_id": self.assignment_id,
                "artifact_hash": self.artifact_hash,
                "epoch": self.epoch,
                "voters": sorted(self.voter_ids),
                "seed": self.committee_seed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation (for merkle_crdt storage)."""
        return {
            "v": 1,
            "assignment_id": self.assignment_id,
            "artifact_hash": self.artifact_hash,
            "epoch": self.epoch,
            "threshold_weight": self.threshold_weight,
            "achieved_weight": self.achieved_weight,
            "committee_seed": self.committee_seed,
            "votes": [
                {
                    "voter_id": v.voter_id,
                    "signature": v.signature.hex(),
                    "public_key": v.public_key_bytes.hex(),
                }
                for v in self.votes
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "QuorumCertificate":
        """Inverse of :meth:`to_dict`."""
        assignment_id = data["assignment_id"]
        artifact_hash = data["artifact_hash"]
        epoch = int(data["epoch"])
        votes = tuple(
            SignedVote(
                voter_id=v["voter_id"],
                assignment_id=assignment_id,
                artifact_hash=artifact_hash,
                epoch=epoch,
                signature=bytes.fromhex(v["signature"]),
                public_key_bytes=bytes.fromhex(v["public_key"]),
            )
            for v in data["votes"]
        )
        return cls(
            assignment_id=assignment_id,
            artifact_hash=artifact_hash,
            epoch=epoch,
            votes=votes,
            threshold_weight=float(data["threshold_weight"]),
            achieved_weight=float(data["achieved_weight"]),
            committee_seed=str(data.get("committee_seed", "")),
        )


@dataclass(frozen=True)
class ConflictEvidence:
    """Slashable evidence: two QCs with same (assignment, epoch) but different hashes.

    ``equivocators`` is the set of voter_ids that signed both
    conflicting QCs — these are the slashable parties. ``qc_a`` and
    ``qc_b`` are the two certificates; exactly one artifact_hash of
    each is legitimate, the other is the equivocating claim.
    """

    qc_a: QuorumCertificate
    qc_b: QuorumCertificate
    equivocators: frozenset[str]

    def is_slashable(self) -> bool:
        """True iff there is at least one equivocator proved by signatures."""
        return bool(self.equivocators) and self.qc_a.qc_id() != self.qc_b.qc_id()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def build_certificate(
    votes: Iterable[SignedVote],
    *,
    committee: CommitteeSelection,
    validator_set: ValidatorSet,
    threshold_fraction: float = 2 / 3,
) -> QuorumCertificate:
    """Build a :class:`QuorumCertificate` from committee votes.

    Validates:
      1. Every vote's signature verifies.
      2. Every voter is a member of ``committee``.
      3. All votes share the same ``(assignment_id, artifact_hash, epoch)``.
      4. Total capped weight meets ``threshold_fraction * committee.weight``.

    Raises
    ------
    InsufficientQuorumError
        If accumulated capped weight does not reach the threshold.
    InvalidCertificateError
        On signature or membership mismatch.
    """
    vote_list = list(votes)
    if not vote_list:
        raise InsufficientQuorumError("no votes supplied")

    first = vote_list[0]
    assignment_id = first.assignment_id
    artifact_hash = first.artifact_hash
    epoch = first.epoch

    committee_ids = frozenset(committee.members)
    policy = validator_set.policy

    # Deduplicate by voter_id (first signature wins)
    seen: set[str] = set()
    ordered_votes: list[SignedVote] = []
    for v in vote_list:
        if v.voter_id in seen:
            continue
        if (
            v.assignment_id != assignment_id
            or v.artifact_hash != artifact_hash
            or v.epoch != epoch
        ):
            raise InvalidCertificateError(
                f"vote from {v.voter_id!r} does not match certificate subject "
                f"(assignment/artifact/epoch mismatch)"
            )
        if v.voter_id not in committee_ids:
            raise InvalidCertificateError(
                f"voter {v.voter_id!r} is not a member of the committee"
            )
        if not v.verify():
            raise InvalidCertificateError(
                f"signature from {v.voter_id!r} failed to verify"
            )
        seen.add(v.voter_id)
        ordered_votes.append(v)

    # Compute capped achieved weight
    # Per-domain cap is enforced as in CommitteeSelector.select: each
    # domain contributes min(domain_weight, ceiling) where
    # ceiling = policy.max_fraction * raw_committee_weight.
    raw_committee_weight = committee.weight
    ceiling = policy.max_fraction * raw_committee_weight
    per_domain_raw: dict[str, float] = {}
    for sv in ordered_votes:
        ident = validator_set.get(sv.voter_id)
        if ident is None:
            raise InvalidCertificateError(
                f"voter {sv.voter_id!r} is not in validator set"
            )
        domain = policy.resolve_domain(ident)
        per_domain_raw[domain] = (
            per_domain_raw.get(domain, 0.0) + ident.effective_weight
        )
    achieved_weight = sum(min(w, ceiling) for w in per_domain_raw.values())

    threshold_weight = threshold_fraction * raw_committee_weight
    if achieved_weight + 1e-12 < threshold_weight:
        raise InsufficientQuorumError(
            f"achieved capped weight {achieved_weight:.6f} < "
            f"threshold {threshold_weight:.6f} (threshold_fraction="
            f"{threshold_fraction:.3f}, raw committee weight="
            f"{raw_committee_weight:.6f})"
        )

    # Sort votes deterministically by voter_id so serialized QCs are
    # canonical.
    ordered_votes.sort(key=lambda v: v.voter_id)
    return QuorumCertificate(
        assignment_id=assignment_id,
        artifact_hash=artifact_hash,
        epoch=epoch,
        votes=tuple(ordered_votes),
        threshold_weight=threshold_weight,
        achieved_weight=achieved_weight,
        committee_seed=committee.seed,
    )


# ---------------------------------------------------------------------------
# Verification & conflict detection
# ---------------------------------------------------------------------------


def verify_certificate(
    qc: QuorumCertificate,
    *,
    validator_set: ValidatorSet,
) -> None:
    """Re-verify a QC against the current validator set.

    Raises
    ------
    InvalidCertificateError
        On any signature or structural failure.
    InsufficientQuorumError
        If the achieved weight no longer meets the threshold (e.g.
        a voter has been removed from the set).
    """
    if not qc.votes:
        raise InvalidCertificateError("empty QC")
    policy = validator_set.policy
    seen_voters: set[str] = set()
    per_domain: dict[str, float] = {}
    for sv in qc.votes:
        if sv.voter_id in seen_voters:
            raise InvalidCertificateError(
                f"duplicate voter {sv.voter_id!r} in QC"
            )
        if (
            sv.assignment_id != qc.assignment_id
            or sv.artifact_hash != qc.artifact_hash
            or sv.epoch != qc.epoch
        ):
            raise InvalidCertificateError("vote/QC subject mismatch")
        if not sv.verify():
            raise InvalidCertificateError(
                f"signature from {sv.voter_id!r} failed"
            )
        ident = validator_set.get(sv.voter_id)
        if ident is None:
            raise InvalidCertificateError(
                f"voter {sv.voter_id!r} not in validator set"
            )
        domain = policy.resolve_domain(ident)
        per_domain[domain] = per_domain.get(domain, 0.0) + ident.effective_weight
        seen_voters.add(sv.voter_id)

    # Recompute achieved weight against the *current* set & threshold
    # The QC stored its own achieved_weight — we trust the stored
    # threshold (signed by committee membership), but we recheck that
    # the current set still produces at least that weight.
    raw_total = sum(per_domain.values())
    ceiling = policy.max_fraction * raw_total if raw_total > 0 else 0.0
    # Conservative capping: if the QC's stored weights are stale, the
    # recomputed capped weight may differ. We accept if the recomputed
    # value is within 1e-9 of the stored value.
    recomputed = sum(min(w, ceiling) for w in per_domain.values())
    if recomputed + 1e-9 < qc.achieved_weight:
        raise InsufficientQuorumError(
            f"recomputed weight {recomputed:.6f} < stored {qc.achieved_weight:.6f}"
        )


def detect_conflict(
    qc_a: QuorumCertificate, qc_b: QuorumCertificate
) -> ConflictEvidence | None:
    """Return slashable evidence iff two QCs conflict.

    A conflict exists when both QCs are for the same
    ``(assignment_id, epoch)`` but different ``artifact_hash``. The
    equivocators are the voter_ids that signed both.

    Returns ``None`` if there is no conflict (same artifact or
    different assignment/epoch — the latter is not a safety issue).
    """
    if qc_a.assignment_id != qc_b.assignment_id:
        return None
    if qc_a.epoch != qc_b.epoch:
        return None
    if qc_a.artifact_hash == qc_b.artifact_hash:
        return None
    equivocators = qc_a.voter_ids & qc_b.voter_ids
    return ConflictEvidence(
        qc_a=qc_a, qc_b=qc_b, equivocators=equivocators
    )
