"""Settlement and proof types for the Constitutional Mesh."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


def _compute_merkle_root(
    assignment_id: str,
    content_hash: str,
    constitutional_hash: str,
    vote_hashes: tuple[str, ...],
    accepted: bool,
) -> str:
    """Compute the Merkle root for a validation proof."""
    leaf = hashlib.sha256(
        f"{assignment_id}:{content_hash}:{constitutional_hash}:{accepted}".encode()
    ).hexdigest()[:32]

    if not vote_hashes:
        votes_root = hashlib.sha256(b"empty").hexdigest()[:32]
    else:
        votes_root = vote_hashes[0]
        for vote_hash in vote_hashes[1:]:
            votes_root = hashlib.sha256(f"{votes_root}:{vote_hash}".encode()).hexdigest()[:32]

    return hashlib.sha256(f"{leaf}:{votes_root}".encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class MeshProof:
    """Cryptographic proof of peer validation."""

    assignment_id: str
    content_hash: str
    constitutional_hash: str
    vote_hashes: tuple[str, ...]
    root_hash: str
    accepted: bool
    timestamp: float

    def verify(self) -> bool:
        """Independently verify the proof chain."""
        recomputed = _compute_merkle_root(
            self.assignment_id,
            self.content_hash,
            self.constitutional_hash,
            self.vote_hashes,
            self.accepted,
        )
        return recomputed == self.root_hash


@dataclass(frozen=True, slots=True)
class MeshResult:
    """Result of a peer validation with cryptographic proof."""

    assignment_id: str
    accepted: bool
    votes_for: int
    votes_against: int
    quorum_met: bool
    pending_votes: int
    constitutional_hash: str
    proof: MeshProof | None
    settled: bool = False
    settled_at: float | None = None


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """Observable summary of one pending-settlement reconciliation pass."""

    attempted: int = 0
    settled: int = 0
    skipped_recovered: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def as_log_fields(self) -> dict[str, Any]:
        """Return a structured log payload for this reconciliation pass."""
        return {
            "attempted": self.attempted,
            "settled": self.settled,
            "skipped_recovered": self.skipped_recovered,
            "failed": self.failed,
            "errors": list(self.errors),
        }
