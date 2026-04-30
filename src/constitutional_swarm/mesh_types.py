"""Immutable public contracts for Constitutional Mesh.

This module is the stable data-model boundary for mesh assignments, votes,
remote vote requests, proofs, and results.  ``constitutional_swarm.mesh`` still
re-exports these names for backward compatibility, but new internal code should
import them from here so orchestration logic can be split away from contracts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from constitutional_swarm.mesh_crypto import compute_merkle_root


@dataclass(frozen=True, slots=True)
class PeerAssignment:
    """A validation assignment linking a producer's output to peer validators."""

    assignment_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    peers: tuple[str, ...]
    constitutional_hash: str
    timestamp: float


@dataclass(frozen=True, slots=True)
class ValidationVote:
    """A peer's Ed25519-signed vote on a producer's output."""

    assignment_id: str
    voter_id: str
    approved: bool
    reason: str
    signature: str
    constitutional_hash: str
    content_hash: str
    timestamp: float

    @property
    def vote_hash(self) -> str:
        """Deterministic hash of this vote for proof chain."""
        payload = (
            f"{self.assignment_id}:{self.voter_id}:{self.approved}"
            f":{self.reason}:{self.signature}:{self.constitutional_hash}:{self.content_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class RemoteVoteRequest:
    """Signable vote request for a public-key-only remote peer."""

    assignment_id: str
    voter_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    constitutional_hash: str
    voter_public_key: str
    request_signer_public_key: str
    request_signature: str


@dataclass(frozen=True, slots=True)
class MeshProof:
    """Cryptographic proof of peer validation.

    A Merkle-style proof linking the producer's output, each peer's vote,
    and the constitutional hash into a single verifiable root.
    Anyone can independently verify this proof.
    """

    assignment_id: str
    content_hash: str
    constitutional_hash: str
    vote_hashes: tuple[str, ...]
    root_hash: str
    accepted: bool
    timestamp: float

    def verify(self) -> bool:
        """Independently verify the proof chain."""
        recomputed = compute_merkle_root(
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
