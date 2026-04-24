"""Voting payload types for the Constitutional Mesh."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


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
    nonce: str
    timestamp: float
    request_signer_public_key: str
    request_signature: str
