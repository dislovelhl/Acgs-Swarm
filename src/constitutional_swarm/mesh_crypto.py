"""Cryptographic helpers for Constitutional Mesh proofs and votes."""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def vote_payload_bytes(
    *,
    assignment_id: str,
    voter_id: str,
    approved: bool,
    reason: str,
    constitutional_hash: str,
    content_hash: str,
) -> bytes:
    """Build the canonical byte payload that peers sign for votes."""
    payload = f"{assignment_id}:{voter_id}:{approved}:{reason}:{constitutional_hash}:{content_hash}"
    return payload.encode("utf-8")


def coerce_public_key(value: Ed25519PublicKey | bytes | str) -> Ed25519PublicKey:
    """Normalize a raw/hex Ed25519 public key into a cryptography object."""
    if isinstance(value, Ed25519PublicKey):
        return value
    raw = bytes.fromhex(value) if isinstance(value, str) else value
    return Ed25519PublicKey.from_public_bytes(raw)


def coerce_private_key(value: Ed25519PrivateKey | bytes | str) -> Ed25519PrivateKey:
    """Normalize a raw/hex Ed25519 private key into a cryptography object."""
    if isinstance(value, Ed25519PrivateKey):
        return value
    raw = bytes.fromhex(value) if isinstance(value, str) else value
    return Ed25519PrivateKey.from_private_bytes(raw)


def verify_vote_signature(
    *,
    public_key: Ed25519PublicKey | bytes | str,
    assignment_id: str,
    voter_id: str,
    approved: bool,
    reason: str,
    constitutional_hash: str,
    content_hash: str,
    signature: str,
) -> bool:
    """Verify a detached Ed25519 vote signature."""
    key = coerce_public_key(public_key)
    try:
        key.verify(
            bytes.fromhex(signature),
            vote_payload_bytes(
                assignment_id=assignment_id,
                voter_id=voter_id,
                approved=approved,
                reason=reason,
                constitutional_hash=constitutional_hash,
                content_hash=content_hash,
            ),
        )
    except (ValueError, InvalidSignature):
        return False
    return True


def compute_merkle_root(
    assignment_id: str,
    content_hash: str,
    constitutional_hash: str,
    vote_hashes: tuple[str, ...],
    accepted: bool,
) -> str:
    """Compute the legacy-compatible Merkle root for a validation proof."""
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
