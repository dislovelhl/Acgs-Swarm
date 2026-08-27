"""Persistence-independent APCC SHA-256 and Ed25519 primitives."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROPOSAL_DOMAIN = b"APCC-PROPOSAL-V1"
POLICY_DOMAIN = b"APCC-POLICY-V1"
AUTHORITY_DOMAIN = b"APCC-AUTHORITY-V1"
COMMIT_DOMAIN = b"APCC-COMMIT-V1"
AUTHORITY_STATUS_DOMAIN = b"APCC-AUTHORITY-STATUS-V1"
_DOMAINS = frozenset(
    {
        PROPOSAL_DOMAIN,
        POLICY_DOMAIN,
        AUTHORITY_DOMAIN,
        COMMIT_DOMAIN,
        AUTHORITY_STATUS_DOMAIN,
    }
)


def b64u_encode(value: bytes) -> str:
    """Return canonical unpadded base64url."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str, *, expected_length: int | None = None) -> bytes:
    """Decode canonical unpadded base64url, rejecting alternate spellings."""
    if "=" in value:
        raise ValueError("padded base64url is forbidden")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url") from exc
    if b64u_encode(decoded) != value:
        raise ValueError("noncanonical base64url")
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("unexpected decoded length")
    return decoded


def sha256_digest(value: bytes) -> str:
    """Hash exact bytes and return the canonical APCC digest spelling."""
    return b64u_encode(hashlib.sha256(value).digest())


def domain_preimage(domain: bytes, payload: bytes) -> bytes:
    """Construct an exact APCC v1 domain-separated signature preimage."""
    if domain not in _DOMAINS:
        raise ValueError("unknown APCC signature domain")
    return domain + b"\x00" + payload


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive a raw Ed25519 public key from a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def sign_detached(seed: bytes, domain: bytes, payload: bytes) -> str:
    """Sign one domain-separated payload with a raw Ed25519 seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
        domain_preimage(domain, payload)
    )
    return b64u_encode(signature)


def verify_detached(
    public_key: bytes, domain: bytes, payload: bytes, signature_b64u: str
) -> bool:
    """Verify a domain-separated Ed25519 signature without raising."""
    if len(public_key) != 32:
        return False
    try:
        signature = b64u_decode(signature_b64u, expected_length=64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, domain_preimage(domain, payload)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def predecessor_root(predecessors: Sequence[Mapping[str, str] | object]) -> str:
    """Hash the APCC-CJ1 canonical predecessor semantic set."""
    from .codec import canonical_predecessors

    objects: list[Mapping[str, str]] = []
    for predecessor in predecessors:
        if isinstance(predecessor, Mapping):
            objects.append(predecessor)
        else:
            to_object = getattr(predecessor, "to_object", None)
            if to_object is None:
                raise TypeError("predecessor must be a mapping or protocol record")
            objects.append(to_object())
    return sha256_digest(canonical_predecessors(objects))
