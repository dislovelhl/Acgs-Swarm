"""Shared constants for constitutional_swarm.

Centralised to avoid silent hash drift across modules.
"""

# 64-bit configuration pin asserting which constitutional document version
# is active.  This is NOT a cryptographic commitment — all content hashing
# uses SHA-256.  See SECURITY.md for the threat model.
CONSTITUTIONAL_HASH: str = "608508a9bd224290"
