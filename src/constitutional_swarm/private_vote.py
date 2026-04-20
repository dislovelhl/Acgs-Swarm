"""Private auditable voting — commit-reveal with nullifiers (Phase 7.2 + 12).

This is a pragmatic first step toward MACI-style private voting for the
constitutional swarm. We use a classic commit-reveal scheme with
nullifiers to get three properties without heavy ZK machinery:

1. **Ballot privacy during collection** — commitments hide the vote
   until the reveal phase, so no voter can adaptively counter-vote.
2. **Double-vote prevention (sybil-within-identity)** — a deterministic
   nullifier derived from the voter's secret and the epoch/subject is
   published alongside the commit. Duplicate nullifiers are rejected.
3. **Auditable tally** — the tally is computed only from revealed
   votes whose commit verifies, and everyone can recompute it from the
   public log.

This is *not* full MACI: it does not hide the vote after reveal, and
relies on voters revealing.

**Phase 12 — validity-proof scaffold (v2 record).**  Commits can now
optionally carry a ``validity_proof`` attesting that the committed
choice is well-formed (membership in :class:`BallotChoice` and
signature-binding) *before* the reveal phase. The
:class:`ValidityProver` ``Protocol`` is the plug-in point for a future
Groth16/PLONK backend; the default :class:`HashCommitmentProver` is
**not** zero-knowledge (it re-binds the digest via a domain-separated
hash) but establishes the v2 wire format, versioning, and tally path
that a real SNARK backend can drop into without breaking clients.

Commit format (stable, JSON-serializable)::

    {
      "version": 1 | 2,
      "epoch": "<bytes hex>",
      "subject": "<bytes hex>",
      "voter": "<ed25519 pubkey hex>",
      "commit": "<sha256 hex>",
      "nullifier": "<sha256 hex>",
      "signature": "<ed25519 sig hex>",
      # v2 only:
      "proof_scheme": "<scheme-id | null>",
      "validity_proof": "<hex | null>",
    }

Reveal format::

    {
      "version": 1,
      "commit": "<sha256 hex>",
      "choice": "yea|nay|abstain",
      "nonce": "<hex>",
      "signature": "<ed25519 sig hex>",
    }

The tally function takes the set of commits and reveals and produces
a deterministic, auditable :class:`PrivateTally`.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "BallotChoice",
    "CommitRecord",
    "DoubleVoteError",
    "HashCommitmentProver",
    "InvalidCommitError",
    "InvalidRevealError",
    "InvalidValidityProofError",
    "MissingRevealError",
    "PrivateBallotBox",
    "PrivateTally",
    "RevealRecord",
    "ValidityProver",
    "ValidityStatement",
    "ValidityWitness",
    "ZKSnarkProver",
    "build_commit",
    "build_reveal",
    "compute_nullifier",
    "tally",
]

# Highest version this module emits; tally accepts anything in _SUPPORTED_VERSIONS.
_RECORD_VERSION = 1  # default write-version when no prover is supplied
_V2_VERSION = 2
_SUPPORTED_VERSIONS: frozenset[int] = frozenset({_RECORD_VERSION, _V2_VERSION})


class BallotChoice(StrEnum):
    """Canonical ballot choices. Extend cautiously — domain is part
    of the commit digest, so adding a choice changes every commit."""

    YEA = "yea"
    NAY = "nay"
    ABSTAIN = "abstain"


class PrivateVotingError(Exception):
    """Base class for private voting errors."""


class InvalidCommitError(PrivateVotingError):
    """Raised when a commit record fails validation."""


class InvalidRevealError(PrivateVotingError):
    """Raised when a reveal record does not match its commit."""


class DoubleVoteError(PrivateVotingError):
    """Raised when a duplicate nullifier is seen in the same epoch."""


class MissingRevealError(PrivateVotingError):
    """Raised when tally is invoked while some commits are unrevealed."""


class InvalidValidityProofError(PrivateVotingError):
    """Raised when a v2 commit's validity proof fails to verify."""


# ---------------------------------------------------------------------------
# Validity-proof plug-in surface (Phase 12)
#
# The default :class:`HashCommitmentProver` is **not** zero-knowledge — it
# binds a domain-separated hash of (scheme-id, commit-digest, voter pubkey,
# nullifier, choice) and stores that hash as the "proof". This establishes
# the v2 wire format and the tally verification path so a real SNARK
# backend can replace it later without breaking clients. A proper
# :class:`ZKSnarkProver` (Groth16/PLONK over the BallotChoice membership
# circuit) is left as a documented future extension; shipping it requires
# picking a SNARK toolchain and is explicitly out of scope here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidityStatement:
    """Public statement the validity proof attests to.

    A valid v2 commit says: "the preimage of ``commit`` is some
    :class:`BallotChoice`, and the same voter key signed it."
    """

    epoch: bytes
    subject: bytes
    voter: bytes
    commit: bytes
    nullifier: bytes


@dataclass(frozen=True)
class ValidityWitness:
    """Private witness held by the voter (never published)."""

    choice: BallotChoice
    nonce: bytes
    voter_secret: bytes


@runtime_checkable
class ValidityProver(Protocol):
    """Pluggable prover/verifier for v2 commit validity proofs.

    Implementations MUST be deterministic on ``(statement, witness)``
    for reproducibility in tests and audit logs. ``verify`` MUST return
    ``False`` rather than raise on malformed input; raise only on
    outright protocol violations (wrong scheme id, etc.).
    """

    scheme_id: str

    def prove(
        self, statement: ValidityStatement, witness: ValidityWitness
    ) -> bytes:  # pragma: no cover - Protocol
        ...

    def verify(
        self, statement: ValidityStatement, proof: bytes
    ) -> bool:  # pragma: no cover - Protocol
        ...


@dataclass(frozen=True)
class HashCommitmentProver:
    """Hash-based well-formedness binding. **Not zero-knowledge.**

    The "proof" is a domain-separated SHA-256 digest of
    ``(scheme_id, statement fields, choice)``. Anyone who knows the
    choice can recompute it — so this is NOT a ZK proof; it only adds
    a tamper-evident binding that v2 readers must verify. Use this as
    a drop-in until a real SNARK backend lands.
    """

    scheme_id: str = "hash-commitment-v1"

    def prove(
        self, statement: ValidityStatement, witness: ValidityWitness
    ) -> bytes:
        if witness.choice not in BallotChoice:
            raise ValueError("witness.choice must be a BallotChoice member")
        return _digest(
            b"acgs-validity-hashcommit-v1",
            self.scheme_id.encode("ascii"),
            statement.epoch,
            statement.subject,
            statement.voter,
            statement.commit,
            statement.nullifier,
            witness.choice.value.encode("ascii"),
        )

    def verify(self, statement: ValidityStatement, proof: bytes) -> bool:
        # Non-ZK verifier: re-derive the expected digest for EVERY choice
        # and accept if any matches. This keeps verification side-channel-
        # free w.r.t. the actual choice (the verifier already sees the
        # choice at reveal time; this check only binds the commit).
        if len(proof) != 32:
            return False
        for choice in BallotChoice:
            expected = _digest(
                b"acgs-validity-hashcommit-v1",
                self.scheme_id.encode("ascii"),
                statement.epoch,
                statement.subject,
                statement.voter,
                statement.commit,
                statement.nullifier,
                choice.value.encode("ascii"),
            )
            if expected == proof:
                return True
        return False


@runtime_checkable
class ZKSnarkProver(ValidityProver, Protocol):  # pragma: no cover - marker
    """Marker Protocol for a future Groth16/PLONK backend.

    A conforming implementation would:
      * Fix a circuit that checks ``choice ∈ {yea, nay, abstain}`` and
        that ``commit == H("acgs-commit-v1" || choice || nonce || ...)``.
      * Run the CRS/trusted-setup once per (epoch, subject) family.
      * Emit a ~200-byte SNARK proof (Groth16) or ~400-byte PLONK proof.

    This module ships the Protocol only; the actual circuit, setup,
    and verifier belong in a dedicated package gated behind an opt-in
    dependency (``arkworks-py``/``gnark``/``snarkjs``).
    """


# ---------------------------------------------------------------------------
# Pure-function primitives
# ---------------------------------------------------------------------------


def _digest(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.digest()


def compute_nullifier(
    voter_secret: bytes,
    epoch: bytes,
    subject: bytes,
) -> bytes:
    """Deterministic, privacy-preserving double-vote tag.

    Derived from the voter's long-term secret bound to the
    (epoch, subject) tuple. Two commits with the same nullifier must
    come from the same voter on the same subject/epoch, regardless of
    which ephemeral identity they publish.
    """
    if not voter_secret:
        raise ValueError("voter_secret must be non-empty")
    return _digest(b"acgs-null-v1", voter_secret, epoch, subject)


def _commit_digest(
    choice: BallotChoice,
    nonce: bytes,
    epoch: bytes,
    subject: bytes,
) -> bytes:
    return _digest(
        b"acgs-commit-v1",
        choice.value.encode("ascii"),
        nonce,
        epoch,
        subject,
    )


def _signing_payload_commit(
    epoch: bytes,
    subject: bytes,
    voter_pub: bytes,
    commit: bytes,
    nullifier: bytes,
) -> bytes:
    return _digest(
        b"acgs-commit-sig-v1", epoch, subject, voter_pub, commit, nullifier
    )


def _signing_payload_reveal(commit: bytes, choice: BallotChoice, nonce: bytes) -> bytes:
    return _digest(
        b"acgs-reveal-sig-v1", commit, choice.value.encode("ascii"), nonce
    )


# ---------------------------------------------------------------------------
# Record types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitRecord:
    """Published commit to a private vote.

    The ``voter`` field is the Ed25519 public key that signed this
    commit; the nullifier is what prevents double-voting across
    ephemeral identities.

    v2 records additionally carry ``proof_scheme`` + ``validity_proof``.
    v1 records set both to ``None`` (backward-compatible wire format).
    """

    version: int
    epoch: bytes
    subject: bytes
    voter: bytes  # Ed25519 pubkey raw (32 bytes)
    commit: bytes  # 32 bytes
    nullifier: bytes  # 32 bytes
    signature: bytes  # 64 bytes
    proof_scheme: str | None = None
    validity_proof: bytes | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        out: dict[str, str | int | None] = {
            "version": self.version,
            "epoch": self.epoch.hex(),
            "subject": self.subject.hex(),
            "voter": self.voter.hex(),
            "commit": self.commit.hex(),
            "nullifier": self.nullifier.hex(),
            "signature": self.signature.hex(),
        }
        if self.version >= _V2_VERSION:
            out["proof_scheme"] = self.proof_scheme
            out["validity_proof"] = (
                self.validity_proof.hex() if self.validity_proof is not None else None
            )
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> CommitRecord:
        try:
            version = int(data["version"])  # type: ignore[arg-type]
            proof_scheme: str | None = None
            validity_proof: bytes | None = None
            if version >= _V2_VERSION:
                raw_scheme = data.get("proof_scheme")
                proof_scheme = None if raw_scheme is None else str(raw_scheme)
                raw_proof = data.get("validity_proof")
                validity_proof = (
                    None if raw_proof is None else bytes.fromhex(str(raw_proof))
                )
            return cls(
                version=version,
                epoch=bytes.fromhex(str(data["epoch"])),
                subject=bytes.fromhex(str(data["subject"])),
                voter=bytes.fromhex(str(data["voter"])),
                commit=bytes.fromhex(str(data["commit"])),
                nullifier=bytes.fromhex(str(data["nullifier"])),
                signature=bytes.fromhex(str(data["signature"])),
                proof_scheme=proof_scheme,
                validity_proof=validity_proof,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidCommitError(f"malformed commit dict: {exc}") from exc


@dataclass(frozen=True)
class RevealRecord:
    """Published reveal for a prior commit."""

    version: int
    commit: bytes
    choice: BallotChoice
    nonce: bytes
    signature: bytes  # Ed25519 sig over the reveal payload

    def to_dict(self) -> dict[str, str | int]:
        return {
            "version": self.version,
            "commit": self.commit.hex(),
            "choice": self.choice.value,
            "nonce": self.nonce.hex(),
            "signature": self.signature.hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RevealRecord:
        try:
            return cls(
                version=int(data["version"]),  # type: ignore[arg-type]
                commit=bytes.fromhex(str(data["commit"])),
                choice=BallotChoice(str(data["choice"])),
                nonce=bytes.fromhex(str(data["nonce"])),
                signature=bytes.fromhex(str(data["signature"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidRevealError(f"malformed reveal dict: {exc}") from exc


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_commit(
    *,
    voter_private_key: Ed25519PrivateKey,
    voter_secret: bytes,
    epoch: bytes,
    subject: bytes,
    choice: BallotChoice,
    nonce: bytes | None = None,
    prover: ValidityProver | None = None,
) -> tuple[CommitRecord, RevealRecord]:
    """Create a commit + matching reveal for a single voter.

    The reveal is *not yet signed* with the commit field filled in
    because we need to produce both atomically. Returns both; the
    voter publishes ``commit`` now and ``reveal`` in the reveal phase.

    If ``prover`` is supplied the commit is emitted as a v2 record
    carrying a ``validity_proof`` attesting that the committed choice
    is a well-formed :class:`BallotChoice`. When ``prover`` is None
    the legacy v1 format is used.
    """
    if nonce is None:
        nonce = secrets.token_bytes(32)
    if len(nonce) < 16:
        raise ValueError("nonce must be at least 16 bytes")

    commit_digest = _commit_digest(choice, nonce, epoch, subject)
    nullifier = compute_nullifier(voter_secret, epoch, subject)

    from cryptography.hazmat.primitives import serialization as _ser  # local

    voter_pub_raw = voter_private_key.public_key().public_bytes(
        encoding=_ser.Encoding.Raw,
        format=_ser.PublicFormat.Raw,
    )

    commit_sig = voter_private_key.sign(
        _signing_payload_commit(
            epoch, subject, voter_pub_raw, commit_digest, nullifier
        )
    )
    reveal_sig = voter_private_key.sign(
        _signing_payload_reveal(commit_digest, choice, nonce)
    )

    proof_scheme: str | None = None
    validity_proof: bytes | None = None
    record_version = _RECORD_VERSION
    if prover is not None:
        statement = ValidityStatement(
            epoch=epoch,
            subject=subject,
            voter=voter_pub_raw,
            commit=commit_digest,
            nullifier=nullifier,
        )
        witness = ValidityWitness(
            choice=choice, nonce=nonce, voter_secret=voter_secret
        )
        validity_proof = prover.prove(statement, witness)
        proof_scheme = prover.scheme_id
        record_version = _V2_VERSION

    commit_record = CommitRecord(
        version=record_version,
        epoch=epoch,
        subject=subject,
        voter=voter_pub_raw,
        commit=commit_digest,
        nullifier=nullifier,
        signature=commit_sig,
        proof_scheme=proof_scheme,
        validity_proof=validity_proof,
    )
    reveal_record = RevealRecord(
        version=record_version,
        commit=commit_digest,
        choice=choice,
        nonce=nonce,
        signature=reveal_sig,
    )
    return commit_record, reveal_record


def build_reveal(
    *,
    voter_private_key: Ed25519PrivateKey,
    commit: bytes,
    choice: BallotChoice,
    nonce: bytes,
) -> RevealRecord:
    """Create a reveal record for a previously built commit."""
    reveal_sig = voter_private_key.sign(
        _signing_payload_reveal(commit, choice, nonce)
    )
    return RevealRecord(
        version=_RECORD_VERSION,
        commit=commit,
        choice=choice,
        nonce=nonce,
        signature=reveal_sig,
    )


# ---------------------------------------------------------------------------
# Validation + tally
# ---------------------------------------------------------------------------


def _verify_commit_signature(record: CommitRecord) -> None:
    try:
        pub = Ed25519PublicKey.from_public_bytes(record.voter)
    except ValueError as exc:
        raise InvalidCommitError(f"bad voter pubkey: {exc}") from exc
    payload = _signing_payload_commit(
        record.epoch,
        record.subject,
        record.voter,
        record.commit,
        record.nullifier,
    )
    try:
        pub.verify(record.signature, payload)
    except InvalidSignature as exc:
        raise InvalidCommitError("bad commit signature") from exc


def _verify_reveal_against_commit(
    reveal: RevealRecord, commit_record: CommitRecord
) -> None:
    expected = _commit_digest(
        reveal.choice, reveal.nonce, commit_record.epoch, commit_record.subject
    )
    if expected != commit_record.commit:
        raise InvalidRevealError("reveal does not open the commit")
    try:
        pub = Ed25519PublicKey.from_public_bytes(commit_record.voter)
    except ValueError as exc:
        raise InvalidRevealError(f"bad voter pubkey: {exc}") from exc
    payload = _signing_payload_reveal(reveal.commit, reveal.choice, reveal.nonce)
    try:
        pub.verify(reveal.signature, payload)
    except InvalidSignature as exc:
        raise InvalidRevealError("bad reveal signature") from exc


@dataclass(frozen=True)
class PrivateTally:
    """Deterministic tally result for an epoch/subject pair."""

    epoch: bytes
    subject: bytes
    totals: Mapping[BallotChoice, int]
    accepted: tuple[bytes, ...] = field(default_factory=tuple)
    rejected: tuple[tuple[bytes, str], ...] = field(default_factory=tuple)

    @property
    def total_valid(self) -> int:
        return sum(self.totals.values())

    def to_dict(self) -> dict[str, object]:
        return {
            "epoch": self.epoch.hex(),
            "subject": self.subject.hex(),
            "totals": {k.value: v for k, v in self.totals.items()},
            "accepted": [c.hex() for c in self.accepted],
            "rejected": [(c.hex(), reason) for c, reason in self.rejected],
        }


def tally(
    commits: Iterable[CommitRecord],
    reveals: Iterable[RevealRecord],
    *,
    epoch: bytes,
    subject: bytes,
    require_all_revealed: bool = False,
    provers: Mapping[str, ValidityProver] | None = None,
    strict_v2: bool = False,
) -> PrivateTally:
    """Audit commits + reveals and produce a deterministic tally.

    Rules:
      * Every commit's Ed25519 signature must verify.
      * Duplicate nullifiers in the same (epoch, subject) are rejected
        as :class:`DoubleVoteError` evidence — only the first commit
        (by byte-order of its digest) counts, matching the mesh's
        first-signature-wins convention.
      * A commit with no matching reveal is counted as missing.
      * Each reveal must open its commit and its signature must verify.
      * Only commits that are accepted *and* have a valid reveal
        contribute to totals.
      * When ``strict_v2`` is True, legacy v1 commits are rejected.
      * v2 commits with a ``proof_scheme`` must have their
        ``validity_proof`` verified by a matching entry in
        ``provers``. If no prover is registered for the declared
        scheme, the commit is rejected (fail-closed).
    """
    commits = list(commits)
    reveals_by_commit: dict[bytes, RevealRecord] = {}
    for rv in reveals:
        # Deterministic conflict rule: first reveal wins.
        reveals_by_commit.setdefault(rv.commit, rv)

    # Filter by epoch/subject + verify commit signatures + nullifier dedup.
    seen_nullifiers: dict[bytes, CommitRecord] = {}
    accepted: list[CommitRecord] = []
    rejected: list[tuple[bytes, str]] = []
    provers_map: Mapping[str, ValidityProver] = provers or {}

    # Sort by commit digest for deterministic first-wins ordering.
    for c in sorted(commits, key=lambda r: r.commit):
        if c.version not in _SUPPORTED_VERSIONS:
            rejected.append((c.commit, f"unsupported commit version {c.version}"))
            continue
        if strict_v2 and c.version < _V2_VERSION:
            rejected.append((c.commit, "strict_v2: legacy v1 commit rejected"))
            continue
        if c.epoch != epoch or c.subject != subject:
            rejected.append((c.commit, "epoch/subject mismatch"))
            continue
        try:
            _verify_commit_signature(c)
        except InvalidCommitError as exc:
            rejected.append((c.commit, str(exc)))
            continue
        # v2 validity proof verification (fail-closed)
        if c.version >= _V2_VERSION and c.proof_scheme is not None:
            prover = provers_map.get(c.proof_scheme)
            if prover is None:
                rejected.append(
                    (c.commit, f"no verifier for scheme {c.proof_scheme!r}")
                )
                continue
            if c.validity_proof is None:
                rejected.append((c.commit, "proof_scheme set but validity_proof absent"))
                continue
            statement = ValidityStatement(
                epoch=c.epoch,
                subject=c.subject,
                voter=c.voter,
                commit=c.commit,
                nullifier=c.nullifier,
            )
            if not prover.verify(statement, c.validity_proof):
                rejected.append((c.commit, "invalid validity proof"))
                continue
        prior = seen_nullifiers.get(c.nullifier)
        if prior is not None:
            rejected.append((c.commit, "duplicate nullifier"))
            continue
        seen_nullifiers[c.nullifier] = c
        accepted.append(c)

    if require_all_revealed:
        missing = [c.commit for c in accepted if c.commit not in reveals_by_commit]
        if missing:
            raise MissingRevealError(
                f"{len(missing)} accepted commits have no reveal"
            )

    totals: dict[BallotChoice, int] = {ch: 0 for ch in BallotChoice}
    tallied_commits: list[bytes] = []
    for c in accepted:
        rv = reveals_by_commit.get(c.commit)
        if rv is None:
            rejected.append((c.commit, "missing reveal"))
            continue
        try:
            _verify_reveal_against_commit(rv, c)
        except InvalidRevealError as exc:
            rejected.append((c.commit, str(exc)))
            continue
        totals[rv.choice] += 1
        tallied_commits.append(c.commit)

    return PrivateTally(
        epoch=epoch,
        subject=subject,
        totals=totals,
        accepted=tuple(tallied_commits),
        rejected=tuple(rejected),
    )


# ---------------------------------------------------------------------------
# Stateful helper (nice-to-have for tests / integration)
# ---------------------------------------------------------------------------


@dataclass
class PrivateBallotBox:
    """In-memory ballot box tracking commits then reveals for one epoch/subject.

    Thin wrapper around :func:`tally` that enforces the two-phase
    commit/reveal discipline. Useful for tests and for embedding in
    mesh services.
    """

    epoch: bytes
    subject: bytes
    _commits: dict[bytes, CommitRecord] = field(default_factory=dict)
    _nullifiers: dict[bytes, bytes] = field(default_factory=dict)  # nullifier -> commit
    _reveals: dict[bytes, RevealRecord] = field(default_factory=dict)
    _closed_commits: bool = False

    def submit_commit(self, record: CommitRecord) -> None:
        if self._closed_commits:
            raise InvalidCommitError("commit phase already closed")
        if record.epoch != self.epoch or record.subject != self.subject:
            raise InvalidCommitError("epoch/subject mismatch")
        if record.commit in self._commits:
            raise InvalidCommitError("duplicate commit digest")
        _verify_commit_signature(record)
        prior = self._nullifiers.get(record.nullifier)
        if prior is not None and prior != record.commit:
            raise DoubleVoteError("nullifier reuse")
        self._commits[record.commit] = record
        self._nullifiers[record.nullifier] = record.commit

    def close_commit_phase(self) -> None:
        self._closed_commits = True

    def submit_reveal(self, record: RevealRecord) -> None:
        if not self._closed_commits:
            raise InvalidRevealError("reveal phase not open")
        commit_record = self._commits.get(record.commit)
        if commit_record is None:
            raise InvalidRevealError("no matching commit")
        _verify_reveal_against_commit(record, commit_record)
        self._reveals.setdefault(record.commit, record)

    def tally(
        self,
        *,
        require_all_revealed: bool = False,
        provers: Mapping[str, ValidityProver] | None = None,
        strict_v2: bool = False,
    ) -> PrivateTally:
        return tally(
            self._commits.values(),
            self._reveals.values(),
            epoch=self.epoch,
            subject=self.subject,
            require_all_revealed=require_all_revealed,
            provers=provers,
            strict_v2=strict_v2,
        )
