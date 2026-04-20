"""Tests for private_vote.py — commit-reveal + nullifier voting."""

from __future__ import annotations

import pytest
from constitutional_swarm.private_vote import (
    BallotChoice,
    CommitRecord,
    DoubleVoteError,
    InvalidCommitError,
    InvalidRevealError,
    MissingRevealError,
    PrivateBallotBox,
    RevealRecord,
    build_commit,
    build_reveal,
    compute_nullifier,
    tally,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EPOCH = bytes.fromhex("00" * 16)
SUBJECT = bytes.fromhex("11" * 16)


def _kp():
    sk = Ed25519PrivateKey.generate()
    return sk


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


class TestNullifier:
    def test_deterministic(self):
        secret = b"voter-seed-1"
        n1 = compute_nullifier(secret, EPOCH, SUBJECT)
        n2 = compute_nullifier(secret, EPOCH, SUBJECT)
        assert n1 == n2

    def test_epoch_separation(self):
        secret = b"voter-seed-1"
        n1 = compute_nullifier(secret, EPOCH, SUBJECT)
        n2 = compute_nullifier(secret, bytes.fromhex("ff" * 16), SUBJECT)
        n3 = compute_nullifier(secret, EPOCH, bytes.fromhex("ff" * 16))
        assert len({n1, n2, n3}) == 3

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError):
            compute_nullifier(b"", EPOCH, SUBJECT)


# ---------------------------------------------------------------------------
# Build + verify
# ---------------------------------------------------------------------------


class TestBuildCommit:
    def test_round_trip_via_dict(self):
        sk = _kp()
        c, r = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs-1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        c2 = CommitRecord.from_dict(c.to_dict())
        r2 = RevealRecord.from_dict(r.to_dict())
        assert c2 == c
        assert r2 == r

    def test_nonce_too_short(self):
        sk = _kp()
        with pytest.raises(ValueError, match="nonce"):
            build_commit(
                voter_private_key=sk,
                voter_secret=b"vs-1",
                epoch=EPOCH,
                subject=SUBJECT,
                choice=BallotChoice.YEA,
                nonce=b"short",
            )

    def test_commit_hides_choice(self):
        sk = _kp()
        nonce = b"\x42" * 32
        c_yea, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
            nonce=nonce,
        )
        c_nay, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"vs",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.NAY,
            nonce=nonce,
        )
        assert c_yea.commit != c_nay.commit
        # Nullifier is deterministic from (secret, epoch, subject)
        assert c_yea.nullifier == c_nay.nullifier


class TestBallotBox:
    def _fresh(self):
        return PrivateBallotBox(epoch=EPOCH, subject=SUBJECT)

    def _voter(self, box, choice, secret, sk=None):
        sk = sk or _kp()
        c, r = build_commit(
            voter_private_key=sk,
            voter_secret=secret,
            epoch=box.epoch,
            subject=box.subject,
            choice=choice,
        )
        box.submit_commit(c)
        return c, r, sk

    def test_happy_path_tally(self):
        box = self._fresh()
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1")
        _, r2, _ = self._voter(box, BallotChoice.YEA, b"s2")
        _, r3, _ = self._voter(box, BallotChoice.NAY, b"s3")
        box.close_commit_phase()
        box.submit_reveal(r1)
        box.submit_reveal(r2)
        box.submit_reveal(r3)
        result = box.tally(require_all_revealed=True)
        assert result.totals[BallotChoice.YEA] == 2
        assert result.totals[BallotChoice.NAY] == 1
        assert result.totals[BallotChoice.ABSTAIN] == 0
        assert result.total_valid == 3
        assert len(result.accepted) == 3
        assert result.rejected == ()

    def test_reveal_before_close_rejected(self):
        box = self._fresh()
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1")
        with pytest.raises(InvalidRevealError, match="phase"):
            box.submit_reveal(r1)

    def test_commit_after_close_rejected(self):
        box = self._fresh()
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"sX",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        box.close_commit_phase()
        with pytest.raises(InvalidCommitError, match="closed"):
            box.submit_commit(c)

    def test_missing_reveal_returns_rejected(self):
        box = self._fresh()
        _, r1, _ = self._voter(box, BallotChoice.YEA, b"s1")
        _, _, _ = self._voter(box, BallotChoice.NAY, b"s2")
        box.close_commit_phase()
        box.submit_reveal(r1)
        result = box.tally()
        assert result.totals[BallotChoice.YEA] == 1
        assert result.totals[BallotChoice.NAY] == 0
        assert any(reason == "missing reveal" for _, reason in result.rejected)

    def test_require_all_revealed_raises(self):
        box = self._fresh()
        self._voter(box, BallotChoice.YEA, b"s1")
        box.close_commit_phase()
        with pytest.raises(MissingRevealError):
            box.tally(require_all_revealed=True)

    def test_double_vote_same_secret_rejected(self):
        box = self._fresh()
        self._voter(box, BallotChoice.YEA, b"shared-secret")
        with pytest.raises(DoubleVoteError):
            # Different keypair, same voter secret → same nullifier
            self._voter(box, BallotChoice.NAY, b"shared-secret")

    def test_epoch_mismatch_rejected(self):
        box = self._fresh()
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=bytes.fromhex("ff" * 16),
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        with pytest.raises(InvalidCommitError, match="mismatch"):
            box.submit_commit(c)

    def test_tampered_reveal_rejected(self):
        box = self._fresh()
        _, r, _ = self._voter(box, BallotChoice.YEA, b"s1")
        box.close_commit_phase()
        # Swap the choice in the reveal (signature will not match)
        forged = RevealRecord(
            version=r.version,
            commit=r.commit,
            choice=BallotChoice.NAY,
            nonce=r.nonce,
            signature=r.signature,
        )
        with pytest.raises(InvalidRevealError):
            box.submit_reveal(forged)

    def test_tampered_commit_signature_rejected(self):
        box = self._fresh()
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        bad = CommitRecord(
            version=c.version,
            epoch=c.epoch,
            subject=c.subject,
            voter=c.voter,
            commit=c.commit,
            nullifier=c.nullifier,
            signature=bytes(64),  # zeroed sig
        )
        with pytest.raises(InvalidCommitError):
            box.submit_commit(bad)


class TestTallyFunction:
    def test_deterministic_across_input_order(self):
        sk1, sk2, sk3 = _kp(), _kp(), _kp()
        triples = []
        for sk, choice, secret in [
            (sk1, BallotChoice.YEA, b"a"),
            (sk2, BallotChoice.NAY, b"b"),
            (sk3, BallotChoice.YEA, b"c"),
        ]:
            c, r = build_commit(
                voter_private_key=sk,
                voter_secret=secret,
                epoch=EPOCH,
                subject=SUBJECT,
                choice=choice,
            )
            triples.append((c, r))
        commits1 = [c for c, _ in triples]
        commits2 = list(reversed(commits1))
        reveals1 = [r for _, r in triples]
        reveals2 = list(reversed(reveals1))
        t1 = tally(commits1, reveals1, epoch=EPOCH, subject=SUBJECT)
        t2 = tally(commits2, reveals2, epoch=EPOCH, subject=SUBJECT)
        assert t1.accepted == t2.accepted
        assert dict(t1.totals) == dict(t2.totals)

    def test_nullifier_first_wins(self):
        # Two commits with same nullifier → only one tallied
        sk1, sk2 = _kp(), _kp()
        c1, r1 = build_commit(
            voter_private_key=sk1,
            voter_secret=b"shared",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        c2, r2 = build_commit(
            voter_private_key=sk2,
            voter_secret=b"shared",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.NAY,
        )
        assert c1.nullifier == c2.nullifier
        result = tally([c1, c2], [r1, r2], epoch=EPOCH, subject=SUBJECT)
        # Exactly one accepted; one rejected for duplicate nullifier
        assert result.total_valid == 1
        assert any(reason == "duplicate nullifier" for _, reason in result.rejected)

    def test_reveal_opens_wrong_commit_rejected(self):
        sk = _kp()
        c, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s1",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.YEA,
        )
        # Build an independent reveal with a mismatched nonce
        bad_reveal = build_reveal(
            voter_private_key=sk,
            commit=c.commit,
            choice=BallotChoice.YEA,
            nonce=b"\x00" * 32,  # different nonce → won't open
        )
        result = tally([c], [bad_reveal], epoch=EPOCH, subject=SUBJECT)
        assert result.total_valid == 0
        assert any("does not open" in reason for _, reason in result.rejected)
