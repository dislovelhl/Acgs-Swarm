"""Phase 12 — validity-proof scaffold (v2 records) tests.

These exercise the v2 commit path: optional ``validity_proof`` field,
pluggable :class:`ValidityProver` Protocol, the non-ZK
:class:`HashCommitmentProver` default, and backward compatibility with
v1 records. A real SNARK backend is out of scope; see private_vote.py
module docstring for the deferred plug-in.
"""

from __future__ import annotations

import pytest
from constitutional_swarm.private_vote import (
    BallotChoice,
    CommitRecord,
    HashCommitmentProver,
    PrivateBallotBox,
    ValidityProver,
    ValidityStatement,
    ValidityWitness,
    build_commit,
    tally,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EPOCH = bytes.fromhex("00" * 16)
SUBJECT = bytes.fromhex("22" * 16)


def _kp() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _v2_roundtrip(choice: BallotChoice = BallotChoice.YEA):
    sk = _kp()
    secret = b"voter-seed-v2"
    prover = HashCommitmentProver()
    commit, reveal = build_commit(
        voter_private_key=sk,
        voter_secret=secret,
        epoch=EPOCH,
        subject=SUBJECT,
        choice=choice,
        prover=prover,
    )
    return commit, reveal, prover


class TestV2Format:
    def test_v2_emits_version_and_proof(self):
        commit, _, prover = _v2_roundtrip()
        assert commit.version == 2
        assert commit.proof_scheme == prover.scheme_id
        assert isinstance(commit.validity_proof, bytes)
        assert len(commit.validity_proof) == 32

    def test_v1_default_preserved_when_no_prover(self):
        sk = _kp()
        commit, _reveal = build_commit(
            voter_private_key=sk,
            voter_secret=b"seed",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.NAY,
        )
        assert commit.version == 1
        assert commit.proof_scheme is None
        assert commit.validity_proof is None
        # v1 serialization must not emit v2-only keys.
        serialized = commit.to_dict()
        assert "proof_scheme" not in serialized
        assert "validity_proof" not in serialized

    def test_v2_json_roundtrip(self):
        commit, _, _ = _v2_roundtrip()
        rebuilt = CommitRecord.from_dict(commit.to_dict())
        assert rebuilt == commit
        assert rebuilt.version == 2
        assert rebuilt.validity_proof == commit.validity_proof

    def test_v1_json_roundtrip_has_no_v2_fields(self):
        sk = _kp()
        commit, _ = build_commit(
            voter_private_key=sk,
            voter_secret=b"s",
            epoch=EPOCH,
            subject=SUBJECT,
            choice=BallotChoice.ABSTAIN,
        )
        rebuilt = CommitRecord.from_dict(commit.to_dict())
        assert rebuilt == commit
        assert rebuilt.proof_scheme is None
        assert rebuilt.validity_proof is None


class TestHashCommitmentProver:
    def test_verify_accepts_valid_proof(self):
        commit, _, prover = _v2_roundtrip(BallotChoice.YEA)
        stmt = ValidityStatement(
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
        )
        assert prover.verify(stmt, commit.validity_proof) is True

    def test_verify_rejects_tampered_proof(self):
        commit, _, prover = _v2_roundtrip(BallotChoice.YEA)
        stmt = ValidityStatement(
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
        )
        flipped = bytes([commit.validity_proof[0] ^ 0x01]) + commit.validity_proof[1:]
        assert prover.verify(stmt, flipped) is False

    def test_verify_rejects_wrong_statement(self):
        commit, _, prover = _v2_roundtrip(BallotChoice.YEA)
        bogus = ValidityStatement(
            epoch=EPOCH,
            subject=SUBJECT,
            voter=commit.voter,
            commit=b"\xff" * 32,  # different commit digest
            nullifier=commit.nullifier,
        )
        assert prover.verify(bogus, commit.validity_proof) is False

    def test_verify_rejects_malformed_length(self):
        commit, _, prover = _v2_roundtrip()
        stmt = ValidityStatement(
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
        )
        assert prover.verify(stmt, b"\x00" * 16) is False

    def test_protocol_runtime_check(self):
        prover = HashCommitmentProver()
        assert isinstance(prover, ValidityProver)

    def test_prover_rejects_non_ballot_choice_witness(self):
        prover = HashCommitmentProver()
        stmt = ValidityStatement(EPOCH, SUBJECT, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)
        with pytest.raises(ValueError):
            prover.prove(stmt, ValidityWitness(choice="not-a-choice", nonce=b"x" * 32, voter_secret=b"s"))  # type: ignore[arg-type]


class TestTallyV2:
    def _build_box(self, choices: list[BallotChoice], with_prover: bool):
        prover = HashCommitmentProver() if with_prover else None
        box = PrivateBallotBox(epoch=EPOCH, subject=SUBJECT)
        built = []
        for i, ch in enumerate(choices):
            sk = _kp()
            secret = f"voter-{i}".encode()
            commit, reveal = build_commit(
                voter_private_key=sk,
                voter_secret=secret,
                epoch=EPOCH,
                subject=SUBJECT,
                choice=ch,
                prover=prover,
            )
            box.submit_commit(commit)
            built.append((commit, reveal))
        box.close_commit_phase()
        for _, rv in built:
            box.submit_reveal(rv)
        return box, prover

    def test_v2_tally_with_matching_prover(self):
        box, prover = self._build_box(
            [BallotChoice.YEA, BallotChoice.YEA, BallotChoice.NAY], with_prover=True
        )
        result = box.tally(provers={prover.scheme_id: prover})
        assert result.totals[BallotChoice.YEA] == 2
        assert result.totals[BallotChoice.NAY] == 1
        assert result.rejected == ()

    def test_v2_without_prover_rejects_fail_closed(self):
        """v2 commit with proof_scheme set but no verifier -> rejected."""
        box, _ = self._build_box([BallotChoice.YEA, BallotChoice.NAY], with_prover=True)
        result = box.tally(provers=None)
        assert result.totals[BallotChoice.YEA] == 0
        assert result.totals[BallotChoice.NAY] == 0
        reasons = [r for _, r in result.rejected]
        assert all("no verifier" in r for r in reasons)

    def test_mixed_v1_v2_ballot_box_tallies_both_without_strict(self):
        sk1, sk2 = _kp(), _kp()
        prover = HashCommitmentProver()
        c1, r1 = build_commit(
            voter_private_key=sk1, voter_secret=b"a", epoch=EPOCH, subject=SUBJECT,
            choice=BallotChoice.YEA,
        )  # v1
        c2, r2 = build_commit(
            voter_private_key=sk2, voter_secret=b"b", epoch=EPOCH, subject=SUBJECT,
            choice=BallotChoice.YEA, prover=prover,
        )  # v2
        box = PrivateBallotBox(epoch=EPOCH, subject=SUBJECT)
        box.submit_commit(c1)
        box.submit_commit(c2)
        box.close_commit_phase()
        box.submit_reveal(r1)
        box.submit_reveal(r2)
        result = box.tally(provers={prover.scheme_id: prover})
        assert result.totals[BallotChoice.YEA] == 2
        assert result.rejected == ()

    def test_strict_v2_rejects_legacy_v1(self):
        sk1 = _kp()
        c1, r1 = build_commit(
            voter_private_key=sk1, voter_secret=b"a", epoch=EPOCH, subject=SUBJECT,
            choice=BallotChoice.YEA,
        )  # v1
        box = PrivateBallotBox(epoch=EPOCH, subject=SUBJECT)
        box.submit_commit(c1)
        box.close_commit_phase()
        box.submit_reveal(r1)
        result = box.tally(strict_v2=True)
        assert result.totals[BallotChoice.YEA] == 0
        assert any("strict_v2" in reason for _, reason in result.rejected)

    def test_v2_proof_tampering_detected_in_tally(self):
        sk = _kp()
        prover = HashCommitmentProver()
        commit, reveal = build_commit(
            voter_private_key=sk, voter_secret=b"a", epoch=EPOCH, subject=SUBJECT,
            choice=BallotChoice.YEA, prover=prover,
        )
        # tamper the proof
        bad_proof = bytes([commit.validity_proof[0] ^ 0xFF]) + commit.validity_proof[1:]
        tampered = CommitRecord(
            version=commit.version,
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
            signature=commit.signature,
            proof_scheme=commit.proof_scheme,
            validity_proof=bad_proof,
        )
        result = tally(
            [tampered], [reveal], epoch=EPOCH, subject=SUBJECT,
            provers={prover.scheme_id: prover},
        )
        assert result.totals[BallotChoice.YEA] == 0
        assert any("invalid validity proof" in r for _, r in result.rejected)

    def test_v2_without_proof_scheme_still_valid(self):
        """A v2 record without a proof_scheme behaves like v1 for the proof check."""
        sk = _kp()
        commit, reveal = build_commit(
            voter_private_key=sk, voter_secret=b"a", epoch=EPOCH, subject=SUBJECT,
            choice=BallotChoice.ABSTAIN,
        )
        # forge version=2 with no proof_scheme/proof (simulating legacy tool bump)
        rebuilt = CommitRecord(
            version=2,
            epoch=commit.epoch,
            subject=commit.subject,
            voter=commit.voter,
            commit=commit.commit,
            nullifier=commit.nullifier,
            signature=commit.signature,
            proof_scheme=None,
            validity_proof=None,
        )
        result = tally([rebuilt], [reveal], epoch=EPOCH, subject=SUBJECT)
        assert result.totals[BallotChoice.ABSTAIN] == 1
