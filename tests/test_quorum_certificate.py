"""Tests for validator_set + quorum_certificate (Phase 7.1).

Covers:
  - ValidatorIdentity validation
  - FaultDomainPolicy cap math (strict / lenient untagged)
  - ValidatorSet domain aggregation
  - CommitteeSelector determinism from seed
  - Sybil adversarial simulation: 40-60% raw IDs malicious bounded to <1/3 effective weight
  - SignedVote signature round-trip, tampering detection
  - QuorumCertificate build / verify / serialize round-trip
  - Conflict detection surfaces slashable evidence
  - InsufficientQuorumError / InvalidCertificateError paths
"""

from __future__ import annotations

import json

import pytest
from constitutional_swarm.quorum_certificate import (
    InsufficientQuorumError,
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    build_certificate,
    build_vote_message,
    detect_conflict,
    verify_certificate,
)
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    FaultDomainPolicy,
    SybilBoundViolation,
    ValidatorIdentity,
    ValidatorSet,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_validator(
    agent_id: str,
    *,
    stake: float = 1.0,
    reputation: float = 1.0,
    fault_domain: str = "",
):
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ident = ValidatorIdentity(
        agent_id=agent_id,
        stake=stake,
        reputation=reputation,
        fault_domain=fault_domain,
    )
    return ident, sk, pk_bytes


def _sign(sk, assignment_id, artifact_hash, epoch):
    return sk.sign(build_vote_message(assignment_id, artifact_hash, epoch))


# ---------------------------------------------------------------------------
# ValidatorIdentity
# ---------------------------------------------------------------------------


class TestValidatorIdentity:
    def test_effective_weight(self):
        v = ValidatorIdentity("a", stake=4.0, reputation=0.5)
        assert v.effective_weight == pytest.approx(2.0)

    def test_empty_id_rejected(self):
        with pytest.raises(ValueError, match="agent_id"):
            ValidatorIdentity("", stake=1.0)

    def test_negative_stake_rejected(self):
        with pytest.raises(ValueError, match="stake"):
            ValidatorIdentity("a", stake=-0.1)

    def test_reputation_out_of_range(self):
        with pytest.raises(ValueError, match="reputation"):
            ValidatorIdentity("a", stake=1.0, reputation=1.5)
        with pytest.raises(ValueError, match="reputation"):
            ValidatorIdentity("a", stake=1.0, reputation=-0.01)


# ---------------------------------------------------------------------------
# FaultDomainPolicy
# ---------------------------------------------------------------------------


class TestFaultDomainPolicy:
    def test_strict_untagged_isolates_each_validator(self):
        p = FaultDomainPolicy(untagged_policy="strict")
        v = ValidatorIdentity("alice", stake=1.0)
        assert p.resolve_domain(v) == "__untagged__:alice"

    def test_lenient_untagged_pools(self):
        p = FaultDomainPolicy(untagged_policy="lenient")
        v1 = ValidatorIdentity("a", stake=1.0)
        v2 = ValidatorIdentity("b", stake=1.0)
        assert p.resolve_domain(v1) == p.resolve_domain(v2) == "__untagged__"

    def test_tagged_is_preserved(self):
        p = FaultDomainPolicy()
        v = ValidatorIdentity("a", stake=1.0, fault_domain="org:x")
        assert p.resolve_domain(v) == "org:x"

    def test_invalid_policy_rejected(self):
        with pytest.raises(ValueError, match="max_fraction"):
            FaultDomainPolicy(max_fraction=0.0)
        with pytest.raises(ValueError, match="max_fraction"):
            FaultDomainPolicy(max_fraction=1.5)
        with pytest.raises(ValueError, match="untagged_policy"):
            FaultDomainPolicy(untagged_policy="nope")


# ---------------------------------------------------------------------------
# ValidatorSet
# ---------------------------------------------------------------------------


class TestValidatorSet:
    def test_basic_membership(self):
        vs = ValidatorSet(
            [ValidatorIdentity("a", stake=2.0), ValidatorIdentity("b", stake=1.0)]
        )
        assert len(vs) == 2
        assert "a" in vs
        assert vs.total_weight() == pytest.approx(3.0)

    def test_add_overwrites(self):
        vs = ValidatorSet([ValidatorIdentity("a", stake=1.0)])
        vs.add(ValidatorIdentity("a", stake=5.0))
        assert len(vs) == 1
        assert vs.total_weight() == pytest.approx(5.0)

    def test_remove_is_silent_on_missing(self):
        vs = ValidatorSet()
        vs.remove("ghost")  # no raise
        assert len(vs) == 0

    def test_domain_aggregation(self):
        vs = ValidatorSet(
            [
                ValidatorIdentity("a", stake=1.0, fault_domain="org:x"),
                ValidatorIdentity("b", stake=1.0, fault_domain="org:x"),
                ValidatorIdentity("c", stake=2.0, fault_domain="org:y"),
            ],
            policy=FaultDomainPolicy(max_fraction=0.5),
        )
        dw = vs.domain_weights()
        assert dw["org:x"] == pytest.approx(2.0)
        assert dw["org:y"] == pytest.approx(2.0)

    def test_effective_total_applies_cap(self):
        # 10 identities all in same domain: effective total should be
        # capped at max_fraction * raw_total rather than raw_total.
        vs = ValidatorSet(
            [
                ValidatorIdentity(f"a{i}", stake=1.0, fault_domain="sybil")
                for i in range(10)
            ],
            policy=FaultDomainPolicy(max_fraction=0.3),
        )
        raw = vs.total_weight()
        effective = vs.effective_total_weight()
        assert raw == pytest.approx(10.0)
        assert effective == pytest.approx(3.0)  # 0.3 * 10

    def test_snapshot_is_sorted_deterministic(self):
        vs = ValidatorSet(
            [ValidatorIdentity(x, stake=1.0) for x in ("z", "a", "m")]
        )
        snap = vs.snapshot()
        assert [v.agent_id for v in snap] == ["a", "m", "z"]


# ---------------------------------------------------------------------------
# CommitteeSelector
# ---------------------------------------------------------------------------


class TestCommitteeSelector:
    def test_deterministic_from_seed(self):
        vs = ValidatorSet(
            [ValidatorIdentity(f"v{i}", stake=1.0) for i in range(20)]
        )
        sel = CommitteeSelector(vs)
        a = sel.select("seed-xyz", committee_size=5)
        b = sel.select("seed-xyz", committee_size=5)
        assert a.members == b.members

    def test_different_seed_different_committee(self):
        vs = ValidatorSet(
            [ValidatorIdentity(f"v{i}", stake=1.0) for i in range(30)]
        )
        sel = CommitteeSelector(vs)
        # Overwhelmingly likely to differ with 30 candidates choosing 5
        a = sel.select("seed-a", committee_size=5)
        b = sel.select("seed-b", committee_size=5)
        assert a.members != b.members

    def test_exclude_keeps_out_producer(self):
        vs = ValidatorSet(
            [ValidatorIdentity(f"v{i}", stake=1.0) for i in range(10)]
        )
        sel = CommitteeSelector(vs)
        out = sel.select("s", committee_size=5, exclude=["v3", "v7"])
        assert "v3" not in out.members and "v7" not in out.members

    def test_empty_candidate_pool(self):
        vs = ValidatorSet()
        sel = CommitteeSelector(vs)
        out = sel.select("s", committee_size=5)
        assert out.members == ()
        assert out.weight == 0.0
        assert out.capped_weight == 0.0

    def test_oversize_clips_to_set(self):
        vs = ValidatorSet(
            [ValidatorIdentity(f"v{i}", stake=1.0) for i in range(3)]
        )
        sel = CommitteeSelector(vs)
        out = sel.select("s", committee_size=10)
        assert len(out.members) == 3

    def test_invalid_size_rejected(self):
        sel = CommitteeSelector(ValidatorSet([ValidatorIdentity("a", stake=1.0)]))
        with pytest.raises(ValueError, match="committee_size"):
            sel.select("s", committee_size=0)

    def test_committee_weight_ratios_accurate(self):
        # 3 domains: each 1/3 of total weight, cap = 1/3 → capped==raw
        vs = ValidatorSet(
            [
                ValidatorIdentity("a", stake=1.0, fault_domain="d1"),
                ValidatorIdentity("b", stake=1.0, fault_domain="d2"),
                ValidatorIdentity("c", stake=1.0, fault_domain="d3"),
            ],
            policy=FaultDomainPolicy(max_fraction=1 / 3),
        )
        sel = CommitteeSelector(vs)
        out = sel.select("seed", committee_size=3)
        assert out.weight == pytest.approx(3.0)
        # cap = 1.0 per domain; each domain has exactly 1.0 so capped=raw
        assert out.capped_weight == pytest.approx(3.0)
        assert out.has_quorum(2 / 3)


class TestSybilAdversarialSimulation:
    """Codex-mandated proof test: 40-60 % raw IDs malicious yet bounded.

    Scenario: attacker spins up many fake validators *in the same
    fault-domain*. Without the cap, ~50 % of raw IDs would let them
    sway an honest-majority vote. With a 1/3 cap, their committee
    influence is bounded to 1/3 regardless of raw count.
    """

    def test_sybil_bounded_at_one_third(self):
        honest = [
            ValidatorIdentity(
                f"honest-{i}", stake=1.0, fault_domain=f"honest-org-{i}"
            )
            for i in range(10)
        ]
        # 10 sybil identities all masquerading under the same org
        sybil = [
            ValidatorIdentity(
                f"sybil-{i}", stake=1.0, fault_domain="attacker-org"
            )
            for i in range(10)
        ]
        vs = ValidatorSet(
            honest + sybil, policy=FaultDomainPolicy(max_fraction=1 / 3)
        )
        sel = CommitteeSelector(vs)
        # Large committee to make sybil concentration visible
        out = sel.select("beacon-epoch-42", committee_size=20)
        raw_sybil = sum(
            1 for m in out.members if m.startswith("sybil-")
        )
        sybil_domain_capped = out.domain_weights.get("attacker-org", 0.0)
        # Even if 10/20 raw members are sybils, their capped weight is bounded
        assert raw_sybil >= 1  # they're in the committee
        assert sybil_domain_capped <= out.weight * (1 / 3) + 1e-9

    def test_select_until_independent_raises_when_all_sybil(self):
        # All validators in one domain — can't construct independent committee
        vs = ValidatorSet(
            [
                ValidatorIdentity(f"v{i}", stake=1.0, fault_domain="one-org")
                for i in range(10)
            ],
            policy=FaultDomainPolicy(max_fraction=1 / 3),
        )
        sel = CommitteeSelector(vs)
        with pytest.raises(SybilBoundViolation):
            sel.select_until_independent(
                "seed", committee_size=5, threshold_fraction=2 / 3
            )

    def test_select_until_independent_succeeds_with_diverse_set(self):
        vs = ValidatorSet(
            [
                ValidatorIdentity(f"v{i}", stake=1.0, fault_domain=f"d{i}")
                for i in range(10)
            ],
            policy=FaultDomainPolicy(max_fraction=1 / 3),
        )
        sel = CommitteeSelector(vs)
        out = sel.select_until_independent(
            "seed", committee_size=4, threshold_fraction=2 / 3
        )
        assert len(out.members) == 4


# ---------------------------------------------------------------------------
# SignedVote
# ---------------------------------------------------------------------------


class TestSignedVote:
    def test_roundtrip_signature_verifies(self):
        _, sk, pk = _make_validator("v1")
        sig = _sign(sk, "asgn-1", "hash-abc", 7)
        sv = SignedVote(
            voter_id="v1",
            assignment_id="asgn-1",
            artifact_hash="hash-abc",
            epoch=7,
            signature=sig,
            public_key_bytes=pk,
        )
        assert sv.verify() is True

    def test_tampered_payload_fails(self):
        _, sk, pk = _make_validator("v1")
        sig = _sign(sk, "asgn-1", "hash-abc", 7)
        sv = SignedVote(
            voter_id="v1",
            assignment_id="asgn-1",
            artifact_hash="hash-XYZ",  # tampered
            epoch=7,
            signature=sig,
            public_key_bytes=pk,
        )
        assert sv.verify() is False

    def test_wrong_public_key_fails(self):
        _, sk1, _ = _make_validator("v1")
        _, _, pk2 = _make_validator("v2")
        sig = _sign(sk1, "a", "h", 1)
        sv = SignedVote("v1", "a", "h", 1, sig, pk2)
        assert sv.verify() is False


# ---------------------------------------------------------------------------
# QuorumCertificate
# ---------------------------------------------------------------------------


def _make_committee_and_votes(
    *, artifact_hash="hash-accept", epoch=1, n_validators=5, policy=None
):
    """Build a validator set + committee + fully-signed QC-ready votes."""
    ids = []
    sks = {}
    pks = {}
    for i in range(n_validators):
        ident, sk, pk = _make_validator(
            f"v{i}", stake=1.0, fault_domain=f"domain-{i}"
        )
        ids.append(ident)
        sks[ident.agent_id] = sk
        pks[ident.agent_id] = pk
    vs = ValidatorSet(ids, policy=policy or FaultDomainPolicy(max_fraction=0.5))
    sel = CommitteeSelector(vs)
    committee = sel.select("seed", committee_size=n_validators)
    votes = [
        SignedVote(
            voter_id=aid,
            assignment_id="asgn",
            artifact_hash=artifact_hash,
            epoch=epoch,
            signature=_sign(sks[aid], "asgn", artifact_hash, epoch),
            public_key_bytes=pks[aid],
        )
        for aid in committee.members
    ]
    return vs, committee, votes, sks, pks


class TestBuildCertificate:
    def test_success_path(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(
            votes, committee=committee, validator_set=vs, threshold_fraction=2 / 3
        )
        assert len(qc.votes) == 5
        assert qc.voter_ids == frozenset(committee.members)
        assert qc.achieved_weight >= qc.threshold_weight

    def test_votes_sorted_by_voter(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        import random

        random.shuffle(votes)
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        assert [v.voter_id for v in qc.votes] == sorted(
            [v.voter_id for v in qc.votes]
        )

    def test_insufficient_votes_raises(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        # Submit only one vote out of 5 — cannot reach 2/3
        with pytest.raises(InsufficientQuorumError):
            build_certificate(
                votes[:1],
                committee=committee,
                validator_set=vs,
                threshold_fraction=2 / 3,
            )

    def test_empty_votes_raises(self):
        vs, committee, _, _, _ = _make_committee_and_votes()
        with pytest.raises(InsufficientQuorumError, match="no votes"):
            build_certificate([], committee=committee, validator_set=vs)

    def test_non_committee_voter_rejected(self):
        vs, committee, votes, sks, pks = _make_committee_and_votes()
        # Add a rogue validator not in committee
        rogue_ident, rogue_sk, rogue_pk = _make_validator("rogue")
        vs.add(rogue_ident)
        rogue_vote = SignedVote(
            "rogue",
            "asgn",
            "hash-accept",
            1,
            _sign(rogue_sk, "asgn", "hash-accept", 1),
            rogue_pk,
        )
        with pytest.raises(InvalidCertificateError, match="not a member"):
            build_certificate(
                [*votes, rogue_vote],
                committee=committee,
                validator_set=vs,
            )

    def test_subject_mismatch_rejected(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        # Change one vote to a different artifact_hash (not the first —
        # first defines the QC subject)
        bad = SignedVote(
            votes[1].voter_id,
            votes[1].assignment_id,
            "DIFFERENT",
            votes[1].epoch,
            votes[1].signature,
            votes[1].public_key_bytes,
        )
        with pytest.raises(InvalidCertificateError, match="subject"):
            build_certificate(
                [votes[0], bad, *votes[2:]], committee=committee, validator_set=vs
            )

    def test_bad_signature_rejected(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        tampered = SignedVote(
            votes[0].voter_id,
            votes[0].assignment_id,
            votes[0].artifact_hash,
            votes[0].epoch,
            b"\x00" * 64,  # invalid signature
            votes[0].public_key_bytes,
        )
        with pytest.raises(InvalidCertificateError, match="signature"):
            build_certificate(
                [tampered, *votes[1:]], committee=committee, validator_set=vs
            )

    def test_duplicate_voter_deduped(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(
            [votes[0], votes[0], *votes[1:]],
            committee=committee,
            validator_set=vs,
        )
        # first duplicate wins, rest unchanged
        assert len(qc.votes) == 5


class TestSerialization:
    def test_qc_roundtrip(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        data = qc.to_dict()
        blob = json.dumps(data)  # must be JSON-safe
        qc2 = QuorumCertificate.from_dict(json.loads(blob))
        assert qc2.qc_id() == qc.qc_id()
        assert qc2.voter_ids == qc.voter_ids
        # signatures still verify after round-trip
        for sv in qc2.votes:
            assert sv.verify()


class TestVerifyCertificate:
    def test_valid_passes(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        verify_certificate(qc, validator_set=vs)  # no raise

    def test_duplicate_voter_in_qc_raises(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        # Manually construct a corrupted QC with a duplicate voter
        corrupted = QuorumCertificate(
            assignment_id=qc.assignment_id,
            artifact_hash=qc.artifact_hash,
            epoch=qc.epoch,
            votes=(qc.votes[0], qc.votes[0], *qc.votes[1:]),
            threshold_weight=qc.threshold_weight,
            achieved_weight=qc.achieved_weight,
            committee_seed=qc.committee_seed,
        )
        with pytest.raises(InvalidCertificateError, match="duplicate"):
            verify_certificate(corrupted, validator_set=vs)

    def test_removed_voter_fails(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        vs.remove(qc.votes[0].voter_id)
        with pytest.raises(InvalidCertificateError, match="not in validator set"):
            verify_certificate(qc, validator_set=vs)

    def test_empty_qc_rejected(self):
        vs = ValidatorSet([ValidatorIdentity("a", stake=1.0)])
        empty = QuorumCertificate(
            assignment_id="a",
            artifact_hash="h",
            epoch=0,
            votes=(),
            threshold_weight=0.0,
            achieved_weight=0.0,
        )
        with pytest.raises(InvalidCertificateError, match="empty"):
            verify_certificate(empty, validator_set=vs)


# ---------------------------------------------------------------------------
# Conflict detection — accountable safety property
# ---------------------------------------------------------------------------


class TestConflictDetection:
    def test_two_conflicting_qcs_produce_slashable_evidence(self):
        """The Codex proof test: under majority-adversary conditions, if
        two conflicting artifacts finalize in the same epoch, the
        intersection of signers is slashable."""
        vs, committee, votes_a, sks, pks = _make_committee_and_votes(
            artifact_hash="hash-A", epoch=1
        )
        # Same committee signs a *different* artifact at the same epoch
        votes_b = [
            SignedVote(
                voter_id=aid,
                assignment_id="asgn",
                artifact_hash="hash-B",
                epoch=1,
                signature=_sign(sks[aid], "asgn", "hash-B", 1),
                public_key_bytes=pks[aid],
            )
            for aid in committee.members
        ]
        qc_a = build_certificate(
            votes_a, committee=committee, validator_set=vs
        )
        qc_b = build_certificate(
            votes_b, committee=committee, validator_set=vs
        )
        ev = detect_conflict(qc_a, qc_b)
        assert ev is not None
        assert ev.is_slashable()
        # All 5 signers equivocated → all 5 slashable
        assert ev.equivocators == frozenset(committee.members)

    def test_same_artifact_is_not_conflict(self):
        vs, committee, votes, _, _ = _make_committee_and_votes()
        qc = build_certificate(votes, committee=committee, validator_set=vs)
        assert detect_conflict(qc, qc) is None

    def test_different_epoch_is_not_conflict(self):
        vs1, c1, v1, *_ = _make_committee_and_votes(
            artifact_hash="hash-A", epoch=1
        )
        vs2, c2, v2, *_ = _make_committee_and_votes(
            artifact_hash="hash-B", epoch=2
        )
        qc1 = build_certificate(v1, committee=c1, validator_set=vs1)
        qc2 = build_certificate(v2, committee=c2, validator_set=vs2)
        assert detect_conflict(qc1, qc2) is None

    def test_different_assignment_is_not_conflict(self):
        # Two QCs for different assignment_ids with different artifact_hashes
        # — not a safety violation.
        vs, committee, votes_a, sks, pks = _make_committee_and_votes(
            artifact_hash="hash-A", epoch=1
        )
        votes_b = [
            SignedVote(
                voter_id=aid,
                assignment_id="asgn-DIFFERENT",
                artifact_hash="hash-B",
                epoch=1,
                signature=_sign(sks[aid], "asgn-DIFFERENT", "hash-B", 1),
                public_key_bytes=pks[aid],
            )
            for aid in committee.members
        ]
        # Re-select for the 2nd assignment's seed to keep test isolated
        sel = CommitteeSelector(vs)
        c2 = sel.select("seed", committee_size=5)
        qc_a = build_certificate(
            votes_a, committee=committee, validator_set=vs
        )
        qc_b = build_certificate(votes_b, committee=c2, validator_set=vs)
        assert detect_conflict(qc_a, qc_b) is None

    def test_partial_overlap_slashes_only_equivocators(self):
        """If only some voters signed both QCs, only they are slashable."""
        # Build a validator set and two disjoint-ish committees
        idents = []
        sks, pks = {}, {}
        for i in range(6):
            ident, sk, pk = _make_validator(
                f"v{i}", stake=1.0, fault_domain=f"d{i}"
            )
            idents.append(ident)
            sks[ident.agent_id] = sk
            pks[ident.agent_id] = pk
        vs = ValidatorSet(idents, policy=FaultDomainPolicy(max_fraction=0.5))
        sel = CommitteeSelector(vs)

        # Committee 1 signs artifact A; committee 2 signs artifact B.
        # We hand-build overlapping committees to force a shared signer.
        c1 = sel.select("seed", committee_size=4)
        c2 = sel.select("seed-other", committee_size=4)
        shared = set(c1.members) & set(c2.members)
        assert shared, "test setup must have at least one shared signer"

        def _sign_set(members, artifact, epoch=1):
            return [
                SignedVote(
                    m,
                    "asgn",
                    artifact,
                    epoch,
                    _sign(sks[m], "asgn", artifact, epoch),
                    pks[m],
                )
                for m in members
            ]

        qc_a = build_certificate(
            _sign_set(c1.members, "hash-A"),
            committee=c1,
            validator_set=vs,
        )
        qc_b = build_certificate(
            _sign_set(c2.members, "hash-B"),
            committee=c2,
            validator_set=vs,
        )
        ev = detect_conflict(qc_a, qc_b)
        assert ev is not None
        assert ev.equivocators == shared
