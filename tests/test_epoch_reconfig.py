"""Tests for Phase 7.5 versioned constitutional reconfiguration."""

from __future__ import annotations

import pytest
from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    DriftBudgetExceeded,
    EpochMismatchError,
    InvalidTransitionError,
    JointQuorumNotMetError,
    TransitionCertificate,
    compute_version_digest,
    evaluate_drift,
    verify_transition,
)


def _v(epoch: int, rules: tuple[str, ...], parent: bytes = b"") -> ConstitutionVersion:
    return ConstitutionVersion(epoch=epoch, rules=tuple(sorted(rules)), parent_digest=parent)


class TestConstitutionVersion:
    def test_digest_is_deterministic(self) -> None:
        v1 = _v(1, ("a", "b"))
        v2 = _v(1, ("a", "b"))
        assert v1.digest == v2.digest

    def test_digest_separates_epoch(self) -> None:
        v1 = _v(1, ("a",))
        v2 = _v(2, ("a",))
        assert v1.digest != v2.digest

    def test_digest_separates_rules(self) -> None:
        v1 = _v(1, ("a",))
        v2 = _v(1, ("a", "b"))
        assert v1.digest != v2.digest

    def test_digest_separates_parent(self) -> None:
        v1 = _v(1, ("a",), parent=b"\x00" * 32)
        v2 = _v(1, ("a",), parent=b"\xff" * 32)
        assert v1.digest != v2.digest

    def test_rules_must_be_sorted(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=0, rules=("b", "a"))

    def test_negative_epoch_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=-1, rules=())

    def test_bad_parent_length_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConstitutionVersion(epoch=0, rules=(), parent_digest=b"\x00" * 16)

    def test_compute_version_digest_requires_nonneg_epoch(self) -> None:
        with pytest.raises(ValueError):
            compute_version_digest(epoch=-1, rules=(), parent_digest=b"")


class TestAmendmentProposal:
    def test_happy_path(self) -> None:
        v0 = _v(0, ("a",))
        v1 = _v(1, ("a", "b"), parent=v0.digest)
        proposal = AmendmentProposal(prior=v0, proposed=v1)
        assert proposal.drift == 1

    def test_rejects_non_adjacent_epoch(self) -> None:
        v0 = _v(0, ("a",))
        v2 = _v(2, ("a",), parent=v0.digest)
        with pytest.raises(EpochMismatchError):
            AmendmentProposal(prior=v0, proposed=v2)

    def test_rejects_bad_parent_pointer(self) -> None:
        v0 = _v(0, ("a",))
        bad_parent = b"\x00" * 32
        v1 = _v(1, ("a",), parent=bad_parent)
        with pytest.raises(InvalidTransitionError):
            AmendmentProposal(prior=v0, proposed=v1)


class TestEvaluateDrift:
    def test_drift_counts_add_and_remove(self) -> None:
        v0 = _v(0, ("a", "b"))
        v1 = _v(1, ("b", "c", "d"), parent=v0.digest)
        # removed: a; added: c, d → drift = 3
        assert evaluate_drift(v0, v1) == 3


class TestTransitionCertificate:
    def _make(
        self,
        *,
        old_signers: frozenset[str] = frozenset({"v1", "v2", "v3"}),
        new_signers: frozenset[str] = frozenset({"w1", "w2", "w3"}),
    ) -> TransitionCertificate:
        v0 = _v(0, ("a", "b"))
        v1 = _v(1, ("a", "b", "c"), parent=v0.digest)
        proposal = AmendmentProposal(prior=v0, proposed=v1)
        return TransitionCertificate(
            proposal=proposal,
            old_side_signers=old_signers,
            new_side_signers=new_signers,
            old_side_threshold=3,
            new_side_threshold=3,
        )

    def test_happy_path(self) -> None:
        cert = self._make()
        verify_transition(
            cert,
            old_stake={"v1": 1, "v2": 1, "v3": 1, "v4": 1},
            new_stake={"w1": 1, "w2": 1, "w3": 1, "w4": 1},
        )

    def test_rejects_insufficient_old_side(self) -> None:
        cert = self._make(old_signers=frozenset({"v1", "v2"}))
        with pytest.raises(JointQuorumNotMetError):
            verify_transition(
                cert,
                old_stake={"v1": 1, "v2": 1, "v3": 1},
                new_stake={"w1": 1, "w2": 1, "w3": 1},
            )

    def test_rejects_insufficient_new_side(self) -> None:
        cert = self._make(new_signers=frozenset({"w1"}))
        with pytest.raises(JointQuorumNotMetError):
            verify_transition(
                cert,
                old_stake={"v1": 1, "v2": 1, "v3": 1},
                new_stake={"w1": 1, "w2": 1, "w3": 1},
            )

    def test_rejects_unknown_old_signer(self) -> None:
        cert = self._make(old_signers=frozenset({"v1", "v2", "ghost"}))
        with pytest.raises(JointQuorumNotMetError):
            verify_transition(
                cert,
                old_stake={"v1": 1, "v2": 1, "v3": 1},
                new_stake={"w1": 1, "w2": 1, "w3": 1},
            )

    def test_stake_weighted_quorum(self) -> None:
        # Two signers with heavy stake can meet threshold while three
        # light signers cannot.
        cert = self._make(
            old_signers=frozenset({"v1", "v2"}),
            new_signers=frozenset({"w1", "w2"}),
        )
        verify_transition(
            cert,
            old_stake={"v1": 5, "v2": 5, "v3": 1},  # 10 ≥ 3
            new_stake={"w1": 5, "w2": 5, "w3": 1},
        )

    def test_drift_budget_exceeded(self) -> None:
        v0 = _v(0, ("a",))
        # Add many rules in one step to blow the default budget (16).
        many = tuple(f"rule{i}" for i in range(20))
        v1 = _v(1, tuple(sorted(("a", *many))), parent=v0.digest)
        proposal = AmendmentProposal(
            prior=v0,
            proposed=v1,
            drift_budget=DriftBudget(max_rule_delta=5),
        )
        cert = TransitionCertificate(
            proposal=proposal,
            old_side_signers=frozenset({"v1", "v2", "v3"}),
            new_side_signers=frozenset({"w1", "w2", "w3"}),
            old_side_threshold=3,
            new_side_threshold=3,
        )
        with pytest.raises(DriftBudgetExceeded):
            verify_transition(
                cert,
                old_stake={"v1": 1, "v2": 1, "v3": 1},
                new_stake={"w1": 1, "w2": 1, "w3": 1},
            )

    def test_drift_budget_is_checked_before_quorum(self) -> None:
        v0 = _v(0, ("a",))
        many = tuple(f"rule{i}" for i in range(20))
        v1 = _v(1, tuple(sorted(("a", *many))), parent=v0.digest)
        proposal = AmendmentProposal(
            prior=v0,
            proposed=v1,
            drift_budget=DriftBudget(max_rule_delta=5),
        )
        # Intentionally empty quorum sets — drift should still be
        # raised first.
        cert = TransitionCertificate(
            proposal=proposal,
            old_side_signers=frozenset(),
            new_side_signers=frozenset(),
            old_side_threshold=1,
            new_side_threshold=1,
        )
        with pytest.raises(DriftBudgetExceeded):
            verify_transition(cert, old_stake={}, new_stake={})

    def test_zero_threshold_rejected(self) -> None:
        v0 = _v(0, ("a",))
        v1 = _v(1, ("a", "b"), parent=v0.digest)
        proposal = AmendmentProposal(prior=v0, proposed=v1)
        with pytest.raises(InvalidTransitionError):
            TransitionCertificate(
                proposal=proposal,
                old_side_signers=frozenset(),
                new_side_signers=frozenset(),
                old_side_threshold=0,
                new_side_threshold=1,
            )
