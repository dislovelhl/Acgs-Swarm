"""Phase 9 — governed constitution sync wire-up tests.

Verifies :meth:`ConstitutionReceiver.apply_governed` gates updates on a
valid :class:`TransitionCertificate` (joint consensus + drift budget +
epoch continuity) before delegating to the underlying hash-integrity
activation path.
"""

from __future__ import annotations

from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionDistributor,
    ConstitutionReceiver,
    ConstitutionSyncMessage,
)
from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    TransitionCertificate,
)

YAML_BOOT = "name: boot\nrules: []\n"
YAML_E0 = "name: ctx-v0\nrules: []\n"
YAML_E1 = "name: ctx-v1\nrules:\n  - safety-01\n"
YAML_E2 = "name: ctx-v2\nrules:\n  - privacy-01\n  - safety-01\n"


def _version(epoch: int, rules: tuple[str, ...], parent: bytes = b"") -> ConstitutionVersion:
    return ConstitutionVersion(
        epoch=epoch,
        rules=tuple(sorted(rules)),
        parent_digest=parent,
    )


def _cert(
    prior: ConstitutionVersion,
    proposed: ConstitutionVersion,
    *,
    old_signers: frozenset[str] = frozenset({"a", "b", "c"}),
    new_signers: frozenset[str] = frozenset({"x", "y", "z"}),
    old_threshold: int = 2,
    new_threshold: int = 2,
    drift_budget: DriftBudget | None = None,
) -> TransitionCertificate:
    proposal = AmendmentProposal(
        prior=prior,
        proposed=proposed,
        drift_budget=drift_budget or DriftBudget(max_rule_delta=16),
    )
    return TransitionCertificate(
        proposal=proposal,
        old_side_signers=old_signers,
        new_side_signers=new_signers,
        old_side_threshold=old_threshold,
        new_side_threshold=new_threshold,
    )


def _stake(members: set[str], weight: int = 1) -> dict[str, int]:
    return {m: weight for m in members}


class TestApplyGovernedHappyPath:
    def test_successful_governed_update_bumps_epoch(self):
        dist = ConstitutionDistributor(YAML_E1)
        receiver = ConstitutionReceiver(node_id="miner-01")
        # Bootstrap via ungoverned apply (legacy path).
        receiver.apply(dist.broadcast_message())
        assert receiver.active_epoch is None

        # Governed upgrade from the current active YAML_E1 payload to YAML_E2.
        current = _version(0, ("safety-01",))
        old_stake = _stake({"a", "b", "c"})
        new_stake = _stake({"x", "y", "z"})

        dist.update(YAML_E2, description="adds privacy-01")
        msg = dist.broadcast_message()

        proposed = _version(1, ("privacy-01", "safety-01"), parent=current.digest)
        cert = _cert(current, proposed)

        result = receiver.apply_governed(
            msg, certificate=cert, old_stake=old_stake, new_stake=new_stake
        )
        assert result.success
        assert receiver.active_epoch == 1
        assert receiver.active_hash == msg.expected_hash

    def test_subsequent_governed_update_requires_epoch_continuity(self):
        receiver = ConstitutionReceiver(node_id="miner-02")
        dist = ConstitutionDistributor(YAML_BOOT)
        receiver.apply(dist.broadcast_message())

        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert1 = _cert(v0, v1)
        old_stake = _stake({"a", "b", "c"})
        new_stake = _stake({"x", "y", "z"})
        dist.update(YAML_E1)
        receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert1,
            old_stake=old_stake,
            new_stake=new_stake,
        )
        assert receiver.active_epoch == 1

        # Now propose E1 -> E2.
        dist.update(YAML_E2)
        v2 = _version(2, ("privacy-01", "safety-01"), parent=v1.digest)
        cert2 = _cert(
            v1, v2, old_signers=frozenset({"x", "y", "z"}), new_signers=frozenset({"p", "q", "r"})
        )
        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert2,
            old_stake=_stake({"x", "y", "z"}),
            new_stake=_stake({"p", "q", "r"}),
        )
        assert result.success
        assert receiver.active_epoch == 2


class TestApplyGovernedRejection:
    def _setup(self):
        dist = ConstitutionDistributor(YAML_BOOT)
        receiver = ConstitutionReceiver(node_id="m")
        receiver.apply(dist.broadcast_message())
        return dist, receiver

    def test_rejects_when_old_side_below_threshold(self):
        dist, receiver = self._setup()
        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert = _cert(v0, v1, old_threshold=99)  # impossible threshold
        dist.update(YAML_E1)

        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert "rejected" in result.message.lower()
        assert receiver.active_epoch is None

    def test_rejects_when_drift_exceeds_budget(self):
        dist, receiver = self._setup()
        v0 = _version(0, ())
        # 3 rules in a single jump — exceeds budget.
        v1 = _version(1, ("a", "b", "c"), parent=v0.digest)
        cert = _cert(v0, v1, drift_budget=DriftBudget(max_rule_delta=2))
        dist.update("name: ctx-v1\nrules:\n  - a\n  - b\n  - c\n")

        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert receiver.active_epoch is None

    def test_rejects_stale_epoch_certificate(self):
        dist, receiver = self._setup()
        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert1 = _cert(v0, v1)
        dist.update(YAML_E1)
        receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert1,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert receiver.active_epoch == 1

        # Replay the same cert — now stale (receiver is at epoch 1).
        dist.update(YAML_E2)
        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert1,  # still E0 -> E1
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert "stale" in result.message.lower()
        assert receiver.active_epoch == 1  # unchanged

    def test_rejects_unknown_signers(self):
        dist, receiver = self._setup()
        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert = _cert(v0, v1, old_signers=frozenset({"ghost", "b", "c"}))
        dist.update(YAML_E1)
        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert receiver.active_epoch is None

    def test_failed_cert_leaves_state_untouched(self):
        dist, receiver = self._setup()
        initial_hash = receiver.active_hash
        initial_epoch = receiver.active_epoch
        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert = _cert(v0, v1, new_threshold=99)

        dist.update(YAML_E2)
        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert receiver.active_hash == initial_hash
        assert receiver.active_epoch == initial_epoch

    def test_rejects_certificate_with_wrong_active_prior(self):
        dist = ConstitutionDistributor(YAML_E1)
        receiver = ConstitutionReceiver(node_id="m")
        receiver.apply(dist.broadcast_message())

        wrong_prior = _version(0, ())
        proposed = _version(1, ("privacy-01", "safety-01"), parent=wrong_prior.digest)
        cert = _cert(wrong_prior, proposed)
        dist.update(YAML_E2)

        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert "prior" in result.message.lower()

    def test_rejects_message_not_bound_to_certificate_proposal(self):
        dist = ConstitutionDistributor(YAML_BOOT)
        receiver = ConstitutionReceiver(node_id="m")
        receiver.apply(dist.broadcast_message())

        v0 = _version(0, ())
        proposed = _version(1, ("safety-01",), parent=v0.digest)
        cert = _cert(v0, proposed)
        dist.update(YAML_E2)

        result = receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert "proposal" in result.message.lower()


class TestApplyGovernedIntegrity:
    def test_hash_mismatch_after_valid_cert_still_rejects(self):
        dist = ConstitutionDistributor(YAML_E1)
        receiver = ConstitutionReceiver(node_id="m")
        receiver.apply(dist.broadcast_message())

        prior = _version(0, ("safety-01",))

        # Tamper only a non-governance field so certificate binding still passes
        # and the rejection comes from the final content-hash integrity check.
        dist.update(YAML_E2)
        legit = dist.broadcast_message()
        proposed = _version(1, ("privacy-01", "safety-01"), parent=prior.digest)
        cert = _cert(prior, proposed)
        tampered = ConstitutionSyncMessage(
            version_id=legit.version_id,
            expected_hash=legit.expected_hash,
            yaml_content="name: tampered\nrules:\n  - privacy-01\n  - safety-01\n",
            issued_at=legit.issued_at,
            issuer_id=legit.issuer_id,
            block_height=legit.block_height,
            description=legit.description,
        )
        result = receiver.apply_governed(
            tampered,
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert not result.success
        assert "hash mismatch" in result.message.lower()
        assert receiver.active_epoch is None

    def test_summary_includes_active_epoch(self):
        receiver = ConstitutionReceiver(node_id="m")
        assert receiver.summary()["active_epoch"] is None

        dist = ConstitutionDistributor(YAML_BOOT)
        receiver.apply(dist.broadcast_message())
        v0 = _version(0, ())
        v1 = _version(1, ("safety-01",), parent=v0.digest)
        cert = _cert(v0, v1)
        dist.update(YAML_E1)
        receiver.apply_governed(
            dist.broadcast_message(),
            certificate=cert,
            old_stake=_stake({"a", "b", "c"}),
            new_stake=_stake({"x", "y", "z"}),
        )
        assert receiver.summary()["active_epoch"] == 1

    def test_legacy_apply_does_not_touch_active_epoch(self):
        dist = ConstitutionDistributor(YAML_E1)
        receiver = ConstitutionReceiver(node_id="m")
        result = receiver.apply(dist.broadcast_message())
        assert result.success
        assert receiver.active_epoch is None
        dist.update(YAML_E2)
        receiver.apply(dist.broadcast_message())
        assert receiver.active_epoch is None
