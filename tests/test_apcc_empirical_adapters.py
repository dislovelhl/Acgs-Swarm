from __future__ import annotations

import threading
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.authority_service import _SwarmExecutionHandle
from constitutional_swarm.governed_commit import CommitRequest
from constitutional_swarm.apcc_empirical.adapters import (
    BaselineEvidence,
    B4InterleavingBarrier,
    B6AuthorityAdapter,
    BaselineBlocked,
    Capability,
    ExperimentalSQLiteAdapter,
    ScenarioExecutionError,
    TrialStimulus,
    create_baseline_adapter,
    native_evidence_for_variant,
)


def test_b0_through_b4_are_isolated_sqlite_experiments_with_exact_guarantees(
    tmp_path: Path,
) -> None:
    expected = {
        "B0": frozenset({Capability.DURABLE_SNAPSHOT}),
        "B1": frozenset({Capability.DURABLE_SNAPSHOT, Capability.POST_HOC_AUDIT}),
        "B2": frozenset({Capability.DURABLE_SNAPSHOT, Capability.POLICY_GATE}),
        "B3": frozenset({Capability.DURABLE_SNAPSHOT, Capability.SIGNED_RESULT}),
        "B4": frozenset(
            {
                Capability.DURABLE_SNAPSHOT,
                Capability.PROOF_VALIDATION,
                Capability.CONTROLLED_INTERLEAVING,
            }
        ),
    }
    for baseline_id, guarantees in expected.items():
        adapter = create_baseline_adapter(baseline_id, tmp_path / f"{baseline_id}.db")
        assert isinstance(adapter, ExperimentalSQLiteAdapter)
        assert adapter.guarantees == guarantees
        control = adapter.execute(TrialStimulus.control(b"valid"))
        assert control.authoritative_outcome == "committed"
        assert adapter.snapshot().accepted_count == 1

    with pytest.raises(BaselineBlocked, match="frozen historical GCB"):
        create_baseline_adapter("B5", tmp_path / "b5.db")


def test_b4_interleaving_barrier_is_explicit_and_one_shot() -> None:
    barrier = B4InterleavingBarrier()
    assert not barrier.verification_reached.is_set()
    barrier.mark_verified()
    assert barrier.verification_reached.is_set()
    barrier.release_commit()
    barrier.await_commit_release(timeout_seconds=0.1)
    with pytest.raises(RuntimeError, match="already released"):
        barrier.release_commit()


def test_b4_adapter_exposes_the_validation_to_commit_interleaving(
    tmp_path: Path,
) -> None:
    barrier = B4InterleavingBarrier()
    adapter = create_baseline_adapter(
        "B4", tmp_path / "b4-race.db", interleaving_barrier=barrier
    )
    stimulus = TrialStimulus(
        b"race",
        native_evidence_for_variant("concurrent-double-commit:default"),
        "concurrent-double-commit",
        frozenset({Capability.DURABLE_SNAPSHOT}),
    )
    result: list[str] = []

    def execute() -> None:
        result.append(adapter.execute(stimulus).authoritative_outcome)

    thread = threading.Thread(target=execute)
    thread.start()
    assert barrier.verification_reached.wait(0.5)
    assert result == []
    barrier.release_commit()
    thread.join(0.5)
    assert not thread.is_alive()
    assert result == ["committed"]


def test_outcome_depends_on_native_evidence_not_attack_metadata(
    tmp_path: Path,
) -> None:
    evidence = native_evidence_for_variant("missing-proof:absent")
    observations = []
    for index, (attack_id, capabilities) in enumerate(
        (("missing-proof", frozenset()), ("invented-label", frozenset(Capability)))
    ):
        adapter = create_baseline_adapter("B4", tmp_path / f"metadata-{index}.db")
        observations.append(
            adapter.execute(
                TrialStimulus(
                    b"identical",
                    evidence,
                    attack_id=attack_id,
                    capabilities=capabilities,
                )
            ).authoritative_outcome
        )
    assert observations == ["denied", "denied"]


def test_real_signature_and_binding_evidence_changes_b4_outcome(tmp_path: Path) -> None:
    valid = BaselineEvidence.valid()
    invalid_signature = native_evidence_for_variant("invalid-signature:default")
    unknown_key = native_evidence_for_variant("unknown-key:default")
    substituted = native_evidence_for_variant("input-substitution:input-digest")

    trusted = valid.trusted_keys[0]
    Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
        valid.signature, valid.encoded_statement
    )
    with pytest.raises(Exception):
        Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
            invalid_signature.signature, invalid_signature.encoded_statement
        )
    assert unknown_key.signer_key_id not in {
        key.key_id for key in unknown_key.trusted_keys
    }
    Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
        substituted.signature, substituted.encoded_statement
    )
    assert substituted.presented_input_digest != substituted.expected_input_digest

    outcomes = []
    for index, evidence in enumerate(
        (valid, invalid_signature, unknown_key, substituted)
    ):
        adapter = create_baseline_adapter("B4", tmp_path / f"native-{index}.db")
        outcomes.append(
            adapter.execute(TrialStimulus(b"payload", evidence)).authoritative_outcome
        )
    assert outcomes == ["committed", "denied", "denied", "denied"]


def test_b3_signs_its_own_result_without_claiming_proof_validation(
    tmp_path: Path,
) -> None:
    b3 = create_baseline_adapter("B3", tmp_path / "fair-b3.db")
    result = b3.execute(
        TrialStimulus(
            b"attacker-result",
            native_evidence_for_variant("invalid-signature:default"),
            attack_id="invalid-signature",
        )
    )
    assert result.authoritative_outcome == "committed"
    assert result.signed_result_verified is True


def test_every_scenario_variant_has_a_distinct_native_evidence_mutation() -> None:
    control = BaselineEvidence.valid()
    from constitutional_swarm.apcc_empirical.scenarios import REQUIRED_VARIANTS

    assert all(
        native_evidence_for_variant(variant) != control for variant in REQUIRED_VARIANTS
    )


def test_b1_post_hoc_audit_detects_but_does_not_prevent_compromise(
    tmp_path: Path,
) -> None:
    invalid = TrialStimulus(
        b"invalid",
        native_evidence_for_variant("invalid-signature:default"),
        attack_id="invalid-signature",
    )
    b0 = create_baseline_adapter("B0", tmp_path / "b0-audit.db")
    b1 = create_baseline_adapter("B1", tmp_path / "b1-audit.db")
    assert b0.execute(invalid).authoritative_outcome == "committed"
    assert b1.execute(invalid).authoritative_outcome == "committed"
    assert b0.snapshot().detected_count == 0
    assert b1.snapshot().detected_count == 1


def test_b1_commit_is_durable_before_the_separate_post_hoc_audit(
    tmp_path: Path,
) -> None:
    observed = []
    b1 = ExperimentalSQLiteAdapter(
        "B1",
        tmp_path / "b1-window.db",
        after_commit=lambda adapter: observed.append(adapter.snapshot()),
    )
    invalid = TrialStimulus(
        b"invalid",
        native_evidence_for_variant("invalid-signature:default"),
        attack_id="invalid-signature",
    )

    result = b1.execute(invalid)

    assert result.authoritative_outcome == "committed"
    assert observed[0].accepted_count == 1
    assert observed[0].detected_count == 0
    assert observed[0].pending_audit_count == 1
    assert b1.snapshot().detected_count == 1
    assert b1.snapshot().pending_audit_count == 0


def test_b3_persists_a_real_verifiable_ed25519_signed_result(tmp_path: Path) -> None:
    b3 = create_baseline_adapter("B3", tmp_path / "b3-signature.db")
    result = b3.execute(TrialStimulus.control(b"valid"))
    assert result.signed_result is not None
    assert result.signed_result_signature is not None
    assert result.signing_public_key is not None
    Ed25519PublicKey.from_public_bytes(result.signing_public_key).verify(
        result.signed_result_signature, result.signed_result
    )
    assert result.signed_result_verified is True
    assert b3.snapshot().signed_result_count == 1


def test_b0_through_b4_do_not_invent_apcc_observation_fields(tmp_path: Path) -> None:
    for baseline_id in ("B0", "B1", "B2", "B3", "B4"):
        adapter = create_baseline_adapter(
            baseline_id, tmp_path / f"{baseline_id}-truth.db"
        )
        observation = adapter.execute(TrialStimulus.control(b"valid"))
        snapshot = adapter.snapshot()
        assert observation.certificate_digest is None
        assert observation.pointer_digest is None
        assert observation.outbox_pending is None
        assert observation.current_status is None
        assert snapshot.certificate_digests is None
        assert snapshot.pointer_digest is None
        assert snapshot.outbox_pending is None


def test_b4_timeout_is_a_harness_error_not_a_blocked_cell(tmp_path: Path) -> None:
    adapter = create_baseline_adapter(
        "B4",
        tmp_path / "b4-timeout.db",
        interleaving_barrier=B4InterleavingBarrier(),
    )
    stimulus = TrialStimulus(
        b"race",
        native_evidence_for_variant("concurrent-double-commit:default"),
        "concurrent-double-commit",
        frozenset({Capability.DURABLE_SNAPSHOT}),
    )
    with pytest.raises(ScenarioExecutionError, match="timed out"):
        adapter.execute(stimulus)


def test_b6_rejects_privileged_duck_typed_client() -> None:
    class HostileClient:
        def commit(self, request: object) -> object:
            return request

        def authoritative_artifact(self, artifact_id: str) -> object:
            return artifact_id

        def revoke(self) -> None:
            raise AssertionError("privileged escape")

    adapter = B6AuthorityAdapter()
    with pytest.raises(TypeError, match="spawned authority execution handle"):
        adapter.execute_trusted(
            TrialStimulus.control(b"unused"),
            execution=cast(_SwarmExecutionHandle, cast(object, HostileClient())),
        )


def test_b6_binds_payload_to_the_exact_prebuilt_request() -> None:
    @dataclass(frozen=True)
    class _Request:
        def canonical_hash(self) -> str:
            return "a" * 64

    class _Process:
        pid = 1

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float) -> None:
            del timeout

    local, peer = socket.socketpair(socket.AF_UNIX)
    handle = _SwarmExecutionHandle(local, _Process(), 4096)
    try:
        adapter = B6AuthorityAdapter()
        with pytest.raises(ScenarioExecutionError, match="payload does not bind"):
            adapter.execute_trusted(
                TrialStimulus.control(
                    b"attacker-payload",
                    cast(CommitRequest, cast(object, _Request())),
                ),
                execution=handle,
            )
        assert vars(adapter) == {}
    finally:
        handle.close()
        peer.close()
