from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import (
    decode_authority_status,
    decode_certificate,
    encode_authority_status,
)
from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import LogicalNodeState
from constitutional_swarm.apcc.observation import (
    AuthorityObservationSnapshot,
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    _canonical_object_profile,
    _nullable_outbox_record,
    _operation_object,
    _validate_outbox_semantics,
    verify_authority_observation,
)
from constitutional_swarm.apcc.ports import (
    RevocationRequest,
    RevocationScope,
    SupersessionRequest,
)
from constitutional_swarm.apcc.sqlite_store import _operation_identity
from constitutional_swarm.apcc.verifier import ScopedTrust
from tests.test_apcc_observation import (
    _advance_candidate,
    _config,
    _launch_expectations,
    _launch_for_observer_key,
    _open_observer,
    _open_store,
    _request,
    _sign_snapshot,
    _target_for,
    commit_request,
)
from tests.test_apcc_sqlite import _resigned_status


def _verify(snapshot: AuthorityObservationSnapshot):
    observer = Ed25519PrivateKey.generate()
    observer_public = observer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, controller)
    signed, _ = _sign_snapshot(
        snapshot, observer, launch_digest=launch.canonical_digest
    )
    return verify_authority_observation(
        signed,
        launch=launch,
        pinned_controller_public_key=controller_public,
        expected_experiment_id=launch.experiment_id,
        expected_run_id=launch.run_id,
        expected_launch=_launch_expectations(launch),
        trust=ScopedTrust(_config().trust_bindings),
        now_ms=int(time.time() * 1000),
        maximum_staleness_ms=5000,
        highest_trust_log_sequence=launch.initial_trust_sequence,
        highest_trust_log_head=launch.initial_trust_head,
    )


def _sequences(snapshot: AuthorityObservationSnapshot) -> tuple[int, int, int, int]:
    assert snapshot.outbox_record_bytes is not None
    assert snapshot.current_status_evidence is not None
    assert snapshot.certificate_payload_bytes is not None
    outbox = json.loads(snapshot.outbox_record_bytes)
    status = decode_authority_status(snapshot.current_status_evidence)
    certificate = decode_certificate(snapshot.certificate_payload_bytes)
    return (
        int(outbox["event_sequence"]),
        int(outbox["trust_sequence"]),
        int(status.trust_log_sequence),
        int(certificate.header.certificate_sequence),
    )


def test_outbox_sequence_is_its_trust_event_not_certificate_sequence(tmp_path) -> None:
    path = tmp_path / "control-before-commit.db"
    store = _open_store(path, None)
    store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            "unrelated-workflow",
            "unrelated-agent",
            "1",
            "control before commit",
        )
    )
    request = commit_request(commit_id="after-control", nonce_byte=210)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    snapshot = _open_observer(path).observe_authority(_target_for(request))

    event, trust, status, certificate = _sequences(snapshot)
    assert event == trust == status
    assert event > certificate
    assert _verify(snapshot).consumable is True


def test_outbox_sequence_allows_later_unrelated_trust_events(tmp_path) -> None:
    path = tmp_path / "later-commit.db"
    store = _open_store(path, None)
    first = commit_request(commit_id="first", nonce_byte=211)
    _advance_candidate(store, first)
    store.atomic_commit(first)
    later = commit_request(commit_id="later", nonce_byte=212, node_id="root")
    _advance_candidate(store, later)
    store.atomic_commit(later)
    snapshot = _open_observer(path).observe_authority(_target_for(first))

    event, trust, status, _certificate = _sequences(snapshot)
    assert event == trust < status
    assert _verify(snapshot).consumable is True


@pytest.mark.parametrize("transition", ("revoked", "superseded"))
def test_outbox_sequence_remains_historical_after_status_transition(
    tmp_path, transition: str
) -> None:
    path = tmp_path / f"{transition}.db"
    store = _open_store(path, None)
    original = commit_request(commit_id=f"{transition}-old", nonce_byte=213)
    _advance_candidate(store, original)
    committed = store.atomic_commit(original)
    assert committed.certificate_digest is not None
    if transition == "revoked":
        store.revoke(
            RevocationRequest(
                RevocationScope.CERTIFICATE,
                original.subject.workflow_id,
                committed.certificate_digest,
                "1",
                "semantic revocation",
            )
        )
    else:
        replacement = commit_request(
            commit_id="superseded-new",
            nonce_byte=214,
            expected_node_version="1",
            attempt_id="replacement-attempt",
        )
        _advance_candidate(store, replacement)
        store.supersede(SupersessionRequest(committed.certificate_digest, replacement))
        replacement_snapshot = _open_observer(path).observe_authority(
            replace(
                _target_for(replacement),
                expected_operation_digest=_operation_identity(
                    replacement, committed.certificate_digest
                ),
            )
        )
        assert _verify(replacement_snapshot).consumable is True
    snapshot = _open_observer(path).observe_authority(_target_for(original))

    event, trust, status, _certificate = _sequences(snapshot)
    assert event == trust < status
    assert _verify(snapshot).consumable is False


def _outbox_record(**changes: str | None) -> dict[str, str | None]:
    value: dict[str, str | None] = {
        "event_sequence": "2",
        "event_id": sha256_digest(b"event-1"),
        "event_kind": "COMMIT",
        "operation_id": "commit-1",
        "event_payload_sha256": sha256_digest(b"payload"),
        "audit_event_id": sha256_digest(b"audit"),
        "trust_sequence": "2",
        "state": "PENDING",
        "lease_token": None,
        "lease_claimed_ms": None,
        "lease_until_ms": None,
        "delivered": "0",
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    "changes",
    (
        {"state": "PENDING", "lease_token": "lease"},
        {"state": "DELIVERED", "delivered": "1", "lease_claimed_ms": "1"},
        {"state": "CLAIMED", "lease_token": "lease", "lease_claimed_ms": "2"},
        {
            "state": "CLAIMED",
            "lease_token": "lease",
            "lease_claimed_ms": "3",
            "lease_until_ms": "2",
        },
    ),
)
def test_outbox_lifecycle_grammar_rejects_invalid_lease_shapes(changes) -> None:
    with pytest.raises(ValueError, match="lifecycle"):
        _validate_outbox_semantics(_outbox_record(**changes), status_trust_sequence="2")


def test_outbox_claimed_and_delivered_exact_grammar() -> None:
    _validate_outbox_semantics(
        _outbox_record(
            state="CLAIMED",
            lease_token="lease-1",
            lease_claimed_ms="2",
            lease_until_ms="2",
        ),
        status_trust_sequence="3",
    )
    _validate_outbox_semantics(
        _outbox_record(state="DELIVERED", delivered="1"),
        status_trust_sequence="3",
    )


@pytest.mark.parametrize(
    "raw",
    (
        b'{"a":"x","a":"y"}',
        b'{"a":1}',
        b'{"a":null}',
        b'{ "a":"x"}',
        b'{"a":"x","extra":"y"}',
    ),
)
def test_strict_cj1_object_profile_rejects_noncanonical_values(raw: bytes) -> None:
    with pytest.raises(ValueError):
        _canonical_object_profile(raw, name="probe", keys=frozenset({"a"}))


def test_nullable_outbox_carrier_rejects_null_outside_lease_fields() -> None:
    raw = json.dumps(
        _outbox_record(event_id=None), separators=(",", ":"), sort_keys=True
    ).encode()
    with pytest.raises(ValueError, match="null"):
        _nullable_outbox_record(raw)


def test_operation_profile_rejects_nested_numbers_and_extra_fields() -> None:
    with pytest.raises(ValueError):
        _operation_object(
            b'{"old_certificate_digest":null,"operation_kind":"COMMIT",'
            b'"request":{"unexpected":1}}'
        )
    with pytest.raises(ValueError):
        _operation_object(
            b'{"extra":"x","old_certificate_digest":null,'
            b'"operation_kind":"COMMIT","request":{}}'
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("session_id", "x" * 129),
        ("session_id", "bad session"),
        ("initial_trust_sequence", "9007199254740992"),
        ("observer_pid", "01"),
        ("not_after_ms", "9007199254740992"),
    ),
)
def test_launch_applies_frozen_identifier_and_decimal_bounds(field, value) -> None:
    observer = Ed25519PrivateKey.generate()
    observer_public = observer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, Ed25519PrivateKey.generate())
    with pytest.raises(ValueError):
        replace(launch, **{field: value})


def test_signed_observation_sequence_and_session_are_bounded() -> None:
    snapshot = AuthorityObservationSnapshot(
        _request(),
        AuthorityObservationState.ABSENT,
        None,
        None,
        None,
        None,
        None,
        LogicalNodeState("workflow-1", "node-1", "0", None),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )
    signed, _ = _sign_snapshot(snapshot, Ed25519PrivateKey.generate())
    with pytest.raises(ValueError):
        replace(signed, sequence="9007199254740992")
    with pytest.raises(ValueError):
        replace(signed, session_id="x" * 129)


def test_stream_anchors_only_after_verified_launch() -> None:
    observer = Ed25519PrivateKey.generate()
    observer_public = observer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, controller)
    forged_launch = replace(launch, initial_trust_sequence="1")
    snapshot = AuthorityObservationSnapshot(
        _request(),
        AuthorityObservationState.ABSENT,
        None,
        None,
        None,
        None,
        None,
        LogicalNodeState("workflow-1", "node-1", "0", None),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )
    forged, _ = _sign_snapshot(
        snapshot, observer, launch_digest=forged_launch.canonical_digest
    )
    stream = AuthorityObservationVerificationStream(launch.session_id)
    with pytest.raises(ValueError, match="signature"):
        stream.consume(
            forged,
            launch=forged_launch,
            pinned_controller_public_key=controller_public,
            expected_experiment_id=forged_launch.experiment_id,
            expected_run_id=forged_launch.run_id,
            expected_launch=_launch_expectations(forged_launch),
            trust=ScopedTrust(_config().trust_bindings),
            now_ms=int(time.time() * 1000),
            maximum_staleness_ms=5000,
        )
    assert stream.highest_trust_log_sequence == "0"
    assert stream.highest_trust_log_head == ""
    assert stream.launch_attestation_digest == ""
    assert stream.next_sequence == 1

    valid, _ = _sign_snapshot(snapshot, observer, launch_digest=launch.canonical_digest)
    stream.consume(
        valid,
        launch=launch,
        pinned_controller_public_key=controller_public,
        expected_experiment_id=launch.experiment_id,
        expected_run_id=launch.run_id,
        expected_launch=_launch_expectations(launch),
        trust=ScopedTrust(_config().trust_bindings),
        now_ms=int(time.time() * 1000),
        maximum_staleness_ms=5000,
    )
    assert stream.highest_trust_log_sequence == launch.initial_trust_sequence
    assert stream.highest_trust_log_head == launch.initial_trust_head
    assert stream.launch_attestation_digest == launch.canonical_digest
    assert stream.next_sequence == 2


def test_stream_rejects_same_sequence_with_different_trust_head(tmp_path) -> None:
    path = tmp_path / "stream-head.db"
    store = _open_store(path, None)
    request = commit_request(commit_id="stream-head", nonce_byte=215)
    _advance_candidate(store, request)
    store.atomic_commit(request)
    snapshot = _open_observer(path).observe_authority(_target_for(request))
    observer = Ed25519PrivateKey.generate()
    observer_public = observer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, controller)
    stream = AuthorityObservationVerificationStream(launch.session_id)

    first, _ = _sign_snapshot(snapshot, observer, launch_digest=launch.canonical_digest)
    stream.consume(
        first,
        launch=launch,
        pinned_controller_public_key=controller_public,
        expected_experiment_id=launch.experiment_id,
        expected_run_id=launch.run_id,
        expected_launch=_launch_expectations(launch),
        trust=ScopedTrust(_config().trust_bindings),
        now_ms=int(time.time() * 1000),
        maximum_staleness_ms=5000,
    )
    assert snapshot.current_status_evidence is not None
    status = decode_authority_status(snapshot.current_status_evidence)
    forged_snapshot = replace(
        snapshot,
        current_status_evidence=encode_authority_status(
            _resigned_status(status, trust_log_head=sha256_digest(b"forged-head"))
        ),
    )
    forged, _ = _sign_snapshot(
        forged_snapshot,
        observer,
        launch_digest=launch.canonical_digest,
        sequence="2",
    )
    with pytest.raises(ValueError, match="ROLLBACK"):
        stream.consume(
            forged,
            launch=launch,
            pinned_controller_public_key=controller_public,
            expected_experiment_id=launch.experiment_id,
            expected_run_id=launch.run_id,
            expected_launch=_launch_expectations(launch),
            trust=ScopedTrust(_config().trust_bindings),
            now_ms=int(time.time() * 1000),
            maximum_staleness_ms=5000,
        )
    assert stream.next_sequence == 2
    assert stream.highest_trust_log_sequence == status.trust_log_sequence
    assert stream.highest_trust_log_head == status.trust_log_head
