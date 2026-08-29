"""Independent APCC authority-observation contracts."""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
import signal
import sqlite3
import struct
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.codec import (
    CodecError,
    decode_authority_status,
    encode_authority_status,
)
from constitutional_swarm.apcc.model import (
    LogicalNodeState,
    Signature,
)
from constitutional_swarm.apcc.observation import (
    AUTHORITY_OBSERVATION_DOMAIN,
    AuthorityObservationRequest,
    AuthorityObservationSnapshot,
    AuthorityObservationState,
    AuthorityObservationVerificationStream,
    ObservationAuthorityProof,
    ObservationEvidenceProvenance,
    ObserverLaunchExpectationsV1,
    ObserverLaunchAttestationV1,
    SignedAuthorityObservation,
    decode_authority_observation_request,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    encode_authority_observation_body,
    encode_authority_observation_request,
    encode_observer_launch_attestation,
    encode_signed_authority_observation,
    verify_authority_observation,
    verify_signed_authority_observation,
)
from constitutional_swarm.apcc.ports import (
    AuthorityObservationStore,
    RevocationRequest,
    RevocationScope,
    SupersessionCommitted,
    SupersessionRequest,
)
from constitutional_swarm.apcc.sqlite_store import (
    SQLiteAuthorityReader,
    SQLiteAuthorityStore,
    _operation_identity,
    _public_request_digest,
)
from tests.test_apcc_sqlite import (
    _config,
    _advance_candidate,
    _open_store,
    _request as commit_request,
    _runtime,
)
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.authority_observer import (
    AuthorityObserverLaunchConfig,
    ControllerKeySourceRef,
    sign_launch_candidate,
)
from tests.gcb_apcc_support import authority_child_config


def _stubborn_observer_child(readiness) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    readiness.send(os.getpid())
    readiness.close()
    while True:
        time.sleep(1)


def _watch_later_child_births(parent_pid: int, known: set[int], channel) -> None:
    own_pid = os.getpid()
    observed: set[int] = set()
    channel.send("ready")
    while True:
        parents: dict[int, int] = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            try:
                stat_tail = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2]
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            stat_fields = stat_tail.split()
            if len(stat_fields) > 1:
                parents[pid] = int(stat_fields[1])
        for pid in parents:
            if pid == own_pid or pid in known:
                continue
            ancestor = parents.get(pid)
            visited: set[int] = set()
            while ancestor not in {None, 0, 1} and ancestor not in visited:
                if ancestor == parent_pid:
                    observed.add(pid)
                    break
                visited.add(ancestor)
                ancestor = parents.get(ancestor)
        if channel.poll(0.01):
            command = channel.recv()
            if command == "checkpoint":
                channel.send("checkpoint")
                continue
            if command == "stop":
                channel.send(observed)
                channel.close()
                return
            raise ValueError("invalid watcher command")


def _direct_child_pids(parent_pid: int) -> set[int]:
    children: set[int] = set()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            stat_tail = Path(f"/proc/{name}/stat").read_text().rpartition(")")[2]
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        fields = stat_tail.split()
        if len(fields) > 1 and int(fields[1]) == parent_pid:
            children.add(int(name))
    return children


def _hold_descendant_probe(channel) -> None:
    channel.send(os.getpid())
    channel.recv()
    channel.close()


def _spawn_descendant_probe(channel) -> None:
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=True)
    descendant = context.Process(target=_hold_descendant_probe, args=(child,))
    descendant.start()
    child.close()
    channel.send((os.getpid(), parent.recv()))
    channel.recv()
    parent.send("stop")
    parent.close()
    descendant.join(2)
    descendant.close()
    channel.close()


def _digest(byte: int) -> str:
    return b64u_encode(bytes((byte,)) * 32)


def _nonce(byte: int = 1) -> str:
    return b64u_encode(bytes((byte,)) * 16)


def _observer_launch(config, tmp_path: Path) -> AuthorityObserverLaunchConfig:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    location = tmp_path / "observer-controller.key"
    location.write_text(b64u_encode(private), encoding="ascii")
    location.chmod(0o600)
    return AuthorityObserverLaunchConfig(
        experiment_id="experiment-1",
        run_id="run-1",
        authority_store_id=config.authority.authority_store_id,
        backend_kind="sqlite",
        backend_instance="sqlite-test-instance",
        backend_schema=None,
        controller_key_id=sha256_digest(public),
        controller_key_source=ControllerKeySourceRef(str(location), public),
    )


def _request() -> AuthorityObservationRequest:
    return AuthorityObservationRequest(
        protocol_version="APCC-1.0-draft",
        statement_type="apcc.authority-observation-request",
        authority_store_id="store-1",
        workflow_id="workflow-1",
        node_id="node-1",
        attempt_id="attempt-1",
        expected_commit_id="commit-1",
        expected_operation_digest=_digest(2),
        public_request_digest=_digest(3),
        request_nonce=_nonce(),
    )


def test_observation_request_round_trips_only_its_canonical_bytes() -> None:
    request = _request()
    encoded = encode_authority_observation_request(request)

    assert decode_authority_observation_request(encoded) == request
    assert sha256_digest(encoded) == request.canonical_digest

    body = json.loads(encoded)
    reordered = json.dumps(
        {key: body[key] for key in reversed(tuple(body))}, separators=(",", ":")
    ).encode()
    with pytest.raises(CodecError):
        decode_authority_observation_request(reordered)

    duplicate = encoded[:-1] + b',"workflow_id":"workflow-1"}'
    with pytest.raises(CodecError):
        decode_authority_observation_request(duplicate)


def test_observation_request_v1_rejects_legacy_digest_field_and_non_cj1_ids() -> None:
    canonical = encode_authority_observation_request(_request())
    legacy = json.loads(canonical)
    legacy["expected_commit_digest"] = legacy.pop("expected_operation_digest")
    legacy_raw = json.dumps(legacy, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(CodecError):
        decode_authority_observation_request(legacy_raw)
    with pytest.raises((CodecError, ValueError)):
        AuthorityObservationRequest(
            **{
                **_request().to_object(),
                "workflow_id": "workflow with spaces",
            }
        )


def test_sqlite_schema_v3_binds_exact_conflicts_and_immutable_commit_outputs(
    tmp_path,
) -> None:
    path = tmp_path / "observation-v3.db"
    _open_store(path, None)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)
        conflict_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(commit_conflicts)")
        }
        assert {
            "original_workflow_id",
            "original_node_id",
            "original_attempt_id",
            "original_request_digest",
            "original_public_request_digest",
            "conflicting_workflow_id",
            "conflicting_node_id",
            "conflicting_attempt_id",
            "conflicting_request_digest",
            "conflicting_public_request_digest",
        }.issubset(conflict_columns)
        output_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(commit_output_refs)")
        }
        assert output_columns == {
            "commit_id",
            "workflow_id",
            "node_id",
            "attempt_id",
            "output_digest",
            "output_size",
        }


@pytest.mark.parametrize(
    "mutation",
    (
        lambda body: {**body, "unknown": "field"},
        lambda body: {key: value for key, value in body.items() if key != "node_id"},
        lambda body: {**body, "request_nonce": "not-base64url"},
        lambda body: {**body, "authority_store_id": ""},
        lambda body: {**body, "expected_operation_digest": _nonce(9)},
        lambda body: {**body, "workflow_id": 7},
    ),
)
def test_observation_request_rejects_unknown_incomplete_or_malformed_fields(
    mutation,
) -> None:
    body = json.loads(encode_authority_observation_request(_request()))
    raw = json.dumps(mutation(body), separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises((TypeError, ValueError)):
        decode_authority_observation_request(raw)


def test_observation_request_enforces_identity_and_total_size_limits() -> None:
    with pytest.raises((CodecError, ValueError)):
        replace(_request(), workflow_id="w" * 129)

    raw = encode_authority_observation_request(_request()) + b" " * 4096
    with pytest.raises((CodecError, ValueError)):
        decode_authority_observation_request(raw)


def _target_for(commit) -> AuthorityObservationRequest:
    return AuthorityObservationRequest(
        protocol_version="APCC-1.0-draft",
        statement_type="apcc.authority-observation-request",
        authority_store_id="store-1",
        workflow_id=commit.subject.workflow_id,
        node_id=commit.subject.node_id,
        attempt_id=commit.subject.attempt_id,
        expected_commit_id=commit.commit_id,
        expected_operation_digest=_operation_identity(commit, None),
        public_request_digest=_public_request_digest(commit),
        request_nonce=_nonce(33),
    )


class _TestStatusSigner:
    def __init__(self, path: Path) -> None:
        self._path = path

    def current_status(self, certificate_digest: str, request_nonce: str) -> bytes:
        class WallClock:
            def now_ms(self) -> int:
                return int(time.time() * 1000)

        return encode_authority_status(
            SQLiteAuthorityStore.open(
                self._path,
                config=_config(),
                runtime=replace(_runtime(), clock=WallClock()),
            )._observation_current_status(certificate_digest, request_nonce)
        )


def _open_observer(path: Path) -> SQLiteAuthorityReader:
    return SQLiteAuthorityReader.open(path, status_signer=_TestStatusSigner(path))


def test_status_capability_accepts_only_certificate_digest_and_nonce(tmp_path) -> None:
    from constitutional_swarm.authority_service import _handle_status_sign_request

    path = tmp_path / "status-capability.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="status-capability", nonce_byte=106)
    _advance_candidate(store, commit)
    committed = store.atomic_commit(commit)
    assert committed.certificate_digest is not None
    result = _handle_status_sign_request(
        {
            "operation": "current_status",
            "request": {
                "certificate_digest": committed.certificate_digest,
                "request_nonce": _nonce(107),
            },
        },
        store,
    )
    status = decode_authority_status(b64u_decode(result["authority_status_b64u"]))
    assert status.certificate_digest == committed.certificate_digest
    with pytest.raises((LookupError, ValueError)):
        _handle_status_sign_request(
            {
                "operation": "sign_status",
                "request": {"status": "current", "trust_log_sequence": "0"},
            },
            store,
        )


def test_observer_retries_whole_snapshot_at_most_three_times(tmp_path) -> None:
    path = tmp_path / "status-race-retry.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="status-race-retry", nonce_byte=108)
    _advance_candidate(store, commit)
    store.atomic_commit(commit)
    delegate = _TestStatusSigner(path)

    class RacingSigner:
        def __init__(self, mismatches: int) -> None:
            self.calls = 0
            self.mismatches = mismatches

        def current_status(self, certificate_digest: str, request_nonce: str) -> bytes:
            self.calls += 1
            encoded = delegate.current_status(certificate_digest, request_nonce)
            if self.calls > self.mismatches:
                return encoded
            status = decode_authority_status(encoded)
            return encode_authority_status(
                replace(
                    status, trust_log_sequence=str(int(status.trust_log_sequence) + 1)
                )
            )

    recovered = RacingSigner(2)
    reader = SQLiteAuthorityReader.open(path, status_signer=recovered)
    assert (
        reader.observe_authority(_target_for(commit)).state
        is AuthorityObservationState.COMMITTED
    )
    assert recovered.calls == 3

    exhausted = RacingSigner(3)
    reader = SQLiteAuthorityReader.open(path, status_signer=exhausted)
    with pytest.raises(RuntimeError, match="snapshot changed"):
        reader.observe_authority(_target_for(commit))
    assert exhausted.calls == 3


@pytest.mark.parametrize(
    "raw",
    (b"", b"dsn\x00tail", b"\xff", b"x" * 4097),
)
def test_postgres_observer_credential_frame_is_strict_and_bounded(raw: bytes) -> None:
    from constitutional_swarm.authority_service import (
        _decode_observer_postgres_credential,
    )

    with pytest.raises(ValueError, match="invalid PostgreSQL observer credential"):
        _decode_observer_postgres_credential(raw)


def _launch_for_observer_key(
    observer_public: bytes, controller: Ed25519PrivateKey
) -> ObserverLaunchAttestationV1:
    now = int(time.time() * 1000)
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    candidate = {
        "protocol_version": "APCC-1.0-draft",
        "statement_type": "apcc.observer-launch-attestation",
        "experiment_id": "experiment-1",
        "run_id": "run-1",
        "authority_store_id": "store-1",
        "backend_kind": "sqlite",
        "backend_instance_digest": _digest(201),
        "schema_version": "3",
        "schema_fingerprint": _digest(202),
        "status_key_id": _config().status_trust.key_id,
        "not_before_ms": str(now - 1000),
        "not_after_ms": str(now + 60_000),
        "observer_pid": "1",
        "launch_nonce": b64u_encode(bytes([203]) * 32),
        "session_id": "session-1",
        "observer_key_id": sha256_digest(observer_public),
        "observer_public_key": b64u_encode(observer_public),
        "initial_trust_sequence": "0",
        "initial_trust_head": sha256_digest(b"APCC-1/trust-log/genesis"),
    }
    return ObserverLaunchAttestationV1(
        **sign_launch_candidate(candidate, controller, sha256_digest(controller_public))
    )


def _launch_expectations(
    launch: ObserverLaunchAttestationV1,
) -> ObserverLaunchExpectationsV1:
    return ObserverLaunchExpectationsV1(
        **{
            name: getattr(launch, name)
            for name in ObserverLaunchExpectationsV1.__dataclass_fields__
        }
    )


def _sign_snapshot(
    snapshot: AuthorityObservationSnapshot,
    key: Ed25519PrivateKey,
    *,
    launch_digest: str | None = None,
    session_id: str = "session-1",
    sequence: str = "1",
) -> tuple[SignedAuthorityObservation, bytes]:
    launch_digest = _digest(200) if launch_digest is None else launch_digest
    request_digest = snapshot.request.canonical_digest
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = sha256_digest(public_key)
    signature = Signature(
        "Ed25519",
        key_id,
        b64u_encode(
            key.sign(
                AUTHORITY_OBSERVATION_DOMAIN
                + b"\x00"
                + encode_authority_observation_body(
                    snapshot,
                    launch_attestation_digest=launch_digest,
                    session_id=session_id,
                    sequence=sequence,
                    request_digest=request_digest,
                )
            )
        ),
    )
    return (
        SignedAuthorityObservation(
            snapshot,
            launch_digest,
            session_id,
            sequence,
            request_digest,
            key_id,
            signature,
        ),
        public_key,
    )


def test_sqlite_observer_reads_complete_committed_tuple_through_narrow_port(
    tmp_path,
) -> None:
    path = tmp_path / "observation.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="observed", nonce_byte=31)
    _advance_candidate(store, commit)
    committed = store.atomic_commit(commit)

    observer = _open_observer(path)
    assert isinstance(observer, AuthorityObservationStore)
    snapshot = observer.observe_authority(_target_for(commit))

    assert snapshot.state is AuthorityObservationState.COMMITTED
    assert snapshot.certificate_digest == committed.certificate_digest
    assert snapshot.certificate_envelope_bytes == committed.certificate_envelope_bytes
    assert (
        snapshot.logical_node.current_certificate_digest == committed.certificate_digest
    )
    assert snapshot.output_digest == commit.subject.output_digest
    assert snapshot.output_bytes is not None
    assert sha256_digest(snapshot.output_bytes) == commit.subject.output_digest
    assert snapshot.persisted_operation_bytes is not None
    assert snapshot.outbox_state == "PENDING"
    assert snapshot.artifact_visible is True
    assert not hasattr(observer, "atomic_commit")


def test_sqlite_observer_distinguishes_absent_denied_and_cross_request_binding(
    tmp_path,
) -> None:
    path = tmp_path / "observation-negative.db"
    store = _open_store(path, None)
    observer = _open_observer(path)
    missing = commit_request(commit_id="missing", nonce_byte=32)
    assert (
        observer.observe_authority(_target_for(missing)).state
        is AuthorityObservationState.ABSENT
    )

    denied = commit_request(
        commit_id="denied", nonce_byte=33, attempt_id="inactive-attempt"
    )
    assert store.atomic_commit(denied).decision.outcome.value == "DENIED"
    denied_snapshot = observer.observe_authority(_target_for(denied))
    assert denied_snapshot.state is AuthorityObservationState.DENIED
    assert denied_snapshot.certificate_digest is None
    assert denied_snapshot.persisted_operation_bytes is not None
    assert denied_snapshot.artifact_visible is False

    with pytest.raises(ValueError, match="binding mismatch"):
        observer.observe_authority(
            replace(_target_for(denied), public_request_digest=_digest(99))
        )


def test_sqlite_observer_rejects_wrong_attempt_with_known_exact_digests(
    tmp_path,
) -> None:
    path = tmp_path / "observation-wrong-attempt.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="wrong-attempt", nonce_byte=95)
    _advance_candidate(store, commit)
    store.atomic_commit(commit)

    with pytest.raises(ValueError, match="binding mismatch"):
        _open_observer(path).observe_authority(
            replace(_target_for(commit), attempt_id="other-attempt")
        )


def test_sqlite_observer_returns_exact_durable_conflict_branch(tmp_path) -> None:
    path = tmp_path / "observation-conflict.db"
    store = _open_store(path, None)
    original = commit_request(commit_id="conflicted", nonce_byte=90)
    _advance_candidate(store, original)
    store.atomic_commit(original)
    conflicting = commit_request(commit_id="conflicted", nonce_byte=91)
    result = store.atomic_commit(conflicting)
    assert result.decision.outcome.value == "CONFLICTED"

    snapshot = _open_observer(path).observe_authority(_target_for(conflicting))

    assert snapshot.state is AuthorityObservationState.CONFLICTED
    assert snapshot.audit_event_id == result.audit_event_id
    assert snapshot.audit_event_bytes is not None
    assert snapshot.authoritative_commit_digest == _operation_identity(original, None)
    assert snapshot.authoritative_public_request_digest == _public_request_digest(
        original
    )
    assert snapshot.certificate_digest is None
    assert snapshot.persisted_operation_bytes is not None
    assert snapshot.conflict_claim_bytes is not None
    assert snapshot.artifact_visible is False


def test_signed_observation_rejects_forgery_and_every_cross_request_binding(
    tmp_path,
) -> None:
    path = tmp_path / "signed-observation.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="signed-observation", nonce_byte=34)
    _advance_candidate(store, commit)
    store.atomic_commit(commit)
    target = _target_for(commit)
    snapshot = _open_observer(path).observe_authority(target)
    signed, public_key = _sign_snapshot(snapshot, Ed25519PrivateKey.generate())

    decoded = decode_signed_authority_observation(
        encode_signed_authority_observation(signed)
    )
    verify_signed_authority_observation(
        decoded,
        pinned_public_key=public_key,
        expected_request=target,
        expected_launch_attestation_digest=decoded.launch_attestation_digest,
        expected_session_id=decoded.session_id,
        expected_sequence="1",
    )

    forged_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    with pytest.raises(ValueError, match="key identity|signature"):
        verify_signed_authority_observation(
            decoded,
            pinned_public_key=forged_key,
            expected_request=target,
            expected_launch_attestation_digest=decoded.launch_attestation_digest,
            expected_session_id=decoded.session_id,
            expected_sequence="1",
        )

    mutations = (
        {"authority_store_id": "other-store"},
        {"workflow_id": "other-workflow"},
        {"node_id": "other-node"},
        {"expected_commit_id": "other-commit"},
        {"expected_operation_digest": _digest(71)},
        {"public_request_digest": _digest(72)},
        {"request_nonce": _nonce(73)},
    )
    for mutation in mutations:
        with pytest.raises(ValueError, match="request binding"):
            verify_signed_authority_observation(
                decoded,
                pinned_public_key=public_key,
                expected_request=replace(target, **mutation),
                expected_launch_attestation_digest=decoded.launch_attestation_digest,
                expected_session_id=decoded.session_id,
                expected_sequence="1",
            )


def test_semantic_verifier_checks_full_committed_tuple_and_derives_visibility(
    tmp_path,
) -> None:
    path = tmp_path / "semantic-observation.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="semantic-observation", nonce_byte=94)
    _advance_candidate(store, commit)
    store.atomic_commit(commit)
    snapshot = _open_observer(path).observe_authority(_target_for(commit))
    observer_key = Ed25519PrivateKey.generate()
    observer_public = observer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    launch = _launch_for_observer_key(observer_public, controller)
    signed, _ = _sign_snapshot(
        snapshot, observer_key, launch_digest=launch.canonical_digest
    )
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    verified = verify_authority_observation(
        signed,
        launch=launch,
        pinned_controller_public_key=controller_public,
        expected_experiment_id="experiment-1",
        expected_run_id="run-1",
        expected_launch=_launch_expectations(launch),
        trust=__import__(
            "constitutional_swarm.apcc.verifier", fromlist=["ScopedTrust"]
        ).ScopedTrust(_config().trust_bindings),
        now_ms=int(time.time() * 1000),
        maximum_staleness_ms=5000,
        highest_trust_log_sequence="0",
        highest_trust_log_head=launch.initial_trust_head,
    )
    assert verified.consumable is True
    assert (
        verified.authority_proof
        is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
    )
    assert (
        verified.measurement_provenance
        is ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
    )
    assert (
        verified.outbox_provenance
        is ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
    )
    assert (
        verified.outbox_authority_proof is ObservationAuthorityProof.NO_AUTHORITY_PROOF
    )
    assert (
        verified.logical_pointer_provenance
        is ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
    )
    assert (
        verified.logical_pointer_authority_proof
        is ObservationAuthorityProof.NO_AUTHORITY_PROOF
    )
    assert snapshot.outbox_record_bytes is not None

    outbox = json.loads(snapshot.outbox_record_bytes)
    outbox.update({"state": "DELIVERED", "delivered": "0"})
    forged_outbox_record = json.dumps(
        outbox, separators=(",", ":"), sort_keys=True
    ).encode()

    for mutated in (
        replace(snapshot, output_bytes=b"forged-output"),
        replace(snapshot, output_digest=_digest(199)),
        replace(snapshot, outbox_event_bytes=b"forged-outbox"),
        replace(snapshot, outbox_record_bytes=forged_outbox_record),
        replace(snapshot, decision_reason="forged"),
        replace(snapshot, audit_event_bytes=b'{"kind":"committed","subject":"forged"}'),
        replace(snapshot, audit_event_id=_digest(198)),
        replace(snapshot, certificate_payload_bytes=b"{}"),
        replace(snapshot, certificate_envelope_bytes=b"{}"),
        replace(snapshot, current_status_evidence=b"{}"),
        replace(snapshot, authoritative_commit_digest=_digest(197)),
        replace(snapshot, authoritative_public_request_digest=_digest(196)),
        replace(
            snapshot,
            logical_node=replace(snapshot.logical_node, current_node_version="999"),
        ),
        replace(snapshot, persisted_operation_bytes=b"{}"),
    ):
        forged, _ = _sign_snapshot(
            mutated, observer_key, launch_digest=launch.canonical_digest
        )
        with pytest.raises(ValueError):
            verify_authority_observation(
                forged,
                launch=launch,
                pinned_controller_public_key=controller_public,
                expected_experiment_id="experiment-1",
                expected_run_id="run-1",
                expected_launch=_launch_expectations(launch),
                trust=__import__(
                    "constitutional_swarm.apcc.verifier", fromlist=["ScopedTrust"]
                ).ScopedTrust(_config().trust_bindings),
                now_ms=int(time.time() * 1000),
                maximum_staleness_ms=5000,
                highest_trust_log_sequence="0",
                highest_trust_log_head=launch.initial_trust_head,
            )


def test_semantic_verifier_accepts_only_exact_absent_denied_and_conflicted_states(
    tmp_path,
) -> None:
    path = tmp_path / "semantic-states.db"
    store = _open_store(path, None)
    observer = _open_observer(path)
    absent_request = commit_request(commit_id="semantic-absent", nonce_byte=101)
    denied_request = commit_request(
        commit_id="semantic-denied", nonce_byte=102, attempt_id="inactive-attempt"
    )
    store.atomic_commit(denied_request)
    original = commit_request(commit_id="semantic-conflict", nonce_byte=103)
    _advance_candidate(store, original)
    store.atomic_commit(original)
    conflicting = commit_request(commit_id="semantic-conflict", nonce_byte=104)
    store.atomic_commit(conflicting)

    observer_key = Ed25519PrivateKey.generate()
    observer_public = observer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, controller)
    trust = __import__(
        "constitutional_swarm.apcc.verifier", fromlist=["ScopedTrust"]
    ).ScopedTrust(_config().trust_bindings)

    snapshots = (
        observer.observe_authority(_target_for(absent_request)),
        observer.observe_authority(_target_for(denied_request)),
        observer.observe_authority(_target_for(conflicting)),
    )
    for sequence, snapshot in enumerate(snapshots, start=1):
        signed, _ = _sign_snapshot(
            snapshot,
            observer_key,
            launch_digest=launch.canonical_digest,
            sequence=str(sequence),
        )
        verified = verify_authority_observation(
            signed,
            launch=launch,
            pinned_controller_public_key=controller_public,
            expected_experiment_id="experiment-1",
            expected_run_id="run-1",
            expected_launch=_launch_expectations(launch),
            trust=trust,
            now_ms=int(time.time() * 1000),
            maximum_staleness_ms=5000,
            highest_trust_log_sequence="0",
            highest_trust_log_head=launch.initial_trust_head,
        )
        assert verified.state == snapshot.state.value
        assert verified.consumable is False
        assert verified.authority_proof is ObservationAuthorityProof.NO_AUTHORITY_PROOF
        assert (
            verified.measurement_provenance
            is ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
        )


def test_false_coherent_observer_claims_never_become_authority_proof(tmp_path) -> None:
    path = tmp_path / "observer-provenance.db"
    store = _open_store(path, None)
    commit = commit_request(commit_id="observer-provenance", nonce_byte=105)
    _advance_candidate(store, commit)
    store.atomic_commit(commit)
    committed = _open_observer(path).observe_authority(_target_for(commit))

    observer_key = Ed25519PrivateKey.generate()
    observer_public = observer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    controller_public = controller.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    launch = _launch_for_observer_key(observer_public, controller)
    trust = __import__(
        "constitutional_swarm.apcc.verifier", fromlist=["ScopedTrust"]
    ).ScopedTrust(_config().trust_bindings)

    def verify_snapshot(snapshot: AuthorityObservationSnapshot, sequence: str):
        signed, _ = _sign_snapshot(
            snapshot,
            observer_key,
            launch_digest=launch.canonical_digest,
            sequence=sequence,
        )
        return verify_authority_observation(
            signed,
            launch=launch,
            pinned_controller_public_key=controller_public,
            expected_experiment_id="experiment-1",
            expected_run_id="run-1",
            expected_launch=_launch_expectations(launch),
            trust=trust,
            now_ms=int(time.time() * 1000),
            maximum_staleness_ms=5000,
            highest_trust_log_sequence="0",
            highest_trust_log_head=launch.initial_trust_head,
        )

    false_absent = AuthorityObservationSnapshot(
        committed.request,
        AuthorityObservationState.ABSENT,
        None,
        None,
        None,
        None,
        None,
        LogicalNodeState(
            committed.request.workflow_id, committed.request.node_id, "0", None
        ),
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
    absent_result = verify_snapshot(false_absent, "1")
    assert absent_result.consumable is False
    assert absent_result.authority_proof is ObservationAuthorityProof.NO_AUTHORITY_PROOF

    denial_reason = "OBSERVER_ONLY_DENIAL"
    denial_audit = json.dumps(
        {"kind": denial_reason, "subject": committed.request.expected_commit_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    denial_audit_id = sha256_digest(
        (
            "DENIED\x00"
            + committed.request.expected_commit_id
            + "\x00"
            + committed.request.expected_operation_digest
            + "\x00"
            + denial_reason
        ).encode("ascii")
    )
    false_denied = AuthorityObservationSnapshot(
        committed.request,
        AuthorityObservationState.DENIED,
        committed.authoritative_commit_digest,
        committed.authoritative_public_request_digest,
        denial_reason,
        denial_audit_id,
        denial_audit,
        committed.logical_node,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
        committed.persisted_operation_bytes,
    )
    denied_result = verify_snapshot(false_denied, "2")
    assert denied_result.consumable is False
    assert denied_result.authority_proof is ObservationAuthorityProof.NO_AUTHORITY_PROOF

    assert committed.outbox_record_bytes is not None
    delivered = json.loads(committed.outbox_record_bytes)
    delivered.update({"state": "DELIVERED", "delivered": "1"})
    coherent_outbox = replace(
        committed,
        outbox_state="DELIVERED",
        outbox_record_bytes=json.dumps(
            delivered, separators=(",", ":"), sort_keys=True
        ).encode(),
    )
    committed_result = verify_snapshot(coherent_outbox, "3")
    assert committed_result.consumable is True
    assert (
        committed_result.authority_proof
        is ObservationAuthorityProof.AUTHORITY_CERTIFICATE_STATUS_OUTPUT
    )
    assert (
        committed_result.outbox_provenance
        is ObservationEvidenceProvenance.OBSERVER_ATTESTED_NONAUTHORITATIVE
    )
    assert (
        committed_result.outbox_authority_proof
        is ObservationAuthorityProof.NO_AUTHORITY_PROOF
    )


def test_launch_codec_is_strict_and_observation_wire_has_no_trusted_visibility() -> (
    None
):
    observer = Ed25519PrivateKey.generate()
    observer_public = observer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    controller = Ed25519PrivateKey.generate()
    launch = _launch_for_observer_key(observer_public, controller)
    encoded_launch = encode_observer_launch_attestation(launch)
    assert decode_observer_launch_attestation(encoded_launch) == launch
    launch_object = json.loads(encoded_launch)
    launch_object["unknown"] = "field"
    with pytest.raises(ValueError):
        decode_observer_launch_attestation(
            json.dumps(launch_object, separators=(",", ":"), sort_keys=True).encode()
        )

    absent = AuthorityObservationSnapshot(
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
    signed, _ = _sign_snapshot(absent, observer)
    wire = encode_signed_authority_observation(signed)
    assert b"artifact_visible" not in wire
    assert b"null" not in wire
    decoded = decode_signed_authority_observation(wire)
    assert decoded.snapshot.state is AuthorityObservationState.ABSENT


def test_offline_observation_stream_rejects_missing_or_reordered_sequence() -> None:
    stream = AuthorityObservationVerificationStream("session-1")
    assert stream.next_sequence == 1
    stream.next_sequence = 2
    assert stream.next_sequence == 2


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["body"].pop("evidence"),
        lambda value: value["body"].update({"unknown": "field"}),
        lambda value: value["body"]["evidence"].update({"unexpected": "field"}),
        lambda value: value["body"]["logical_node"].update({"current_node_version": 1}),
    ),
)
def test_signed_observation_rejects_incomplete_unknown_or_malformed_body(
    tmp_path, mutation
) -> None:
    path = tmp_path / "malformed-observation.db"
    _open_store(path, None)
    target = _target_for(commit_request(commit_id="absent", nonce_byte=35))
    snapshot = _open_observer(path).observe_authority(target)
    signed, _public_key = _sign_snapshot(snapshot, Ed25519PrivateKey.generate())
    value = json.loads(encode_signed_authority_observation(signed))
    mutation(value)
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises((TypeError, ValueError)):
        decode_signed_authority_observation(raw)


def test_sqlite_observation_tracks_revoked_and_superseded_status_atomically(
    tmp_path,
) -> None:
    path = tmp_path / "observation-status.db"
    store = _open_store(path, None)
    original_request = commit_request(commit_id="status-old", nonce_byte=36)
    _advance_candidate(store, original_request)
    original = store.atomic_commit(original_request)
    assert original.certificate_digest is not None
    target = _target_for(original_request)
    observer = _open_observer(path)

    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            original_request.subject.workflow_id,
            original.certificate_digest,
            "1",
            "observer revocation probe",
        )
    )
    revoked = observer.observe_authority(target)
    assert revoked.current_status_evidence is not None
    assert (
        decode_authority_status(revoked.current_status_evidence).status.value
        == "revoked"
    )
    assert revoked.artifact_visible is False

    second_path = tmp_path / "observation-supersession.db"
    second_store = _open_store(second_path, None)
    old_request = commit_request(commit_id="superseded-old", nonce_byte=37)
    _advance_candidate(second_store, old_request)
    old = second_store.atomic_commit(old_request)
    assert old.certificate_digest is not None
    replacement = commit_request(
        commit_id="superseded-new",
        nonce_byte=38,
        expected_node_version="1",
        attempt_id="superseded-new-attempt",
    )
    _advance_candidate(second_store, replacement)
    superseded = second_store.supersede(
        SupersessionRequest(old.certificate_digest, replacement)
    )
    assert isinstance(superseded, SupersessionCommitted)
    after = _open_observer(second_path).observe_authority(_target_for(old_request))
    assert after.current_status_evidence is not None
    status = decode_authority_status(after.current_status_evidence)
    assert status.status.value == "current"
    assert status.superseded.value == "yes"
    assert (
        after.logical_node.current_certificate_digest
        == superseded.new_certificate_digest
    )
    assert after.artifact_visible is False


def test_sqlite_observation_never_returns_a_torn_supersession_tuple(tmp_path) -> None:
    path = tmp_path / "observation-race.db"
    store = _open_store(path, None)
    original_request = commit_request(commit_id="race-old", nonce_byte=39)
    _advance_candidate(store, original_request)
    original = store.atomic_commit(original_request)
    assert original.certificate_digest is not None
    original_digest = original.certificate_digest
    replacement = commit_request(
        commit_id="race-new",
        nonce_byte=40,
        expected_node_version="1",
        attempt_id="race-new-attempt",
    )
    _advance_candidate(store, replacement)
    target = _target_for(original_request)
    observer = _open_observer(path)
    started = threading.Event()

    def writer() -> None:
        started.wait()
        store.supersede(SupersessionRequest(original_digest, replacement))

    thread = threading.Thread(target=writer)
    thread.start()
    started.set()
    snapshots = [observer.observe_authority(target) for _ in range(40)]
    thread.join(5)
    assert not thread.is_alive()

    for snapshot in snapshots:
        assert snapshot.current_status_evidence is not None
        status = decode_authority_status(snapshot.current_status_evidence)
        if snapshot.logical_node.current_certificate_digest == original_digest:
            assert status.status.value == "current"
            assert status.superseded.value == "no"
            assert snapshot.artifact_visible is True
        else:
            assert snapshot.logical_node.current_certificate_digest is not None
            assert status.status.value == "current"
            assert status.superseded.value == "yes"
            assert snapshot.artifact_visible is False


def test_spawned_observer_is_a_distinct_read_only_nonce_bound_channel(tmp_path) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "rpc-observer.db", tmp_path / "rpc-observer.keys"
    )
    handle = start_authority(config)
    observer_handle = None
    launch = _observer_launch(config, tmp_path)
    request = AuthorityObservationRequest(
        protocol_version="APCC-1.0-draft",
        statement_type="apcc.authority-observation-request",
        authority_store_id=config.authority.authority_store_id,
        workflow_id="workflow-1",
        node_id="node-1",
        attempt_id="attempt-1",
        expected_commit_id="not-committed",
        expected_operation_digest=_digest(40),
        public_request_digest=_digest(41),
        request_nonce=_nonce(42),
    )
    try:
        observer_handle = start_authority_observer(handle, launch)
        assert not os.path.lexists(launch.controller_key_source.location)
        assert handle.controlled_boot.observer_ready
        assert not handle.controlled_boot.publishable_evidence
        assert not handle.controlled_boot.tcb_ready
        assert handle.controlled_boot.controller_source_consumed
        assert handle.controlled_boot.observer_ready
        assert all(
            child.name != "apcc-controller-signer-child"
            for child in multiprocessing.active_children()
        )
        assert observer_handle.pid not in {None, handle.pid}
        response = observer_handle.client.observe(request)
        assert response.snapshot.state is AuthorityObservationState.ABSENT
        assert response.snapshot.request == request
        assert not hasattr(observer_handle.client, "commit")
        assert observer_handle.client._channel_role == "observer"
        assert observer_handle.client._ipc_public_key != handle._ipc_public_key
        assert observer_handle.client._session != handle._session_id
        with pytest.raises(PermissionError):
            os.readlink(f"/proc/{observer_handle.pid}/cwd")
        with pytest.raises(PermissionError):
            os.listdir(f"/proc/{observer_handle.pid}/fd")
        with pytest.raises(PermissionError):
            Path(f"/proc/{observer_handle.pid}/environ").read_bytes()
        from tests.test_apcc_authority_service import _probe_process_access

        probe_parent, probe_child = multiprocessing.get_context("spawn").Pipe(
            duplex=False
        )
        probe = multiprocessing.get_context("spawn").Process(
            target=_probe_process_access,
            args=(observer_handle.pid, probe_child),
        )
        probe.start()
        probe_child.close()
        observer_probe = probe_parent.recv()
        probe_parent.close()
        probe.join(2)
        assert all(
            error in {errno.EACCES, errno.EPERM} for error in observer_probe.values()
        )
        exposed = Path(f"/proc/{observer_handle.pid}/cmdline").read_bytes()
        assert str(config.key_source.location).encode() not in exposed
        assert handle._session_id.encode() not in exposed
        assert b64u_encode(handle._ipc_public_key).encode() not in exposed

        assert (
            observer_handle.client.observe(request).snapshot.state
            is AuthorityObservationState.ABSENT
        )
        assert observer_handle.launch_attestation.experiment_id == "experiment-1"
        assert observer_handle.launch_attestation.run_id == "run-1"
        assert observer_handle.launch_attestation.controller_signature
        observer_handle.launch_attestation.verify(
            pinned_controller_public_key=launch.controller_key_source.expected_public_key,
            expected=_launch_expectations(observer_handle.launch_attestation),
            now_ms=int(time.time() * 1000),
        )
        attacker = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        with pytest.raises(ValueError, match="trust binding|signature"):
            observer_handle.launch_attestation.verify(
                pinned_controller_public_key=attacker,
                expected=_launch_expectations(observer_handle.launch_attestation),
                now_ms=int(time.time() * 1000),
            )
        with pytest.raises(GovernanceBypassDenied):
            observer_handle.client.observe(
                replace(
                    request,
                    authority_store_id="other",
                    request_nonce=_nonce(43),
                )
            )
    finally:
        if observer_handle is not None:
            observer_handle.close()
        handle.close()


def test_controller_signer_is_nondumpable_one_purpose_and_rejects_arbitrary_input(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_isolation import consume_secret_file
    from constitutional_swarm.authority_service import _start_controller_signer
    from tests.test_apcc_authority_service import _probe_process_access

    config = authority_child_config(
        tmp_path / "controller-unit.db", tmp_path / "controller-unit.keys"
    )
    launch = _observer_launch(config, tmp_path)
    secret = consume_secret_file(
        launch.controller_key_source.location,
        maximum_bytes=256,
        label="observer controller key",
    )
    signer = _start_controller_signer(launch.controller_key_source, secret)
    try:
        probe_parent, probe_child = multiprocessing.get_context("spawn").Pipe(
            duplex=False
        )
        probe = multiprocessing.get_context("spawn").Process(
            target=_probe_process_access,
            args=(signer._process.pid, probe_child),
        )
        probe.start()
        probe_child.close()
        results = probe_parent.recv()
        probe_parent.close()
        probe.join(2)
        assert all(error in {errno.EACCES, errno.EPERM} for error in results.values())
        with pytest.raises(RuntimeError, match="controller signer"):
            signer.sign({"arbitrary": "request"})
        with pytest.raises(GovernanceBypassDenied, match="already_used"):
            signer.sign({"arbitrary": "second"})
    finally:
        signer.close()
    assert not os.path.lexists(launch.controller_key_source.location)


def test_publishable_observer_cannot_start_after_scheduler(tmp_path) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-order.db", tmp_path / "observer-order.keys"
    )
    authority = start_authority(config)
    launch = _observer_launch(config, tmp_path)
    try:
        authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        with pytest.raises(GovernanceBypassDenied, match="must_precede_scheduler"):
            start_authority_observer(authority, launch)
        assert os.path.exists(launch.controller_key_source.location)
        assert not authority.controlled_boot.publishable_evidence
    finally:
        authority.close()


def test_observer_and_scheduler_start_are_one_atomic_lifecycle(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "lifecycle-race.db", tmp_path / "lifecycle-race.keys"
    )
    authority = start_authority(config)
    launch = _observer_launch(config, tmp_path)
    controller_opened = threading.Event()
    release_controller = threading.Event()
    scheduler_done = threading.Event()
    observer_result: list[object] = []
    scheduler_result: list[object] = []
    failures: list[BaseException] = []
    original_consume = service_module.consume_secret_file

    def delayed_consume(location: str, *, maximum_bytes: int, label: str):
        if label == "observer controller key":
            controller_opened.set()
            if not release_controller.wait(3):
                raise TimeoutError("test controller barrier timed out")
        return original_consume(location, maximum_bytes=maximum_bytes, label=label)

    monkeypatch.setattr(service_module, "consume_secret_file", delayed_consume)

    def launch_observer() -> None:
        try:
            observer_result.append(start_authority_observer(authority, launch))
        except BaseException as error:
            failures.append(error)

    def launch_scheduler() -> None:
        try:
            scheduler_result.append(
                authority.spawn_executor(CapabilityRegistry(), policy_version="1")
            )
        except BaseException as error:
            failures.append(error)
        finally:
            scheduler_done.set()

    observer_thread = threading.Thread(target=launch_observer)
    scheduler_thread = threading.Thread(target=launch_scheduler)
    observer_thread.start()
    assert controller_opened.wait(2)
    scheduler_thread.start()
    try:
        assert not scheduler_done.wait(0.25)
        assert os.path.exists(launch.controller_key_source.location)
    finally:
        release_controller.set()
    observer_thread.join(5)
    scheduler_thread.join(5)
    try:
        assert not observer_thread.is_alive() and not scheduler_thread.is_alive()
        assert not failures
        assert len(observer_result) == len(scheduler_result) == 1
        assert authority.controlled_boot.publishable_evidence
        assert not os.path.lexists(launch.controller_key_source.location)
    finally:
        for item in observer_result:
            item.close()
        authority.close()


def test_second_observer_rejects_before_consuming_replacement_controller_source(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-once.db", tmp_path / "observer-once.keys"
    )
    authority = start_authority(config)
    first = start_authority_observer(authority, _observer_launch(config, tmp_path))
    replacement = _observer_launch(config, tmp_path)
    before = {child.pid for child in multiprocessing.active_children()}
    try:
        with pytest.raises(GovernanceBypassDenied, match="observer_already_started"):
            start_authority_observer(authority, replacement)
        assert os.path.exists(replacement.controller_key_source.location)
        assert {child.pid for child in multiprocessing.active_children()} == before
    finally:
        first.close()
        authority.close()


def test_explicit_observer_close_revokes_observer_and_publishable_claims(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-close.db", tmp_path / "observer-close.keys"
    )
    authority = start_authority(config)
    observer = start_authority_observer(authority, _observer_launch(config, tmp_path))
    authority_pid = authority.pid
    scheduler_pid = authority._scheduler_worker.pid
    observer.close()
    result = authority.controlled_boot
    assert result.phase == "failed"
    assert not result.observer_ready
    assert not result.tcb_ready
    assert not result.publishable_evidence
    with pytest.raises(GovernanceBypassDenied):
        authority.spawn_executor(CapabilityRegistry(), policy_version="1")
    assert authority_pid is not None and not os.path.exists(f"/proc/{authority_pid}")
    assert scheduler_pid is not None and not os.path.exists(f"/proc/{scheduler_pid}")
    authority.close()


def test_unexpected_observer_death_revokes_fresh_controlled_boot(tmp_path) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-death.db", tmp_path / "observer-death.keys"
    )
    authority = start_authority(config)
    observer = start_authority_observer(authority, _observer_launch(config, tmp_path))
    authority_pid = authority.pid
    try:
        observer_pid = observer.pid
        assert observer_pid is not None
        from multiprocessing.connection import wait

        descriptor = os.dup(observer._process.sentinel)
        os.kill(observer_pid, signal.SIGKILL)
        try:
            assert wait([descriptor], timeout=2) == [descriptor]
        finally:
            os.close(descriptor)
        result = authority.controlled_boot
        assert result.phase == "failed"
        assert not result.observer_ready
        assert not result.tcb_ready
        assert not result.publishable_evidence
        assert authority_pid is not None and not os.path.exists(
            f"/proc/{authority_pid}"
        )
    finally:
        authority.close()


def test_controller_signer_is_owned_before_status_channel_detach(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "signer-detach.db", tmp_path / "signer-detach.keys"
    )
    authority = start_authority(config)
    signer_processes: list[tuple[int, object]] = []
    original_start = service_module._start_controller_signer

    def record_signer(*args, **kwargs):
        signer = original_start(*args, **kwargs)
        signer_processes.append((signer._process.pid, signer._process))
        return signer

    def reject_detach(_client):
        raise OSError("injected status detach failure")

    monkeypatch.setattr(service_module, "_start_controller_signer", record_signer)
    monkeypatch.setattr(
        service_module._StatusSigningClient, "_detach_socket", reject_detach
    )
    try:
        with pytest.raises(OSError, match="injected status detach failure"):
            start_authority_observer(authority, _observer_launch(config, tmp_path))
        assert len(signer_processes) == 1
        signer_pid, signer = signer_processes[0]
        with pytest.raises(ValueError, match="process object is closed"):
            signer.join(2)
        assert not os.path.exists(f"/proc/{signer_pid}")
        assert authority.controlled_boot.phase == "failed"
    finally:
        for _pid, signer in signer_processes:
            service_module._abort_process(signer)
        authority.close()


@pytest.mark.parametrize("failure_point", ["dup", "cloexec", "thread_start"])
def test_observer_watcher_registration_failure_is_transactional(
    tmp_path, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    import inspect

    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_isolation import IsolationUnavailable
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / f"watcher-{failure_point}.db",
        tmp_path / f"watcher-{failure_point}.keys",
    )
    authority = start_authority(config)
    authority_pid = authority.pid
    scheduler_pid = authority._scheduler_worker.pid
    if failure_point == "dup":
        original = service_module.os.dup

        def fail_dup(descriptor: int) -> int:
            if any(
                frame.function == "_watch_process_locked" for frame in inspect.stack()
            ):
                raise OSError("injected watcher dup failure")
            return original(descriptor)

        monkeypatch.setattr(service_module.os, "dup", fail_dup)
    elif failure_point == "cloexec":
        original = service_module.os.set_inheritable

        def fail_cloexec(descriptor: int, inheritable: bool) -> None:
            if any(
                frame.function == "_watch_process_locked" for frame in inspect.stack()
            ):
                raise OSError("injected watcher CLOEXEC failure")
            original(descriptor, inheritable)

        monkeypatch.setattr(service_module.os, "set_inheritable", fail_cloexec)
    else:
        original = service_module.threading.Thread.start

        def fail_start(thread) -> None:
            if thread.name == "apcc-observer-lifecycle-watcher":
                raise RuntimeError("injected watcher thread failure")
            original(thread)

        monkeypatch.setattr(service_module.threading.Thread, "start", fail_start)
    try:
        with pytest.raises(
            (IsolationUnavailable, OSError, RuntimeError), match="watcher"
        ):
            start_authority_observer(authority, _observer_launch(config, tmp_path))
        assert authority.controlled_boot.phase == "failed"
        with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
            authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert not authority._watcher_fds
        assert all(not watcher.is_alive() for watcher in authority._watchers)
        assert all(
            observer.pid is None or not os.path.exists(f"/proc/{observer.pid}")
            for observer in authority._observers
        )
        assert authority_pid is not None and not os.path.exists(
            f"/proc/{authority_pid}"
        )
        assert scheduler_pid is not None and not os.path.exists(
            f"/proc/{scheduler_pid}"
        )
    finally:
        authority.close()


def test_observer_watcher_select_failure_revokes_without_status_poll(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "watcher-select.db", tmp_path / "watcher-select.keys"
    )
    authority = start_authority(config)
    select_entered = threading.Event()
    release_select = threading.Event()
    original_select = service_module.select.select

    def fail_observer_select(readable, writable, exceptional, timeout=None):
        if timeout is None and threading.current_thread().name == (
            "apcc-observer-lifecycle-watcher"
        ):
            select_entered.set()
            assert release_select.wait(3)
            raise OSError("injected observer watcher select failure")
        return original_select(readable, writable, exceptional, timeout)

    monkeypatch.setattr(service_module.select, "select", fail_observer_select)
    observer = start_authority_observer(authority, _observer_launch(config, tmp_path))
    watcher = next(
        item
        for item in authority._watchers
        if item.name == "apcc-observer-lifecycle-watcher"
    )
    assert select_entered.wait(2)
    observer_pid = observer.pid
    assert observer_pid is not None
    os.kill(observer_pid, signal.SIGKILL)
    release_select.set()
    watcher.join(5)
    assert not watcher.is_alive()
    assert authority._controlled_boot.phase == "failed"
    assert not authority._controlled_boot.observer_ready
    assert not authority._controlled_boot.tcb_ready
    assert not authority._controlled_boot.publishable_evidence
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        authority.spawn_executor(CapabilityRegistry(), policy_version="1")
    assert not authority._watcher_fds
    authority.close()
    assert authority.controlled_boot.phase == "failed"


def test_close_waits_for_observer_start_and_wins_terminal_state(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-close-race.db", tmp_path / "observer-close-race.keys"
    )
    authority = start_authority(config)
    launch = _observer_launch(config, tmp_path)
    entered = threading.Event()
    release = threading.Event()
    close_done = threading.Event()
    original_consume = service_module.consume_secret_file

    def delayed_consume(location: str, *, maximum_bytes: int, label: str):
        if label == "observer controller key":
            entered.set()
            assert release.wait(3)
        return original_consume(location, maximum_bytes=maximum_bytes, label=label)

    monkeypatch.setattr(service_module, "consume_secret_file", delayed_consume)
    observer_result: list[object] = []
    observer_thread = threading.Thread(
        target=lambda: observer_result.append(
            start_authority_observer(authority, launch)
        )
    )
    close_thread = threading.Thread(
        target=lambda: (authority.close(), close_done.set())
    )
    observer_thread.start()
    assert entered.wait(2)
    close_thread.start()
    assert not close_done.wait(0.2)
    release.set()
    observer_thread.join(5)
    close_thread.join(5)
    assert not observer_thread.is_alive() and not close_thread.is_alive()
    assert authority.controlled_boot.phase == "closed"
    assert observer_result
    assert observer_result[0].client._channel_socket.fileno() == -1


def test_execution_handle_cannot_reach_observer_capability_or_secrets(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(
        tmp_path / "capability-surface.db", tmp_path / "capability-surface.keys"
    )
    handle = start_authority(config)
    try:
        assert {"observer_client", "_observer_process", "observe"}.isdisjoint(
            dir(handle)
        )
        executor = handle.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert executor.health()["executor_pid"] not in {None, os.getpid(), handle.pid}
        forbidden = {
            "observe",
            "observer_client",
            "_observer_process",
            "_execution_channel",
            "admin_client",
            "_session_id",
            "_ipc_public_key",
        }
        assert forbidden.isdisjoint(dir(executor))
        assert all(
            not hasattr(value, "observe")
            for slot in executor.__slots__
            if (value := getattr(executor, slot, None)) is not None
        )
    finally:
        handle.close()


def test_final_admission_has_no_later_privileged_process_birth(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "birth-watch.db", tmp_path / "birth-watch.keys"
    )
    authority = start_authority(config)
    observer = start_authority_observer(authority, _observer_launch(config, tmp_path))
    children_before_admission = {
        child.pid for child in multiprocessing.active_children()
    }
    try:
        executor = authority.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert authority.controlled_boot.tcb_ready
        assert authority.controlled_boot.publishable_evidence
        assert {
            child.pid for child in multiprocessing.active_children()
        } == children_before_admission
        admitted_children = {child.pid for child in multiprocessing.active_children()}
        admitted_direct_children = _direct_child_pids(os.getpid())
        context = multiprocessing.get_context("spawn")
        watcher_parent, watcher_child = context.Pipe(duplex=True)
        watcher = context.Process(
            target=_watch_later_child_births,
            args=(
                os.getpid(),
                admitted_direct_children,
                watcher_child,
            ),
        )
        watcher.start()
        watcher_child.close()
        assert watcher_parent.recv() == "ready"
        for _ in range(10):
            assert executor.health()["executor_pid"] == executor.pid
            assert authority.health()["authority_pid"] == authority.pid
        watcher_parent.send("checkpoint")
        assert watcher_parent.recv() == "checkpoint"
        watcher_parent.send("stop")
        assert watcher_parent.recv() == set()
        watcher_parent.close()
        watcher.join(2)
        watcher.close()
        assert {
            child.pid for child in multiprocessing.active_children()
        } == admitted_children
    finally:
        observer.close()
        authority.close()


def test_birth_watcher_observes_recursive_descendants() -> None:
    context = multiprocessing.get_context("spawn")
    watcher_parent, watcher_child = context.Pipe(duplex=True)
    watcher = context.Process(
        target=_watch_later_child_births,
        args=(os.getpid(), _direct_child_pids(os.getpid()), watcher_child),
    )
    probe_parent, probe_child = context.Pipe(duplex=True)
    probe = context.Process(target=_spawn_descendant_probe, args=(probe_child,))
    try:
        watcher.start()
        watcher_child.close()
        assert watcher_parent.recv() == "ready"
        probe.start()
        probe_child.close()
        probe_pid, descendant_pid = probe_parent.recv()
        watcher_parent.send("checkpoint")
        assert watcher_parent.recv() == "checkpoint"
        watcher_parent.send("stop")
        observed = watcher_parent.recv()
        assert {probe_pid, descendant_pid} <= observed
    finally:
        if probe.is_alive():
            probe_parent.send("stop")
        probe_parent.close()
        probe.join(2)
        if probe.is_alive():
            probe.kill()
            probe.join(2)
        probe.close()
        watcher_parent.close()
        watcher.join(2)
        if watcher.is_alive():
            watcher.kill()
            watcher.join(2)
        watcher.close()


def test_controller_launch_key_cannot_reuse_authority_identity(tmp_path) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "controller-separation.db", tmp_path / "authority.keys"
    )
    launch = _observer_launch(config, tmp_path)
    identity = config.key_source.expected_identity_public_key
    launch = replace(
        launch,
        controller_key_id=sha256_digest(identity),
        controller_key_source=ControllerKeySourceRef(
            launch.controller_key_source.location, identity
        ),
    )
    authority = start_authority(config)
    try:
        with pytest.raises(ValueError, match="distinct"):
            start_authority_observer(authority, launch)
    finally:
        authority.close()


def test_failed_controller_signing_leaves_no_observer_process(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "failed-launch.db", tmp_path / "failed-launch.keys"
    )
    authority = start_authority(config)
    before = {child.pid for child in multiprocessing.active_children()}
    monkeypatch.setattr(
        service_module._ControllerSigner,
        "sign",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("sign failed")),
    )
    try:
        with pytest.raises(RuntimeError, match="sign failed"):
            start_authority_observer(authority, _observer_launch(config, tmp_path))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            leaked = {
                child.pid
                for child in multiprocessing.active_children()
                if child.pid not in before
            }
            if not leaked:
                break
            time.sleep(0.01)
        assert not leaked
    finally:
        authority.close()


def test_post_start_attestation_failure_kills_stubborn_observer(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "stubborn-observer.db", tmp_path / "stubborn-observer.keys"
    )
    authority = start_authority(config)
    observer_pid: list[int] = []

    def fake_start_observer(*_args, **kwargs):
        kwargs["status_connection"].close()
        kwargs["controller_signer"].close()
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_stubborn_observer_child, args=(child,))
        process.start()
        child.close()
        observer_pid.append(parent.recv())
        parent.close()
        return process, SimpleNamespace(close=lambda: None), {"malformed": "proof"}

    monkeypatch.setattr(service_module, "_start_observer", fake_start_observer)
    monkeypatch.setattr(
        service_module,
        "decode_observer_launch_attestation",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid launch proof")),
    )
    try:
        with pytest.raises(ValueError, match="invalid launch proof"):
            start_authority_observer(authority, _observer_launch(config, tmp_path))
        assert observer_pid and not os.path.exists(f"/proc/{observer_pid[0]}")
        assert authority.controlled_boot.phase == "failed"
    finally:
        authority.close()


def test_observer_publishable_readiness_requires_authenticated_tcb_ready(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from constitutional_swarm import authority_service as service_module
    from constitutional_swarm.authority_isolation import IsolationUnavailable
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "tcb-ready.db", tmp_path / "tcb-ready.keys"
    )
    authority = start_authority(config)
    before = {child.pid for child in multiprocessing.active_children()}

    def reject_tcb_ready(*_args, **_kwargs) -> None:
        raise IsolationUnavailable("ISOLATION_UNAVAILABLE: forged observer TCB ready")

    monkeypatch.setattr(service_module, "_verify_observer_tcb_ready", reject_tcb_ready)
    try:
        with pytest.raises(IsolationUnavailable, match="forged observer TCB ready"):
            start_authority_observer(authority, _observer_launch(config, tmp_path))
        assert not authority.controlled_boot.publishable_evidence
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            leaked = {
                child.pid
                for child in multiprocessing.active_children()
                if child.pid not in before
            }
            if not leaked:
                break
            time.sleep(0.01)
        assert not leaked
    finally:
        authority.close()


def test_observer_supports_10001_monotonic_requests_without_nonce_state(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "observer-10001.db", tmp_path / "observer-10001.keys"
    )
    authority = start_authority(config)
    observer = None
    request = AuthorityObservationRequest(
        "APCC-1.0-draft",
        "apcc.authority-observation-request",
        config.authority.authority_store_id,
        "workflow-1",
        "node-1",
        "attempt-1",
        "absent-commit",
        _digest(91),
        _digest(92),
        _nonce(93),
    )
    try:
        observer = start_authority_observer(
            authority, _observer_launch(config, tmp_path)
        )
        for _sequence in range(1, 10_002):
            assert (
                observer.client.observe(request).snapshot.state
                is AuthorityObservationState.ABSENT
            )
    finally:
        if observer is not None:
            observer.close()
        authority.close()


def test_partial_observer_frame_poisoning_is_bounded_and_fails_closed(tmp_path) -> None:
    from constitutional_swarm.authority_service import (
        start_authority,
        start_authority_observer,
    )

    config = authority_child_config(
        tmp_path / "partial-frame.db", tmp_path / "partial-frame.keys"
    )
    handle = start_authority(config)
    observer_handle = None
    try:
        observer_handle = start_authority_observer(
            handle, _observer_launch(config, tmp_path)
        )
        channel = observer_handle.client._channel_socket
        assert channel is not None
        channel.sendall(struct.pack("!I", 32) + b"{")
        with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
            observer_handle.client.observe(
                AuthorityObservationRequest(
                    "APCC-1.0-draft",
                    "apcc.authority-observation-request",
                    config.authority.authority_store_id,
                    "workflow",
                    "node",
                    "attempt",
                    "commit",
                    _digest(81),
                    _digest(82),
                    _nonce(83),
                )
            )
    finally:
        if observer_handle is not None:
            observer_handle.close()
        handle.close()
