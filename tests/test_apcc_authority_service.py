"""Security contracts for the APCC authority-service boundary (RED first)."""

from __future__ import annotations

import importlib
import json
import os
import socket
import sqlite3
import struct
import pickle
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import constitutional_swarm.governed_commit as governed_commit_module
from constitutional_swarm.apcc.ports import (
    OutboxRecoveryRequest,
    RevocationRequest,
    RevocationScope,
)
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.governed_commit import (
    CommitOutcome,
    GovernedCommitBoundary,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode
from tests.gcb_apcc_support import (
    InProcessExecutionClientHarness,
    authority_child_config,
    canonical_nonce,
    producer_key,
    provision_executor_workflow,
    typed_bootstrap,
)


def test_spawned_pathless_authority_is_authenticated_and_dies_closed(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys"
    )
    assert pickle.loads(pickle.dumps(config)) == config
    handle = start_authority(config)
    try:
        assert handle.pid is not None and handle.pid != os.getpid()
        assert handle.health() == {"authority_pid": handle.pid}
        assert handle.admin_client.health() == {"authority_pid": handle.pid}
    finally:
        handle.terminate()
        handle.join(2)
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        handle.health()


def test_execution_channel_denies_admin_operation_without_dying(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys"
    )
    handle = start_authority(config)
    try:
        assert handle._execution_channel is not None
        with pytest.raises(GovernanceBypassDenied, match="unknown_operation"):
            handle._execution_channel._rpc("create_workflow", {})
        assert handle.health()["authority_pid"] == handle.pid
    finally:
        handle.terminate()
        handle.join(2)


def test_wrong_persistent_identity_fails_readiness_closed(tmp_path) -> None:
    from constitutional_swarm.authority_child import KeySourceRef
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(
        tmp_path / "authority.db", tmp_path / "authority.keys"
    )
    wrong = replace(
        config,
        key_source=KeySourceRef("file", config.key_source.location, bytes(range(32))),
    )
    with pytest.raises(RuntimeError, match="startup failed"):
        start_authority(wrong)


def test_insecure_or_symlinked_key_bundle_fails_closed_before_readiness(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_child import KeySourceRef
    from constitutional_swarm.authority_service import start_authority

    insecure = authority_child_config(
        tmp_path / "insecure.db", tmp_path / "insecure.keys"
    )
    os.chmod(insecure.key_source.location, 0o644)
    with pytest.raises(RuntimeError, match="mode 0600"):
        start_authority(insecure)

    secure = authority_child_config(tmp_path / "symlink.db", tmp_path / "secure.keys")
    symlink = tmp_path / "linked.keys"
    symlink.symlink_to(secure.key_source.location)
    linked = replace(
        secure,
        key_source=KeySourceRef(
            "file",
            str(symlink),
            secure.key_source.expected_identity_public_key,
        ),
    )
    with pytest.raises(RuntimeError, match="startup failed"):
        start_authority(linked)


def test_restart_rotates_ephemeral_ipc_identity(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    database = tmp_path / "authority.db"
    config = authority_child_config(database, tmp_path / "authority.keys")
    first = start_authority(config)
    first_identity = (first._session_id, first._ipc_public_key)
    first.terminate()
    first.join(2)
    second = start_authority(replace(config, provision=False))
    try:
        assert (second._session_id, second._ipc_public_key) != first_identity
        assert second.health()["authority_pid"] == second.pid
    finally:
        second.terminate()
        second.join(2)


def test_forged_signed_response_poisons_execution_client() -> None:
    from constitutional_swarm.authority_ipc import (
        recv_frame,
        send_frame,
        signed_response,
    )
    from constitutional_swarm.authority_service import (
        _AuthorityExecutionChannel,
        _bind_verified_child_channel,
    )

    expected_key = producer_key("expected-ipc")
    attacker_key = producer_key("attacker-ipc")
    client_socket, attacker_socket = socket.socketpair(socket.AF_UNIX)
    client = _bind_verified_child_channel(
        _AuthorityExecutionChannel,
        client_socket,
        channel_role="execution",
        session="pinned-session",
        authority_pid=1234,
        ipc_public_key=expected_key.public_key(),
        max_frame_bytes=4_096,
    )

    def forge() -> None:
        request = recv_frame(attacker_socket, 4_096)
        response = signed_response(
            key=attacker_key,
            session="pinned-session",
            channel="execution",
            sequence=1,
            authority_pid=1234,
            request_digest=__import__(
                "constitutional_swarm.authority_ipc", fromlist=["digest"]
            ).digest(request),
            result={"authority_pid": 1234},
        )
        send_frame(attacker_socket, response, 4_096)
        attacker_socket.close()

    thread = threading.Thread(target=forge)
    thread.start()
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        client.health()
    thread.join(2)
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        client.health()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"session": "wrong-session"}, "transcript mismatch"),
        ({"authority_pid": 999}, "transcript mismatch"),
        ({"request_digest": "wrong-request"}, "transcript mismatch"),
        ({"sequence": 2}, "transcript mismatch"),
    ],
)
def test_signed_transcript_rejects_wrong_binding_and_replay(
    override: dict[str, object], message: str
) -> None:
    from constitutional_swarm.authority_ipc import (
        digest,
        signed_response,
        verify_response,
    )

    key = producer_key("transcript")
    request = {"operation": "health", "request": {}}
    response = signed_response(
        key=key,
        session="session",
        channel="execution",
        sequence=1,
        authority_pid=123,
        request_digest=digest(request),
        result={"authority_pid": 123},
    )
    expected = {
        "public_key": key.public_key(),
        "session": "session",
        "channel": "execution",
        "sequence": 1,
        "authority_pid": 123,
        "request_digest": digest(request),
        **override,
    }
    expected_public_key = expected["public_key"]
    expected_session = expected["session"]
    expected_channel = expected["channel"]
    expected_sequence = expected["sequence"]
    expected_authority_pid = expected["authority_pid"]
    expected_request_digest = expected["request_digest"]
    assert isinstance(expected_public_key, Ed25519PublicKey)
    assert type(expected_session) is str
    assert type(expected_channel) is str
    assert type(expected_sequence) is int
    assert type(expected_authority_pid) is int
    assert type(expected_request_digest) is str
    with pytest.raises(ValueError, match=message):
        verify_response(
            response,
            public_key=expected_public_key,
            session=expected_session,
            channel=expected_channel,
            sequence=expected_sequence,
            authority_pid=expected_authority_pid,
            request_digest=expected_request_digest,
        )


def test_signed_transcript_rejects_unsigned_response() -> None:
    from constitutional_swarm.authority_ipc import (
        digest,
        signed_response,
        verify_response,
    )

    key = producer_key("unsigned-transcript")
    request = {"operation": "health", "request": {}}
    response = signed_response(
        key=key,
        session="session",
        channel="execution",
        sequence=1,
        authority_pid=123,
        request_digest=digest(request),
        result={"authority_pid": 123},
    )
    response.pop("signature")
    with pytest.raises(ValueError, match="invalid signed response"):
        verify_response(
            response,
            public_key=key.public_key(),
            session="session",
            channel="execution",
            sequence=1,
            authority_pid=123,
            request_digest=digest(request),
        )


class _RecordingSink:
    def __init__(self) -> None:
        self.delivered: list[str] = []
        self.fail = False

    def deliver(self, event_id: str, payload: bytes) -> None:
        del payload
        self.delivered.append(event_id)
        if self.fail:
            raise RuntimeError("sink unavailable")


class _RestrictedExecutionClient:
    """Test double for the least-privilege execution-side IPC contract."""

    def __init__(self) -> None:
        self.alive = True

    def _check(self) -> None:
        if not self.alive:
            raise ConnectionError("authority unavailable")

    def attach_workflow(self, **_request):
        self._check()
        return {
            "root": SimpleNamespace(
                status="ready",
                claimed_by=None,
                artifact_id=None,
                attempt_id=None,
            )
        }

    def authoritative_artifact(self, _workflow_id, _artifact_id):
        self._check()
        return None

    def commit(self, _request):
        self._check()
        raise AssertionError("live test client does not synthesize authority")


def _reachable_privileged_capabilities(root: object) -> set[str]:
    forbidden_names = {
        "_apcc_store",
        "_bootstrap",
        "_conn",
        "_control_signer",
        "_key_provider",
        "_path",
        "_policy_signer",
        "_registry_signer",
        "_trusted_admin",
        "apply_control_command",
        "bind_projection",
        "commit_port",
        "create_workflow",
        "dispatch_outbox",
        "dispatch_revocation_outbox",
        "recover",
        "recover_outbox",
        "revoke_agent",
        "revoke_root",
        "update_policy",
    }
    found: set[str] = set()
    pending = [root]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values = getattr(current, "__dict__", {})
        if not isinstance(values, dict):
            continue
        for name, value in values.items():
            if name in forbidden_names:
                found.add(name)
            if isinstance(value, (str, bytes, int, float, bool, type(None))):
                continue
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, (list, tuple, set, frozenset)):
                pending.extend(value)
            else:
                pending.append(value)
        for name in forbidden_names:
            if callable(getattr(current, name, None)):
                found.add(name)
    return found


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("authority closed an incomplete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _raw_channel_rpc(
    client, body: bytes, *, declared_size: int | None = None
) -> dict[str, object]:
    connection = client._channel_socket
    assert isinstance(connection, socket.socket)
    size = len(body) if declared_size is None else declared_size
    connection.sendall(struct.pack("!I", size) + body)
    response_size = struct.unpack("!I", _recv_exact(connection, 4))[0]
    assert response_size <= client._max_frame_bytes
    response = json.loads(_recv_exact(connection, response_size))
    assert isinstance(response, dict)
    return response


def _error_code(response: dict[str, object]) -> str:
    error = response.get("error")
    if isinstance(error, dict):
        return str(error.get("code", ""))
    return str(error or "")


def _provision(
    path,
    *,
    nodes=None,
    producers=None,
    policy_versions=(("1", 1),),
    sink=None,
):
    bootstrap = typed_bootstrap(
        policy_versions=policy_versions,
        producers=producers,
        outbox_sink=sink,
    )
    admin = bootstrap.provision(path)
    admin.create_workflow(
        workflow_id="wf", nodes=nodes or {"root": ()}, policy_version="1"
    )
    return bootstrap, admin


def _stage(
    admin,
    key,
    *,
    node_id="root",
    attempt_id="attempt",
    agent_id="agent",
    register=True,
):
    if register:
        admin.register_agent(
            workflow_id="wf",
            agent_id=agent_id,
            public_key=key.public_key(),
            capabilities=(),
        )
    port = admin.commit_port
    authorization = sign_attempt_authorization(
        port.prepare_attempt_authorization(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=attempt_id,
            agent_id=agent_id,
            nonce=canonical_nonce(f"claim:{agent_id}:{node_id}:{attempt_id}"),
        ),
        key,
    )
    port.claim(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=attempt_id,
        agent_id=agent_id,
        authorization=authorization,
    )
    artifact = Artifact(
        f"artifact-{node_id}", node_id, agent_id, "text", f"result-{node_id}"
    )
    port.stage_result(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=attempt_id,
        artifact=artifact,
        authorization=authorization,
    )
    return artifact


def _request(
    bootstrap,
    admin,
    key,
    *,
    node_id="root",
    attempt_id="attempt",
    agent_id="agent",
    commit_id="commit",
    nonce_label="commit",
):
    payload = admin.prepare_receipt_payload(
        workflow_id="wf",
        node_id=node_id,
        attempt_id=attempt_id,
        agent_id=agent_id,
        commit_id=commit_id,
        nonce=canonical_nonce(nonce_label),
    )
    receipt = sign_governed_receipt(payload, key)
    return admin.commit_port.build_request(receipt, bootstrap.verdict_for(receipt))


def _certificate_digest(admin, node_id="root") -> str:
    logical = admin.commit_port._apcc_store.read_logical_node("wf", node_id)
    assert logical.current_certificate_digest is not None
    return logical.current_certificate_digest


def _workflow_row(path) -> tuple[str, int, str]:
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT authority_root, authority_epoch, policy_version "
            "FROM workflows WHERE workflow_id='wf'"
        ).fetchone()
    assert row is not None
    return str(row[0]), int(row[1]), str(row[2])


def test_authoritative_status_reads_use_distinct_fresh_csprng_nonces(
    tmp_path, monkeypatch
) -> None:
    from constitutional_swarm.apcc.crypto import b64u_encode
    from constitutional_swarm.authority_ipc import b64u_decode

    key = producer_key()
    bootstrap, admin = _provision(tmp_path / "fresh-status.sqlite3")
    _stage(admin, key)
    assert (
        admin.commit_port.commit(_request(bootstrap, admin, key)).outcome
        is CommitOutcome.COMMITTED
    )
    nonces: list[str] = []
    original_token_bytes = governed_commit_module.secrets.token_bytes

    def capture_token_bytes(size: int) -> bytes:
        value = original_token_bytes(size)
        nonces.append(b64u_encode(value))
        return value

    monkeypatch.setattr(
        governed_commit_module.secrets, "token_bytes", capture_token_bytes
    )
    admin.commit_port.node_state("wf", "root")
    admin.commit_port.node_state("wf", "root")
    assert admin.commit_port.authoritative_artifact("wf", "artifact-root") is not None
    assert len(nonces) == 3
    assert len(set(nonces)) == 3
    assert all(b64u_decode(nonce) != bytes(16) for nonce in nonces)
    assert all(len(b64u_decode(nonce)) == 16 for nonce in nonces)


def test_no_raw_or_unattached_apcc_gcb_open_path_is_caller_accessible(tmp_path) -> None:
    path = tmp_path / "sealed.sqlite3"
    key = producer_key()
    bootstrap, admin = _provision(path)
    _stage(admin, key)
    request = _request(bootstrap, admin, key)

    assert not hasattr(GovernedCommitBoundary, "_open_typed")
    governed_commit = importlib.import_module("constitutional_swarm.governed_commit")
    assert not hasattr(governed_commit, "_BOOTSTRAP_CAPABILITY")
    assert not hasattr(GovernedCommitBoundary, "_construct")
    with pytest.raises(GovernanceBypassDenied):
        GovernedCommitBoundary.open(path)
    with pytest.raises(GovernanceBypassDenied):
        GovernedCommitBoundary(path)
    raw = object.__new__(GovernedCommitBoundary)
    with pytest.raises(GovernanceBypassDenied, match="not attached"):
        raw.commit(request)

    reopened = bootstrap.open_admin(path).commit_port
    assert hasattr(reopened, "_apcc_service")
    assert not hasattr(reopened, "_commit_transaction")


def test_certificate_revocation_fences_all_consumption_across_reopen(tmp_path) -> None:
    path = tmp_path / "certificate-revocation.sqlite3"
    key = producer_key()
    bootstrap, admin = _provision(path)
    artifact = _stage(admin, key)
    request = _request(bootstrap, admin, key)
    assert admin.commit(request).outcome is CommitOutcome.COMMITTED
    projection_store = ArtifactStore()
    projection = admin.bind_projection("wf", projection_store)
    certificate_digest = _certificate_digest(admin)

    admin.commit_port._apcc_store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "wf",
            certificate_digest,
            "0",
            "security review",
        )
    )

    reopened = bootstrap.open_admin(path)
    assert reopened.node_state("wf", "root").status != "governed_committed"
    assert reopened.authoritative_artifact("wf", artifact.artifact_id) is None
    assert reopened.dispatch_outbox(projection) == 0
    assert projection_store.get(artifact.artifact_id, workflow_id="wf") is None


def test_commit_id_cache_cannot_substitute_a_different_exact_request(tmp_path) -> None:
    key = producer_key()
    bootstrap, admin = _provision(tmp_path / "cache.sqlite3")
    _stage(admin, key)
    request_a = _request(
        bootstrap, admin, key, commit_id="same-commit", nonce_label="request-a"
    )
    payload_b = admin.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt",
        agent_id="agent",
        commit_id="same-commit",
        nonce=canonical_nonce("request-b"),
    )
    receipt_b = sign_governed_receipt(payload_b, key)
    request_b = admin.commit_port.build_request(
        receipt_b, bootstrap.verdict_for(receipt_b)
    )

    decision_a = admin.commit(request_a)
    decision_b = admin.commit(request_b)

    assert decision_a.outcome is CommitOutcome.COMMITTED
    assert decision_b.outcome is not CommitOutcome.COMMITTED
    assert decision_b.reason in {"idempotency_conflict", "equivocation"}
    assert not hasattr(admin.commit_port, "_apcc_requests")
    assert not hasattr(admin.commit_port, "_governed_requests")


def test_predeclared_policy_rotation_selects_exact_binding_across_reopen(
    tmp_path,
) -> None:
    path = tmp_path / "policy-rotation.sqlite3"
    key = producer_key()
    bootstrap, admin = _provision(
        path,
        nodes={"old": (), "fresh": ()},
        policy_versions=(("1", 1), ("2", 2)),
    )
    _stage(admin, key, node_id="old", attempt_id="old")
    _stage(admin, key, node_id="fresh", attempt_id="fresh", register=False)
    stale = _request(
        bootstrap,
        admin,
        key,
        node_id="old",
        attempt_id="old",
        commit_id="old-commit",
        nonce_label="old-policy",
    )

    assert admin.update_policy(workflow_id="wf", policy_version="2") == 2
    assert admin.commit(stale).outcome is not CommitOutcome.COMMITTED
    reopened = bootstrap.open_admin(path)
    fresh = _request(
        bootstrap,
        reopened,
        key,
        node_id="fresh",
        attempt_id="fresh",
        commit_id="fresh-commit",
        nonce_label="fresh-policy",
    )
    assert fresh.verdict.policy_id == "gcb-test-policy"
    assert fresh.verdict.policy_version == "2"
    assert fresh.verdict.policy_epoch == 2
    assert fresh.verdict.verifier_key_id == "gcb-policy-key-2"
    governed_commit = importlib.import_module("constitutional_swarm.governed_commit")
    stale_v1 = replace(
        fresh.verdict,
        policy_version="1",
        policy_epoch=1,
        verifier_key_id="gcb-policy-key-1",
        signature="",
    )
    stale_v1 = governed_commit._sign_authoritative_verdict(
        stale_v1, bootstrap._policy_signer, detached=True
    )
    substituted = replace(fresh, verdict=stale_v1)
    assert reopened.commit(substituted).outcome is not CommitOutcome.COMMITTED
    fresh_v2 = _request(
        bootstrap,
        reopened,
        key,
        node_id="fresh",
        attempt_id="fresh",
        commit_id="fresh-v2-commit",
        nonce_label="fresh-v2-policy",
    )
    assert reopened.commit(fresh_v2).outcome is CommitOutcome.COMMITTED

    with pytest.raises(GovernanceBypassDenied, match="untrusted_policy_binding"):
        reopened.update_policy(workflow_id="wf", policy_version="3")
    assert _workflow_row(path)[2] == "2"


def test_actor_revocation_preserves_registry_and_other_actor_across_reopen(
    tmp_path,
) -> None:
    path = tmp_path / "actor-revocation.sqlite3"
    key_a = producer_key("actor-a")
    key_b = producer_key("actor-b")
    producers = {"actor-a": key_a, "actor-b": key_b}
    bootstrap, admin = _provision(path, nodes={"a": (), "b": ()}, producers=producers)
    _stage(admin, key_a, node_id="a", attempt_id="a", agent_id="actor-a")
    _stage(admin, key_b, node_id="b", attempt_id="b", agent_id="actor-b")
    before = _workflow_row(path)

    admin.revoke_agent(workflow_id="wf", agent_id="actor-a")
    reopened = bootstrap.open_admin(path)
    after = _workflow_row(path)
    assert after[:2] == before[:2]
    request_b = _request(
        bootstrap,
        reopened,
        key_b,
        node_id="b",
        attempt_id="b",
        agent_id="actor-b",
        commit_id="actor-b-commit",
        nonce_label="actor-b",
    )
    assert reopened.commit(request_b).outcome is CommitOutcome.COMMITTED


def test_authority_lifecycle_delivers_commit_and_control_outbox_after_reopen(
    tmp_path,
) -> None:
    path = tmp_path / "authority-outbox.sqlite3"
    sink = _RecordingSink()
    key = producer_key()
    bootstrap, admin = _provision(path, sink=sink)
    _stage(admin, key)
    request = _request(bootstrap, admin, key)
    assert admin.commit(request).outcome is CommitOutcome.COMMITTED

    sink.fail = True
    with pytest.raises(RuntimeError, match="sink unavailable"):
        admin.commit_port._apcc_store.recover_outbox(OutboxRecoveryRequest("10"))
    sink.fail = False
    reopened = bootstrap.open_admin(path)
    commit_delivery = reopened.commit_port._apcc_store.recover_outbox(
        OutboxRecoveryRequest("10")
    )
    assert int(commit_delivery.delivered_count) >= 1

    certificate_digest = _certificate_digest(reopened)
    reopened.commit_port._apcc_store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            "wf",
            certificate_digest,
            "0",
            "control delivery",
        )
    )
    control_delivery = bootstrap.open_admin(
        path
    ).commit_port._apcc_store.recover_outbox(OutboxRecoveryRequest("10"))
    assert int(control_delivery.delivered_count) >= 1
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM apcc_outbox WHERE state <> 'DELIVERED'"
            ).fetchone()[0]
            == 0
        )


def test_pathless_launcher_ignores_rogue_path_and_exposes_no_connect_api(
    tmp_path,
) -> None:
    service_api = importlib.import_module("constitutional_swarm.authority_service")
    rogue_path = tmp_path / "authority.sock"
    rogue_path.write_text("foreign")
    handle = service_api.start_authority(
        authority_child_config(tmp_path / "pathless.db", tmp_path / "pathless.keys")
    )
    try:
        assert not hasattr(service_api, "AuthorityServiceProcess")
        assert not hasattr(service_api, "AuthorityExecutionClient")
        assert rogue_path.read_text() == "foreign"
        assert handle.health()["authority_pid"] == handle.pid
    finally:
        handle.terminate()
        handle.join(2)


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"not-json", "malformed_json"),
        (
            b'{"operation":"health","operation":"commit","request":{}}',
            "malformed_json",
        ),
        (b'{"operation":"health","request":{"value":NaN}}', "malformed_json"),
        (
            b'{"operation":"health","request":{"value":'
            + (b"[" * 70)
            + b"0"
            + (b"]" * 70)
            + b"}}",
            "malformed_json",
        ),
        (
            b'{"operation":"health","request":{"value":' + (b"9" * 5_000) + b"}}",
            "malformed_json",
        ),
        (
            b'{"operation":"become_admin","request":{}}',
            "unknown_operation",
        ),
    ],
)
def test_pathless_channel_rejects_adversarial_json_and_service_survives(
    tmp_path, payload: bytes, code: str
) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(
            tmp_path / f"strict-{len(payload)}.db",
            tmp_path / f"strict-{len(payload)}.keys",
            provision=True,
        )
    )
    try:
        response = _raw_channel_rpc(handle._execution_channel, payload)
        assert _error_code(response) == code
        assert handle.admin_client.health()["authority_pid"] == handle.pid
    finally:
        handle.terminate()
        handle.join(2)


def test_pathless_channel_rejects_oversized_frame_and_service_survives(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = replace(
        authority_child_config(tmp_path / "bounded.db", tmp_path / "bounded.keys"),
        max_frame_bytes=4_096,
    )
    handle = start_authority(config)
    try:
        response = _raw_channel_rpc(
            handle._execution_channel, b"", declared_size=config.max_frame_bytes + 1
        )
        assert _error_code(response) == "frame_too_large"
        assert handle.admin_client.health()["authority_pid"] == handle.pid
    finally:
        handle.terminate()
        handle.join(2)


def test_oversized_execution_response_returns_signed_error_and_survives(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    config = replace(
        authority_child_config(tmp_path / "response.db", tmp_path / "response.keys"),
        max_frame_bytes=1_024,
    )
    handle = start_authority(config)
    nodes = {f"node-{index}": () for index in range(8)}
    try:
        handle.admin_client.create_workflow(
            workflow_id="wf", nodes=nodes, policy_version="1"
        )
        assert handle._execution_channel is not None
        execution_channel = handle._execution_channel
        with pytest.raises(GovernanceBypassDenied, match="response_too_large"):
            execution_channel.attach_workflow(
                workflow_id="wf", nodes=nodes, policy_version="1"
            )
        assert execution_channel.health()["authority_pid"] == handle.pid
    finally:
        handle.close()


def test_execution_status_batch_rejects_empty_rpc_and_service_survives(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "empty.db", tmp_path / "empty.keys")
    )
    try:
        assert handle._execution_channel is not None
        channel = handle._execution_channel
        with pytest.raises(GovernanceBypassDenied, match="empty_node_status_batch"):
            channel._rpc("workflow_node_states", {"workflow_id": "wf", "node_ids": []})
        assert channel.health()["authority_pid"] == handle.pid
    finally:
        handle.close()


def test_execution_status_batch_accepts_1000_ordered_duplicate_nodes(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "maximum.db", tmp_path / "maximum.keys")
    )
    try:
        handle.admin_client.create_workflow(
            workflow_id="wf", nodes={"root": ()}, policy_version="1"
        )
        assert handle._execution_channel is not None
        node_ids = ("root",) * 1000

        states = handle._execution_channel.workflow_node_states("wf", node_ids)

        assert len(states) == 1000
        assert tuple(state.node_id for state in states) == node_ids
        assert all(state.workflow_id == "wf" for state in states)
    finally:
        handle.close()


def test_execution_status_batch_rejects_1001_node_rpc_and_service_survives(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "oversized.db", tmp_path / "oversized.keys")
    )
    try:
        assert handle._execution_channel is not None
        channel = handle._execution_channel
        with pytest.raises(GovernanceBypassDenied, match="node_status_batch_too_large"):
            channel._rpc(
                "workflow_node_states",
                {"workflow_id": "wf", "node_ids": ["root"] * 1001},
            )
        assert channel.health()["authority_pid"] == handle.pid
    finally:
        handle.close()


def test_in_process_execution_status_batch_rejects_order_spoof(tmp_path) -> None:
    _bootstrap, admin = _provision(
        tmp_path / "order-spoof.db", nodes={"root": (), "child": ("root",)}
    )

    class ReorderingAdmin:
        def workflow_node_states(self, workflow_id, node_ids):
            states = admin.workflow_node_states(workflow_id, node_ids)
            return tuple(reversed(states))

    client = InProcessExecutionClientHarness(ReorderingAdmin())

    with pytest.raises(
        GovernanceBypassDenied, match="authority_status_batch_order_mismatch"
    ):
        getattr(client, "workflow_node_states")("wf", ("root", "child"))


def test_execution_channel_rejects_signed_order_spoof_and_poisons() -> None:
    from constitutional_swarm.authority_ipc import (
        digest,
        recv_frame,
        send_frame,
        signed_response,
    )
    from constitutional_swarm.authority_service import (
        _AuthorityExecutionChannel,
        _bind_verified_child_channel,
    )

    key = producer_key("ordered-batch-ipc")
    client_socket, authority_socket = socket.socketpair(socket.AF_UNIX)
    client = _bind_verified_child_channel(
        _AuthorityExecutionChannel,
        client_socket,
        channel_role="execution",
        session="ordered-batch-session",
        authority_pid=4321,
        ipc_public_key=key.public_key(),
        max_frame_bytes=16_384,
    )

    def reply_out_of_order() -> None:
        request = recv_frame(authority_socket, 16_384)
        states = [
            {
                "workflow_id": "wf",
                "node_id": node_id,
                "status": "ready",
                "version": 0,
                "attempt_id": None,
                "claimed_by": None,
                "artifact_id": None,
                "commit_id": None,
            }
            for node_id in ("child", "root")
        ]
        response = signed_response(
            key=key,
            session="ordered-batch-session",
            channel="execution",
            sequence=1,
            authority_pid=4321,
            request_digest=digest(request),
            result=states,
        )
        send_frame(authority_socket, response, 16_384)
        authority_socket.close()

    thread = threading.Thread(target=reply_out_of_order)
    thread.start()
    with pytest.raises(
        GovernanceBypassDenied, match="authority_status_batch_order_mismatch"
    ):
        client.workflow_node_states("wf", ("root", "child"))
    thread.join(2)
    assert client._poisoned is True
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        client.health()


def test_no_importable_executor_composer_accepts_caller_execution_client() -> None:
    service = importlib.import_module("constitutional_swarm.authority_service")
    swarm = importlib.import_module("constitutional_swarm.swarm")

    assert not hasattr(swarm, "_compose_spawned_executor")
    assert not hasattr(service, "compose_spawned_executor")


def test_swarm_executor_rejects_trusted_governance_admin(tmp_path) -> None:
    _bootstrap, admin = _provision(tmp_path / "reject-admin.sqlite3")

    with pytest.raises(TypeError, match="execution_client"):
        SwarmExecutor(CapabilityRegistry(), ArtifactStore(), admin, policy_version="1")


@pytest.mark.parametrize("client_name", ["admin", "commit_port"])
def test_swarm_executor_rejects_privileged_execution_client(
    tmp_path, client_name: str
) -> None:
    _bootstrap, admin = _provision(tmp_path / f"reject-{client_name}.sqlite3")
    client = admin if client_name == "admin" else admin.commit_port

    with pytest.raises(TypeError, match="execution_client"):
        type.__call__(
            SwarmExecutor,
            CapabilityRegistry(),
            ArtifactStore(),
            execution_client=client,
            policy_version="1",
        )


def test_swarm_executor_rejects_renamed_slots_closure_descriptor_and_subclass_proxies(
    tmp_path,
) -> None:
    _bootstrap, admin = _provision(tmp_path / "reject-proxies.sqlite3")

    class SlotsProxy:
        __slots__ = ("renamed",)

        def __init__(self, value) -> None:
            self.renamed = value

    class DescriptorProxy:
        def __init__(self, value) -> None:
            self._value = value

        @property
        def renamed(self):
            return self._value

    def closure_proxy(value):
        return lambda: value

    proxies = (
        SimpleNamespace(renamed=admin),
        SlotsProxy(admin),
        closure_proxy(admin),
        DescriptorProxy(admin),
        type("RenamedClient", (), {"commit": lambda self, request: request})(),
    )
    for proxy in proxies:
        with pytest.raises(TypeError, match="execution_client"):
            type.__call__(
                SwarmExecutor,
                CapabilityRegistry(),
                ArtifactStore(),
                execution_client=proxy,
                policy_version="1",
            )


def test_supported_executor_is_composed_only_by_trusted_authority_handle(
    tmp_path,
) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "exact.db", tmp_path / "exact.keys")
    )
    try:
        executor = handle.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert executor.health()["executor_pid"] not in {os.getpid(), handle.pid}
        assert not hasattr(handle, "execution_client")
        assert not hasattr(
            importlib.import_module("constitutional_swarm.authority_service"),
            "AuthorityExecutionClient",
        )
    finally:
        handle.close()


def test_forged_scheduler_cannot_enter_supported_composition_or_mutate_authority(
    tmp_path,
) -> None:
    """An attacker-selected socket/key object is not a production composition input."""
    from constitutional_swarm.authority_service import start_authority

    config = authority_child_config(tmp_path / "forge.db", tmp_path / "forge.keys")
    handle = start_authority(config)

    class ForgedScheduler:
        def authoritative_artifact(self, _artifact_id: str) -> Artifact:
            return Artifact("attacker", "root", "attacker", "text", "forged")

    try:
        with pytest.raises(TypeError, match="execution_client"):
            type.__call__(
                SwarmExecutor,
                CapabilityRegistry(),
                ArtifactStore(),
                execution_client=ForgedScheduler(),
                policy_version="1",
            )
        with sqlite3.connect(config.database_path) as connection:
            assert connection.execute(
                "SELECT count(*) FROM certificates"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT count(*) FROM apcc_decisions"
            ).fetchone() == (0,)
    finally:
        handle.close()


def test_spawn_executor_rejects_callable_and_proxy_registry_metadata(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "registry.db", tmp_path / "registry.keys")
    )
    registry = CapabilityRegistry()
    registry.register("agent", [Capability("work", "d")])
    registered = registry.__dict__["_by_agent"]["agent"]
    assert isinstance(registered, list)
    registered.append(lambda: "authority endpoint")
    try:
        with pytest.raises(TypeError, match="inert metadata"):
            handle.spawn_executor(registry, policy_version="1")
        assert handle.health()["authority_pid"] == handle.pid
    finally:
        handle.close()


@pytest.mark.parametrize(
    "client",
    [
        _RestrictedExecutionClient(),
        type("RenamedProxy", (), {"commit": lambda self, request: request})(),
        SimpleNamespace(commit=lambda request: request),
    ],
)
def test_swarm_executor_rejects_execution_client_proxies(client) -> None:
    with pytest.raises(TypeError, match="execution_client"):
        type.__call__(
            SwarmExecutor,
            CapabilityRegistry(),
            ArtifactStore(),
            execution_client=client,
            policy_version="1",
        )


def test_executor_reachable_graph_excludes_authority_capabilities(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    handle = start_authority(
        authority_child_config(tmp_path / "graph.db", tmp_path / "graph.keys")
    )
    try:
        executor = handle.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert executor.health()["executor_pid"] not in {os.getpid(), handle.pid}
        assert not hasattr(executor, "_socket_path")
        assert not hasattr(executor, "admin_client")
    finally:
        handle.close()


def test_authority_death_fails_commit_and_authoritative_read_closed(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    key = producer_key("agent")
    config = authority_child_config(
        tmp_path / "death.db",
        tmp_path / "death.keys",
        producers={"agent": key},
    )
    handle = start_authority(config)
    executor = handle.spawn_executor(CapabilityRegistry(), policy_version="1")
    dag = TaskDAG(dag_id="wf").add_node(TaskNode(node_id="root"))
    provision_executor_workflow(handle.admin_client, dag, policy_version="1")
    handle.admin_client.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=key.public_key(),
    )
    executor.load_dag(dag)
    claim_payload = executor.prepare_claim("root", "agent")
    authorization = sign_attempt_authorization(claim_payload, key)
    executor.claim("root", "agent", authorization)
    artifact = Artifact("artifact", "root", "agent", "text", "result")
    receipt_payload = executor.produce_result(
        "root", artifact, authorization=authorization
    )
    receipt = sign_governed_receipt(receipt_payload, key)
    request = executor.build_request(receipt)
    handle.terminate()
    handle.join(2)

    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        executor.commit(request)
    with pytest.raises(GovernanceBypassDenied, match="authority_unavailable"):
        executor.authoritative_artifact("artifact")
    with sqlite3.connect(config.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM nodes WHERE workflow_id='wf' AND node_id='root'"
        ).fetchone() == ("result_produced",)


def test_separately_spawned_executor_receives_only_restricted_channel(tmp_path) -> None:
    from constitutional_swarm.authority_service import start_authority

    key = producer_key("agent")
    config = authority_child_config(
        tmp_path / "separate.db",
        tmp_path / "separate.keys",
        producers={"agent": key},
    )
    handle = start_authority(config)
    try:
        dag = TaskDAG(dag_id="wf").add_node(TaskNode(node_id="root"))
        provision_executor_workflow(handle.admin_client, dag, policy_version="1")
        handle.admin_client.register_agent(
            workflow_id="wf", agent_id="agent", public_key=key.public_key()
        )
        executor = handle.spawn_executor(CapabilityRegistry(), policy_version="1")
        assert executor.health()["executor_pid"] not in {os.getpid(), handle.pid}
        executor.load_dag(dag)
        claim_payload = executor.prepare_claim("root", "agent")
        authorization = sign_attempt_authorization(claim_payload, key)
        executor.claim("root", "agent", authorization)
        payload = executor.produce_result(
            "root",
            Artifact("artifact", "root", "agent", "text", "result"),
            authorization=authorization,
        )
        decision = executor.commit(
            executor.build_request(sign_governed_receipt(payload, key))
        )
        assert decision.outcome is CommitOutcome.COMMITTED
        committed = executor.authoritative_artifact("artifact")
        assert committed is not None and committed.artifact_id == "artifact"
        executor_pid = executor.pid
        assert executor_pid is not None
        fd_targets = []
        descriptor_root = f"/proc/{executor_pid}/fd"
        if os.path.isdir(descriptor_root):
            for descriptor in os.listdir(descriptor_root):
                try:
                    fd_targets.append(os.readlink(f"{descriptor_root}/{descriptor}"))
                except OSError:
                    pass
        forbidden_values = {config.database_path, config.key_source.location}
        assert not forbidden_values.intersection(fd_targets)
    finally:
        if handle.is_alive():
            handle.terminate()
        handle.join(2)
