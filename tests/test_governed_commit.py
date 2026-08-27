from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import ast
from dataclasses import replace
import multiprocessing
from pathlib import Path
import sqlite3
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.governed_commit import (
    GCB_TLA_ACTION_MAP,
    CommitOutcome,
    CommitRequest,
    GovernedCommitBoundary as RuntimeGovernedCommitBoundary,
    GovernedReceiptPayload,
    TrustedGovernanceBootstrap,
    VerdictDecision,
    sign_attempt_authorization,
    sign_governed_receipt,
)
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.execution import ExecutionStatus
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode


_TEST_BOOTSTRAPS: dict[str, TrustedGovernanceBootstrap] = {}


def _attempt_authorization(
    boundary,
    private_key,
    *,
    workflow_id: str,
    node_id: str,
    attempt_id: str,
    agent_id: str = "agent",
):
    payload = boundary.prepare_attempt_authorization(
        workflow_id=workflow_id,
        node_id=node_id,
        attempt_id=attempt_id,
        agent_id=agent_id,
        nonce=f"claim:{attempt_id}",
    )
    return sign_attempt_authorization(payload, private_key)


def _executor_claim(executor, private_key, node_id: str, agent_id: str = "agent"):
    return executor.claim(
        node_id,
        agent_id,
        sign_attempt_authorization(
            executor.prepare_claim(node_id, agent_id), private_key
        ),
    )


def _trusted_admin(
    path,
    *,
    default_verdict: VerdictDecision = VerdictDecision.ALLOW,
    fault_injector=None,
    busy_timeout_ms=5_000,
):
    """Explicit trusted provisioning fixture for production GCB surfaces."""
    resolved = str(path)
    if resolved in _TEST_BOOTSTRAPS:
        return _TEST_BOOTSTRAPS[resolved].open_admin(
            path,
            fault_injector=fault_injector,
            busy_timeout_ms=busy_timeout_ms,
        )
    if Path(path).exists() and Path(path).stat().st_size > 0:
        return RuntimeGovernedCommitBoundary.open(path, busy_timeout_ms=busy_timeout_ms)
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=Ed25519PrivateKey.generate(), default_verdict=default_verdict
    )
    _TEST_BOOTSTRAPS[resolved] = bootstrap
    return bootstrap.provision(
        path,
        fault_injector=fault_injector,
        busy_timeout_ms=busy_timeout_ms,
    )


def _multiprocess_commit(path, request, start, results) -> None:
    boundary = RuntimeGovernedCommitBoundary.open(path)
    start.wait()
    decision = boundary.commit(request)
    results.put((decision.outcome.value, decision.reason))


def _configured_boundary(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    boundary = _trusted_admin(tmp_path / "authority.sqlite3")
    boundary.create_workflow(
        workflow_id="wf",
        nodes={"root": (), "child": ("root",)},
        policy_version="policy-v1",
    )
    boundary.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=("work",),
    )
    authorization = _attempt_authorization(
        boundary,
        private_key,
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
    )
    boundary.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        agent_id="agent",
        authorization=authorization,
        required_capabilities=("work",),
    )
    artifact = Artifact(
        artifact_id="artifact-1",
        task_id="root",
        agent_id="agent",
        content_type="text",
        content="verified result",
    )
    boundary.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        artifact=artifact,
        authorization=authorization,
    )
    return boundary, private_key, artifact


def _request(boundary, private_key, *, commit_id="commit-1"):
    payload = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        agent_id="agent",
        commit_id=commit_id,
        nonce="nonce-1",
    )
    return boundary.build_request(sign_governed_receipt(payload, private_key))


def test_staged_artifact_is_invisible_until_outbox_projection(tmp_path) -> None:
    boundary, private_key, artifact = _configured_boundary(tmp_path)
    projection = ArtifactStore()

    assert projection.get(artifact.artifact_id) is None
    decision = boundary.commit(_request(boundary, private_key))
    assert decision.outcome is CommitOutcome.COMMITTED
    assert projection.get(artifact.artifact_id) is None

    projector = boundary.bind_projection("wf", projection)
    assert boundary.dispatch_outbox(projector) == 1
    assert projection.get(artifact.artifact_id, workflow_id="wf") == artifact


def test_receipt_tampering_and_replay_fail_closed(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    request = _request(boundary, private_key)
    tampered_payload = GovernedReceiptPayload(
        **{
            **request.receipt.payload.to_dict(),
            "policy_version": "stale-policy",
            "commit_id": "tampered-commit",
        }
    )
    tampered = boundary.build_request(request.receipt.replace(payload=tampered_payload))

    assert boundary.commit(tampered).outcome is CommitOutcome.DENIED
    assert boundary.commit(request).outcome is CommitOutcome.COMMITTED


def test_invalid_signature_and_unknown_context_deny_without_exception(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    request = _request(boundary, private_key, commit_id="bad-signature")
    invalid = request.receipt.replace(signature=base64.b64encode(bytes(64)).decode())
    assert (
        boundary.commit(boundary.build_request(invalid)).reason == "invalid_signature"
    )

    unknown_payload = GovernedReceiptPayload(
        **{
            **request.receipt.payload.to_dict(),
            "workflow_id": "another-workflow",
            "commit_id": "unknown-context",
        }
    )
    unknown = sign_governed_receipt(unknown_payload, private_key)
    assert boundary.commit(boundary.build_request(unknown)).reason == "unknown_context"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("profile", "unknown/profile", "unknown_receipt_profile"),
        ("workflow_id", "other-workflow", "unknown_context"),
        ("node_id", "other-node", "unknown_context"),
        ("attempt_id", "other-attempt", "stale_or_mismatched_attempt_id"),
        ("agent_id", "other-agent", "unknown_context"),
        ("input_digest", "0" * 64, "stale_or_mismatched_input_digest"),
        ("output_digest", "0" * 64, "output_digest_mismatch"),
        ("predecessor_root", "0" * 64, "predecessor_binding_mismatch"),
        ("state_version", 999, "stale_or_mismatched_state_version"),
        ("signature_algorithm", "unknown", "unknown_signature_algorithm"),
        ("key_id", "unknown", "stale_or_mismatched_key_id"),
        ("issued_at", 9_999_999_999, "receipt_expired_or_not_yet_valid"),
        ("expires_at", 0, "receipt_expired_or_not_yet_valid"),
        ("intent", "report_only", "invalid_commit_intent"),
        ("verifier_policy_id", "report", "stale_or_mismatched_verifier_policy_id"),
        ("policy_digest", "0" * 64, "stale_or_mismatched_policy_digest"),
        ("policy_epoch", 999, "stale_or_mismatched_policy_epoch"),
        (
            "authority_snapshot_digest",
            "0" * 64,
            "stale_or_mismatched_authority_snapshot_digest",
        ),
        ("authority_root", "0" * 64, "stale_or_mismatched_authority_root"),
        ("authority_epoch", 999, "stale_or_mismatched_authority_epoch"),
        (
            "agent_revocation_epoch",
            999,
            "stale_or_mismatched_agent_revocation_epoch",
        ),
        (
            "workflow_revocation_generation",
            999,
            "stale_or_mismatched_workflow_revocation_generation",
        ),
        ("workflow_generation", 999, "stale_or_mismatched_workflow_generation"),
    ),
)
def test_receipt_context_binding_tampering_fails_closed(
    tmp_path, field, value, reason
) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path / field)
    request = _request(boundary, private_key)
    payload = GovernedReceiptPayload(
        **{
            **request.receipt.payload.to_dict(),
            field: value,
            "commit_id": f"tampered-{field}",
        }
    )
    tampered = boundary.build_request(sign_governed_receipt(payload, private_key))
    decision = boundary.commit(tampered)
    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == reason


@pytest.mark.parametrize("field", ("nonce", "commit_id"))
def test_unique_commit_bindings_are_covered_by_the_signature(tmp_path, field) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path / field)
    request = _request(boundary, private_key)
    payload = replace(request.receipt.payload, **{field: f"tampered-{field}"})
    tampered = boundary.build_request(request.receipt.replace(payload=payload))

    decision = boundary.commit(tampered)

    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == "invalid_signature"
    assert boundary.node_state("wf", "root").status == "result_produced"


def test_claim_requires_registered_capability_and_current_revocation(tmp_path) -> None:
    boundary = _trusted_admin(tmp_path / "claim.sqlite3")
    private_key = Ed25519PrivateKey.generate()
    boundary.create_workflow(
        workflow_id="wf",
        nodes={"root": ()},
        policy_version="p",
        required_capabilities={"root": ("deploy",)},
    )
    boundary.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=("read",),
    )
    authorization = _attempt_authorization(
        boundary,
        private_key,
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
    )
    with pytest.raises(PermissionError, match="authority_or_capability_denied"):
        boundary.claim(
            workflow_id="wf",
            node_id="root",
            attempt_id="a",
            agent_id="agent",
            authorization=authorization,
        )
    boundary.revoke_agent(workflow_id="wf", agent_id="agent")
    with pytest.raises(PermissionError, match="agent_revoked"):
        boundary.prepare_attempt_authorization(
            workflow_id="wf",
            node_id="root",
            attempt_id="b",
            agent_id="agent",
            nonce="revoked",
        )


def test_concurrent_double_commit_has_one_authoritative_winner(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    first = _request(boundary, private_key, commit_id="commit-a")
    second_payload = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        agent_id="agent",
        commit_id="commit-b",
        nonce="nonce-2",
    )
    second = boundary.build_request(sign_governed_receipt(second_payload, private_key))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(boundary.commit, (first, second)))

    assert [d.outcome for d in outcomes].count(CommitOutcome.COMMITTED) == 1
    assert boundary.node_state("wf", "root").status == "governed_committed"


def test_multiprocess_multiconnection_commit_has_one_winner(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    first = _request(boundary, private_key, commit_id="process-a")
    second_payload = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        agent_id="agent",
        commit_id="process-b",
        nonce="process-nonce-b",
    )
    second = boundary.build_request(sign_governed_receipt(second_payload, private_key))
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_multiprocess_commit,
            args=(boundary.path, request, start, results),
        )
        for request in (first, second)
    ]
    for process in processes:
        process.start()
    start.set()
    outcomes = [results.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert [outcome for outcome, _reason in outcomes].count("committed") == 1
    assert boundary.node_state("wf", "root").status == "governed_committed"


def test_identical_commit_retry_is_idempotent_but_conflict_denies(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    request = _request(boundary, private_key)

    first = boundary.commit(request)
    retry = boundary.commit(request)
    conflict = boundary.commit(
        boundary.build_request(
            sign_governed_receipt(
                GovernedReceiptPayload(
                    **{**request.receipt.payload.to_dict(), "nonce": "different"}
                ),
                private_key,
            )
        )
    )

    assert retry == first
    assert conflict.outcome is CommitOutcome.DENIED
    assert conflict.reason == "idempotency_conflict"
    with sqlite3.connect(boundary.path) as conn:
        event_types = {
            row[0]
            for row in conn.execute(
                "SELECT event_type FROM security_events WHERE event_key=?",
                (request.commit_id,),
            )
        }
    assert event_types == {"commit_collision_attempt"}


def test_stale_policy_and_revoked_agent_are_fenced(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    stale_policy = _request(boundary, private_key, commit_id="stale-policy")
    boundary.update_policy(workflow_id="wf", policy_version="policy-v2")
    assert boundary.commit(stale_policy).reason == "stale_or_mismatched_policy_version"

    fresh = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="attempt-1",
        agent_id="agent",
        commit_id="revoked",
        nonce="nonce-revoked",
    )
    boundary.revoke_agent(workflow_id="wf", agent_id="agent")
    assert boundary.commit(
        boundary.build_request(sign_governed_receipt(fresh, private_key))
    ).reason in {
        "stale_or_mismatched_agent_revocation_epoch",
        "stale_or_mismatched_authority_snapshot_digest",
        "agent_revoked",
    }


def test_authority_change_and_revocation_taint_descendants(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    stale_authority = _request(boundary, private_key, commit_id="stale-authority")
    other_key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id="wf",
        agent_id="other",
        public_key=other_key.public_key(),
        capabilities=("work",),
    )
    assert boundary.commit(stale_authority).reason in {
        "stale_or_mismatched_authority_root",
        "stale_or_mismatched_authority_epoch",
    }
    boundary.revoke_agent(workflow_id="wf", agent_id="agent")
    assert boundary.node_state("wf", "child").status == "revoked"


def test_missing_or_untyped_verdict_fails_closed(tmp_path) -> None:
    boundary, private_key, _artifact = _configured_boundary(tmp_path)
    receipt = sign_governed_receipt(
        boundary.prepare_receipt_payload(
            workflow_id="wf",
            node_id="root",
            attempt_id="attempt-1",
            agent_id="agent",
            commit_id="missing-verdict",
            nonce="n",
        ),
        private_key,
    )
    decision = boundary.commit(CommitRequest(receipt, None))  # type: ignore[arg-type]
    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == "invalid_authoritative_verdict"
    assert boundary.node_state("wf", "root").status == "result_produced"


def test_signed_policy_denial_is_an_immutable_denial(tmp_path) -> None:
    boundary = _trusted_admin(
        tmp_path / "missing.sqlite3", default_verdict=VerdictDecision.DENY
    )
    private_key = Ed25519PrivateKey.generate()
    boundary.create_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p")
    boundary.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=(),
    )
    authorization = _attempt_authorization(
        boundary, private_key, workflow_id="wf", node_id="root", attempt_id="a"
    )
    boundary.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        authorization=authorization,
    )
    boundary.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        artifact=Artifact("art", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    payload = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        commit_id="missing",
        nonce="n",
    )
    request = boundary.build_request(sign_governed_receipt(payload, private_key))
    first = boundary.commit(request)
    assert first.reason == "policy_denied"
    assert boundary.commit(request) == first


def test_wal_foreign_keys_and_recovery_do_not_promote_staging(tmp_path) -> None:
    boundary, _private_key, _ = _configured_boundary(tmp_path)
    recovered = _trusted_admin(boundary.path)
    assert recovered.node_state("wf", "root").status == "result_produced"
    assert recovered.pending_outbox() == 0
    with sqlite3.connect(boundary.path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        conn.execute("PRAGMA foreign_keys=ON")
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_unknown_schema_version_fails_closed(tmp_path) -> None:
    path = tmp_path / "future.sqlite3"
    _trusted_admin(path)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE schema_meta SET version=99 WHERE singleton=1")
    with pytest.raises(RuntimeError, match="unsupported GCB schema"):
        _trusted_admin(path)


def test_legacy_schema_is_quarantined_without_partial_migration(tmp_path) -> None:
    path = tmp_path / "legacy-v1.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE schema_meta(singleton INTEGER PRIMARY KEY, version INTEGER)"
        )
        conn.execute("INSERT INTO schema_meta VALUES(1,1)")

    with pytest.raises(RuntimeError, match="unsupported GCB schema version: 1"):
        _trusted_admin(path)

    with sqlite3.connect(path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert tables == {"schema_meta"}
        assert conn.execute("SELECT version FROM schema_meta").fetchone()[0] == 1


@pytest.mark.parametrize(
    "fault_point", ("after_authority_update", "after_decision_before_outbox")
)
def test_crash_between_authority_update_and_outbox_rolls_back(
    tmp_path, fault_point
) -> None:
    def crash(point: str) -> None:
        if point == fault_point:
            raise RuntimeError("simulated crash")

    private_key = Ed25519PrivateKey.generate()
    boundary = _trusted_admin(tmp_path / "crash.sqlite3", fault_injector=crash)
    boundary.create_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p")
    boundary.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=(),
    )
    authorization = _attempt_authorization(
        boundary, private_key, workflow_id="wf", node_id="root", attempt_id="a"
    )
    boundary.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        authorization=authorization,
    )
    boundary.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        artifact=Artifact("art", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    payload = boundary.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        commit_id="crash",
        nonce="n",
    )
    decision = boundary.commit(
        boundary.build_request(sign_governed_receipt(payload, private_key))
    )
    assert decision.reason == "persistence_error"
    assert boundary.node_state("wf", "root").status == "result_produced"
    assert boundary.pending_outbox() == 0


def test_real_sqlite_persistence_lock_fails_closed(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    boundary._busy_timeout_ms = 25
    request = _request(boundary, private_key, commit_id="locked")
    blocker = sqlite3.connect(boundary.path, isolation_level=None)
    blocker.execute("PRAGMA journal_mode=WAL")
    blocker.execute("BEGIN IMMEDIATE")
    try:
        decision = boundary.commit(request)
    finally:
        blocker.rollback()
        blocker.close()

    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == "persistence_error"
    assert boundary.node_state("wf", "root").status == "result_produced"


def test_outbox_callback_failure_is_recoverable_without_duplicate_publish(
    tmp_path,
) -> None:
    boundary, private_key, artifact = _configured_boundary(tmp_path)
    assert (
        boundary.commit(_request(boundary, private_key)).outcome
        is CommitOutcome.COMMITTED
    )
    projection = ArtifactStore()
    calls = 0

    def fail_once(_artifact) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("consumer unavailable")

    projector = boundary.bind_projection("wf", projection)
    projector.watch("root", fail_once)
    with pytest.raises(RuntimeError, match="consumer unavailable"):
        boundary.dispatch_outbox(projector)
    assert projection.get(artifact.artifact_id, workflow_id="wf") == artifact
    assert boundary.pending_outbox() == 1

    assert boundary.dispatch_outbox(projector) == 1
    assert boundary.pending_outbox() == 0
    assert calls == 2


def test_policy_cache_cannot_override_newer_sqlite_policy_state(tmp_path) -> None:
    boundary, private_key, _ = _configured_boundary(tmp_path)
    stale = _request(boundary, private_key, commit_id="stale-other-connection")
    other_connection = _trusted_admin(boundary.path)
    other_connection.update_policy(workflow_id="wf", policy_version="policy-v2")

    decision = boundary.commit(stale)

    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == "stale_or_mismatched_policy_version"


def test_commit_and_retroactive_revoke_race_never_leaves_consumable_descendant(
    tmp_path,
) -> None:
    path = tmp_path / "revoke-race.sqlite3"
    key = Ed25519PrivateKey.generate()
    setup = _trusted_admin(path)
    setup.create_workflow(
        workflow_id="wf", nodes={"root": (), "child": ("root",)}, policy_version="p"
    )
    setup.register_agent(
        workflow_id="wf", agent_id="agent", public_key=key.public_key(), capabilities=()
    )
    for node_id in ("root", "child"):
        authorization = _attempt_authorization(
            setup,
            key,
            workflow_id="wf",
            node_id=node_id,
            attempt_id=f"{node_id}-attempt",
        )
        setup.claim(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=f"{node_id}-attempt",
            agent_id="agent",
            authorization=authorization,
        )
        setup.stage_result(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=f"{node_id}-attempt",
            artifact=Artifact(f"{node_id}-art", node_id, "agent", "text", node_id),
            authorization=authorization,
        )
        payload = setup.prepare_receipt_payload(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=f"{node_id}-attempt",
            agent_id="agent",
            commit_id=f"{node_id}-commit",
            nonce=f"{node_id}-nonce",
        )
        request = setup.build_request(sign_governed_receipt(payload, key))
        if node_id == "root":
            assert setup.commit(request).outcome is CommitOutcome.COMMITTED
        else:
            child_request = request

    gate = threading.Barrier(2)
    commit_boundary = _trusted_admin(path)
    revoke_boundary = _trusted_admin(path)

    def commit_child():
        gate.wait()
        return commit_boundary.commit(child_request)

    def revoke_root():
        gate.wait()
        return revoke_boundary.revoke_root(
            workflow_id="wf", node_id="root", event_id="race", reason="fraud"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit_child)
        revoke_future = pool.submit(revoke_root)
        decision = commit_future.result()
        assert revoke_future.result() == 2

    assert decision.outcome in {CommitOutcome.COMMITTED, CommitOutcome.DENIED}
    assert setup.node_state("wf", "child").status in {"blocked", "superseded"}
    assert setup.authoritative_artifact("wf", "child-art") is None


def test_executor_unlocks_only_after_governed_commit(tmp_path) -> None:
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    boundary = _trusted_admin(tmp_path / "executor.sqlite3")
    store = ArtifactStore()
    executor = SwarmExecutor(registry, store, boundary, policy_version="p1")
    dag = TaskDAG(dag_id="dag", goal="g")
    dag = dag.add_node(TaskNode(node_id="root", required_capabilities=("work",)))
    dag = dag.add_node(TaskNode(node_id="child", depends_on=("root",)))
    executor.load_dag(dag)
    private_key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id="dag",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=("work",),
    )
    _executor_claim(executor, private_key, "root")
    payload = executor.produce_result(
        "root", Artifact("art", "root", "agent", "text", "result")
    )
    assert executor.available_tasks("agent") == []
    assert store.get("art") is None

    decision = executor.commit(
        boundary.build_request(sign_governed_receipt(payload, private_key))
    )
    assert decision.outcome is CommitOutcome.COMMITTED
    assert [node.node_id for node in executor.available_tasks("agent")] == ["child"]
    assert executor.authoritative_artifact("art") is not None
    assert store.get("art", workflow_id="dag") is not None

    _executor_claim(executor, private_key, "child")
    child_payload = executor.produce_result(
        "child", Artifact("child-art", "child", "agent", "text", "child result")
    )
    assert len(child_payload.predecessor_bindings) == 1
    binding = child_payload.predecessor_bindings[0]
    root_state = boundary.node_state("dag", "root")
    assert binding.node_id == "root"
    assert binding.node_version == root_state.version
    assert binding.commit_id == root_state.commit_id
    assert len(binding.receipt_digest) == 64
    assert len(binding.authoritative_result_digest) == 64

    for field, value in (
        ("node_id", "other-node"),
        ("node_version", 999),
        ("commit_id", "other-commit"),
        ("receipt_digest", "0" * 64),
        ("authoritative_result_digest", "0" * 64),
    ):
        tampered = replace(
            child_payload,
            predecessor_bindings=(replace(binding, **{field: value}),),
            commit_id=f"tampered-predecessor-{field}",
            nonce=f"tampered-predecessor-{field}",
        )
        assert (
            boundary.commit(
                boundary.build_request(sign_governed_receipt(tampered, private_key))
            ).reason
            == "predecessor_binding_mismatch"
        )


def test_executor_response_loss_retry_does_not_double_count_completion(
    tmp_path,
) -> None:
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    boundary = _trusted_admin(tmp_path / "retry.sqlite3")
    executor = SwarmExecutor(
        registry, ArtifactStore(), boundary, policy_version="policy-v1"
    )
    dag = TaskDAG(dag_id="retry-dag", goal="g")
    dag = dag.add_node(TaskNode(node_id="root", required_capabilities=("work",)))
    dag = dag.add_node(TaskNode(node_id="child", depends_on=("root",)))
    executor.load_dag(dag)
    private_key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id="retry-dag",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=("work",),
    )
    _executor_claim(executor, private_key, "root")
    payload = executor.produce_result(
        "root", Artifact("retry-art", "root", "agent", "text", "result")
    )
    request = boundary.build_request(sign_governed_receipt(payload, private_key))

    first = executor.commit(request)
    retry = executor.commit(request)

    assert retry == first
    assert executor.is_complete is False
    assert executor.progress == {"governed_committed": 1, "ready": 1}


def test_executor_recovery_attaches_to_existing_authority_without_promotion(
    tmp_path,
) -> None:
    path = tmp_path / "recovery.sqlite3"
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    private_key = Ed25519PrivateKey.generate()

    def build_dag() -> TaskDAG:
        dag = TaskDAG(dag_id="recover-dag", goal="g")
        return dag.add_node(TaskNode(node_id="root", required_capabilities=("work",)))

    first_boundary = _trusted_admin(path)
    first_executor = SwarmExecutor(
        registry, ArtifactStore(), first_boundary, policy_version="policy-v1"
    )
    first_executor.load_dag(build_dag())
    first_boundary.register_agent(
        workflow_id="recover-dag",
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=("work",),
    )
    _executor_claim(first_executor, private_key, "root")
    first_executor.produce_result(
        "root", Artifact("recover-art", "root", "agent", "text", "staged")
    )

    recovered_boundary = _trusted_admin(path)
    recovered_store = ArtifactStore()
    recovered_executor = SwarmExecutor(
        registry, recovered_store, recovered_boundary, policy_version="policy-v1"
    )
    recovered_executor.load_dag(build_dag())

    assert recovered_executor.progress == {"result_produced": 1}
    assert recovered_store.get("recover-art") is None
    state = recovered_boundary.node_state("recover-dag", "root")
    payload = recovered_boundary.prepare_receipt_payload(
        workflow_id="recover-dag",
        node_id="root",
        attempt_id=state.attempt_id or "",
        agent_id="agent",
        commit_id="recovery-commit",
        nonce="recovery-nonce",
    )
    decision = recovered_executor.commit(
        recovered_boundary.build_request(sign_governed_receipt(payload, private_key))
    )
    assert decision.outcome is CommitOutcome.COMMITTED
    assert recovered_store.get("recover-art", workflow_id="recover-dag") is not None


def test_executor_recovery_requires_retained_signed_attempt_capability_to_stage(
    tmp_path,
) -> None:
    path = tmp_path / "claimed-recovery.sqlite3"
    registry = CapabilityRegistry()
    private_key = Ed25519PrivateKey.generate()
    dag = TaskDAG(dag_id="claimed-recovery").add_node(TaskNode(node_id="root"))

    first = _trusted_admin(path)
    first_executor = SwarmExecutor(
        registry, ArtifactStore(), first, policy_version="policy-v1"
    )
    first_executor.load_dag(dag)
    first.register_agent(
        workflow_id=dag.dag_id,
        agent_id="agent",
        public_key=private_key.public_key(),
        capabilities=(),
    )
    authorization = sign_attempt_authorization(
        first_executor.prepare_claim("root", "agent"), private_key
    )
    first_executor.claim("root", "agent", authorization)

    recovered = _trusted_admin(path)
    recovered_executor = SwarmExecutor(
        registry, ArtifactStore(), recovered, policy_version="policy-v1"
    )
    recovered_executor.load_dag(dag)

    payload = recovered_executor.produce_result(
        "root",
        Artifact("recovered-art", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    assert payload.attempt_id == authorization.payload.attempt_id
    assert recovered_executor.progress == {"result_produced": 1}


def test_executor_recovery_rejects_topology_and_policy_mismatch(tmp_path) -> None:
    path = tmp_path / "mismatch.sqlite3"
    registry = CapabilityRegistry()
    boundary = _trusted_admin(path)
    original = TaskDAG(dag_id="wf", goal="g").add_node(TaskNode(node_id="root"))
    SwarmExecutor(
        registry, ArtifactStore(), boundary, policy_version="policy-v1"
    ).load_dag(original)

    with pytest.raises(PermissionError, match="recovery_policy_mismatch"):
        SwarmExecutor(
            registry, ArtifactStore(), boundary, policy_version="policy-v2"
        ).load_dag(original)

    changed = original.add_node(TaskNode(node_id="extra"))
    with pytest.raises(PermissionError, match="recovery_topology_mismatch"):
        SwarmExecutor(
            registry, ArtifactStore(), boundary, policy_version="policy-v1"
        ).load_dag(changed)


def test_fresh_load_quarantines_legacy_completed_state(tmp_path) -> None:
    boundary = _trusted_admin(tmp_path / "legacy.sqlite3")
    executor = SwarmExecutor(
        CapabilityRegistry(), ArtifactStore(), boundary, policy_version="policy-v1"
    )
    legacy = TaskDAG(dag_id="legacy", goal="g")
    legacy = legacy.add_node(
        TaskNode(
            node_id="root",
            status=ExecutionStatus.GOVERNED_COMMITTED,
            artifact_id="unverified-artifact",
        )
    )
    legacy = legacy.add_node(TaskNode(node_id="child", depends_on=("root",)))

    executor.load_dag(legacy)

    assert executor.progress == {"ready": 1, "blocked": 1}
    assert executor.is_complete is False
    assert [node.node_id for node in executor.available_tasks("any-agent")] == ["root"]


def test_revoke_root_fences_immediately_and_resumes_materialization(tmp_path) -> None:
    registry = CapabilityRegistry()
    registry.register("agent", [Capability(name="work", domain="d")])
    boundary = _trusted_admin(tmp_path / "retro.sqlite3")
    store = ArtifactStore()
    executor = SwarmExecutor(registry, store, boundary, policy_version="p")
    dag = TaskDAG(dag_id="retro", goal="g")
    dag = dag.add_node(TaskNode(node_id="root", required_capabilities=("work",)))
    dag = dag.add_node(TaskNode(node_id="child", depends_on=("root",)))
    dag = dag.add_node(TaskNode(node_id="leaf", depends_on=("child",)))
    executor.load_dag(dag)
    key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id="retro",
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=("work",),
    )
    for node_id, artifact_id in (("root", "root-art"), ("child", "child-art")):
        _executor_claim(executor, key, node_id)
        payload = executor.produce_result(
            node_id, Artifact(artifact_id, node_id, "agent", "text", node_id)
        )
        assert (
            executor.commit(
                boundary.build_request(sign_governed_receipt(payload, key))
            ).outcome
            is CommitOutcome.COMMITTED
        )
    _executor_claim(executor, key, "leaf")
    stale_leaf = executor.produce_result(
        "leaf", Artifact("leaf-art", "leaf", "agent", "text", "leaf")
    )

    generation = boundary.revoke_root(
        workflow_id="retro", node_id="root", event_id="revoke-1", reason="fraud"
    )

    assert generation == 2
    assert (
        boundary.revoke_root(
            workflow_id="retro", node_id="root", event_id="revoke-1", reason="fraud"
        )
        == generation
    )
    assert boundary.node_state("retro", "root").status == "revoked"
    assert boundary.node_state("retro", "child").status == "superseded"
    assert boundary.node_state("retro", "leaf").status == "blocked"
    assert boundary.authoritative_artifact("retro", "root-art") is None
    assert boundary.authoritative_artifact("retro", "child-art") is None
    assert (
        boundary.commit(
            boundary.build_request(sign_governed_receipt(stale_leaf, key))
        ).outcome
        is CommitOutcome.DENIED
    )
    assert boundary.pending_revocations() == 1

    recovered = _trusted_admin(boundary.path)
    assert recovered.resume_revocation_propagation() == 1
    projector = recovered.bind_projection("retro", store)
    assert recovered.dispatch_revocation_outbox(projector) == 1
    assert recovered.pending_revocations() == 0
    assert store.get("root-art", workflow_id="retro") is None
    assert store.get("child-art", workflow_id="retro") is None
    assert recovered.node_state("retro", "root").status == "revoked"
    assert recovered.node_state("retro", "child").status == "superseded"
    assert recovered.node_state("retro", "leaf").status == "blocked"
    assert recovered.resume_revocation_propagation() == 0


def test_revocation_fence_survives_response_loss_and_propagation_crash(
    tmp_path,
) -> None:
    path = tmp_path / "revoke-crash.sqlite3"
    key = Ed25519PrivateKey.generate()
    setup = _trusted_admin(path)
    setup.create_workflow(
        workflow_id="wf", nodes={"root": (), "child": ("root",)}, policy_version="p"
    )
    setup.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )
    authorization = _attempt_authorization(
        setup, key, workflow_id="wf", node_id="root", attempt_id="a"
    )
    setup.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        authorization=authorization,
    )
    setup.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        artifact=Artifact("art", "root", "agent", "text", "result"),
        authorization=authorization,
    )
    payload = setup.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        commit_id="commit",
        nonce="nonce",
    )
    assert (
        setup.commit(setup.build_request(sign_governed_receipt(payload, key))).outcome
        is CommitOutcome.COMMITTED
    )

    def lose_response(point: str) -> None:
        if point == "after_revocation_fence_commit":
            raise RuntimeError("response lost")

    boundary = _trusted_admin(path, fault_injector=lose_response)
    with pytest.raises(RuntimeError, match="response lost"):
        boundary.revoke_root(
            workflow_id="wf", node_id="root", event_id="event", reason="fraud"
        )
    assert boundary.node_state("wf", "child").status == "blocked"

    def crash_propagation(point: str) -> None:
        if point == "during_revocation_propagation":
            raise RuntimeError("propagation crash")

    crashing = _trusted_admin(path, fault_injector=crash_propagation)
    with pytest.raises(RuntimeError, match="propagation crash"):
        crashing.resume_revocation_propagation()
    assert crashing.node_state("wf", "child").status == "blocked"
    assert crashing.pending_revocations() == 1
    recovered = _trusted_admin(path)
    assert recovered.resume_revocation_propagation() == 1
    assert recovered.pending_revocations() == 1


def test_executor_revocation_refreshes_projection_and_blocks_descendants(
    tmp_path,
) -> None:
    registry = CapabilityRegistry()
    boundary = _trusted_admin(tmp_path / "executor-revoke.sqlite3")
    store = ArtifactStore()
    executor = SwarmExecutor(registry, store, boundary, policy_version="p")
    dag = TaskDAG(dag_id="executor-revoke")
    dag = dag.add_node(TaskNode(node_id="root"))
    dag = dag.add_node(TaskNode(node_id="child", depends_on=("root",)))
    executor.load_dag(dag)
    key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id=dag.dag_id,
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )
    _executor_claim(executor, key, "root")
    payload = executor.produce_result(
        "root", Artifact("root-art", "root", "agent", "text", "result")
    )
    assert (
        executor.commit(
            boundary.build_request(sign_governed_receipt(payload, key))
        ).outcome
        is CommitOutcome.COMMITTED
    )

    executor.revoke_root("root", event_id="event", reason="invalid result")

    assert executor.progress == {"revoked": 1, "blocked": 1}
    assert executor.available_tasks("agent") == []
    assert store.get("root-art", workflow_id=dag.dag_id) is None
    assert boundary.pending_revocations() == 0


def test_external_revocation_fence_invalidates_executor_ready_cache(tmp_path) -> None:
    registry = CapabilityRegistry()
    store = ArtifactStore()
    boundary = _trusted_admin(tmp_path / "stale-ready.sqlite3")
    executor = SwarmExecutor(registry, store, boundary, policy_version="p")
    dag = TaskDAG(dag_id="stale-ready")
    dag = dag.add_node(TaskNode(node_id="root"))
    dag = dag.add_node(TaskNode(node_id="child", depends_on=("root",)))
    executor.load_dag(dag)
    key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id=dag.dag_id,
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )
    _executor_claim(executor, key, "root")
    payload = executor.produce_result(
        "root", Artifact("root-art", "root", "agent", "text", "result")
    )
    assert (
        executor.commit(
            boundary.build_request(sign_governed_receipt(payload, key))
        ).outcome
        is CommitOutcome.COMMITTED
    )
    assert [node.node_id for node in executor.available_tasks("agent")] == ["child"]
    assert executor.authoritative_artifact("root-art") is not None

    boundary.revoke_root(
        workflow_id=dag.dag_id,
        node_id="root",
        event_id="external-revoke",
        reason="fraud",
    )

    assert executor.available_tasks("agent") == []
    assert executor.progress == {"revoked": 1, "blocked": 1}
    assert executor.authoritative_artifact("root-art") is None
    assert store.get("root-art", workflow_id=dag.dag_id) is None
    assert store.get_by_task("root", workflow_id=dag.dag_id) == []


def test_executor_recovery_resumes_pending_revocation_and_retracts_artifact(
    tmp_path,
) -> None:
    registry = CapabilityRegistry()
    path = tmp_path / "executor-revoke-recovery.sqlite3"
    store = ArtifactStore()
    key = Ed25519PrivateKey.generate()
    first = _trusted_admin(path)
    dag = TaskDAG(dag_id="recover-revoke").add_node(TaskNode(node_id="root"))
    executor = SwarmExecutor(registry, store, first, policy_version="p")
    executor.load_dag(dag)
    first.register_agent(
        workflow_id=dag.dag_id,
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )
    _executor_claim(executor, key, "root")
    payload = executor.produce_result(
        "root", Artifact("root-art", "root", "agent", "text", "result")
    )
    assert (
        executor.commit(
            first.build_request(sign_governed_receipt(payload, key))
        ).outcome
        is CommitOutcome.COMMITTED
    )
    first.revoke_root(
        workflow_id=dag.dag_id,
        node_id="root",
        event_id="event",
        reason="invalid result",
    )
    assert first.pending_revocations() == 1
    assert store.get("root-art", workflow_id=dag.dag_id) is None

    recovered = _trusted_admin(path)
    recovered_executor = SwarmExecutor(registry, store, recovered, policy_version="p")
    recovered_executor.load_dag(dag)

    assert recovered.pending_revocations() == 0
    assert recovered_executor.progress == {"revoked": 1}
    assert store.get("root-art", workflow_id=dag.dag_id) is None


def test_authority_sql_is_confined_to_boundary_module() -> None:
    source_root = (
        __import__("pathlib").Path(__file__).parents[1] / "src" / "constitutional_swarm"
    )
    forbidden = ("status='governed_committed'", "INSERT INTO outbox")
    offenders = []
    for path in source_root.rglob("*.py"):
        text = path.read_text()
        ast.parse(text)
        if path.name != "governed_commit.py" and any(
            token in text for token in forbidden
        ):
            offenders.append(path.name)
    assert offenders == []


def test_authoritative_status_assignments_are_confined_to_projection_refresh() -> None:
    source_root = Path(__file__).parents[1] / "src" / "constitutional_swarm"
    allowed = {
        ("swarm.py", "commit"),
        ("swarm.py", "_synchronize_authoritative_states"),
    }
    offenders = []

    class StatusAssignmentVisitor(ast.NodeVisitor):
        def __init__(self, filename: str) -> None:
            self.filename = filename
            self.functions: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        def visit_Assign(self, node: ast.Assign) -> None:
            value = ast.unparse(node.value)
            authoritative = (
                "GOVERNED_COMMITTED" in value or repr("governed_committed") in value
            )
            status_target = any(
                isinstance(target, ast.Attribute) and target.attr == "status"
                for target in node.targets
            )
            function = self.functions[-1] if self.functions else "<module>"
            if (
                authoritative
                and status_target
                and (self.filename, function) not in allowed
            ):
                offenders.append((self.filename, function, node.lineno))
            self.generic_visit(node)

    for path in source_root.rglob("*.py"):
        StatusAssignmentVisitor(path.name).visit(ast.parse(path.read_text()))
    assert offenders == []


def test_authority_module_does_not_depend_on_non_authoritative_runtimes() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "constitutional_swarm"
        / "governed_commit.py"
    )
    imports = {
        alias.name
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or ""
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(
        forbidden in imported
        for imported in imports
        for forbidden in ("mesh", "langgraph", "jsonl")
    )


def test_runtime_contains_no_legacy_dag_completion_calls() -> None:
    source_root = (
        __import__("pathlib").Path(__file__).parents[1] / "src" / "constitutional_swarm"
    )

    def bypass_sinks(source: str) -> list[str]:
        tree = ast.parse(source)
        findings: list[str] = []
        values: dict[str, str] = {}
        call_aliases: set[str] = set()

        def is_authority_sink(expression: str) -> bool:
            normalized = expression.replace(" ", "")
            if normalized.endswith(
                (".complete_node", ".mark_success", ".store_result")
            ):
                return True
            if not normalized.endswith(".submit"):
                return False
            receiver = normalized.removesuffix(".submit").split(".")[-1].lower()
            return receiver in {"executor", "_executor", "dag", "_dag", "swarm"}

        def resolve(node: ast.AST | None) -> str:
            if node is None:
                return ""
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.Name):
                return values.get(node.id, node.id)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return resolve(node.left) + resolve(node.right)
            if isinstance(node, ast.JoinedStr):
                return "".join(resolve(value) for value in node.values)
            if isinstance(node, ast.FormattedValue):
                return resolve(node.value)
            return ast.unparse(node)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                value_node = node.value
                for target in targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = resolve(value_node)
                        if is_authority_sink(resolve(value_node)):
                            call_aliases.add(target.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func).replace(" ", "")
                if is_authority_sink(name) or (
                    isinstance(node.func, ast.Name) and node.func.id in call_aliases
                ):
                    findings.append(name)
                if name in {"setattr", "object.__setattr__"} and len(node.args) >= 2:
                    try:
                        attribute = ast.literal_eval(node.args[1])
                    except (ValueError, TypeError):
                        attribute = None
                    if attribute == "status":
                        findings.append("dynamic-status-write")
                if isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "execute",
                    "executemany",
                    "executescript",
                }:
                    for argument in node.args[:1]:
                        sql = " ".join(resolve(argument).split()).lower()
                        if "update nodes set" in sql and (
                            "completed" in sql or "governed_committed" in sql
                        ):
                            findings.append("authoritative-sql-write")
                elif node.args:
                    sql = " ".join(resolve(node.args[0]).split()).lower()
                    if "update nodes set" in sql and (
                        "completed" in sql or "governed_committed" in sql
                    ):
                        findings.append("indirect-authoritative-sql-write")
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(
                    isinstance(target, ast.Attribute) and target.attr == "status"
                    for target in targets
                ):
                    value = ast.unparse(node.value) if node.value is not None else ""
                    resolved = resolve(node.value)
                    if (
                        "COMPLETED" in value
                        or "governed_committed" in resolved.lower()
                        or resolved.lower() == "completed"
                    ):
                        findings.append("direct-status-write")
                if any(
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "__dict__"
                    and resolve(target.slice) == "status"
                    for target in targets
                ):
                    findings.append("dict-status-write")
        return findings

    offenders: list[str] = []
    for path in source_root.rglob("*.py"):
        if path.name == "governed_commit.py":
            continue
        findings = bypass_sinks(path.read_text())
        if findings:
            offenders.append(f"{path.relative_to(source_root).as_posix()}: {findings}")
    assert offenders == []
    negative_fixtures = (
        "setattr(node, 'status', 'completed')",
        'getattr(store, "execute")("UPDATE  nodes  SET status = \'governed_committed\'")',
        "db.execute('UPDATE\\n nodes SET status=\"completed\"')",
        "node.status = ExecutionStatus.COMPLETED",
        "node.status = 'governed_' + 'committed'",
        "sql = 'UPDATE ' + 'nodes SET status=completed'; run = db.execute; run(sql)",
        "node.__dict__['status'] = 'completed'",
        "finish = executor.submit; finish(node)",
    )
    assert all(bypass_sinks(fixture) for fixture in negative_fixtures)


def test_public_projection_methods_never_return_internal_dag_nodes() -> None:
    source = Path(__file__).parents[1] / "src" / "constitutional_swarm" / "swarm.py"
    tree = ast.parse(source.read_text())
    projection_methods = {"dag", "available_tasks"}
    checked = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in projection_methods:
            continue
        method_source = ast.unparse(node)
        assert "_node_snapshot" in method_source
        assert "return self._dag" not in method_source
        assert "return list(self._ready_list)" not in method_source
        checked.add(node.name)
    assert checked == projection_methods


def test_tla_actions_have_implementation_refinement_anchors() -> None:
    root = Path(__file__).parents[1]
    model = (root / "specs" / "governed_commit.tla").read_text()
    implementation = (
        root / "src" / "constitutional_swarm" / "governed_commit.py"
    ).read_text()
    assert set(GCB_TLA_ACTION_MAP) == {
        "Claim",
        "ProduceResult",
        "TryCommit",
        "RejectConflict",
        "RejectCrossContext",
        "RejectRevokedAttempt",
        "ExactReplay",
        "Equivocation",
        "RevokeRoot",
        "PropagationCrash",
        "RecoverPropagation",
        "Propagate",
        "Dispatch",
        "CrashRecover",
        "ReconfigurePolicy",
        "RevokeExecutor",
        "FenceWorkflowGeneration",
        "ValidatorFailure",
        "RecoverValidator",
        "ResponseLoss",
    }
    function_names = {
        node.name
        for node in ast.walk(ast.parse(implementation))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for action, anchors in GCB_TLA_ACTION_MAP.items():
        assert f"{action}(" in model or f"{action} ==" in model
        assert anchors[0] in function_names
        assert all(anchor in implementation for anchor in anchors[1:])
    for certificate_field in (
        "CertificateNode",
        "CertificateVersion",
        "CertificateCommit",
        "CertificateReceiptDigest",
        "CertificateResultDigest",
        "CertificateRoot",
        "ConcretePredecessorFence",
    ):
        assert certificate_field in model
    assert model.count("executorEligible[w][ReceiptExecutor(c)]") >= 3
    assert "PostRevocationExecutorFence" in model
    assert "executorEligible' = [executorEligible EXCEPT ![w][e] = FALSE]" in model
    assert "nodeVersion' = [nodeVersion EXCEPT ![w]" in model


def test_tla_non_vacuity_coverage_has_reachable_witness_contract() -> None:
    root = Path(__file__).parents[1]
    model = (root / "specs" / "governed_commit.tla").read_text()
    safety_config = (root / "specs" / "governed_commit.cfg").read_text()
    coverage_config = (root / "specs" / "governed_commit_coverage.cfg").read_text()

    assert "ReceiptAuthorityEpoch(c) == 0" in model
    assert "ReceiptAgentRevocationEpoch(c) == 0" in model
    assert "ReceiptRootRevocationEpoch(c) == 0" in model
    assert "CertificateCommit(c, p) ==" in model
    assert "c = C3 /\\ p = Root THEN C1" in model
    assert "c = C4 /\\ p = Child THEN C3" in model
    assert "RejectRevokedAttempt(c) ==" in model
    assert "CommittedChildLeafWithCertificates" in model
    assert "ObservedPostRevocationDenial" in model
    assert "CoverageGoalReached" in model
    assert "CoverageGoalNotReached == ~CoverageGoalReached" in model
    assert "CoverageGoalNotReached" not in safety_config
    assert "INVARIANT Invariant" in coverage_config
    assert "INVARIANT CoverageGoalNotReached" in coverage_config
    assert "ValidReceipts = {c1, c3, c4, c5, c6}" in coverage_config
    assert "Expected result: TLC exit 12" in coverage_config
    assert '"Invariant CoverageGoalNotReached is violated."' in coverage_config
    assert "not a safety failure" in coverage_config


def test_public_dag_and_available_task_projections_are_defensive_copies(
    tmp_path,
) -> None:
    registry = CapabilityRegistry()
    boundary = _trusted_admin(tmp_path / "projection.sqlite3")
    executor = SwarmExecutor(registry, ArtifactStore(), boundary, policy_version="p")
    executor.load_dag(TaskDAG(dag_id="projection").add_node(TaskNode(node_id="root")))
    key = Ed25519PrivateKey.generate()
    boundary.register_agent(
        workflow_id="projection",
        agent_id="agent",
        public_key=key.public_key(),
        capabilities=(),
    )

    available = executor.available_tasks("agent")
    snapshot = executor.dag
    assert snapshot is not None
    available[0].status = ExecutionStatus.GOVERNED_COMMITTED
    snapshot.nodes["root"].status = ExecutionStatus.GOVERNED_COMMITTED
    snapshot.nodes["root"].metadata["attempt_id"] = "forged"

    assert executor.progress == {"ready": 1}
    assert _executor_claim(executor, key, "root").claimed_by == "agent"
