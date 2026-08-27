"""Regression probes derived from the independent GCB-1 FAIL review."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from constitutional_swarm.artifact import Artifact, ArtifactEvent, ArtifactStore
from constitutional_swarm.execution import (
    ContractStatus,
    ExecutionStatus,
    WorkReceipt,
    contract_status_from_execution,
)
from constitutional_swarm.governed_commit import (
    AuthoritativeVerdict,
    CommitOutcome,
    GovernanceBypassDenied,
    GovernedCommitBoundary,
    TrustedGovernanceBootstrap,
    sign_attempt_authorization,
)


def _authorize(port, key, workflow_id: str, node_id: str, attempt_id: str):
    return sign_attempt_authorization(
        port.prepare_attempt_authorization(
            workflow_id=workflow_id,
            node_id=node_id,
            attempt_id=attempt_id,
            agent_id="agent",
            nonce=f"claim:{workflow_id}:{node_id}:{attempt_id}",
        ),
        key,
    )


def _provision(path):
    verifier_key = Ed25519PrivateKey.generate()
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=verifier_key,
        policy_id="review-policy",
    )
    admin = bootstrap.provision(path)
    admin.create_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p1")
    agent_key = Ed25519PrivateKey.generate()
    admin.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=agent_key.public_key(),
        capabilities=(),
    )
    port = admin.commit_port
    authorization = _authorize(port, agent_key, "wf", "root", "a1")
    port.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        authorization=authorization,
    )
    port.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        artifact=Artifact("artifact", "root", "agent", "text", "value"),
        authorization=authorization,
    )
    return bootstrap, admin, port, agent_key


def test_existing_authority_rejects_replacement_or_truthy_verifier(tmp_path) -> None:
    bootstrap, _admin, _port, _agent_key = _provision(tmp_path / "sealed.sqlite3")

    with pytest.raises(GovernanceBypassDenied, match="authority_store_already_exists"):
        TrustedGovernanceBootstrap(
            verifier_key=Ed25519PrivateKey.generate(),
            policy_id="review-policy",
        ).provision(tmp_path / "sealed.sqlite3")

    with pytest.raises(GovernanceBypassDenied, match="sealed store"):
        GovernedCommitBoundary(tmp_path / "raw.sqlite3", validator=lambda _p: True)

    payload = _port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, _agent_key)
    assert isinstance(bootstrap.verdict_for(receipt), AuthoritativeVerdict)


def test_agent_commit_port_cannot_administer_authority(tmp_path) -> None:
    _bootstrap, _admin, port, _agent_key = _provision(tmp_path / "admin.sqlite3")

    for name in (
        "create_workflow",
        "register_agent",
        "update_policy",
        "revoke_agent",
        "bind_projection",
        "dispatch_outbox",
        "dispatch_revocation_outbox",
    ):
        assert not hasattr(port, name)


def test_claim_and_stage_require_agent_proof_of_possession(tmp_path) -> None:
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=Ed25519PrivateKey.generate(), policy_id="attempt-proof"
    )
    admin = bootstrap.provision(tmp_path / "attempt-proof.sqlite3")
    admin.create_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p")
    key = Ed25519PrivateKey.generate()
    admin.register_agent(
        workflow_id="wf", agent_id="agent", public_key=key.public_key(), capabilities=()
    )
    port = admin.commit_port

    with pytest.raises(
        GovernanceBypassDenied, match="signed_attempt_authorization_required"
    ):
        port.claim(workflow_id="wf", node_id="root", attempt_id="a", agent_id="agent")

    authorization = _authorize(port, key, "wf", "root", "a")
    forged = replace(authorization, signature="AAAA")
    with pytest.raises(
        GovernanceBypassDenied, match="invalid_attempt_authorization_signature"
    ):
        port.claim(
            workflow_id="wf",
            node_id="root",
            attempt_id="a",
            agent_id="agent",
            authorization=forged,
        )

    port.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        authorization=authorization,
    )
    with pytest.raises(
        GovernanceBypassDenied, match="signed_attempt_authorization_required"
    ):
        port.stage_result(
            workflow_id="wf",
            node_id="root",
            attempt_id="a",
            artifact=Artifact("artifact", "root", "agent", "text", "value"),
        )


def test_signed_expected_node_version_fences_reviewer_race(tmp_path) -> None:
    bootstrap, admin, port, agent_key = _provision(tmp_path / "version.sqlite3")
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    assert payload.expected_node_state_version == 2

    # A trusted authority mutation changes the node version after signing.
    admin.fence_node_for_review(workflow_id="wf", node_id="root")
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    decision = port.commit(port.build_request(receipt, bootstrap.verdict_for(receipt)))
    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == "stale_or_mismatched_expected_node_state_version"


def test_governed_projection_is_monotonic_namespaced_and_fail_closed(tmp_path) -> None:
    _bootstrap, admin, port, _agent_key = _provision(tmp_path / "projection.sqlite3")
    store = ArtifactStore()
    projection = admin.bind_projection("wf", store)

    with pytest.raises(GovernanceBypassDenied, match="governed_projection_is_sealed"):
        store.publish(Artifact("artifact", "root", "agent", "text", "forged"))
    with pytest.raises(
        GovernanceBypassDenied, match="governed_projection_is_monotonic"
    ):
        store.set_visibility_guard(lambda _artifact_id: True)

    assert store.get("artifact", workflow_id="wf") is None
    assert projection.workflow_id == "wf"
    with pytest.raises(
        GovernanceBypassDenied, match="projection_artifact_not_authoritative"
    ):
        projection.publish(Artifact("forged", "root", "agent", "text", "forged"))


def test_arbitrary_truthy_authoritative_verdict_is_denied(tmp_path) -> None:
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=Ed25519PrivateKey.generate(),
        policy_id="typed",
    )
    admin = bootstrap.provision(tmp_path / "truthy.sqlite3")
    admin.create_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p")
    key = Ed25519PrivateKey.generate()
    admin.register_agent(
        workflow_id="wf", agent_id="agent", public_key=key.public_key(), capabilities=()
    )
    port = admin.commit_port
    authorization = _authorize(port, key, "wf", "root", "a")
    port.claim(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        authorization=authorization,
    )
    port.stage_result(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        artifact=Artifact("artifact", "root", "agent", "text", "value"),
        authorization=authorization,
    )
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a",
        agent_id="agent",
        commit_id="c",
        nonce="n",
    )
    receipt = bootstrap.sign_agent_receipt(payload, key)
    decision = port.commit(port.build_request(receipt, {"allow": True}))  # type: ignore[arg-type]
    assert decision.reason == "invalid_authoritative_verdict"


def test_expected_node_version_tampering_is_signature_covered(tmp_path) -> None:
    bootstrap, _admin, port, agent_key = _provision(tmp_path / "tamper.sqlite3")
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    tampered = replace(
        receipt,
        payload=replace(
            payload,
            expected_node_state_version=payload.expected_node_state_version + 1,
        ),
    )
    verdict = bootstrap.verdict_for(receipt)
    assert (
        port.commit(port.build_request(tampered, verdict)).reason == "invalid_signature"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("store_id", "other-store"),
        ("verifier_policy_id", "other-policy"),
        ("verifier_key_id", "other-key"),
        ("receipt_digest", "0" * 64),
        ("workflow_id", "other-workflow"),
        ("node_id", "other-node"),
        ("attempt_id", "other-attempt"),
        ("agent_id", "other-agent"),
        ("expected_node_state_version", 99),
        ("policy_epoch", 99),
        ("authority_epoch", 99),
        ("agent_revocation_epoch", 99),
        ("workflow_revocation_generation", 99),
        ("workflow_generation", 99),
    ),
)
def test_each_verdict_context_binding_rejects_one_field_tamper(
    tmp_path, field: str, value: object
) -> None:
    bootstrap, _admin, port, agent_key = _provision(tmp_path / f"{field}.sqlite3")
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    verdict = replace(bootstrap.verdict_for(receipt), **{field: value})
    decision = port.commit(port.build_request(receipt, verdict))
    assert decision.outcome is CommitOutcome.DENIED
    assert decision.reason == f"stale_or_mismatched_verdict_{field}"


def test_recovery_reverifies_persisted_receipt_evidence(tmp_path) -> None:
    path = tmp_path / "recovery.sqlite3"
    bootstrap, admin, port, agent_key = _provision(path)
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    decision = port.commit(port.build_request(receipt, bootstrap.verdict_for(receipt)))
    assert decision.outcome is CommitOutcome.COMMITTED
    admin.attach_workflow(workflow_id="wf", nodes={"root": ()}, policy_version="p1")

    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE receipt_evidence SET receipt_material=receipt_material || ' '"
        )
    with pytest.raises(
        GovernanceBypassDenied, match="recovery_receipt_digest_mismatch"
    ):
        GovernedCommitBoundary.open(path)


def test_legacy_completed_requires_governed_revalidation() -> None:
    assert (
        contract_status_from_execution(ExecutionStatus.COMPLETED)
        is ContractStatus.REQUIRES_REVALIDATION
    )
    result = WorkReceipt(title="legacy").claim("agent").complete("unverified")
    assert result.status is ContractStatus.REQUIRES_REVALIDATION
    assert result.execution_status is ExecutionStatus.RESULT_PRODUCED


def test_response_loss_after_sqlite_commit_is_idempotently_recoverable(
    tmp_path,
) -> None:
    path = tmp_path / "response-loss.sqlite3"
    bootstrap, _admin, port, agent_key = _provision(path)
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    request = port.build_request(receipt, bootstrap.verdict_for(receipt))

    def lose_response(point: str) -> None:
        if point == "after_durable_commit":
            raise RuntimeError("response lost")

    crashing = bootstrap.open_admin(path, fault_injector=lose_response).commit_port
    with pytest.raises(RuntimeError, match="response lost"):
        crashing.commit(request)

    recovered = GovernedCommitBoundary.open(path)
    assert recovered.node_state("wf", "root").status == "governed_committed"
    retry = recovered.commit(request)
    assert retry.outcome is CommitOutcome.COMMITTED
    assert retry.commit_id == "c1"


@pytest.mark.parametrize("control", ["policy", "agent_revocation"])
def test_commit_competes_with_signed_control_transition_on_real_connections(
    tmp_path, control: str
) -> None:
    path = tmp_path / f"{control}.sqlite3"
    bootstrap, admin, port, agent_key = _provision(path)
    payload = port.prepare_receipt_payload(
        workflow_id="wf",
        node_id="root",
        attempt_id="a1",
        agent_id="agent",
        commit_id="c1",
        nonce="n1",
    )
    receipt = bootstrap.sign_agent_receipt(payload, agent_key)
    request = port.build_request(receipt, bootstrap.verdict_for(receipt))
    committing = GovernedCommitBoundary.open(path)
    barrier = threading.Barrier(2)

    def do_commit():
        barrier.wait()
        return committing.commit(request)

    def do_control():
        barrier.wait()
        if control == "policy":
            return admin.update_policy(workflow_id="wf", policy_version="p2")
        return admin.revoke_agent(workflow_id="wf", agent_id="agent")

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(do_commit)
        control_future = pool.submit(do_control)
        decision = commit_future.result()
        assert control_future.result() >= 2

    assert decision.outcome in {CommitOutcome.COMMITTED, CommitOutcome.DENIED}
    if decision.outcome is CommitOutcome.DENIED:
        expected = (
            "stale_or_mismatched_policy_version"
            if control == "policy"
            else {
                "stale_or_mismatched_authority_snapshot_digest",
                "stale_or_mismatched_authority_root",
                "stale_or_mismatched_authority_epoch",
                "stale_or_mismatched_agent_revocation_epoch",
                "agent_revoked",
            }
        )
        if isinstance(expected, set):
            assert decision.reason in expected
        else:
            assert decision.reason == expected


def test_predecessor_generation_replacement_competes_atomically_with_commit(
    tmp_path,
) -> None:
    path = tmp_path / "generation-race.sqlite3"
    verifier_key = Ed25519PrivateKey.generate()
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=verifier_key, policy_id="review-policy"
    )
    admin = bootstrap.provision(path)
    admin.create_workflow(
        workflow_id="wf", nodes={"root": (), "child": ("root",)}, policy_version="p1"
    )
    agent_key = Ed25519PrivateKey.generate()
    admin.register_agent(
        workflow_id="wf",
        agent_id="agent",
        public_key=agent_key.public_key(),
        capabilities=(),
    )
    port = admin.commit_port
    for node_id in ("root", "child"):
        attempt = f"{node_id}-attempt"
        authorization = _authorize(port, agent_key, "wf", node_id, attempt)
        port.claim(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=attempt,
            agent_id="agent",
            authorization=authorization,
        )
        port.stage_result(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=attempt,
            artifact=Artifact(f"{node_id}-artifact", node_id, "agent", "text", node_id),
            authorization=authorization,
        )
        payload = port.prepare_receipt_payload(
            workflow_id="wf",
            node_id=node_id,
            attempt_id=attempt,
            agent_id="agent",
            commit_id=f"{node_id}-commit",
            nonce=f"{node_id}-nonce",
        )
        receipt = bootstrap.sign_agent_receipt(payload, agent_key)
        request = port.build_request(receipt, bootstrap.verdict_for(receipt))
        if node_id == "root":
            assert port.commit(request).outcome is CommitOutcome.COMMITTED
        else:
            child_request = request

    barrier = threading.Barrier(2)
    committing = GovernedCommitBoundary.open(path)

    def do_commit():
        barrier.wait()
        return committing.commit(child_request)

    def replace_generation():
        barrier.wait()
        return admin.bump_workflow_generation(workflow_id="wf")

    with ThreadPoolExecutor(max_workers=2) as pool:
        decision_future = pool.submit(do_commit)
        generation_future = pool.submit(replace_generation)
        decision = decision_future.result()
        assert generation_future.result() == 2

    assert decision.outcome in {CommitOutcome.COMMITTED, CommitOutcome.DENIED}
    if decision.outcome is CommitOutcome.DENIED:
        assert decision.reason in {
            "stale_or_mismatched_workflow_generation",
            "node_not_result_produced",
        }


def test_governed_artifact_reads_and_watchers_are_workflow_scoped(tmp_path) -> None:
    bootstrap = TrustedGovernanceBootstrap(
        verifier_key=Ed25519PrivateKey.generate(), policy_id="scoped"
    )
    admin = bootstrap.provision(tmp_path / "scoped.sqlite3")
    key = Ed25519PrivateKey.generate()
    store = ArtifactStore()
    events_a: list[ArtifactEvent] = []
    events_b: list[ArtifactEvent] = []

    for workflow_id, content in (("wf-a", "a"), ("wf-b", "b")):
        admin.create_workflow(
            workflow_id=workflow_id, nodes={"root": ()}, policy_version="p"
        )
        admin.register_agent(
            workflow_id=workflow_id,
            agent_id="agent",
            public_key=key.public_key(),
            capabilities=(),
        )
        projection = admin.bind_projection(workflow_id, store)
        projection.watch(
            "root", events_a.append if workflow_id == "wf-a" else events_b.append
        )
        port = admin.commit_port
        authorization = _authorize(port, key, workflow_id, "root", "attempt")
        port.claim(
            workflow_id=workflow_id,
            node_id="root",
            attempt_id="attempt",
            agent_id="agent",
            authorization=authorization,
        )
        port.stage_result(
            workflow_id=workflow_id,
            node_id="root",
            attempt_id="attempt",
            artifact=Artifact("same-id", "root", "agent", "text", content),
            authorization=authorization,
        )
        payload = port.prepare_receipt_payload(
            workflow_id=workflow_id,
            node_id="root",
            attempt_id="attempt",
            agent_id="agent",
            commit_id=f"commit-{workflow_id}",
            nonce=f"nonce-{workflow_id}",
        )
        receipt = bootstrap.sign_agent_receipt(payload, key)
        assert (
            port.commit(
                port.build_request(receipt, bootstrap.verdict_for(receipt))
            ).outcome
            is CommitOutcome.COMMITTED
        )
        admin.dispatch_outbox(projection)

    with pytest.raises(
        GovernanceBypassDenied, match="workflow_id_required_for_governed_read"
    ):
        store.get("same-id")
    with pytest.raises(
        GovernanceBypassDenied, match="workflow_id_required_for_governed_watch"
    ):
        store.watch("root", lambda _event: None)
    assert [event.workflow_id for event in events_a] == ["wf-a"]
    assert [event.workflow_id for event in events_b] == ["wf-b"]
    assert events_a[0].artifact.content == "a"
    assert events_b[0].artifact.content == "b"


@pytest.mark.parametrize(
    "damage", ["drop_index", "drop_evidence_table", "extra_trigger"]
)
def test_open_quarantines_schema_damage_without_repair(tmp_path, damage: str) -> None:
    path = tmp_path / f"{damage}.sqlite3"
    _bootstrap, _admin, _port, _agent_key = _provision(path)
    with sqlite3.connect(path) as conn:
        if damage == "drop_index":
            conn.execute("DROP INDEX idx_outbox_pending")
        elif damage == "drop_evidence_table":
            conn.execute("DROP TABLE receipt_evidence")
        else:
            conn.execute(
                "CREATE TRIGGER forbidden AFTER UPDATE ON nodes BEGIN SELECT 1; END"
            )
    with pytest.raises(GovernanceBypassDenied, match="authority_schema_shape_mismatch"):
        GovernedCommitBoundary.open(path)
    with sqlite3.connect(path) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','index','trigger')"
            )
        }
    if damage == "drop_index":
        assert "idx_outbox_pending" not in names
    elif damage == "drop_evidence_table":
        assert "receipt_evidence" not in names
    else:
        assert "forbidden" in names
