"""Backend-neutral real-store APCC authority conformance contract."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Barrier
from typing import Protocol

import pytest

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    CandidateLifecycle,
    FailureCode,
    RequestOutcome,
)
from constitutional_swarm.apcc.ports import (
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthorityStore,
    CommitContextRequest,
    CommitResult,
    OutboxRecoveryRequest,
    PersistedOutboxEvent,
    ProposeCommitRequest,
    ProposeCommitResult,
    RecoveryRequest,
    ReplayCommitRequest,
    RevocationRequest,
    RevocationScope,
    StageResultRequest,
    SupersessionCommitted,
    SupersessionConflicted,
    SupersessionDenied,
    SupersessionRequest,
)
from constitutional_swarm.apcc.verifier import (
    CausalClosureLimits,
    ScopedTrust,
    verify_current,
    verify_historical,
)


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """Exact canonical observation of all authority/control tables and pointers."""

    tables: Mapping[str, tuple[bytes, ...]]
    current_pointers: tuple[bytes, ...]


class FaultProbe(Protocol):
    """Private test fixture protocol; never part of a production open API."""

    def hit(self, point: str) -> None: ...


@dataclass(frozen=True, slots=True)
class AuthorityStoreHarness:
    """Only test fixtures supply bootstrap, faults, and persistence observation."""

    open_store: Callable[[Path, FaultProbe | None], AuthorityStore]
    reopen_store: Callable[[Path], AuthorityStore]
    make_request: Callable[..., AtomicCommitRequest]
    trust: ScopedTrust
    snapshot: Callable[[AuthorityStore], AuthoritySnapshot]
    stage_request: Callable[[AtomicCommitRequest], StageResultRequest]
    assemble_evidence_request: Callable[[AtomicCommitRequest], AssembleEvidenceRequest]
    propose_commit_request: Callable[[AtomicCommitRequest], ProposeCommitRequest]
    outbox_event: Callable[[AuthorityStore, str], PersistedOutboxEvent]
    assert_conflict_and_audit_delta: Callable[
        [AuthoritySnapshot, AuthoritySnapshot, str], None
    ]
    assert_denied_decision_delta: Callable[
        [AuthoritySnapshot, AuthoritySnapshot, str], None
    ]
    assert_missing_recovery_delta: Callable[
        [AuthoritySnapshot, AuthoritySnapshot], None
    ]
    assert_outbox_delivery_delta: Callable[[AuthoritySnapshot, AuthoritySnapshot], None]
    commit_signature_count: Callable[[], int] | None = None
    tamper_certificate_payload: Callable[[AuthorityStore, str], None] | None = None
    replace_predecessor_edges: (
        Callable[[AuthorityStore, str, tuple[str, ...]], None] | None
    ) = None
    set_clock_sequence: Callable[[AuthorityStore, tuple[int, ...]], None] | None = None
    set_invalid_commit_signature: Callable[[AuthorityStore, bool], None] | None = None


def _stage(
    store: AuthorityStore, harness: AuthorityStoreHarness, request: AtomicCommitRequest
) -> None:
    staged = store.stage_result(harness.stage_request(request))
    assert staged.candidate_state.workflow_id == request.subject.workflow_id
    assert staged.candidate_state.lifecycle is CandidateLifecycle.RESULT_STAGED

    assembled: AssembleEvidenceResult = store.assemble_evidence(
        harness.assemble_evidence_request(request)
    )
    assert assembled.candidate_state.lifecycle is CandidateLifecycle.EVIDENCE_ASSEMBLED

    proposed: ProposeCommitResult = store.propose_commit(
        harness.propose_commit_request(request)
    )
    assert proposed.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING


def assert_commit_tuple_is_exact(store: AuthorityStore, result: CommitResult) -> None:
    assert result.decision.outcome is RequestOutcome.COMMITTED
    assert (
        store.get_certificate(result.decision.commit_id)
        == result.certificate_envelope_bytes
    )
    assert result.certificate_payload_bytes
    assert result.certificate_digest


def assert_non_authoritative_tuple_is_exact(
    result: CommitResult,
    *,
    commit_id: str,
    outcome: RequestOutcome,
    reason: FailureCode,
) -> None:
    assert result.decision.commit_id == commit_id
    assert result.decision.outcome is outcome
    assert result.decision.reason is reason
    assert result.certificate_payload_bytes is None
    assert result.certificate_envelope_bytes is None
    assert result.certificate_digest is None
    assert result.audit_event_id


def _verify_store_status(
    harness: AuthorityStoreHarness,
    result: CommitResult,
    *,
    status: AuthorityStatus,
    request_nonce: str,
    expected: FailureCode | None,
    highest_sequence: str | None = None,
    highest_head: str | None = None,
    now_ms: str | None = None,
    maximum_staleness_ms: str = "5000",
) -> None:
    assert result.certificate_envelope_bytes is not None
    verdict = verify_current(
        result.certificate_envelope_bytes,
        trust=harness.trust,
        authority_status=status,
        request_nonce=request_nonce,
        now_ms=now_ms or status.this_update_ms,
        highest_trust_log_sequence=highest_sequence or status.trust_log_sequence,
        highest_trust_log_head=highest_head or status.trust_log_head,
        maximum_staleness_ms=maximum_staleness_ms,
    )
    if expected is None:
        assert verdict.ok
    else:
        assert verdict.code is expected


def _predecessor(
    request: AtomicCommitRequest, committed: CommitResult
) -> dict[str, str]:
    """Return the exact six-field reference required by the APCC wire contract."""
    assert committed.certificate_digest
    return {
        "workflow_id": request.subject.workflow_id,
        "node_id": request.subject.node_id,
        "committed_node_version": request.bindings.committed_node_version,
        "commit_id": request.commit_id,
        "certificate_digest": committed.certificate_digest,
        "output_digest": request.subject.output_digest,
    }


def assert_authority_store_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    """Run unchanged against SQLite and PostgreSQL authority stores."""
    store = harness.open_store(tmp_path / "authority.db", None)
    request = harness.make_request(commit_id="commit-1", nonce_byte=1)
    _stage(store, harness, request)
    committed = store.atomic_commit(request)
    assert_commit_tuple_is_exact(store, committed)
    committed_snapshot = harness.snapshot(store)

    replay = store.replay_commit(
        ReplayCommitRequest(request.commit_id, request.request_digest)
    )
    assert replay == committed
    assert harness.snapshot(store) == committed_snapshot
    assert store.atomic_commit(request) == committed  # response-loss exact replay
    assert harness.snapshot(store) == committed_snapshot

    equivocation = harness.make_request(
        commit_id=request.commit_id, nonce_byte=2, workflow_id="workflow-2"
    )
    conflicted = store.atomic_commit(equivocation)
    assert_non_authoritative_tuple_is_exact(
        conflicted,
        commit_id=request.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.COMMIT_ID_EQUIVOCATION,
    )
    harness.assert_conflict_and_audit_delta(
        committed_snapshot, harness.snapshot(store), request.commit_id
    )
    conflicted_snapshot = harness.snapshot(store)
    assert store.atomic_commit(equivocation) == conflicted
    assert (
        store.replay_commit(
            ReplayCommitRequest(equivocation.commit_id, equivocation.request_digest)
        )
        == conflicted
    )
    assert harness.snapshot(store) == conflicted_snapshot

    nonce_replay = harness.make_request(
        commit_id="commit-2", nonce_byte=1, node_id="child"
    )
    _stage(store, harness, nonce_replay)
    before_nonce_denial = harness.snapshot(store)
    denied = store.atomic_commit(nonce_replay)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=nonce_replay.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.NONCE_REPLAY,
    )
    denied_snapshot = harness.snapshot(store)
    harness.assert_denied_decision_delta(
        before_nonce_denial, denied_snapshot, nonce_replay.commit_id
    )
    assert (
        store.replay_commit(
            ReplayCommitRequest(nonce_replay.commit_id, nonce_replay.request_digest)
        )
        == denied
    )
    assert store.atomic_commit(nonce_replay) == denied
    assert harness.snapshot(store) == denied_snapshot

    # A persisted denial still reserves the store-global commit ID. A different
    # request must report equivocation before staging, nonce, or workflow checks.
    denied_equivocation = harness.make_request(
        commit_id=nonce_replay.commit_id,
        nonce_byte=1,
        workflow_id="workflow-3",
    )
    conflicted_denial = store.atomic_commit(denied_equivocation)
    assert_non_authoritative_tuple_is_exact(
        conflicted_denial,
        commit_id=nonce_replay.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.COMMIT_ID_EQUIVOCATION,
    )
    after_denied_equivocation = harness.snapshot(store)
    harness.assert_conflict_and_audit_delta(
        denied_snapshot, after_denied_equivocation, nonce_replay.commit_id
    )
    assert store.atomic_commit(denied_equivocation) == conflicted_denial
    assert (
        store.replay_commit(
            ReplayCommitRequest(
                denied_equivocation.commit_id, denied_equivocation.request_digest
            )
        )
        == conflicted_denial
    )
    assert harness.snapshot(store) == after_denied_equivocation

    # Same active attempt, different IDs/nonces, same expected version: one winner.
    race_store = harness.open_store(tmp_path / "race.db", None)
    race_one = harness.make_request(commit_id="race-1", nonce_byte=3)
    race_two = harness.make_request(
        commit_id="race-2", nonce_byte=4, attempt_id="race-attempt-2"
    )
    # Two distinct pending attempts contend for the same logical-node version;
    # each candidate authorizes only its own exact proposal identity.
    _stage(race_store, harness, race_one)
    _stage(race_store, harness, race_two)
    start = Barrier(3)

    def contend(request_item: AtomicCommitRequest) -> CommitResult:
        start.wait()
        return race_store.atomic_commit(request_item)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(contend, race_one), pool.submit(contend, race_two))
        start.wait()
        results = [future.result() for future in futures]
    assert (
        sum(item.decision.outcome is RequestOutcome.COMMITTED for item in results) == 1
    )
    loser_request, loser = next(
        (request_item, result_item)
        for request_item, result_item in zip((race_one, race_two), results, strict=True)
        if result_item.decision.outcome is not RequestOutcome.COMMITTED
    )
    assert_non_authoritative_tuple_is_exact(
        loser,
        commit_id=loser_request.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.NODE_VERSION_CONFLICT,
    )
    race_snapshot = harness.snapshot(race_store)
    assert (
        race_store.replay_commit(
            ReplayCommitRequest(loser_request.commit_id, loser_request.request_digest)
        )
        == loser
    )
    assert race_store.atomic_commit(loser_request) == loser
    assert harness.snapshot(race_store) == race_snapshot

    before_exact_recovery = harness.snapshot(store)
    assert (
        store.recover(RecoveryRequest(request.commit_id, request.request_digest))
        == committed
    )
    assert harness.snapshot(store) == before_exact_recovery
    before_missing = harness.snapshot(store)
    missing = store.recover(RecoveryRequest("missing", request.request_digest))
    after_missing = harness.snapshot(store)
    mismatch = store.recover(RecoveryRequest(request.commit_id, "different-digest"))
    after_mismatch = harness.snapshot(store)
    assert missing.decision.outcome is RequestOutcome.DENIED
    assert missing.decision.reason == FailureCode.AUTHORITY_FROM_RECOVERY_DENIED
    assert mismatch.decision.outcome is RequestOutcome.CONFLICTED
    assert mismatch.decision.reason == FailureCode.COMMIT_ID_EQUIVOCATION
    assert missing.certificate_envelope_bytes is None
    assert mismatch.certificate_envelope_bytes is None
    harness.assert_missing_recovery_delta(before_missing, after_missing)
    harness.assert_conflict_and_audit_delta(
        after_missing, after_mismatch, request.commit_id
    )
    assert (
        store.recover(RecoveryRequest(request.commit_id, "different-digest"))
        == mismatch
    )
    assert harness.snapshot(store) == after_mismatch
    assert before_missing.current_pointers == after_mismatch.current_pointers

    # A replacement is one atomic authority transition. The old certificate
    # remains historical, the replacement is current, and every exact replay is
    # immutable. Reusing the replacement commit ID wins over stale-pointer checks.
    committed_digest = committed.certificate_digest
    assert committed_digest is not None
    replacement = harness.make_request(
        commit_id="replacement-1",
        nonce_byte=5,
        expected_node_version="1",
        attempt_id="attempt-replacement",
    )
    _stage(store, harness, replacement)
    superseded = store.supersede(SupersessionRequest(committed_digest, replacement))
    assert isinstance(superseded, SupersessionCommitted)
    assert_commit_tuple_is_exact(store, superseded.commit_result)
    assert superseded.old_certificate_digest == committed_digest
    replacement_snapshot = harness.snapshot(store)
    assert (
        store.supersede(SupersessionRequest(committed_digest, replacement))
        == superseded
    )
    assert harness.snapshot(store) == replacement_snapshot

    stale_pointer = harness.make_request(
        commit_id="replacement-stale-pointer",
        nonce_byte=12,
        expected_node_version="2",
        attempt_id="stale-pointer-attempt",
    )
    _stage(store, harness, stale_pointer)
    denied_replacement = store.supersede(
        SupersessionRequest(committed_digest, stale_pointer)
    )
    assert isinstance(denied_replacement, SupersessionDenied)
    assert_non_authoritative_tuple_is_exact(
        denied_replacement.commit_result,
        commit_id=stale_pointer.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.PREDECESSOR_REPLACED,
    )
    denied_snapshot = harness.snapshot(store)
    assert (
        store.supersede(SupersessionRequest(committed_digest, stale_pointer))
        == denied_replacement
    )
    assert harness.snapshot(store) == denied_snapshot
    replacement_equivocation = harness.make_request(
        commit_id=replacement.commit_id,
        nonce_byte=6,
        expected_node_version="0",
        attempt_id="stale-conflicting-attempt",
    )
    replacement_conflict = store.supersede(
        SupersessionRequest(committed_digest, replacement_equivocation)
    )
    assert isinstance(replacement_conflict, SupersessionConflicted)
    assert_non_authoritative_tuple_is_exact(
        replacement_conflict.commit_result,
        commit_id=replacement.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.COMMIT_ID_EQUIVOCATION,
    )
    assert replacement_conflict.old_certificate_digest == committed.certificate_digest
    replacement_conflict_snapshot = harness.snapshot(store)
    assert (
        store.supersede(
            SupersessionRequest(committed.certificate_digest, replacement_equivocation)
        )
        == replacement_conflict
    )
    assert harness.snapshot(store) == replacement_conflict_snapshot

    # Causal closure and propagation are backend contracts, not SQLite-only
    # behavior: direct root revocation reaches a grandchild across reopen-safe
    # persisted predecessor edges.
    chain_path = tmp_path / "causal-chain.db"
    chain_store = harness.open_store(chain_path, None)
    root_request = harness.make_request(
        commit_id="causal-root", nonce_byte=7, node_id="root"
    )
    _stage(chain_store, harness, root_request)
    root = chain_store.atomic_commit(root_request)
    root_digest = root.certificate_digest
    assert root_digest is not None
    middle_request = harness.make_request(
        commit_id="causal-middle",
        nonce_byte=8,
        node_id="middle",
        predecessors=[_predecessor(root_request, root)],
    )
    _stage(chain_store, harness, middle_request)
    middle = chain_store.atomic_commit(middle_request)
    leaf_request = harness.make_request(
        commit_id="causal-leaf",
        nonce_byte=9,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _stage(chain_store, harness, leaf_request)
    leaf = chain_store.atomic_commit(leaf_request)
    assert leaf.certificate_digest
    current = chain_store.current_status(
        leaf.certificate_digest, "AAAAAAAAAAAAAAAAAAAAAA"
    )
    assert current.status.value == "current"
    _verify_store_status(
        harness,
        leaf,
        status=current,
        request_nonce="AAAAAAAAAAAAAAAAAAAAAA",
        expected=None,
    )
    chain_store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            root_request.subject.workflow_id,
            root_digest,
            "1",
            "backend-neutral transitive propagation",
        )
    )
    chain_store = harness.reopen_store(chain_path)
    propagated = chain_store.current_status(
        leaf.certificate_digest, "AQEBAQEBAQEBAQEBAQEBAQ"
    )
    assert propagated.status.value == "revoked"
    assert int(propagated.trust_log_sequence) > int(current.trust_log_sequence)
    _verify_store_status(
        harness,
        leaf,
        status=current,
        request_nonce="AAAAAAAAAAAAAAAAAAAAAA",
        expected=FailureCode.AUTHORITY_STATUS_ROLLBACK,
        highest_sequence=propagated.trust_log_sequence,
        highest_head=propagated.trust_log_head,
    )
    _verify_store_status(
        harness,
        leaf,
        status=propagated,
        request_nonce="AQEBAQEBAQEBAQEBAQEBAQ",
        expected=FailureCode.AUTHORITY_STATUS_REVOKED,
    )

    before_delivery = harness.snapshot(store)
    outbox = store.recover_outbox(OutboxRecoveryRequest(max_items="100"))
    assert int(outbox.delivered_count) >= 0
    after_delivery = harness.snapshot(store)
    harness.assert_outbox_delivery_delta(before_delivery, after_delivery)
    assert (
        store.recover_outbox(OutboxRecoveryRequest(max_items="100")).delivered_count
        == "0"
    )
    assert harness.snapshot(store) == after_delivery


def assert_authority_store_extended_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    """Portable lifecycle, revocation, status, and causality conformance slice."""
    lifecycle_path = tmp_path / "lifecycle"
    lifecycle = harness.open_store(lifecycle_path, None)
    request = harness.make_request(commit_id="lifecycle-1", nonce_byte=31)
    with pytest.raises(ValueError):
        lifecycle.assemble_evidence(harness.assemble_evidence_request(request))
    with pytest.raises(ValueError):
        lifecycle.propose_commit(harness.propose_commit_request(request))
    staged = lifecycle.stage_result(harness.stage_request(request))
    assert staged.candidate_state.lifecycle is CandidateLifecycle.RESULT_STAGED
    lifecycle = harness.reopen_store(lifecycle_path)
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    assert (
        lifecycle.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.RESULT_STAGED
    )
    assert (
        lifecycle.assemble_evidence(
            harness.assemble_evidence_request(request)
        ).candidate_state.lifecycle
        is CandidateLifecycle.EVIDENCE_ASSEMBLED
    )
    lifecycle = harness.reopen_store(lifecycle_path)
    assert (
        lifecycle.propose_commit(
            harness.propose_commit_request(request)
        ).candidate_state.lifecycle
        is CandidateLifecycle.COMMIT_PENDING
    )
    lifecycle = harness.reopen_store(lifecycle_path)
    assert (
        lifecycle.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.COMMIT_PENDING
    )

    quarantine_path = tmp_path / "quarantine"
    quarantine = harness.open_store(quarantine_path, None)
    quarantined = harness.make_request(commit_id="quarantine-1", nonce_byte=32)
    stage_request = harness.stage_request(quarantined)
    quarantine.stage_result(stage_request)
    with pytest.raises(ValueError):
        quarantine.stage_result(
            replace(stage_request, result_bytes=b"different-output")
        )
    quarantine = harness.reopen_store(quarantine_path)
    quarantined_context = quarantine.read_commit_context(
        CommitContextRequest(
            quarantined.subject.workflow_id,
            quarantined.subject.node_id,
            quarantined.subject.attempt_id,
            quarantined.subject.agent_id,
        )
    )
    assert (
        quarantined_context.candidate_state.lifecycle is CandidateLifecycle.QUARANTINED
    )
    assert quarantined_context.logical_node_state.current_certificate_digest is None
    assert quarantine.get_certificate(quarantined.commit_id) is None
    with pytest.raises(ValueError):
        quarantine.assemble_evidence(harness.assemble_evidence_request(quarantined))

    actor_path = tmp_path / "actor-scope"
    actor_store = harness.open_store(actor_path, None)
    first_request = harness.make_request(commit_id="actor-w1", nonce_byte=33)
    second_request = harness.make_request(
        commit_id="actor-w2", nonce_byte=34, workflow_id="workflow-2"
    )
    _stage(actor_store, harness, first_request)
    _stage(actor_store, harness, second_request)
    first = actor_store.atomic_commit(first_request)
    second = actor_store.atomic_commit(second_request)
    assert first.certificate_digest and second.certificate_digest
    actor_store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            first_request.subject.workflow_id,
            first_request.subject.agent_id,
            str(int(first_request.context.agent_revocation_generation) + 1),
            "workflow-scoped actor revocation",
        )
    )
    actor_store = harness.reopen_store(actor_path)
    first_status = actor_store.current_status(
        first.certificate_digest, "AwMDAwMDAwMDAwMDAwMDAw"
    )
    second_status = actor_store.current_status(
        second.certificate_digest, "BAQEBAQEBAQEBAQEBAQEBA"
    )
    _verify_store_status(
        harness,
        first,
        status=first_status,
        request_nonce="AwMDAwMDAwMDAwMDAwMDAw",
        expected=FailureCode.AUTHORITY_STATUS_REVOKED,
    )
    _verify_store_status(
        harness,
        second,
        status=second_status,
        request_nonce="BAQEBAQEBAQEBAQEBAQEBA",
        expected=None,
    )
    assert int(second_status.next_update_ms) > int(second_status.this_update_ms) + 2
    _verify_store_status(
        harness,
        second,
        status=second_status,
        request_nonce="BAQEBAQEBAQEBAQEBAQEBA",
        expected=FailureCode.AUTHORITY_STATUS_EXPIRED,
        now_ms=str(int(second_status.this_update_ms) + 2),
        maximum_staleness_ms="1",
    )

    predecessor_path = tmp_path / "supersession-causality"
    predecessor_store = harness.open_store(predecessor_path, None)
    root_request = harness.make_request(
        commit_id="root-1", nonce_byte=35, node_id="root"
    )
    _stage(predecessor_store, harness, root_request)
    root = predecessor_store.atomic_commit(root_request)
    root_digest = root.certificate_digest
    assert root_digest is not None
    root_ref = _predecessor(root_request, root)
    child_request = harness.make_request(
        commit_id="child-1", nonce_byte=36, node_id="child", predecessors=[root_ref]
    )
    _stage(predecessor_store, harness, child_request)
    child = predecessor_store.atomic_commit(child_request)
    pending_request = harness.make_request(
        commit_id="pending-1", nonce_byte=37, node_id="leaf", predecessors=[root_ref]
    )
    _stage(predecessor_store, harness, pending_request)
    replacement = harness.make_request(
        commit_id="root-2",
        nonce_byte=38,
        node_id="root",
        expected_node_version="1",
        attempt_id="root-replacement",
    )
    _stage(predecessor_store, harness, replacement)
    replacement_result = predecessor_store.supersede(
        SupersessionRequest(root_digest, replacement)
    )
    assert isinstance(replacement_result, SupersessionCommitted)
    assert replacement_result.commit_result.decision.outcome is RequestOutcome.COMMITTED
    terminal = harness.snapshot(predecessor_store)
    assert (
        predecessor_store.supersede(SupersessionRequest(root_digest, replacement))
        == replacement_result
    )
    assert harness.snapshot(predecessor_store) == terminal
    assert child.certificate_digest
    child_status = predecessor_store.current_status(
        child.certificate_digest, "BgYGBgYGBgYGBgYGBgYGBg"
    )
    _verify_store_status(
        harness,
        child,
        status=child_status,
        request_nonce="BgYGBgYGBgYGBgYGBgYGBg",
        expected=None,
    )
    stale = predecessor_store.atomic_commit(pending_request)
    assert_non_authoritative_tuple_is_exact(
        stale,
        commit_id=pending_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.PREDECESSOR_REPLACED,
    )
    stale_snapshot = harness.snapshot(predecessor_store)
    assert predecessor_store.atomic_commit(pending_request) == stale
    assert (
        predecessor_store.replay_commit(
            ReplayCommitRequest(
                pending_request.commit_id, pending_request.request_digest
            )
        )
        == stale
    )
    assert harness.snapshot(predecessor_store) == stale_snapshot

    attempt_store = harness.open_store(tmp_path / "attempt-precedence", None)
    malformed_base = harness.make_request(commit_id="attempt-mismatch", nonce_byte=39)
    mismatched = replace(
        malformed_base,
        subject=replace(malformed_base.subject, attempt_id="subject-only-mismatch"),
    )
    coherent = harness.make_request(
        commit_id="inactive-attempt", nonce_byte=40, attempt_id="inactive-attempt"
    )
    malformed = attempt_store.atomic_commit(mismatched)
    assert_non_authoritative_tuple_is_exact(
        malformed,
        commit_id=mismatched.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.ATTEMPT_MISMATCH,
    )
    malformed_snapshot = harness.snapshot(attempt_store)
    assert attempt_store.atomic_commit(mismatched) == malformed
    assert harness.snapshot(attempt_store) == malformed_snapshot
    inactive = attempt_store.atomic_commit(coherent)
    assert_non_authoritative_tuple_is_exact(
        inactive,
        commit_id=coherent.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.CROSS_ATTEMPT_REPLAY,
    )
    inactive_snapshot = harness.snapshot(attempt_store)
    assert attempt_store.atomic_commit(coherent) == inactive
    assert harness.snapshot(attempt_store) == inactive_snapshot


def assert_staged_result_digest_binding_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "staged-output-digest", None)
    request = harness.make_request(commit_id="staged-output-digest", nonce_byte=81)
    wrong = replace(harness.stage_request(request), result_bytes=b"wrong-output")
    try:
        store.stage_result(wrong)
    except ValueError:
        pass
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    context = store.read_commit_context(context_request)
    assert context.candidate_state.lifecycle in {
        CandidateLifecycle.EXECUTING,
        CandidateLifecycle.QUARANTINED,
    }
    denied = store.atomic_commit(request)
    assert denied.decision.outcome is RequestOutcome.DENIED
    assert denied.decision.reason in {
        FailureCode.RESULT_NOT_STAGED,
        FailureCode.QUARANTINED,
    }
    assert denied.certificate_digest is None
    assert store.get_certificate(request.commit_id) is None
    assert (
        store.read_commit_context(
            context_request
        ).logical_node_state.current_certificate_digest
        is None
    )


def assert_stage_after_commit_pending_cannot_regress_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "stage-after-pending", None)
    request = harness.make_request(commit_id="stage-after-pending", nonce_byte=98)
    _stage(store, harness, request)
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    before = harness.snapshot(store)
    replacement_bytes = b"replacement-output"
    replacement = StageResultRequest(
        replace(
            request.subject,
            output_digest=sha256_digest(replacement_bytes),
        ),
        request.bindings.expected_node_version,
        replacement_bytes,
    )
    with pytest.raises(ValueError, match=FailureCode.ILLEGAL_NODE_STATE.value):
        store.stage_result(replacement)
    assert harness.snapshot(store) == before
    assert (
        store.read_commit_context(context_request).candidate_state.lifecycle
        is CandidateLifecycle.COMMIT_PENDING
    )
    committed = store.atomic_commit(request)
    assert committed.decision.outcome is RequestOutcome.COMMITTED


def assert_pending_proposal_identity_is_exact_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "pending-proposal-identity", None)
    pending = harness.make_request(commit_id="pending-a", nonce_byte=131)
    substituted = harness.make_request(commit_id="pending-b", nonce_byte=132)
    _stage(store, harness, pending)
    before = harness.snapshot(store)

    denied = store.atomic_commit(substituted)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=substituted.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.STAGED_RESULT_CONFLICT,
    )
    assert store.get_certificate(substituted.commit_id) is None
    context = store.read_commit_context(
        CommitContextRequest(
            pending.subject.workflow_id,
            pending.subject.node_id,
            pending.subject.attempt_id,
            pending.subject.agent_id,
        )
    )
    assert context.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING
    assert before.current_pointers == harness.snapshot(store).current_pointers
    assert store.atomic_commit(substituted) == denied
    committed = store.atomic_commit(pending)
    assert committed.decision.outcome is RequestOutcome.COMMITTED


def assert_commit_signer_is_authority_only_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    count = harness.commit_signature_count
    assert count is not None
    store = harness.open_store(tmp_path / "commit-signer-boundary", None)
    request = harness.make_request(commit_id="signer-success", nonce_byte=133)
    baseline = count()
    store.stage_result(harness.stage_request(request))
    store.assemble_evidence(harness.assemble_evidence_request(request))
    store.propose_commit(harness.propose_commit_request(request))
    assert count() == baseline
    committed = store.atomic_commit(request)
    assert committed.decision.outcome is RequestOutcome.COMMITTED
    assert count() == baseline + 1

    invalid = harness.make_request(
        commit_id="signer-invalid", nonce_byte=134, node_id="child"
    )
    invalid = replace(
        invalid,
        signatures=replace(
            invalid.signatures,
            producer=replace(
                invalid.signatures.producer,
                signature_b64u="A" * 86,
            ),
        ),
    )
    before_invalid = count()
    invalid_result = store.atomic_commit(invalid)
    assert invalid_result.decision.reason is FailureCode.INVALID_PRODUCER_SIGNATURE
    assert invalid_result.certificate_digest is None
    assert count() == before_invalid

    unstaged = harness.make_request(
        commit_id="signer-denied", nonce_byte=135, node_id="leaf"
    )
    before_denial = count()
    denied = store.atomic_commit(unstaged)
    assert denied.decision.reason is FailureCode.RESULT_NOT_STAGED
    assert denied.certificate_digest is None
    assert count() == before_denial


def assert_reachable_ancestor_integrity_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    tamper = harness.tamper_certificate_payload
    assert tamper is not None
    store = harness.open_store(tmp_path / "reachable-ancestor-integrity", None)
    root_request = harness.make_request(
        commit_id="integrity-root", nonce_byte=136, node_id="root"
    )
    _stage(store, harness, root_request)
    root = store.atomic_commit(root_request)
    middle_request = harness.make_request(
        commit_id="integrity-middle",
        nonce_byte=137,
        node_id="middle",
        predecessors=[_predecessor(root_request, root)],
    )
    _stage(store, harness, middle_request)
    middle = store.atomic_commit(middle_request)
    assert root.certificate_digest is not None
    tamper(store, root.certificate_digest)

    leaf_request = harness.make_request(
        commit_id="integrity-leaf",
        nonce_byte=138,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _stage(store, harness, leaf_request)
    denied = store.atomic_commit(leaf_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=leaf_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )
    assert store.get_certificate(leaf_request.commit_id) is None


def assert_reachable_adjacency_matches_signed_bindings_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    replace_edges = harness.replace_predecessor_edges
    assert replace_edges is not None
    store = harness.open_store(tmp_path / "reachable-adjacency-binding", None)
    first_request = harness.make_request(
        commit_id="adjacency-first", nonce_byte=139, node_id="root"
    )
    second_request = harness.make_request(
        commit_id="adjacency-second", nonce_byte=140, node_id="child"
    )
    _stage(store, harness, first_request)
    first = store.atomic_commit(first_request)
    _stage(store, harness, second_request)
    second = store.atomic_commit(second_request)
    middle_request = harness.make_request(
        commit_id="adjacency-middle",
        nonce_byte=141,
        node_id="middle",
        predecessors=[_predecessor(first_request, first)],
    )
    _stage(store, harness, middle_request)
    middle = store.atomic_commit(middle_request)
    assert second.certificate_digest is not None
    replace_edges(store, middle_request.commit_id, (second.certificate_digest,))

    leaf_request = harness.make_request(
        commit_id="adjacency-leaf",
        nonce_byte=142,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _stage(store, harness, leaf_request)
    before = harness.snapshot(store)
    denied = store.atomic_commit(leaf_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=leaf_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )
    after = harness.snapshot(store)
    harness.assert_denied_decision_delta(before, after, leaf_request.commit_id)
    assert store.get_certificate(leaf_request.commit_id) is None
    assert store.atomic_commit(leaf_request) == denied
    assert harness.snapshot(store) == after


def assert_reachable_adjacency_cycle_fails_closed_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    replace_edges = harness.replace_predecessor_edges
    assert replace_edges is not None
    store = harness.open_store(tmp_path / "reachable-adjacency-cycle", None)
    root_request = harness.make_request(
        commit_id="cycle-root", nonce_byte=143, node_id="root"
    )
    _stage(store, harness, root_request)
    root = store.atomic_commit(root_request)
    middle_request = harness.make_request(
        commit_id="cycle-middle",
        nonce_byte=144,
        node_id="middle",
        predecessors=[_predecessor(root_request, root)],
    )
    _stage(store, harness, middle_request)
    middle = store.atomic_commit(middle_request)
    assert middle.certificate_digest is not None
    replace_edges(store, root_request.commit_id, (middle.certificate_digest,))

    leaf_request = harness.make_request(
        commit_id="cycle-leaf",
        nonce_byte=145,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _stage(store, harness, leaf_request)
    denied = store.atomic_commit(leaf_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=leaf_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )
    assert store.get_certificate(leaf_request.commit_id) is None


def assert_default_causal_limits_are_enforced_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    assert CausalClosureLimits() == CausalClosureLimits(
        max_depth=64,
        max_certificates=4096,
        max_total_bytes=64 * 1024 * 1024,
    )
    store = harness.open_store(tmp_path / "default-causal-depth", None)
    predecessor: dict[str, str] | None = None
    for index in range(65):
        request = harness.make_request(
            commit_id=f"depth-{index}",
            nonce_byte=146 + index,
            node_id=f"depth-node-{index}",
            attempt_id=f"depth-attempt-{index}",
            expected_node_version="0",
            predecessors=[] if predecessor is None else [predecessor],
        )
        _stage(store, harness, request)
        committed = store.atomic_commit(request)
        assert committed.decision.outcome is RequestOutcome.COMMITTED
        predecessor = _predecessor(request, committed)
    assert predecessor is not None
    boundary = harness.make_request(
        commit_id="depth-boundary",
        nonce_byte=211,
        node_id="depth-node-65",
        attempt_id="depth-boundary",
        expected_node_version="0",
        predecessors=[predecessor],
    )
    _stage(store, harness, boundary)
    denied = store.atomic_commit(boundary)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=boundary.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.DEPTH_LIMIT_EXCEEDED,
    )
    assert store.get_certificate(boundary.commit_id) is None


def assert_final_certificate_is_the_validated_certificate_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    set_clock = harness.set_clock_sequence
    assert set_clock is not None
    store = harness.open_store(tmp_path / "final-certificate-clock", None)
    request = harness.make_request(commit_id="final-clock", nonce_byte=213)
    _stage(store, harness, request)
    set_clock(store, (1_760_000_001_000, 1_760_000_006_000))
    committed = store.atomic_commit(request)
    assert committed.decision.outcome is RequestOutcome.COMMITTED
    assert committed.certificate_envelope_bytes is not None
    assert verify_historical(
        committed.certificate_envelope_bytes, trust=harness.trust
    ).ok


def assert_invalid_final_commit_signature_is_atomic_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    set_invalid = harness.set_invalid_commit_signature
    count = harness.commit_signature_count
    assert set_invalid is not None
    assert count is not None
    store = harness.open_store(tmp_path / "invalid-final-signature", None)
    request = harness.make_request(commit_id="invalid-final-signature", nonce_byte=214)
    _stage(store, harness, request)
    before = harness.snapshot(store)
    baseline = count()
    set_invalid(store, True)
    with pytest.raises(ValueError, match=FailureCode.INVALID_COMMIT_SEAL.value):
        store.atomic_commit(request)
    assert count() == baseline + 1
    assert harness.snapshot(store) == before
    assert store.get_certificate(request.commit_id) is None


def assert_root_revocation_generation_is_current_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, scope: RevocationScope
) -> None:
    assert scope in {RevocationScope.ACTOR, RevocationScope.WORKFLOW}
    store = harness.open_store(tmp_path / f"root-generation-{scope.value}", None)
    request = harness.make_request(
        commit_id=f"root-generation-{scope.value}", nonce_byte=215
    )
    target = (
        request.subject.agent_id
        if scope is RevocationScope.ACTOR
        else request.subject.workflow_id
    )
    claimed_generation = int(
        request.context.agent_revocation_generation
        if scope is RevocationScope.ACTOR
        else request.context.workflow_revocation_generation
    )
    for generation in range(1, claimed_generation + 2):
        store.revoke(
            RevocationRequest(
                scope,
                request.subject.workflow_id,
                target,
                str(generation),
                "advance root governance generation",
            )
        )
    _stage(store, harness, request)
    before = harness.snapshot(store)
    denied = store.atomic_commit(request)
    expected = (
        FailureCode.ACTOR_REVOKED
        if scope is RevocationScope.ACTOR
        else FailureCode.WORKFLOW_REVOKED
    )
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=expected,
    )
    after = harness.snapshot(store)
    harness.assert_denied_decision_delta(before, after, request.commit_id)
    assert len(after.tables["nonce_ledger"]) == len(before.tables["nonce_ledger"]) + 1
    assert store.get_certificate(request.commit_id) is None
    assert before.current_pointers == after.current_pointers
    assert store.atomic_commit(request) == denied
    assert harness.snapshot(store) == after


def assert_equal_revocation_generation_is_not_retroactive_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, scope: RevocationScope
) -> None:
    assert scope in {RevocationScope.ACTOR, RevocationScope.WORKFLOW}
    store = harness.open_store(tmp_path / f"equal-generation-{scope.value}", None)
    root_request = harness.make_request(
        commit_id=f"equal-generation-root-{scope.value}",
        nonce_byte=224,
        node_id="root",
        attempt_id=f"equal-generation-root-{scope.value}",
    )
    claimed_generation = int(
        root_request.context.agent_revocation_generation
        if scope is RevocationScope.ACTOR
        else root_request.context.workflow_revocation_generation
    )
    target = (
        root_request.subject.agent_id
        if scope is RevocationScope.ACTOR
        else root_request.subject.workflow_id
    )
    for generation in range(1, claimed_generation + 1):
        store.revoke(
            RevocationRequest(
                scope,
                root_request.subject.workflow_id,
                target,
                str(generation),
                "advance to the certificate issuance generation",
            )
        )
    _stage(store, harness, root_request)
    root = store.atomic_commit(root_request)
    assert_commit_tuple_is_exact(store, root)
    assert root.certificate_digest is not None
    equal_status = store.current_status(root.certificate_digest, root_request.nonce)
    assert equal_status.status.value == "current"

    equal_child_request = harness.make_request(
        commit_id=f"equal-generation-child-{scope.value}",
        nonce_byte=225,
        node_id="child",
        attempt_id=f"equal-generation-child-{scope.value}",
        predecessors=[_predecessor(root_request, root)],
    )
    _stage(store, harness, equal_child_request)
    equal_child = store.atomic_commit(equal_child_request)
    assert_commit_tuple_is_exact(store, equal_child)

    store.revoke(
        RevocationRequest(
            scope,
            root_request.subject.workflow_id,
            target,
            str(claimed_generation + 1),
            "advance beyond the certificate issuance generation",
        )
    )
    stale_status = store.current_status(root.certificate_digest, root_request.nonce)
    assert stale_status.status.value == "revoked"
    current_generation = str(claimed_generation + 1)
    stale_child_request = harness.make_request(
        commit_id=f"stale-ancestor-child-{scope.value}",
        nonce_byte=226,
        node_id="middle",
        attempt_id=f"stale-ancestor-child-{scope.value}",
        predecessors=[_predecessor(root_request, root)],
        **(
            {"agent_revocation_generation": current_generation}
            if scope is RevocationScope.ACTOR
            else {"workflow_revocation_generation": current_generation}
        ),
    )
    _stage(store, harness, stale_child_request)
    before = harness.snapshot(store)
    denied = store.atomic_commit(stale_child_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=stale_child_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )
    after = harness.snapshot(store)
    harness.assert_denied_decision_delta(before, after, stale_child_request.commit_id)
    assert store.get_certificate(stale_child_request.commit_id) is None


def assert_request_digest_cache_is_not_authority_bearing_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "request-digest-cache", None)
    request = harness.make_request(commit_id="request-digest-cache", nonce_byte=227)
    _stage(store, harness, request)
    changed_cache = replace(request, request_digest="A" * 43)
    committed = store.atomic_commit(changed_cache)
    assert_commit_tuple_is_exact(store, committed)
    committed_snapshot = harness.snapshot(store)
    assert store.atomic_commit(request) == committed
    assert harness.snapshot(store) == committed_snapshot

    changed_subject = replace(
        request,
        subject=replace(request.subject, actor_authority="mutated-authority"),
    )
    conflict = store.atomic_commit(changed_subject)
    assert_non_authoritative_tuple_is_exact(
        conflict,
        commit_id=request.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.COMMIT_ID_EQUIVOCATION,
    )
    harness.assert_conflict_and_audit_delta(
        committed_snapshot, harness.snapshot(store), request.commit_id
    )


def assert_ordinary_commit_requires_empty_pointer_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "ordinary-empty-pointer", None)
    original_request = harness.make_request(
        commit_id="ordinary-original", nonce_byte=216
    )
    _stage(store, harness, original_request)
    original = store.atomic_commit(original_request)
    assert_commit_tuple_is_exact(store, original)
    replacement_request = harness.make_request(
        commit_id="ordinary-second",
        nonce_byte=217,
        expected_node_version="1",
        attempt_id="ordinary-second-attempt",
    )
    _stage(store, harness, replacement_request)
    before = harness.snapshot(store)
    denied = store.atomic_commit(replacement_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=replacement_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.ILLEGAL_NODE_STATE,
    )
    after = harness.snapshot(store)
    harness.assert_denied_decision_delta(before, after, replacement_request.commit_id)
    assert len(after.tables["nonce_ledger"]) == len(before.tables["nonce_ledger"]) + 1
    assert store.get_certificate(original_request.commit_id) == (
        original.certificate_envelope_bytes
    )
    assert store.get_certificate(replacement_request.commit_id) is None
    assert before.current_pointers == after.current_pointers
    assert store.atomic_commit(replacement_request) == denied
    assert harness.snapshot(store) == after


def assert_revoked_current_certificate_cannot_be_superseded_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "revoked-supersession", None)
    original_request = harness.make_request(
        commit_id="revoked-supersession-original", nonce_byte=218, node_id="root"
    )
    _stage(store, harness, original_request)
    original = store.atomic_commit(original_request)
    child_request = harness.make_request(
        commit_id="revoked-supersession-child",
        nonce_byte=219,
        node_id="child",
        predecessors=[_predecessor(original_request, original)],
    )
    _stage(store, harness, child_request)
    child = store.atomic_commit(child_request)
    assert original.certificate_digest is not None
    assert child.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            original_request.subject.workflow_id,
            original.certificate_digest,
            "1",
            "terminal root revocation",
        )
    )
    replacement = harness.make_request(
        commit_id="revoked-supersession-replacement",
        nonce_byte=220,
        node_id="root",
        expected_node_version="1",
        attempt_id="revoked-supersession-replacement",
    )
    _stage(store, harness, replacement)
    before = harness.snapshot(store)
    denied = store.supersede(
        SupersessionRequest(original.certificate_digest, replacement)
    )
    assert isinstance(denied, SupersessionDenied)
    assert_non_authoritative_tuple_is_exact(
        denied.commit_result,
        commit_id=replacement.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.PREDECESSOR_REPLACED,
    )
    after = harness.snapshot(store)
    harness.assert_denied_decision_delta(before, after, replacement.commit_id)
    assert len(after.tables["nonce_ledger"]) == len(before.tables["nonce_ledger"]) + 1
    root_status = store.current_status(
        original.certificate_digest, original_request.nonce
    )
    child_status = store.current_status(child.certificate_digest, child_request.nonce)
    assert root_status.status.value == "revoked"
    assert child_status.status.value == "revoked"
    assert before.current_pointers == after.current_pointers
    assert (
        store.supersede(SupersessionRequest(original.certificate_digest, replacement))
        == denied
    )
    assert harness.snapshot(store) == after


def assert_complete_request_identity_is_guarded_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    original = harness.make_request(
        commit_id="complete-request-identity", nonce_byte=221
    )

    def mutate_policy(request: AtomicCommitRequest) -> AtomicCommitRequest:
        statement = dict(request.evidence.policy_statement)
        statement["policy_version"] = "mutated-policy-version"
        return replace(
            request,
            evidence=replace(request.evidence, policy_statement=statement),
        )

    def mutate_authority(request: AtomicCommitRequest) -> AtomicCommitRequest:
        statement = dict(request.evidence.authority_statement)
        statement["authority_epoch"] = "mutated-authority-epoch"
        return replace(
            request,
            evidence=replace(request.evidence, authority_statement=statement),
        )

    mutations: tuple[
        tuple[str, Callable[[AtomicCommitRequest], AtomicCommitRequest]], ...
    ] = (
        ("policy", mutate_policy),
        ("authority", mutate_authority),
        (
            "signature",
            lambda request: replace(
                request,
                signatures=replace(
                    request.signatures,
                    policy_authority=replace(
                        request.signatures.policy_authority,
                        signature_b64u="A" * 86,
                    ),
                ),
            ),
        ),
        (
            "subject",
            lambda request: replace(
                request, subject=replace(request.subject, actor_authority="mutated")
            ),
        ),
        (
            "context",
            lambda request: replace(
                request, context=replace(request.context, policy_epoch="mutated")
            ),
        ),
        (
            "bindings",
            lambda request: replace(
                request,
                bindings=replace(
                    request.bindings,
                    expected_node_version="9",
                    committed_node_version="10",
                ),
            ),
        ),
        ("nonce", lambda request: replace(request, nonce="C" * 21 + "A")),
    )
    for label, mutate in mutations:
        store = harness.open_store(tmp_path / f"request-identity-{label}", None)
        _stage(store, harness, original)
        committed = store.atomic_commit(original)
        committed_snapshot = harness.snapshot(store)
        cached_digest_only = replace(original, request_digest="D" * 43)
        assert store.atomic_commit(cached_digest_only) == committed
        assert harness.snapshot(store) == committed_snapshot
        conflicting = mutate(original)
        conflict = store.atomic_commit(conflicting)
        assert_non_authoritative_tuple_is_exact(
            conflict,
            commit_id=original.commit_id,
            outcome=RequestOutcome.CONFLICTED,
            reason=FailureCode.COMMIT_ID_EQUIVOCATION,
        )
        after = harness.snapshot(store)
        harness.assert_conflict_and_audit_delta(
            committed_snapshot, after, original.commit_id
        )
        assert store.atomic_commit(conflicting) == conflict
        assert harness.snapshot(store) == after


def assert_negative_decisions_reserve_nonce_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    for label, reason in (
        ("static", FailureCode.INVALID_PRODUCER_SIGNATURE),
        ("active", FailureCode.RESULT_NOT_STAGED),
    ):
        store = harness.open_store(tmp_path / f"negative-nonce-{label}", None)
        denied_request = harness.make_request(
            commit_id=f"negative-nonce-{label}", nonce_byte=222
        )
        if label == "static":
            denied_request = replace(
                denied_request,
                signatures=replace(
                    denied_request.signatures,
                    producer=replace(
                        denied_request.signatures.producer, signature_b64u="A" * 86
                    ),
                ),
            )
        before = harness.snapshot(store)
        denied = store.atomic_commit(denied_request)
        assert_non_authoritative_tuple_is_exact(
            denied,
            commit_id=denied_request.commit_id,
            outcome=RequestOutcome.DENIED,
            reason=reason,
        )
        denied_snapshot = harness.snapshot(store)
        assert (
            len(denied_snapshot.tables["nonce_ledger"])
            == len(before.tables["nonce_ledger"]) + 1
        )
        assert store.atomic_commit(denied_request) == denied
        assert harness.snapshot(store) == denied_snapshot

        reused = harness.make_request(
            commit_id=f"negative-nonce-{label}-reused",
            nonce_byte=222,
            node_id="child",
        )
        replay_denied = store.atomic_commit(reused)
        assert_non_authoritative_tuple_is_exact(
            replay_denied,
            commit_id=reused.commit_id,
            outcome=RequestOutcome.DENIED,
            reason=FailureCode.NONCE_REPLAY,
        )
        replay_snapshot = harness.snapshot(store)
        assert store.atomic_commit(reused) == replay_denied
        assert harness.snapshot(store) == replay_snapshot


def assert_predecessor_reference_field_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, field_name: str
) -> None:
    assert field_name in {"committed_node_version", "output_digest"}
    store = harness.open_store(tmp_path / f"predecessor-{field_name}", None)
    parent_request = harness.make_request(
        commit_id=f"predecessor-{field_name}-parent", nonce_byte=82, node_id="root"
    )
    _stage(store, harness, parent_request)
    parent = store.atomic_commit(parent_request)
    reference = _predecessor(parent_request, parent)
    assert set(reference) == {
        "workflow_id",
        "node_id",
        "committed_node_version",
        "commit_id",
        "certificate_digest",
        "output_digest",
    }
    reference[field_name] = (
        "999" if field_name == "committed_node_version" else "A" * 43
    )
    child_request = harness.make_request(
        commit_id=f"predecessor-{field_name}-child",
        nonce_byte=83,
        node_id="child",
        predecessors=[reference],
    )
    _stage(store, harness, child_request)
    denied = store.atomic_commit(child_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=child_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )


def assert_transitive_ancestor_revocation_admission_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "transitive-revocation-admission", None)
    root_request = harness.make_request(
        commit_id="revoked-root", nonce_byte=84, node_id="root"
    )
    _stage(store, harness, root_request)
    root = store.atomic_commit(root_request)
    middle_request = harness.make_request(
        commit_id="revoked-middle",
        nonce_byte=85,
        node_id="middle",
        predecessors=[_predecessor(root_request, root)],
    )
    _stage(store, harness, middle_request)
    middle = store.atomic_commit(middle_request)
    assert root.certificate_digest is not None
    store.revoke(
        RevocationRequest(
            RevocationScope.CERTIFICATE,
            root_request.subject.workflow_id,
            root.certificate_digest,
            "1",
            "ancestor revoked before descendant admission",
        )
    )
    leaf_request = harness.make_request(
        commit_id="revoked-leaf",
        nonce_byte=86,
        node_id="leaf",
        predecessors=[_predecessor(middle_request, middle)],
    )
    _stage(store, harness, leaf_request)
    denied = store.atomic_commit(leaf_request)
    assert_non_authoritative_tuple_is_exact(
        denied,
        commit_id=leaf_request.commit_id,
        outcome=RequestOutcome.DENIED,
        reason=FailureCode.INVALID_PREDECESSOR,
    )


def assert_revocation_generation_monotonicity_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, scope: RevocationScope
) -> None:
    assert scope in {RevocationScope.ACTOR, RevocationScope.WORKFLOW}
    store = harness.open_store(tmp_path / f"generation-{scope.value.lower()}", None)
    request = harness.make_request(commit_id=f"generation-{scope.value}", nonce_byte=87)
    target = (
        request.subject.agent_id
        if scope is RevocationScope.ACTOR
        else request.subject.workflow_id
    )
    first = RevocationRequest(
        scope, request.subject.workflow_id, target, "2", "advance generation"
    )
    store.revoke(first)
    before = harness.snapshot(store)
    with pytest.raises(ValueError):
        store.revoke(replace(first, next_generation="1", reason="generation rollback"))
    assert harness.snapshot(store) == before


def assert_certificate_revocation_terminality_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, case: str
) -> None:
    assert case in {"unknown", "revoked", "superseded"}
    store = harness.open_store(tmp_path / f"terminal-revocation-{case}", None)
    request = harness.make_request(
        commit_id=f"terminal-revocation-{case}", nonce_byte=88
    )
    _stage(store, harness, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    target = committed.certificate_digest
    exact_request = RevocationRequest(
        RevocationScope.CERTIFICATE,
        request.subject.workflow_id,
        target,
        "1",
        "first terminal event",
    )
    prior = None
    if case == "unknown":
        target = "A" * 43
        exact_request = replace(exact_request, target_id=target)
    elif case == "revoked":
        prior = store.revoke(exact_request)
    else:
        replacement = harness.make_request(
            commit_id="terminal-replacement",
            nonce_byte=89,
            expected_node_version="1",
            attempt_id="terminal-replacement",
        )
        _stage(store, harness, replacement)
        superseded = store.supersede(SupersessionRequest(target, replacement))
        assert isinstance(superseded, SupersessionCommitted)
    before = harness.snapshot(store)
    if case == "revoked":
        try:
            replay = store.revoke(exact_request)
        except ValueError:
            pass
        else:
            assert replay == prior
    else:
        with pytest.raises(ValueError):
            store.revoke(
                RevocationRequest(
                    RevocationScope.CERTIFICATE,
                    request.subject.workflow_id,
                    target,
                    "2",
                    "terminal or unknown target must not mutate",
                )
            )
    assert harness.snapshot(store) == before


def assert_supersession_replay_identity_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path, branch: str
) -> None:
    assert branch in {"committed", "denied", "conflicted"}
    path = tmp_path / f"supersession-replay-{branch}"
    store = harness.open_store(path, None)
    old_request = harness.make_request(
        commit_id=f"supersession-replay-{branch}-old", nonce_byte=90
    )
    _stage(store, harness, old_request)
    old = store.atomic_commit(old_request)
    assert old.certificate_digest is not None
    if branch == "committed":
        replay_old_digest = old.certificate_digest
        proposal = harness.make_request(
            commit_id="supersession-replay-committed-new",
            nonce_byte=91,
            expected_node_version="1",
            attempt_id="committed-replacement",
        )
        _stage(store, harness, proposal)
        original = store.supersede(
            SupersessionRequest(old.certificate_digest, proposal)
        )
        assert isinstance(original, SupersessionCommitted)
    elif branch == "denied":
        replay_old_digest = "A" * 43
        proposal = harness.make_request(
            commit_id="supersession-replay-denied-new",
            nonce_byte=92,
            expected_node_version="1",
            attempt_id="denied-replacement",
        )
        _stage(store, harness, proposal)
        original = store.supersede(SupersessionRequest(replay_old_digest, proposal))
        assert isinstance(original, SupersessionDenied)
    else:
        replay_old_digest = old.certificate_digest
        first_proposal = harness.make_request(
            commit_id="supersession-replay-conflicted-new",
            nonce_byte=93,
            expected_node_version="1",
            attempt_id="conflicted-replacement",
        )
        _stage(store, harness, first_proposal)
        first = store.supersede(
            SupersessionRequest(old.certificate_digest, first_proposal)
        )
        assert isinstance(first, SupersessionCommitted)
        proposal = harness.make_request(
            commit_id=first_proposal.commit_id,
            nonce_byte=99,
            workflow_id="workflow-2",
        )
        original = store.supersede(
            SupersessionRequest(old.certificate_digest, proposal)
        )
        assert isinstance(original, SupersessionConflicted)
    terminal = harness.snapshot(store)
    store = harness.reopen_store(path)
    replay = store.supersede(SupersessionRequest(replay_old_digest, proposal))
    assert replay == original
    assert harness.snapshot(store) == terminal


def assert_repeated_supersession_chain_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    path = tmp_path / "repeated-supersession"
    store = harness.open_store(path, None)
    a_request = harness.make_request(commit_id="chain-a", nonce_byte=201)
    _stage(store, harness, a_request)
    a = store.atomic_commit(a_request)
    assert a.certificate_digest is not None
    b_request = harness.make_request(
        commit_id="chain-b",
        nonce_byte=202,
        expected_node_version="1",
        attempt_id="chain-b-attempt",
    )
    _stage(store, harness, b_request)
    b = store.supersede(SupersessionRequest(a.certificate_digest, b_request))
    assert isinstance(b, SupersessionCommitted)
    assert b.commit_result.certificate_digest is not None
    c_request = harness.make_request(
        commit_id="chain-c",
        nonce_byte=203,
        expected_node_version="2",
        attempt_id="chain-c-attempt",
    )
    _stage(store, harness, c_request)
    c = store.supersede(
        SupersessionRequest(b.commit_result.certificate_digest, c_request)
    )
    assert isinstance(c, SupersessionCommitted)
    assert c.commit_result.certificate_digest is not None
    terminal = harness.snapshot(store)
    reopened = harness.reopen_store(path)
    assert harness.snapshot(reopened) == terminal
    context = reopened.read_commit_context(
        CommitContextRequest(
            c_request.subject.workflow_id,
            c_request.subject.node_id,
            c_request.subject.attempt_id,
            c_request.subject.agent_id,
        )
    )
    assert (
        context.logical_node_state.current_certificate_digest
        == c.commit_result.certificate_digest
    )


def assert_canonical_request_digest_recomputation_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "canonical-request-digest", None)
    request = harness.make_request(commit_id="canonical-request-digest", nonce_byte=94)
    _stage(store, harness, request)
    committed = store.atomic_commit(request)
    changed_statement = dict(request.evidence.producer_statement)
    changed_statement["issued_at_ms"] = str(int(changed_statement["issued_at_ms"]) + 1)
    modified = replace(
        request,
        evidence=replace(request.evidence, producer_statement=changed_statement),
    )
    assert modified.request_digest == request.request_digest
    assert modified.evidence.producer_statement != request.evidence.producer_statement
    conflicted = store.atomic_commit(modified)
    assert_non_authoritative_tuple_is_exact(
        conflicted,
        commit_id=request.commit_id,
        outcome=RequestOutcome.CONFLICTED,
        reason=FailureCode.COMMIT_ID_EQUIVOCATION,
    )
    assert conflicted != committed


def assert_repeated_single_event_outbox_recovery_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "repeated-single-outbox", None)
    first_request = harness.make_request(commit_id="outbox-one", nonce_byte=95)
    second_request = harness.make_request(
        commit_id="outbox-two", nonce_byte=96, workflow_id="workflow-2"
    )
    for request in (first_request, second_request):
        _stage(store, harness, request)
        assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED
    first = store.recover_outbox(OutboxRecoveryRequest(max_items="1"))
    second = store.recover_outbox(OutboxRecoveryRequest(max_items="1"))
    assert first.delivered_count == second.delivered_count == "1"
    assert first.audit_event_id != second.audit_event_id
    assert not harness.outbox_event(store, first_request.commit_id).pending
    assert not harness.outbox_event(store, second_request.commit_id).pending


def assert_lifecycle_outcome_orthogonality_conforms(
    harness: AuthorityStoreHarness, tmp_path: Path
) -> None:
    store = harness.open_store(tmp_path / "lifecycle-outcome", None)
    request = harness.make_request(commit_id="lifecycle-outcome", nonce_byte=97)
    _stage(store, harness, request)
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    before = store.read_commit_context(context_request)
    assert before.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING
    committed = store.atomic_commit(request)
    after = store.read_commit_context(context_request)
    assert committed.decision.outcome is RequestOutcome.COMMITTED
    assert after.candidate_state.lifecycle is CandidateLifecycle.COMMIT_PENDING
    assert type(committed.decision.outcome) is not type(after.candidate_state.lifecycle)
    assert (
        after.logical_node_state.current_certificate_digest
        == committed.certificate_digest
    )


def assert_fault_is_atomic(
    harness: AuthorityStoreHarness, tmp_path: Path, point: str
) -> None:
    controller = _FailController(point)
    path = tmp_path / f"fault-{point}.db"
    if "predecessor_edges" in point:
        setup = harness.open_store(path, None)
        parent_request = harness.make_request(
            commit_id=f"fault-parent-{point}", nonce_byte=10, node_id="root"
        )
        _stage(setup, harness, parent_request)
        parent = setup.atomic_commit(parent_request)
        request = harness.make_request(
            commit_id=f"fault-{point}",
            nonce_byte=11,
            node_id="child",
            predecessors=[_predecessor(parent_request, parent)],
        )
        store = harness.open_store(path, controller)
    else:
        store = harness.open_store(path, controller)
        request = harness.make_request(commit_id=f"fault-{point}", nonce_byte=10)
    _stage(store, harness, request)
    before = harness.snapshot(store)
    try:
        store.atomic_commit(request)
    except _InjectedFault:
        pass
    else:
        raise AssertionError(f"fault {point!r} did not abort")
    assert harness.snapshot(store) == before
    assert store.get_certificate(request.commit_id) is None


def assert_supersession_fault_is_atomic(
    harness: AuthorityStoreHarness, tmp_path: Path, point: str
) -> None:
    """Every replacement write is atomic: old authority survives every crash."""
    path = tmp_path / f"supersession-{point}.db"
    setup = harness.open_store(path, None)
    parent_request = harness.make_request(
        commit_id="supersession-parent", nonce_byte=70, node_id="root"
    )
    _stage(setup, harness, parent_request)
    parent = setup.atomic_commit(parent_request)
    parent_ref = _predecessor(parent_request, parent)
    old_request = harness.make_request(
        commit_id="supersession-old",
        nonce_byte=71,
        node_id="child",
        predecessors=[parent_ref],
    )
    _stage(setup, harness, old_request)
    old = setup.atomic_commit(old_request)
    old_digest = old.certificate_digest
    assert old_digest is not None
    controller = _FailController(point)
    store = harness.open_store(path, controller)
    replacement = harness.make_request(
        commit_id=f"supersession-{point}",
        nonce_byte=72,
        node_id="child",
        expected_node_version="1",
        attempt_id=f"attempt-{point}",
        predecessors=[parent_ref],
    )
    _stage(store, harness, replacement)
    before = harness.snapshot(store)
    try:
        store.supersede(SupersessionRequest(old_digest, replacement))
    except _InjectedFault:
        pass
    else:
        raise AssertionError(f"supersession fault {point!r} did not abort")
    assert harness.snapshot(store) == before
    assert (
        store.get_certificate(old_request.commit_id) == old.certificate_envelope_bytes
    )
    assert store.get_certificate(replacement.commit_id) is None


class _InjectedFault(RuntimeError):
    pass


@dataclass(slots=True)
class _FailController:
    """Private test-only failpoint controller; production defaults to no controller."""

    point: str

    def hit(self, point: str) -> None:
        if point == self.point:
            raise _InjectedFault(point)
