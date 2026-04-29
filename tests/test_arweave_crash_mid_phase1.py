"""Crash-mid-two-phase-commit regression for ArweaveAuditLogger."""

from __future__ import annotations

import uuid

import pytest
from constitutional_swarm.bittensor.arweave_audit_log import (
    ArweaveAuditLogger,
    AuditDecisionType,
    AuditLogEntry,
    InMemoryArweaveClient,
)

CONST_HASH = "608508a9bd224290"


class RecordingSubmitter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    def submit(
        self,
        batch_root: str,
        constitutional_hash: str,
        proof_count: int,
    ) -> int:
        self.calls.append((batch_root, constitutional_hash, proof_count))
        return 777


def _entry(entry_id: str | None = None) -> AuditLogEntry:
    return AuditLogEntry(
        entry_id=entry_id or uuid.uuid4().hex[:8],
        case_id="ESC-CRASH",
        constitutional_hash=CONST_HASH,
        decision_type=AuditDecisionType.ESCALATED,
        compliance_passed=True,
        impact_score=0.87,
        escalation_type="safety",
        resolution="allow_with_conditions",
        miner_uid="miner-01",
        validator_grade=0.93,
    )


def test_crash_after_phase1_preserves_retry_state_and_replays_phase2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arweave = InMemoryArweaveClient()
    submitter = RecordingSubmitter()
    logger = ArweaveAuditLogger(
        constitutional_hash=CONST_HASH,
        arweave_client=arweave,
        chain_submitter=submitter,
        batch_size=10,
    )
    for idx in range(3):
        logger.add_entry(_entry(f"crash-{idx}"))

    original_submit = submitter.submit

    def crash_once(
        batch_root: str,
        constitutional_hash: str,
        proof_count: int,
    ) -> int:
        submitter.calls.append((batch_root, constitutional_hash, proof_count))
        raise RuntimeError("phase 2 crash")

    monkeypatch.setattr(submitter, "submit", crash_once)
    with pytest.raises(RuntimeError, match="phase 2 crash"):
        logger.flush()

    assert logger.pending_count == 3
    assert logger._retry_state is not None
    cached_batch, cached_tx_id = logger._retry_state
    assert cached_batch.entry_count == 3
    assert arweave.transaction_count == 1
    assert submitter.calls == [(cached_batch.batch_root, CONST_HASH, cached_batch.entry_count)]

    monkeypatch.setattr(submitter, "submit", original_submit)
    receipt = logger.flush()

    assert receipt is not None
    assert receipt.block_height == 777
    assert receipt.batch_root == cached_batch.batch_root
    assert receipt.arweave_tx_id == cached_tx_id
    assert arweave.transaction_count == 1
    assert logger.pending_count == 0
    assert logger._retry_state is None
    assert submitter.calls == [
        (cached_batch.batch_root, CONST_HASH, cached_batch.entry_count),
        (cached_batch.batch_root, CONST_HASH, cached_batch.entry_count),
    ]
