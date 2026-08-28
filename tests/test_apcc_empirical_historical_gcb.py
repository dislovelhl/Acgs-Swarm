from __future__ import annotations

import hashlib
import base64
import json
import os
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical.adapters import (
    TrialStimulus,
    create_baseline_adapter,
    native_evidence_for_variant,
)
from constitutional_swarm.apcc_empirical import historical_gcb as historical_gcb_module
from constitutional_swarm.apcc_empirical.historical_gcb import (
    FROZEN_CRYPTOGRAPHY_VERSION,
    FROZEN_PYTHON_VERSION,
    GCB1_COMMIT_SHA,
    GCB1_TREE_SHA,
    HistoricalGCBAdapter,
    HistoricalSnapshotError,
    JOURNAL_COVERAGE_LIMITATION,
    JOURNAL_ROLLBACK_SCOPE,
    SQLITE_PATH_SCOPE,
)
from constitutional_swarm.apcc_empirical.scenarios import (
    ScenarioOutcome,
    ScenarioRunner,
    default_scenario_catalog,
)


def test_b5_extracts_and_verifies_the_exact_historical_source(tmp_path: Path) -> None:
    adapter = create_baseline_adapter("B5", tmp_path / "historical.sqlite3")
    assert isinstance(adapter, HistoricalGCBAdapter)
    try:
        identity = adapter.identity
        assert identity.commit_sha == GCB1_COMMIT_SHA
        assert identity.tree_sha == GCB1_TREE_SHA
        assert len(identity.lock_sha256) == 64
        assert identity.python_version
        assert identity.python_version == FROZEN_PYTHON_VERSION
        assert identity.cryptography_version == FROZEN_CRYPTOGRAPHY_VERSION
        assert len(identity.environment_digest) == 64
        assert len(identity.module_sha256) == 64
        assert (
            len(adapter._environment_identity["material"]["environment_content_sha256"])
            == 64
        )
        assert identity.adapter_version
        assert identity.module_path == "src/constitutional_swarm/governed_commit.py"
        assert "/apcc/" not in identity.module_path
        assert not (identity.snapshot_root.stat().st_mode & 0o222)
        assert identity.snapshot_root.parent == adapter._state_root
        assert adapter._state_root.stat().st_mode & 0o777 == 0o700
        assert identity.as_manifest_record()["commit_sha"] == GCB1_COMMIT_SHA
        assert (
            identity.as_manifest_record()["journal_coverage_limitation"]
            == JOURNAL_COVERAGE_LIMITATION
        )
        assert (
            identity.as_manifest_record()["journal_rollback_scope"]
            == JOURNAL_ROLLBACK_SCOPE
        )
        assert identity.as_manifest_record()["sqlite_path_scope"] == SQLITE_PATH_SCOPE
        worker_identity = adapter._rpc({"command": "identity"})
        assert worker_identity["database_path"] == str(adapter.path)
        database_state = adapter.path.lstat()
        assert database_state.st_mode & 0o777 == 0o600
        assert adapter._database_identity == (
            database_state.st_dev,
            database_state.st_ino,
        )
    finally:
        adapter.close()


def test_b5_executes_a_real_historical_commit_and_public_observation(
    tmp_path: Path,
) -> None:
    adapter = create_baseline_adapter("B5", tmp_path / "historical.sqlite3")
    assert isinstance(adapter, HistoricalGCBAdapter)
    try:
        observation = adapter.execute(TrialStimulus.control(b"valid-result"))
        snapshot = adapter.snapshot()
        assert observation.authoritative_outcome == "committed"
        assert observation.current_status == "governed_committed"
        assert observation.artifact_visible is True
        assert observation.outbox_pending is True
        assert snapshot.accepted_count == 1
        assert snapshot.denied_count == 0
        assert snapshot.outbox_pending is not None
    finally:
        adapter.close()


@pytest.mark.parametrize(
    "variant_id",
    (
        "invalid-signature:default",
        "input-substitution:input-digest",
        "cross-workflow-replay:default",
        "cross-attempt-replay:default",
    ),
)
def test_b5_uses_historical_signature_and_binding_validation(
    tmp_path: Path, variant_id: str
) -> None:
    adapter = create_baseline_adapter("B5", tmp_path / "historical.sqlite3")
    assert isinstance(adapter, HistoricalGCBAdapter)
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"attacker-result",
                attack_id=variant_id.partition(":")[0],
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(variant_id),
            )
        )
        assert observation.authoritative_outcome == "denied"
        assert observation.artifact_visible is False
        assert observation.current_status == "result_produced"
    finally:
        adapter.close()


def test_b5_retry_is_historical_idempotency_and_reopen_uses_same_source_and_keys(
    tmp_path: Path,
) -> None:
    path = tmp_path / "historical.sqlite3"
    first = create_baseline_adapter("B5", path)
    assert isinstance(first, HistoricalGCBAdapter)
    try:
        retried = first.execute(
            TrialStimulus.attack(
                b"retry-result",
                attack_id="response-loss-and-retry",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant("response-loss-and-retry:default"),
            )
        )
        identity = first.identity
        assert retried.authoritative_outcome == "committed"
        assert first._last_execution_evidence["idempotent_retry"] is True
        assert first._last_execution_evidence["response_lost_after_commit"] is True
    finally:
        first.close()
    reopened = HistoricalGCBAdapter(path, retained_identity=identity)
    try:
        assert reopened.identity.commit_sha == identity.commit_sha
        assert reopened.identity.lock_sha256 == identity.lock_sha256
        assert reopened.execute(
            TrialStimulus.control(b"after-reopen")
        ).current_status == ("governed_committed")
        assert reopened.snapshot().accepted_count == 2
    finally:
        reopened.close()


def test_b5_rejects_wrong_pin_postgresql_and_tampered_supervisor_messages(
    tmp_path: Path,
) -> None:
    with pytest.raises(HistoricalSnapshotError, match="commit"):
        HistoricalGCBAdapter(tmp_path / "bad.sqlite3", expected_commit_sha="0" * 40)
    with pytest.raises(HistoricalSnapshotError, match="tree"):
        HistoricalGCBAdapter(tmp_path / "bad-tree.sqlite3", expected_tree_sha="0" * 40)
    with pytest.raises(HistoricalSnapshotError, match="lock"):
        HistoricalGCBAdapter(
            tmp_path / "bad-lock.sqlite3", expected_lock_sha256="0" * 64
        )
    with pytest.raises(HistoricalSnapshotError, match="URI"):
        HistoricalGCBAdapter(Path("postgresql://localhost/apcc"))

    adapter = HistoricalGCBAdapter(tmp_path / "tamper.sqlite3")
    try:
        with pytest.raises(HistoricalSnapshotError, match="authenticated"):
            adapter._rpc_for_test({"sequence": 1, "body": {}, "mac": "0" * 64})
    finally:
        adapter.close()


def test_b5_lock_digest_is_the_pinned_blob_not_the_current_worktree(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "lock.sqlite3")
    try:
        pinned = adapter.identity.snapshot_root / "uv.lock"
        assert (
            adapter.identity.lock_sha256
            == hashlib.sha256(pinned.read_bytes()).hexdigest()
        )
    finally:
        adapter.close()


def test_b5_secrets_are_not_process_arguments_and_close_reaps_worker(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "process.sqlite3")
    process = adapter._process
    assert process is not None
    assert isinstance(process.args, list)
    arguments = "\0".join(str(value) for value in process.args)
    assert all(
        base64.b64encode(seed).decode() not in arguments for seed in adapter._seeds
    )
    assert adapter._python == adapter._environment_root / "bin" / "python"
    assert adapter._repo / ".venv" not in adapter._python.parents
    adapter.close()
    assert process.poll() is not None
    assert all(
        stream is None or stream.closed
        for stream in (process.stdin, process.stdout, process.stderr)
    )


@pytest.mark.parametrize(
    "uri",
    (
        "postgresql+psycopg://localhost/apcc",
        "sqlite:///tmp/apcc.db",
        "https://example.invalid/apcc",
    ),
)
def test_b5_rejects_every_uri_scheme_before_writes(tmp_path: Path, uri: str) -> None:
    before = set(tmp_path.iterdir())
    with pytest.raises(HistoricalSnapshotError, match="URI"):
        HistoricalGCBAdapter(Path(uri))
    assert set(tmp_path.iterdir()) == before


def test_b5_rejects_database_and_key_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("not-a-database")
    database_link = tmp_path / "database.sqlite3"
    database_link.symlink_to(target)
    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        HistoricalGCBAdapter(database_link)

    database = tmp_path / "keys.sqlite3"
    state_root = tmp_path / ".keys.sqlite3.apcc-b5"
    state_root.mkdir(mode=0o700)
    key_link = state_root / "authority.sqlite3.b5-keys.json"
    key_link.symlink_to(target)
    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        HistoricalGCBAdapter(database)

    locked_database = tmp_path / "locked.sqlite3"
    lock_link = tmp_path / ".locked.sqlite3.apcc-b5.lock"
    lock_link.symlink_to(target)
    with pytest.raises(HistoricalSnapshotError, match="ownership lock"):
        HistoricalGCBAdapter(locked_database)
    assert not (tmp_path / ".locked.sqlite3.apcc-b5").exists()


def test_b5_rejects_dangling_requested_database_symlink_without_path_escape(
    tmp_path: Path,
) -> None:
    external_root = tmp_path / "external-requested-target"
    database_link = tmp_path / "dangling-requested.sqlite3"
    database_link.symlink_to(external_root / "database.sqlite3")

    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        HistoricalGCBAdapter(database_link)

    assert database_link.is_symlink()
    assert not external_root.exists()
    assert not (tmp_path / ".dangling-requested.sqlite3.apcc-b5").exists()
    assert not (tmp_path / ".dangling-requested.sqlite3.apcc-b5.lock").exists()


def test_b5_rejects_dangling_internal_database_symlink_without_path_escape(
    tmp_path: Path,
) -> None:
    requested = tmp_path / "dangling-internal.sqlite3"
    state_root = tmp_path / ".dangling-internal.sqlite3.apcc-b5"
    state_root.mkdir(mode=0o700)
    external_root = tmp_path / "external-internal-target"
    internal_database = state_root / "authority.sqlite3"
    internal_database.symlink_to(external_root / "authority.sqlite3")

    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        HistoricalGCBAdapter(requested)

    assert internal_database.is_symlink()
    assert not external_root.exists()
    assert set(state_root.iterdir()) == {internal_database}
    assert not (tmp_path / ".dangling-internal.sqlite3.apcc-b5.lock").exists()


def test_b5_preserves_published_lock_if_under_lock_symlink_preflight_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requested = tmp_path / "late-symlink.sqlite3"
    external_root = tmp_path / "external-late-target"
    original_acquire = HistoricalGCBAdapter._acquire_state_lock

    def acquire_then_inject(adapter: HistoricalGCBAdapter) -> None:
        original_acquire(adapter)
        adapter._state_root.mkdir(mode=0o700)
        adapter.path.symlink_to(external_root / "authority.sqlite3")

    monkeypatch.setattr(
        HistoricalGCBAdapter, "_acquire_state_lock", acquire_then_inject
    )
    with pytest.raises(HistoricalSnapshotError, match="symlink"):
        HistoricalGCBAdapter(requested)

    assert not external_root.exists()
    lock_path = tmp_path / ".late-symlink.sqlite3.apcc-b5.lock"
    lock_state = lock_path.lstat()
    assert stat.S_ISREG(lock_state.st_mode)
    assert stat.S_IMODE(lock_state.st_mode) == 0o600
    assert (tmp_path / ".late-symlink.sqlite3.apcc-b5/authority.sqlite3").is_symlink()


def test_b5_lock_creation_and_reuse_ignore_caller_umask_0777(tmp_path: Path) -> None:
    lock_path = tmp_path / ".umask.sqlite3.apcc-b5.lock"

    def acquire_once() -> tuple[int, int]:
        adapter = object.__new__(HistoricalGCBAdapter)
        adapter._state_lock_fd = None
        adapter._state_lock_path = lock_path
        adapter._acquire_state_lock()
        try:
            assert adapter._state_lock_fd is not None
            state = os.fstat(adapter._state_lock_fd)
            assert stat.S_IMODE(state.st_mode) == 0o600
            return state.st_dev, state.st_ino
        finally:
            adapter._release_state_lock()

    original_umask = os.umask(0o777)
    try:
        first_identity = acquire_once()
        second_identity = acquire_once()
    finally:
        os.umask(original_umask)

    published = lock_path.lstat()
    assert stat.S_IMODE(published.st_mode) == 0o600
    assert first_identity == second_identity == (published.st_dev, published.st_ino)


def test_b5_journal_cannot_invent_authoritative_snapshot_facts(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "journal.sqlite3")
    try:
        adapter._journal.append(
            {
                "sequence": 1,
                "workflow_id": "invented",
                "node_id": "invented",
                "artifact_id": "invented",
                "variant": None,
            }
        )
        with pytest.raises(HistoricalSnapshotError, match="KeyError"):
            adapter.snapshot()
    finally:
        adapter.close()


def test_b5_rejects_oversized_supervisor_frame(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "frame.sqlite3")
    try:
        with pytest.raises(HistoricalSnapshotError, match="too large"):
            adapter._rpc({"command": "unknown", "padding": "x" * 1_048_576})
    finally:
        adapter.close()


@pytest.mark.parametrize(
    "variant_id",
    (
        "input-substitution:input-digest",
        "output-substitution:output-digest",
        "identity-substitution:default",
        "cross-node-replay:default",
        "cross-workflow-replay:default",
        "cross-attempt-replay:default",
        "malicious-executor:default",
        "duplicate-predecessor:default",
        "predecessor-set-reordering:default",
    ),
)
def test_b5_semantic_mutations_do_not_collapse_to_invalid_signature(
    tmp_path: Path, variant_id: str
) -> None:
    adapter = HistoricalGCBAdapter(
        tmp_path / f"semantic-{variant_id.partition(':')[0]}.db"
    )
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"semantic",
                attack_id=variant_id.partition(":")[0],
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(variant_id),
            )
        )
        assert observation.authoritative_outcome == "denied"
        assert (
            adapter._last_execution_evidence["decision_reason"] != "invalid_signature"
        )
    finally:
        adapter.close()


def test_b5_unknown_key_is_self_consistently_signed_by_an_unregistered_key(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "unknown-key.sqlite3")
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"unknown-key",
                attack_id="unknown-key",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant("unknown-key:default"),
            )
        )
        assert observation.authoritative_outcome == "denied"
        assert adapter._last_execution_evidence["unknown_key_signature_valid"] is True
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("variant_id", "reason"),
    (
        ("missing-proof:absent", "invalid_signature"),
        ("unknown-protocol-version:default", "unknown_receipt_profile"),
    ),
)
def test_b5_missing_proof_and_unknown_profile_have_native_receipt_mutations(
    tmp_path: Path, variant_id: str, reason: str
) -> None:
    adapter = HistoricalGCBAdapter(
        tmp_path / f"native-{variant_id.partition(':')[0]}.db"
    )
    try:
        adapter.execute(
            TrialStimulus.attack(
                b"native",
                attack_id=variant_id.partition(":")[0],
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(variant_id),
            )
        )
        assert adapter._last_execution_evidence["decision_reason"] == reason
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("variant_id", "reason"),
    (
        ("policy-update-race:default", "stale_or_mismatched_policy_version"),
        ("authority-update-race:default", "stale_or_mismatched_authority_root"),
        (
            "actor-revocation-race:revoked",
            "stale_or_mismatched_authority_snapshot_digest",
        ),
        (
            "workflow-revocation-race:revoked",
            "stale_or_mismatched_workflow_generation",
        ),
    ),
)
def test_b5_races_mutate_the_distinct_historical_epoch_surface(
    tmp_path: Path, variant_id: str, reason: str
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / f"race-{variant_id.partition(':')[0]}.db")
    try:
        adapter.execute(
            TrialStimulus.attack(
                b"race",
                attack_id=variant_id.partition(":")[0],
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(variant_id),
            )
        )
        assert adapter._last_execution_evidence["decision_reason"] == reason
    finally:
        adapter.close()


def test_b5_exercises_public_historical_recovery_attach(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "blocked.sqlite3")
    first_pid = adapter._process.pid if adapter._process is not None else None
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"unsupported",
                attack_id="recovery-import",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant("recovery-import:default"),
            )
        )
        assert observation.authoritative_outcome == "committed"
        assert adapter._process is not None and adapter._process.pid != first_pid
        assert adapter._last_execution_evidence == {
            "invalid_recovery_source": {
                "rejections": {
                    "policy": "recovery_policy_mismatch",
                    "topology": "recovery_topology_mismatch",
                    "input": "recovery_topology_mismatch",
                },
                "unchanged_non_authoritative": True,
            },
            "exact_attach_after_reopen": True,
            "worker_reopened": True,
        }
    finally:
        adapter.close()


def test_b5_explicitly_verifies_legacy_completion_is_not_promoted(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "legacy.sqlite3")
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"legacy",
                attack_id="legacy-completion-promotion",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(
                    "legacy-completion-promotion:default"
                ),
            )
        )
        assert observation.authoritative_outcome == "denied"
        assert observation.current_status == "result_produced"
        assert observation.artifact_visible is False
        assert adapter._last_execution_evidence["legacy_non_promotion_verified"] is True
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("variant_id", "barrier"),
    (
        ("validator-crash:validator-crash", "receipt-validation"),
        ("validator-crash:verifier-crash", "verdict-issued"),
    ),
)
def test_b5_crash_recovery_interrupts_an_explicit_historical_barrier(
    tmp_path: Path, variant_id: str, barrier: str
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / f"crash-{barrier}.sqlite3")
    first_pid = adapter._process.pid if adapter._process is not None else None
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"crash",
                attack_id="validator-crash",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant(variant_id),
            )
        )
        assert observation.authoritative_outcome == "committed"
        assert adapter._process is not None and adapter._process.pid != first_pid
        assert adapter._last_execution_evidence == {
            "crash_barrier": barrier,
            "worker_interrupted": True,
            "attach_workflow_verified": True,
        }
    finally:
        adapter.close()


def test_b5_outbox_recovery_proves_event_retention_and_exact_delivery(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "outbox.sqlite3")
    try:
        observation = adapter.execute(
            TrialStimulus.attack(
                b"outbox",
                attack_id="outbox-failure",
                capabilities=frozenset(),
                evidence=native_evidence_for_variant("outbox-failure:default"),
            )
        )
        assert observation.outbox_pending is False
        assert adapter._last_execution_evidence["outbox_retry"] == {
            "pending_after_failure": 1,
            "pending_after_retry": 0,
            "delivered": True,
        }
    finally:
        adapter.close()


def test_b5_retained_identity_mismatch_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "identity.sqlite3"
    first = HistoricalGCBAdapter(path)
    identity = first.identity
    first.close()
    with pytest.raises(HistoricalSnapshotError, match="retained"):
        HistoricalGCBAdapter(
            path,
            retained_identity=replace(identity, python_version="0.0.0"),
        )


def test_b5_rejects_a_worker_with_the_wrong_frozen_runtime(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "wrong-runtime.sqlite3")
    process = adapter._process
    assert process is not None
    forged = {
        "module_path": str(
            adapter.identity.snapshot_root / adapter.identity.module_path
        ),
        "python_version": "0.0.0",
        "cryptography_version": FROZEN_CRYPTOGRAPHY_VERSION,
        "environment": adapter._environment_identity["material"],
        "environment_digest": adapter._environment_identity["digest"],
    }
    with pytest.raises(HistoricalSnapshotError, match="environment mismatch"):
        adapter._validate_worker_identity(forged)
    assert process.poll() is not None
    adapter.close()


def test_b5_journal_mac_is_domain_separated_from_verifier_seed(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "journal-kdf.sqlite3")
    try:
        assert adapter._journal_mac_key() != adapter._seeds[0]
        assert adapter._journal_head_mac_key() != adapter._journal_mac_key()
    finally:
        adapter.close()


@pytest.mark.parametrize("conflict", ("workflow-node", "artifact"))
def test_b5_rejects_authenticated_duplicate_or_conflicting_journal_identity(
    tmp_path: Path, conflict: str
) -> None:
    path = tmp_path / f"journal-{conflict}.sqlite3"
    first = HistoricalGCBAdapter(path)
    first.execute(TrialStimulus.control(b"one"))
    first.execute(TrialStimulus.control(b"two"))
    if conflict == "workflow-node":
        first._journal[1]["workflow_id"] = first._journal[0]["workflow_id"]
        first._journal[1]["node_id"] = first._journal[0]["node_id"]
    else:
        first._journal[1]["artifact_id"] = first._journal[0]["artifact_id"]
    first._persist_journal()
    first.close()
    with pytest.raises(HistoricalSnapshotError, match="duplicate or conflicting"):
        HistoricalGCBAdapter(path)


def test_b5_detects_authenticated_journal_only_rollback(tmp_path: Path) -> None:
    path = tmp_path / "journal-rollback.sqlite3"
    first = HistoricalGCBAdapter(path)
    first.execute(TrialStimulus.control(b"one"))
    prior = first._journal_path.read_bytes()
    first.execute(TrialStimulus.control(b"two"))
    first.close()
    first._journal_path.write_bytes(prior)
    with pytest.raises(HistoricalSnapshotError, match="rollback"):
        HistoricalGCBAdapter(path)


def test_b5_partial_unterminated_worker_frame_times_out_and_reaps(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "partial-frame.sqlite3")
    process = adapter._process
    assert process is not None
    adapter._rpc_timeout_seconds = 0.05
    with pytest.raises(HistoricalSnapshotError, match="timed out"):
        adapter._rpc({"command": "partial-frame-for-test"})
    assert process.poll() is not None
    adapter.close()


def test_b5_failed_initialization_removes_only_new_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new_path = tmp_path / "new.sqlite3"
    original = HistoricalGCBAdapter._validate_worker_identity

    def reject(_self: HistoricalGCBAdapter, _identity: object) -> None:
        raise HistoricalSnapshotError("forced identity failure")

    monkeypatch.setattr(HistoricalGCBAdapter, "_validate_worker_identity", reject)
    with pytest.raises(HistoricalSnapshotError, match="forced identity failure"):
        HistoricalGCBAdapter(new_path)
    assert not (tmp_path / ".new.sqlite3.apcc-b5").exists()

    monkeypatch.setattr(HistoricalGCBAdapter, "_validate_worker_identity", original)
    durable_path = tmp_path / "durable.sqlite3"
    durable = HistoricalGCBAdapter(durable_path)
    state_root = durable._state_root
    marker = state_root / "pre-existing.marker"
    marker.write_text("preserve", encoding="utf-8")
    durable.execute(TrialStimulus.control(b"durable"))
    journal_before = durable._journal_path.read_bytes()
    keys_before = durable.path.with_suffix(
        durable.path.suffix + ".b5-keys.json"
    ).read_bytes()
    durable.close()

    monkeypatch.setattr(HistoricalGCBAdapter, "_validate_worker_identity", reject)
    with pytest.raises(HistoricalSnapshotError, match="forced identity failure"):
        HistoricalGCBAdapter(durable_path)
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert (
        state_root / "authority.sqlite3.b5-journal.json"
    ).read_bytes() == journal_before
    assert (state_root / "authority.sqlite3.b5-keys.json").read_bytes() == keys_before


@pytest.mark.parametrize("repeat", range(3))
def test_b5_shared_adapter_serializes_one_hundred_clients_without_loss(
    tmp_path: Path, repeat: int
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / f"shared-{repeat}.sqlite3")
    try:
        with ThreadPoolExecutor(max_workers=32) as pool:
            observations = tuple(
                pool.map(
                    lambda index: adapter.execute(
                        TrialStimulus.control(f"client-{index}".encode())
                    ),
                    range(100),
                )
            )
        assert all(
            observation.authoritative_outcome == "committed"
            for observation in observations
        )
        assert len(adapter._journal) == 100
        assert (
            len(
                {
                    (
                        record["workflow_id"],
                        record["node_id"],
                        record["artifact_id"],
                    )
                    for record in adapter._journal
                }
            )
            == 100
        )
        snapshot = adapter.snapshot()
        assert snapshot.accepted_count == 100
        assert snapshot.denied_count == 0
        assert snapshot.outbox_pending is not None
        assert len(snapshot.outbox_pending) == 100
    finally:
        adapter.close()


def test_b5_same_path_has_exclusive_lifetime_ownership_and_clean_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "same-path.sqlite3"
    first = HistoricalGCBAdapter(path)
    marker = first._state_root / "peer.marker"
    marker.write_text("peer-owned", encoding="utf-8")
    first.execute(TrialStimulus.control(b"first"))
    journal_before = first._journal_path.read_bytes()
    environment_inode = first._environment_root.stat().st_ino
    environment_digest = first.identity.environment_digest
    started = time.monotonic()
    try:
        with pytest.raises(HistoricalSnapshotError, match="already owned"):
            HistoricalGCBAdapter(path)
        assert time.monotonic() - started < 2.0
        assert marker.read_text(encoding="utf-8") == "peer-owned"
        assert first._journal_path.read_bytes() == journal_before
        first.execute(TrialStimulus.control(b"second"))
        assert first.snapshot().accepted_count == 2
    finally:
        first.close()

    reopened = HistoricalGCBAdapter(path)
    try:
        assert reopened._environment_root.stat().st_ino == environment_inode
        assert reopened.identity.environment_digest == environment_digest
        assert marker.read_text(encoding="utf-8") == "peer-owned"
        assert reopened.snapshot().accepted_count == 2
        reopened.execute(TrialStimulus.control(b"third"))
        assert reopened.snapshot().accepted_count == 3
    finally:
        reopened.close()


@pytest.mark.parametrize("repeat", range(3))
def test_b5_failed_initializer_waiters_share_one_persistent_lock_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, repeat: int
) -> None:
    path = tmp_path / f"aba-{repeat}.sqlite3"
    lock_path = tmp_path / f".aba-{repeat}.sqlite3.apcc-b5.lock"
    labels: dict[int, str] = {}
    acquired_identities: dict[str, tuple[int, int]] = {}
    opened_identities: dict[str, tuple[int, int]] = {}
    post_lock_initializers: set[str] = set()
    labels_lock = threading.Lock()
    a_at_failure_barrier = threading.Event()
    waiter_opened = {"B": threading.Event(), "C": threading.Event()}
    release_a = threading.Event()
    original_flock = historical_gcb_module.fcntl.flock
    original_acquire = HistoricalGCBAdapter._acquire_state_lock
    original_validate = HistoricalGCBAdapter._validate_worker_identity

    def tracked_flock(descriptor: int, operation: int) -> None:
        try:
            original_flock(descriptor, operation)
        except BlockingIOError:
            with labels_lock:
                label = labels.get(threading.get_ident())
            if label in waiter_opened:
                state = os.fstat(descriptor)
                opened_identities[label] = (state.st_dev, state.st_ino)
                waiter_opened[label].set()
            raise

    def tracked_acquire(adapter: HistoricalGCBAdapter) -> None:
        original_acquire(adapter)
        assert adapter._state_lock_fd is not None
        state = os.fstat(adapter._state_lock_fd)
        with labels_lock:
            label = labels.get(threading.get_ident())
            if label is not None:
                acquired_identities[label] = (state.st_dev, state.st_ino)

    def fail_a_after_waiters_open(
        adapter: HistoricalGCBAdapter, identity: object
    ) -> None:
        with labels_lock:
            label = labels.get(threading.get_ident())
        if label == "A":
            a_at_failure_barrier.set()
            assert release_a.wait(timeout=10)
            raise HistoricalSnapshotError("forced post-lock initializer failure")
        if label in waiter_opened:
            with labels_lock:
                post_lock_initializers.add(label)
        original_validate(adapter, identity)  # type: ignore[arg-type]

    monkeypatch.setattr(historical_gcb_module.fcntl, "flock", tracked_flock)
    monkeypatch.setattr(HistoricalGCBAdapter, "_acquire_state_lock", tracked_acquire)
    monkeypatch.setattr(
        HistoricalGCBAdapter, "_validate_worker_identity", fail_a_after_waiters_open
    )

    def construct(label: str) -> HistoricalGCBAdapter | Exception:
        with labels_lock:
            labels[threading.get_ident()] = label
        try:
            return HistoricalGCBAdapter(path)
        except Exception as error:
            return error

    with ThreadPoolExecutor(max_workers=3) as pool:
        future_a = pool.submit(construct, "A")
        assert a_at_failure_barrier.wait(timeout=30)
        future_b = pool.submit(construct, "B")
        future_c = pool.submit(construct, "C")
        assert waiter_opened["B"].wait(timeout=10)
        assert waiter_opened["C"].wait(timeout=10)
        published_while_waiting = lock_path.lstat()
        release_a.set()
        result_a = future_a.result(timeout=30)
        result_b = future_b.result(timeout=30)
        result_c = future_c.result(timeout=30)

    assert isinstance(result_a, HistoricalSnapshotError)
    contenders = (result_b, result_c)
    winners = tuple(
        result for result in contenders if isinstance(result, HistoricalGCBAdapter)
    )
    losers = tuple(result for result in contenders if isinstance(result, Exception))
    assert len(winners) == 1
    assert len(losers) == 1
    assert "already owned" in str(losers[0])
    winner = winners[0]
    try:
        published = lock_path.lstat()
        expected_identity = (published.st_dev, published.st_ino)
        assert expected_identity == (
            published_while_waiting.st_dev,
            published_while_waiting.st_ino,
        )
        assert set(acquired_identities.values()) == {expected_identity}
        assert opened_identities == {"B": expected_identity, "C": expected_identity}
        assert len(post_lock_initializers) == 1
    finally:
        winner.close()

    reopened = HistoricalGCBAdapter(path)
    try:
        reopened_lock = os.fstat(reopened._state_lock_fd)  # type: ignore[arg-type]
        assert (reopened_lock.st_dev, reopened_lock.st_ino) == expected_identity
    finally:
        reopened.close()


def test_b5_rejects_tampered_authenticated_journal_on_reopen(tmp_path: Path) -> None:
    path = tmp_path / "tampered-journal.sqlite3"
    first = HistoricalGCBAdapter(path)
    first.execute(TrialStimulus.control(b"journal"))
    journal = first._journal_path
    first.close()
    value = json.loads(journal.read_text(encoding="utf-8"))
    value["records"][0]["workflow_id"] = "invented"
    journal.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(HistoricalSnapshotError, match="authentication"):
        HistoricalGCBAdapter(path)


def test_b5_rehashes_read_only_source_before_worker_restart(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "rehash.sqlite3")
    source = adapter.identity.snapshot_root / adapter.identity.module_path
    source.chmod(source.stat().st_mode | 0o200)
    source.write_text(source.read_text(encoding="utf-8") + "\n# tampered\n")
    try:
        with pytest.raises(HistoricalSnapshotError, match="snapshot changed"):
            adapter._restart_worker()
    finally:
        adapter.close()


def test_b5_rehashes_the_resolved_environment_before_worker_restart(
    tmp_path: Path,
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "environment-drift.sqlite3")
    cryptography_init = next(
        adapter._environment_root.glob(
            "lib/python*/site-packages/cryptography/__init__.py"
        )
    )
    drift = cryptography_init.parent / "b5-drift.py"
    drift.write_text("DRIFT = True\n", encoding="utf-8")
    try:
        with pytest.raises(HistoricalSnapshotError, match="environment changed"):
            adapter._restart_worker()
        assert adapter._process is None
    finally:
        adapter.close()


@pytest.mark.parametrize("mode", (0o755, 0o777))
def test_b5_rejects_state_root_permission_drift_before_restart(
    tmp_path: Path, mode: int
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / f"root-mode-{mode:o}.sqlite3")
    adapter._state_root.chmod(mode)
    try:
        with pytest.raises(HistoricalSnapshotError, match="state root identity"):
            adapter._restart_worker()
        assert adapter._process is None
    finally:
        adapter._state_root.chmod(0o700)
        adapter.close()


def test_b5_rejects_database_permission_drift_before_restart(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "database-mode.sqlite3")
    assert adapter.path.stat().st_mode & 0o777 == 0o600
    adapter.path.chmod(0o644)
    try:
        with pytest.raises(
            HistoricalSnapshotError, match="database identity is unsafe"
        ):
            adapter._restart_worker()
        assert adapter._process is None
    finally:
        adapter.path.chmod(0o600)
        adapter.close()


def test_b5_rejects_database_owner_drift_before_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "database-owner.sqlite3")
    original_lstat = Path.lstat

    def owner_drift(path: Path) -> os.stat_result:
        value = original_lstat(path)
        if path == adapter.path:
            fields = list(value)
            fields[4] = value.st_uid + 1
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "lstat", owner_drift)
    try:
        with pytest.raises(
            HistoricalSnapshotError, match="database identity is unsafe"
        ):
            adapter._restart_worker()
        assert adapter._process is None
    finally:
        monkeypatch.setattr(Path, "lstat", original_lstat)
        adapter.close()


def test_b5_blocked_supersession_result_keeps_pinned_public_api_evidence(
    tmp_path: Path,
) -> None:
    spec = next(
        item
        for item in default_scenario_catalog()
        if item.variant_id == "predecessor-replacement-race:supersession-current"
    )
    adapter = HistoricalGCBAdapter(tmp_path / "blocked-evidence.sqlite3")
    try:
        result = ScenarioRunner().run(
            spec,
            adapter,
            control=TrialStimulus.control(b"control"),
            attack=TrialStimulus.attack(
                b"attack",
                attack_id=spec.attack_id,
                capabilities=spec.capabilities,
                evidence=native_evidence_for_variant(spec.variant_id),
            ),
        )
    finally:
        adapter.close()
    assert result.outcome is ScenarioOutcome.BLOCKED
    assert result.blocked_reason is not None
    assert GCB1_COMMIT_SHA in result.blocked_reason
    assert "GovernedCommitBoundary public methods" in result.blocked_reason


def test_b5_runs_or_truthfully_blocks_all_39_frozen_variants(tmp_path: Path) -> None:
    adapter = HistoricalGCBAdapter(tmp_path / "matrix.sqlite3")
    results = {}
    try:
        for spec in default_scenario_catalog():
            result = ScenarioRunner().run(
                spec,
                adapter,
                control=TrialStimulus.control(b"control"),
                attack=TrialStimulus.attack(
                    b"attack",
                    attack_id=spec.attack_id,
                    capabilities=spec.capabilities,
                    evidence=native_evidence_for_variant(spec.variant_id),
                ),
            )
            results[spec.variant_id] = result
            assert result.outcome is spec.expected["B5"]
    finally:
        adapter.close()

    assert len(results) == 39
    blocked = {
        variant_id: result
        for variant_id, result in results.items()
        if result.outcome is ScenarioOutcome.BLOCKED
    }
    assert len(blocked) == 2
    assert all(
        result.blocked_capabilities or result.blocked_reason
        for result in blocked.values()
    )
    not_applicable = {
        variant_id: result
        for variant_id, result in results.items()
        if result.outcome is ScenarioOutcome.NOT_APPLICABLE
    }
    assert len(not_applicable) == 11
    assert all(result.not_applicable_reason for result in not_applicable.values())
    assert {spec.attack_id for spec in default_scenario_catalog()} == {
        "missing-proof",
        "invalid-signature",
        "unknown-key",
        "output-substitution",
        "input-substitution",
        "identity-substitution",
        "cross-node-replay",
        "cross-workflow-replay",
        "cross-attempt-replay",
        "commit-id-equivocation",
        "policy-update-race",
        "authority-update-race",
        "actor-revocation-race",
        "workflow-revocation-race",
        "predecessor-replacement-race",
        "concurrent-double-commit",
        "response-loss-and-retry",
        "validator-crash",
        "authority-store-transaction-failure",
        "outbox-failure",
        "recovery-import",
        "legacy-completion-promotion",
        "malicious-scheduler",
        "malicious-executor",
        "malicious-retry-caller",
        "stale-cache",
        "certificate-truncation",
        "canonicalization-ambiguity",
        "unknown-protocol-version",
        "oversized-certificate",
        "duplicate-predecessor",
        "predecessor-set-reordering",
    }
    counts = {
        outcome: sum(result.outcome is outcome for result in results.values())
        for outcome in ScenarioOutcome
    }
    assert counts == {
        ScenarioOutcome.COMPROMISED: 0,
        ScenarioOutcome.FAIL_CLOSED: 21,
        ScenarioOutcome.RECOVERED: 5,
        ScenarioOutcome.BLOCKED: 2,
        ScenarioOutcome.NOT_APPLICABLE: 11,
    }
