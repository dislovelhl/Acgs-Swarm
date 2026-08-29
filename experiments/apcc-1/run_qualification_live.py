#!/usr/bin/env python3
"""APCC-1 qualification-live runner.

v1: apcc-1.qualification-live.v1 (1 ms sleep cap; do not reuse for 10/s).
v2: apcc-1.qualification-live.v2 (sleep until next beat).
Does not close apcc-1.matrix.v1. Protocol:
docs/internal/APCC-1-Qualification-Live-Protocol.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import time
import traceback
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

PROTOCOL_ID = "apcc-1.qualification-live.v2"
PACER = "sleep-until-next-beat"
SEED = 104729
PAYLOAD = os.urandom(1024)
OUTPUT = os.urandom(4096)
TARGET_RATE = 10
WARMUPS = 3
MEASURED = 10
DURATION_S = 30
MIN_OPS = 10_000
B6_NODES = 400
B5_INIT_TIMEOUT_S = 180.0

from constitutional_swarm.apcc_empirical.adapters import (  # noqa: E402
    B6AuthorityAdapter,
    TrialStimulus,
    create_baseline_adapter,
    native_evidence_for_variant,
)
from constitutional_swarm.apcc_empirical.scenarios import (  # noqa: E402
    ScenarioRunner,
    default_scenario_catalog,
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    path.write_text(raw + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _percentile(samples: list[int], percent: float) -> int | None:
    if not samples:
        return None
    ordered = sorted(samples)
    rank = (len(ordered) - 1) * (percent / 100.0)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return int(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _git_sha() -> str:
    import subprocess

    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()


def _append(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run_scenarios(run_dir: Path, git_sha: str) -> dict[str, Any]:
    catalog = default_scenario_catalog()
    runner = ScenarioRunner()
    out = run_dir / "scenarios.jsonl"
    counts: dict[str, int] = {
        "attempted": 0,
        "matched_expected": 0,
        "mismatched": 0,
        "errors": 0,
        "b6_blocked": 0,
    }
    start = _utc()
    for spec in catalog:
        for baseline_id in ("B0", "B1", "B2", "B3", "B4", "B5", "B6"):
            counts["attempted"] += 1
            db = (
                run_dir
                / "scenario-db"
                / f"{baseline_id}-{spec.variant_id.replace(':', '_')}.db"
            )
            db.parent.mkdir(parents=True, exist_ok=True)
            adapter: Any
            closer: Callable[[], None] | None = None
            try:
                if baseline_id == "B6":
                    adapter = B6AuthorityAdapter()
                else:
                    adapter = create_baseline_adapter(baseline_id, db)
                    closer = getattr(adapter, "close", None)
                result = runner.run(
                    spec,
                    adapter,
                    control=TrialStimulus.control(b"control-payload"),
                    attack=TrialStimulus.attack(
                        b"attack-payload",
                        attack_id=spec.attack_id,
                        capabilities=spec.capabilities,
                        evidence=native_evidence_for_variant(spec.variant_id),
                    ),
                )
                observed = result.outcome.value
                expected = spec.expected[baseline_id].value
                matched = observed == expected
                if matched:
                    counts["matched_expected"] += 1
                else:
                    counts["mismatched"] += 1
                if baseline_id == "B6" and observed == "blocked":
                    counts["b6_blocked"] += 1
                record = {
                    "cell": "scenario-catalog",
                    "baseline_id": baseline_id,
                    "attack_id": spec.attack_id,
                    "variant_id": spec.variant_id,
                    "expected": expected,
                    "observed": observed,
                    "matched_expected": matched,
                    "blocked_reason": result.blocked_reason,
                    "not_applicable_reason": result.not_applicable_reason,
                    "blocked_capabilities": sorted(result.blocked_capabilities),
                    "error": None,
                    "git_sha": git_sha,
                    "protocol_id": PROTOCOL_ID,
                    "seed": SEED,
                }
            except Exception as error:
                counts["errors"] += 1
                record = {
                    "cell": "scenario-catalog",
                    "baseline_id": baseline_id,
                    "attack_id": spec.attack_id,
                    "variant_id": spec.variant_id,
                    "expected": spec.expected[baseline_id].value,
                    "observed": "error",
                    "matched_expected": False,
                    "blocked_reason": None,
                    "not_applicable_reason": None,
                    "blocked_capabilities": [],
                    "error": f"{type(error).__name__}: {error}",
                    "traceback": traceback.format_exc(limit=8),
                    "git_sha": git_sha,
                    "protocol_id": PROTOCOL_ID,
                    "seed": SEED,
                }
            finally:
                if closer is not None:
                    try:
                        closer()
                    except Exception:
                        pass
            _append(out, record)
    return {
        "start_utc": start,
        "end_utc": _utc(),
        "artifact": str(out.relative_to(ROOT)),
        "counts": counts,
    }


def _b6_helpers():
    import tests.test_apcc_sqlite as sqlite_tests
    from constitutional_swarm.apcc.model import RequestOutcome, Signature
    from constitutional_swarm.apcc.ports import ReplayCommitRequest
    from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore

    return (
        sqlite_tests,
        RequestOutcome,
        Signature,
        ReplayCommitRequest,
        SQLiteAuthorityStore,
    )


def _unique_request(
    sqlite_tests: Any,
    *,
    commit_id: str,
    nonce_index: int,
    node_id: str,
    result_bytes: bytes,
):
    nonce_raw = nonce_index.to_bytes(16, "big")
    import base64

    nonce = base64.urlsafe_b64encode(nonce_raw).rstrip(b"=").decode("ascii")
    original_nonce = sqlite_tests._nonce
    sqlite_tests._nonce = lambda _byte: nonce
    try:
        return sqlite_tests._request(
            commit_id=commit_id,
            nonce_byte=0,
            node_id=node_id,
            result_bytes=result_bytes,
            attempt_id=f"attempt-ql-{nonce_index}",
        )
    finally:
        sqlite_tests._nonce = original_nonce


def _advance_candidate(store: Any, request: Any, result_bytes: bytes) -> None:
    from constitutional_swarm.apcc.model import CandidateLifecycle
    from constitutional_swarm.apcc.ports import (
        AssembleEvidenceRequest,
        ProposeCommitRequest,
        StageResultRequest,
    )

    staged = store.stage_result(
        StageResultRequest(
            request.subject, request.bindings.expected_node_version, result_bytes
        )
    )
    if staged.candidate_state.lifecycle is not CandidateLifecycle.RESULT_STAGED:
        raise RuntimeError(f"stage:{staged.candidate_state.lifecycle}")
    assembled = store.assemble_evidence(AssembleEvidenceRequest(request))
    if assembled.candidate_state.lifecycle is not CandidateLifecycle.EVIDENCE_ASSEMBLED:
        raise RuntimeError(f"assemble:{assembled.candidate_state.lifecycle}")
    proposed = store.propose_commit(ProposeCommitRequest(request))
    if proposed.candidate_state.lifecycle is not CandidateLifecycle.COMMIT_PENDING:
        raise RuntimeError(f"propose:{proposed.candidate_state.lifecycle}")


def run_b6_sqlite_negatives(run_dir: Path, git_sha: str) -> dict[str, Any]:
    (
        sqlite_tests,
        RequestOutcome,
        Signature,
        ReplayCommitRequest,
        SQLiteAuthorityStore,
    ) = _b6_helpers()
    path = run_dir / "b6-sqlite" / "authority.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    start = _utc()
    records: list[dict[str, Any]] = []
    store = None
    try:
        store = sqlite_tests._open_store(path, None)
        valid = _unique_request(
            sqlite_tests,
            commit_id="ql-commit-0001",
            nonce_index=1,
            node_id="node-1",
            result_bytes=OUTPUT,
        )
        _advance_candidate(store, valid, OUTPUT)
        first = store.atomic_commit(valid)
        records.append(
            {
                "cell": "b6-sqlite-negative",
                "case_id": "valid-first-commit",
                "outcome": first.decision.outcome.value,
                "reason": first.decision.reason,
                "authoritative": first.decision.outcome is RequestOutcome.COMMITTED,
                "certificate_digest": first.certificate_digest,
                "certificate_bytes": (
                    len(first.certificate_envelope_bytes)
                    if first.certificate_envelope_bytes is not None
                    else 0
                ),
            }
        )
        replay = store.atomic_commit(valid)
        same_envelope = (
            first.certificate_envelope_bytes is not None
            and replay.certificate_envelope_bytes == first.certificate_envelope_bytes
        )
        replay_via_api = store.replay_commit(
            ReplayCommitRequest(valid.commit_id, valid.request_digest)
        )
        records.append(
            {
                "cell": "b6-sqlite-negative",
                "case_id": "exact-replay",
                "outcome": replay.decision.outcome.value,
                "reason": replay.decision.reason,
                "authoritative": replay.decision.outcome is RequestOutcome.COMMITTED,
                "same_envelope_bytes": same_envelope,
                "replay_api_outcome": replay_via_api.decision.outcome.value,
                "second_authority": (
                    replay.decision.outcome is RequestOutcome.COMMITTED
                    and replay.certificate_digest != first.certificate_digest
                ),
            }
        )
        conflict = _unique_request(
            sqlite_tests,
            commit_id="ql-commit-0001",
            nonce_index=2,
            node_id="root",
            result_bytes=OUTPUT + b"x",
        )
        try:
            _advance_candidate(store, conflict, OUTPUT + b"x")
        except Exception as error:
            records.append(
                {
                    "cell": "b6-sqlite-negative",
                    "case_id": "commit-id-equivocation-advance",
                    "error": f"{type(error).__name__}: {error}",
                    "authoritative": False,
                }
            )
        conflicted = store.atomic_commit(conflict)
        records.append(
            {
                "cell": "b6-sqlite-negative",
                "case_id": "commit-id-equivocation",
                "outcome": conflicted.decision.outcome.value,
                "reason": conflicted.decision.reason,
                "authoritative": conflicted.decision.outcome
                is RequestOutcome.COMMITTED,
                "second_authority": conflicted.decision.outcome
                is RequestOutcome.COMMITTED,
            }
        )
        try:
            unsigned_base = _unique_request(
                sqlite_tests,
                commit_id="ql-commit-0002",
                nonce_index=3,
                node_id="middle",
                result_bytes=OUTPUT,
            )
            _advance_candidate(store, unsigned_base, OUTPUT)
            producer = unsigned_base.signatures.producer
            flipped = (
                "A" if producer.signature_b64u[0] != "A" else "B"
            ) + producer.signature_b64u[1:]
            tampered_sig = Signature(producer.algorithm, producer.key_id, flipped)
            tampered = replace(
                unsigned_base,
                signatures=replace(unsigned_base.signatures, producer=tampered_sig),
            )
            denied = store.atomic_commit(tampered)
            records.append(
                {
                    "cell": "b6-sqlite-negative",
                    "case_id": "invalid-commit-request",
                    "outcome": denied.decision.outcome.value,
                    "reason": denied.decision.reason,
                    "authoritative": denied.decision.outcome
                    is RequestOutcome.COMMITTED,
                    "construction": "tampered-producer-signature",
                }
            )
        except Exception as error:
            records.append(
                {
                    "cell": "b6-sqlite-negative",
                    "case_id": "invalid-commit-request",
                    "outcome": "construction-or-commit-error",
                    "error": f"{type(error).__name__}: {error}",
                    "authoritative": False,
                    "construction": "failed",
                }
            )
    except Exception as error:
        records.append(
            {
                "cell": "b6-sqlite-negative",
                "case_id": "harness",
                "error": f"{type(error).__name__}: {error}",
                "traceback": traceback.format_exc(limit=12),
            }
        )
    finally:
        if store is not None and hasattr(store, "close"):
            try:
                store.close()
            except Exception:
                pass
    out = run_dir / "b6-sqlite-negatives.jsonl"
    for record in records:
        record.update({"git_sha": git_sha, "protocol_id": PROTOCOL_ID, "seed": SEED})
        _append(out, record)
    invalid_authority = sum(
        1
        for record in records
        if record.get("second_authority") is True
        or (
            record.get("case_id")
            in {"commit-id-equivocation", "invalid-commit-request"}
            and record.get("authoritative") is True
        )
    )
    return {
        "start_utc": start,
        "end_utc": _utc(),
        "artifact": str(out.relative_to(ROOT)),
        "cases": [record.get("case_id") for record in records],
        "invalid_authoritative_commits": invalid_authority,
        "records": records,
    }


def _b6_negative_cases(
    store: Any,
    sqlite_tests: Any,
    RequestOutcome: Any,
    Signature: Any,
    ReplayCommitRequest: Any,
    *,
    cell: str,
    commit_prefix: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    valid = _unique_request(
        sqlite_tests,
        commit_id=f"{commit_prefix}-0001",
        nonce_index=1,
        node_id="node-1",
        result_bytes=OUTPUT,
    )
    _advance_candidate(store, valid, OUTPUT)
    first = store.atomic_commit(valid)
    records.append(
        {
            "cell": cell,
            "case_id": "valid-first-commit",
            "outcome": first.decision.outcome.value,
            "reason": first.decision.reason,
            "authoritative": first.decision.outcome is RequestOutcome.COMMITTED,
            "certificate_digest": first.certificate_digest,
            "certificate_bytes": (
                len(first.certificate_envelope_bytes)
                if first.certificate_envelope_bytes is not None
                else 0
            ),
        }
    )
    replay = store.atomic_commit(valid)
    same_envelope = (
        first.certificate_envelope_bytes is not None
        and replay.certificate_envelope_bytes == first.certificate_envelope_bytes
    )
    replay_via_api = store.replay_commit(
        ReplayCommitRequest(valid.commit_id, valid.request_digest)
    )
    records.append(
        {
            "cell": cell,
            "case_id": "exact-replay",
            "outcome": replay.decision.outcome.value,
            "reason": replay.decision.reason,
            "authoritative": replay.decision.outcome is RequestOutcome.COMMITTED,
            "same_envelope_bytes": same_envelope,
            "replay_api_outcome": replay_via_api.decision.outcome.value,
            "second_authority": (
                replay.decision.outcome is RequestOutcome.COMMITTED
                and replay.certificate_digest != first.certificate_digest
            ),
        }
    )
    conflict = _unique_request(
        sqlite_tests,
        commit_id=f"{commit_prefix}-0001",
        nonce_index=2,
        node_id="root",
        result_bytes=OUTPUT + b"x",
    )
    try:
        _advance_candidate(store, conflict, OUTPUT + b"x")
    except Exception as error:
        records.append(
            {
                "cell": cell,
                "case_id": "commit-id-equivocation-advance",
                "error": f"{type(error).__name__}: {error}",
                "authoritative": False,
            }
        )
    conflicted = store.atomic_commit(conflict)
    records.append(
        {
            "cell": cell,
            "case_id": "commit-id-equivocation",
            "outcome": conflicted.decision.outcome.value,
            "reason": conflicted.decision.reason,
            "authoritative": conflicted.decision.outcome is RequestOutcome.COMMITTED,
            "second_authority": conflicted.decision.outcome is RequestOutcome.COMMITTED,
        }
    )
    try:
        unsigned_base = _unique_request(
            sqlite_tests,
            commit_id=f"{commit_prefix}-0002",
            nonce_index=3,
            node_id="middle",
            result_bytes=OUTPUT,
        )
        _advance_candidate(store, unsigned_base, OUTPUT)
        producer = unsigned_base.signatures.producer
        flipped = (
            "A" if producer.signature_b64u[0] != "A" else "B"
        ) + producer.signature_b64u[1:]
        tampered_sig = Signature(producer.algorithm, producer.key_id, flipped)
        tampered = replace(
            unsigned_base,
            signatures=replace(unsigned_base.signatures, producer=tampered_sig),
        )
        denied = store.atomic_commit(tampered)
        records.append(
            {
                "cell": cell,
                "case_id": "invalid-commit-request",
                "outcome": denied.decision.outcome.value,
                "reason": denied.decision.reason,
                "authoritative": denied.decision.outcome is RequestOutcome.COMMITTED,
                "construction": "tampered-producer-signature",
            }
        )
    except Exception as error:
        records.append(
            {
                "cell": cell,
                "case_id": "invalid-commit-request",
                "outcome": "construction-or-commit-error",
                "error": f"{type(error).__name__}: {error}",
                "authoritative": False,
            }
        )
    return records


def run_b6_postgres_negatives(run_dir: Path, git_sha: str) -> dict[str, Any]:
    start = _utc()
    dsn = os.environ.get("APCC_POSTGRES_DSN")
    if not dsn:
        return {
            "start_utc": start,
            "end_utc": _utc(),
            "status": "BLOCKED_MISSING_SERVICE",
            "reason": "APCC_POSTGRES_DSN unset",
        }
    sqlite_tests, RequestOutcome, Signature, ReplayCommitRequest, _ = _b6_helpers()
    import tests.test_apcc_postgres as pg_tests

    env_gen = pg_tests.postgres_environment()
    store = None
    records: list[dict[str, Any]] = []
    try:
        env = next(env_gen)
        harness = pg_tests._harness(env)
        store = harness.open_store(run_dir / "b6-postgres-marker", None)
        records = _b6_negative_cases(
            store,
            sqlite_tests,
            RequestOutcome,
            Signature,
            ReplayCommitRequest,
            cell="b6-postgres-negative",
            commit_prefix="ql-commit-pg",
        )
    except Exception as error:
        return {
            "start_utc": start,
            "end_utc": _utc(),
            "status": "error",
            "error": f"{type(error).__name__}: {error}",
            "traceback": traceback.format_exc(limit=12),
            "git_sha": git_sha,
            "protocol_id": PROTOCOL_ID,
        }
    finally:
        if store is not None and hasattr(store, "close"):
            try:
                store.close()
            except Exception:
                pass
        try:
            env_gen.close()
        except Exception:
            pass
    out = run_dir / "b6-postgres-negatives.jsonl"
    for record in records:
        record.update({"git_sha": git_sha, "protocol_id": PROTOCOL_ID, "seed": SEED})
        _append(out, record)
    invalid_authority = sum(
        1
        for record in records
        if record.get("second_authority") is True
        or (
            record.get("case_id")
            in {"commit-id-equivocation", "invalid-commit-request"}
            and record.get("authoritative") is True
        )
    )
    return {
        "start_utc": start,
        "end_utc": _utc(),
        "status": "LIVE_MEASURED",
        "store": "postgresql",
        "artifact": str(out.relative_to(ROOT)),
        "cases": [record.get("case_id") for record in records],
        "invalid_authoritative_commits": invalid_authority,
        "records": records,
    }


def _measure_loop(
    label: str,
    operation: Callable[[], None],
    duration_s: int,
    target_rate: int,
) -> dict[str, Any]:
    samples: list[int] = []
    failures = 0
    t0 = time.perf_counter()
    deadline = t0 + duration_s
    interval = 1.0 / target_rate
    next_beat = t0
    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if now < next_beat:
            time.sleep(next_beat - now)
        started = time.perf_counter_ns()
        try:
            operation()
            samples.append(time.perf_counter_ns() - started)
        except Exception:
            failures += 1
            samples.append(time.perf_counter_ns() - started)
        next_beat += interval
        if next_beat < time.perf_counter() - 1:
            next_beat = time.perf_counter()
    wall = max(time.perf_counter() - t0, 1e-9)
    completed = len(samples) - failures
    return {
        "label": label,
        "completed_operations": completed,
        "failures": failures,
        "attempted": len(samples),
        "duration_seconds": wall,
        "scheduled_duration_seconds": duration_s,
        "ops_per_second": completed / wall,
        "p50_ns": _percentile(samples, 50),
        "p95_ns": _percentile(samples, 95),
        "p99_ns": _percentile(samples, 99),
        "incomplete_run": completed < MIN_OPS,
        "sample_count": len(samples),
        "pacer": PACER,
        "target_rate_enforced": True,
    }


def run_performance(run_dir: Path, git_sha: str) -> dict[str, Any]:
    out = run_dir / "performance.jsonl"
    summary: dict[str, Any] = {"baselines": {}, "b5_blocked": None}
    start = _utc()
    b5_blocked = False

    def execute_adapter(
        baseline_id: str, db: Path
    ) -> tuple[Callable[[], None], Callable[[], None] | None]:
        adapter = create_baseline_adapter(baseline_id, db)
        payload = PAYLOAD
        stimulus = TrialStimulus.control(payload)

        def op() -> None:
            adapter.execute(stimulus)

        return op, getattr(adapter, "close", None)

    for baseline_id in ("B0", "B1", "B2", "B3", "B4", "B5"):
        runs: list[dict[str, Any]] = []
        if baseline_id == "B5" and b5_blocked:
            summary["baselines"][baseline_id] = {"status": "BLOCKED_TIMEOUT"}
            continue
        for phase, count in (("warmup", WARMUPS), ("measured", MEASURED)):
            for index in range(count):
                db = run_dir / "perf-db" / f"{baseline_id}-{phase}-{index}.db"
                db.parent.mkdir(parents=True, exist_ok=True)
                closer = None
                try:
                    if baseline_id == "B5":
                        init_start = time.perf_counter()
                        adapter = create_baseline_adapter(baseline_id, db)
                        init_s = time.perf_counter() - init_start
                        if init_s > B5_INIT_TIMEOUT_S:
                            b5_blocked = True
                            summary["b5_blocked"] = {
                                "phase": phase,
                                "index": index,
                                "init_seconds": init_s,
                            }
                            record = {
                                "cell": "performance",
                                "baseline_id": baseline_id,
                                "phase": phase,
                                "repetition": index,
                                "status": "BLOCKED_TIMEOUT",
                                "init_seconds": init_s,
                            }
                            _append(out, record)
                            break
                        closer = adapter.close
                        payload = PAYLOAD
                        stimulus = TrialStimulus.control(payload)

                        def op(adapter=adapter, stimulus=stimulus) -> None:
                            adapter.execute(stimulus)

                    else:
                        op, closer = execute_adapter(baseline_id, db)
                    result = _measure_loop(
                        f"{baseline_id}-{phase}-{index}",
                        op,
                        DURATION_S,
                        TARGET_RATE,
                    )
                    result.update(
                        {
                            "cell": "performance",
                            "baseline_id": baseline_id,
                            "phase": phase,
                            "repetition": index,
                            "git_sha": git_sha,
                            "protocol_id": PROTOCOL_ID,
                            "seed": SEED,
                            "target_rate_per_second": TARGET_RATE,
                            "input_bytes": 1024,
                            "output_bytes": 4096,
                            "store": "sqlite",
                        }
                    )
                    _append(out, result)
                    if phase == "measured":
                        runs.append(result)
                except Exception as error:
                    record = {
                        "cell": "performance",
                        "baseline_id": baseline_id,
                        "phase": phase,
                        "repetition": index,
                        "status": "error",
                        "error": f"{type(error).__name__}: {error}",
                        "traceback": traceback.format_exc(limit=8),
                        "git_sha": git_sha,
                    }
                    _append(out, record)
                    if baseline_id == "B5":
                        b5_blocked = True
                        break
                finally:
                    if closer is not None:
                        try:
                            closer()
                        except Exception:
                            pass
            else:
                continue
            break
        if runs:
            ops = [item["ops_per_second"] for item in runs]
            p95 = [item["p95_ns"] for item in runs if item["p95_ns"] is not None]
            summary["baselines"][baseline_id] = {
                "measured_runs": len(runs),
                "median_ops_per_second": statistics.median(ops) if ops else None,
                "median_p95_ns": int(statistics.median(p95)) if p95 else None,
                "incomplete_runs": sum(1 for item in runs if item["incomplete_run"]),
                "status": "LIVE_MEASURED",
                "pacer": PACER,
            }

    sqlite_tests, RequestOutcome, _Signature, _Replay, SQLiteAuthorityStore = (
        _b6_helpers()
    )
    b6_dir = run_dir / "perf-b6-sqlite"
    b6_dir.mkdir(parents=True, exist_ok=True)
    b6_runs: list[dict[str, Any]] = []
    for phase, count in (("warmup", WARMUPS), ("measured", MEASURED)):
        for index in range(count):
            db = b6_dir / f"{phase}-{index}.sqlite3"
            store = None
            counter = {"n": 0}
            try:
                contexts = []
                vector_tests = sqlite_tests

                def initial_context(node_id: str):
                    return vector_tests._initial_contexts()[0].__class__

                from constitutional_swarm.apcc.model import (
                    CandidateLifecycle,
                    CandidateState,
                    LogicalNodeState,
                )
                from constitutional_swarm.apcc.ports import CommitContext
                from constitutional_swarm.apcc.model import CommitCertificate

                certificate = CommitCertificate.from_object(
                    sqlite_tests.valid_vector().payload
                )

                def make_ctx(node_id: str) -> CommitContext:
                    subject = replace(
                        certificate.subject, workflow_id="workflow-1", node_id=node_id
                    )
                    return CommitContext(
                        subject=subject,
                        governance=certificate.context,
                        candidate_state=CandidateState(
                            subject.workflow_id,
                            subject.node_id,
                            subject.attempt_id,
                            CandidateLifecycle.EXECUTING,
                        ),
                        logical_node_state=LogicalNodeState(
                            subject.workflow_id, subject.node_id, "0", None
                        ),
                        predecessors=(),
                        audit_event_id=f"bootstrap-{node_id}",
                    )

                initial = tuple(make_ctx(f"ql-node-{n}") for n in range(B6_NODES))
                SQLiteAuthorityStore.provision(
                    db,
                    config=sqlite_tests._config(),
                    initial_contexts=initial,
                    runtime=sqlite_tests._runtime(),
                )
                store = SQLiteAuthorityStore.open(
                    db, config=sqlite_tests._config(), runtime=sqlite_tests._runtime()
                )

                def op(store=store, counter=counter) -> None:
                    n = counter["n"]
                    if n >= B6_NODES:
                        raise RuntimeError("node-space-exhausted")
                    request = _unique_request(
                        sqlite_tests,
                        commit_id=f"ql-perf-{phase}-{index}-{n:06d}",
                        nonce_index=1_000_000 + index * 10_000 + n,
                        node_id=f"ql-node-{n}",
                        result_bytes=OUTPUT,
                    )
                    _advance_candidate(store, request, OUTPUT)
                    result = store.atomic_commit(request)
                    if result.decision.outcome is not RequestOutcome.COMMITTED:
                        raise RuntimeError(
                            f"b6-commit-{result.decision.outcome}:{result.decision.reason}"
                        )
                    counter["n"] = n + 1

                result = _measure_loop(
                    f"B6-{phase}-{index}", op, DURATION_S, TARGET_RATE
                )
                result.update(
                    {
                        "cell": "performance",
                        "baseline_id": "B6",
                        "phase": phase,
                        "repetition": index,
                        "git_sha": git_sha,
                        "protocol_id": PROTOCOL_ID,
                        "seed": SEED,
                        "store": "sqlite",
                        "workload": "QL-INDEP-NODE",
                        "target_rate_per_second": TARGET_RATE,
                        "nodes_used": counter["n"],
                    }
                )
                _append(out, result)
                if phase == "measured":
                    b6_runs.append(result)
            except Exception as error:
                record = {
                    "cell": "performance",
                    "baseline_id": "B6",
                    "phase": phase,
                    "repetition": index,
                    "status": "error",
                    "error": f"{type(error).__name__}: {error}",
                    "traceback": traceback.format_exc(limit=12),
                    "git_sha": git_sha,
                    "store": "sqlite",
                }
                _append(out, record)
            finally:
                if store is not None and hasattr(store, "close"):
                    try:
                        store.close()
                    except Exception:
                        pass
    if b6_runs:
        ops = [item["ops_per_second"] for item in b6_runs]
        p95 = [item["p95_ns"] for item in b6_runs if item["p95_ns"] is not None]
        summary["baselines"]["B6"] = {
            "measured_runs": len(b6_runs),
            "median_ops_per_second": statistics.median(ops) if ops else None,
            "median_p95_ns": int(statistics.median(p95)) if p95 else None,
            "incomplete_runs": sum(1 for item in b6_runs if item["incomplete_run"]),
            "status": "LIVE_MEASURED",
            "workload": "QL-INDEP-NODE",
            "pacer": PACER,
        }
    else:
        summary["baselines"]["B6"] = {"status": "error-or-empty"}
    summary["baselines"]["B6-postgresql"] = {"status": "BLOCKED_MISSING_DEPENDENCY"}
    return {
        "start_utc": start,
        "end_utc": _utc(),
        "artifact": str(out.relative_to(ROOT)),
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="APCC-1 qualification-live v2")
    parser.add_argument("--scenarios", action="store_true")
    parser.add_argument("--b6-sqlite", action="store_true")
    parser.add_argument("--b6-postgres", action="store_true")
    parser.add_argument("--performance", action="store_true")
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()
    selected = args.scenarios or args.b6_sqlite or args.b6_postgres or args.performance
    if not selected:
        args.scenarios = args.b6_sqlite = args.performance = True
    git_sha = _git_sha()
    run_id = args.run_id or datetime.now(timezone.utc).strftime("ql-%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "experiments" / "apcc-1" / "qualification-live" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(run_dir, 0o700)
    report: dict[str, Any] = {
        "protocol_id": PROTOCOL_ID,
        "git_sha": git_sha,
        "run_id": run_id,
        "start_utc": _utc(),
        "worktree": str(ROOT),
        "frozen_pair": {
            "postgres_store.py": _sha256_file(
                ROOT / "src/constitutional_swarm/apcc/postgres_store.py"
            ),
            "test_apcc_postgres.py": _sha256_file(ROOT / "tests/test_apcc_postgres.py"),
        },
    }
    if args.scenarios:
        report["scenarios"] = run_scenarios(run_dir, git_sha)
    if args.b6_sqlite:
        report["b6_sqlite_negatives"] = run_b6_sqlite_negatives(run_dir, git_sha)
    if args.b6_postgres:
        report["b6_postgres_negatives"] = run_b6_postgres_negatives(run_dir, git_sha)
    if args.performance:
        report["performance"] = run_performance(run_dir, git_sha)
    report["end_utc"] = _utc()
    summary_path = run_dir / "summary.json"
    _write_json(summary_path, report)
    manifest = {}
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.sha256":
            manifest[str(path.relative_to(run_dir))] = _sha256_file(path)
    (run_dir / "MANIFEST.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(manifest.items())),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {"run_id": run_id, "git_sha": git_sha, "summary": str(summary_path)},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
