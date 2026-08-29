from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import TypedDict

import pytest

import constitutional_swarm.apcc_empirical.artifacts as artifacts_module
from constitutional_swarm.apcc_empirical.artifacts import (
    ArtifactViolation,
    REVIEWED_MATRIX_SHA256,
    REVIEWED_SCHEMA_SHA256,
    RawArtifactWriter,
    read_artifact_run,
)
from constitutional_swarm.apcc_empirical.contract import (
    ExperimentMatrix,
    canonical_json_bytes,
    derive_attack_trial,
    load_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "experiments" / "apcc-1" / "matrix.v1.json"
SCHEMA_PATH = ROOT / "experiments" / "apcc-1" / "raw-result.schema.json"


class _WriterArgs(TypedDict):
    matrix: ExperimentMatrix
    matrix_path: Path
    schema_path: Path
    planned_trial_ids: list[str]
    environment: dict[str, str]
    environment_id: str
    git_sha: str
    tool_versions: dict[str, str]


def _record(
    matrix: ExperimentMatrix, attack_id: str, trial_index: int
) -> dict[str, object]:
    trial = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id=attack_id,
        trial_index=trial_index,
    )
    return {
        "ablation_id": None,
        "ablation_classification": None,
        "artifact_sha256": "1" * 64,
        "attack_id": attack_id,
        "authoritative_compromise": False,
        "authoritative_outcome": "none",
        "baseline_id": "B6",
        "byte_counts": {"certificate": 0},
        "cache_state": "cold",
        "case_index": None,
        "condition_id": None,
        "concurrency": 1,
        "cost_saved_ns": None,
        "dag": "single-node",
        "database_index": None,
        "detected": True,
        "distinct_states": None,
        "environment_id": "test",
        "fail_closed": True,
        "failed_invariant": None,
        "failure_code": "EXPECTED_REJECTION",
        "fault_target": None,
        "formal_evidence": None,
        "generated_states": None,
        "git_sha": "0" * 40,
        "incorrect_current_consumption": False,
        "input_bytes": 1024,
        "matrix_revision": matrix.revision,
        "matrix_sha256": matrix.matrix_sha256,
        "outcome": "rejected",
        "output_bytes": 4096,
        "phase": None,
        "record_type": "functional-attack",
        "recovered": False,
        "repetition": trial.seed_repetition,
        "schema_version": "apcc-1.raw-result.v1",
        "search_depth": None,
        "seed": trial.seed,
        "store": "sqlite",
        "sub_seed_b64u": trial.sub_seed_b64u,
        "successful_commits": None,
        "target_rate_per_second": 10,
        "timings_ns": {"total": 1},
        "tool_versions": {"python": "test"},
        "trial_id": trial.trial_id,
        "trial_index": trial.trial_index,
        "witness_marker": None,
        "workload_id": "W1",
        "workload_evidence": {
            "agents": 1,
            "completed_operations": 1,
            "duration_seconds": None,
            "incomplete_run": False,
            "lifecycle_mode": "single-trial",
            "nodes": 1,
            "operation_limit": None,
            "parameters": {},
            "payload_pair": [1024, 4096],
            "pre_run_queries": 0,
            "schedule": "none",
            "warmup_runs_completed": 0,
        },
    }


def test_writer_promotes_only_complete_ordered_validated_run(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    records = [
        _record(matrix, "missing-proof", 0),
        _record(matrix, "invalid-signature", 0),
    ]
    writer = RawArtifactWriter(
        tmp_path,
        "run-001",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(item["trial_id"]) for item in records],
        environment={"os": "test"},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    assert not (tmp_path / "run-001").exists()
    for record in records:
        writer.append(record)
    run = writer.finalize()
    loaded = read_artifact_run(run)
    assert loaded.record_count == 2
    assert (
        loaded.raw_sha256
        == hashlib.sha256(
            b"".join(canonical_json_bytes(item) for item in records)
        ).hexdigest()
    )
    assert not (run / "raw.jsonl.partial").exists()


def test_writer_rejects_duplicate_out_of_order_and_existing_run(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    first = _record(matrix, "missing-proof", 0)
    second = _record(matrix, "invalid-signature", 0)
    kwargs: _WriterArgs = {
        "matrix": matrix,
        "matrix_path": MATRIX_PATH,
        "schema_path": SCHEMA_PATH,
        "planned_trial_ids": [str(first["trial_id"]), str(second["trial_id"])],
        "environment": {},
        "environment_id": "test",
        "git_sha": "0" * 40,
        "tool_versions": {"python": "test"},
    }
    writer = RawArtifactWriter(tmp_path, "ordered", **kwargs)
    with pytest.raises(ArtifactViolation, match="planner order"):
        writer.append(second)
    writer.abort()
    replacement = RawArtifactWriter(tmp_path, "ordered", **kwargs)
    replacement.abort()


def test_crash_partial_is_not_promoted_and_reader_rejects_tamper(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _record(matrix, "missing-proof", 0)
    kwargs: _WriterArgs = {
        "matrix": matrix,
        "matrix_path": MATRIX_PATH,
        "schema_path": SCHEMA_PATH,
        "planned_trial_ids": [str(record["trial_id"])],
        "environment": {},
        "environment_id": "test",
        "git_sha": "0" * 40,
        "tool_versions": {"python": "test"},
    }
    crashed = RawArtifactWriter(tmp_path, "crashed", **kwargs)
    crashed.append(record)
    crashed.abort()
    assert not (tmp_path / "crashed").exists()
    assert not any(item.name.startswith(".crashed.") for item in tmp_path.iterdir())

    writer = RawArtifactWriter(tmp_path, "tamper", **kwargs)
    writer.append(record)
    run = writer.finalize()
    (run / "raw.jsonl").write_bytes(b"{}\n")
    with pytest.raises(ArtifactViolation, match="hash"):
        read_artifact_run(run)


def test_reader_rejects_traversal_symlink_extra_and_reordered_sums(
    tmp_path: Path,
) -> None:
    with pytest.raises(ArtifactViolation, match="run id"):
        RawArtifactWriter(
            tmp_path,
            "../escape",
            matrix=load_matrix(MATRIX_PATH),
            matrix_path=MATRIX_PATH,
            schema_path=SCHEMA_PATH,
            planned_trial_ids=[],
            environment={},
            environment_id="test",
            git_sha="0" * 40,
            tool_versions={"python": "test"},
        )
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    os.symlink(target, link)
    with pytest.raises(ArtifactViolation, match="open artifact run"):
        read_artifact_run(link)


def test_reader_rejects_extra_file_and_reordered_hash_manifest(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _record(matrix, "missing-proof", 0)
    writer = RawArtifactWriter(
        tmp_path,
        "reader-adversary",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"])],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    writer.append(record)
    run = writer.finalize()
    extra = run / "unexpected"
    extra.write_text("extra", encoding="utf-8")
    with pytest.raises(ArtifactViolation, match="missing or extra"):
        read_artifact_run(run)
    extra.unlink()
    sums = run / "SHA256SUMS"
    lines = sums.read_bytes().splitlines(keepends=True)
    sums.write_bytes(b"".join(reversed(lines)))
    with pytest.raises(ArtifactViolation, match="reordered"):
        read_artifact_run(run)


def test_reviewed_contract_hashes_are_pinned() -> None:
    assert (
        REVIEWED_MATRIX_SHA256 == hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest()
    )
    assert (
        REVIEWED_SCHEMA_SHA256 == hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    )


def _rehash_run(run: Path) -> None:
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    raw = (run / "raw.jsonl").read_bytes()
    manifest["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    manifest["raw_size_bytes"] = len(raw)
    records = [json.loads(line) for line in raw.splitlines()]
    manifest["trial_ids"] = [record["trial_id"] for record in records]
    manifest["schema_sha256"] = hashlib.sha256(
        (run / "raw-result.schema.json").read_bytes()
    ).hexdigest()
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    names = ("manifest.json", "matrix.v1.json", "raw-result.schema.json", "raw.jsonl")
    (run / "SHA256SUMS").write_bytes(
        b"".join(
            f"{hashlib.sha256((run / name).read_bytes()).hexdigest()}  {name}\n".encode()
            for name in sorted(names)
        )
    )


def test_reader_rejects_reordered_records_even_with_recomputed_hashes(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    records = [
        _record(matrix, "missing-proof", 0),
        _record(matrix, "invalid-signature", 0),
    ]
    writer = RawArtifactWriter(
        tmp_path,
        "reordered-records",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"]) for record in records],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    for record in records:
        writer.append(record)
    run = writer.finalize()
    (run / "raw.jsonl").write_bytes(
        b"".join(canonical_json_bytes(record) for record in reversed(records))
    )
    _rehash_run(run)
    with pytest.raises(ArtifactViolation, match="frozen planner order"):
        read_artifact_run(run)


def test_reader_rejects_rehashed_unreviewed_schema(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _record(matrix, "missing-proof", 0)
    writer = RawArtifactWriter(
        tmp_path,
        "invalid-schema",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"])],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    writer.append(record)
    run = writer.finalize()
    (run / "raw-result.schema.json").write_bytes(b'{"type":"object"}\n')
    _rehash_run(run)
    with pytest.raises(ArtifactViolation, match="reviewed schema"):
        read_artifact_run(run)


@pytest.mark.parametrize("tamper", ["symlink", "mode", "oversized"])
def test_reader_uses_bounded_nofollow_private_descriptor_reads(
    tmp_path: Path, tamper: str
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _record(matrix, "missing-proof", 0)
    writer = RawArtifactWriter(
        tmp_path,
        f"descriptor-{tamper}",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"])],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    writer.append(record)
    run = writer.finalize()
    raw_path = run / "raw.jsonl"
    if tamper == "symlink":
        raw_path.unlink()
        os.symlink(MATRIX_PATH, raw_path)
        match = "read artifact raw.jsonl"
    elif tamper == "mode":
        raw_path.chmod(0o666)
        match = "writable"
    else:
        (run / "manifest.json").write_bytes(b"x" * ((1 << 20) + 1))
        match = "bounded size"
    with pytest.raises(ArtifactViolation, match=match):
        read_artifact_run(run)


def test_writer_rejects_record_provenance_mismatch_before_append(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    base = _record(matrix, "missing-proof", 0)
    for field, value in (
        ("git_sha", "f" * 40),
        ("environment_id", "other"),
        ("tool_versions", {"python": "other"}),
        ("matrix_sha256", "f" * 64),
        ("schema_version", "apcc-1.raw-result.other"),
    ):
        writer = RawArtifactWriter(
            tmp_path,
            f"mismatch-{field}",
            matrix=matrix,
            matrix_path=MATRIX_PATH,
            schema_path=SCHEMA_PATH,
            planned_trial_ids=[str(base["trial_id"])],
            environment={},
            environment_id="test",
            git_sha="0" * 40,
            tool_versions={"python": "test"},
        )
        with pytest.raises(ArtifactViolation, match="provenance"):
            writer.append({**base, field: value})
        writer.abort()


def test_reader_rejects_rehashed_record_provenance_mismatch(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _record(matrix, "missing-proof", 0)
    writer = RawArtifactWriter(
        tmp_path,
        "rehashed-provenance",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[str(record["trial_id"])],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    writer.append(record)
    run = writer.finalize()
    record["git_sha"] = "f" * 40
    (run / "raw.jsonl").write_bytes(canonical_json_bytes(record))
    _rehash_run(run)
    with pytest.raises(ArtifactViolation, match="provenance"):
        read_artifact_run(run)


def test_manifest_schema_is_exact(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    writer = RawArtifactWriter(
        tmp_path,
        "manifest-schema",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    run = writer.finalize()
    manifest = json.loads((run / "manifest.json").read_bytes())
    assert set(manifest) == {
        "environment",
        "environment_id",
        "git_sha",
        "matrix_revision",
        "matrix_sha256",
        "raw_record_count",
        "raw_sha256",
        "raw_size_bytes",
        "schema_sha256",
        "schema_version",
        "tool_versions",
        "trial_ids",
    }


@pytest.mark.parametrize("nonempty", [False, True])
def test_finalize_atomically_refuses_late_created_target(
    tmp_path: Path, nonempty: bool
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    writer = RawArtifactWriter(
        tmp_path,
        "late-target",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )
    target = tmp_path / "late-target"
    target.mkdir()
    if nonempty:
        (target / "owner").write_text("late creator", encoding="utf-8")
    with pytest.raises(ArtifactViolation, match="already exists"):
        writer.finalize()
    assert target.is_dir()
    if nonempty:
        assert (target / "owner").read_text() == "late creator"
    else:
        assert not tuple(target.iterdir())
    assert not any(item.name.endswith(".partial") for item in tmp_path.iterdir())


def test_constructor_and_reader_failures_do_not_leak_descriptors_or_staging(
    tmp_path: Path,
) -> None:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        pytest.skip("Linux descriptor accounting requires /proc")
    matrix = load_matrix(MATRIX_PATH)
    before = len(tuple(descriptor_root.iterdir()))
    for index in range(20):
        with pytest.raises(ArtifactViolation, match="matrix source"):
            RawArtifactWriter(
                tmp_path,
                f"constructor-{index}",
                matrix=matrix,
                matrix_path=tmp_path / "missing-matrix",
                schema_path=SCHEMA_PATH,
                planned_trial_ids=[],
                environment={},
                environment_id="test",
                git_sha="0" * 40,
                tool_versions={"python": "test"},
            )
        with pytest.raises(ArtifactViolation):
            read_artifact_run(tmp_path / f"missing-{index}")
    after = len(tuple(descriptor_root.iterdir()))
    assert after <= before + 1
    assert not any(item.name.endswith(".partial") for item in tmp_path.iterdir())


def test_constructor_removes_staging_if_open_fails_immediately_after_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        pytest.skip("Linux descriptor accounting requires /proc")
    matrix = load_matrix(MATRIX_PATH)
    real_open = artifacts_module.os.open
    before = len(tuple(descriptor_root.iterdir()))

    def fail_staging_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if (
            isinstance(path, str)
            and path.endswith(".partial")
            and flags & artifacts_module._DIRECTORY
            and dir_fd is not None
        ):
            raise OSError("injected staging open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(artifacts_module.os, "open", fail_staging_open)
    with pytest.raises(ArtifactViolation, match="staging directory"):
        RawArtifactWriter(
            tmp_path,
            "open-failure",
            matrix=matrix,
            matrix_path=MATRIX_PATH,
            schema_path=SCHEMA_PATH,
            planned_trial_ids=[],
            environment={},
            environment_id="test",
            git_sha="0" * 40,
            tool_versions={"python": "test"},
        )

    after = len(tuple(descriptor_root.iterdir()))
    assert after <= before + 1
    assert not any(item.name.endswith(".partial") for item in tmp_path.iterdir())
