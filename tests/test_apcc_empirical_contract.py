from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, TypeAlias, cast

import jsonschema
import pytest

import constitutional_swarm.apcc_empirical.contract as contract_module
from constitutional_swarm.apcc_empirical.contract import (
    ContractViolation,
    ExperimentMatrix,
    HashCounterPRNG,
    baseline_order,
    canonical_json_bytes,
    derive_attack_trial,
    load_matrix,
    load_raw_result,
    planning_cardinalities,
    planned_attack_trials,
    planned_ablation_trials,
    planned_formal_runs,
    planned_parser_trials,
    planned_performance_runs,
    planned_race_recovery_trials,
    planned_storage_runs,
    planned_timing_trials,
    store_order,
    validate_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "experiments" / "apcc-1" / "matrix.v1.json"
RAW_SCHEMA_PATH = ROOT / "experiments" / "apcc-1" / "raw-result.schema.json"

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)

ATTACK_IDS = (
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
)

ABLATION_IDS = (
    "atomic-validation-and-commit",
    "policy-epoch-binding",
    "authority-epoch-binding",
    "revocation-generation",
    "attempt-binding",
    "predecessor-certificate-binding",
    "stable-commit-id",
    "nonce-replay-fence",
    "independent-certificate-verification",
    "staging-invisibility",
    "downstream-certificate-and-current-status-requirement",
    "transactional-outbox",
)


def test_frozen_matrix_has_exact_named_dimensions_and_settings() -> None:
    matrix = load_matrix(MATRIX_PATH)

    assert matrix.revision == "apcc-1.matrix.v1"
    assert tuple(item.id for item in matrix.baselines) == tuple(
        f"B{i}" for i in range(7)
    )
    assert tuple(item.id for item in matrix.attacks) == ATTACK_IDS
    assert tuple(item.id for item in matrix.ablations) == ABLATION_IDS
    assert tuple(item.id for item in matrix.workloads) == tuple(
        f"W{i}" for i in range(1, 11)
    )
    assert matrix.stores == ("sqlite", "postgresql")
    assert matrix.target_rates_per_second == (10, 100, 500)
    assert matrix.cache_states == ("cold", "warm")
    assert matrix.seeds == (104729, 130363, 155921, 196613, 262147)
    assert tuple((item.id, item.name) for item in matrix.fault_targets) == (
        ("validator-crash", "validator-crash"),
        ("verifier-crash", "validator-crash"),
    )

    repetitions = matrix.repetitions
    assert repetitions.functional_attack_trials_per_cell == 30
    assert repetitions.functional_attack_trials_per_seed == 6
    assert repetitions.race_recovery_trials_per_condition == 100
    assert repetitions.race_recovery_trials_per_seed == 20
    assert repetitions.parser_vectors_per_build == 126
    assert repetitions.generated_parser_cases_per_seed == 10_000
    assert repetitions.unreported_warmups == 3
    assert repetitions.measured_runs == 10
    assert repetitions.run_duration_seconds == 30
    assert repetitions.minimum_completed_operations == 10_000
    assert repetitions.timing_repetitions == 30
    assert repetitions.timing_repetitions_per_seed == 6
    assert repetitions.storage_commits == 100_000
    assert repetitions.storage_fresh_databases == 3


def test_workloads_preserve_frozen_shapes() -> None:
    matrix = load_matrix(MATRIX_PATH)
    workloads = {item.id: item for item in matrix.workloads}

    assert (
        workloads["W1"].nodes,
        workloads["W1"].agents,
        workloads["W1"].concurrency,
    ) == (
        1,
        1,
        1,
    )
    assert (workloads["W2"].dag, workloads["W2"].nodes) == ("linear", 100)
    assert (workloads["W3"].dag, workloads["W3"].fan_out) == ("fan-out", 100)
    assert (workloads["W4"].dag, workloads["W4"].fan_in) == ("fan-in", 100)
    assert workloads["W5"].competing_attempts == 100
    assert (workloads["W6"].nodes, workloads["W6"].agents) == (10_000, 1_000)
    assert workloads["W7"].policy_update_ratio == 0.01
    assert (
        workloads["W8"].actor_revocation_ratio,
        workloads["W8"].workflow_revocation_ratio,
    ) == (
        0.01,
        0.001,
    )
    assert (workloads["W9"].replay_ratio, workloads["W9"].conflicting_replay_ratio) == (
        0.5,
        0.01,
    )
    assert workloads["W10"].payload_pairs_bytes == (
        (0, 0),
        (1024, 4096),
        (65536, 262144),
    )


def test_attack_plan_has_exact_balanced_cardinality() -> None:
    matrix = load_matrix(MATRIX_PATH)
    trials = tuple(planned_attack_trials(matrix))

    # B0-B5 run SQLite; B6 runs SQLite and PostgreSQL.
    assert len(trials) == 8 * 32 * 30 == 7_680
    assert len({trial.trial_id for trial in trials}) == len(trials)
    assert len({trial.nonce for trial in trials}) == len(trials)
    assert len({trial.key for trial in trials}) == len(trials)
    for baseline_id in (f"B{i}" for i in range(7)):
        stores = ("sqlite", "postgresql") if baseline_id == "B6" else ("sqlite",)
        for store in stores:
            for attack_id in ATTACK_IDS:
                selected = [
                    trial
                    for trial in trials
                    if (trial.baseline_id, trial.store, trial.attack_id)
                    == (baseline_id, store, attack_id)
                ]
                assert len(selected) == 30
                assert {trial.seed for trial in selected} == set(matrix.seeds)
                assert {
                    seed: sum(trial.seed == seed for trial in selected)
                    for seed in matrix.seeds
                } == {seed: 6 for seed in matrix.seeds}


def test_trial_material_and_orders_are_deterministic_and_domain_separated() -> None:
    matrix = load_matrix(MATRIX_PATH)
    first = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="postgresql",
        attack_id="predecessor-set-reordering",
        trial_index=29,
    )
    second = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="postgresql",
        attack_id="predecessor-set-reordering",
        trial_index=29,
    )

    assert first == second
    assert first.seed == 262147
    assert first.seed_repetition == 5
    assert first.trial_id == "0UrvNgHgWlNzdSpDV84feKpdlZp9kHRxdDVMMBaj4Yw"
    assert (
        first.sub_seed.hex()
        == "f89e0aca05a930544708ba663dfdc50793ba367a75919b5dddf1e43e1281efbd"
    )
    assert first.nonce.hex() == "0b193a72cbd0573f83adfb9378bb5157"
    assert (
        first.key.hex()
        == "34641cb5f36b3b10ab6d94b1ac4f20de6cfab696445274d4ddbd9d6933839ced"
    )
    assert len(first.sub_seed) == len(first.key) == 32
    assert len(first.nonce) == 16
    assert len({first.sub_seed, first.key}) == 2

    assert baseline_order(matrix, 104729) == ("B6", "B1", "B4", "B0", "B2", "B3", "B5")
    assert baseline_order(matrix, 104729) == baseline_order(matrix, 104729)
    assert baseline_order(matrix, 130363) != baseline_order(matrix, 104729)
    assert store_order(matrix, 104729) == ("sqlite", "postgresql")
    assert store_order(matrix, 130363) == ("postgresql", "sqlite")


def test_hash_counter_prng_is_stable_and_rejects_invalid_bounds() -> None:
    rng = HashCounterPRNG(seed=b"seed", domain=b"test-vector")

    assert rng.read(48).hex() == (
        "403aa4d4ae26112edef80a05515e0d551a1abe6ff008a6e2dea1d5c827ef17cc"
        "2dac64e6e7080954cc7ebaa4df7ef8cd"
    )
    shuffle_rng = HashCounterPRNG(seed=b"seed", domain=b"shuffle")
    assert [shuffle_rng.randbelow(17) for _ in range(2)] == [8, 6]
    with pytest.raises(ValueError, match="positive"):
        rng.randbelow(0)
    with pytest.raises(ValueError, match="non-negative"):
        rng.read(-1)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(extra=True), "unknown fields"),
        (
            lambda value: value["attacks"].append(copy.deepcopy(value["attacks"][0])),
            "duplicate",
        ),
        (lambda value: value["attacks"].pop(), "exactly 32"),
        (lambda value: value["attacks"].reverse(), "canonical order"),
        (
            lambda value: value["attacks"][0].update(id="invented-attack"),
            "unknown attack",
        ),
        (lambda value: value["attacks"][0].update(name="Renamed"), "frozen names"),
        (lambda value: value["seeds"].append(999), "frozen seeds"),
        (
            lambda value: value["repetitions"].update(
                functional_attack_trials_per_cell=29
            ),
            "30",
        ),
        (lambda value: value["workloads"][0].update(nodes=True), "integer"),
        (
            lambda value: value["workloads"][9]["parameters"].update(
                payload_pairs_bytes=[[0]]
            ),
            "invalid pair",
        ),
        (
            lambda value: value["workloads"][0]["parameters"].update(fan_out=1),
            "noncanonical",
        ),
    ],
)
def test_matrix_validation_rejects_unknown_duplicate_and_noncanonical_values(
    mutation: object, match: str
) -> None:
    value = json.loads(MATRIX_PATH.read_bytes())
    assert callable(mutation)
    mutation(value)

    with pytest.raises(ContractViolation, match=match):
        validate_matrix(value)


def test_matrix_loader_rejects_duplicate_keys_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"revision":"x","revision":"y"}', encoding="utf-8")
    with pytest.raises(ContractViolation, match="duplicate key"):
        load_matrix(duplicate)

    noncanonical = tmp_path / "noncanonical.json"
    value = json.loads(MATRIX_PATH.read_bytes())
    noncanonical.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(ContractViolation, match="canonical JSON"):
        load_matrix(noncanonical)


def test_raw_result_schema_is_strict_and_matches_matrix_enums() -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)

    properties = schema["properties"]
    assert properties["baseline_id"]["enum"] == [item.id for item in matrix.baselines]
    assert properties["store"]["enum"] == list(matrix.stores)
    assert properties["workload_id"]["enum"] == [item.id for item in matrix.workloads]
    assert properties["attack_id"]["enum"] == [*ATTACK_IDS, None]
    assert properties["ablation_id"]["enum"] == [*ABLATION_IDS, None]
    assert schema["additionalProperties"] is False
    assert "lexical forms for integral values" in schema["$comment"]


def test_raw_result_loader_accepts_only_canonical_known_records(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    trial = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id="missing-proof",
        trial_index=0,
    )
    record: dict[str, object] = {
        "ablation_id": None,
        "ablation_classification": None,
        "artifact_sha256": "1" * 64,
        "attack_id": trial.attack_id,
        "authoritative_compromise": False,
        "authoritative_outcome": "none",
        "baseline_id": trial.baseline_id,
        "byte_counts": {"certificate": 0},
        "cache_state": "cold",
        "case_index": None,
        "condition_id": None,
        "concurrency": 1,
        "dag": "single-node",
        "database_index": None,
        "detected": True,
        "distinct_states": None,
        "environment_id": "fedora44-ryzen7800x3d",
        "fail_closed": True,
        "failed_invariant": None,
        "failure_code": "MISSING_PROOF",
        "fault_target": None,
        "formal_evidence": None,
        "git_sha": "0" * 40,
        "generated_states": None,
        "incorrect_current_consumption": False,
        "input_bytes": 1024,
        "matrix_sha256": matrix.matrix_sha256,
        "matrix_revision": matrix.revision,
        "outcome": "rejected",
        "output_bytes": 4096,
        "phase": None,
        "record_type": "functional-attack",
        "recovered": False,
        "repetition": trial.seed_repetition,
        "schema_version": "apcc-1.raw-result.v1",
        "search_depth": None,
        "seed": trial.seed,
        "store": trial.store,
        "sub_seed_b64u": trial.sub_seed_b64u,
        "successful_commits": None,
        "target_rate_per_second": 10,
        "timings_ns": {"total": 1234},
        "tool_versions": {"python": "3.13.13"},
        "trial_id": trial.trial_id,
        "trial_index": trial.trial_index,
        "cost_saved_ns": None,
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
    path = tmp_path / "result.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record

    unknown = {**record, "surprise": True}
    path.write_bytes(canonical_json_bytes(unknown))
    with pytest.raises(ContractViolation, match="raw result"):
        load_raw_result(path, matrix=matrix)

    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    with pytest.raises(ContractViolation, match="canonical JSON"):
        load_raw_result(path, matrix=matrix)

    duplicate_text = (
        canonical_json_bytes(record)
        .decode()
        .replace('"ablation_id":null', '"ablation_id":null,"ablation_id":null', 1)
    )
    path.write_text(duplicate_text, encoding="utf-8")
    with pytest.raises(ContractViolation, match="duplicate key"):
        load_raw_result(path, matrix=matrix)


def _raw_record(matrix: ExperimentMatrix, **overrides: object) -> dict[str, object]:
    trial = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id="missing-proof",
        trial_index=0,
    )
    record: dict[str, object] = {
        "ablation_id": None,
        "ablation_classification": None,
        "artifact_sha256": "1" * 64,
        "attack_id": trial.attack_id,
        "authoritative_compromise": False,
        "authoritative_outcome": "none",
        "baseline_id": trial.baseline_id,
        "byte_counts": {"certificate": 0},
        "cache_state": "cold",
        "case_index": None,
        "condition_id": None,
        "concurrency": 1,
        "dag": "single-node",
        "database_index": None,
        "detected": True,
        "distinct_states": None,
        "environment_id": "fedora44-ryzen7800x3d",
        "fail_closed": True,
        "failed_invariant": None,
        "failure_code": "MISSING_PROOF",
        "fault_target": None,
        "formal_evidence": None,
        "git_sha": "0" * 40,
        "generated_states": None,
        "incorrect_current_consumption": False,
        "input_bytes": 1024,
        "matrix_sha256": matrix.matrix_sha256,
        "matrix_revision": matrix.revision,
        "outcome": "rejected",
        "output_bytes": 4096,
        "phase": None,
        "record_type": "functional-attack",
        "recovered": False,
        "repetition": trial.seed_repetition,
        "schema_version": "apcc-1.raw-result.v1",
        "search_depth": None,
        "seed": trial.seed,
        "store": trial.store,
        "sub_seed_b64u": trial.sub_seed_b64u,
        "successful_commits": None,
        "target_rate_per_second": 10,
        "timings_ns": {"total": 1234},
        "tool_versions": {"python": "3.13.13"},
        "trial_id": trial.trial_id,
        "trial_index": trial.trial_index,
        "cost_saved_ns": None,
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
    record.update(overrides)
    return record


def _raw_record_for_family(
    matrix: ExperimentMatrix, record_type: str
) -> dict[str, object]:
    record = _raw_record(matrix)
    run: Any
    if record_type == "functional-attack":
        return record
    if record_type == "race-recovery":
        run = next(planned_race_recovery_trials(matrix))
        record.update(
            baseline_id=run.baseline_id,
            store=run.store,
            attack_id=run.attack_id,
            condition_id=run.attack_id,
            fault_target=run.fault_target,
            phase="fault",
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.seed_repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
        )
    elif record_type == "parser":
        run = next(planned_parser_trials(matrix))
        record.update(
            attack_id=run.attack_id,
            condition_id=run.condition_id,
            case_index=run.case_index,
            phase=run.phase,
            trial_index=run.case_index,
            seed=run.seed,
            repetition=run.seed_repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
        )
    elif record_type == "timing":
        run = next(planned_timing_trials(matrix))
        record.update(
            attack_id=None,
            baseline_id=run.baseline_id,
            store=run.store,
            condition_id=run.condition_id,
            phase="measured",
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.seed_repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
        )
    elif record_type == "performance":
        run = next(
            item
            for item in planned_performance_runs(matrix)
            if item.phase == "measured" and item.cache_state == "cold"
        )
        workload = next(item for item in matrix.workloads if item.id == run.workload_id)
        record.update(
            attack_id=None,
            baseline_id=run.baseline_id,
            store=run.store,
            workload_id=run.workload_id,
            cache_state=run.cache_state,
            target_rate_per_second=run.target_rate_per_second,
            phase=run.phase,
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
            concurrency=workload.concurrency,
            dag=workload.dag,
            input_bytes=run.payload_pair[0],
            output_bytes=run.payload_pair[1],
            workload_evidence={
                "agents": workload.agents,
                "completed_operations": 10_000,
                "duration_seconds": run.duration_seconds,
                "incomplete_run": False,
                "lifecycle_mode": run.lifecycle_mode,
                "nodes": workload.nodes,
                "operation_limit": run.operation_limit,
                "parameters": {},
                "payload_pair": list(run.payload_pair),
                "pre_run_queries": 0,
                "schedule": workload.schedule,
                "warmup_runs_completed": 0,
            },
        )
    elif record_type == "storage":
        run = next(planned_storage_runs(matrix))
        record.update(
            attack_id=None,
            baseline_id=run.baseline_id,
            store=run.store,
            database_index=run.database_index,
            successful_commits=run.successful_commits,
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
        )
    elif record_type == "ablation":
        run = next(planned_ablation_trials(matrix))
        record.update(
            ablation_id=run.ablation_id,
            ablation_classification="essential",
            attack_id=run.attack_id,
            baseline_id=run.baseline_id,
            store=run.store,
            condition_id=run.condition_id,
            cost_saved_ns=100,
            failed_invariant="atomic authority",
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.seed_repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
        )
    elif record_type == "formal":
        run = next(planned_formal_runs(matrix))
        record.update(
            attack_id=None,
            condition_id=run.config_id,
            distinct_states=50,
            generated_states=100,
            phase="measured",
            search_depth=12,
            witness_marker=run.expected_witness_marker,
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
            formal_evidence={
                "command": run.command,
                "config_sha256": run.config_sha256,
                "duration_ns": 1234,
                "exit_status": run.expected_exit_status,
                "failure": None,
                "jar_sha256": run.jar_sha256,
                "model": run.model,
                "model_sha256": run.model_sha256,
            },
        )
    else:
        raise AssertionError(record_type)
    record["record_type"] = record_type
    return record


@pytest.mark.parametrize(
    "record_type",
    list(
        (
            "functional-attack",
            "race-recovery",
            "parser",
            "timing",
            "performance",
            "storage",
            "ablation",
            "formal",
        )
    ),
)
def test_raw_result_schema_and_loader_accept_every_frozen_record_family(
    tmp_path: Path, record_type: str
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    record = _raw_record_for_family(matrix, record_type)
    jsonschema.Draft202012Validator(schema).validate(record)
    path = tmp_path / f"{record_type}.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record


@pytest.mark.parametrize(
    "record_type",
    [
        "race-recovery",
        "parser",
        "timing",
        "performance",
        "storage",
        "ablation",
        "formal",
    ],
)
def test_nonfunctional_records_reject_cross_family_or_forged_identity(
    tmp_path: Path, record_type: str
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, record_type)
    functional = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id="missing-proof",
        trial_index=0,
    )
    record["trial_id"] = functional.trial_id
    record["sub_seed_b64u"] = functional.sub_seed_b64u
    path = tmp_path / f"forged-{record_type}.json"
    path.write_bytes(canonical_json_bytes(record))

    with pytest.raises(ContractViolation, match="deterministic planner identity"):
        load_raw_result(path, matrix=matrix)


def test_race_record_rejects_an_attack_absent_from_the_race_planner(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, "race-recovery")
    record["attack_id"] = "missing-proof"
    record["condition_id"] = "missing-proof"
    path = tmp_path / "unscheduled-race.json"
    path.write_bytes(canonical_json_bytes(record))

    with pytest.raises(ContractViolation, match="unscheduled"):
        load_raw_result(path, matrix=matrix)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(repetition=True),
        lambda value: value.update(trial_index=True),
        lambda value: value.update(concurrency=True),
        lambda value: value.update(byte_counts={"certificate": True}),
        lambda value: value.update(baseline_id="B0", store="postgresql"),
        lambda value: value.update(
            record_type="performance", attack_id="missing-proof"
        ),
        lambda value: value.update(
            record_type="functional-attack", ablation_id=ABLATION_IDS[0]
        ),
        lambda value: value.update(record_type="ablation", ablation_id=None),
        lambda value: value.update(
            record_type="parser", phase="generated", case_index=None
        ),
        lambda value: value.update(workload_id="W2"),
    ],
)
def test_raw_result_json_schema_and_python_loader_reject_the_same_invalid_records(
    tmp_path: Path, mutation: object
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    record = _raw_record(matrix)
    assert callable(mutation)
    mutation(record)
    assert list(
        jsonschema.Draft202012Validator(schema).iter_errors(cast(JsonValue, record))
    )
    path = tmp_path / "invalid.json"
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation):
        load_raw_result(path, matrix=matrix)


def test_planners_consume_every_frozen_repetition_count() -> None:
    matrix = load_matrix(MATRIX_PATH)
    counts = planning_cardinalities(matrix)

    assert counts == {
        "functional_attack": 7_680,
        "race_recovery": len(tuple(planned_race_recovery_trials(matrix))),
        "parser_vector": 126,
        "parser_generated": 50_000,
        "parser": 50_126,
        "timing": len(tuple(planned_timing_trials(matrix))),
        "performance_warmup": 4_320,
        "performance_measured": 28_800,
        "ablation_performance_warmup": 180,
        "ablation_performance_measured": 600,
        "storage_runs": 24,
        "storage_commits": 2_400_000,
        "ablation": 360,
        "formal": 6,
    }
    assert len(tuple(planned_parser_trials(matrix))) == 50_126
    performance = tuple(planned_performance_runs(matrix))
    assert sum(run.phase == "warmup" for run in performance) == 4_320
    assert sum(run.phase == "measured" for run in performance) == 28_800
    storage = tuple(planned_storage_runs(matrix))
    assert len(storage) == 24
    assert sum(run.successful_commits for run in storage) == 2_400_000


def test_validator_and_verifier_crash_are_distinct_mandatory_fault_targets() -> None:
    matrix = load_matrix(MATRIX_PATH)
    crash_trials = [
        trial
        for trial in planned_race_recovery_trials(matrix)
        if trial.attack_id == "validator-crash"
    ]

    assert {trial.fault_target for trial in crash_trials} == {
        "validator-crash",
        "verifier-crash",
    }
    assert {trial.attack_id for trial in crash_trials} == {"validator-crash"}


def test_contract_bounds_files_json_depth_unicode_and_prng_allocations(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (1_048_576 + 1))
    with pytest.raises(ContractViolation, match="size"):
        load_matrix(oversized)

    deep: object = 0
    for _ in range(80):
        deep = [deep]
    with pytest.raises(ContractViolation, match="depth"):
        canonical_json_bytes(deep)
    with pytest.raises(ContractViolation, match="canonical JSON"):
        canonical_json_bytes("\ud800")
    with pytest.raises(ContractViolation, match="size"):
        canonical_json_bytes("x" * 1_048_577)

    path = tmp_path / "deep.json"
    path.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")
    with pytest.raises(ContractViolation):
        load_raw_result(path, matrix=matrix)

    rng = HashCounterPRNG(seed=b"seed", domain=b"bounded")
    with pytest.raises(ValueError, match="too large"):
        rng.read(1_048_577)
    with pytest.raises(ValueError, match="too large"):
        rng.randbelow(1 << 65)


def test_nonfunctional_planners_have_distinct_exact_deterministic_identities() -> None:
    matrix = load_matrix(MATRIX_PATH)
    families: dict[str, tuple[Any, ...]] = {
        "race-recovery": tuple(planned_race_recovery_trials(matrix)),
        "parser": tuple(planned_parser_trials(matrix)),
        "timing": tuple(planned_timing_trials(matrix)),
        "performance": tuple(planned_performance_runs(matrix)),
        "storage": tuple(planned_storage_runs(matrix)),
        "ablation": tuple(planned_ablation_trials(matrix)),
        "formal": tuple(planned_formal_runs(matrix)),
    }

    all_ids = [run.trial_id for runs in families.values() for run in runs]
    assert len(all_ids) == len(set(all_ids))
    assert all(
        len(run.sub_seed_b64u) == 43 for runs in families.values() for run in runs
    )
    functional_id = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id="missing-proof",
        trial_index=0,
    ).trial_id
    assert functional_id not in set(all_ids)


def test_parser_ablation_and_all_six_formal_plans_are_frozen() -> None:
    matrix = load_matrix(MATRIX_PATH)
    manifest = json.loads(
        (ROOT / "tests" / "fixtures" / "apcc" / "v1" / "manifest.json").read_bytes()
    )
    vector_names = tuple(vector["name"] for vector in manifest["vectors"])
    parser = tuple(planned_parser_trials(matrix))
    vectors = tuple(trial for trial in parser if trial.phase == "vector")

    assert tuple(trial.condition_id for trial in vectors) == vector_names
    assert len(vectors) == 126
    assert len(tuple(planned_ablation_trials(matrix))) == 12 * 30
    formal = tuple(planned_formal_runs(matrix))
    assert tuple(run.config_id for run in formal) == (
        "apcc_safety.cfg",
        "apcc_witness_valid_chain.cfg",
        "apcc_witness_exact_replay.cfg",
        "apcc_witness_stale_rejection.cfg",
        "apcc_witness_revocation.cfg",
        "apcc_witness_recovery.cfg",
    )
    assert len({run.config_sha256 for run in formal}) == 6
    assert {run.jar_sha256 for run in formal} == {
        "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
    }


def test_performance_plan_expands_payloads_and_preserves_cold_warm_lifecycle() -> None:
    matrix = load_matrix(MATRIX_PATH)
    runs = tuple(planned_performance_runs(matrix))
    w10 = [run for run in runs if run.workload_id == "W10"]

    assert {run.payload_pair for run in w10} == {
        (0, 0),
        (1024, 4096),
        (65536, 262144),
    }
    assert not any(run.phase == "warmup" and run.cache_state == "cold" for run in runs)
    assert all(
        run.lifecycle_mode
        == ("fixed-operations" if run.workload_id == "W6" else "duration")
        for run in runs
    )
    assert all(
        (run.duration_seconds is None and run.operation_limit == 10_000)
        if run.workload_id == "W6"
        else (run.duration_seconds == 30 and run.operation_limit is None)
        for run in runs
    )


def test_planning_cardinalities_include_all_frozen_plan_families() -> None:
    matrix = load_matrix(MATRIX_PATH)

    assert planning_cardinalities(matrix) == {
        "functional_attack": 7_680,
        "race_recovery": 9_600,
        "parser_vector": 126,
        "parser_generated": 50_000,
        "parser": 50_126,
        "timing": 720,
        "performance_warmup": 4_320,
        "performance_measured": 28_800,
        "ablation_performance_warmup": 180,
        "ablation_performance_measured": 600,
        "storage_runs": 24,
        "storage_commits": 2_400_000,
        "ablation": 360,
        "formal": 6,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["attacks"][0].update(id=[]),
        lambda value: value["baselines"][0].update(stores=None),
        lambda value: value.update(stores=None),
        lambda value: value["fault_targets"][0].update(id=[]),
    ],
)
def test_all_malformed_matrix_containers_fail_as_contract_violations(
    mutation: object,
) -> None:
    value = json.loads(MATRIX_PATH.read_bytes())
    assert callable(mutation)
    mutation(value)

    with pytest.raises(ContractViolation):
        validate_matrix(value)


@pytest.mark.parametrize(
    "field",
    [
        "repetition",
        "trial_index",
        "concurrency",
        "input_bytes",
        "output_bytes",
    ],
)
def test_integral_float_lexemes_are_rejected_before_schema_and_python_acceptance(
    tmp_path: Path, field: str
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record(matrix)
    raw = canonical_json_bytes(record).decode("utf-8")
    raw = raw.replace(f'"{field}":{record[field]}', f'"{field}":{record[field]}.0')
    path = tmp_path / f"integral-float-{field}.json"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ContractViolation, match="integer lexical form"):
        load_raw_result(path, matrix=matrix)


@pytest.mark.parametrize(
    ("record_type", "path"),
    [
        ("functional-attack", ("seed",)),
        ("functional-attack", ("target_rate_per_second",)),
        ("functional-attack", ("timings_ns", "total")),
        ("functional-attack", ("byte_counts", "certificate")),
        ("functional-attack", ("workload_evidence", "agents")),
        ("functional-attack", ("workload_evidence", "completed_operations")),
        ("functional-attack", ("workload_evidence", "nodes")),
        ("functional-attack", ("workload_evidence", "pre_run_queries")),
        ("functional-attack", ("workload_evidence", "warmup_runs_completed")),
        ("parser", ("case_index",)),
        ("storage", ("database_index",)),
        ("storage", ("successful_commits",)),
        ("ablation", ("cost_saved_ns",)),
        ("formal", ("generated_states",)),
        ("formal", ("distinct_states",)),
        ("formal", ("search_depth",)),
        ("formal", ("formal_evidence", "duration_ns")),
        ("formal", ("formal_evidence", "exit_status")),
    ],
)
def test_integral_float_profile_covers_every_nested_record_family_integer(
    tmp_path: Path, record_type: str, path: tuple[str, ...]
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, record_type)
    parent: dict[str, object] = record
    for component in path[:-1]:
        child = parent[component]
        assert isinstance(child, dict)
        parent = child
    value = parent[path[-1]]
    assert type(value) is int
    parent[path[-1]] = float(value)
    result_path = tmp_path / f"{record_type}-{'-'.join(path)}.json"
    result_path.write_bytes(canonical_json_bytes(record))

    with pytest.raises(ContractViolation, match="integer lexical form"):
        load_raw_result(result_path, matrix=matrix)


def test_all_w10_payload_pairs_bind_exact_shape_and_identity(tmp_path: Path) -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    workload = next(item for item in matrix.workloads if item.id == "W10")
    runs = [
        run
        for run in planned_performance_runs(matrix)
        if run.workload_id == "W10"
        and run.phase == "measured"
        and run.cache_state == "cold"
        and run.seed == matrix.seeds[0]
        and run.repetition == 0
        and run.baseline_id == "B0"
        and run.target_rate_per_second == 10
    ]

    assert len(runs) == 3
    for run in runs:
        record = _raw_record_for_family(matrix, "performance")
        record.update(
            baseline_id=run.baseline_id,
            store=run.store,
            workload_id=run.workload_id,
            cache_state=run.cache_state,
            target_rate_per_second=run.target_rate_per_second,
            phase=run.phase,
            trial_index=run.trial_index,
            seed=run.seed,
            repetition=run.repetition,
            trial_id=run.trial_id,
            sub_seed_b64u=run.sub_seed_b64u,
            concurrency=workload.concurrency,
            dag=workload.dag,
            input_bytes=run.payload_pair[0],
            output_bytes=run.payload_pair[1],
            workload_evidence={
                "agents": workload.agents,
                "completed_operations": 10_000,
                "duration_seconds": 30,
                "incomplete_run": False,
                "lifecycle_mode": "duration",
                "nodes": workload.nodes,
                "operation_limit": None,
                "parameters": {
                    "payload_pairs_bytes": [
                        [0, 0],
                        [1024, 4096],
                        [65536, 262144],
                    ]
                },
                "payload_pair": list(run.payload_pair),
                "pre_run_queries": 0,
                "schedule": workload.schedule,
                "warmup_runs_completed": 0,
            },
        )
        jsonschema.Draft202012Validator(schema).validate(record)
        path = tmp_path / f"w10-{run.payload_pair[0]}.json"
        path.write_bytes(canonical_json_bytes(record))
        assert load_raw_result(path, matrix=matrix) == record


def test_performance_lifecycle_rejects_cold_warmups_and_unflagged_incomplete_runs(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, "performance")
    evidence = record["workload_evidence"]
    assert isinstance(evidence, dict)
    evidence["completed_operations"] = 9_999
    path = tmp_path / "unflagged-incomplete.json"
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation, match="incomplete-run flag"):
        load_raw_result(path, matrix=matrix)

    evidence["incomplete_run"] = True
    path = tmp_path / "retained-incomplete.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record

    record["phase"] = "warmup"
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation, match="cold cells"):
        load_raw_result(path, matrix=matrix)


def test_formal_failure_is_retained_but_cannot_change_frozen_inputs(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, "formal")
    evidence = record["formal_evidence"]
    assert isinstance(evidence, dict)
    evidence["exit_status"] = 2
    evidence["failure"] = "TLC timeout"
    record["outcome"] = "failed"
    path = tmp_path / "formal-failure.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record

    evidence["model_sha256"] = "f" * 64
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation, match="frozen configuration"):
        load_raw_result(path, matrix=matrix)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: record.update(baseline_id=[]),
        lambda record: record.update(store=None),
        lambda record: record.update(workload_evidence=[]),
        lambda record: record.update(trial_id=[]),
    ],
)
def test_malformed_raw_containers_are_stable_contract_violations(
    tmp_path: Path, mutation: object
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record(matrix)
    assert callable(mutation)
    mutation(record)
    path = tmp_path / "malformed-container.json"
    path.write_bytes(canonical_json_bytes(record))

    with pytest.raises(ContractViolation):
        load_raw_result(path, matrix=matrix)


def _select_workload(
    record: dict[str, object], matrix: ExperimentMatrix, workload_id: str
) -> None:
    workload = next(item for item in matrix.workloads if item.id == workload_id)
    pair = (
        workload.payload_pairs_bytes[0]
        if workload.payload_pairs_bytes
        else (workload.input_bytes, workload.output_bytes)
    )
    assert pair[0] is not None and pair[1] is not None
    parameters = {
        name: getattr(workload, name)
        for name in (
            "fan_out",
            "fan_in",
            "competing_attempts",
            "policy_update_ratio",
            "actor_revocation_ratio",
            "workflow_revocation_ratio",
            "replay_ratio",
            "conflicting_replay_ratio",
        )
        if getattr(workload, name) is not None
    }
    if workload.payload_pairs_bytes:
        parameters["payload_pairs_bytes"] = [
            list(item) for item in workload.payload_pairs_bytes
        ]
    record.update(
        workload_id=workload.id,
        concurrency=workload.concurrency,
        dag=workload.dag,
        input_bytes=pair[0],
        output_bytes=pair[1],
        workload_evidence={
            "agents": workload.agents,
            "completed_operations": 1,
            "duration_seconds": None,
            "incomplete_run": False,
            "lifecycle_mode": "single-trial",
            "nodes": workload.nodes,
            "operation_limit": None,
            "parameters": parameters,
            "payload_pair": list(pair),
            "pre_run_queries": 0,
            "schedule": workload.schedule,
            "warmup_runs_completed": 0,
        },
    )


@pytest.mark.parametrize(
    ("record_type", "mutation"),
    [
        (
            "functional-attack",
            lambda record, matrix: _select_workload(record, matrix, "W2"),
        ),
        (
            "race-recovery",
            lambda record, matrix: _select_workload(record, matrix, "W2"),
        ),
        ("parser", lambda record, matrix: record.update(target_rate_per_second=100)),
        ("timing", lambda record, matrix: record.update(cache_state="warm")),
        (
            "performance",
            lambda record, matrix: record.update(ablation_id=ABLATION_IDS[0]),
        ),
        ("storage", lambda record, matrix: _select_workload(record, matrix, "W2")),
        ("ablation", lambda record, matrix: record.update(target_rate_per_second=100)),
        ("formal", lambda record, matrix: record.update(cache_state="warm")),
    ],
)
def test_every_record_family_rejects_a_dimension_outside_its_planner_identity(
    tmp_path: Path,
    record_type: str,
    mutation: object,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    record = _raw_record_for_family(matrix, record_type)
    assert callable(mutation)
    mutation(record, matrix)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    assert list(
        jsonschema.Draft202012Validator(schema).iter_errors(cast(JsonValue, record))
    )
    path = tmp_path / f"identity-dimension-{record_type}.json"
    path.write_bytes(canonical_json_bytes(record))

    with pytest.raises(ContractViolation, match="planner|scheduled|ablation"):
        load_raw_result(path, matrix=matrix)


def test_matched_ablation_performance_plan_is_explicit_and_deterministic() -> None:
    matrix = load_matrix(MATRIX_PATH)
    runs = tuple(contract_module.planned_ablation_performance_runs(matrix))

    assert len(runs) == 12 * 5 * (3 + 10) == 780
    assert sum(run.phase == "warmup" for run in runs) == 180
    assert sum(run.phase == "measured" for run in runs) == 600
    assert {run.ablation_id for run in runs} == set(ABLATION_IDS)
    assert {
        (
            run.baseline_id,
            run.store,
            run.workload_id,
            run.payload_pair,
            run.target_rate_per_second,
            run.cache_state,
            run.lifecycle_mode,
        )
        for run in runs
    } == {("B6", "sqlite", "W1", (1024, 4096), 100, "warm", "duration")}
    assert len({run.trial_id for run in runs}) == len(runs)
    assert not (
        {run.trial_id for run in runs}
        & {run.trial_id for run in planned_performance_runs(matrix)}
    )
    counts = planning_cardinalities(matrix)
    assert counts["ablation_performance_warmup"] == 180
    assert counts["ablation_performance_measured"] == 600


def test_ablation_performance_raw_run_binds_ablation_and_matrix_hash(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    run = next(
        item
        for item in contract_module.planned_ablation_performance_runs(matrix)
        if item.phase == "measured"
    )
    record = _raw_record_for_family(matrix, "performance")
    workload = next(item for item in matrix.workloads if item.id == run.workload_id)
    record.update(
        ablation_id=run.ablation_id,
        baseline_id=run.baseline_id,
        store=run.store,
        workload_id=run.workload_id,
        target_rate_per_second=run.target_rate_per_second,
        cache_state=run.cache_state,
        seed=run.seed,
        repetition=run.repetition,
        phase=run.phase,
        trial_index=run.trial_index,
        trial_id=run.trial_id,
        sub_seed_b64u=run.sub_seed_b64u,
        concurrency=workload.concurrency,
        dag=workload.dag,
        input_bytes=run.payload_pair[0],
        output_bytes=run.payload_pair[1],
        matrix_sha256=matrix.matrix_sha256,
        workload_evidence={
            "agents": workload.agents,
            "completed_operations": 10_000,
            "duration_seconds": 30,
            "incomplete_run": False,
            "lifecycle_mode": "duration",
            "nodes": workload.nodes,
            "operation_limit": None,
            "parameters": {},
            "payload_pair": list(run.payload_pair),
            "pre_run_queries": 1,
            "schedule": workload.schedule,
            "warmup_runs_completed": 3,
        },
    )
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    jsonschema.Draft202012Validator(schema).validate(record)
    path = tmp_path / "ablation-performance.json"
    path.write_bytes(canonical_json_bytes(record))
    assert load_raw_result(path, matrix=matrix) == record

    record["matrix_sha256"] = "f" * 64
    path.write_bytes(canonical_json_bytes(record))
    with pytest.raises(ContractViolation, match="matrix hash"):
        load_raw_result(path, matrix=matrix)


def test_w10_schema_rejects_cross_product_payload_pairs() -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    record = _raw_record_for_family(matrix, "performance")
    _select_workload(record, matrix, "W10")
    record["record_type"] = "performance"
    record["input_bytes"] = 0
    record["output_bytes"] = 4096
    evidence = record["workload_evidence"]
    assert isinstance(evidence, dict)
    evidence["payload_pair"] = [0, 4096]

    assert list(
        jsonschema.Draft202012Validator(schema).iter_errors(cast(JsonValue, record))
    )


def _outcome_tuple_is_valid(
    outcome: str,
    authoritative_outcome: str,
    compromise: bool,
    incorrect: bool,
    fail_closed: bool,
    detected: bool,
    recovered: bool,
    failure_present: bool,
) -> bool:
    if incorrect and not compromise:
        return False
    if fail_closed == compromise:
        return False
    if recovered and not detected:
        return False
    if (outcome != "accepted") != failure_present:
        return False
    if outcome != "accepted" and not detected:
        return False
    allowed_authority = {
        "accepted": {"none", "committed"},
        "rejected": {"none", "denied", "conflicted"},
        "failed": {"none", "unavailable", "committed"},
    }[outcome]
    if authoritative_outcome not in allowed_authority:
        return False
    if outcome == "rejected" and compromise:
        return False
    if outcome == "failed" and compromise and authoritative_outcome != "committed":
        return False
    return True


def test_schema_and_loader_enforce_the_complete_outcome_truth_table(
    tmp_path: Path,
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    schema = json.loads(RAW_SCHEMA_PATH.read_bytes())
    validator = jsonschema.Draft202012Validator(schema)
    path = tmp_path / "outcome-truth.json"
    outcomes = ("accepted", "rejected", "failed")
    authoritative = ("none", "committed", "denied", "conflicted", "unavailable")

    for outcome in outcomes:
        for authoritative_outcome in authoritative:
            for compromise in (False, True):
                for incorrect in (False, True):
                    for fail_closed in (False, True):
                        for detected in (False, True):
                            for recovered in (False, True):
                                for failure_present in (False, True):
                                    record = _raw_record(matrix)
                                    record.update(
                                        outcome=outcome,
                                        authoritative_outcome=authoritative_outcome,
                                        authoritative_compromise=compromise,
                                        incorrect_current_consumption=incorrect,
                                        fail_closed=fail_closed,
                                        detected=detected,
                                        recovered=recovered,
                                        failure_code=(
                                            "EXPECTED_FAILURE"
                                            if failure_present
                                            else None
                                        ),
                                    )
                                    expected = _outcome_tuple_is_valid(
                                        outcome,
                                        authoritative_outcome,
                                        compromise,
                                        incorrect,
                                        fail_closed,
                                        detected,
                                        recovered,
                                        failure_present,
                                    )
                                    schema_accepts = not list(
                                        validator.iter_errors(cast(JsonValue, record))
                                    )
                                    path.write_bytes(canonical_json_bytes(record))
                                    try:
                                        load_raw_result(path, matrix=matrix)
                                    except ContractViolation:
                                        loader_accepts = False
                                    else:
                                        loader_accepts = True
                                    assert schema_accepts is expected
                                    assert loader_accepts is expected


@pytest.mark.parametrize("loader", ["matrix", "raw"])
def test_public_json_loaders_normalize_huge_integer_lexemes(
    tmp_path: Path, loader: str
) -> None:
    matrix = load_matrix(MATRIX_PATH)
    path = tmp_path / f"huge-{loader}.json"
    huge = "9" * 5_000
    if loader == "matrix":
        raw = MATRIX_PATH.read_text(encoding="utf-8").replace("104729", huge, 1)
        path.write_text(raw, encoding="utf-8")
        with pytest.raises(ContractViolation, match="integer|JSON"):
            load_matrix(path)
    else:
        record = _raw_record(matrix)
        raw = (
            canonical_json_bytes(record)
            .decode("utf-8")
            .replace('"seed":104729', f'"seed":{huge}', 1)
        )
        path.write_text(raw, encoding="utf-8")
        with pytest.raises(ContractViolation, match="integer|JSON"):
            load_raw_result(path, matrix=matrix)
