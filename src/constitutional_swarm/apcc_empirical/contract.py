"""Frozen APCC-1 empirical matrix and deterministic trial contract."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, NoReturn


MATRIX_REVISION = "apcc-1.matrix.v1"
RAW_RESULT_SCHEMA_VERSION = "apcc-1.raw-result.v1"
_PRNG_PREFIX = b"APCC-1 empirical hash-counter PRNG v1\0"
_B64U_256 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 1_048_576
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000
_MAX_PRNG_READ = 1_048_576
_MAX_PRNG_BOUND = 1 << 64
_PARSER_VECTOR_PROJECTION_SHA256 = (
    "9840c8a6e600c878ec2b937cd9b34def2f78b8a3d5207a5e2ffdb31f76bced34"
)
_TLC_JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"

BASELINE_IDS = tuple(f"B{index}" for index in range(7))
BASELINE_NAMES = (
    "Direct completion",
    "Post-hoc audit",
    "Pre-execution policy gate",
    "Signed result log",
    "Non-atomic proof verification",
    "Existing GCB-1 realization",
    "APCC-1",
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
ATTACK_NAMES = (
    "Missing proof",
    "Invalid signature",
    "Unknown key",
    "Output substitution",
    "Input substitution",
    "Identity substitution",
    "Cross-node replay",
    "Cross-workflow replay",
    "Cross-attempt replay",
    "commit_id equivocation",
    "Policy update race",
    "Authority update race",
    "Actor revocation race",
    "Workflow revocation race",
    "Predecessor replacement race",
    "Concurrent double commit",
    "Response loss and retry",
    "Validator crash",
    "Authority-store transaction failure",
    "Outbox failure",
    "Recovery import",
    "Legacy completion promotion",
    "Malicious scheduler",
    "Malicious executor",
    "Malicious retry caller",
    "Stale cache",
    "Certificate truncation",
    "Canonicalization ambiguity",
    "Unknown protocol version",
    "Oversized certificate",
    "Duplicate predecessor",
    "Predecessor-set reordering",
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
ABLATION_NAMES = (
    "Atomic validation-and-commit",
    "Policy epoch binding",
    "Authority epoch binding",
    "Revocation generation",
    "Attempt binding",
    "Predecessor certificate binding",
    "Stable commit_id",
    "Nonce replay fence",
    "Independent certificate verification",
    "Staging invisibility",
    "Downstream certificate and current-status requirement",
    "Transactional outbox",
)
WORKLOAD_IDS = tuple(f"W{index}" for index in range(1, 11))
WORKLOAD_NAMES = (
    "Single node",
    "Linear DAG",
    "High fan-out",
    "High fan-in",
    "Competing attempts",
    "One thousand logical Agents",
    "Policy reconfiguration",
    "Revocation load",
    "Duplicate retry load",
    "Payload-size sweep",
)
STORES = ("sqlite", "postgresql")
TARGET_RATES = (10, 100, 500)
CACHE_STATES = ("cold", "warm")
SEEDS = (104729, 130363, 155921, 196613, 262147)
FAULT_TARGETS = ("validator-crash", "verifier-crash")
RACE_RECOVERY_ATTACKS = (
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
)
TIMING_CONDITIONS = ("restart-recovery", "revocation-propagation", "outbox-delay")
FORMAL_CONFIG_IDS = (
    "apcc_safety.cfg",
    "apcc_witness_valid_chain.cfg",
    "apcc_witness_exact_replay.cfg",
    "apcc_witness_stale_rejection.cfg",
    "apcc_witness_revocation.cfg",
    "apcc_witness_recovery.cfg",
)
_FORMAL_CONFIG_SHA256 = (
    "3c346d8d50a0ab03d900e7c1a05355d74dfb7b4690fc9cd0376dd362f1807cee",
    "edb6f4daa97b9897c967587e2692560e6a72899e210ffe45844d35fea0c38c23",
    "c9009303d9ec07363e7002787c986fe6c802d54df66c1a665049d660ef0a05c0",
    "6087063c73586015907bafbb68a05137a526bb49f08239f9446a30d090c1e349",
    "37100539c3b2838111eec3c6c73fe12acb416a3cab25057e9ac3396813287cf9",
    "3319334dfcf87ef90674a6e8f1a1555050607c073fa3afff7d8db0203b95ae0d",
)
_FORMAL_MODEL_SHA256 = (
    "88beb23dfcd99b143201e9911203e1a5ace82e49b96e13d286d4e84cd7d0d566"
)
_FORMAL_WITNESSES = (
    None,
    "WitnessValidChainNotReached",
    "WitnessExactReplayNotReached",
    "WitnessStaleRejectionNotReached",
    "WitnessRevocationBlockedNotReached",
    "WitnessRecoveryNotReached",
)
ABLATION_ATTACKS = (
    "concurrent-double-commit",
    "policy-update-race",
    "authority-update-race",
    "actor-revocation-race",
    "cross-attempt-replay",
    "predecessor-replacement-race",
    "commit-id-equivocation",
    "stale-cache",
    "invalid-signature",
    "legacy-completion-promotion",
    "stale-cache",
    "outbox-failure",
)
RAW_RECORD_TYPES = (
    "functional-attack",
    "race-recovery",
    "parser",
    "timing",
    "performance",
    "storage",
    "ablation",
    "formal",
)


class ContractViolation(ValueError):
    """Raised when an empirical input deviates from the frozen contract."""


@dataclass(frozen=True)
class NamedDimension:
    id: str
    name: str


@dataclass(frozen=True)
class Baseline(NamedDimension):
    stores: tuple[str, ...]


@dataclass(frozen=True)
class Workload(NamedDimension):
    dag: str
    nodes: int
    input_bytes: int | None
    output_bytes: int | None
    agents: int
    concurrency: int
    schedule: str
    fan_out: int | None = None
    fan_in: int | None = None
    competing_attempts: int | None = None
    policy_update_ratio: float | None = None
    actor_revocation_ratio: float | None = None
    workflow_revocation_ratio: float | None = None
    replay_ratio: float | None = None
    conflicting_replay_ratio: float | None = None
    payload_pairs_bytes: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Repetitions:
    functional_attack_trials_per_cell: int
    functional_attack_trials_per_seed: int
    race_recovery_trials_per_condition: int
    race_recovery_trials_per_seed: int
    parser_vectors_per_build: int
    generated_parser_cases_per_seed: int
    unreported_warmups: int
    measured_runs: int
    run_duration_seconds: int
    minimum_completed_operations: int
    timing_repetitions: int
    timing_repetitions_per_seed: int
    storage_commits: int
    storage_fresh_databases: int


@dataclass(frozen=True)
class AblationPerformanceCell:
    ablation_id: str
    baseline_id: str
    store: str
    workload_id: str
    payload_pair: tuple[int, int]
    target_rate_per_second: int
    cache_state: str
    lifecycle_mode: str


@dataclass(frozen=True)
class ExperimentMatrix:
    revision: str
    matrix_sha256: str
    baselines: tuple[Baseline, ...]
    attacks: tuple[NamedDimension, ...]
    ablations: tuple[NamedDimension, ...]
    ablation_performance_cells: tuple[AblationPerformanceCell, ...]
    workloads: tuple[Workload, ...]
    stores: tuple[str, ...]
    target_rates_per_second: tuple[int, ...]
    cache_states: tuple[str, ...]
    fault_targets: tuple[NamedDimension, ...]
    parser_vectors: tuple[ParserVector, ...]
    formal_configs: tuple[FormalConfig, ...]
    seeds: tuple[int, ...]
    repetitions: Repetitions


@dataclass(frozen=True)
class AttackTrial:
    baseline_id: str
    store: str
    attack_id: str
    trial_index: int
    seed: int
    seed_repetition: int
    trial_id: str
    sub_seed: bytes
    nonce: bytes
    key: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class RaceRecoveryTrial:
    baseline_id: str
    store: str
    attack_id: str
    fault_target: str | None
    trial_index: int
    seed: int
    seed_repetition: int
    trial_id: str
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class ParserTrial:
    baseline_id: str
    store: str
    phase: str
    condition_id: str
    attack_id: str
    case_index: int
    seed: int | None
    seed_repetition: int
    trial_id: str
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class PerformanceRun:
    baseline_id: str
    store: str
    workload_id: str
    target_rate_per_second: int
    cache_state: str
    seed: int
    repetition: int
    phase: str
    trial_index: int
    trial_id: str
    sub_seed: bytes
    payload_pair: tuple[int, int]
    lifecycle_mode: str
    duration_seconds: int | None
    operation_limit: int | None
    ablation_id: str | None = None

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class TimingTrial:
    baseline_id: str
    store: str
    condition_id: str
    trial_index: int
    seed: int
    seed_repetition: int
    trial_id: str
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class StorageRun:
    baseline_id: str
    store: str
    database_index: int
    successful_commits: int
    trial_id: str
    seed: int
    repetition: int
    trial_index: int
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class ParserVector:
    id: str
    mode: str
    expected_code: str


@dataclass(frozen=True)
class FormalConfig:
    id: str
    model: str
    model_sha256: str
    config_sha256: str
    jar_sha256: str
    command: str
    expected_exit_status: int
    witness_marker: str | None


@dataclass(frozen=True)
class AblationTrial:
    ablation_id: str
    attack_id: str
    baseline_id: str
    store: str
    condition_id: str
    trial_index: int
    seed: int
    seed_repetition: int
    trial_id: str
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


@dataclass(frozen=True)
class FormalRun:
    baseline_id: str
    store: str
    config_id: str
    model: str
    model_sha256: str
    config_sha256: str
    jar_sha256: str
    command: str
    expected_exit_status: int
    expected_witness_marker: str | None
    trial_index: int
    seed: int
    repetition: int
    trial_id: str
    sub_seed: bytes

    @property
    def sub_seed_b64u(self) -> str:
        return _b64u(self.sub_seed)


def _bounded_json_shape(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    visited = 0
    allocation_budget = 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        allocation_budget += 2
        if visited > _MAX_JSON_NODES:
            _fail("JSON contains too many values")
        if depth > _MAX_JSON_DEPTH:
            _fail("JSON exceeds maximum depth")
        if isinstance(item, dict):
            stack.extend((key, depth + 1) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            try:
                allocation_budget += max(len(item) * 6, len(item.encode("utf-8")))
            except UnicodeEncodeError as error:
                raise ContractViolation("value is not canonical JSON") from error
        elif isinstance(item, int):
            allocation_budget += item.bit_length() // 3 + 2
        if allocation_budget > _MAX_JSON_BYTES:
            _fail("JSON input exceeds maximum size")


def canonical_json_bytes(value: object) -> bytes:
    """Encode the empirical JSON profile: sorted, compact UTF-8 plus LF."""
    try:
        _bounded_json_shape(value)
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        raw = encoded.encode("utf-8") + b"\n"
    except ContractViolation:
        raise
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ) as error:
        raise ContractViolation("value is not canonical JSON") from error
    if len(raw) > _MAX_JSON_BYTES:
        _fail("canonical JSON exceeds maximum size")
    return raw


class HashCounterPRNG:
    """Domain-separated SHA-256 hash-counter deterministic byte generator."""

    def __init__(self, *, seed: bytes, domain: bytes) -> None:
        if not isinstance(seed, bytes) or not seed:
            raise ValueError("seed must be non-empty bytes")
        if not isinstance(domain, bytes) or not domain:
            raise ValueError("domain must be non-empty bytes")
        if len(seed) > _MAX_PRNG_READ:
            raise ValueError("seed is too large")
        if len(domain) > 65535:
            raise ValueError("domain is too long")
        self._seed = seed
        self._domain = domain
        self._counter = 0
        self._buffer = b""

    def _block(self) -> bytes:
        if self._counter >= 1 << 64:
            raise OverflowError("hash-counter exhausted")
        material = b"".join(
            (
                _PRNG_PREFIX,
                len(self._domain).to_bytes(2, "big"),
                self._domain,
                len(self._seed).to_bytes(4, "big"),
                self._seed,
                self._counter.to_bytes(8, "big"),
            )
        )
        self._counter += 1
        return hashlib.sha256(material).digest()

    def read(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be a non-negative integer")
        if length > _MAX_PRNG_READ:
            raise ValueError("length is too large")
        buffered = bytearray(self._buffer)
        while len(buffered) < length:
            buffered.extend(self._block())
        result = bytes(buffered[:length])
        self._buffer = bytes(buffered[length:])
        return result

    def randbelow(self, bound: int) -> int:
        if isinstance(bound, bool) or not isinstance(bound, int) or bound <= 0:
            raise ValueError("bound must be a positive integer")
        if bound > _MAX_PRNG_BOUND:
            raise ValueError("bound is too large")
        width = max(1, (bound.bit_length() + 7) // 8)
        ceiling = 1 << (width * 8)
        limit = ceiling - (ceiling % bound)
        while True:
            candidate = int.from_bytes(self.read(width), "big")
            if candidate < limit:
                return candidate % bound


def _fail(message: str) -> NoReturn:
    raise ContractViolation(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON number: {value}")


def _load_canonical(path: Path, *, reject_integral_floats: bool = False) -> object:
    try:
        size = path.stat().st_size
        if size > _MAX_JSON_BYTES:
            _fail("JSON input exceeds maximum size")
        with path.open("rb") as stream:
            raw = stream.read(_MAX_JSON_BYTES + 1)
    except OSError as error:
        raise ContractViolation("cannot read JSON input") from error
    if len(raw) > _MAX_JSON_BYTES:
        _fail("JSON input exceeds maximum size")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_int=_parse_bounded_int_lexeme,
            parse_float=(
                _reject_integral_float_lexeme if reject_integral_floats else float
            ),
        )
        _bounded_json_shape(value)
    except ContractViolation:
        raise
    except (
        RecursionError,
        UnicodeDecodeError,
        UnicodeEncodeError,
        ValueError,
    ) as error:
        raise ContractViolation("invalid UTF-8 JSON") from error
    if canonical_json_bytes(value) != raw:
        _fail("input must use canonical JSON encoding")
    return value


def _reject_integral_float_lexeme(value: str) -> float:
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ContractViolation("invalid JSON number") from error
    if parsed == parsed.to_integral_value():
        _fail("raw result integer lexical form must not use decimal or exponent syntax")
    return float(parsed)


def _parse_bounded_int_lexeme(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 128:
        _fail("JSON integer lexical form exceeds the bounded profile")
    try:
        return int(value)
    except ValueError as error:
        raise ContractViolation("invalid JSON integer") from error


def _mapping(value: object, *, where: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{where} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown:
        _fail(f"{where} has unknown fields: {sorted(unknown)}")
    if missing:
        _fail(f"{where} is missing fields: {sorted(missing)}")
    return value


def _id_sequence(
    value: object,
    *,
    where: str,
    expected: tuple[str, ...],
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        _fail(f"{where} must be an array")
    entries = tuple(_mapping(item, where=where, keys={"id", "name"}) for item in value)
    ids = tuple(item["id"] for item in entries)
    if len(ids) != len(set(ids)):
        _fail(f"{where} contains a duplicate id")
    unknown = set(ids) - set(expected)
    if unknown:
        singular = where[:-1] if where.endswith("s") else where
        _fail(f"unknown {singular}: {sorted(unknown)}")
    if len(ids) != len(expected):
        _fail(f"{where} must contain exactly {len(expected)} entries")
    if ids != expected:
        _fail(f"{where} must use canonical order")
    if any(not isinstance(item["name"], str) or not item["name"] for item in entries):
        _fail(f"{where} names must be non-empty strings")
    return entries


def _validate_matrix(value: object) -> ExperimentMatrix:
    root_keys = {
        "ablation_performance_cells",
        "ablations",
        "attacks",
        "baselines",
        "cache_states",
        "fault_targets",
        "formal_configs",
        "parser_vectors",
        "repetitions",
        "revision",
        "seeds",
        "stores",
        "target_rates_per_second",
        "workloads",
    }
    root = _mapping(value, where="matrix", keys=root_keys)
    if root["revision"] != MATRIX_REVISION:
        _fail(f"revision must be {MATRIX_REVISION}")

    attacks = _id_sequence(root["attacks"], where="attacks", expected=ATTACK_IDS)
    ablations = _id_sequence(
        root["ablations"], where="ablations", expected=ABLATION_IDS
    )
    if tuple(item["name"] for item in attacks) != ATTACK_NAMES:
        _fail("attacks must preserve frozen names")
    if tuple(item["name"] for item in ablations) != ABLATION_NAMES:
        _fail("ablations must preserve frozen names")

    raw_ablation_performance = root["ablation_performance_cells"]
    if not isinstance(raw_ablation_performance, list):
        _fail("ablation_performance_cells must be an array")
    ablation_performance_keys = {
        "ablation_id",
        "baseline_id",
        "cache_state",
        "lifecycle_mode",
        "payload_pair",
        "store",
        "target_rate_per_second",
        "workload_id",
    }
    ablation_performance_entries = tuple(
        _mapping(
            item,
            where="ablation_performance_cells",
            keys=ablation_performance_keys,
        )
        for item in raw_ablation_performance
    )
    if (
        tuple(item["ablation_id"] for item in ablation_performance_entries)
        != ABLATION_IDS
    ):
        _fail("ablation performance cells must preserve canonical ablation order")
    for item in ablation_performance_entries:
        if item != {
            "ablation_id": item["ablation_id"],
            "baseline_id": "B6",
            "cache_state": "warm",
            "lifecycle_mode": "duration",
            "payload_pair": [1024, 4096],
            "store": "sqlite",
            "target_rate_per_second": 100,
            "workload_id": "W1",
        }:
            _fail("ablation performance cell deviates from the matched B6 plan")

    baseline_value = root["baselines"]
    if not isinstance(baseline_value, list):
        _fail("baselines must be an array")
    baseline_entries = tuple(
        _mapping(item, where="baselines", keys={"id", "name", "stores"})
        for item in baseline_value
    )
    baseline_ids = tuple(item["id"] for item in baseline_entries)
    if baseline_ids != BASELINE_IDS:
        _fail("baselines must contain B0-B6 in canonical order")
    if tuple(item["name"] for item in baseline_entries) != BASELINE_NAMES:
        _fail("baselines must preserve frozen names")
    expected_stores = [("sqlite",)] * 6 + [("sqlite", "postgresql")]
    for item, supported in zip(baseline_entries, expected_stores, strict=True):
        if tuple(item["stores"]) != supported:
            _fail(f"baseline {item['id']} has noncanonical stores")

    if tuple(root["stores"]) != STORES:
        _fail("stores must use frozen values and canonical order")
    if tuple(root["target_rates_per_second"]) != TARGET_RATES:
        _fail("target rates must use frozen values")
    if tuple(root["cache_states"]) != CACHE_STATES:
        _fail("cache states must use frozen cold/warm values")
    raw_fault_targets = root["fault_targets"]
    if not isinstance(raw_fault_targets, list):
        _fail("fault_targets must be an array")
    fault_targets = tuple(
        _mapping(item, where="fault_targets", keys={"attack_id", "id"})
        for item in raw_fault_targets
    )
    if tuple(item["id"] for item in fault_targets) != FAULT_TARGETS or tuple(
        item["attack_id"] for item in fault_targets
    ) != (
        "validator-crash",
        "validator-crash",
    ):
        _fail("fault targets must preserve validator/verifier crash mapping")
    if tuple(root["seeds"]) != SEEDS:
        _fail("matrix must use frozen seeds")

    raw_vectors = root["parser_vectors"]
    if not isinstance(raw_vectors, list):
        _fail("parser_vectors must be an array")
    vector_entries = tuple(
        _mapping(
            item,
            where="parser_vectors",
            keys={"expected_code", "id", "mode"},
        )
        for item in raw_vectors
    )
    for item in vector_entries:
        if any(
            not isinstance(item[field], str) or not item[field]
            for field in ("expected_code", "id", "mode")
        ):
            _fail("parser vector fields must be non-empty strings")
    vector_ids = tuple(item["id"] for item in vector_entries)
    if len(vector_ids) != 126 or len(set(vector_ids)) != 126:
        _fail("parser_vectors must contain 126 unique frozen vectors")
    projection_hash = hashlib.sha256(canonical_json_bytes(raw_vectors)).hexdigest()
    if projection_hash != _PARSER_VECTOR_PROJECTION_SHA256:
        _fail("parser_vectors deviate from the frozen corpus projection")

    raw_formal = root["formal_configs"]
    if not isinstance(raw_formal, list):
        _fail("formal_configs must be an array")
    formal_keys = {
        "command",
        "config_sha256",
        "expected_exit_status",
        "id",
        "jar_sha256",
        "model",
        "model_sha256",
        "witness_marker",
    }
    formal_entries = tuple(
        _mapping(item, where="formal_configs", keys=formal_keys) for item in raw_formal
    )
    if tuple(item["id"] for item in formal_entries) != FORMAL_CONFIG_IDS:
        _fail("formal_configs must preserve all six frozen configurations")
    for index, item in enumerate(formal_entries):
        expected_command = (
            "java -cp tla2tools.jar tlc2.TLC -cleanup -config "
            f"{FORMAL_CONFIG_IDS[index]} apcc"
        )
        expected_exit = 0 if index == 0 else 12
        if (
            item["model"] != "apcc.tla"
            or item["model_sha256"] != _FORMAL_MODEL_SHA256
            or item["config_sha256"] != _FORMAL_CONFIG_SHA256[index]
            or item["jar_sha256"] != _TLC_JAR_SHA256
            or item["command"] != expected_command
            or item["expected_exit_status"] != expected_exit
            or item["witness_marker"] != _FORMAL_WITNESSES[index]
        ):
            _fail(f"formal config {FORMAL_CONFIG_IDS[index]} is noncanonical")

    repetition_keys = set(Repetitions.__dataclass_fields__)
    repetition_value = _mapping(
        root["repetitions"], where="repetitions", keys=repetition_keys
    )
    expected_repetitions = {
        "functional_attack_trials_per_cell": 30,
        "functional_attack_trials_per_seed": 6,
        "generated_parser_cases_per_seed": 10_000,
        "measured_runs": 10,
        "minimum_completed_operations": 10_000,
        "parser_vectors_per_build": 126,
        "race_recovery_trials_per_condition": 100,
        "race_recovery_trials_per_seed": 20,
        "run_duration_seconds": 30,
        "storage_commits": 100_000,
        "storage_fresh_databases": 3,
        "timing_repetitions": 30,
        "timing_repetitions_per_seed": 6,
        "unreported_warmups": 3,
    }
    for key, expected in expected_repetitions.items():
        _require_non_negative_integer(repetition_value[key], where=f"repetitions.{key}")
        if repetition_value[key] != expected:
            _fail(f"repetitions.{key} must remain {expected}")

    workload_value = root["workloads"]
    if not isinstance(workload_value, list):
        _fail("workloads must be an array")
    workload_keys = {
        "agents",
        "concurrency",
        "dag",
        "id",
        "input_bytes",
        "name",
        "nodes",
        "output_bytes",
        "parameters",
        "schedule",
    }
    workload_entries = tuple(
        _mapping(item, where="workloads", keys=workload_keys) for item in workload_value
    )
    workload_ids = tuple(item["id"] for item in workload_entries)
    if workload_ids != WORKLOAD_IDS:
        _fail("workloads must contain W1-W10 in canonical order")
    workloads = tuple(_parse_workload(item) for item in workload_entries)
    _validate_workloads(workloads)

    return ExperimentMatrix(
        revision=MATRIX_REVISION,
        matrix_sha256=hashlib.sha256(canonical_json_bytes(value)).hexdigest(),
        baselines=tuple(
            Baseline(str(item["id"]), str(item["name"]), tuple(item["stores"]))
            for item in baseline_entries
        ),
        attacks=tuple(
            NamedDimension(str(item["id"]), str(item["name"])) for item in attacks
        ),
        ablations=tuple(
            NamedDimension(str(item["id"]), str(item["name"])) for item in ablations
        ),
        ablation_performance_cells=tuple(
            AblationPerformanceCell(
                ablation_id=str(item["ablation_id"]),
                baseline_id="B6",
                store="sqlite",
                workload_id="W1",
                payload_pair=(1024, 4096),
                target_rate_per_second=100,
                cache_state="warm",
                lifecycle_mode="duration",
            )
            for item in ablation_performance_entries
        ),
        workloads=workloads,
        stores=STORES,
        target_rates_per_second=TARGET_RATES,
        cache_states=CACHE_STATES,
        fault_targets=tuple(
            NamedDimension(str(item["id"]), str(item["attack_id"]))
            for item in fault_targets
        ),
        parser_vectors=tuple(
            ParserVector(str(item["id"]), str(item["mode"]), str(item["expected_code"]))
            for item in vector_entries
        ),
        formal_configs=tuple(
            FormalConfig(
                id=str(item["id"]),
                model=str(item["model"]),
                model_sha256=str(item["model_sha256"]),
                config_sha256=str(item["config_sha256"]),
                jar_sha256=str(item["jar_sha256"]),
                command=str(item["command"]),
                expected_exit_status=item["expected_exit_status"],
                witness_marker=item["witness_marker"],
            )
            for item in formal_entries
        ),
        seeds=SEEDS,
        repetitions=Repetitions(**repetition_value),
    )


def validate_matrix(value: object) -> ExperimentMatrix:
    """Validate an untrusted matrix and normalize malformed shapes."""
    try:
        return _validate_matrix(value)
    except ContractViolation:
        raise
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError) as error:
        raise ContractViolation("matrix contains a malformed value") from error


def _parse_workload(item: Mapping[str, Any]) -> Workload:
    parameters = item["parameters"]
    if not isinstance(parameters, dict):
        _fail(f"workload {item['id']} parameters must be an object")
    known_parameters = {
        "actor_revocation_ratio",
        "competing_attempts",
        "conflicting_replay_ratio",
        "fan_in",
        "fan_out",
        "payload_pairs_bytes",
        "policy_update_ratio",
        "replay_ratio",
        "workflow_revocation_ratio",
    }
    unknown = set(parameters) - known_parameters
    if unknown:
        _fail(f"workload {item['id']} has unknown fields: {sorted(unknown)}")
    for field in ("nodes", "agents", "concurrency"):
        _require_non_negative_integer(
            item[field], where=f"workload {item['id']}.{field}"
        )
        if item[field] == 0:
            _fail(f"workload {item['id']}.{field} must be positive")
    for field in ("input_bytes", "output_bytes"):
        if item[field] is not None:
            _require_non_negative_integer(
                item[field], where=f"workload {item['id']}.{field}"
            )
    for field in ("fan_out", "fan_in", "competing_attempts"):
        if field in parameters:
            _require_non_negative_integer(
                parameters[field], where=f"workload {item['id']}.{field}"
            )
    for field in (
        "policy_update_ratio",
        "actor_revocation_ratio",
        "workflow_revocation_ratio",
        "replay_ratio",
        "conflicting_replay_ratio",
    ):
        if field in parameters and (
            isinstance(parameters[field], bool)
            or not isinstance(parameters[field], float)
            or not 0.0 <= parameters[field] <= 1.0
        ):
            _fail(f"workload {item['id']}.{field} must be a finite ratio")
    pairs = parameters.get("payload_pairs_bytes", [])
    if not isinstance(pairs, list):
        _fail(f"workload {item['id']}.payload_pairs_bytes must be an array")
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            _fail(f"workload {item['id']}.payload_pairs_bytes contains an invalid pair")
        for size in pair:
            _require_non_negative_integer(
                size, where=f"workload {item['id']}.payload_pairs_bytes"
            )
    return Workload(
        id=str(item["id"]),
        name=str(item["name"]),
        dag=str(item["dag"]),
        nodes=item["nodes"],
        input_bytes=item["input_bytes"],
        output_bytes=item["output_bytes"],
        agents=item["agents"],
        concurrency=item["concurrency"],
        schedule=str(item["schedule"]),
        fan_out=parameters.get("fan_out"),
        fan_in=parameters.get("fan_in"),
        competing_attempts=parameters.get("competing_attempts"),
        policy_update_ratio=parameters.get("policy_update_ratio"),
        actor_revocation_ratio=parameters.get("actor_revocation_ratio"),
        workflow_revocation_ratio=parameters.get("workflow_revocation_ratio"),
        replay_ratio=parameters.get("replay_ratio"),
        conflicting_replay_ratio=parameters.get("conflicting_replay_ratio"),
        payload_pairs_bytes=tuple((pair[0], pair[1]) for pair in pairs),
    )


def _require_non_negative_integer(value: object, *, where: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{where} must be a non-negative integer")


def _validate_workloads(workloads: tuple[Workload, ...]) -> None:
    by_id = {item.id: item for item in workloads}
    if tuple(item.name for item in workloads) != WORKLOAD_NAMES:
        _fail("workloads must preserve frozen names")
    expected_core = {
        "W1": ("single-node", 1, 1024, 4096, 1, 1, "none"),
        "W2": ("linear", 100, 1024, 4096, 100, 16, "none"),
        "W3": ("fan-out", 101, 1024, 4096, 101, 100, "none"),
        "W4": ("fan-in", 101, 1024, 4096, 101, 100, "none"),
        "W5": ("contention", 1, 1024, 4096, 100, 100, "simultaneous"),
        "W6": ("independent", 10_000, 1024, 4096, 1_000, 100, "round-robin"),
        "W7": ("linear", 100, 1024, 4096, 100, 16, "policy-update-1-percent"),
        "W8": ("fan-out", 101, 1024, 4096, 101, 100, "revocation-load"),
        "W9": ("independent", 1, 1024, 4096, 100, 100, "retry-load"),
        "W10": ("payload-sweep", 1, None, None, 1, 1, "none"),
    }
    for workload_id, expected_core_value in expected_core.items():
        item = by_id[workload_id]
        observed = (
            item.dag,
            item.nodes,
            item.input_bytes,
            item.output_bytes,
            item.agents,
            item.concurrency,
            item.schedule,
        )
        if observed != expected_core_value:
            _fail(f"workload {workload_id} deviates from the frozen shape")
    expected_parameters: dict[str, dict[str, object]] = {
        "W3": {"fan_out": 100},
        "W4": {"fan_in": 100},
        "W5": {"competing_attempts": 100},
        "W7": {"policy_update_ratio": 0.01},
        "W8": {"actor_revocation_ratio": 0.01, "workflow_revocation_ratio": 0.001},
        "W9": {"conflicting_replay_ratio": 0.01, "replay_ratio": 0.5},
        "W10": {"payload_pairs_bytes": ((0, 0), (1024, 4096), (65536, 262144))},
    }
    parameter_fields = {
        "fan_out",
        "fan_in",
        "competing_attempts",
        "policy_update_ratio",
        "actor_revocation_ratio",
        "workflow_revocation_ratio",
        "replay_ratio",
        "conflicting_replay_ratio",
        "payload_pairs_bytes",
    }
    for workload in workloads:
        populated = {
            field
            for field in parameter_fields
            if getattr(workload, field) not in {None, ()}
        }
        if populated != set(expected_parameters.get(workload.id, {})):
            _fail(f"workload {workload.id} has noncanonical parameters")
    for workload_id, parameters in expected_parameters.items():
        item = by_id[workload_id]
        for field, expected_parameter_value in parameters.items():
            if getattr(item, field) != expected_parameter_value:
                _fail(f"workload {workload_id}.{field} deviates from the frozen value")


def load_matrix(path: str | Path) -> ExperimentMatrix:
    return validate_matrix(_load_canonical(Path(path)))


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _derive(seed: bytes, domain: bytes, length: int) -> bytes:
    return HashCounterPRNG(seed=seed, domain=domain).read(length)


def _shuffle(values: Sequence[str], *, seed: bytes, domain: bytes) -> tuple[str, ...]:
    result = list(values)
    random = HashCounterPRNG(seed=seed, domain=domain)
    for index in range(len(result) - 1, 0, -1):
        swap = random.randbelow(index + 1)
        result[index], result[swap] = result[swap], result[index]
    return tuple(result)


def baseline_order(matrix: ExperimentMatrix, seed: int) -> tuple[str, ...]:
    if seed not in matrix.seeds:
        _fail("baseline order seed is not frozen")
    return _shuffle(
        tuple(item.id for item in matrix.baselines),
        seed=seed.to_bytes(8, "big"),
        domain=b"baseline-order",
    )


def store_order(matrix: ExperimentMatrix, seed: int) -> tuple[str, ...]:
    try:
        seed_index = matrix.seeds.index(seed)
    except ValueError as error:
        raise ContractViolation("store order seed is not frozen") from error
    return matrix.stores if seed_index % 2 == 0 else tuple(reversed(matrix.stores))


def derive_attack_trial(
    matrix: ExperimentMatrix,
    *,
    baseline_id: str,
    store: str,
    attack_id: str,
    trial_index: int,
) -> AttackTrial:
    baselines = {item.id: item for item in matrix.baselines}
    if baseline_id not in baselines:
        _fail(f"unknown baseline: {baseline_id}")
    if store not in baselines[baseline_id].stores:
        _fail(f"store {store} is unsupported for {baseline_id}")
    if attack_id not in ATTACK_IDS:
        _fail(f"unknown attack: {attack_id}")
    trial_count = matrix.repetitions.functional_attack_trials_per_cell
    if isinstance(trial_index, bool) or not isinstance(trial_index, int):
        _fail("trial index must be an integer")
    if not 0 <= trial_index < trial_count:
        _fail(f"trial index must be in [0, {trial_count})")

    per_seed = matrix.repetitions.functional_attack_trials_per_seed
    seed = matrix.seeds[trial_index // per_seed]
    repetition = trial_index % per_seed
    domain = b"\0".join(
        (
            b"attack-trial",
            baseline_id.encode("ascii"),
            store.encode("ascii"),
            attack_id.encode("ascii"),
            str(trial_index).encode("ascii"),
        )
    )
    sub_seed = _derive(seed.to_bytes(8, "big"), domain, 32)
    return AttackTrial(
        baseline_id=baseline_id,
        store=store,
        attack_id=attack_id,
        trial_index=trial_index,
        seed=seed,
        seed_repetition=repetition,
        trial_id=_b64u(_derive(sub_seed, b"trial-id", 32)),
        sub_seed=sub_seed,
        nonce=_derive(sub_seed, b"nonce", 16),
        key=_derive(sub_seed, b"key", 32),
    )


def planned_attack_trials(matrix: ExperimentMatrix) -> Iterator[AttackTrial]:
    repetitions = matrix.repetitions.functional_attack_trials_per_seed
    for seed in matrix.seeds:
        seed_offset = matrix.seeds.index(seed) * repetitions
        for baseline_id in baseline_order(matrix, seed):
            baseline = next(item for item in matrix.baselines if item.id == baseline_id)
            for store in store_order(matrix, seed):
                if store not in baseline.stores:
                    continue
                for attack_id in ATTACK_IDS:
                    for repetition in range(repetitions):
                        yield derive_attack_trial(
                            matrix,
                            baseline_id=baseline_id,
                            store=store,
                            attack_id=attack_id,
                            trial_index=seed_offset + repetition,
                        )


planned_functional_trials = planned_attack_trials


def _supported_baseline_stores(
    matrix: ExperimentMatrix,
) -> Iterator[tuple[str, str]]:
    for baseline in matrix.baselines:
        for store in baseline.stores:
            yield baseline.id, store


def _planned_identity(*parts: object) -> tuple[str, bytes]:
    domain = b"\0".join(str(part).encode("utf-8") for part in parts)
    sub_seed = _derive(hashlib.sha256(domain).digest(), b"planned-sub-seed", 32)
    return _b64u(_derive(sub_seed, b"planned-trial-id", 32)), sub_seed


def planned_race_recovery_trials(
    matrix: ExperimentMatrix,
) -> Iterator[RaceRecoveryTrial]:
    per_seed = matrix.repetitions.race_recovery_trials_per_seed
    for baseline_id, store in _supported_baseline_stores(matrix):
        for attack_id in RACE_RECOVERY_ATTACKS:
            targets: tuple[str | None, ...] = (
                FAULT_TARGETS if attack_id == "validator-crash" else (None,)
            )
            for fault_target in targets:
                for trial_index in range(
                    matrix.repetitions.race_recovery_trials_per_condition
                ):
                    seed = matrix.seeds[trial_index // per_seed]
                    trial_id, sub_seed = _planned_identity(
                        "race-recovery",
                        baseline_id,
                        store,
                        attack_id,
                        fault_target or "none",
                        trial_index,
                        seed,
                    )
                    yield RaceRecoveryTrial(
                        baseline_id,
                        store,
                        attack_id,
                        fault_target,
                        trial_index,
                        seed,
                        trial_index % per_seed,
                        trial_id,
                        sub_seed,
                    )


def planned_parser_trials(matrix: ExperimentMatrix) -> Iterator[ParserTrial]:
    for case_index, vector in enumerate(matrix.parser_vectors):
        seed = matrix.seeds[case_index % len(matrix.seeds)]
        attack_id = _parser_attack(vector.id, vector.expected_code)
        trial_id, sub_seed = _planned_identity(
            "parser",
            "B6",
            "sqlite",
            "vector",
            vector.id,
            vector.mode,
            vector.expected_code,
        )
        yield ParserTrial(
            "B6",
            "sqlite",
            "vector",
            vector.id,
            attack_id,
            case_index,
            seed,
            0,
            trial_id,
            sub_seed,
        )
    per_seed = matrix.repetitions.generated_parser_cases_per_seed
    for seed in matrix.seeds:
        for seed_repetition in range(per_seed):
            case_index = seed_repetition + matrix.seeds.index(seed) * per_seed
            trial_id, sub_seed = _planned_identity(
                "parser", "B6", "sqlite", "generated", seed, seed_repetition
            )
            yield ParserTrial(
                "B6",
                "sqlite",
                "generated",
                "generated-canonical-parser-case",
                "canonicalization-ambiguity",
                case_index,
                seed,
                seed_repetition,
                trial_id,
                sub_seed,
            )


def _parser_attack(vector_id: str, expected_code: str) -> str:
    if "VERSION" in expected_code:
        return "unknown-protocol-version"
    if expected_code in {"DEPTH_LIMIT_EXCEEDED", "SIZE_LIMIT_EXCEEDED"}:
        return "oversized-certificate"
    if any(
        token in vector_id for token in ("trunc", "missing", "malformed", "trailing")
    ):
        return "certificate-truncation"
    return "canonicalization-ambiguity"


def _workload_variants(workload: Workload) -> tuple[tuple[int, int], ...]:
    if workload.id == "W10":
        return workload.payload_pairs_bytes
    assert workload.input_bytes is not None and workload.output_bytes is not None
    return ((workload.input_bytes, workload.output_bytes),)


def planned_performance_runs(matrix: ExperimentMatrix) -> Iterator[PerformanceRun]:
    for baseline_id, store in _supported_baseline_stores(matrix):
        for workload in matrix.workloads:
            for payload_pair in _workload_variants(workload):
                for target_rate in matrix.target_rates_per_second:
                    for cache_state in matrix.cache_states:
                        for seed in matrix.seeds:
                            phases = [("measured", matrix.repetitions.measured_runs)]
                            if cache_state == "warm":
                                phases.insert(
                                    0,
                                    (
                                        "warmup",
                                        matrix.repetitions.unreported_warmups,
                                    ),
                                )
                            for phase, count in phases:
                                lifecycle_mode = (
                                    "fixed-operations"
                                    if workload.id == "W6"
                                    else "duration"
                                )
                                duration_seconds = (
                                    None
                                    if lifecycle_mode == "fixed-operations"
                                    else matrix.repetitions.run_duration_seconds
                                )
                                operation_limit = (
                                    matrix.repetitions.minimum_completed_operations
                                    if lifecycle_mode == "fixed-operations"
                                    else None
                                )
                                for repetition in range(count):
                                    trial_id, sub_seed = _planned_identity(
                                        "performance",
                                        baseline_id,
                                        store,
                                        workload.id,
                                        payload_pair[0],
                                        payload_pair[1],
                                        target_rate,
                                        cache_state,
                                        seed,
                                        phase,
                                        repetition,
                                    )
                                    yield PerformanceRun(
                                        baseline_id,
                                        store,
                                        workload.id,
                                        target_rate,
                                        cache_state,
                                        seed,
                                        repetition,
                                        phase,
                                        repetition,
                                        trial_id,
                                        sub_seed,
                                        payload_pair,
                                        lifecycle_mode,
                                        duration_seconds,
                                        operation_limit,
                                    )


def planned_ablation_performance_runs(
    matrix: ExperimentMatrix,
) -> Iterator[PerformanceRun]:
    """Schedule one matched B6 performance cell for every initial-v1 ablation."""
    for cell in matrix.ablation_performance_cells:
        for seed in matrix.seeds:
            for phase, count in (
                ("warmup", matrix.repetitions.unreported_warmups),
                ("measured", matrix.repetitions.measured_runs),
            ):
                for repetition in range(count):
                    trial_id, sub_seed = _planned_identity(
                        "ablation-performance",
                        cell.ablation_id,
                        cell.baseline_id,
                        cell.store,
                        cell.workload_id,
                        cell.payload_pair[0],
                        cell.payload_pair[1],
                        cell.target_rate_per_second,
                        cell.cache_state,
                        cell.lifecycle_mode,
                        seed,
                        phase,
                        repetition,
                    )
                    yield PerformanceRun(
                        baseline_id=cell.baseline_id,
                        store=cell.store,
                        workload_id=cell.workload_id,
                        target_rate_per_second=cell.target_rate_per_second,
                        cache_state=cell.cache_state,
                        seed=seed,
                        repetition=repetition,
                        phase=phase,
                        trial_index=repetition,
                        trial_id=trial_id,
                        sub_seed=sub_seed,
                        payload_pair=cell.payload_pair,
                        lifecycle_mode=cell.lifecycle_mode,
                        duration_seconds=matrix.repetitions.run_duration_seconds,
                        operation_limit=None,
                        ablation_id=cell.ablation_id,
                    )


def planned_timing_trials(matrix: ExperimentMatrix) -> Iterator[TimingTrial]:
    per_seed = matrix.repetitions.timing_repetitions_per_seed
    for baseline_id, store in _supported_baseline_stores(matrix):
        for condition_id in TIMING_CONDITIONS:
            for trial_index in range(matrix.repetitions.timing_repetitions):
                seed = matrix.seeds[trial_index // per_seed]
                trial_id, sub_seed = _planned_identity(
                    "timing", baseline_id, store, condition_id, trial_index, seed
                )
                yield TimingTrial(
                    baseline_id,
                    store,
                    condition_id,
                    trial_index,
                    seed,
                    trial_index % per_seed,
                    trial_id,
                    sub_seed,
                )


def planned_storage_runs(matrix: ExperimentMatrix) -> Iterator[StorageRun]:
    for baseline_id, store in _supported_baseline_stores(matrix):
        for database_index in range(matrix.repetitions.storage_fresh_databases):
            seed = matrix.seeds[database_index]
            trial_id, sub_seed = _planned_identity(
                "storage", baseline_id, store, database_index
            )
            yield StorageRun(
                baseline_id,
                store,
                database_index,
                matrix.repetitions.storage_commits,
                trial_id,
                seed,
                database_index,
                database_index,
                sub_seed,
            )


def planned_ablation_trials(matrix: ExperimentMatrix) -> Iterator[AblationTrial]:
    per_seed = matrix.repetitions.functional_attack_trials_per_seed
    for ablation_id, attack_id in zip(ABLATION_IDS, ABLATION_ATTACKS, strict=True):
        for trial_index in range(matrix.repetitions.functional_attack_trials_per_cell):
            seed = matrix.seeds[trial_index // per_seed]
            condition_id = f"{ablation_id}:{attack_id}:matched-W1"
            trial_id, sub_seed = _planned_identity(
                "ablation",
                ablation_id,
                attack_id,
                "B6",
                "sqlite",
                condition_id,
                trial_index,
                seed,
            )
            yield AblationTrial(
                ablation_id,
                attack_id,
                "B6",
                "sqlite",
                condition_id,
                trial_index,
                seed,
                trial_index % per_seed,
                trial_id,
                sub_seed,
            )


def planned_formal_runs(matrix: ExperimentMatrix) -> Iterator[FormalRun]:
    for trial_index, config in enumerate(matrix.formal_configs):
        seed = matrix.seeds[trial_index % len(matrix.seeds)]
        trial_id, sub_seed = _planned_identity(
            "formal",
            "B6",
            "sqlite",
            config.id,
            config.model_sha256,
            config.config_sha256,
            config.jar_sha256,
            config.command,
        )
        yield FormalRun(
            "B6",
            "sqlite",
            config.id,
            config.model,
            config.model_sha256,
            config.config_sha256,
            config.jar_sha256,
            config.command,
            config.expected_exit_status,
            config.witness_marker,
            trial_index,
            seed,
            0,
            trial_id,
            sub_seed,
        )


def planning_cardinalities(matrix: ExperimentMatrix) -> dict[str, int]:
    supported_pairs = sum(len(item.stores) for item in matrix.baselines)
    workload_variant_count = sum(
        len(_workload_variants(item)) for item in matrix.workloads
    )
    performance_cells = (
        supported_pairs
        * workload_variant_count
        * len(matrix.target_rates_per_second)
        * len(matrix.cache_states)
        * len(matrix.seeds)
    )
    race_conditions = len(RACE_RECOVERY_ATTACKS) + len(FAULT_TARGETS) - 1
    storage_runs = supported_pairs * matrix.repetitions.storage_fresh_databases
    ablation_performance_cells = len(matrix.ablation_performance_cells) * len(
        matrix.seeds
    )
    return {
        "functional_attack": supported_pairs
        * len(matrix.attacks)
        * matrix.repetitions.functional_attack_trials_per_cell,
        "race_recovery": supported_pairs
        * race_conditions
        * matrix.repetitions.race_recovery_trials_per_condition,
        "parser_vector": len(matrix.parser_vectors),
        "parser_generated": len(matrix.seeds)
        * matrix.repetitions.generated_parser_cases_per_seed,
        "parser": len(matrix.parser_vectors)
        + len(matrix.seeds) * matrix.repetitions.generated_parser_cases_per_seed,
        "timing": supported_pairs
        * len(TIMING_CONDITIONS)
        * matrix.repetitions.timing_repetitions,
        "performance_warmup": performance_cells
        // len(matrix.cache_states)
        * matrix.repetitions.unreported_warmups,
        "performance_measured": performance_cells * matrix.repetitions.measured_runs,
        "ablation_performance_warmup": ablation_performance_cells
        * matrix.repetitions.unreported_warmups,
        "ablation_performance_measured": ablation_performance_cells
        * matrix.repetitions.measured_runs,
        "storage_runs": storage_runs,
        "storage_commits": storage_runs * matrix.repetitions.storage_commits,
        "ablation": len(matrix.ablations)
        * matrix.repetitions.functional_attack_trials_per_cell,
        "formal": len(matrix.formal_configs),
    }


_RAW_RESULT_KEYS = {
    "ablation_id",
    "artifact_sha256",
    "attack_id",
    "authoritative_compromise",
    "authoritative_outcome",
    "baseline_id",
    "byte_counts",
    "cache_state",
    "case_index",
    "condition_id",
    "concurrency",
    "dag",
    "database_index",
    "detected",
    "distinct_states",
    "environment_id",
    "fail_closed",
    "failed_invariant",
    "failure_code",
    "fault_target",
    "formal_evidence",
    "git_sha",
    "generated_states",
    "incorrect_current_consumption",
    "input_bytes",
    "matrix_sha256",
    "matrix_revision",
    "outcome",
    "output_bytes",
    "phase",
    "record_type",
    "recovered",
    "repetition",
    "schema_version",
    "search_depth",
    "seed",
    "store",
    "sub_seed_b64u",
    "successful_commits",
    "target_rate_per_second",
    "timings_ns",
    "tool_versions",
    "trial_id",
    "trial_index",
    "cost_saved_ns",
    "ablation_classification",
    "witness_marker",
    "workload_id",
    "workload_evidence",
}


def load_raw_result(path: str | Path, *, matrix: ExperimentMatrix) -> dict[str, Any]:
    value = _load_canonical(Path(path), reject_integral_floats=True)
    record = _mapping(value, where="raw result", keys=_RAW_RESULT_KEYS)
    try:
        _validate_raw_result(record, matrix)
    except ContractViolation:
        raise
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError) as error:
        raise ContractViolation("raw result contains a malformed value") from error
    return dict(record)


def _validate_raw_result(record: Mapping[str, Any], matrix: ExperimentMatrix) -> None:
    if record["schema_version"] != RAW_RESULT_SCHEMA_VERSION:
        _fail("raw result has unknown schema version")
    if record["matrix_revision"] != matrix.revision:
        _fail("raw result has unknown matrix revision")
    if record["matrix_sha256"] != matrix.matrix_sha256:
        _fail("raw result matrix hash does not match the frozen matrix")
    record_type = record["record_type"]
    if record_type not in RAW_RECORD_TYPES:
        _fail("raw result has unknown record type")
    attack_id = record["attack_id"]
    if attack_id is not None and attack_id not in ATTACK_IDS:
        _fail("raw result has unknown attack")
    ablation_id = record["ablation_id"]
    if ablation_id is not None and ablation_id not in ABLATION_IDS:
        _fail("raw result has unknown ablation")
    baselines = {item.id: item for item in matrix.baselines}
    baseline_id = record["baseline_id"]
    if baseline_id not in baselines:
        _fail("raw result has unknown baseline")
    store = record["store"]
    if store not in baselines[baseline_id].stores:
        _fail(f"store {store} is unsupported for {baseline_id}")
    if record["workload_id"] not in WORKLOAD_IDS:
        _fail("raw result has unknown workload")
    if record["cache_state"] not in CACHE_STATES:
        _fail("raw result has unknown cache state")
    if record["target_rate_per_second"] not in TARGET_RATES:
        _fail("raw result has unknown target rate")
    if record["outcome"] not in {"accepted", "rejected", "failed"}:
        _fail("raw result has unknown outcome")
    if record["authoritative_outcome"] not in {
        "none",
        "committed",
        "denied",
        "conflicted",
        "unavailable",
    }:
        _fail("raw result has unknown authoritative outcome")
    for key in (
        "authoritative_compromise",
        "incorrect_current_consumption",
        "detected",
        "fail_closed",
        "recovered",
    ):
        if type(record[key]) is not bool:
            _fail(f"raw result {key} must be boolean")
    if not isinstance(record["environment_id"], str) or not record["environment_id"]:
        _fail("raw result environment_id must be non-empty")
    if (
        not isinstance(record["git_sha"], str)
        or _GIT_SHA.fullmatch(record["git_sha"]) is None
    ):
        _fail("raw result git_sha must be lowercase SHA-1")
    if (
        not isinstance(record["artifact_sha256"], str)
        or _SHA256_HEX.fullmatch(record["artifact_sha256"]) is None
    ):
        _fail("raw result artifact_sha256 must be lowercase SHA-256")
    failure_code = record["failure_code"]
    if failure_code is not None and (
        not isinstance(failure_code, str) or not failure_code
    ):
        _fail("raw result failure_code must be null or non-empty")
    _validate_outcome_truth(record)
    for field, maximum in (("repetition", 9_999), ("trial_index", 50_000)):
        _raw_integer(record[field], where=field, minimum=0, maximum=maximum)
    _raw_integer(record["concurrency"], where="concurrency", minimum=1)
    for field in ("input_bytes", "output_bytes"):
        if record[field] is not None:
            _raw_integer(record[field], where=field, minimum=0)
    for field in ("case_index", "database_index", "successful_commits"):
        if record[field] is not None:
            optional_maximum = 2 if field == "database_index" else None
            _raw_integer(
                record[field], where=field, minimum=0, maximum=optional_maximum
            )
    for field in (
        "generated_states",
        "distinct_states",
        "search_depth",
        "cost_saved_ns",
    ):
        if record[field] is not None:
            _raw_integer(record[field], where=field, minimum=0)
    if record["seed"] not in matrix.seeds:
        _fail("raw result has unknown seed")
    if not isinstance(record["dag"], str) or not record["dag"]:
        _fail("raw result dag must be non-empty")
    for field in ("trial_id", "sub_seed_b64u"):
        if (
            not isinstance(record[field], str)
            or _B64U_256.fullmatch(record[field]) is None
        ):
            _fail(f"raw result {field} must be canonical base64url")
    for field in ("timings_ns", "byte_counts"):
        _raw_non_negative_integer_map(record[field], where=field)
    versions = record["tool_versions"]
    if (
        not isinstance(versions, dict)
        or not versions
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or not value
            for key, value in versions.items()
        )
    ):
        _fail("raw result tool_versions must be a non-empty string map")

    workload = next(
        item for item in matrix.workloads if item.id == record["workload_id"]
    )
    _validate_workload_evidence(record, workload, matrix)
    if record["concurrency"] != workload.concurrency or record["dag"] != workload.dag:
        _fail("raw result workload evidence does not match the frozen workload")

    _validate_raw_record_family(record_type, record, attack_id, ablation_id)
    if record_type != "performance" and (
        record["workload_id"] != "W1"
        or record["target_rate_per_second"] != 10
        or record["cache_state"] != "cold"
    ):
        _fail("raw result generic dimensions are outside its scheduled planner cell")
    if record_type == "functional-attack":
        assert isinstance(attack_id, str)
        trial = derive_attack_trial(
            matrix,
            baseline_id=baseline_id,
            store=store,
            attack_id=attack_id,
            trial_index=record["trial_index"],
        )
        if (
            record["seed"] != trial.seed
            or record["repetition"] != trial.seed_repetition
        ):
            _fail("raw result seed/repetition does not match its trial index")
        if record["trial_id"] != trial.trial_id:
            _fail("raw result trial_id does not match deterministic derivation")
        if record["sub_seed_b64u"] != trial.sub_seed_b64u:
            _fail("raw result sub-seed does not match deterministic derivation")
    else:
        _validate_nonfunctional_identity(record_type, record, matrix)


def _validate_outcome_truth(record: Mapping[str, Any]) -> None:
    outcome = record["outcome"]
    authoritative = record["authoritative_outcome"]
    compromise = record["authoritative_compromise"]
    incorrect = record["incorrect_current_consumption"]
    fail_closed = record["fail_closed"]
    detected = record["detected"]
    recovered = record["recovered"]
    failure_present = record["failure_code"] is not None
    allowed_authority = {
        "accepted": {"none", "committed"},
        "rejected": {"none", "denied", "conflicted"},
        "failed": {"none", "unavailable", "committed"},
    }
    valid = (
        (not incorrect or compromise)
        and fail_closed == (not compromise)
        and (not recovered or detected)
        and ((outcome != "accepted") is failure_present)
        and (outcome == "accepted" or detected)
        and authoritative in allowed_authority[outcome]
        and not (outcome == "rejected" and compromise)
        and not (outcome == "failed" and compromise and authoritative != "committed")
    )
    if not valid:
        _fail("raw result outcome fields contradict the empirical truth table")


def _workload_parameters(workload: Workload) -> dict[str, object]:
    fields = (
        "fan_out",
        "fan_in",
        "competing_attempts",
        "policy_update_ratio",
        "actor_revocation_ratio",
        "workflow_revocation_ratio",
        "replay_ratio",
        "conflicting_replay_ratio",
    )
    result = {
        field: getattr(workload, field)
        for field in fields
        if getattr(workload, field) is not None
    }
    if workload.payload_pairs_bytes:
        result["payload_pairs_bytes"] = [
            list(pair) for pair in workload.payload_pairs_bytes
        ]
    return result


def _validate_workload_evidence(
    record: Mapping[str, Any], workload: Workload, matrix: ExperimentMatrix
) -> None:
    keys = {
        "agents",
        "completed_operations",
        "duration_seconds",
        "incomplete_run",
        "lifecycle_mode",
        "nodes",
        "operation_limit",
        "parameters",
        "payload_pair",
        "pre_run_queries",
        "schedule",
        "warmup_runs_completed",
    }
    evidence = _mapping(
        record["workload_evidence"], where="workload_evidence", keys=keys
    )
    for field in (
        "agents",
        "completed_operations",
        "nodes",
        "pre_run_queries",
        "warmup_runs_completed",
    ):
        _raw_integer(evidence[field], where=f"workload_evidence.{field}", minimum=0)
    for field in ("duration_seconds", "operation_limit"):
        if evidence[field] is not None:
            _raw_integer(evidence[field], where=f"workload_evidence.{field}", minimum=0)
    pair = evidence["payload_pair"]
    if (
        not isinstance(pair, list)
        or len(pair) != 2
        or any(type(item) is not int or item < 0 for item in pair)
    ):
        _fail("raw result workload payload pair is malformed")
    if (
        evidence["agents"] != workload.agents
        or evidence["nodes"] != workload.nodes
        or evidence["schedule"] != workload.schedule
        or evidence["parameters"] != _workload_parameters(workload)
        or tuple(pair) not in _workload_variants(workload)
        or record["input_bytes"] != pair[0]
        or record["output_bytes"] != pair[1]
        or type(evidence["incomplete_run"]) is not bool
    ):
        _fail("raw result workload evidence does not match the frozen workload")
    if record["record_type"] != "performance":
        if evidence != {
            "agents": workload.agents,
            "completed_operations": 1,
            "duration_seconds": None,
            "incomplete_run": False,
            "lifecycle_mode": "single-trial",
            "nodes": workload.nodes,
            "operation_limit": None,
            "parameters": _workload_parameters(workload),
            "payload_pair": pair,
            "pre_run_queries": 0,
            "schedule": workload.schedule,
            "warmup_runs_completed": 0,
        }:
            _fail("nonperformance workload must use the single-trial lifecycle")
        return
    fixed = workload.id == "W6"
    expected_mode = "fixed-operations" if fixed else "duration"
    if (
        evidence["lifecycle_mode"] != expected_mode
        or evidence["duration_seconds"]
        != (None if fixed else matrix.repetitions.run_duration_seconds)
        or evidence["operation_limit"]
        != (matrix.repetitions.minimum_completed_operations if fixed else None)
    ):
        _fail("performance workload lifecycle deviates from the frozen plan")
    completed = evidence["completed_operations"]
    if fixed:
        if (
            completed != matrix.repetitions.minimum_completed_operations
            or evidence["incomplete_run"]
        ):
            _fail("W6 must complete its fixed operation count")
    elif evidence["incomplete_run"] != (
        completed < matrix.repetitions.minimum_completed_operations
    ):
        _fail("performance incomplete-run flag does not match completed operations")
    if record["cache_state"] == "cold":
        if evidence["pre_run_queries"] != 0 or evidence["warmup_runs_completed"] != 0:
            _fail("cold performance cells cannot have pre-run queries or warmups")
    else:
        expected_warmups = (
            record["repetition"]
            if record["phase"] == "warmup"
            else matrix.repetitions.unreported_warmups
        )
        if (
            evidence["pre_run_queries"] == 0
            or evidence["warmup_runs_completed"] != expected_warmups
        ):
            _fail("warm performance cells must bind their warmup lifecycle")


def _validate_nonfunctional_identity(
    record_type: object, record: Mapping[str, Any], matrix: ExperimentMatrix
) -> None:
    trial_id: str
    sub_seed: bytes
    if record_type == "race-recovery":
        trial_index = record["trial_index"]
        per_seed = matrix.repetitions.race_recovery_trials_per_seed
        if record["attack_id"] not in RACE_RECOVERY_ATTACKS:
            _fail("race/recovery attack is unscheduled")
        if trial_index >= matrix.repetitions.race_recovery_trials_per_condition:
            _fail("race/recovery trial index is unscheduled")
        seed = matrix.seeds[trial_index // per_seed]
        if record["condition_id"] != record["attack_id"]:
            _fail("race/recovery condition does not match its attack")
        trial_id, sub_seed = _planned_identity(
            "race-recovery",
            record["baseline_id"],
            record["store"],
            record["attack_id"],
            record["fault_target"] or "none",
            trial_index,
            seed,
        )
        repetition = trial_index % per_seed
    elif record_type == "parser":
        case_index = record["case_index"]
        if record["phase"] == "vector":
            if not 0 <= case_index < len(matrix.parser_vectors):
                _fail("parser vector identity is unscheduled")
            vector = matrix.parser_vectors[case_index]
            seed = matrix.seeds[case_index % len(matrix.seeds)]
            repetition = 0
            if (
                record["baseline_id"] != "B6"
                or record["store"] != "sqlite"
                or record["condition_id"] != vector.id
                or record["attack_id"]
                != _parser_attack(vector.id, vector.expected_code)
            ):
                _fail("parser vector identity does not match the frozen corpus")
            trial_id, sub_seed = _planned_identity(
                "parser",
                "B6",
                "sqlite",
                "vector",
                vector.id,
                vector.mode,
                vector.expected_code,
            )
        else:
            per_seed = matrix.repetitions.generated_parser_cases_per_seed
            if not 0 <= case_index < len(matrix.seeds) * per_seed:
                _fail("generated parser identity is unscheduled")
            seed = matrix.seeds[case_index // per_seed]
            repetition = case_index % per_seed
            if (
                record["baseline_id"] != "B6"
                or record["store"] != "sqlite"
                or record["condition_id"] != "generated-canonical-parser-case"
                or record["attack_id"] != "canonicalization-ambiguity"
            ):
                _fail("generated parser identity is noncanonical")
            trial_id, sub_seed = _planned_identity(
                "parser", "B6", "sqlite", "generated", seed, repetition
            )
        if record["trial_index"] != case_index:
            _fail("parser trial index must equal its case index")
    elif record_type == "timing":
        trial_index = record["trial_index"]
        per_seed = matrix.repetitions.timing_repetitions_per_seed
        if trial_index >= matrix.repetitions.timing_repetitions:
            _fail("timing trial index is unscheduled")
        seed = matrix.seeds[trial_index // per_seed]
        repetition = trial_index % per_seed
        trial_id, sub_seed = _planned_identity(
            "timing",
            record["baseline_id"],
            record["store"],
            record["condition_id"],
            trial_index,
            seed,
        )
    elif record_type == "performance":
        workload = next(
            item for item in matrix.workloads if item.id == record["workload_id"]
        )
        pair = record["workload_evidence"]["payload_pair"]
        repetition = record["repetition"]
        limit = (
            matrix.repetitions.unreported_warmups
            if record["phase"] == "warmup"
            else matrix.repetitions.measured_runs
        )
        if not 0 <= repetition < limit or record["trial_index"] != repetition:
            _fail("performance repetition is unscheduled")
        if record["phase"] == "warmup" and record["cache_state"] != "warm":
            _fail("cold cells cannot schedule warmup runs")
        seed = record["seed"]
        ablation_id = record["ablation_id"]
        if ablation_id is None:
            trial_id, sub_seed = _planned_identity(
                "performance",
                record["baseline_id"],
                record["store"],
                workload.id,
                pair[0],
                pair[1],
                record["target_rate_per_second"],
                record["cache_state"],
                seed,
                record["phase"],
                repetition,
            )
        else:
            cell = next(
                item
                for item in matrix.ablation_performance_cells
                if item.ablation_id == ablation_id
            )
            if (
                record["baseline_id"],
                record["store"],
                workload.id,
                tuple(pair),
                record["target_rate_per_second"],
                record["cache_state"],
                record["workload_evidence"]["lifecycle_mode"],
            ) != (
                cell.baseline_id,
                cell.store,
                cell.workload_id,
                cell.payload_pair,
                cell.target_rate_per_second,
                cell.cache_state,
                cell.lifecycle_mode,
            ):
                _fail("ablation performance tuple is outside its matched planner cell")
            trial_id, sub_seed = _planned_identity(
                "ablation-performance",
                cell.ablation_id,
                cell.baseline_id,
                cell.store,
                cell.workload_id,
                cell.payload_pair[0],
                cell.payload_pair[1],
                cell.target_rate_per_second,
                cell.cache_state,
                cell.lifecycle_mode,
                seed,
                record["phase"],
                repetition,
            )
    elif record_type == "storage":
        database_index = record["database_index"]
        if database_index >= matrix.repetitions.storage_fresh_databases:
            _fail("storage database index is unscheduled")
        seed = matrix.seeds[database_index]
        repetition = database_index
        if record["trial_index"] != database_index:
            _fail("storage trial index must equal database index")
        trial_id, sub_seed = _planned_identity(
            "storage", record["baseline_id"], record["store"], database_index
        )
    elif record_type == "ablation":
        trial_index = record["trial_index"]
        per_seed = matrix.repetitions.functional_attack_trials_per_seed
        if trial_index >= matrix.repetitions.functional_attack_trials_per_cell:
            _fail("ablation trial index is unscheduled")
        ablation_index = ABLATION_IDS.index(record["ablation_id"])
        expected_attack = ABLATION_ATTACKS[ablation_index]
        expected_condition = f"{record['ablation_id']}:{expected_attack}:matched-W1"
        if (
            record["baseline_id"] != "B6"
            or record["store"] != "sqlite"
            or record["attack_id"] != expected_attack
            or record["condition_id"] != expected_condition
        ):
            _fail("ablation tuple is not in the frozen plan")
        seed = matrix.seeds[trial_index // per_seed]
        repetition = trial_index % per_seed
        trial_id, sub_seed = _planned_identity(
            "ablation",
            record["ablation_id"],
            expected_attack,
            "B6",
            "sqlite",
            expected_condition,
            trial_index,
            seed,
        )
    elif record_type == "formal":
        trial_index = record["trial_index"]
        if not 0 <= trial_index < len(matrix.formal_configs):
            _fail("formal configuration is unscheduled")
        config = matrix.formal_configs[trial_index]
        if record["condition_id"] != config.id:
            _fail("formal condition does not match its configuration")
        if record["baseline_id"] != "B6" or record["store"] != "sqlite":
            _fail("formal records must use the frozen B6 SQLite tuple")
        seed = matrix.seeds[trial_index % len(matrix.seeds)]
        repetition = 0
        trial_id, sub_seed = _planned_identity(
            "formal",
            "B6",
            "sqlite",
            config.id,
            config.model_sha256,
            config.config_sha256,
            config.jar_sha256,
            config.command,
        )
        _validate_formal_evidence(record, config)
    else:
        _fail("raw result has unknown record type")
    if (
        record["seed"] != seed
        or record["repetition"] != repetition
        or record["trial_id"] != trial_id
        or record["sub_seed_b64u"] != _b64u(sub_seed)
    ):
        _fail("raw result does not match its deterministic planner identity")


def _validate_formal_evidence(record: Mapping[str, Any], config: FormalConfig) -> None:
    keys = {
        "command",
        "config_sha256",
        "duration_ns",
        "exit_status",
        "failure",
        "jar_sha256",
        "model",
        "model_sha256",
    }
    evidence = _mapping(record["formal_evidence"], where="formal_evidence", keys=keys)
    _raw_integer(
        evidence["duration_ns"], where="formal_evidence.duration_ns", minimum=0
    )
    if type(evidence["exit_status"]) is not int:
        _fail("formal exit status must be an integer")
    if (
        evidence["command"] != config.command
        or evidence["config_sha256"] != config.config_sha256
        or evidence["jar_sha256"] != config.jar_sha256
        or evidence["model"] != config.model
        or evidence["model_sha256"] != config.model_sha256
    ):
        _fail("formal evidence does not match the frozen configuration")
    succeeded = evidence["exit_status"] == config.expected_exit_status
    failure = evidence["failure"]
    if succeeded:
        if failure is not None or record["witness_marker"] != config.witness_marker:
            _fail("successful formal evidence has mismatched witness or failure")
    elif not isinstance(failure, str) or not failure:
        _fail("failed formal evidence must retain a failure description")


def _raw_integer(
    value: object, *, where: str, minimum: int, maximum: int | None = None
) -> None:
    if (
        type(value) is not int
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        _fail(f"raw result {where} must be an integer in range")


def _raw_non_negative_integer_map(value: object, *, where: str) -> None:
    if (
        not isinstance(value, dict)
        or not value
        or any(
            not isinstance(key, str) or not key or type(item) is not int or item < 0
            for key, item in value.items()
        )
    ):
        _fail(f"raw result {where} must be a non-empty integer map")


def _validate_raw_record_family(
    record_type: object,
    record: Mapping[str, Any],
    attack_id: object,
    ablation_id: object,
) -> None:
    def require_null(*names: str) -> None:
        if any(record[name] is not None for name in names):
            _fail(f"raw result {record_type} has incompatible fields")

    if record_type != "formal":
        require_null(
            "generated_states", "distinct_states", "search_depth", "witness_marker"
        )
        if record["formal_evidence"] is not None:
            _fail("only formal records may contain formal evidence")
    if record_type != "ablation":
        require_null("failed_invariant", "cost_saved_ns", "ablation_classification")

    if record_type == "functional-attack":
        if attack_id is None or ablation_id is not None:
            _fail("functional attack requires only an attack")
        require_null(
            "case_index",
            "condition_id",
            "database_index",
            "fault_target",
            "phase",
            "successful_commits",
        )
    elif record_type == "race-recovery":
        if attack_id is None or ablation_id is not None:
            _fail("race/recovery requires only an attack")
        if (
            record["phase"] != "fault"
            or not isinstance(record["condition_id"], str)
            or not record["condition_id"]
        ):
            _fail("race/recovery requires its fault condition")
        require_null("case_index", "database_index", "successful_commits")
        fault_target = record["fault_target"]
        if attack_id == "validator-crash":
            if fault_target not in FAULT_TARGETS:
                _fail("validator crash requires validator/verifier fault target")
        elif fault_target is not None:
            _fail("only validator crash may select a fault target")
    elif record_type == "parser":
        if attack_id is None or ablation_id is not None:
            _fail("parser record requires only an attack")
        if record["phase"] not in {"vector", "generated"}:
            _fail("parser record has unknown phase")
        if (
            type(record["case_index"]) is not int
            or not isinstance(record["condition_id"], str)
            or not record["condition_id"]
        ):
            _fail("parser record requires case and condition")
        require_null("database_index", "fault_target", "successful_commits")
    elif record_type == "timing":
        if attack_id is not None or ablation_id is not None:
            _fail("timing record cannot select attack or ablation")
        if (
            record["condition_id"] not in TIMING_CONDITIONS
            or record["phase"] != "measured"
        ):
            _fail("timing record has unknown condition or phase")
        require_null(
            "case_index", "database_index", "fault_target", "successful_commits"
        )
    elif record_type == "performance":
        if attack_id is not None or (
            ablation_id is not None and ablation_id not in ABLATION_IDS
        ):
            _fail("performance record has incompatible attack/ablation")
        if record["phase"] not in {"warmup", "measured"}:
            _fail("performance record has unknown phase")
        require_null(
            "case_index",
            "condition_id",
            "database_index",
            "fault_target",
            "successful_commits",
        )
    elif record_type == "storage":
        if attack_id is not None or ablation_id is not None:
            _fail("storage record cannot select attack or ablation")
        if record["successful_commits"] != 100_000:
            _fail("storage record must contain 100000 successful commits")
        if type(record["database_index"]) is not int:
            _fail("storage record requires database index")
        require_null("case_index", "condition_id", "fault_target", "phase")
    elif record_type == "ablation":
        if (
            attack_id is None
            or ablation_id is None
            or not isinstance(record["condition_id"], str)
            or not record["condition_id"]
        ):
            _fail("ablation record requires attack, ablation, and condition")
        if (
            not isinstance(record["failed_invariant"], str)
            or not record["failed_invariant"]
            or type(record["cost_saved_ns"]) is not int
            or record["ablation_classification"]
            not in {"essential", "defense-in-depth", "redundant"}
        ):
            _fail("ablation record requires invariant, cost, and classification")
        require_null(
            "case_index",
            "database_index",
            "fault_target",
            "phase",
            "successful_commits",
        )
    elif record_type == "formal":
        if attack_id is not None or ablation_id is not None:
            _fail("formal record cannot select attack or ablation")
        if (
            not isinstance(record["condition_id"], str)
            or not record["condition_id"]
            or record["phase"] != "measured"
            or any(
                type(record[field]) is not int
                for field in ("generated_states", "distinct_states", "search_depth")
            )
            or (
                record["witness_marker"] is not None
                and (
                    not isinstance(record["witness_marker"], str)
                    or not record["witness_marker"]
                )
            )
            or not isinstance(record["formal_evidence"], dict)
        ):
            _fail("formal record requires model state and witness evidence")
        require_null(
            "case_index", "database_index", "fault_target", "successful_commits"
        )
    else:
        _fail("raw result has unknown record type")


__all__ = [
    "ABLATION_IDS",
    "ATTACK_IDS",
    "AttackTrial",
    "AblationTrial",
    "AblationPerformanceCell",
    "Baseline",
    "ContractViolation",
    "ExperimentMatrix",
    "FormalRun",
    "FAULT_TARGETS",
    "HashCounterPRNG",
    "NamedDimension",
    "Repetitions",
    "RaceRecoveryTrial",
    "ParserTrial",
    "PerformanceRun",
    "StorageRun",
    "TimingTrial",
    "Workload",
    "baseline_order",
    "canonical_json_bytes",
    "derive_attack_trial",
    "load_matrix",
    "load_raw_result",
    "planned_parser_trials",
    "planned_ablation_trials",
    "planned_ablation_performance_runs",
    "planned_formal_runs",
    "planned_functional_trials",
    "planned_performance_runs",
    "planned_race_recovery_trials",
    "planned_storage_runs",
    "planned_timing_trials",
    "planning_cardinalities",
    "planned_attack_trials",
    "store_order",
    "validate_matrix",
]
