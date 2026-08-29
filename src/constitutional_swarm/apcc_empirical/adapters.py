"""Isolated empirical baselines and the narrow B6 execution adapter."""

from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.authority_service import _SwarmExecutionHandle
from constitutional_swarm.governed_commit import CommitRequest


class Capability(StrEnum):
    DURABLE_SNAPSHOT = "durable-snapshot"
    POST_HOC_AUDIT = "post-hoc-audit"
    POLICY_GATE = "policy-gate"
    SIGNED_RESULT = "signed-result"
    PROOF_VALIDATION = "proof-validation"
    ATOMIC_COMMIT = "atomic-commit"
    CURRENT_STATUS = "current-status"
    REVOCATION = "revocation"
    SUPERSESSION = "supersession"
    RECOVERY = "recovery"
    REOPEN = "reopen"
    OUTBOX = "outbox"
    ARTIFACT_VISIBILITY = "artifact-visibility"
    CONTROLLED_INTERLEAVING = "controlled-interleaving"


class BaselineBlocked(RuntimeError):
    """The public boundary cannot execute or observe the requested experiment."""


_TEST_SIGNING_SEED = b"\x11" * 32
_UNKNOWN_SIGNING_SEED = b"\x22" * 32
_MAX_CERTIFICATE_BYTES = 4096


@dataclass(frozen=True, slots=True)
class TrustedKey:
    key_id: str
    public_key: bytes


@dataclass(frozen=True, slots=True)
class BaselineEvidence:
    """Baseline-native messages, keys, bindings, and current state.

    This contains no evaluator verdicts.  Each baseline derives the checks its
    named mechanism can actually perform from these bytes and state values.
    """

    proof: bytes | None = b"proof-v1"
    encoded_statement: bytes = b""
    signature: bytes = b""
    signer_key_id: str = "baseline-test-key"
    trusted_keys: tuple[TrustedKey, ...] = ()
    presented_input_digest: str = "input-1"
    expected_input_digest: str = "input-1"
    presented_output_digest: str = "output-1"
    expected_output_digest: str = "output-1"
    presented_actor_id: str = "actor-1"
    expected_actor_id: str = "actor-1"
    presented_workflow_id: str = "workflow-1"
    expected_workflow_id: str = "workflow-1"
    presented_node_id: str = "node-1"
    expected_node_id: str = "node-1"
    presented_attempt: int = 1
    expected_attempt: int = 1
    commit_id: str = "commit-1"
    desired_commit_digest: str = "commit-payload-1"
    existing_commit_digest: str | None = None
    presented_policy_epoch: int = 7
    current_policy_epoch: int = 7
    presented_authority_epoch: int = 9
    current_authority_epoch: int = 9
    actor_state: str = "active"
    workflow_state: str = "active"
    presented_predecessor_root: str = "root-1"
    current_predecessor_root: str = "root-1"
    presented_nonce: str = "nonce-1"
    current_nonce: str = "nonce-1"
    protocol_version: str = "apcc-1"
    certificate: bytes = b"certificate-v1"
    predecessors: tuple[str, ...] = ("p1", "p2")
    presented_scheduler_id: str = "scheduler-1"
    authorized_scheduler_id: str = "scheduler-1"
    presented_executor_id: str = "executor-1"
    authorized_executor_id: str = "executor-1"
    presented_retry_caller: str = "caller-1"
    original_retry_caller: str = "caller-1"
    presented_status_certificate: str = "status-cert-1"
    current_status_certificate: str = "status-cert-1"
    presented_payload_digest: str = "payload-1"
    expected_payload_digest: str = "payload-1"
    presented_envelope_digest: str = "envelope-1"
    expected_envelope_digest: str = "envelope-1"
    concurrent_writer: str | None = None
    fault_event: str | None = None
    legacy_artifact_state: str = "absent"

    @classmethod
    def valid(cls) -> BaselineEvidence:
        private_key = Ed25519PrivateKey.from_private_bytes(_TEST_SIGNING_SEED)
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        evidence = cls(trusted_keys=(TrustedKey("baseline-test-key", public_key),))
        encoded = evidence.canonical_statement_bytes()
        return replace(
            evidence, encoded_statement=encoded, signature=private_key.sign(encoded)
        )

    def canonical_statement_bytes(self) -> bytes:
        statement = {
            "attempt": self.presented_attempt,
            "actor_id": self.presented_actor_id,
            "authority_epoch": self.presented_authority_epoch,
            "certificate_sha256": hashlib.sha256(self.certificate).hexdigest(),
            "commit_id": self.commit_id,
            "envelope_digest": self.presented_envelope_digest,
            "executor_id": self.presented_executor_id,
            "input_digest": self.presented_input_digest,
            "node_id": self.presented_node_id,
            "nonce": self.presented_nonce,
            "output_digest": self.presented_output_digest,
            "payload_digest": self.presented_payload_digest,
            "policy_epoch": self.presented_policy_epoch,
            "predecessor_root": self.presented_predecessor_root,
            "predecessors": self.predecessors,
            "proof_sha256": (
                hashlib.sha256(self.proof).hexdigest()
                if self.proof is not None
                else None
            ),
            "protocol_version": self.protocol_version,
            "retry_caller": self.presented_retry_caller,
            "scheduler_id": self.presented_scheduler_id,
            "status_certificate": self.presented_status_certificate,
            "workflow_id": self.presented_workflow_id,
        }
        return json.dumps(
            statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def digest(self) -> str:
        trust = b"|".join(
            key.key_id.encode("utf-8") + b":" + key.public_key
            for key in self.trusted_keys
        )
        return hashlib.sha256(
            self.encoded_statement + b"|" + self.signature + b"|" + trust
        ).hexdigest()


def _seal(
    evidence: BaselineEvidence, *, seed: bytes = _TEST_SIGNING_SEED
) -> BaselineEvidence:
    encoded = evidence.canonical_statement_bytes()
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(encoded)
    return replace(evidence, encoded_statement=encoded, signature=signature)


_EVIDENCE_MUTATIONS: dict[str, dict[str, object]] = {
    "missing-proof:absent": {"proof": None},
    "input-substitution:input-digest": {"presented_input_digest": "attacker-input"},
    "output-substitution:output-digest": {"presented_output_digest": "attacker-output"},
    "identity-substitution:default": {"presented_actor_id": "attacker"},
    "cross-workflow-replay:default": {"presented_workflow_id": "workflow-old"},
    "cross-node-replay:default": {"presented_node_id": "node-old"},
    "cross-attempt-replay:default": {"presented_attempt": 0},
    "commit-id-equivocation:default": {"existing_commit_digest": "other-payload"},
    "policy-update-race:default": {"presented_policy_epoch": 6},
    "authority-update-race:default": {"presented_authority_epoch": 8},
    "actor-revocation-race:revoked": {"actor_state": "revoked"},
    "actor-revocation-race:status-expired": {"presented_nonce": "nonce-old"},
    "workflow-revocation-race:revoked": {"workflow_state": "revoked"},
    "workflow-revocation-race:status-expired": {"presented_nonce": "nonce-old"},
    "predecessor-replacement-race:supersession-current": {
        "presented_predecessor_root": "root-old"
    },
    "predecessor-replacement-race:supersession-stale": {"presented_nonce": "nonce-old"},
    "concurrent-double-commit:default": {"concurrent_writer": "writer-2"},
    "response-loss-and-retry:default": {"fault_event": "response-lost"},
    "validator-crash:validator-crash": {"fault_event": "validator-crash"},
    "validator-crash:verifier-crash": {"fault_event": "verifier-crash"},
    "authority-store-transaction-failure:default": {"fault_event": "store-failure"},
    "outbox-failure:default": {"fault_event": "outbox-failure"},
    "recovery-import:default": {"fault_event": "invalid-recovery-source"},
    "legacy-completion-promotion:default": {"legacy_artifact_state": "completed"},
    "malicious-scheduler:default": {"presented_scheduler_id": "scheduler-attacker"},
    "malicious-executor:default": {"presented_executor_id": "executor-attacker"},
    "malicious-retry-caller:default": {"presented_retry_caller": "caller-attacker"},
    "stale-cache:status-replay": {"presented_nonce": "nonce-old"},
    "stale-cache:status-wrong-certificate": {
        "presented_status_certificate": "status-cert-other"
    },
    "stale-cache:status-fresh-nonce": {"presented_authority_epoch": 8},
    "certificate-truncation:payload-digest": {
        "presented_payload_digest": "payload-truncated"
    },
    "certificate-truncation:envelope-digest": {
        "presented_envelope_digest": "envelope-truncated"
    },
    "unknown-protocol-version:default": {"protocol_version": "apcc-99"},
    "oversized-certificate:default": {
        "certificate": b"x" * (_MAX_CERTIFICATE_BYTES + 1)
    },
    "duplicate-predecessor:default": {"predecessors": ("p1", "p1")},
    "predecessor-set-reordering:default": {"predecessors": ("p2", "p1")},
}


def native_evidence_for_variant(variant_id: str) -> BaselineEvidence:
    evidence = BaselineEvidence.valid()
    if variant_id == "invalid-signature:default":
        return replace(evidence, signature=b"\x00" * 64)
    if variant_id == "unknown-key:default":
        return _seal(
            replace(evidence, signer_key_id="attacker-key"),
            seed=_UNKNOWN_SIGNING_SEED,
        )
    if variant_id == "canonicalization-ambiguity:default":
        encoded = b'{ "ambiguous" : true }'
        return replace(
            evidence,
            encoded_statement=encoded,
            signature=Ed25519PrivateKey.from_private_bytes(_TEST_SIGNING_SEED).sign(
                encoded
            ),
        )
    try:
        mutation = _EVIDENCE_MUTATIONS[variant_id]
    except KeyError as error:
        raise ValueError(f"unknown empirical variant {variant_id!r}") from error
    return _seal(replace(evidence, **cast(Any, mutation)))


def variant_id_for_native_evidence(attack_id: str, evidence: BaselineEvidence) -> str:
    candidates = (
        "invalid-signature:default",
        "unknown-key:default",
        "canonicalization-ambiguity:default",
        *_EVIDENCE_MUTATIONS,
    )
    matches = [
        variant_id
        for variant_id in candidates
        if variant_id.partition(":")[0] == attack_id
        and native_evidence_for_variant(variant_id) == evidence
    ]
    if len(matches) != 1:
        raise ScenarioExecutionError(
            "attack evidence does not identify exactly one empirical variant"
        )
    return matches[0]


@dataclass(frozen=True, slots=True)
class TrialStimulus:
    payload: bytes
    evidence: BaselineEvidence = field(default_factory=BaselineEvidence.valid)
    attack_id: str | None = None
    capabilities: frozenset[Capability] = frozenset()
    commit_request: CommitRequest | None = None

    @classmethod
    def control(
        cls, payload: bytes, request: CommitRequest | None = None
    ) -> TrialStimulus:
        return cls(bytes(payload), commit_request=request)

    @classmethod
    def attack(
        cls,
        payload: bytes,
        *,
        attack_id: str,
        capabilities: frozenset[Capability],
        evidence: BaselineEvidence | None = None,
        request: CommitRequest | None = None,
    ) -> TrialStimulus:
        return cls(
            bytes(payload),
            evidence or BaselineEvidence.valid(),
            attack_id,
            frozenset(capabilities),
            request,
        )


@dataclass(frozen=True, slots=True)
class DurableSnapshot:
    accepted_count: int
    denied_count: int
    detected_count: int
    certificate_digests: tuple[str, ...] | None
    pointer_digest: str | None
    outbox_pending: tuple[str, ...] | None
    pending_audit_count: int = 0
    signed_result_count: int = 0


@dataclass(frozen=True, slots=True)
class AuthorityObservation:
    authoritative_outcome: str
    certificate_digest: str | None
    pointer_digest: str | None
    artifact_visible: bool | None
    outbox_pending: bool | None
    current_status: str | None
    signed_result: bytes | None = None
    signed_result_signature: bytes | None = None
    signing_public_key: bytes | None = None
    signed_result_verified: bool | None = None


class ScenarioExecutionError(RuntimeError):
    """The harness could not execute a configured, preflight-capable cell."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.control: AuthorityObservation | None = None
        self.before_attack: DurableSnapshot | None = None
        self.after_attack: DurableSnapshot | None = None


class BaselineAdapter(Protocol):
    baseline_id: str
    capabilities: frozenset[Capability]

    def execute(self, stimulus: TrialStimulus) -> AuthorityObservation: ...

    def snapshot(self) -> DurableSnapshot: ...


class B4InterleavingBarrier:
    def __init__(self) -> None:
        self.verification_reached = threading.Event()
        self._commit_release = threading.Event()
        self._released = False

    def mark_verified(self) -> None:
        self.verification_reached.set()

    def release_commit(self) -> None:
        if self._released:
            raise RuntimeError("B4 interleaving barrier already released")
        self._released = True
        self._commit_release.set()

    def await_commit_release(self, *, timeout_seconds: float) -> None:
        if not self._commit_release.wait(timeout_seconds):
            raise ScenarioExecutionError("B4 interleaving barrier timed out")


_BASELINE_GUARANTEES: dict[str, frozenset[Capability]] = {
    "B0": frozenset({Capability.DURABLE_SNAPSHOT}),
    "B1": frozenset({Capability.DURABLE_SNAPSHOT, Capability.POST_HOC_AUDIT}),
    "B2": frozenset({Capability.DURABLE_SNAPSHOT, Capability.POLICY_GATE}),
    "B3": frozenset({Capability.DURABLE_SNAPSHOT, Capability.SIGNED_RESULT}),
    "B4": frozenset(
        {
            Capability.DURABLE_SNAPSHOT,
            Capability.PROOF_VALIDATION,
            Capability.CONTROLLED_INTERLEAVING,
        }
    ),
}


def _proof_validation_failures(evidence: BaselineEvidence) -> tuple[str, ...]:
    failures: list[str] = []
    if evidence.proof is None:
        failures.append("missing-proof")
    trusted = {key.key_id: key.public_key for key in evidence.trusted_keys}
    public_key = trusted.get(evidence.signer_key_id)
    if public_key is None:
        failures.append("unknown-key")
    else:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                evidence.signature, evidence.encoded_statement
            )
        except ValueError:
            failures.append("malformed-key")
        except InvalidSignature:
            failures.append("invalid-signature")
    if evidence.encoded_statement != evidence.canonical_statement_bytes():
        failures.append("noncanonical-statement")
    comparisons = (
        (
            "input-binding",
            evidence.presented_input_digest,
            evidence.expected_input_digest,
        ),
        (
            "output-binding",
            evidence.presented_output_digest,
            evidence.expected_output_digest,
        ),
        ("identity-binding", evidence.presented_actor_id, evidence.expected_actor_id),
        (
            "workflow-binding",
            evidence.presented_workflow_id,
            evidence.expected_workflow_id,
        ),
        ("node-binding", evidence.presented_node_id, evidence.expected_node_id),
        ("attempt-binding", evidence.presented_attempt, evidence.expected_attempt),
        (
            "policy-currentness",
            evidence.presented_policy_epoch,
            evidence.current_policy_epoch,
        ),
        (
            "authority-currentness",
            evidence.presented_authority_epoch,
            evidence.current_authority_epoch,
        ),
        (
            "predecessor-currentness",
            evidence.presented_predecessor_root,
            evidence.current_predecessor_root,
        ),
        ("nonce-currentness", evidence.presented_nonce, evidence.current_nonce),
        (
            "scheduler-authorization",
            evidence.presented_scheduler_id,
            evidence.authorized_scheduler_id,
        ),
        (
            "executor-authorization",
            evidence.presented_executor_id,
            evidence.authorized_executor_id,
        ),
        (
            "retry-binding",
            evidence.presented_retry_caller,
            evidence.original_retry_caller,
        ),
        (
            "status-certificate-binding",
            evidence.presented_status_certificate,
            evidence.current_status_certificate,
        ),
        (
            "payload-binding",
            evidence.presented_payload_digest,
            evidence.expected_payload_digest,
        ),
        (
            "envelope-binding",
            evidence.presented_envelope_digest,
            evidence.expected_envelope_digest,
        ),
    )
    failures.extend(
        name for name, presented, expected in comparisons if presented != expected
    )
    if evidence.existing_commit_digest not in {None, evidence.desired_commit_digest}:
        failures.append("commit-id-equivocation")
    if evidence.actor_state != "active":
        failures.append("actor-not-active")
    if evidence.workflow_state != "active":
        failures.append("workflow-not-active")
    if evidence.protocol_version != "apcc-1":
        failures.append("unknown-protocol")
    if len(evidence.certificate) > _MAX_CERTIFICATE_BYTES:
        failures.append("oversized-certificate")
    if len(set(evidence.predecessors)) != len(evidence.predecessors):
        failures.append("duplicate-predecessor")
    if evidence.predecessors != tuple(sorted(evidence.predecessors)):
        failures.append("noncanonical-predecessor-order")
    return tuple(failures)


class ExperimentalSQLiteAdapter:
    """B0--B4 implement their named mechanisms in isolated SQLite state."""

    def __init__(
        self,
        baseline_id: str,
        path: Path,
        *,
        interleaving_barrier: B4InterleavingBarrier | None = None,
        after_commit: Callable[[ExperimentalSQLiteAdapter], None] | None = None,
    ) -> None:
        if baseline_id not in _BASELINE_GUARANTEES:
            raise ValueError("experimental SQLite adapter requires B0 through B4")
        self.baseline_id = baseline_id
        self.path = Path(path)
        self.guarantees = _BASELINE_GUARANTEES[baseline_id]
        self.capabilities = self.guarantees
        self._barrier = interleaving_barrier
        self._after_commit = after_commit
        self._signing_key = (
            Ed25519PrivateKey.generate() if baseline_id == "B3" else None
        )
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """CREATE TABLE empirical_events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                authoritative_digest TEXT NOT NULL,
                accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
                detected INTEGER NOT NULL CHECK(detected IN (0,1)),
                artifact_digest TEXT,
                audit_pending INTEGER NOT NULL CHECK(audit_pending IN (0,1)),
                signed_result BLOB,
                signed_result_signature BLOB,
                signing_public_key BLOB)"""
            )
            connection.commit()
        finally:
            connection.close()

    def _accepted(self, evidence: BaselineEvidence) -> bool:
        if self.baseline_id in {"B0", "B1", "B3"}:
            return True
        if self.baseline_id == "B2":
            return (
                evidence.presented_scheduler_id == evidence.authorized_scheduler_id
                and evidence.presented_policy_epoch == evidence.current_policy_epoch
            )
        return not _proof_validation_failures(evidence)

    def _audit_detected(self, evidence: BaselineEvidence) -> bool:
        return bool(_proof_validation_failures(evidence))

    def execute(self, stimulus: TrialStimulus) -> AuthorityObservation:
        accepted = self._accepted(stimulus.evidence)
        if (
            self.baseline_id == "B4"
            and stimulus.evidence.concurrent_writer is not None
            and self._barrier is not None
        ):
            self._barrier.mark_verified()
            self._barrier.await_commit_release(timeout_seconds=1.0)
        audit_detected = self._audit_detected(stimulus.evidence)
        detected = not accepted
        digest = hashlib.sha256(stimulus.payload).hexdigest() if accepted else None
        authoritative_digest = stimulus.evidence.digest()
        signed_result: bytes | None = None
        signature: bytes | None = None
        public_key: bytes | None = None
        signature_verified: bool | None = None
        if self._signing_key is not None:
            signed_result = (
                f"{authoritative_digest}|{int(accepted)}|{digest or '-'}"
            ).encode("ascii")
            signature = self._signing_key.sign(signed_result)
            public_key = self._signing_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, signed_result
            )
            signature_verified = True
        audit_pending = int(self.baseline_id == "B1" and audit_detected)
        connection = sqlite3.connect(self.path)
        try:
            cursor = connection.execute(
                """INSERT INTO empirical_events(
                authoritative_digest,accepted,detected,artifact_digest,audit_pending,
                signed_result,signed_result_signature,signing_public_key)
                VALUES(?,?,?,?,?,?,?,?)""",
                (
                    authoritative_digest,
                    int(accepted),
                    int(detected),
                    digest,
                    audit_pending,
                    signed_result,
                    signature,
                    public_key,
                ),
            )
            if cursor.lastrowid is None:
                raise ScenarioExecutionError("baseline event sequence was not assigned")
            sequence = cursor.lastrowid
            connection.commit()
        finally:
            connection.close()
        if self._after_commit is not None:
            self._after_commit(self)
        if audit_pending:
            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    "UPDATE empirical_events SET detected=1,audit_pending=0 WHERE sequence=?",
                    (sequence,),
                )
                connection.commit()
            finally:
                connection.close()
        return AuthorityObservation(
            "committed" if accepted else "denied",
            None,
            None,
            accepted,
            None,
            None,
            signed_result,
            signature,
            public_key,
            signature_verified,
        )

    def snapshot(self) -> DurableSnapshot:
        connection = sqlite3.connect(self.path)
        try:
            rows = connection.execute(
                """SELECT accepted,detected,audit_pending,
                signed_result,signed_result_signature,signing_public_key
                FROM empirical_events ORDER BY sequence"""
            ).fetchall()
        finally:
            connection.close()
        return DurableSnapshot(
            sum(int(row[0]) for row in rows),
            sum(not bool(row[0]) for row in rows),
            sum(int(row[1]) for row in rows),
            None,
            None,
            None,
            sum(int(row[2]) for row in rows),
            sum(all(value is not None for value in row[3:6]) for row in rows),
        )


class B6AuthorityAdapter:
    """Inert B6 scenario adapter; all current cells fail capability preflight.

    ``execute_trusted`` is only for a trusted experiment supervisor which already
    owns a spawn-only scheduler handle.  The adapter retains no privileged handle
    and does not claim Python-level capability isolation.
    """

    baseline_id = "B6"
    capabilities: frozenset[Capability] = frozenset()
    guarantees = frozenset({Capability.PROOF_VALIDATION, Capability.ATOMIC_COMMIT})

    def execute(self, stimulus: TrialStimulus) -> AuthorityObservation:
        del stimulus
        raise ScenarioExecutionError(
            "B6 execution requires trusted supervisor preflight"
        )

    def execute_trusted(
        self,
        stimulus: TrialStimulus,
        *,
        execution: _SwarmExecutionHandle,
    ) -> AuthorityObservation:
        if type(execution) is not _SwarmExecutionHandle:
            raise TypeError("B6 requires a spawned authority execution handle")
        request = stimulus.commit_request
        if request is None:
            raise ScenarioExecutionError(
                "B6 trial requires an exact governed CommitRequest"
            )
        if stimulus.payload != request.canonical_hash().encode("ascii"):
            raise ScenarioExecutionError(
                "B6 payload does not bind the governed request"
            )
        decision = execution.commit(request)
        return AuthorityObservation(
            decision.outcome.value, None, None, None, None, None
        )

    def snapshot(self) -> DurableSnapshot:
        raise ScenarioExecutionError(
            "B6 public boundary lacks a complete durable observation"
        )


def create_baseline_adapter(
    baseline_id: str,
    path: Path,
    *,
    interleaving_barrier: B4InterleavingBarrier | None = None,
) -> BaselineAdapter:
    if baseline_id == "B5":
        module = importlib.import_module(
            "constitutional_swarm.apcc_empirical.historical_gcb"
        )
        constructor = cast(
            Callable[[Path], BaselineAdapter], module.HistoricalGCBAdapter
        )
        return constructor(path)
    return ExperimentalSQLiteAdapter(
        baseline_id, path, interleaving_barrier=interleaving_barrier
    )
