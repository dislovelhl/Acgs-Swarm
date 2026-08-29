"""SQLite realization of the storage-neutral APCC authority port.

The database contains only public configuration and durable authority facts.
Private signing material is supplied by a fresh ``AuthorityRuntime`` to each
writer process and is never persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock
from typing import Iterator, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .codec import (
    canonical_statement,
    decode_authority_status,
    decode_certificate,
    decode_envelope,
    encode_authority_status_body,
    encode_certificate,
    encode_envelope,
)
from .crypto import (
    AUTHORITY_STATUS_DOMAIN,
    COMMIT_DOMAIN,
    b64u_decode,
    b64u_encode,
    predecessor_root,
    sha256_digest,
    verify_detached,
)
from .gcb_projection import (
    _GCBAgentFacts,
    _GCBAtomicCommitRequest,
    _GCBNodeFacts,
    _GCBPredecessorFacts,
    _GCBProjectionCheckpoint,
    _GCBProjectionDenied,
    _GCBProjectionFacts,
    _GCBProjectionFault,
    _GCBProjectionPlan,
    _GCBStagedArtifactFacts,
    _GCBWorkflowFacts,
    _ValidatedGCBProjection as _PureValidatedGCBProjection,
    _gcb_exact_int,
    _gcb_material_object,
    _gcb_string_list,
    _validate_gcb_projection,
    _validate_gcb_projection_identity,
)
from .model import (
    AuthorityStatus,
    AuthorityStatusValue,
    CandidateLifecycle,
    CandidateState,
    CertificateDecision,
    CertificateDisposition,
    CertificateBindings,
    CertificateContext,
    CertificateEvidence,
    CertificateHeader,
    CertificateSignatures,
    CertificateSubject,
    CommitCertificate,
    CommitDecision,
    FailureCode,
    LogicalNodeState,
    PredecessorRef,
    RequestOutcome,
    Signature,
    SupersessionValue,
)
from .observation import (
    AuthorityObservationRequest,
    AuthorityObservationSnapshot,
    AuthorityObservationSnapshotChanged,
    AuthorityObservationState,
)
from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthorityObservationStatusSigner,
    AuthorityRuntime,
    AuthorityClock,
    AuthoritySigningRole,
    CommitContext,
    CommitContextRequest,
    CommitResult,
    CurrentStatusRequest,
    CurrentStatusResult,
    LogicalNodeStatusRequest,
    LogicalNodeStatusResult,
    OutboxRecoveryRequest,
    OutboxRecoveryResult,
    PersistedOutboxEvent,
    ProposeCommitRequest,
    ProposeCommitResult,
    RecoveryRequest,
    ReplayCommitRequest,
    RevocationRequest,
    RevocationResult,
    RevocationScope,
    StageResultRequest,
    StageResultResult,
    StatusFreshnessPolicy,
    SupersessionCommitted,
    SupersessionConflicted,
    SupersessionDenied,
    SupersessionRequest,
    SupersessionResult,
)
from .verifier import (
    CausalClosureLimits,
    ScopedTrust,
    TrustBinding,
    TrustRole,
    _bindings,
    _evidence,
    _header,
    _verify_signature,
    verify_causal_closure,
    verify_historical,
)

_APPLICATION_ID = 0x41504343  # ASCII "APCC"
_AUTHORITY_SCHEMA_VERSION = "3"
_SCHEMA_VERSION = int(_AUTHORITY_SCHEMA_VERSION)
_MAX_STATUS_BATCH_SIZE = 1000
_MAX_CERTIFICATE_CACHE_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_SEMANTIC_CHECKPOINT_DOMAIN = b"APCC-SEMANTIC-CHECKPOINT-V1"
_SEMANTIC_CHECKPOINT_GENESIS = sha256_digest(b"APCC-1/semantic-checkpoint/genesis")
_SCHEMA_VERSION_INCOMPATIBLE = "APCC authority schema version is incompatible"


class _FaultProbe(Protocol):
    def hit(self, point: str) -> None: ...


class _AuthorityCursor(Protocol):
    @property
    def rowcount(self) -> int: ...

    def fetchone(self) -> tuple[object, ...] | None: ...

    def fetchall(self) -> list[tuple[object, ...]]: ...

    def __iter__(self) -> Iterator[tuple[object, ...]]: ...


class _AuthorityConnection(Protocol):
    """Small DB-API surface shared by the SQLite and PostgreSQL realizations."""

    def execute(
        self, statement: str, parameters: tuple[object, ...] = (), /
    ) -> _AuthorityCursor: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _SemanticSnapshot:
    """Validated certificate facts produced by one full store attestation."""

    certificates: Mapping[str, CommitCertificate]
    dispositions: Mapping[str, CertificateDisposition]
    envelope_sizes: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class _CausalBatchFacts:
    closure: frozenset[str]
    depth: int
    error: FailureCode | None


def _semantic_checkpoint_body(
    config: APCCAuthorityConfig,
    schema_fingerprint: str,
    change_sequence: int,
    prior_digest: str,
) -> bytes:
    return _json(
        {
            "profile": "APCC-1.0-draft",
            "kind": "apcc.semantic-checkpoint",
            "authority_store_id": config.authority_store_id,
            "schema_fingerprint": schema_fingerprint,
            "change_sequence": str(change_sequence),
            "prior_digest": prior_digest,
        }
    ).encode("utf-8")


def _semantic_checkpoint_row(
    connection: _AuthorityConnection,
) -> tuple[int, str, str, str, str]:
    rows = connection.execute(
        "SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
        "FROM semantic_checkpoint WHERE singleton=1"
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("APCC authority semantic checkpoint validation failed")
    sequence, prior_digest, checkpoint_digest, key_id, signature = rows[0]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 0 <= sequence <= _MAX_SAFE_INTEGER
        or any(
            not isinstance(value, str)
            for value in (prior_digest, checkpoint_digest, key_id, signature)
        )
    ):
        raise ValueError("APCC authority semantic checkpoint validation failed")
    return (
        sequence,
        _row_text(prior_digest),
        _row_text(checkpoint_digest),
        _row_text(key_id),
        _row_text(signature),
    )


def _verify_semantic_checkpoint(
    connection: _AuthorityConnection,
    config: APCCAuthorityConfig,
    schema_fingerprint: str,
    *,
    allow_initial_unsealed: bool = False,
) -> bool:
    invalid = ValueError("APCC authority semantic checkpoint validation failed")
    sequence, prior_digest, checkpoint_digest, key_id, signature_b64u = (
        _semantic_checkpoint_row(connection)
    )
    if not checkpoint_digest and not signature_b64u:
        if (
            allow_initial_unsealed
            and sequence == 0
            and prior_digest == _SEMANTIC_CHECKPOINT_GENESIS
            and key_id == config.commit_trust.key_id
        ):
            return False
        raise invalid
    if (
        not checkpoint_digest
        or not signature_b64u
        or key_id != config.commit_trust.key_id
    ):
        raise invalid
    body = _semantic_checkpoint_body(config, schema_fingerprint, sequence, prior_digest)
    if sha256_digest(body) != checkpoint_digest:
        raise invalid
    try:
        signature = b64u_decode(signature_b64u, expected_length=64)
        Ed25519PublicKey.from_public_bytes(config.commit_trust.public_key).verify(
            signature, _SEMANTIC_CHECKPOINT_DOMAIN + b"\x00" + body
        )
    except (InvalidSignature, ValueError) as error:
        raise invalid from error
    return True


def _seal_semantic_checkpoint(
    connection: _AuthorityConnection,
    config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
    schema_fingerprint: str,
) -> None:
    sequence, prior_digest, checkpoint_digest, key_id, signature_b64u = (
        _semantic_checkpoint_row(connection)
    )
    if checkpoint_digest or signature_b64u:
        _verify_semantic_checkpoint(connection, config, schema_fingerprint)
        return
    if key_id != config.commit_trust.key_id:
        raise ValueError("APCC authority semantic checkpoint validation failed")
    body = _semantic_checkpoint_body(config, schema_fingerprint, sequence, prior_digest)
    signature = runtime.key_provider.sign(
        AuthoritySigningRole.COMMIT,
        config.commit_trust.key_id,
        _SEMANTIC_CHECKPOINT_DOMAIN,
        body,
    )
    if signature.algorithm != "Ed25519" or signature.key_id != key_id:
        raise ValueError("APCC authority semantic checkpoint signing failed")
    try:
        raw_signature = b64u_decode(signature.signature_b64u, expected_length=64)
        Ed25519PublicKey.from_public_bytes(config.commit_trust.public_key).verify(
            raw_signature, _SEMANTIC_CHECKPOINT_DOMAIN + b"\x00" + body
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("APCC authority semantic checkpoint signing failed") from error
    digest = sha256_digest(body)
    changed = connection.execute(
        "UPDATE semantic_checkpoint SET checkpoint_digest=?,signature=? "
        "WHERE singleton=1 AND change_sequence=? AND prior_digest=? "
        "AND checkpoint_digest='' AND key_id=? AND signature=''",
        (digest, signature.signature_b64u, sequence, prior_digest, key_id),
    ).rowcount
    if changed != 1:
        raise ValueError("APCC authority semantic checkpoint signing failed")


@dataclass(frozen=True, slots=True)
class _CertificateDecodeCacheInfo:
    entries: int
    payload_bytes: int
    max_entries: int
    max_payload_bytes: int


class _CertificateDecodeCache:
    """Bounded process-local cache of exact payload parses only.

    The byte budget accounts for immutable raw payload keys.  The decoded
    certificate graph is additionally bounded by the same entry limit and by
    the APCC grammar represented by each charged payload.  No verification,
    revocation, status, nonce, or store verdict is cached.
    """

    def __init__(self, *, max_entries: int, max_payload_bytes: int) -> None:
        if max_entries <= 0 or max_payload_bytes <= 0:
            raise ValueError("certificate decode cache limits must be positive")
        self._max_entries = max_entries
        self._max_payload_bytes = max_payload_bytes
        self._entries: OrderedDict[bytes, CommitCertificate] = OrderedDict()
        self._payload_bytes = 0
        self._lock = Lock()

    def decode(self, payload: bytes) -> CommitCertificate:
        with self._lock:
            cached = self._entries.get(payload)
            if cached is not None:
                self._entries.move_to_end(payload)
                return cached

        certificate = decode_certificate(payload)
        payload_size = len(payload)
        if payload_size > self._max_payload_bytes:
            return certificate

        with self._lock:
            cached = self._entries.get(payload)
            if cached is not None:
                self._entries.move_to_end(payload)
                return cached
            while self._entries and (
                len(self._entries) >= self._max_entries
                or self._payload_bytes + payload_size > self._max_payload_bytes
            ):
                evicted_payload, _ = self._entries.popitem(last=False)
                self._payload_bytes -= len(evicted_payload)
            self._entries[payload] = certificate
            self._payload_bytes += payload_size
            return certificate

    def info(self) -> _CertificateDecodeCacheInfo:
        with self._lock:
            return _CertificateDecodeCacheInfo(
                entries=len(self._entries),
                payload_bytes=self._payload_bytes,
                max_entries=self._max_entries,
                max_payload_bytes=self._max_payload_bytes,
            )


_CERTIFICATE_DECODE_CACHE = _CertificateDecodeCache(
    max_entries=_MAX_STATUS_BATCH_SIZE,
    max_payload_bytes=_MAX_CERTIFICATE_CACHE_PAYLOAD_BYTES,
)


def _decode_checkpoint_certificate(payload: bytes) -> CommitCertificate:
    """Reconstruct an immutable certificate through the bounded exact cache."""

    return _CERTIFICATE_DECODE_CACHE.decode(payload)


def _checkpoint_semantic_snapshot(
    connection: _AuthorityConnection,
    certificate_digests: Sequence[str],
) -> _SemanticSnapshot:
    """Load only the requested causal closure after checkpoint attestation."""

    certificates: dict[str, CommitCertificate] = {}
    envelope_sizes: dict[str, int] = {}
    attempted: set[str] = set()
    pending = set(certificate_digests)
    while pending:
        batch = tuple(sorted(pending)[:400])
        pending.difference_update(batch)
        attempted.update(batch)
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT certificate_digest,commit_id,certificate_json,envelope,"
            "workflow_id,node_id,sequence FROM certificates "
            f"WHERE certificate_digest IN ({placeholders})",
            batch,
        ).fetchall()
        for row in rows:
            digest = _row_text(row[0])
            try:
                payload = _row_bytes(row[2])
                sequence = _row_int(row[6])
                if sha256_digest(payload) != digest:
                    raise ValueError(
                        "APCC semantic checkpoint protected row is invalid"
                    )
                certificate = _decode_checkpoint_certificate(payload)
            except Exception as error:
                raise ValueError(
                    "APCC semantic checkpoint protected row is invalid"
                ) from error
            if (
                certificate.decision.commit_id != _row_text(row[1])
                or certificate.subject.workflow_id != _row_text(row[4])
                or certificate.subject.node_id != _row_text(row[5])
                or certificate.header.certificate_sequence != str(sequence)
            ):
                raise ValueError("APCC semantic checkpoint protected row is invalid")
            certificates[digest] = certificate
            envelope_sizes[digest] = len(_row_bytes(row[3]))
            pending.update(
                reference.certificate_digest
                for reference in certificate.bindings.predecessors
                if reference.certificate_digest not in attempted
                and reference.certificate_digest not in certificates
            )

    dispositions: dict[str, CertificateDisposition] = {}
    digests = tuple(sorted(certificates))
    for offset in range(0, len(digests), 400):
        batch = digests[offset : offset + 400]
        placeholders = ",".join("?" for _ in batch)
        for row_digest, raw_event_sequence, raw_disposition in connection.execute(
            "SELECT certificate_digest,event_sequence,disposition "
            "FROM certificate_dispositions "
            f"WHERE certificate_digest IN ({placeholders}) "
            "ORDER BY certificate_digest,event_sequence",
            batch,
        ):
            resolved_digest = _row_text(row_digest)
            event_sequence = _row_int(raw_event_sequence)
            current = CertificateDisposition(_row_text(raw_disposition))
            prior = dispositions.get(resolved_digest)
            if (event_sequence, current, prior) == (
                1,
                CertificateDisposition.CURRENT,
                None,
            ) or (
                event_sequence == 2
                and current
                in {
                    CertificateDisposition.REVOKED,
                    CertificateDisposition.SUPERSEDED,
                }
                and prior is CertificateDisposition.CURRENT
            ):
                dispositions[resolved_digest] = current
                continue
            raise ValueError("APCC semantic checkpoint protected row is invalid")
    if set(dispositions) != set(certificates):
        raise ValueError("APCC semantic checkpoint protected row is invalid")
    return _SemanticSnapshot(certificates, dispositions, envelope_sizes)


def _row_text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("APCC authority row contains non-text data")
    return value


def _row_optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _row_text(value)


def _row_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("APCC authority row contains non-binary data")
    return bytes(value)


def _row_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("APCC authority row contains non-integer data")
    try:
        return int(value)
    except ValueError as error:
        raise ValueError("APCC authority row contains non-integer data") from error


class _AuthorityPredecessorResolver:
    """Resolve and adjacency-check certificates in the active write transaction."""

    def __init__(self, connection: _AuthorityConnection) -> None:
        self._connection = connection

    def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
        row = self._connection.execute(
            "SELECT commit_id, certificate_json, envelope FROM certificates "
            "WHERE certificate_digest=?",
            (certificate_digest,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = _row_bytes(row[1])
            envelope = _row_bytes(row[2])
            detached = decode_envelope(envelope)
            if (
                detached.payload != payload
                or detached.payload_sha256 != certificate_digest
                or sha256_digest(payload) != certificate_digest
            ):
                return None
            certificate = decode_certificate(payload)
        except Exception:
            return None
        signed_edges = tuple(
            sorted(
                item.certificate_digest for item in certificate.bindings.predecessors
            )
        )
        stored_edges = tuple(
            edge[0]
            for edge in self._connection.execute(
                "SELECT predecessor_digest FROM predecessor_edges "
                "WHERE child_commit_id=? ORDER BY predecessor_digest",
                (row[0],),
            )
        )
        if stored_edges != signed_edges:
            return None
        return envelope


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _loads(value: str) -> object:
    return json.loads(value)


def _gcb_revoked_closure(
    connection: sqlite3.Connection, workflow_id: str, node_id: str
) -> bool:
    roots = {
        str(row[0])
        for row in connection.execute(
            "SELECT root_node_id FROM revoked_roots WHERE workflow_id=?",
            (workflow_id,),
        ).fetchall()
    }
    pending = [node_id]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in roots:
            return True
        row = connection.execute(
            "SELECT predecessors FROM nodes WHERE workflow_id=? AND node_id=?",
            (workflow_id, current),
        ).fetchone()
        if row is None:
            raise _GCBProjectionDenied("unknown_context")
        pending.extend(_gcb_string_list(json.loads(str(row[0])), label="predecessors"))
    return False


def _load_gcb_projection_facts(
    connection: sqlite3.Connection,
    clock: AuthorityClock,
    plan: _GCBProjectionPlan,
) -> _GCBProjectionFacts:
    """Load the fixed GCB rows while the authority write transaction is held."""
    workflow = connection.execute(
        "SELECT generation,policy_version,policy_digest,policy_epoch,"
        "verifier_policy_id,authority_root,authority_epoch,"
        "revocation_generation,state_version FROM workflows WHERE workflow_id=?",
        (plan.workflow_id,),
    ).fetchone()
    node = connection.execute(
        "SELECT status,version,input_digest,required_capabilities,predecessors,"
        "attempt_id,claimed_by,result_digest,tainted FROM nodes "
        "WHERE workflow_id=? AND node_id=?",
        (plan.workflow_id, plan.node_id),
    ).fetchone()
    agent = connection.execute(
        "SELECT public_key,key_id,capabilities,authority_epoch,revocation_epoch,revoked "
        "FROM agents WHERE workflow_id=? AND agent_id=?",
        (plan.workflow_id, plan.agent_id),
    ).fetchone()
    staged = connection.execute(
        "SELECT artifact_json,output_digest FROM staged_artifacts "
        "WHERE workflow_id=? AND node_id=? AND attempt_id=?",
        (plan.workflow_id, plan.node_id, plan.attempt_id),
    ).fetchone()
    seal = connection.execute(
        "SELECT store_id FROM store_seal WHERE singleton=1 AND sealed=1"
    ).fetchone()
    if any(row is None for row in (workflow, node, agent, staged, seal)):
        raise _GCBProjectionDenied("unknown_context")
    assert workflow is not None
    assert node is not None
    assert agent is not None
    assert staged is not None
    assert seal is not None

    predecessors = _gcb_string_list(json.loads(str(node[4])), label="predecessors")
    predecessor_facts: list[_GCBPredecessorFacts] = []
    for predecessor_id in predecessors:
        predecessor = connection.execute(
            "SELECT status,commit_id,result_digest,tainted FROM nodes "
            "WHERE workflow_id=? AND node_id=?",
            (plan.workflow_id, predecessor_id),
        ).fetchone()
        logical = connection.execute(
            "SELECT version,certificate_digest FROM logical_nodes "
            "WHERE workflow_id=? AND node_id=?",
            (plan.workflow_id, predecessor_id),
        ).fetchone()
        if predecessor is None or logical is None:
            raise _GCBProjectionDenied("predecessor_binding_mismatch")
        predecessor_facts.append(
            _GCBPredecessorFacts(
                predecessor_id,
                cast(str, predecessor[0]),
                cast(str | None, predecessor[1]),
                cast(str, predecessor[2]),
                cast(int, predecessor[3]),
                cast(str, logical[0]),
                cast(str | None, logical[1]),
            )
        )

    return _GCBProjectionFacts(
        _GCBWorkflowFacts(
            cast(int, workflow[0]),
            cast(str, workflow[1]),
            cast(str, workflow[2]),
            cast(int, workflow[3]),
            cast(str, workflow[4]),
            cast(str, workflow[5]),
            cast(int, workflow[6]),
            cast(int, workflow[7]),
            cast(int, workflow[8]),
        ),
        _GCBNodeFacts(
            cast(str, node[0]),
            cast(int, node[1]),
            cast(str, node[2]),
            _gcb_string_list(json.loads(str(node[3])), label="required_capabilities"),
            predecessors,
            cast(str, node[5]),
            cast(str, node[6]),
            cast(str, node[7]),
            cast(int, node[8]),
        ),
        _GCBAgentFacts(
            bytes(agent[0]),
            cast(str, agent[1]),
            _gcb_string_list(json.loads(str(agent[2])), label="agent_capabilities"),
            cast(int, agent[3]),
            cast(int, agent[4]),
            cast(int, agent[5]),
        ),
        _GCBStagedArtifactFacts(str(staged[0]), cast(str, staged[1])),
        cast(str, seal[0]),
        tuple(predecessor_facts),
        _gcb_revoked_closure(connection, plan.workflow_id, plan.node_id),
        _trusted_now(clock) // 1000,
    )


def _attest_gcb_projection(
    connection: sqlite3.Connection,
    request: AtomicCommitRequest,
    result: CommitResult,
    plan: _GCBProjectionPlan,
    validated: _PureValidatedGCBProjection,
    unlocked_children: tuple[tuple[str, int], ...],
) -> None:
    if result.certificate_digest is None:
        raise _GCBProjectionDenied("projection_certificate_missing")
    node = connection.execute(
        "SELECT status,version,attempt_id,claimed_by,result_digest,commit_id,"
        "receipt_digest,tainted FROM nodes WHERE workflow_id=? AND node_id=?",
        (plan.workflow_id, plan.node_id),
    ).fetchone()
    workflow = connection.execute(
        "SELECT state_version FROM workflows WHERE workflow_id=?", (plan.workflow_id,)
    ).fetchone()
    decision = connection.execute(
        "SELECT request_hash,outcome,reason,workflow_id,node_id,state_version,nonce "
        "FROM decisions WHERE commit_id=?",
        (plan.commit_id,),
    ).fetchone()
    evidence = connection.execute(
        "SELECT receipt_material,receipt_digest,verdict_material,verdict_digest "
        "FROM receipt_evidence WHERE commit_id=?",
        (plan.commit_id,),
    ).fetchone()
    outbox = connection.execute(
        "SELECT workflow_id,node_id,artifact_json,dispatched FROM outbox WHERE commit_id=?",
        (plan.commit_id,),
    ).fetchone()
    logical = connection.execute(
        "SELECT version,certificate_digest FROM logical_nodes "
        "WHERE workflow_id=? AND node_id=?",
        (plan.workflow_id, plan.node_id),
    ).fetchone()
    expected_node = (
        "governed_committed",
        validated.legacy_node_version + 1,
        plan.attempt_id,
        plan.agent_id,
        request.subject.output_digest,
        plan.commit_id,
        plan.receipt_digest,
        0,
    )
    expected_decision = (
        plan.request_hash,
        "committed",
        "verified",
        plan.workflow_id,
        plan.node_id,
        validated.next_workflow_state_version,
        plan.nonce,
    )
    if (
        node != expected_node
        or workflow != (validated.next_workflow_state_version,)
        or decision != expected_decision
        or evidence
        != (
            plan.receipt_material,
            plan.receipt_digest,
            plan.verdict_material,
            plan.verdict_digest,
        )
        or outbox != (plan.workflow_id, plan.node_id, validated.artifact_json, 0)
        or logical
        != (request.bindings.committed_node_version, result.certificate_digest)
    ):
        raise _GCBProjectionDenied("projection_semantic_attestation_failed")
    for child_id, expected_version in unlocked_children:
        child = connection.execute(
            "SELECT status,version FROM nodes WHERE workflow_id=? AND node_id=?",
            (plan.workflow_id, child_id),
        ).fetchone()
        if child != ("ready", expected_version):
            raise _GCBProjectionDenied("projection_semantic_attestation_failed")


def _attest_gcb_projection_replay(
    connection: _AuthorityConnection,
    request: AtomicCommitRequest,
    plan: _GCBProjectionPlan,
) -> None:
    expected_node_version = _gcb_exact_int(
        plan.expected_node_version, label="expected_node_version"
    )
    committed_node_version = _gcb_exact_int(
        plan.committed_node_version, label="committed_node_version"
    )
    expected_workflow_state_version = _gcb_exact_int(
        plan.expected_workflow_state_version, label="workflow_state_version"
    )
    receipt = _gcb_material_object(plan.receipt_material, label="receipt")
    receipt_payload = receipt.get("payload")
    if not isinstance(receipt_payload, dict):
        raise _GCBProjectionDenied("projection_replay_mismatch")
    if (
        plan.workflow_id != request.subject.workflow_id
        or plan.node_id != request.subject.node_id
        or plan.attempt_id != request.subject.attempt_id
        or plan.agent_id != request.subject.agent_id
        or plan.commit_id != request.commit_id
        or plan.nonce != request.nonce
        or str(expected_node_version) != request.bindings.expected_node_version
        or committed_node_version != expected_node_version + 1
        or str(committed_node_version) != request.bindings.committed_node_version
        or receipt_payload.get("policy_digest") != plan.policy_digest
        or receipt_payload.get("state_version") != expected_workflow_state_version
        or hashlib.sha256(plan.receipt_material.encode()).hexdigest()
        != plan.receipt_digest
        or hashlib.sha256(plan.verdict_material.encode()).hexdigest()
        != plan.verdict_digest
    ):
        raise _GCBProjectionDenied("projection_replay_mismatch")
    decision = connection.execute(
        "SELECT request_hash,outcome,reason,workflow_id,node_id,state_version,nonce "
        "FROM decisions WHERE commit_id=?",
        (plan.commit_id,),
    ).fetchone()
    evidence = connection.execute(
        "SELECT receipt_material,receipt_digest,verdict_material,verdict_digest "
        "FROM receipt_evidence WHERE commit_id=?",
        (plan.commit_id,),
    ).fetchone()
    node = connection.execute(
        "SELECT status,attempt_id,claimed_by,result_digest,commit_id,receipt_digest "
        "FROM nodes WHERE workflow_id=? AND node_id=?",
        (plan.workflow_id, plan.node_id),
    ).fetchone()
    outbox = connection.execute(
        "SELECT workflow_id,node_id FROM outbox WHERE commit_id=?", (plan.commit_id,)
    ).fetchone()
    logical = connection.execute(
        "SELECT version FROM logical_nodes WHERE workflow_id=? AND node_id=?",
        (plan.workflow_id, plan.node_id),
    ).fetchone()
    if (
        decision is None
        or decision[0] != plan.request_hash
        or decision[1] != "committed"
        or decision[2] != "verified"
        or decision[3] != plan.workflow_id
        or decision[4] != plan.node_id
        or decision[5] != expected_workflow_state_version + 1
        or decision[6] != plan.nonce
        or evidence
        != (
            plan.receipt_material,
            plan.receipt_digest,
            plan.verdict_material,
            plan.verdict_digest,
        )
        or node
        != (
            "governed_committed",
            plan.attempt_id,
            plan.agent_id,
            request.subject.output_digest,
            plan.commit_id,
            plan.receipt_digest,
        )
        or outbox != (plan.workflow_id, plan.node_id)
        or logical != (request.bindings.committed_node_version,)
    ):
        raise _GCBProjectionDenied("projection_replay_mismatch")


def _config_object(config: APCCAuthorityConfig) -> dict[str, object]:
    def binding(item: TrustBinding) -> dict[str, object]:
        return {
            "role": item.role.value,
            "scope": list(item.scope),
            "key_id": item.key_id,
            "public_key": b64u_encode(item.public_key),
        }

    return {
        "authority_store_id": config.authority_store_id,
        "bindings": [binding(item) for item in config.trust_bindings],
        "freshness": {
            "maximum_staleness_ms": config.freshness.maximum_staleness_ms,
            "issued_status_lifetime_ms": config.freshness.issued_status_lifetime_ms,
        },
    }


def _config_from_object(value: object) -> APCCAuthorityConfig:
    if not isinstance(value, dict) or set(value) != {
        "authority_store_id",
        "bindings",
        "freshness",
    }:
        raise ValueError("APCC SQLite store schema validation failed")
    store_id = value["authority_store_id"]
    bindings_value = value["bindings"]
    freshness_value = value["freshness"]
    if (
        not isinstance(store_id, str)
        or not store_id
        or not isinstance(bindings_value, list)
        or not isinstance(freshness_value, dict)
        or set(freshness_value)
        != {
            "maximum_staleness_ms",
            "issued_status_lifetime_ms",
        }
        or not isinstance(freshness_value.get("maximum_staleness_ms"), str)
        or not isinstance(freshness_value.get("issued_status_lifetime_ms"), str)
    ):
        raise ValueError("APCC SQLite store schema validation failed")
    bindings: list[TrustBinding] = []
    for item in bindings_value:
        if not isinstance(item, dict) or set(item) != {
            "role",
            "scope",
            "key_id",
            "public_key",
        }:
            raise ValueError("APCC SQLite store schema validation failed")
        scope = item["scope"]
        if (
            not isinstance(scope, list)
            or not all(isinstance(part, str) for part in scope)
            or not isinstance(item["key_id"], str)
            or not isinstance(item["public_key"], str)
            or not isinstance(item["role"], str)
        ):
            raise ValueError("APCC SQLite store schema validation failed")
        bindings.append(
            TrustBinding(
                TrustRole(item["role"]),
                tuple(scope),
                item["key_id"],
                b64u_decode(item["public_key"], expected_length=32),
            )
        )
    by_role = {
        role: tuple(binding for binding in bindings if binding.role is role)
        for role in TrustRole
    }
    try:
        if (
            len(by_role[TrustRole.COMMIT]) != 1
            or len(by_role[TrustRole.STATUS]) != 1
            or not by_role[TrustRole.PRODUCER]
            or not by_role[TrustRole.POLICY]
            or not by_role[TrustRole.REGISTRY]
            or len({item.key_id for item in bindings}) != len(bindings)
            or len({item.public_key for item in bindings}) != len(bindings)
            or len(
                {
                    (item.role, item.scope, item.key_id, item.public_key)
                    for item in bindings
                }
            )
            != len(bindings)
        ):
            raise ValueError("APCC SQLite store schema validation failed")
        parsed = APCCAuthorityConfig(
            store_id,
            by_role[TrustRole.PRODUCER],
            by_role[TrustRole.POLICY],
            by_role[TrustRole.REGISTRY],
            by_role[TrustRole.COMMIT][0],
            by_role[TrustRole.STATUS][0],
            StatusFreshnessPolicy(
                freshness_value["maximum_staleness_ms"],
                freshness_value["issued_status_lifetime_ms"],
            ),
        )
        if _config_object(parsed) != value:
            raise ValueError("APCC SQLite store schema validation failed")
        return parsed
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ValueError("APCC SQLite store schema validation failed") from error


def _trust(config: APCCAuthorityConfig) -> ScopedTrust:
    return ScopedTrust(config.trust_bindings)


def _audit_id(kind: str, *parts: str) -> str:
    return sha256_digest((kind + "\x00" + "\x00".join(parts)).encode("utf-8"))


def _request_identity(request: AtomicCommitRequest) -> str:
    """Bind replay identity to every typed field supplied to the authority."""

    return sha256_digest(_authority_request_json(request).encode("utf-8"))


def _authority_request_object(request: AtomicCommitRequest) -> dict[str, object]:
    return {
        "subject": request.subject.to_object(),
        "context": request.context.to_object(),
        "evidence": request.evidence.to_object(),
        "bindings": request.bindings.to_object(),
        "signatures": request.signatures.to_object(),
        "commit_id": request.commit_id,
        "nonce": request.nonce,
    }


def _authority_request_json(request: AtomicCommitRequest) -> str:
    return _json(_authority_request_object(request))


def _operation_request_object(
    request: AtomicCommitRequest, old_certificate_digest: str | None
) -> dict[str, object]:
    return {
        "operation_kind": "SUPERSEDE"
        if old_certificate_digest is not None
        else "COMMIT",
        "old_certificate_digest": old_certificate_digest,
        "request": _authority_request_object(request),
    }


def _operation_request_json(
    request: AtomicCommitRequest, old_certificate_digest: str | None
) -> str:
    return _json(_operation_request_object(request, old_certificate_digest))


def _operation_identity(
    request: AtomicCommitRequest, old_certificate_digest: str | None
) -> str:
    return sha256_digest(
        _operation_request_json(request, old_certificate_digest).encode("utf-8")
    )


def _operation_from_json(value: str) -> tuple[AtomicCommitRequest, str | None]:
    parsed = _loads(value)
    if not isinstance(parsed, dict) or set(parsed) != {
        "operation_kind",
        "old_certificate_digest",
        "request",
    }:
        raise ValueError("invalid persisted authority operation")
    old = parsed["old_certificate_digest"]
    kind = parsed["operation_kind"]
    if (kind == "COMMIT" and old is not None) or (
        kind == "SUPERSEDE" and not isinstance(old, str)
    ):
        raise ValueError("invalid persisted authority operation")
    if kind not in {"COMMIT", "SUPERSEDE"}:
        raise ValueError("invalid persisted authority operation")
    request = _request_from_json(_json(parsed["request"]))
    return request, cast("str | None", old)


def _request_from_json(value: str) -> AtomicCommitRequest:
    parsed = _loads(value)
    if not isinstance(parsed, dict) or set(parsed) != {
        "subject",
        "context",
        "evidence",
        "bindings",
        "signatures",
        "commit_id",
        "nonce",
    }:
        raise ValueError("invalid persisted authority request")
    return AtomicCommitRequest(
        CertificateSubject.from_object(cast("dict[str, object]", parsed["subject"])),
        CertificateContext.from_object(cast("dict[str, object]", parsed["context"])),
        CertificateEvidence.from_object(cast("dict[str, object]", parsed["evidence"])),
        CertificateBindings.from_object(cast("dict[str, object]", parsed["bindings"])),
        CertificateSignatures.from_object(
            cast("dict[str, object]", parsed["signatures"])
        ),
        cast("str", parsed["commit_id"]),
        cast("str", parsed["nonce"]),
        "",
    )


def _public_request_digest(request: AtomicCommitRequest) -> str:
    """Recompute the legacy public replay handle from signed producer content."""

    return sha256_digest(canonical_statement(request.evidence.producer_statement))


def _proposal_identity(request: AtomicCommitRequest) -> str:
    """Digest every typed field authorized by the COMMIT_PENDING transition."""

    return _request_identity(request)


def _trusted_now(clock: object) -> int:
    value = cast("AuthorityClock", clock).now_ms()
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SAFE_INTEGER
    ):
        raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
    return value


def _validate_runtime_signers(
    config: APCCAuthorityConfig, runtime: AuthorityRuntime
) -> None:
    for role, binding in (
        (AuthoritySigningRole.COMMIT, config.commit_trust),
        (AuthoritySigningRole.STATUS, config.status_trust),
    ):
        if (
            bytes(runtime.key_provider.public_key(role, binding.key_id))
            != binding.public_key
        ):
            raise ValueError("APCC runtime signer does not match public configuration")


def _has_later_generation_revocation(
    connection: _AuthorityConnection, certificate: CommitCertificate
) -> bool:
    actor = connection.execute(
        "SELECT generation FROM actor_revocations WHERE workflow_id=? AND actor_id=?",
        (certificate.subject.workflow_id, certificate.subject.agent_id),
    ).fetchone()
    if actor is not None and _row_int(actor[0]) > int(
        certificate.context.agent_revocation_generation
    ):
        return True
    workflow = connection.execute(
        "SELECT generation FROM workflow_revocations WHERE workflow_id=?",
        (certificate.subject.workflow_id,),
    ).fetchone()
    return workflow is not None and _row_int(workflow[0]) > int(
        certificate.context.workflow_revocation_generation
    )


def _latest_disposition(
    connection: _AuthorityConnection, certificate_digest: str
) -> CertificateDisposition | None:
    row = connection.execute(
        "SELECT disposition FROM certificate_dispositions "
        "WHERE certificate_digest=? ORDER BY event_sequence DESC LIMIT 1",
        (certificate_digest,),
    ).fetchone()
    return None if row is None else CertificateDisposition(_row_text(row[0]))


def _candidate_matches(
    row: sqlite3.Row | tuple[object, ...],
    request: AtomicCommitRequest,
    *,
    evidence_bound: bool,
) -> bool:
    """Bind every proposal object to the durable candidate created for its attempt."""

    result = row[2]
    staged_binding_matches = (
        row[1] == request.bindings.expected_node_version
        and result is not None
        and sha256_digest(bytes(cast("bytes", result))) == request.subject.output_digest
        and row[3] == _json(request.subject.to_object())
    )
    return staged_binding_matches and (
        not evidence_bound
        or (
            row[4] == _json(request.context.to_object())
            and row[5]
            == _json([item.to_object() for item in request.bindings.predecessors])
        )
    )


def _write_audit(
    connection: _AuthorityConnection,
    audit_event_id: str,
    kind: str,
    subject: str,
    **details: str,
) -> None:
    connection.execute(
        "INSERT INTO audit_events(audit_event_id, event_json) VALUES (?, ?)",
        (audit_event_id, _json({"kind": kind, "subject": subject, **details})),
    )


def _canonical_positive_decimal(value: object, *, maximum: int) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
    if parsed > maximum:
        raise ValueError(
            (
                FailureCode.SIZE_LIMIT_EXCEEDED
                if maximum == 1000
                else FailureCode.INVALID_DECIMAL_STRING
            ).value
        )
    return parsed


def _canonical_nonnegative_decimal(value: object, *, maximum: int) -> int:
    if value == "0":
        return 0
    return _canonical_positive_decimal(value, maximum=maximum)


def _observation_effective_revoked(
    connection: _AuthorityConnection,
    certificate_digest: str,
    *,
    active: set[str] | None = None,
    cache: dict[str, bool] | None = None,
) -> bool:
    """Resolve guarded transitive revocation inside an observation snapshot."""
    active_digests = set() if active is None else active
    resolved = {} if cache is None else cache
    cached = resolved.get(certificate_digest)
    if cached is not None:
        return cached
    if (
        certificate_digest in active_digests
        or len(active_digests) + len(resolved) >= CausalClosureLimits().max_certificates
    ):
        return True
    active_digests.add(certificate_digest)
    row = connection.execute(
        "SELECT certificate_json FROM certificates WHERE certificate_digest=?",
        (certificate_digest,),
    ).fetchone()
    disposition = _latest_disposition(connection, certificate_digest)
    if row is None or disposition is None:
        active_digests.remove(certificate_digest)
        resolved[certificate_digest] = True
        return True
    certificate = decode_certificate(_row_bytes(row[0]))
    if (
        disposition is CertificateDisposition.REVOKED
        or _has_later_generation_revocation(connection, certificate)
    ):
        active_digests.remove(certificate_digest)
        resolved[certificate_digest] = True
        return True
    revoked = any(
        _observation_effective_revoked(
            connection,
            predecessor.certificate_digest,
            active=active_digests,
            cache=resolved,
        )
        for predecessor in certificate.bindings.predecessors
    )
    active_digests.remove(certificate_digest)
    resolved[certificate_digest] = revoked
    return revoked


class _AuthorityReaderCore:
    """Storage-neutral APCC read operations over a transactional DB-API port."""

    _config: APCCAuthorityConfig

    def __init__(
        self,
        authority_store_id: str,
        status_signer: AuthorityObservationStatusSigner | None = None,
    ) -> None:
        self.authority_store_id = authority_store_id
        self._observation_status_signer = status_signer

    def _read_transaction(
        self,
    ) -> AbstractContextManager[_AuthorityConnection]:
        raise NotImplementedError

    def read_logical_node(self, workflow_id: str, node_id: str) -> LogicalNodeState:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT version, certificate_digest FROM logical_nodes "
                "WHERE workflow_id = ? AND node_id = ?",
                (workflow_id, node_id),
            ).fetchone()
            if row is None:
                return LogicalNodeState(workflow_id, node_id, "0", None)
            return LogicalNodeState(
                workflow_id, node_id, str(row[0]), _row_optional_text(row[1])
            )

    def read_commit_context(self, request: CommitContextRequest) -> CommitContext:
        with self._read_transaction() as connection:
            candidate = connection.execute(
                "SELECT lifecycle, subject_json, context_json, predecessors_json, audit_event_id "
                "FROM candidates WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                (request.workflow_id, request.node_id, request.attempt_id),
            ).fetchone()
            if candidate is None:
                raise ValueError(FailureCode.CROSS_ATTEMPT_REPLAY.value)
            subject = CommitCertificate.from_object(
                _certificate_shell(
                    _loads(_row_text(candidate[1])),
                    _loads(_row_text(candidate[2])),
                    _loads(_row_text(candidate[3])),
                )
            ).subject
            certificate = CommitCertificate.from_object(
                _certificate_shell(
                    _loads(_row_text(candidate[1])),
                    _loads(_row_text(candidate[2])),
                    _loads(_row_text(candidate[3])),
                )
            )
            logical_row = connection.execute(
                "SELECT version, certificate_digest FROM logical_nodes "
                "WHERE workflow_id=? AND node_id=?",
                (request.workflow_id, request.node_id),
            ).fetchone()
            logical = (
                LogicalNodeState(request.workflow_id, request.node_id, "0", None)
                if logical_row is None
                else LogicalNodeState(
                    request.workflow_id,
                    request.node_id,
                    str(logical_row[0]),
                    _row_optional_text(logical_row[1]),
                )
            )
            return CommitContext(
                subject,
                certificate.context,
                CandidateState(
                    request.workflow_id,
                    request.node_id,
                    request.attempt_id,
                    CandidateLifecycle(_row_text(candidate[0])),
                ),
                logical,
                certificate.bindings.predecessors,
                _row_text(candidate[4]),
            )

    def replay_commit(self, request: ReplayCommitRequest) -> CommitResult:
        with self._read_transaction() as connection:
            return _replay(connection, request.commit_id, request.request_digest)

    def get_certificate(self, commit_id: str) -> bytes | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT envelope FROM certificates WHERE commit_id = ?", (commit_id,)
            ).fetchone()
            return None if row is None else _row_bytes(row[0])

    def get_outbox_event(self, commit_id: str) -> PersistedOutboxEvent:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT event_id, event_json, audit_event_id, delivered FROM apcc_outbox "
                "WHERE event_kind='COMMIT' AND operation_id = ?",
                (commit_id,),
            ).fetchone()
            if row is None:
                raise ValueError("no APCC outbox event for commit")
            return PersistedOutboxEvent(
                _row_text(row[0]),
                _row_bytes(row[1]),
                _row_text(row[2]),
                not bool(row[3]),
            )

    def observe_authority(
        self, request: AuthorityObservationRequest
    ) -> AuthorityObservationSnapshot:
        """Retry the complete read transaction after a status-snapshot race."""
        for attempt in range(3):
            try:
                return self._observe_authority_once(request)
            except AuthorityObservationSnapshotChanged:
                if attempt == 2:
                    raise
        raise AssertionError("unreachable observation retry state")

    def _observe_authority_once(
        self, request: AuthorityObservationRequest
    ) -> AuthorityObservationSnapshot:
        """Observe one complete authority tuple in one attested DB snapshot."""
        if request.authority_store_id != self.authority_store_id:
            raise ValueError("authority observation store binding mismatch")
        with self._read_transaction() as connection:
            logical_row = connection.execute(
                "SELECT version,certificate_digest FROM logical_nodes "
                "WHERE workflow_id=? AND node_id=?",
                (request.workflow_id, request.node_id),
            ).fetchone()
            logical = (
                LogicalNodeState(request.workflow_id, request.node_id, "0", None)
                if logical_row is None
                else LogicalNodeState(
                    request.workflow_id,
                    request.node_id,
                    _row_text(logical_row[0]),
                    _row_optional_text(logical_row[1]),
                )
            )
            indexed = connection.execute(
                "SELECT request_digest,workflow_id,request_json FROM commit_index "
                "WHERE commit_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if indexed is None:
                return AuthorityObservationSnapshot(
                    request,
                    AuthorityObservationState.ABSENT,
                    None,
                    None,
                    None,
                    None,
                    None,
                    logical,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    False,
                )
            authoritative_digest = _row_text(indexed[0])
            indexed_workflow = _row_text(indexed[1])
            persisted_operation_bytes = _row_text(indexed[2]).encode("utf-8")
            persisted_request, persisted_supersession = _operation_from_json(
                _row_text(indexed[2])
            )
            if (
                _operation_identity(persisted_request, persisted_supersession)
                != authoritative_digest
            ):
                raise ValueError("authority observation operation digest mismatch")
            public_row = connection.execute(
                "SELECT request_digest FROM request_index WHERE commit_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if public_row is None:
                raise ValueError("authority observation lacks public request binding")
            authoritative_public_digest = _row_text(public_row[0])
            if _public_request_digest(persisted_request) != authoritative_public_digest:
                raise ValueError("authority observation public request digest mismatch")
            if (
                indexed_workflow != request.workflow_id
                or persisted_request.subject.workflow_id != request.workflow_id
                or persisted_request.subject.node_id != request.node_id
                or persisted_request.subject.attempt_id != request.attempt_id
                or persisted_request.commit_id != request.expected_commit_id
                or authoritative_digest != request.expected_operation_digest
                or authoritative_public_digest != request.public_request_digest
            ):
                conflict = connection.execute(
                    "SELECT audit_event_id,original_workflow_id,original_node_id,"
                    "original_attempt_id,original_request_digest,"
                    "original_public_request_digest,conflicting_workflow_id,"
                    "conflicting_node_id,conflicting_attempt_id,"
                    "conflicting_request_digest,conflicting_public_request_digest "
                    "FROM commit_conflicts "
                    "WHERE commit_id=? AND "
                    "conflicting_workflow_id=? AND conflicting_node_id=? AND "
                    "conflicting_attempt_id=? AND conflicting_request_digest=? AND "
                    "conflicting_public_request_digest=?",
                    (
                        request.expected_commit_id,
                        request.workflow_id,
                        request.node_id,
                        request.attempt_id,
                        request.expected_operation_digest,
                        request.public_request_digest,
                    ),
                ).fetchone()
                if conflict is None:
                    raise ValueError("authority observation target binding mismatch")
                audit_id = _row_text(conflict[0])
                audit = connection.execute(
                    "SELECT event_json FROM audit_events WHERE audit_event_id=?",
                    (audit_id,),
                ).fetchone()
                if audit is None:
                    raise ValueError("authority conflict lacks audit evidence")
                conflict_claim = _json(
                    {
                        "commit_id": request.expected_commit_id,
                        "original_workflow_id": _row_text(conflict[1]),
                        "original_node_id": _row_text(conflict[2]),
                        "original_attempt_id": _row_text(conflict[3]),
                        "original_request_digest": _row_text(conflict[4]),
                        "original_public_request_digest": _row_text(conflict[5]),
                        "conflicting_workflow_id": _row_text(conflict[6]),
                        "conflicting_node_id": _row_text(conflict[7]),
                        "conflicting_attempt_id": _row_text(conflict[8]),
                        "conflicting_request_digest": _row_text(conflict[9]),
                        "conflicting_public_request_digest": _row_text(conflict[10]),
                    }
                ).encode("ascii")
                return AuthorityObservationSnapshot(
                    request,
                    AuthorityObservationState.CONFLICTED,
                    authoritative_digest,
                    authoritative_public_digest,
                    FailureCode.COMMIT_ID_EQUIVOCATION.value,
                    audit_id,
                    _row_text(audit[0]).encode(),
                    logical,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    False,
                    persisted_operation_bytes,
                    conflict_claim,
                )
            decision = connection.execute(
                "SELECT outcome,reason,audit_event_id,certificate_digest "
                "FROM apcc_decisions WHERE commit_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if decision is None:
                raise ValueError("authority commit index has no durable decision")
            outcome = AuthorityObservationState(_row_text(decision[0]))
            reason = _row_text(decision[1])
            audit_id = _row_text(decision[2])
            audit = connection.execute(
                "SELECT event_json FROM audit_events WHERE audit_event_id=?",
                (audit_id,),
            ).fetchone()
            if audit is None:
                raise ValueError("authority decision lacks audit evidence")
            audit_bytes = _row_text(audit[0]).encode()
            if outcome is not AuthorityObservationState.COMMITTED:
                return AuthorityObservationSnapshot(
                    request,
                    outcome,
                    authoritative_digest,
                    authoritative_public_digest,
                    reason,
                    audit_id,
                    audit_bytes,
                    logical,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    False,
                    persisted_operation_bytes,
                )
            certificate = connection.execute(
                "SELECT certificate_json,envelope,certificate_digest,workflow_id,node_id,sequence "
                "FROM certificates WHERE commit_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if certificate is None:
                raise ValueError("committed observation lacks certificate")
            certificate_digest = _row_text(certificate[2])
            if (
                _row_text(certificate[3]) != request.workflow_id
                or _row_text(certificate[4]) != request.node_id
                or certificate_digest != _row_optional_text(decision[3])
            ):
                raise ValueError("committed observation certificate binding mismatch")
            payload = _row_bytes(certificate[0])
            envelope = _row_bytes(certificate[1])
            decoded = decode_certificate(payload)
            disposition_row = connection.execute(
                "SELECT disposition FROM certificate_dispositions "
                "WHERE certificate_digest=? ORDER BY event_sequence DESC LIMIT 1",
                (certificate_digest,),
            ).fetchone()
            if disposition_row is None:
                raise ValueError("committed observation lacks disposition")
            effectively_revoked = _observation_effective_revoked(
                connection, certificate_digest
            )
            supersession = connection.execute(
                "SELECT new_digest FROM supersession_edges WHERE old_digest=?",
                (certificate_digest,),
            ).fetchone()
            superseded_by = None if supersession is None else _row_text(supersession[0])
            current_status = "revoked" if effectively_revoked else "current"
            pointer_current = logical.current_certificate_digest == certificate_digest
            status_signer = self._observation_status_signer
            if status_signer is None:
                raise ValueError("authority observation requires status signer")
            trust_row = connection.execute(
                "SELECT sequence,entry_digest FROM trust_log "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            trust_sequence, trust_head = (
                ("0", sha256_digest(b"APCC-1/trust-log/genesis"))
                if trust_row is None
                else (str(trust_row[0]), _row_text(trust_row[1]))
            )
            facts = {
                "authority_store_id": self.authority_store_id,
                "status_key_id": self._config.status_trust.key_id,
                "request_nonce": request.request_nonce,
                "certificate_digest": certificate_digest,
                "certificate_sequence": str(certificate[5]),
                "trust_log_sequence": trust_sequence,
                "trust_log_head": trust_head,
                "status": current_status,
                "actor_revocation_generation": decoded.context.agent_revocation_generation,
                "workflow_revocation_generation": decoded.context.workflow_revocation_generation,
                "superseded": (
                    SupersessionValue.YES.value
                    if superseded_by is not None
                    else SupersessionValue.NO.value
                ),
            }
            status_evidence = status_signer.current_status(
                certificate_digest, request.request_nonce
            )
            signed_status = decode_authority_status(status_evidence)
            if signed_status.body_object() | {} != {
                "protocol_version": "APCC-1.0-draft",
                "statement_type": "apcc.authority-status",
                **facts,
                "this_update_ms": signed_status.this_update_ms,
                "next_update_ms": signed_status.next_update_ms,
            }:
                raise AuthorityObservationSnapshotChanged(
                    "authority status snapshot changed during observation"
                )
            body = encode_authority_status_body(signed_status)
            if not verify_detached(
                self._config.status_trust.public_key,
                AUTHORITY_STATUS_DOMAIN,
                body,
                signed_status.signature.signature_b64u,
            ):
                raise ValueError("authority observation status signature invalid")
            if int(signed_status.this_update_ms) > int(
                signed_status.next_update_ms
            ) or (
                int(signed_status.next_update_ms) - int(signed_status.this_update_ms)
                != int(self._config.freshness.issued_status_lifetime_ms)
            ):
                raise ValueError("authority observation status validity invalid")
            outbox = connection.execute(
                "SELECT event_sequence,event_id,event_kind,operation_id,event_json,"
                "audit_event_id,trust_sequence,state,lease_token,lease_claimed_ms,"
                "lease_until_ms,delivered FROM apcc_outbox "
                "WHERE event_kind='COMMIT' AND operation_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if outbox is None:
                raise ValueError("committed observation lacks outbox evidence")
            output = connection.execute(
                "SELECT r.output_digest,r.output_size,c.result "
                "FROM commit_output_refs r JOIN candidates c ON "
                "c.workflow_id=r.workflow_id AND c.node_id=r.node_id "
                "AND c.attempt_id=r.attempt_id WHERE r.commit_id=?",
                (request.expected_commit_id,),
            ).fetchone()
            if output is None:
                raise ValueError("committed observation lacks output binding")
            output_bytes = _row_bytes(output[2])
            if (
                _row_text(output[0]) != decoded.subject.output_digest
                or _row_int(output[1]) != len(output_bytes)
                or sha256_digest(output_bytes) != decoded.subject.output_digest
            ):
                raise ValueError("committed observation output binding mismatch")
            outbox_record = _json(
                {
                    "event_sequence": str(outbox[0]),
                    "event_id": _row_text(outbox[1]),
                    "event_kind": _row_text(outbox[2]),
                    "operation_id": _row_text(outbox[3]),
                    "event_payload_sha256": sha256_digest(_row_bytes(outbox[4])),
                    "audit_event_id": _row_text(outbox[5]),
                    "trust_sequence": str(outbox[6]),
                    "state": _row_text(outbox[7]),
                    "lease_token": outbox[8],
                    "lease_claimed_ms": (None if outbox[9] is None else str(outbox[9])),
                    "lease_until_ms": (None if outbox[10] is None else str(outbox[10])),
                    "delivered": str(outbox[11]),
                }
            ).encode("utf-8")
            visible = (
                pointer_current
                and current_status == "current"
                and superseded_by is None
            )
            return AuthorityObservationSnapshot(
                request,
                outcome,
                authoritative_digest,
                authoritative_public_digest,
                reason,
                audit_id,
                audit_bytes,
                logical,
                payload,
                envelope,
                certificate_digest,
                status_evidence,
                _row_text(outbox[1]),
                _row_bytes(outbox[4]),
                _row_text(outbox[7]),
                decoded.subject.output_digest,
                visible,
                persisted_operation_bytes,
                None,
                output_bytes,
                outbox_record,
            )


class SQLiteAuthorityReader(_AuthorityReaderCore):
    """Signer-free SQLite APCC reader.  It never opens a writer transaction."""

    def __init__(
        self,
        path: Path,
        config: APCCAuthorityConfig,
        status_signer: AuthorityObservationStatusSigner | None = None,
    ) -> None:
        super().__init__(config.authority_store_id, status_signer)
        self.database_path = Path(path)
        self._config = config
        self._attested_read_connections: set[sqlite3.Connection] = set()

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        status_signer: AuthorityObservationStatusSigner | None = None,
    ) -> SQLiteAuthorityReader:
        connection = _connect_reader(path)
        try:
            connection.execute("BEGIN")
            config_text = _validate_schema(connection)
            config = _config_from_object(_loads(config_text))
            connection.commit()
            return cls(Path(path), config, status_signer)
        except ValueError:
            raise
        except sqlite3.DatabaseError as error:
            raise ValueError("APCC SQLite store schema validation failed") from error
        finally:
            connection.close()

    def _connection(self) -> sqlite3.Connection:
        return _connect_reader(self.database_path)

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            _attest_sqlite_read_connection(connection, self._config)
            self._attested_read_connections.add(connection)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._attested_read_connections.discard(connection)
            connection.close()


class _AuthorityStoreCore(_AuthorityReaderCore):
    """Storage-neutral APCC state machine over one atomic write transaction."""

    def __init__(self, config: APCCAuthorityConfig, runtime: AuthorityRuntime) -> None:
        super().__init__(config.authority_store_id)
        self._config = config
        self._runtime = runtime

    def _transaction(self) -> AbstractContextManager[_AuthorityConnection]:
        raise NotImplementedError

    def _connection(self) -> _AuthorityConnection:
        raise NotImplementedError

    def _hit(self, point: str) -> None:
        del point

    def _run_projection(
        self,
        connection: _AuthorityConnection,
        request: AtomicCommitRequest,
        result: CommitResult,
        plan: _GCBProjectionPlan | None,
    ) -> None:
        del connection, request, result
        if plan is not None:
            raise TypeError("GCB projection requires the SQLite authority store")

    def stage_result(self, request: StageResultRequest) -> StageResultResult:
        audit = _audit_id(
            "stage",
            request.subject.workflow_id,
            request.subject.node_id,
            request.subject.attempt_id,
            request.subject.output_digest,
            request.expected_node_version,
        )
        quarantined = False
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT lifecycle, result, expected_version, subject_json "
                "FROM candidates WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                (
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                ),
            ).fetchone()
            if row is None:
                template = connection.execute(
                    "SELECT context_json FROM candidates WHERE workflow_id=? AND node_id=? LIMIT 1",
                    (request.subject.workflow_id, request.subject.node_id),
                ).fetchone()
                node = connection.execute(
                    "SELECT version FROM logical_nodes WHERE workflow_id=? AND node_id=?",
                    (request.subject.workflow_id, request.subject.node_id),
                ).fetchone()
                if template is None or node is None:
                    raise ValueError(FailureCode.CROSS_ATTEMPT_REPLAY.value)
                connection.execute(
                    "INSERT INTO candidates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        request.subject.workflow_id,
                        request.subject.node_id,
                        request.subject.attempt_id,
                        request.subject.agent_id,
                        CandidateLifecycle.EXECUTING.value,
                        str(node[0]),
                        None,
                        _json(request.subject.to_object()),
                        template[0],
                        "[]",
                        None,
                        _audit_id("candidate", request.subject.attempt_id),
                        None,
                    ),
                )
                row = (
                    CandidateLifecycle.EXECUTING.value,
                    None,
                    request.expected_node_version,
                    _json(request.subject.to_object()),
                )
            if sha256_digest(request.result_bytes) != request.subject.output_digest:
                if row[0] == CandidateLifecycle.RESULT_STAGED.value:
                    connection.execute(
                        "UPDATE candidates SET lifecycle=? WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                        (
                            CandidateLifecycle.QUARANTINED.value,
                            request.subject.workflow_id,
                            request.subject.node_id,
                            request.subject.attempt_id,
                        ),
                    )
                    quarantined = True
                else:
                    raise ValueError(FailureCode.OUTPUT_DIGEST_MISMATCH.value)
            if row[0] == CandidateLifecycle.QUARANTINED.value:
                raise ValueError(FailureCode.QUARANTINED.value)
            if row[0] not in (
                CandidateLifecycle.EXECUTING.value,
                CandidateLifecycle.RESULT_STAGED.value,
            ):
                raise ValueError(FailureCode.ILLEGAL_NODE_STATE.value)
            if row[2] != request.expected_node_version or row[3] != _json(
                request.subject.to_object()
            ):
                raise ValueError(FailureCode.STAGED_RESULT_CONFLICT.value)
            if (
                row[0] == CandidateLifecycle.RESULT_STAGED.value
                and _row_bytes(row[1]) != request.result_bytes
            ):
                connection.execute(
                    "UPDATE candidates SET lifecycle=? WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                    (
                        CandidateLifecycle.QUARANTINED.value,
                        request.subject.workflow_id,
                        request.subject.node_id,
                        request.subject.attempt_id,
                    ),
                )
                quarantined = True
            else:
                connection.execute(
                    "UPDATE candidates SET lifecycle=?, result=?, audit_event_id=? "
                    "WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                    (
                        CandidateLifecycle.RESULT_STAGED.value,
                        request.result_bytes,
                        audit,
                        request.subject.workflow_id,
                        request.subject.node_id,
                        request.subject.attempt_id,
                    ),
                )
        if quarantined:
            raise ValueError(FailureCode.STAGED_RESULT_CONFLICT.value)
        return StageResultResult(
            CandidateState(
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
                CandidateLifecycle.RESULT_STAGED,
            ),
            audit,
        )

    def assemble_evidence(
        self, request: AssembleEvidenceRequest
    ) -> AssembleEvidenceResult:
        return cast(
            "AssembleEvidenceResult",
            self._advance(
                request.proposal,
                CandidateLifecycle.RESULT_STAGED,
                CandidateLifecycle.EVIDENCE_ASSEMBLED,
                AssembleEvidenceResult,
            ),
        )

    def propose_commit(self, request: ProposeCommitRequest) -> ProposeCommitResult:
        return cast(
            "ProposeCommitResult",
            self._advance(
                request.proposal,
                CandidateLifecycle.EVIDENCE_ASSEMBLED,
                CandidateLifecycle.COMMIT_PENDING,
                ProposeCommitResult,
            ),
        )

    def _advance(
        self,
        proposal: AtomicCommitRequest,
        expected: CandidateLifecycle,
        target: CandidateLifecycle,
        result_type: type[AssembleEvidenceResult] | type[ProposeCommitResult],
    ) -> AssembleEvidenceResult | ProposeCommitResult:
        with self._transaction() as connection:
            static_error = self._static_error(proposal)
            if static_error is not None:
                raise ValueError(static_error.value)
            row = connection.execute(
                "SELECT lifecycle, expected_version, result, subject_json, context_json, predecessors_json, proposal_digest "
                "FROM candidates WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                (
                    proposal.subject.workflow_id,
                    proposal.subject.node_id,
                    proposal.subject.attempt_id,
                ),
            ).fetchone()
            if row is None:
                raise ValueError(FailureCode.CROSS_ATTEMPT_REPLAY.value)
            if row[0] == CandidateLifecycle.EXECUTING.value and row[2] is None:
                code = (
                    FailureCode.RESULT_NOT_STAGED
                    if expected is CandidateLifecycle.RESULT_STAGED
                    else FailureCode.ILLEGAL_NODE_STATE
                )
                raise ValueError(code.value)
            if not _candidate_matches(
                row,
                proposal,
                evidence_bound=expected is not CandidateLifecycle.RESULT_STAGED,
            ):
                raise ValueError(FailureCode.STAGED_RESULT_CONFLICT.value)
            if row[0] == CandidateLifecycle.QUARANTINED.value:
                raise ValueError(FailureCode.QUARANTINED.value)
            if row[0] != expected.value:
                code = (
                    FailureCode.RESULT_NOT_STAGED
                    if expected is CandidateLifecycle.RESULT_STAGED
                    else FailureCode.ILLEGAL_NODE_STATE
                )
                raise ValueError(code.value)
            audit = _audit_id(
                target.value, proposal.commit_id, _proposal_identity(proposal)
            )
            if target is CandidateLifecycle.EVIDENCE_ASSEMBLED:
                connection.execute(
                    "UPDATE candidates SET lifecycle=?, context_json=?, predecessors_json=?, audit_event_id=?, proposal_digest=?, proposal_json=? "
                    "WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                    (
                        target.value,
                        _json(proposal.context.to_object()),
                        _json(
                            [
                                item.to_object()
                                for item in proposal.bindings.predecessors
                            ]
                        ),
                        audit,
                        _proposal_identity(proposal),
                        _authority_request_json(proposal),
                        proposal.subject.workflow_id,
                        proposal.subject.node_id,
                        proposal.subject.attempt_id,
                    ),
                )
            else:
                connection.execute(
                    "UPDATE candidates SET lifecycle=?, proposal_digest=?, audit_event_id=?, proposal_json=? "
                    "WHERE workflow_id=? AND node_id=? AND attempt_id=?",
                    (
                        target.value,
                        _proposal_identity(proposal),
                        audit,
                        _authority_request_json(proposal),
                        proposal.subject.workflow_id,
                        proposal.subject.node_id,
                        proposal.subject.attempt_id,
                    ),
                )
            value = CandidateState(
                proposal.subject.workflow_id,
                proposal.subject.node_id,
                proposal.subject.attempt_id,
                target,
            )
            return result_type(value, audit)

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult:
        return self._commit(request, supersede_old=None, projection_plan=None)

    def _commit(
        self,
        request: AtomicCommitRequest,
        supersede_old: str | None,
        projection_plan: _GCBProjectionPlan | None = None,
    ) -> CommitResult:
        prefix = "supersession_" if supersede_old is not None else ""
        request_digest = _operation_identity(request, supersede_old)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT request_digest FROM commit_index WHERE commit_id=?",
                (request.commit_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] == request_digest:
                    if projection_plan is not None:
                        _attest_gcb_projection_replay(
                            connection, request, projection_plan
                        )
                    return _replay(connection, request.commit_id, request_digest)
                return self._conflict(
                    connection,
                    request.commit_id,
                    request_digest,
                    _public_request_digest(request),
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                    _json(
                        {
                            "kind": "atomic",
                            "request": _authority_request_object(request),
                            "supersede_old": supersede_old,
                        }
                    ),
                    supersede_old,
                )
            self._hit(f"before_{prefix}verification")
            certificate: CommitCertificate | None = None
            sequence: str | None = None
            error: FailureCode | None
            if connection.execute(
                "SELECT 1 FROM nonce_ledger WHERE nonce=?", (request.nonce,)
            ).fetchone():
                error = FailureCode.NONCE_REPLAY
            else:
                sequence = self._next_sequence(connection)
                certificate = self._certificate(request, sequence)
                error = self._certificate_error(certificate)
                if error is None:
                    error = self._preflight(
                        connection, request, supersede_old, certificate
                    )
            self._hit(f"after_{prefix}verification")
            if error is not None:
                return self._negative(connection, request, error, supersede_old)
            assert certificate is not None
            assert sequence is not None
            self._hit(f"before_{prefix}seal")
            payload, envelope, digest = self._seal(certificate)
            self._hit(f"after_{prefix}seal")
            self._hit(f"before_{prefix}commit_index_reservation")
            connection.execute(
                "INSERT INTO commit_index VALUES (?, ?, ?, ?)",
                (
                    request.commit_id,
                    request_digest,
                    request.subject.workflow_id,
                    _operation_request_json(request, supersede_old),
                ),
            )
            self._hit(f"after_{prefix}commit_index_reservation")
            self._hit(f"before_{prefix}request_index_write")
            connection.execute(
                "INSERT INTO request_index VALUES (?, ?)",
                (_public_request_digest(request), request.commit_id),
            )
            self._hit(f"after_{prefix}request_index_write")
            self._hit(f"before_{prefix}nonce_ledger")
            connection.execute(
                "INSERT INTO nonce_ledger VALUES (?, ?)",
                (request.nonce, request.commit_id),
            )
            self._hit(f"after_{prefix}nonce_ledger")
            self._hit(f"before_{prefix}candidate_update")
            # Candidate lifecycle is independent from a request outcome: a
            # successful commit leaves the durable staged state COMMIT_PENDING.
            self._hit(f"after_{prefix}candidate_update")
            self._hit(f"before_{prefix}audit_write")
            audit = _audit_id("commit", request.commit_id, request_digest)
            _write_audit(
                connection,
                audit,
                "committed",
                request.commit_id,
                **({"old_certificate_digest": supersede_old} if supersede_old else {}),
            )
            self._hit(f"after_{prefix}audit_write")
            self._hit(f"before_{prefix}evidence_refs")
            connection.execute(
                "INSERT INTO evidence_refs VALUES (?, ?, ?, ?)",
                (
                    request.commit_id,
                    request.evidence.producer_statement_digest,
                    request.evidence.policy_statement_digest,
                    request.evidence.authority_statement_digest,
                ),
            )
            self._hit(f"after_{prefix}evidence_refs")
            if supersede_old is None:
                self._hit("before_node_write")
                connection.execute(
                    "UPDATE logical_nodes SET version=?, certificate_digest=? WHERE workflow_id=? AND node_id=?",
                    (
                        request.bindings.committed_node_version,
                        digest,
                        request.subject.workflow_id,
                        request.subject.node_id,
                    ),
                )
                self._hit("after_node_write")
                self._hit("before_node_pointer_write")
                self._hit("after_node_pointer_write")
            self._hit(f"before_{prefix}certificate_write")
            connection.execute(
                "INSERT INTO certificates(certificate_digest, commit_id, certificate_json, envelope, workflow_id, node_id, sequence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    digest,
                    request.commit_id,
                    payload,
                    envelope,
                    request.subject.workflow_id,
                    request.subject.node_id,
                    sequence,
                ),
            )
            self._hit(f"after_{prefix}certificate_write")
            output_row = connection.execute(
                "SELECT result FROM candidates WHERE workflow_id=? AND node_id=? "
                "AND attempt_id=?",
                (
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                ),
            ).fetchone()
            if output_row is None or output_row[0] is None:
                raise ValueError("committed APCC operation lacks staged output")
            output_bytes = _row_bytes(output_row[0])
            if sha256_digest(output_bytes) != request.subject.output_digest:
                raise ValueError("committed APCC output digest mismatch")
            connection.execute(
                "INSERT INTO commit_output_refs VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request.commit_id,
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                    request.subject.output_digest,
                    len(output_bytes),
                ),
            )
            if request.bindings.predecessors:
                self._hit(f"before_{prefix}predecessor_edges")
                for predecessor in request.bindings.predecessors:
                    connection.execute(
                        "INSERT INTO predecessor_edges(child_commit_id, predecessor_digest) VALUES (?, ?)",
                        (request.commit_id, predecessor.certificate_digest),
                    )
                self._hit(f"after_{prefix}predecessor_edges")
            self._hit(f"before_{prefix}decision_write")
            connection.execute(
                "INSERT INTO apcc_decisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    request.commit_id,
                    RequestOutcome.COMMITTED.value,
                    "OK",
                    audit,
                    digest,
                    request.nonce,
                    request.commit_id,
                ),
            )
            self._hit(f"after_{prefix}decision_write")
            if supersede_old is None:
                self._hit("before_disposition_write")
                connection.execute(
                    "INSERT INTO certificate_dispositions VALUES (?, 1, ?)",
                    (digest, CertificateDisposition.CURRENT.value),
                )
                self._hit("after_disposition_write")
            else:
                self._hit("before_supersession_old_disposition_write")
                connection.execute(
                    "INSERT INTO certificate_dispositions VALUES (?, 2, ?)",
                    (supersede_old, CertificateDisposition.SUPERSEDED.value),
                )
                self._hit("after_supersession_old_disposition_write")
                self._hit("before_supersession_new_disposition_write")
                connection.execute(
                    "INSERT INTO certificate_dispositions VALUES (?, 1, ?)",
                    (digest, CertificateDisposition.CURRENT.value),
                )
                self._hit("after_supersession_new_disposition_write")
                edge = _audit_id("replace", supersede_old, digest)
                self._hit("before_supersession_replacement_edge_write")
                connection.execute(
                    "INSERT INTO supersession_edges(edge_id, old_digest, new_digest, nonce) VALUES (?, ?, ?, ?)",
                    (edge, supersede_old, digest, request.nonce),
                )
                self._hit("after_supersession_replacement_edge_write")
                self._hit("before_supersession_node_pointer_write")
                connection.execute(
                    "UPDATE logical_nodes SET version=?, certificate_digest=? WHERE workflow_id=? AND node_id=?",
                    (
                        request.bindings.committed_node_version,
                        digest,
                        request.subject.workflow_id,
                        request.subject.node_id,
                    ),
                )
                self._hit("after_supersession_node_pointer_write")
            self._hit(f"before_{prefix}trust_log_write")
            trust_sequence, _trust_head = self._append_trust(
                connection, "commit", digest, audit
            )
            self._hit(f"after_{prefix}trust_log_write")
            event = _audit_id("outbox", "COMMIT", request.commit_id, digest)
            self._hit(f"before_{prefix}outbox_write")
            connection.execute(
                "INSERT INTO apcc_outbox(event_sequence,event_id,event_kind,operation_id,event_json,audit_event_id,trust_sequence,state,lease_token,lease_until_ms,delivered) "
                "VALUES (?, ?, 'COMMIT', ?, ?, ?, ?, 'PENDING', NULL, NULL, 0)",
                (
                    trust_sequence,
                    event,
                    request.commit_id,
                    payload,
                    audit,
                    trust_sequence,
                ),
            )
            self._hit(f"after_{prefix}outbox_write")
            self._hit(f"before_{prefix}commit")
            result = CommitResult(
                CommitDecision(request.commit_id, RequestOutcome.COMMITTED, "OK"),
                payload,
                envelope,
                digest,
                audit,
            )
            if supersede_old is None:
                self._run_projection(connection, request, result, projection_plan)
        if supersede_old is None:
            self._hit("after_commit_before_response")
        return result

    def _preflight(
        self,
        connection: _AuthorityConnection,
        request: AtomicCommitRequest,
        supersede_old: str | None,
        certificate: CommitCertificate,
    ) -> FailureCode | None:
        candidate = connection.execute(
            "SELECT lifecycle, expected_version, result, subject_json, context_json, predecessors_json, proposal_digest "
            "FROM candidates WHERE workflow_id=? AND node_id=? AND attempt_id=?",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        ).fetchone()
        if candidate is None:
            return FailureCode.CROSS_ATTEMPT_REPLAY
        if candidate[0] == CandidateLifecycle.EXECUTING.value and candidate[2] is None:
            return FailureCode.RESULT_NOT_STAGED
        node = connection.execute(
            "SELECT version, certificate_digest FROM logical_nodes WHERE workflow_id=? AND node_id=?",
            (request.subject.workflow_id, request.subject.node_id),
        ).fetchone()
        if node is None or str(node[0]) != request.bindings.expected_node_version:
            return FailureCode.NODE_VERSION_CONFLICT
        if candidate[0] == CandidateLifecycle.QUARANTINED.value:
            return FailureCode.QUARANTINED
        if candidate[0] == CandidateLifecycle.EXECUTING.value:
            return FailureCode.RESULT_NOT_STAGED
        if candidate[0] != CandidateLifecycle.COMMIT_PENDING.value:
            return FailureCode.AUTHORITY_FROM_STAGING_DENIED
        if supersede_old is None:
            if node[1] is not None:
                return FailureCode.ILLEGAL_NODE_STATE
        else:
            disposition = _latest_disposition(connection, supersede_old)
            if (
                node[1] != supersede_old
                or disposition is not CertificateDisposition.CURRENT
            ):
                return FailureCode.PREDECESSOR_REPLACED
        actor_generation = connection.execute(
            "SELECT generation FROM actor_revocations WHERE workflow_id=? AND actor_id=?",
            (request.subject.workflow_id, request.subject.agent_id),
        ).fetchone()
        if actor_generation is not None and _row_int(actor_generation[0]) > int(
            request.context.agent_revocation_generation
        ):
            return FailureCode.ACTOR_REVOKED
        workflow_generation = connection.execute(
            "SELECT generation FROM workflow_revocations WHERE workflow_id=?",
            (request.subject.workflow_id,),
        ).fetchone()
        if workflow_generation is not None and _row_int(workflow_generation[0]) > int(
            request.context.workflow_revocation_generation
        ):
            return FailureCode.WORKFLOW_REVOKED
        if not _candidate_matches(candidate, request, evidence_bound=True):
            return FailureCode.STAGED_RESULT_CONFLICT
        if candidate[6] != _proposal_identity(request):
            return FailureCode.STAGED_RESULT_CONFLICT
        if (
            predecessor_root(request.bindings.predecessors)
            != request.bindings.predecessor_root
        ):
            return FailureCode.PREDECESSOR_ROOT_MISMATCH
        causal_error = self._request_causal_error(connection, certificate)
        if causal_error is not None:
            return causal_error
        for predecessor in request.bindings.predecessors:
            row = connection.execute(
                "SELECT commit_id, workflow_id, node_id, certificate_json "
                "FROM certificates WHERE certificate_digest=?",
                (predecessor.certificate_digest,),
            ).fetchone()
            if row is None or tuple(row[:3]) != (
                predecessor.commit_id,
                predecessor.workflow_id,
                predecessor.node_id,
            ):
                return FailureCode.INVALID_PREDECESSOR
            try:
                payload = _row_bytes(row[3])
                certificate = decode_certificate(payload)
            except Exception:
                return FailureCode.INVALID_PREDECESSOR
            if (
                certificate.bindings.committed_node_version
                != predecessor.committed_node_version
                or certificate.subject.output_digest != predecessor.output_digest
            ):
                return FailureCode.INVALID_PREDECESSOR
            pointer = connection.execute(
                "SELECT certificate_digest FROM logical_nodes WHERE workflow_id=? AND node_id=?",
                (predecessor.workflow_id, predecessor.node_id),
            ).fetchone()
            disposition = _latest_disposition(
                connection, predecessor.certificate_digest
            )
            if (
                pointer is None
                or pointer[0] != predecessor.certificate_digest
                or disposition is not CertificateDisposition.CURRENT
            ):
                return FailureCode.PREDECESSOR_REPLACED
        return None

    def _static_error(self, request: AtomicCommitRequest) -> FailureCode | None:
        """Validate signed, request-local proof before consulting active store state."""
        try:
            return self._certificate_error(self._certificate(request, "1"))
        except ValueError as error:
            if str(error) == FailureCode.INVALID_DECIMAL_STRING.value:
                raise
            return FailureCode.TRANSACTION_ABORTED
        except Exception:
            return FailureCode.TRANSACTION_ABORTED

    def _certificate_error(self, certificate: CommitCertificate) -> FailureCode | None:
        evidence_error = _evidence(certificate, _trust(self._config))
        if evidence_error is not None:
            return evidence_error
        return _bindings(certificate)

    def _certificate(
        self, request: AtomicCommitRequest, sequence: str
    ) -> CommitCertificate:
        now = str(_trusted_now(self._runtime.clock))
        return CommitCertificate(
            CertificateHeader(
                "APCC-1.0-draft",
                "apcc.commit-certificate",
                "APCC-CJ1",
                "SHA-256",
                "Ed25519",
                self.authority_store_id,
                self._config.commit_trust.key_id,
                sequence,
            ),
            request.subject,
            request.context,
            request.evidence,
            CertificateDecision(
                "committed", "OK", request.commit_id, request.nonce, now
            ),
            request.bindings,
            request.signatures,
        )

    def _seal(self, certificate: CommitCertificate) -> tuple[bytes, bytes, str]:
        payload = encode_certificate(certificate)
        seal = self._runtime.key_provider.sign(
            AuthoritySigningRole.COMMIT,
            self._config.commit_trust.key_id,
            COMMIT_DOMAIN,
            payload,
        )
        envelope = encode_envelope(
            payload, seal_key_id=seal.key_id, seal_signature_b64u=seal.signature_b64u
        )
        verdict = verify_historical(envelope, trust=_trust(self._config))
        if not verdict.ok:
            code = verdict.code or FailureCode.TRANSACTION_ABORTED
            raise ValueError(code.value)
        return payload, envelope, sha256_digest(payload)

    def _negative(
        self,
        connection: _AuthorityConnection,
        request: AtomicCommitRequest,
        reason: FailureCode,
        supersede_old: str | None = None,
    ) -> CommitResult:
        request_digest = _operation_identity(request, supersede_old)
        outcome = (
            RequestOutcome.CONFLICTED
            if reason is FailureCode.NODE_VERSION_CONFLICT
            else RequestOutcome.DENIED
        )
        audit = _audit_id(
            outcome.value, request.commit_id, request_digest, reason.value
        )
        connection.execute(
            "INSERT INTO commit_index VALUES (?, ?, ?, ?)",
            (
                request.commit_id,
                request_digest,
                request.subject.workflow_id,
                _operation_request_json(request, supersede_old),
            ),
        )
        connection.execute(
            "INSERT INTO request_index VALUES (?, ?)",
            (_public_request_digest(request), request.commit_id),
        )
        owner = connection.execute(
            "SELECT commit_id FROM nonce_ledger WHERE nonce=?", (request.nonce,)
        ).fetchone()
        if reason is FailureCode.NONCE_REPLAY:
            if owner is None:
                raise ValueError("APCC nonce replay has no durable owner")
            nonce_owner = str(owner[0])
        else:
            if owner is not None:
                raise ValueError("APCC nonce already has a durable owner")
            connection.execute(
                "INSERT INTO nonce_ledger VALUES (?, ?)",
                (request.nonce, request.commit_id),
            )
            nonce_owner = request.commit_id
        _write_audit(
            connection,
            audit,
            reason.value,
            request.commit_id,
            **({"old_certificate_digest": supersede_old} if supersede_old else {}),
        )
        connection.execute(
            "INSERT INTO apcc_decisions VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                request.commit_id,
                outcome.value,
                reason.value,
                audit,
                None,
                request.nonce,
                nonce_owner,
            ),
        )
        return CommitResult(
            CommitDecision(request.commit_id, outcome, reason), None, None, None, audit
        )

    def _conflict(
        self,
        connection: _AuthorityConnection,
        commit_id: str,
        digest: str,
        public_request_digest: str,
        conflicting_workflow_id: str,
        conflicting_node_id: str,
        conflicting_attempt_id: str,
        conflict_claim_json: str,
        supersede_old: str | None = None,
    ) -> CommitResult:
        audit = _audit_id("conflict", commit_id, digest)
        original = connection.execute(
            "SELECT request_digest,workflow_id,request_json FROM commit_index "
            "WHERE commit_id=?",
            (commit_id,),
        ).fetchone()
        if original is None:
            raise ValueError("APCC conflict lacks an original operation")
        original_request, _original_old = _operation_from_json(_row_text(original[2]))
        original_public = connection.execute(
            "SELECT request_digest FROM request_index WHERE commit_id=?", (commit_id,)
        ).fetchone()
        if original_public is None:
            raise ValueError("APCC conflict lacks an original public request")
        if not conflicting_workflow_id:
            conflicting_workflow_id = original_request.subject.workflow_id
            conflicting_node_id = original_request.subject.node_id
            conflicting_attempt_id = original_request.subject.attempt_id
        identity = (
            commit_id,
            conflicting_workflow_id,
            conflicting_node_id,
            conflicting_attempt_id,
            digest,
            public_request_digest,
        )
        existing = connection.execute(
            "SELECT audit_event_id FROM commit_conflicts WHERE commit_id=? AND "
            "conflicting_workflow_id=? AND conflicting_node_id=? AND "
            "conflicting_attempt_id=? AND conflicting_request_digest=? AND "
            "conflicting_public_request_digest=?",
            identity,
        ).fetchone()
        if existing is not None:
            return CommitResult(
                CommitDecision(
                    commit_id,
                    RequestOutcome.CONFLICTED,
                    FailureCode.COMMIT_ID_EQUIVOCATION,
                ),
                None,
                None,
                None,
                _row_text(existing[0]),
            )
        sequence = connection.execute(
            "SELECT COUNT(*) FROM commit_conflicts WHERE commit_id=?", (commit_id,)
        ).fetchone()
        connection.execute(
            "INSERT INTO commit_conflicts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                commit_id,
                _row_text(original[0]),
                _row_text(original_public[0]),
                original_request.subject.workflow_id,
                original_request.subject.node_id,
                original_request.subject.attempt_id,
                digest,
                public_request_digest,
                conflicting_workflow_id,
                conflicting_node_id,
                conflicting_attempt_id,
                _row_int(sequence[0]) + 1 if sequence else 1,
                audit,
                conflict_claim_json,
            ),
        )
        _write_audit(
            connection,
            audit,
            FailureCode.COMMIT_ID_EQUIVOCATION.value,
            commit_id,
            **({"old_certificate_digest": supersede_old} if supersede_old else {}),
        )
        return CommitResult(
            CommitDecision(
                commit_id, RequestOutcome.CONFLICTED, FailureCode.COMMIT_ID_EQUIVOCATION
            ),
            None,
            None,
            None,
            audit,
        )

    def supersede(self, request: SupersessionRequest) -> SupersessionResult:
        request_digest = _operation_identity(
            request.new_proposal, request.old_certificate_digest
        )
        connection = self._connection()
        try:
            existing = connection.execute(
                "SELECT 1 FROM commit_index WHERE commit_id=? AND request_digest=?",
                (request.new_proposal.commit_id, request_digest),
            ).fetchone()
            if existing is not None:
                return _supersession_replay(
                    connection, request.new_proposal.commit_id, request_digest
                )
        finally:
            connection.close()
        self._commit(request.new_proposal, supersede_old=request.old_certificate_digest)
        connection = self._connection()
        try:
            replay = _supersession_replay(
                connection, request.new_proposal.commit_id, request_digest
            )
        finally:
            connection.close()
        self._hit("after_supersession_commit_before_response")
        return replay

    def revoke(self, request: RevocationRequest) -> RevocationResult:
        with self._transaction() as connection:
            return self._revoke_on_connection(connection, request)

    def _revoke_on_connection(
        self, connection: _AuthorityConnection, request: RevocationRequest
    ) -> RevocationResult:
        """Apply a typed revocation within an existing authority transaction."""
        generation = None
        if request.scope is not RevocationScope.CERTIFICATE:
            generation = str(
                _canonical_positive_decimal(
                    request.next_generation, maximum=_MAX_SAFE_INTEGER
                )
            )
        audit = _audit_id(
            "revoke",
            request.scope.value,
            request.workflow_id,
            request.target_id,
            request.next_generation,
        )
        if connection.execute(
            "SELECT 1 FROM audit_events WHERE audit_event_id=?", (audit,)
        ).fetchone():
            return RevocationResult(
                request.scope, request.target_id, request.next_generation, audit
            )
        self._hit("before_revocation_fence")
        if request.scope is RevocationScope.CERTIFICATE:
            disposition = _latest_disposition(connection, request.target_id)
            if disposition is not CertificateDisposition.CURRENT:
                raise ValueError("certificate revocation target is not current")
            self._hit("before_revocation_disposition_write")
            connection.execute(
                "INSERT INTO certificate_dispositions VALUES (?, 2, ?)",
                (request.target_id, CertificateDisposition.REVOKED.value),
            )
            self._hit("after_revocation_disposition_write")
        elif request.scope is RevocationScope.ACTOR:
            existing = connection.execute(
                "SELECT generation FROM actor_revocations WHERE workflow_id=? AND actor_id=?",
                (request.workflow_id, request.target_id),
            ).fetchone()
            prior_generation = _row_int(existing[0]) if existing is not None else 0
            assert generation is not None
            if int(generation) <= prior_generation:
                raise ValueError("revocation generation must increase")
            self._hit("before_revocation_generation_write")
            connection.execute(
                "INSERT OR REPLACE INTO actor_revocations(workflow_id, actor_id, generation) VALUES (?, ?, ?)",
                (request.workflow_id, request.target_id, generation),
            )
            self._hit("after_revocation_generation_write")
        else:
            existing = connection.execute(
                "SELECT generation FROM workflow_revocations WHERE workflow_id=?",
                (request.workflow_id,),
            ).fetchone()
            prior_generation = _row_int(existing[0]) if existing is not None else 0
            assert generation is not None
            if int(generation) <= prior_generation:
                raise ValueError("revocation generation must increase")
            self._hit("before_revocation_generation_write")
            connection.execute(
                "INSERT OR REPLACE INTO workflow_revocations VALUES (?, ?)",
                (request.workflow_id, generation),
            )
            self._hit("after_revocation_generation_write")
        self._hit("after_revocation_fence")
        self._hit("before_revocation_audit_write")
        control_object = {
            "scope": request.scope.value,
            "workflow_id": request.workflow_id,
            "target_id": request.target_id,
            "generation": generation,
            "claimed_generation": request.next_generation,
            "reason": request.reason,
            "audit_event_id": audit,
        }
        control_payload = _json(control_object).encode("utf-8")
        control_digest = sha256_digest(control_payload)
        _write_audit(
            connection,
            audit,
            "revoked",
            request.target_id,
            scope=request.scope.value,
            workflow_id=request.workflow_id,
            **({"generation": generation} if generation is not None else {}),
        )
        connection.execute(
            "INSERT INTO control_events(operation_id,scope,workflow_id,target_id,generation,claimed_generation,reason,audit_event_id,payload,payload_digest) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                audit,
                request.scope.value,
                request.workflow_id,
                request.target_id,
                generation,
                request.next_generation,
                request.reason,
                audit,
                control_payload,
                control_digest,
            ),
        )
        self._hit("after_revocation_audit_write")
        self._hit("before_revocation_trust_log_write")
        trust_sequence, _trust_head = self._append_trust(
            connection, "control", audit, audit
        )
        self._hit("after_revocation_trust_log_write")
        self._hit("before_revocation_outbox_write")
        event_id = _audit_id("outbox", "CONTROL", audit, control_digest)
        connection.execute(
            "INSERT INTO apcc_outbox(event_sequence,event_id,event_kind,operation_id,event_json,audit_event_id,trust_sequence,state,lease_token,lease_until_ms,delivered) "
            "VALUES (?, ?, 'CONTROL', ?, ?, ?, ?, 'PENDING', NULL, NULL, 0)",
            (
                trust_sequence,
                event_id,
                audit,
                control_payload,
                audit,
                trust_sequence,
            ),
        )
        self._hit("after_revocation_outbox_write")
        self._hit("before_revocation_commit")
        return RevocationResult(
            request.scope, request.target_id, request.next_generation, audit
        )

    @staticmethod
    def _validated_status_requests(
        requests: Sequence[CurrentStatusRequest],
    ) -> tuple[CurrentStatusRequest, ...]:
        resolved = tuple(requests)
        if len(resolved) > _MAX_STATUS_BATCH_SIZE:
            raise ValueError(FailureCode.SIZE_LIMIT_EXCEEDED.value)
        if any(type(request) is not CurrentStatusRequest for request in resolved):
            raise ValueError("invalid current-status batch request")
        nonces = tuple(request.request_nonce for request in resolved)
        if len(set(nonces)) != len(nonces):
            raise ValueError("duplicate request_nonce in status batch")
        return resolved

    @staticmethod
    def _validated_logical_status_requests(
        requests: Sequence[LogicalNodeStatusRequest],
    ) -> tuple[LogicalNodeStatusRequest, ...]:
        resolved = tuple(requests)
        if len(resolved) > _MAX_STATUS_BATCH_SIZE:
            raise ValueError(FailureCode.SIZE_LIMIT_EXCEEDED.value)
        if any(type(request) is not LogicalNodeStatusRequest for request in resolved):
            raise ValueError("invalid logical-node status batch request")
        nonces = tuple(request.request_nonce for request in resolved)
        if len(set(nonces)) != len(nonces):
            raise ValueError("duplicate request_nonce in logical-node status batch")
        return resolved

    def _attest_batch_snapshot(
        self,
        connection: _AuthorityConnection,
        certificate_digests: Sequence[str] = (),
    ) -> _SemanticSnapshot:
        del certificate_digests
        return _validate_semantic_integrity(connection, self._config)

    @staticmethod
    def _trust_head(connection: _AuthorityConnection) -> tuple[str, str]:
        latest = connection.execute(
            "SELECT sequence, entry_digest FROM trust_log ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest is None:
            return "0", sha256_digest(b"APCC-1/trust-log/genesis")
        return str(latest[0]), _row_text(latest[1])

    def _current_status_at(
        self,
        connection: _AuthorityConnection,
        request: CurrentStatusRequest,
        trust_head: tuple[str, str],
        semantic_snapshot: _SemanticSnapshot,
        causal_cache: dict[str, _CausalBatchFacts],
        generation_cache: dict[str, bool],
    ) -> tuple[AuthorityStatus, str]:
        certificate = semantic_snapshot.certificates.get(request.certificate_digest)
        if certificate is None:
            raise ValueError("unknown APCC certificate")
        disposition = semantic_snapshot.dispositions.get(request.certificate_digest)
        if disposition is None:
            raise ValueError("APCC certificate has no disposition")
        status_value = AuthorityStatusValue.CURRENT
        superseded = (
            SupersessionValue.YES
            if disposition is CertificateDisposition.SUPERSEDED
            else SupersessionValue.NO
        )
        if disposition is CertificateDisposition.REVOKED:
            status_value = AuthorityStatusValue.REVOKED
        facts = self._causal_batch_facts(
            request.certificate_digest, semantic_snapshot, causal_cache, set()
        )
        if facts.error is not None or any(
            semantic_snapshot.dispositions.get(digest) is CertificateDisposition.REVOKED
            or self._later_generation_revoked(
                connection, digest, semantic_snapshot, generation_cache
            )
            for digest in facts.closure
        ):
            status_value = AuthorityStatusValue.REVOKED
        actor_generation = certificate.context.agent_revocation_generation
        workflow_generation = certificate.context.workflow_revocation_generation
        seq, head = trust_head
        now_value = _trusted_now(self._runtime.clock)
        lifetime = int(self._config.freshness.issued_status_lifetime_ms)
        if now_value > _MAX_SAFE_INTEGER - lifetime:
            raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
        unsigned = AuthorityStatus(
            "APCC-1.0-draft",
            "apcc.authority-status",
            self.authority_store_id,
            self._config.status_trust.key_id,
            request.request_nonce,
            request.certificate_digest,
            certificate.header.certificate_sequence,
            seq,
            head,
            status_value,
            actor_generation,
            workflow_generation,
            superseded,
            str(now_value),
            str(now_value + lifetime),
            Signature(
                "Ed25519", self._config.status_trust.key_id, b64u_encode(bytes(64))
            ),
        )
        body = encode_authority_status_body(unsigned)
        signature = self._runtime.key_provider.sign(
            AuthoritySigningRole.STATUS,
            self._config.status_trust.key_id,
            AUTHORITY_STATUS_DOMAIN,
            body,
        )
        if signature.key_id != self._config.status_trust.key_id:
            raise ValueError(FailureCode.KEY_ID_MISMATCH.value)
        try:
            b64u_decode(signature.signature_b64u, expected_length=64)
        except ValueError as error:
            raise ValueError(FailureCode.INVALID_BASE64URL.value) from error
        if signature.algorithm != "Ed25519" or not verify_detached(
            self._config.status_trust.public_key,
            AUTHORITY_STATUS_DOMAIN,
            body,
            signature.signature_b64u,
        ):
            raise ValueError(FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE.value)
        return replace(unsigned, signature=signature), certificate.decision.commit_id

    def _later_generation_revoked(
        self,
        connection: _AuthorityConnection,
        digest: str,
        semantic_snapshot: _SemanticSnapshot,
        cache: dict[str, bool],
    ) -> bool:
        cached = cache.get(digest)
        if cached is not None:
            return cached
        certificate = semantic_snapshot.certificates.get(digest)
        if certificate is None:
            return True
        revoked = _has_later_generation_revocation(connection, certificate)
        cache[digest] = revoked
        return revoked

    def _causal_batch_facts(
        self,
        digest: str,
        semantic_snapshot: _SemanticSnapshot,
        cache: dict[str, _CausalBatchFacts],
        active: set[str],
    ) -> _CausalBatchFacts:
        cached = cache.get(digest)
        if cached is not None:
            return cached
        certificate = semantic_snapshot.certificates.get(digest)
        if certificate is None or digest in active:
            return _CausalBatchFacts(
                frozenset((digest,)), 0, FailureCode.INVALID_PREDECESSOR
            )
        active.add(digest)
        closure = {digest}
        depth = 0
        error: FailureCode | None = None
        for reference in certificate.bindings.predecessors:
            predecessor = semantic_snapshot.certificates.get(
                reference.certificate_digest
            )
            if predecessor is None or (
                predecessor.subject.workflow_id,
                predecessor.subject.node_id,
                predecessor.bindings.committed_node_version,
                predecessor.decision.commit_id,
                reference.certificate_digest,
                predecessor.subject.output_digest,
            ) != (
                reference.workflow_id,
                reference.node_id,
                reference.committed_node_version,
                reference.commit_id,
                reference.certificate_digest,
                reference.output_digest,
            ):
                error = FailureCode.INVALID_PREDECESSOR
                break
            child = self._causal_batch_facts(
                reference.certificate_digest, semantic_snapshot, cache, active
            )
            if child.error is not None:
                error = child.error
                break
            closure.update(child.closure)
            depth = max(depth, child.depth + 1)
        active.remove(digest)
        limits = CausalClosureLimits()
        if error is None and depth > limits.max_depth:
            error = FailureCode.DEPTH_LIMIT_EXCEEDED
        if error is None and (
            len(closure) > limits.max_certificates
            or sum(
                semantic_snapshot.envelope_sizes.get(item, limits.max_total_bytes + 1)
                for item in closure
            )
            > limits.max_total_bytes
        ):
            error = FailureCode.SIZE_LIMIT_EXCEEDED
        facts = _CausalBatchFacts(frozenset(closure), depth, error)
        cache[digest] = facts
        return facts

    def current_status_batch(
        self, requests: Sequence[CurrentStatusRequest]
    ) -> tuple[CurrentStatusResult, ...]:
        resolved = self._validated_status_requests(requests)
        if not resolved:
            return ()
        with self._read_transaction() as connection:
            semantic_snapshot = self._attest_batch_snapshot(
                connection,
                tuple(request.certificate_digest for request in resolved),
            )
            trust_head = self._trust_head(connection)
            causal_cache: dict[str, _CausalBatchFacts] = {}
            generation_cache: dict[str, bool] = {}
            return tuple(
                CurrentStatusResult(
                    request,
                    self._current_status_at(
                        connection,
                        request,
                        trust_head,
                        semantic_snapshot,
                        causal_cache,
                        generation_cache,
                    )[0],
                )
                for request in resolved
            )

    def current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus:
        request = CurrentStatusRequest(certificate_digest, request_nonce)
        return self.current_status_batch((request,))[0].status

    def logical_node_status_batch(
        self, requests: Sequence[LogicalNodeStatusRequest]
    ) -> tuple[LogicalNodeStatusResult, ...]:
        resolved = self._validated_logical_status_requests(requests)
        if not resolved:
            return ()
        with self._read_transaction() as connection:
            return self._logical_node_status_batch_at(connection, resolved)

    def _logical_node_status_batch_at(
        self,
        connection: _AuthorityConnection,
        requests: tuple[LogicalNodeStatusRequest, ...],
        semantic_snapshot: _SemanticSnapshot | None = None,
    ) -> tuple[LogicalNodeStatusResult, ...]:
        keys = tuple(
            dict.fromkeys(
                (request.workflow_id, request.node_id) for request in requests
            )
        )
        placeholders = ",".join("(?,?)" for _ in keys)
        parameters = tuple(value for key in keys for value in key)
        rows = connection.execute(
            "SELECT workflow_id,node_id,version,certificate_digest "
            "FROM logical_nodes WHERE (workflow_id,node_id) IN "
            f"(VALUES {placeholders})",
            parameters,
        ).fetchall()
        persisted = {
            (_row_text(row[0]), _row_text(row[1])): (
                _row_text(row[2]),
                _row_optional_text(row[3]),
            )
            for row in rows
        }
        logical_nodes = [
            LogicalNodeState(
                request.workflow_id,
                request.node_id,
                *persisted.get((request.workflow_id, request.node_id), ("0", None)),
            )
            for request in requests
        ]
        if semantic_snapshot is None:
            semantic_snapshot = self._attest_batch_snapshot(
                connection,
                tuple(
                    logical.current_certificate_digest
                    for logical in logical_nodes
                    if logical.current_certificate_digest is not None
                ),
            )
        trust_head = self._trust_head(connection)
        causal_cache: dict[str, _CausalBatchFacts] = {}
        generation_cache: dict[str, bool] = {}
        results: list[LogicalNodeStatusResult] = []
        for request, logical in zip(requests, logical_nodes, strict=True):
            if logical.current_certificate_digest is None:
                results.append(LogicalNodeStatusResult(request, logical, None, None))
                continue
            status, commit_id = self._current_status_at(
                connection,
                CurrentStatusRequest(
                    logical.current_certificate_digest, request.request_nonce
                ),
                trust_head,
                semantic_snapshot,
                causal_cache,
                generation_cache,
            )
            results.append(LogicalNodeStatusResult(request, logical, commit_id, status))
        return tuple(results)

    def _request_causal_error(
        self, connection: _AuthorityConnection, root: CommitCertificate
    ) -> FailureCode | None:
        limits = CausalClosureLimits()
        root_payload = encode_certificate(root)
        root_envelope = encode_envelope(
            root_payload,
            seal_key_id=self._config.commit_trust.key_id,
            seal_signature_b64u=b64u_encode(bytes(64)),
        )
        if len(root_envelope) > limits.max_total_bytes:
            return FailureCode.SIZE_LIMIT_EXCEEDED
        resolver = _AuthorityPredecessorResolver(connection)
        cache: dict[str, CommitCertificate] = {}
        active: set[str] = {sha256_digest(root_payload)}
        complete: set[str] = set()
        total_bytes = len(root_envelope)

        def visit(certificate: CommitCertificate, depth: int) -> FailureCode | None:
            nonlocal total_bytes
            for reference in certificate.bindings.predecessors:
                digest = reference.certificate_digest
                if depth + 1 > limits.max_depth:
                    return FailureCode.DEPTH_LIMIT_EXCEEDED
                if digest in active:
                    return FailureCode.INVALID_PREDECESSOR
                resolved = cache.get(digest)
                if resolved is None:
                    if len(cache) + 1 >= limits.max_certificates:
                        return FailureCode.SIZE_LIMIT_EXCEEDED
                    envelope = resolver.resolve_predecessor(digest)
                    if envelope is None:
                        return FailureCode.INVALID_PREDECESSOR
                    if total_bytes + len(envelope) > limits.max_total_bytes:
                        return FailureCode.SIZE_LIMIT_EXCEEDED
                    historical = verify_historical(envelope, trust=_trust(self._config))
                    if not historical.ok or historical.certificate is None:
                        return FailureCode.INVALID_PREDECESSOR
                    resolved = historical.certificate
                    cache[digest] = resolved
                    total_bytes += len(envelope)
                if (
                    resolved.subject.workflow_id,
                    resolved.subject.node_id,
                    resolved.bindings.committed_node_version,
                    resolved.decision.commit_id,
                    digest,
                    resolved.subject.output_digest,
                ) != (
                    reference.workflow_id,
                    reference.node_id,
                    reference.committed_node_version,
                    reference.commit_id,
                    reference.certificate_digest,
                    reference.output_digest,
                ):
                    return FailureCode.INVALID_PREDECESSOR
                if digest in complete:
                    continue
                active.add(digest)
                error = visit(resolved, depth + 1)
                active.remove(digest)
                if error is not None:
                    return error
                complete.add(digest)
            return None

        try:
            error = visit(root, 0)
        except Exception:
            return FailureCode.INVALID_PREDECESSOR
        if error is not None:
            return error
        for digest, certificate in cache.items():
            disposition = _latest_disposition(connection, digest)
            if disposition is None or disposition is CertificateDisposition.REVOKED:
                return FailureCode.INVALID_PREDECESSOR
            if _has_later_generation_revocation(connection, certificate):
                return FailureCode.INVALID_PREDECESSOR
        return None

    def _persisted_causal_error(
        self, connection: _AuthorityConnection, digest: str
    ) -> FailureCode | None:
        resolver = _AuthorityPredecessorResolver(connection)
        root_envelope = resolver.resolve_predecessor(digest)
        if root_envelope is None:
            return FailureCode.INVALID_PREDECESSOR
        closure = verify_causal_closure(
            root_envelope,
            trust=_trust(self._config),
            resolver=resolver,
        )
        if not closure.ok:
            if closure.code in {
                FailureCode.DEPTH_LIMIT_EXCEEDED,
                FailureCode.SIZE_LIMIT_EXCEEDED,
            }:
                return closure.code
            return FailureCode.INVALID_PREDECESSOR

        pending = [digest]
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            state = _latest_disposition(connection, current)
            if state is None or state is CertificateDisposition.REVOKED:
                return FailureCode.INVALID_PREDECESSOR
            envelope = resolver.resolve_predecessor(current)
            if envelope is None:
                return FailureCode.INVALID_PREDECESSOR
            try:
                detached = decode_envelope(envelope)
                certificate = decode_certificate(detached.payload)
            except Exception:
                return FailureCode.INVALID_PREDECESSOR
            if _has_later_generation_revocation(connection, certificate):
                return FailureCode.INVALID_PREDECESSOR
            pending.extend(
                predecessor.certificate_digest
                for predecessor in certificate.bindings.predecessors
            )
        return None

    def recover(self, request: RecoveryRequest) -> CommitResult:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT request_digest FROM commit_index WHERE commit_id=?",
                (request.commit_id,),
            ).fetchone()
            if row is None:
                audit = _audit_id(
                    "recovery-missing", request.commit_id, request.request_digest
                )
                return CommitResult(
                    CommitDecision(
                        request.commit_id,
                        RequestOutcome.DENIED,
                        FailureCode.AUTHORITY_FROM_RECOVERY_DENIED,
                    ),
                    None,
                    None,
                    None,
                    audit,
                )
            public_replay = connection.execute(
                "SELECT 1 FROM request_index WHERE request_digest=? AND commit_id=?",
                (request.request_digest, request.commit_id),
            ).fetchone()
            if row[0] != request.request_digest and public_replay is None:
                return self._conflict(
                    connection,
                    request.commit_id,
                    request.request_digest,
                    request.request_digest,
                    "",
                    "",
                    "",
                    _json(
                        {
                            "kind": "recovery",
                            "commit_id": request.commit_id,
                            "request_digest": request.request_digest,
                        }
                    ),
                )
            return _replay(connection, request.commit_id, request.request_digest)

    def recover_outbox(self, request: OutboxRecoveryRequest) -> OutboxRecoveryResult:
        del request
        raise NotImplementedError

    def _next_sequence(self, connection: _AuthorityConnection) -> str:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM certificates"
        ).fetchone()
        if row is None:
            raise ValueError("APCC authority sequence query returned no row")
        sequence = _row_int(row[0]) + 1
        if sequence > _MAX_SAFE_INTEGER:
            raise ValueError(FailureCode.SIZE_LIMIT_EXCEEDED.value)
        return str(sequence)

    def _append_trust(
        self,
        connection: _AuthorityConnection,
        kind: str,
        subject: str,
        audit_event_id: str,
    ) -> tuple[str, str]:
        previous = connection.execute(
            "SELECT sequence, entry_digest FROM trust_log ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = _row_int(previous[0]) + 1 if previous else 1
        prior = (
            _row_text(previous[1])
            if previous
            else sha256_digest(b"APCC-1/trust-log/genesis")
        )
        entry_json = _json(
            {
                "sequence": str(sequence),
                "prior_digest": prior,
                "kind": kind,
                "subject": subject,
                "audit_event_id": audit_event_id,
            }
        )
        head = sha256_digest(entry_json.encode("utf-8"))
        connection.execute(
            "INSERT INTO trust_log(sequence,audit_event_id,prior_digest,entry_digest,entry_json) VALUES (?, ?, ?, ?, ?)",
            (sequence, audit_event_id, prior, head, entry_json),
        )
        return str(sequence), head


class SQLiteAuthorityStore(_AuthorityStoreCore):
    """Single-writer, ``BEGIN IMMEDIATE`` SQLite APCC authority store."""

    def __init__(
        self,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
    ) -> None:
        _AuthorityStoreCore.__init__(self, config, runtime)
        self.database_path = Path(path)
        self.authority_store_id = config.authority_store_id
        self._probe: _FaultProbe | None = None
        self._gcb_attached = False
        self._gcb_projection_fault: _GCBProjectionCheckpoint | None = None
        self._gcb_projection_fault_fired = False
        self._attested_read_connections: set[sqlite3.Connection] = set()
        raise ValueError("use SQLiteAuthorityStore.open on a provisioned store")

    @classmethod
    def provision(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[CommitContext, ...],
        runtime: AuthorityRuntime,
    ) -> None:
        path = Path(path)
        _validate_runtime_signers(config, runtime)
        if path.exists():
            connection = _connect_reader(path)
            try:
                if connection.execute("PRAGMA application_id").fetchone() == (
                    _APPLICATION_ID,
                ):
                    existing = connection.execute(
                        "SELECT value FROM metadata WHERE key='config'"
                    ).fetchone()
                    if existing is not None and existing[0] != _json(
                        _config_object(config)
                    ):
                        raise ValueError("APCC SQLite configuration is immutable")
                    raise ValueError("APCC SQLite store is already provisioned")
                raise ValueError("APCC SQLite store schema validation failed")
            finally:
                connection.close()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.apcc-tmp")
        try:
            connection = _connect_create(temporary)
            try:
                connection.execute("BEGIN IMMEDIATE")
                _schema(connection)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('config', ?)",
                    (_json(_config_object(config)),),
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_fingerprint', ?)",
                    (_SCHEMA_FINGERPRINT,),
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                    (_AUTHORITY_SCHEMA_VERSION,),
                )
                for context in initial_contexts:
                    _insert_context(connection, context)
                connection.execute(
                    "INSERT INTO semantic_checkpoint(singleton,change_sequence,"
                    "prior_digest,checkpoint_digest,key_id,signature) "
                    "VALUES (1,0,?,'',?,'')",
                    (_SEMANTIC_CHECKPOINT_GENESIS, config.commit_trust.key_id),
                )
                for statement in _SEMANTIC_CHECKPOINT_TRIGGERS:
                    connection.execute(statement)
                config_text = _validate_schema_manifest(
                    connection, storage_checks=False
                )
                if config_text != _json(_config_object(config)):
                    raise ValueError(
                        "APCC authority configuration does not match provisioned store"
                    )
                _validate_semantic_integrity(connection, config)
                sealed = _verify_semantic_checkpoint(
                    connection,
                    config,
                    _SCHEMA_FINGERPRINT,
                    allow_initial_unsealed=True,
                )
                if sealed:
                    raise ValueError(
                        "APCC authority bootstrap checkpoint was already sealed"
                    )
                _seal_semantic_checkpoint(
                    connection, config, runtime, _SCHEMA_FINGERPRINT
                )
                _verify_semantic_checkpoint(connection, config, _SCHEMA_FINGERPRINT)
                connection.commit()
                _validate_schema(connection)
                checkpoint = connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if checkpoint != (0, 0, 0):
                    raise ValueError("APCC SQLite WAL checkpoint is incomplete")
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            if Path(f"{temporary}-wal").exists() or Path(f"{temporary}-shm").exists():
                raise ValueError("APCC SQLite WAL checkpoint left sidecar state")
            validation = _connect_reader(temporary)
            try:
                _validate_schema(validation)
            finally:
                validation.close()
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            attempted_inode = temporary.stat()
            os.link(temporary, path)
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except Exception:
                try:
                    published_inode = path.stat()
                    if (
                        published_inode.st_dev == attempted_inode.st_dev
                        and published_inode.st_ino == attempted_inode.st_ino
                    ):
                        path.unlink()
                        retry_fd = os.open(path.parent, os.O_RDONLY)
                        try:
                            os.fsync(retry_fd)
                        except Exception:
                            pass
                        finally:
                            os.close(retry_fd)
                except FileNotFoundError:
                    pass
                raise
        finally:
            for created in (
                temporary,
                Path(f"{temporary}-wal"),
                Path(f"{temporary}-shm"),
            ):
                try:
                    created.unlink()
                except FileNotFoundError:
                    pass

    @classmethod
    def open(
        cls, path: Path, config: APCCAuthorityConfig, runtime: AuthorityRuntime
    ) -> SQLiteAuthorityStore:
        return cls._open(path, config, runtime, None, gcb_attached=False)

    @classmethod
    def _open_with_probe(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: _FaultProbe,
    ) -> SQLiteAuthorityStore:
        return cls._open(path, config, runtime, probe, gcb_attached=False)

    @classmethod
    def _open_gcb(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        *,
        projection_fault: _GCBProjectionCheckpoint | None = None,
    ) -> SQLiteAuthorityStore:
        if projection_fault is not None and not isinstance(
            projection_fault, _GCBProjectionCheckpoint
        ):
            raise TypeError("GCB projection fault must be a fixed checkpoint")
        return cls._open(
            path,
            config,
            runtime,
            None,
            gcb_attached=True,
            projection_fault=projection_fault,
        )

    @classmethod
    def _open(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: _FaultProbe | None,
        *,
        gcb_attached: bool,
        projection_fault: _GCBProjectionCheckpoint | None = None,
    ) -> SQLiteAuthorityStore:
        reader = SQLiteAuthorityReader.open(path)
        connection = _connect(path)
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='config'"
            ).fetchone()
            if row is None or row[0] != _json(_config_object(config)):
                raise ValueError(
                    "APCC SQLite configuration does not match provisioned store"
                )
            gcb_tables = {
                str(item[0])
                for item in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            required_gcb_tables = {
                "agents",
                "decisions",
                "nodes",
                "outbox",
                "receipt_evidence",
                "staged_artifacts",
                "store_seal",
                "workflows",
            }
            has_gcb_marker = required_gcb_tables.issubset(gcb_tables)
            if gcb_attached and not required_gcb_tables.issubset(gcb_tables):
                raise ValueError("GCB projection schema is incomplete")
            if not gcb_attached and has_gcb_marker:
                raise ValueError(
                    "GCB-attached APCC store requires typed governance bootstrap"
                )
        finally:
            connection.close()
        if reader.authority_store_id != config.authority_store_id:
            raise ValueError("APCC authority store identity mismatch")
        _validate_runtime_signers(config, runtime)
        store = object.__new__(cls)
        _AuthorityStoreCore.__init__(store, config, runtime)
        store.database_path = Path(path)
        store.authority_store_id = config.authority_store_id
        store._probe = probe
        store._gcb_attached = gcb_attached
        store._gcb_projection_fault = projection_fault
        store._gcb_projection_fault_fired = False
        store._attested_read_connections = set()
        store._ensure_semantic_checkpoint()
        return store

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult:
        if self._gcb_attached:
            if type(request) is not _GCBAtomicCommitRequest:
                raise _GCBProjectionDenied("unprojected_gcb_commit_denied")
            return self._commit(
                request,
                supersede_old=None,
                projection_plan=request._gcb_projection_plan,
            )
        if type(request) is _GCBAtomicCommitRequest:
            raise _GCBProjectionDenied("gcb_projection_requires_attached_store")
        return self._commit(request, supersede_old=None, projection_plan=None)

    def _connection(self) -> sqlite3.Connection:
        return _connect_reader(self.database_path)

    def _observation_current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus:
        """Issue status under a dedicated guard without mutating the checkpoint."""
        request = CurrentStatusRequest(certificate_digest, request_nonce)
        connection = _connect(self.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_mutation_checkpoint(connection)
            self._attested_read_connections.add(connection)
            semantic_snapshot = self._attest_batch_snapshot(
                connection, (certificate_digest,)
            )
            status, _commit_id = self._current_status_at(
                connection,
                request,
                self._trust_head(connection),
                semantic_snapshot,
                {},
                {},
            )
            connection.commit()
            return status
        except Exception:
            connection.rollback()
            raise
        finally:
            self._attested_read_connections.discard(connection)
            connection.close()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            _attest_sqlite_read_connection(connection, self._config)
            self._attested_read_connections.add(connection)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._attested_read_connections.discard(connection)
            connection.close()

    def _attest_batch_snapshot(
        self,
        connection: _AuthorityConnection,
        certificate_digests: Sequence[str] = (),
    ) -> _SemanticSnapshot:
        if (
            not isinstance(connection, sqlite3.Connection)
            or connection not in self._attested_read_connections
        ):
            raise ValueError("APCC SQLite batch snapshot was not attested")
        return _checkpoint_semantic_snapshot(connection, certificate_digests)

    def _hit(self, point: str) -> None:
        if self._probe is not None:
            self._probe.hit(point)

    def _validate_mutation_checkpoint(self, connection: sqlite3.Connection) -> None:
        config_text = _validate_schema_manifest(connection, storage_checks=False)
        if config_text != _json(_config_object(self._config)):
            raise ValueError(
                "APCC authority configuration does not match provisioned store"
            )
        _verify_semantic_checkpoint(connection, self._config, _SCHEMA_FINGERPRINT)

    def _seal_mutation_checkpoint(self, connection: sqlite3.Connection) -> None:
        _seal_semantic_checkpoint(
            connection, self._config, self._runtime, _SCHEMA_FINGERPRINT
        )

    def _finalize_attached_gcb_transaction(
        self, connection: sqlite3.Connection
    ) -> None:
        """Validate and seal APCC changes made by the trusted GCB control path."""
        _, _, checkpoint_digest, _, signature = _semantic_checkpoint_row(connection)
        if not checkpoint_digest and not signature:
            _validate_semantic_integrity(connection, self._config)
        self._seal_mutation_checkpoint(connection)

    def _ensure_semantic_checkpoint(self) -> None:
        connection = _connect(self.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            config_text = _validate_schema_manifest(connection, storage_checks=False)
            if config_text != _json(_config_object(self._config)):
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            _verify_semantic_checkpoint(
                connection,
                self._config,
                _SCHEMA_FINGERPRINT,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = _connect(self.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_mutation_checkpoint(connection)
            yield connection
            self._seal_mutation_checkpoint(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _run_projection(
        self,
        connection: _AuthorityConnection,
        request: AtomicCommitRequest,
        result: CommitResult,
        plan: _GCBProjectionPlan | None,
    ) -> None:
        if plan is None:
            if self._gcb_attached:
                raise _GCBProjectionDenied("unprojected_gcb_commit_denied")
            return
        if not self._gcb_attached:
            raise _GCBProjectionDenied("gcb_projection_requires_attached_store")
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SQLite APCC projection requires a SQLite transaction")
        _validate_gcb_projection_identity(request, plan)
        facts = _load_gcb_projection_facts(connection, self._runtime.clock, plan)
        validated = _validate_gcb_projection(self._config, request, plan, facts)
        self._gcb_checkpoint(_GCBProjectionCheckpoint.BEFORE_LEGACY_WRITE)
        changed = connection.execute(
            "UPDATE nodes SET status='governed_committed',version=version+1,"
            "commit_id=?,receipt_digest=? WHERE workflow_id=? AND node_id=? "
            "AND status='result_produced' AND version=? AND attempt_id=? "
            "AND claimed_by=? AND result_digest=? AND tainted=0",
            (
                plan.commit_id,
                plan.receipt_digest,
                plan.workflow_id,
                plan.node_id,
                validated.legacy_node_version,
                plan.attempt_id,
                plan.agent_id,
                request.subject.output_digest,
            ),
        ).rowcount
        if changed != 1:
            raise _GCBProjectionDenied("legacy_projection_state_conflict")
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_NODE_WRITE)
        changed = connection.execute(
            "UPDATE workflows SET state_version=? WHERE workflow_id=? AND state_version=?",
            (
                validated.next_workflow_state_version,
                plan.workflow_id,
                plan.expected_workflow_state_version,
            ),
        ).rowcount
        if changed != 1:
            raise _GCBProjectionDenied("legacy_projection_state_conflict")
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_WORKFLOW_WRITE)
        connection.execute(
            "INSERT INTO decisions(commit_id,request_hash,outcome,reason,workflow_id,"
            "node_id,state_version,nonce) VALUES (?,?,'committed','verified',?,?,?,?)",
            (
                plan.commit_id,
                plan.request_hash,
                plan.workflow_id,
                plan.node_id,
                validated.next_workflow_state_version,
                plan.nonce,
            ),
        )
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_DECISION_WRITE)
        connection.execute(
            "INSERT INTO receipt_evidence(commit_id,receipt_material,receipt_digest,"
            "verdict_material,verdict_digest) VALUES (?,?,?,?,?)",
            (
                plan.commit_id,
                plan.receipt_material,
                plan.receipt_digest,
                plan.verdict_material,
                plan.verdict_digest,
            ),
        )
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_EVIDENCE_WRITE)
        connection.execute(
            "INSERT INTO outbox(commit_id,workflow_id,node_id,artifact_json) "
            "VALUES (?,?,?,?)",
            (
                plan.commit_id,
                plan.workflow_id,
                plan.node_id,
                validated.artifact_json,
            ),
        )
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_OUTBOX_WRITE)
        unlocked: list[tuple[str, int]] = []
        children = connection.execute(
            "SELECT node_id,version,predecessors FROM nodes "
            "WHERE workflow_id=? AND status='blocked'",
            (plan.workflow_id,),
        ).fetchall()
        for child_id_value, child_version_value, predecessors_json in children:
            child_id = str(child_id_value)
            predecessors = _gcb_string_list(
                json.loads(str(predecessors_json)), label="predecessors"
            )
            if plan.node_id not in predecessors or _gcb_revoked_closure(
                connection, plan.workflow_id, child_id
            ):
                continue
            predecessor_states = [
                connection.execute(
                    "SELECT status,commit_id FROM nodes "
                    "WHERE workflow_id=? AND node_id=?",
                    (plan.workflow_id, predecessor_id),
                ).fetchone()
                for predecessor_id in predecessors
            ]
            if not all(
                state is not None
                and state[0] == "governed_committed"
                and isinstance(state[1], str)
                and bool(state[1])
                for state in predecessor_states
            ):
                continue
            child_version = _gcb_exact_int(
                child_version_value, label="child_node_version"
            )
            changed = connection.execute(
                "UPDATE nodes SET status='ready',version=version+1 "
                "WHERE workflow_id=? AND node_id=? AND status='blocked' AND version=?",
                (plan.workflow_id, child_id, child_version),
            ).rowcount
            if changed != 1:
                raise _GCBProjectionDenied("legacy_projection_state_conflict")
            unlocked.append((child_id, child_version + 1))
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_CHILD_UNLOCK)
        _attest_gcb_projection(
            connection, request, result, plan, validated, tuple(unlocked)
        )
        self._gcb_checkpoint(_GCBProjectionCheckpoint.AFTER_ATTESTATION)

    def _gcb_checkpoint(self, checkpoint: _GCBProjectionCheckpoint) -> None:
        if (
            self._gcb_projection_fault is checkpoint
            and not self._gcb_projection_fault_fired
        ):
            self._gcb_projection_fault_fired = True
            raise _GCBProjectionFault(checkpoint.value)

    def recover_outbox(self, request: OutboxRecoveryRequest) -> OutboxRecoveryResult:
        maximum = _canonical_positive_decimal(request.max_items, maximum=1000)
        delivered_ids: list[str] = []
        lease_ms = 30_000
        for _ in range(maximum):
            token = secrets.token_hex(32)
            now = _trusted_now(self._runtime.clock)
            if now > _MAX_SAFE_INTEGER - lease_ms:
                raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
            connection = _connect(self.database_path)
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_mutation_checkpoint(connection)
                head = connection.execute(
                    "SELECT event_sequence,event_id,event_json,state,lease_until_ms "
                    "FROM apcc_outbox WHERE state<>'DELIVERED' "
                    "ORDER BY event_sequence LIMIT 1"
                ).fetchone()
                if head is None or (
                    head[3] == "CLAIMED" and head[4] is not None and int(head[4]) > now
                ):
                    self._seal_mutation_checkpoint(connection)
                    connection.commit()
                    break
                claimed = connection.execute(
                    "UPDATE apcc_outbox SET state='CLAIMED',lease_token=?,lease_claimed_ms=?,lease_until_ms=?,delivered=0 "
                    "WHERE event_sequence=? AND (state='PENDING' OR (state='CLAIMED' AND lease_until_ms<=?))",
                    (token, now, now + lease_ms, head[0], now),
                ).rowcount
                self._seal_mutation_checkpoint(connection)
                connection.commit()
                if claimed != 1:
                    continue
                event_id, payload = str(head[1]), bytes(head[2])
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            try:
                self._runtime.outbox_sink.deliver(event_id, payload)
            except Exception:
                release = _connect(self.database_path)
                try:
                    release.execute("BEGIN IMMEDIATE")
                    self._validate_mutation_checkpoint(release)
                    release.execute(
                        "UPDATE apcc_outbox SET state='PENDING',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=0 "
                        "WHERE event_id=? AND state='CLAIMED' AND lease_token=?",
                        (event_id, token),
                    )
                    self._seal_mutation_checkpoint(release)
                    release.commit()
                except Exception:
                    release.rollback()
                    raise
                finally:
                    release.close()
                raise
            finalize = _connect(self.database_path)
            try:
                finalize.execute("BEGIN IMMEDIATE")
                self._validate_mutation_checkpoint(finalize)
                changed = finalize.execute(
                    "UPDATE apcc_outbox SET state='DELIVERED',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=1 "
                    "WHERE event_id=? AND state='CLAIMED' AND lease_token=?",
                    (event_id, token),
                ).rowcount
                if changed == 1:
                    delivered_ids.append(event_id)
                self._seal_mutation_checkpoint(finalize)
                finalize.commit()
            except Exception:
                finalize.rollback()
                raise
            finally:
                finalize.close()
        audit = _audit_id(
            "outbox-delivered", *(delivered_ids if delivered_ids else ["none"])
        )
        connection = _connect(self.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_mutation_checkpoint(connection)
            if (
                delivered_ids
                and connection.execute(
                    "SELECT 1 FROM audit_events WHERE audit_event_id=?", (audit,)
                ).fetchone()
                is None
            ):
                _write_audit(connection, audit, "outbox_delivered", "outbox")
            pending = int(
                connection.execute(
                    "SELECT COUNT(*) FROM apcc_outbox WHERE state<>'DELIVERED'"
                ).fetchone()[0]
            )
            self._seal_mutation_checkpoint(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return OutboxRecoveryResult(str(len(delivered_ids)), str(pending), audit)


_SEMANTIC_CHECKPOINT_GUARDED_TABLES = (
    "metadata",
    "logical_nodes",
    "candidates",
    "commit_index",
    "request_index",
    "nonce_ledger",
    "evidence_refs",
    "certificates",
    "audit_events",
    "apcc_decisions",
    "certificate_dispositions",
    "predecessor_edges",
    "supersession_edges",
    "workflow_revocations",
    "actor_revocations",
    "trust_log",
    "control_events",
    "apcc_outbox",
    "commit_conflicts",
    "commit_output_refs",
)


def _semantic_checkpoint_triggers() -> tuple[str, ...]:
    statements: list[str] = []
    update = (
        "BEGIN UPDATE semantic_checkpoint SET "
        "prior_digest=CASE WHEN signature<>'' THEN checkpoint_digest ELSE prior_digest END,"
        "change_sequence=change_sequence+1,checkpoint_digest='',signature='' "
        "WHERE singleton=1; "
        "SELECT CASE WHEN changes()<>1 THEN "
        "RAISE(ABORT, 'APCC semantic checkpoint is missing') END; END"
    )
    for table in _SEMANTIC_CHECKPOINT_GUARDED_TABLES:
        for event in ("INSERT", "UPDATE", "DELETE"):
            statements.append(
                f"CREATE TRIGGER apcc_semantic_dirty_{table}_{event.lower()} "
                f"AFTER {event} ON {table} {update}"
            )
    return tuple(statements)


_SEMANTIC_CHECKPOINT_TRIGGERS = _semantic_checkpoint_triggers()


_SCHEMA_STATEMENTS = (
    "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    f"CREATE TABLE semantic_checkpoint (singleton INTEGER PRIMARY KEY CHECK(singleton=1), change_sequence INTEGER NOT NULL CHECK(typeof(change_sequence)='integer' AND change_sequence BETWEEN 0 AND {_MAX_SAFE_INTEGER}), prior_digest TEXT NOT NULL, checkpoint_digest TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL)",
    "CREATE TABLE logical_nodes (workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, version TEXT NOT NULL CHECK(version <> '' AND version NOT GLOB '*[^0-9]*' AND (version='0' OR version NOT GLOB '0*')), certificate_digest TEXT REFERENCES certificates(certificate_digest) DEFERRABLE INITIALLY DEFERRED, PRIMARY KEY(workflow_id,node_id))",
    "CREATE TABLE candidates (workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL, agent_id TEXT NOT NULL, lifecycle TEXT NOT NULL CHECK(lifecycle IN ('EXECUTING','RESULT_STAGED','EVIDENCE_ASSEMBLED','COMMIT_PENDING','QUARANTINED')), expected_version TEXT NOT NULL, result BLOB, subject_json TEXT NOT NULL, context_json TEXT NOT NULL, predecessors_json TEXT NOT NULL, proposal_digest TEXT, audit_event_id TEXT NOT NULL, proposal_json TEXT, PRIMARY KEY(workflow_id,node_id,attempt_id))",
    "CREATE TABLE commit_index (commit_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, workflow_id TEXT NOT NULL, request_json TEXT NOT NULL)",
    "CREATE TABLE request_index (request_digest TEXT PRIMARY KEY, commit_id TEXT NOT NULL UNIQUE REFERENCES commit_index(commit_id))",
    "CREATE TABLE nonce_ledger (nonce TEXT PRIMARY KEY NOT NULL, commit_id TEXT NOT NULL UNIQUE REFERENCES commit_index(commit_id))",
    "CREATE TABLE evidence_refs (commit_id TEXT PRIMARY KEY REFERENCES commit_index(commit_id), producer_digest TEXT NOT NULL, policy_digest TEXT NOT NULL, authority_digest TEXT NOT NULL)",
    f"CREATE TABLE certificates (certificate_digest TEXT PRIMARY KEY NOT NULL, commit_id TEXT UNIQUE NOT NULL REFERENCES commit_index(commit_id), certificate_json BLOB NOT NULL, envelope BLOB NOT NULL, workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, sequence INTEGER NOT NULL UNIQUE CHECK(typeof(sequence)='integer' AND sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}))",
    f"CREATE TABLE commit_output_refs (commit_id TEXT PRIMARY KEY NOT NULL REFERENCES certificates(commit_id), workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL, output_digest TEXT NOT NULL, output_size INTEGER NOT NULL CHECK(typeof(output_size)='integer' AND output_size BETWEEN 0 AND {_MAX_SAFE_INTEGER}), FOREIGN KEY(workflow_id,node_id,attempt_id) REFERENCES candidates(workflow_id,node_id,attempt_id))",
    "CREATE TABLE audit_events (audit_event_id TEXT PRIMARY KEY NOT NULL, event_json TEXT NOT NULL)",
    "CREATE TABLE apcc_decisions (commit_id TEXT PRIMARY KEY NOT NULL REFERENCES commit_index(commit_id), outcome TEXT NOT NULL CHECK(outcome IN ('COMMITTED','DENIED','CONFLICTED')), reason TEXT NOT NULL, audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(audit_event_id), certificate_digest TEXT REFERENCES certificates(certificate_digest) DEFERRABLE INITIALLY DEFERRED, nonce TEXT NOT NULL, nonce_owner_commit_id TEXT NOT NULL REFERENCES commit_index(commit_id) DEFERRABLE INITIALLY DEFERRED, CHECK((outcome='COMMITTED')=(certificate_digest IS NOT NULL)))",
    "CREATE TABLE certificate_dispositions (certificate_digest TEXT NOT NULL REFERENCES certificates(certificate_digest), event_sequence INTEGER NOT NULL CHECK(event_sequence IN (1,2)), disposition TEXT NOT NULL CHECK(disposition IN ('CURRENT','REVOKED','SUPERSEDED')), PRIMARY KEY(certificate_digest,event_sequence))",
    "CREATE TABLE predecessor_edges (child_commit_id TEXT NOT NULL REFERENCES certificates(commit_id), predecessor_digest TEXT NOT NULL REFERENCES certificates(certificate_digest), PRIMARY KEY(child_commit_id, predecessor_digest))",
    "CREATE TABLE supersession_edges (edge_id TEXT PRIMARY KEY, old_digest TEXT NOT NULL REFERENCES certificates(certificate_digest), new_digest TEXT NOT NULL REFERENCES certificates(certificate_digest), nonce TEXT NOT NULL)",
    f"CREATE TABLE workflow_revocations (workflow_id TEXT PRIMARY KEY NOT NULL, generation TEXT NOT NULL CHECK(generation <> '' AND generation NOT GLOB '*[^0-9]*' AND generation NOT GLOB '0*' AND length(generation)<=16 AND CAST(generation AS INTEGER) BETWEEN 1 AND {_MAX_SAFE_INTEGER}))",
    f"CREATE TABLE actor_revocations (workflow_id TEXT NOT NULL, actor_id TEXT NOT NULL, generation TEXT NOT NULL CHECK(generation <> '' AND generation NOT GLOB '*[^0-9]*' AND generation NOT GLOB '0*' AND length(generation)<=16 AND CAST(generation AS INTEGER) BETWEEN 1 AND {_MAX_SAFE_INTEGER}), PRIMARY KEY(workflow_id,actor_id))",
    f"CREATE TABLE trust_log (sequence INTEGER PRIMARY KEY CHECK(typeof(sequence)='integer' AND sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}), audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(audit_event_id), prior_digest TEXT NOT NULL, entry_digest TEXT NOT NULL UNIQUE, entry_json TEXT NOT NULL)",
    "CREATE TABLE control_events (operation_id TEXT PRIMARY KEY, scope TEXT NOT NULL CHECK(scope IN ('CERTIFICATE','ACTOR','WORKFLOW')), workflow_id TEXT NOT NULL, target_id TEXT NOT NULL, generation TEXT, claimed_generation TEXT NOT NULL, reason TEXT NOT NULL, audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(audit_event_id), payload BLOB NOT NULL, payload_digest TEXT NOT NULL UNIQUE, CHECK((scope='CERTIFICATE')=(generation IS NULL)))",
    f"CREATE TABLE apcc_outbox (event_sequence INTEGER PRIMARY KEY CHECK(typeof(event_sequence)='integer' AND event_sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}), event_id TEXT NOT NULL UNIQUE, event_kind TEXT NOT NULL CHECK(event_kind IN ('COMMIT','CONTROL')), operation_id TEXT NOT NULL, event_json BLOB NOT NULL, audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(audit_event_id), trust_sequence INTEGER NOT NULL UNIQUE REFERENCES trust_log(sequence), state TEXT NOT NULL CHECK(state IN ('PENDING','CLAIMED','DELIVERED')), lease_token TEXT, lease_claimed_ms INTEGER CHECK(lease_claimed_ms IS NULL OR (typeof(lease_claimed_ms)='integer' AND lease_claimed_ms BETWEEN 0 AND {_MAX_SAFE_INTEGER})), lease_until_ms INTEGER CHECK(lease_until_ms IS NULL OR (typeof(lease_until_ms)='integer' AND lease_until_ms BETWEEN 0 AND {_MAX_SAFE_INTEGER})), delivered INTEGER NOT NULL CHECK(delivered IN (0,1)), UNIQUE(event_kind,operation_id), CHECK((state='PENDING' AND delivered=0 AND lease_token IS NULL AND lease_claimed_ms IS NULL AND lease_until_ms IS NULL) OR (state='CLAIMED' AND delivered=0 AND lease_token IS NOT NULL AND lease_claimed_ms IS NOT NULL AND lease_until_ms IS NOT NULL AND lease_until_ms>=lease_claimed_ms) OR (state='DELIVERED' AND delivered=1 AND lease_token IS NULL AND lease_claimed_ms IS NULL AND lease_until_ms IS NULL)))",
    "CREATE TABLE commit_conflicts (commit_id TEXT NOT NULL, original_request_digest TEXT NOT NULL, original_public_request_digest TEXT NOT NULL, original_workflow_id TEXT NOT NULL, original_node_id TEXT NOT NULL, original_attempt_id TEXT NOT NULL, conflicting_request_digest TEXT NOT NULL, conflicting_public_request_digest TEXT NOT NULL, conflicting_workflow_id TEXT NOT NULL, conflicting_node_id TEXT NOT NULL, conflicting_attempt_id TEXT NOT NULL, observation_sequence INTEGER NOT NULL, audit_event_id TEXT NOT NULL, conflict_claim_json TEXT NOT NULL, PRIMARY KEY(commit_id, conflicting_workflow_id, conflicting_node_id, conflicting_attempt_id, conflicting_request_digest, conflicting_public_request_digest))",
    "CREATE TRIGGER commit_output_refs_no_update BEFORE UPDATE ON commit_output_refs BEGIN SELECT RAISE(ABORT, 'commit output refs are immutable'); END",
    "CREATE TRIGGER commit_output_refs_no_delete BEFORE DELETE ON commit_output_refs BEGIN SELECT RAISE(ABORT, 'commit output refs are immutable'); END",
    "CREATE TRIGGER committed_candidate_no_update BEFORE UPDATE ON candidates WHEN EXISTS (SELECT 1 FROM commit_output_refs WHERE workflow_id=OLD.workflow_id AND node_id=OLD.node_id AND attempt_id=OLD.attempt_id) AND (NEW.workflow_id<>OLD.workflow_id OR NEW.node_id<>OLD.node_id OR NEW.attempt_id<>OLD.attempt_id OR NEW.result IS NOT OLD.result OR NEW.subject_json<>OLD.subject_json) BEGIN SELECT RAISE(ABORT, 'committed candidate output is immutable'); END",
    "CREATE TRIGGER committed_candidate_no_delete BEFORE DELETE ON candidates WHEN EXISTS (SELECT 1 FROM commit_output_refs WHERE workflow_id=OLD.workflow_id AND node_id=OLD.node_id AND attempt_id=OLD.attempt_id) BEGIN SELECT RAISE(ABORT, 'committed candidate output is immutable'); END",
    "CREATE TRIGGER certificate_dispositions_no_update BEFORE UPDATE ON certificate_dispositions BEGIN SELECT RAISE(ABORT, 'certificate dispositions are append-only'); END",
    "CREATE TRIGGER certificate_dispositions_no_delete BEFORE DELETE ON certificate_dispositions BEGIN SELECT RAISE(ABORT, 'certificate dispositions are append-only'); END",
    "CREATE TRIGGER certificate_dispositions_validate_insert BEFORE INSERT ON certificate_dispositions WHEN NOT ((NEW.event_sequence=1 AND NEW.disposition='CURRENT' AND NOT EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest)) OR (NEW.event_sequence=2 AND NEW.disposition IN ('REVOKED','SUPERSEDED') AND EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest AND event_sequence=1 AND disposition='CURRENT') AND NOT EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest AND event_sequence=2))) BEGIN SELECT RAISE(ABORT, 'invalid certificate disposition transition'); END",
    "CREATE TRIGGER trust_log_no_update BEFORE UPDATE ON trust_log BEGIN SELECT RAISE(ABORT, 'trust log is append-only'); END",
    "CREATE TRIGGER trust_log_no_delete BEFORE DELETE ON trust_log BEGIN SELECT RAISE(ABORT, 'trust log is append-only'); END",
    "CREATE TRIGGER control_events_no_update BEFORE UPDATE ON control_events BEGIN SELECT RAISE(ABORT, 'control events are immutable'); END",
    "CREATE TRIGGER control_events_no_delete BEFORE DELETE ON control_events BEGIN SELECT RAISE(ABORT, 'control events are immutable'); END",
    "CREATE TRIGGER apcc_outbox_identity_no_update BEFORE UPDATE ON apcc_outbox WHEN NEW.event_sequence<>OLD.event_sequence OR NEW.event_id<>OLD.event_id OR NEW.event_kind<>OLD.event_kind OR NEW.operation_id<>OLD.operation_id OR NEW.event_json<>OLD.event_json OR NEW.audit_event_id<>OLD.audit_event_id OR NEW.trust_sequence<>OLD.trust_sequence BEGIN SELECT RAISE(ABORT, 'outbox identity is immutable'); END",
    "CREATE TRIGGER apcc_outbox_no_delete BEFORE DELETE ON apcc_outbox BEGIN SELECT RAISE(ABORT, 'outbox is append-only'); END",
    *_SEMANTIC_CHECKPOINT_TRIGGERS,
    "CREATE INDEX idx_apcc_outbox_pending ON apcc_outbox(state,lease_until_ms,event_sequence)",
    "CREATE INDEX idx_apcc_outbox_head ON apcc_outbox(event_sequence) WHERE state<>'DELIVERED'",
    "CREATE INDEX idx_nonce_ledger_nonce ON nonce_ledger(nonce)",
    "CREATE INDEX idx_commit_conflicts_exact ON commit_conflicts(commit_id,conflicting_workflow_id,conflicting_node_id,conflicting_attempt_id,conflicting_request_digest,conflicting_public_request_digest)",
    "CREATE INDEX idx_supersession_new_digest ON supersession_edges(new_digest)",
)


def _normalize_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


_SCHEMA_FINGERPRINT = sha256_digest(
    (
        f"schema-version={_AUTHORITY_SCHEMA_VERSION}\n"
        + "\n".join(_normalize_schema_sql(item) for item in _SCHEMA_STATEMENTS)
    ).encode()
)


def _sqlite_uri(path: Path, mode: str) -> str:
    return f"{Path(path).resolve().as_uri()}?mode={mode}"


def _configure_connection(connection: sqlite3.Connection) -> sqlite3.Connection:
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection
    except Exception:
        connection.close()
        raise


def _connect(path: Path) -> sqlite3.Connection:
    if not Path(path).is_file():
        raise ValueError("APCC SQLite store is not provisioned")
    try:
        connection = sqlite3.connect(
            _sqlite_uri(path, "rw"),
            uri=True,
            isolation_level=None,
            check_same_thread=False,
            timeout=5,
        )
    except sqlite3.OperationalError as error:
        raise ValueError("APCC SQLite store is not provisioned") from error
    return _configure_connection(connection)


def _connect_reader(path: Path) -> sqlite3.Connection:
    if not Path(path).is_file():
        raise ValueError("APCC SQLite store is not provisioned")
    try:
        connection = sqlite3.connect(
            _sqlite_uri(path, "ro"),
            uri=True,
            isolation_level=None,
            check_same_thread=False,
            timeout=5,
        )
    except sqlite3.OperationalError as error:
        raise ValueError("APCC SQLite store is not provisioned") from error
    try:
        _configure_connection(connection)
        connection.execute("PRAGMA query_only=ON")
        return connection
    except Exception:
        connection.close()
        raise


def _connect_create(path: Path) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            _sqlite_uri(path, "rwc"),
            uri=True,
            isolation_level=None,
            check_same_thread=False,
            timeout=5,
        )
        if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
            raise ValueError("APCC SQLite store requires WAL journal mode")
        return _configure_connection(connection)
    except Exception:
        if connection is not None:
            connection.close()
        raise


def _schema_objects() -> dict[tuple[str, str], str]:
    objects: dict[tuple[str, str], str] = {}
    pattern = re.compile(r"^CREATE (TABLE|TRIGGER|INDEX) ([a-z0-9_]+)", re.IGNORECASE)
    for statement in _SCHEMA_STATEMENTS:
        match = pattern.match(statement)
        if match is None:
            raise RuntimeError("invalid APCC schema definition")
        objects[(match.group(1).lower(), match.group(2))] = _normalize_schema_sql(
            statement
        )
    return objects


_REQUIRED_SCHEMA_OBJECTS = _schema_objects()
_APCC_TABLES = frozenset(
    name for (kind, name) in _REQUIRED_SCHEMA_OBJECTS if kind == "table"
)


def _validate_schema_manifest(
    connection: _AuthorityConnection, *, storage_checks: bool
) -> str:
    invalid = ValueError("APCC SQLite store schema validation failed")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    application_id = connection.execute("PRAGMA application_id").fetchone()
    user_version = connection.execute("PRAGMA user_version").fetchone()
    if journal_mode is None or tuple(journal_mode) != ("wal",):
        raise invalid
    if application_id is None or tuple(application_id) != (_APPLICATION_ID,):
        raise invalid
    if user_version is None or tuple(user_version) != (_SCHEMA_VERSION,):
        raise ValueError(_SCHEMA_VERSION_INCOMPATIBLE)
    if storage_checks:
        if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise invalid
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise invalid
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','index','trigger') AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    actual = {
        (str(kind), str(name)): _normalize_schema_sql(str(sql))
        for kind, name, _table, sql in rows
        if sql is not None
    }
    if any(
        actual.get(key) != expected
        for key, expected in _REQUIRED_SCHEMA_OBJECTS.items()
    ):
        raise invalid
    if any(
        (kind == "trigger" and (str(kind), str(name)) not in _REQUIRED_SCHEMA_OBJECTS)
        or (
            kind == "index"
            and table in _APCC_TABLES
            and (str(kind), str(name)) not in _REQUIRED_SCHEMA_OBJECTS
            and not str(name).startswith("sqlite_autoindex_")
        )
        for kind, name, table, _sql in rows
    ):
        raise invalid
    values = {
        str(key): str(value)
        for key, value in connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        )
    }
    if values.get("schema_version") != _AUTHORITY_SCHEMA_VERSION:
        raise ValueError(_SCHEMA_VERSION_INCOMPATIBLE)
    if set(values) != {"config", "schema_fingerprint", "schema_version"}:
        raise invalid
    if values.get("schema_fingerprint") != _SCHEMA_FINGERPRINT:
        raise invalid
    config = values.get("config")
    if config is None:
        raise invalid
    try:
        config_object = _loads(config)
        if _json(config_object) != config:
            raise invalid
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("APCC SQLite store schema validation failed") from error
    return config


def _validate_schema(connection: sqlite3.Connection) -> str:
    config = _validate_schema_manifest(connection, storage_checks=True)
    parsed_config = _config_from_object(_loads(config))
    _validate_semantic_integrity(connection, parsed_config)
    _verify_semantic_checkpoint(
        connection,
        parsed_config,
        _SCHEMA_FINGERPRINT,
    )
    return config


def _attest_sqlite_read_connection(
    connection: _AuthorityConnection, config: APCCAuthorityConfig
) -> None:
    config_text = _validate_schema_manifest(connection, storage_checks=False)
    if config_text != _json(_config_object(config)):
        raise ValueError(
            "APCC authority configuration does not match provisioned store"
        )
    _verify_semantic_checkpoint(connection, config, _SCHEMA_FINGERPRINT)


def _validate_semantic_integrity(
    connection: _AuthorityConnection, config: APCCAuthorityConfig
) -> _SemanticSnapshot:
    invalid = ValueError("APCC SQLite store semantic validation failed")
    certificates: dict[str, CommitCertificate] = {}
    envelope_sizes: dict[str, int] = {}
    trust = _trust(config)
    for (
        digest,
        commit_id,
        payload,
        envelope,
        workflow_id,
        node_id,
        sequence,
    ) in connection.execute(
        "SELECT certificate_digest, commit_id, certificate_json, envelope, workflow_id, node_id, sequence FROM certificates"
    ):
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or not 1 <= sequence <= _MAX_SAFE_INTEGER
        ):
            raise invalid
        try:
            payload_bytes = _row_bytes(payload)
            envelope_bytes = _row_bytes(envelope)
            detached = decode_envelope(envelope_bytes)
            if (
                detached.payload != payload_bytes
                or detached.payload_sha256 != digest
                or sha256_digest(payload_bytes) != digest
            ):
                raise invalid
            certificate = decode_certificate(payload_bytes)
            if (
                _header(certificate) is not None
                or _verify_signature(
                    detached.seal,
                    certificate.header.commit_authority_key_id,
                    trust,
                    TrustRole.COMMIT,
                    (certificate.header.authority_store_id,),
                    COMMIT_DOMAIN,
                    payload_bytes,
                    FailureCode.INVALID_COMMIT_SEAL,
                )
                is not None
                or _evidence(certificate, trust) is not None
                or _bindings(certificate) is not None
            ):
                raise invalid
        except Exception as error:
            raise invalid from error
        if (
            certificate.decision.commit_id != commit_id
            or certificate.subject.workflow_id != workflow_id
            or certificate.subject.node_id != node_id
            or certificate.header.certificate_sequence != str(sequence)
        ):
            raise invalid
        certificates[str(digest)] = certificate
        envelope_sizes[str(digest)] = len(envelope_bytes)

    latest: dict[str, CertificateDisposition] = {}
    for digest, event_sequence, disposition in connection.execute(
        "SELECT certificate_digest, event_sequence, disposition FROM certificate_dispositions ORDER BY certificate_digest,event_sequence"
    ):
        if digest not in certificates:
            raise invalid
        current = CertificateDisposition(_row_text(disposition))
        prior = latest.get(str(digest))
        if (event_sequence, current, prior) == (
            1,
            CertificateDisposition.CURRENT,
            None,
        ):
            latest[str(digest)] = current
        elif (
            event_sequence == 2
            and current
            in {CertificateDisposition.REVOKED, CertificateDisposition.SUPERSEDED}
            and prior is CertificateDisposition.CURRENT
        ):
            latest[str(digest)] = current
        else:
            raise invalid
    if set(latest) != set(certificates):
        raise invalid

    pointed: set[str] = set()
    for workflow_id, node_id, version, digest in connection.execute(
        "SELECT workflow_id,node_id,version,certificate_digest FROM logical_nodes"
    ):
        if (str(version) == "0") != (digest is None):
            raise invalid
        if digest is None:
            continue
        pointed_certificate = certificates.get(str(digest))
        if pointed_certificate is None or (
            pointed_certificate.subject.workflow_id != workflow_id
            or pointed_certificate.subject.node_id != node_id
            or pointed_certificate.bindings.committed_node_version != version
            or latest[str(digest)] is CertificateDisposition.SUPERSEDED
        ):
            raise invalid
        pointed.add(str(digest))
    if not {
        digest
        for digest, disposition in latest.items()
        if disposition is CertificateDisposition.CURRENT
    }.issubset(pointed):
        raise invalid

    logical_keys = {
        (str(workflow), str(node))
        for workflow, node in connection.execute(
            "SELECT workflow_id,node_id FROM logical_nodes"
        )
    }
    for row in connection.execute(
        "SELECT workflow_id,node_id,attempt_id,agent_id,lifecycle,expected_version,result,subject_json,context_json,predecessors_json,proposal_digest,proposal_json,audit_event_id FROM candidates"
    ):
        (
            workflow,
            node,
            attempt,
            agent,
            lifecycle,
            expected_version,
            result,
            subject_json,
            context_json,
            predecessors_json,
            proposal_digest,
            proposal_json,
            audit_event_id,
        ) = row
        try:
            subject_object = _loads(str(subject_json))
            context_object = _loads(str(context_json))
            predecessor_objects = _loads(str(predecessors_json))
            subject = CertificateSubject.from_object(
                cast("dict[str, object]", subject_object)
            )
            CertificateContext.from_object(cast("dict[str, object]", context_object))
            if not isinstance(predecessor_objects, list):
                raise ValueError("invalid predecessors")
            predecessors = tuple(
                PredecessorRef.from_object(item) for item in predecessor_objects
            )
        except Exception as error:
            raise invalid from error
        try:
            canonical_expected_version = str(
                _canonical_nonnegative_decimal(
                    expected_version, maximum=_MAX_SAFE_INTEGER
                )
            )
        except ValueError as error:
            raise invalid from error
        if (
            _json(subject_object) != subject_json
            or _json(context_object) != context_json
            or _json([item.to_object() for item in predecessors]) != predecessors_json
            or (str(workflow), str(node)) not in logical_keys
            or subject.workflow_id != workflow
            or subject.node_id != node
            or subject.attempt_id != attempt
            or subject.agent_id != agent
            or canonical_expected_version != expected_version
        ):
            raise invalid
        state = CandidateLifecycle(str(lifecycle))
        if state is CandidateLifecycle.EXECUTING:
            if (
                result is not None
                or proposal_digest is not None
                or proposal_json is not None
            ):
                raise invalid
        elif (
            result is None or sha256_digest(_row_bytes(result)) != subject.output_digest
        ):
            raise invalid
        if state in {
            CandidateLifecycle.EVIDENCE_ASSEMBLED,
            CandidateLifecycle.COMMIT_PENDING,
        }:
            try:
                proposal = _request_from_json(str(proposal_json))
            except Exception as error:
                raise invalid from error
            if (
                proposal_json != _authority_request_json(proposal)
                or proposal_digest != _proposal_identity(proposal)
                or proposal.subject != subject
                or proposal.context.to_object() != context_object
                or proposal.bindings.predecessors != predecessors
                or proposal.bindings.expected_node_version != expected_version
                or _evidence(
                    CommitCertificate(
                        CertificateHeader(
                            "APCC-1.0-draft",
                            "apcc.commit-certificate",
                            "APCC-CJ1",
                            "SHA-256",
                            "Ed25519",
                            config.authority_store_id,
                            config.commit_trust.key_id,
                            "1",
                        ),
                        proposal.subject,
                        proposal.context,
                        proposal.evidence,
                        CertificateDecision(
                            "committed", "OK", proposal.commit_id, proposal.nonce, "0"
                        ),
                        proposal.bindings,
                        proposal.signatures,
                    ),
                    _trust(config),
                )
                is not None
            ):
                raise invalid
            expected_candidate_audit = _audit_id(
                state.value, proposal.commit_id, _proposal_identity(proposal)
            )
            if audit_event_id != expected_candidate_audit:
                raise invalid
        elif state is CandidateLifecycle.RESULT_STAGED:
            if audit_event_id != _audit_id(
                "stage",
                _row_text(workflow),
                _row_text(node),
                _row_text(attempt),
                subject.output_digest,
                _row_text(expected_version),
            ):
                raise invalid
        elif proposal_digest is not None or proposal_json is not None:
            raise invalid

    audits = {
        str(audit_id): str(event_json)
        for audit_id, event_json in connection.execute(
            "SELECT audit_event_id,event_json FROM audit_events"
        )
    }
    genesis = sha256_digest(b"APCC-1/trust-log/genesis")
    trust_prior = genesis
    trust_by_sequence: dict[int, tuple[str, str, str]] = {}
    for expected, row in enumerate(
        connection.execute(
            "SELECT sequence,audit_event_id,prior_digest,entry_digest,entry_json "
            "FROM trust_log ORDER BY sequence"
        ),
        1,
    ):
        sequence, audit_id, prior_digest, entry_digest, entry_json = row
        entry_json_text = _row_text(entry_json)
        if (
            not isinstance(sequence, int)
            or sequence != expected
            or sequence > _MAX_SAFE_INTEGER
            or audit_id not in audits
            or prior_digest != trust_prior
        ):
            raise invalid
        try:
            entry = _loads(entry_json_text)
        except Exception as error:
            raise invalid from error
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {"sequence", "prior_digest", "kind", "subject", "audit_event_id"}
            or entry_json_text != _json(entry)
            or entry.get("sequence") != str(sequence)
            or entry.get("prior_digest") != trust_prior
            or entry.get("audit_event_id") != audit_id
            or entry.get("kind") not in {"commit", "control"}
            or not isinstance(entry.get("subject"), str)
            or sha256_digest(entry_json_text.encode("utf-8")) != entry_digest
        ):
            raise invalid
        trust_by_sequence[sequence] = (
            str(entry["kind"]),
            str(entry["subject"]),
            str(audit_id),
        )
        trust_prior = str(entry_digest)

    commit_index: dict[str, tuple[str, str, AtomicCommitRequest, str | None]] = {}
    for commit_id, request_digest, workflow_id, request_json in connection.execute(
        "SELECT commit_id,request_digest,workflow_id,request_json FROM commit_index"
    ):
        try:
            request, old_certificate_digest = _operation_from_json(str(request_json))
        except Exception as error:
            raise invalid from error
        if (
            str(request_json)
            != _operation_request_json(request, old_certificate_digest)
            or request.commit_id != commit_id
            or request.subject.workflow_id != workflow_id
            or _operation_identity(request, old_certificate_digest) != request_digest
        ):
            raise invalid
        commit_index[str(commit_id)] = (
            str(request_digest),
            str(workflow_id),
            request,
            old_certificate_digest,
        )
    request_rows = list(
        connection.execute("SELECT request_digest,commit_id FROM request_index")
    )
    nonce_rows = list(connection.execute("SELECT nonce,commit_id FROM nonce_ledger"))
    decisions = {
        str(commit_id): (
            str(outcome),
            str(reason),
            str(audit),
            digest,
            str(nonce),
            str(owner),
        )
        for commit_id, outcome, reason, audit, digest, nonce, owner in connection.execute(
            "SELECT commit_id,outcome,reason,audit_event_id,certificate_digest,nonce,nonce_owner_commit_id FROM apcc_decisions"
        )
    }
    evidence_rows = {
        str(commit_id): (str(producer), str(policy), str(authority))
        for commit_id, producer, policy, authority in connection.execute(
            "SELECT commit_id,producer_digest,policy_digest,authority_digest FROM evidence_refs"
        )
    }
    if (
        len(request_rows) != len(commit_index)
        or set(decisions) != set(commit_index)
        or {str(commit_id) for _digest, commit_id in request_rows} != set(commit_index)
        or len({str(nonce) for nonce, _commit_id in nonce_rows}) != len(nonce_rows)
        or len({str(commit_id) for _nonce, commit_id in nonce_rows}) != len(nonce_rows)
    ):
        raise invalid
    nonce_owner = {str(nonce): str(commit_id) for nonce, commit_id in nonce_rows}
    public_by_commit = {
        str(commit_id): str(digest) for digest, commit_id in request_rows
    }

    signed_edges = {
        (certificate.decision.commit_id, predecessor.certificate_digest)
        for certificate in certificates.values()
        for predecessor in certificate.bindings.predecessors
    }
    stored_edges = {
        (str(commit_id), str(digest))
        for commit_id, digest in connection.execute(
            "SELECT child_commit_id,predecessor_digest FROM predecessor_edges"
        )
    }
    if signed_edges != stored_edges:
        raise invalid

    committed_ids: set[str] = set()
    committed_by_digest: dict[str, str] = {}
    for commit_id, (
        outcome,
        reason,
        audit_id,
        digest,
        nonce,
        owner,
    ) in decisions.items():
        request_digest, _workflow, request, old_certificate_digest = commit_index[
            commit_id
        ]
        expected_outcome = RequestOutcome(outcome)
        if (expected_outcome is RequestOutcome.CONFLICTED) != (
            reason == FailureCode.NODE_VERSION_CONFLICT.value
        ):
            raise invalid
        expected_audit = _audit_id(
            "commit" if expected_outcome is RequestOutcome.COMMITTED else outcome,
            commit_id,
            request_digest,
            *(() if expected_outcome is RequestOutcome.COMMITTED else (reason,)),
        )
        try:
            audit_object = _loads(audits[audit_id])
        except Exception as error:
            raise invalid from error
        if (
            audit_id != expected_audit
            or not isinstance(audit_object, dict)
            or audits[audit_id] != _json(audit_object)
            or audit_object.get("subject") != commit_id
            or audit_object.get("kind")
            != ("committed" if expected_outcome is RequestOutcome.COMMITTED else reason)
            or set(audit_object)
            != {
                "kind",
                "subject",
                *(
                    ("old_certificate_digest",)
                    if old_certificate_digest is not None
                    else ()
                ),
            }
            or audit_object.get("old_certificate_digest") != old_certificate_digest
            or nonce != request.nonce
            or public_by_commit.get(commit_id) != _public_request_digest(request)
            or nonce_owner.get(nonce) != owner
            or ((reason == FailureCode.NONCE_REPLAY.value) == (owner == commit_id))
        ):
            raise invalid
        decision_certificate = (
            certificates.get(str(digest)) if digest is not None else None
        )
        if (
            expected_outcome is not RequestOutcome.COMMITTED
            and reason != FailureCode.NONCE_REPLAY.value
        ):
            immutable_failure = _evidence(
                CommitCertificate(
                    CertificateHeader(
                        "APCC-1.0-draft",
                        "apcc.commit-certificate",
                        "APCC-CJ1",
                        "SHA-256",
                        "Ed25519",
                        config.authority_store_id,
                        config.commit_trust.key_id,
                        "1",
                    ),
                    request.subject,
                    request.context,
                    request.evidence,
                    CertificateDecision(
                        "committed", "OK", request.commit_id, request.nonce, "0"
                    ),
                    request.bindings,
                    request.signatures,
                ),
                _trust(config),
            )
            if immutable_failure is not None and reason != immutable_failure.value:
                raise invalid
        if outcome == RequestOutcome.COMMITTED.value:
            if (
                decision_certificate is None
                or decision_certificate.decision.commit_id != commit_id
                or decision_certificate.subject != request.subject
                or decision_certificate.context != request.context
                or decision_certificate.evidence != request.evidence
                or decision_certificate.bindings != request.bindings
                or decision_certificate.signatures != request.signatures
                or decision_certificate.decision.nonce != request.nonce
                or reason != "OK"
                or owner != commit_id
            ):
                raise invalid
            expected_evidence = (
                decision_certificate.evidence.producer_statement_digest,
                decision_certificate.evidence.policy_statement_digest,
                decision_certificate.evidence.authority_statement_digest,
            )
            if evidence_rows.get(commit_id) != expected_evidence:
                raise invalid
            committed_ids.add(commit_id)
            committed_by_digest[str(digest)] = commit_id
        elif (
            digest is not None
            or commit_id in evidence_rows
            or (reason != FailureCode.NONCE_REPLAY.value and owner != commit_id)
            or (reason == FailureCode.NONCE_REPLAY.value and owner == commit_id)
        ):
            raise invalid
    if not set(nonce_owner.values()).issubset(commit_index):
        raise invalid
    if (
        set(evidence_rows) != committed_ids
        or {certificate.decision.commit_id for certificate in certificates.values()}
        != committed_ids
    ):
        raise invalid
    output_refs = {
        _row_text(row[0]): (
            _row_text(row[1]),
            _row_text(row[2]),
            _row_text(row[3]),
            _row_text(row[4]),
            _row_int(row[5]),
        )
        for row in connection.execute(
            "SELECT commit_id,workflow_id,node_id,attempt_id,output_digest,"
            "output_size FROM commit_output_refs"
        )
    }
    if set(output_refs) != committed_ids:
        raise invalid
    for commit_id, output_ref in output_refs.items():
        request = commit_index[commit_id][2]
        candidate = connection.execute(
            "SELECT result FROM candidates WHERE workflow_id=? AND node_id=? "
            "AND attempt_id=?",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        ).fetchone()
        if candidate is None or candidate[0] is None:
            raise invalid
        result_bytes = _row_bytes(candidate[0])
        if (
            output_ref
            != (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
                request.subject.output_digest,
                len(result_bytes),
            )
            or sha256_digest(result_bytes) != request.subject.output_digest
        ):
            raise invalid

    superseded_new: set[str] = set()
    outgoing: dict[str, str] = {}
    incoming: dict[str, str] = {}
    for edge_row in connection.execute(
        "SELECT edge_id,old_digest,new_digest,nonce FROM supersession_edges"
    ):
        edge_id = _row_text(edge_row[0])
        old_digest = _row_text(edge_row[1])
        new_digest = _row_text(edge_row[2])
        nonce = _row_text(edge_row[3])
        old = certificates.get(str(old_digest))
        new = certificates.get(str(new_digest))
        if old is None or new is None:
            raise invalid
        decision = decisions.get(new.decision.commit_id)
        try:
            audit_object = _loads(audits[decision[2]]) if decision is not None else None
        except Exception as error:
            raise invalid from error
        supersession_operation = commit_index[new.decision.commit_id]
        if (
            edge_id != _audit_id("replace", str(old_digest), str(new_digest))
            or nonce != new.decision.nonce
            or old.subject.workflow_id != new.subject.workflow_id
            or old.subject.node_id != new.subject.node_id
            or latest.get(str(old_digest)) is not CertificateDisposition.SUPERSEDED
            or latest.get(str(new_digest))
            not in {
                CertificateDisposition.CURRENT,
                CertificateDisposition.REVOKED,
                CertificateDisposition.SUPERSEDED,
            }
            or int(new.bindings.committed_node_version)
            != int(old.bindings.committed_node_version) + 1
            or supersession_operation[3] != old_digest
            or not isinstance(audit_object, dict)
            or audit_object.get("old_certificate_digest") != old_digest
            or str(old_digest) in outgoing
            or str(new_digest) in incoming
        ):
            raise invalid
        outgoing[str(old_digest)] = str(new_digest)
        incoming[str(new_digest)] = str(old_digest)
        superseded_new.add(str(new_digest))
    if {
        digest
        for digest, disposition in latest.items()
        if disposition is CertificateDisposition.SUPERSEDED
    } != set(outgoing):
        raise invalid
    for digest, commit_id in committed_by_digest.items():
        operation_old = commit_index[commit_id][3]
        if (operation_old is not None) != (digest in incoming):
            raise invalid
        if operation_old is not None and incoming.get(digest) != operation_old:
            raise invalid

    controls: dict[str, tuple[str, str, str, str | None, str, bytes, str]] = {}
    for row in connection.execute(
        "SELECT operation_id,scope,workflow_id,target_id,generation,claimed_generation,reason,audit_event_id,payload,payload_digest FROM control_events"
    ):
        control_operation = _row_text(row[0])
        control_scope = _row_text(row[1])
        control_workflow = _row_text(row[2])
        control_target = _row_text(row[3])
        control_generation = _row_optional_text(row[4])
        control_claimed_generation = _row_text(row[5])
        control_reason = _row_text(row[6])
        control_audit = _row_text(row[7])
        payload_bytes = _row_bytes(row[8])
        control_digest = _row_text(row[9])
        control_object = {
            "scope": control_scope,
            "workflow_id": control_workflow,
            "target_id": control_target,
            "generation": control_generation,
            "claimed_generation": control_claimed_generation,
            "reason": control_reason,
            "audit_event_id": control_audit,
        }
        expected_audit = _audit_id(
            "revoke",
            control_scope,
            control_workflow,
            control_target,
            control_claimed_generation,
        )
        expected_audit_object = {
            "kind": "revoked",
            "subject": control_target,
            "scope": control_scope,
            "workflow_id": control_workflow,
            **(
                {"generation": control_generation}
                if control_generation is not None
                else {}
            ),
        }
        if (
            control_operation != expected_audit
            or control_audit != expected_audit
            or audits.get(control_audit) != _json(expected_audit_object)
            or payload_bytes != _json(control_object).encode("utf-8")
            or sha256_digest(payload_bytes) != control_digest
        ):
            raise invalid
        if control_scope == RevocationScope.CERTIFICATE.value:
            if (
                control_generation is not None
                or latest.get(control_target) is not CertificateDisposition.REVOKED
            ):
                raise invalid
        else:
            try:
                canonical = str(
                    _canonical_positive_decimal(
                        control_generation, maximum=_MAX_SAFE_INTEGER
                    )
                )
            except ValueError as error:
                raise invalid from error
            if canonical != control_generation:
                raise invalid
        controls[control_operation] = (
            control_scope,
            control_workflow,
            control_target,
            control_generation,
            control_audit,
            payload_bytes,
            control_digest,
        )

    expected_actor: dict[tuple[str, str], int] = {}
    expected_workflow: dict[str, int] = {}
    for (
        scope,
        workflow,
        target,
        generation,
        _audit,
        _payload,
        _digest,
    ) in controls.values():
        if scope == RevocationScope.ACTOR.value and generation is not None:
            expected_actor[(workflow, target)] = max(
                expected_actor.get((workflow, target), 0), int(generation)
            )
        elif scope == RevocationScope.WORKFLOW.value and generation is not None:
            expected_workflow[workflow] = max(
                expected_workflow.get(workflow, 0), int(generation)
            )
    actual_actor = {
        (str(workflow), str(actor)): _row_int(generation)
        for workflow, actor, generation in connection.execute(
            "SELECT workflow_id,actor_id,generation FROM actor_revocations"
        )
    }
    actual_workflow = {
        str(workflow): _row_int(generation)
        for workflow, generation in connection.execute(
            "SELECT workflow_id,generation FROM workflow_revocations"
        )
    }
    if actual_actor != expected_actor or actual_workflow != expected_workflow:
        raise invalid

    seen_commits: set[str] = set()
    seen_controls: set[str] = set()
    for row in connection.execute(
        "SELECT event_sequence,event_id,event_kind,operation_id,event_json,audit_event_id,trust_sequence,state,lease_token,lease_claimed_ms,lease_until_ms,delivered FROM apcc_outbox"
    ):
        outbox_sequence = _row_int(row[0])
        outbox_event_id = _row_text(row[1])
        outbox_kind = _row_text(row[2])
        outbox_operation = _row_text(row[3])
        outbox_payload = _row_bytes(row[4])
        outbox_audit = _row_text(row[5])
        outbox_trust_sequence = _row_int(row[6])
        outbox_state = _row_text(row[7])
        outbox_token = _row_optional_text(row[8])
        outbox_claimed = None if row[9] is None else _row_int(row[9])
        outbox_lease = None if row[10] is None else _row_int(row[10])
        outbox_delivered = _row_int(row[11])
        if (
            outbox_sequence != outbox_trust_sequence
            or trust_by_sequence.get(outbox_sequence) is None
        ):
            raise invalid
        trust_kind, trust_subject, trust_audit = trust_by_sequence[outbox_sequence]
        if outbox_audit != trust_audit:
            raise invalid
        if outbox_kind == "COMMIT":
            decision = decisions.get(outbox_operation)
            if decision is None or decision[0] != RequestOutcome.COMMITTED.value:
                raise invalid
            digest = str(decision[3])
            certificate = certificates[digest]
            expected_payload = encode_certificate(certificate)
            if (
                outbox_audit != decision[2]
                or trust_kind != "commit"
                or trust_subject != digest
                or outbox_event_id
                != _audit_id("outbox", "COMMIT", outbox_operation, digest)
            ):
                raise invalid
            seen_commits.add(outbox_operation)
        else:
            control = controls.get(outbox_operation)
            if control is None:
                raise invalid
            expected_payload = control[5]
            if (
                outbox_audit != control[4]
                or trust_kind != "control"
                or trust_subject != outbox_operation
                or outbox_event_id
                != _audit_id("outbox", "CONTROL", outbox_operation, control[6])
            ):
                raise invalid
            seen_controls.add(outbox_operation)
        if outbox_payload != expected_payload or not (
            (
                outbox_state == "PENDING"
                and outbox_delivered == 0
                and outbox_token is None
                and outbox_claimed is None
                and outbox_lease is None
            )
            or (
                outbox_state == "CLAIMED"
                and outbox_delivered == 0
                and outbox_token is not None
                and outbox_claimed is not None
                and outbox_lease is not None
                and outbox_lease >= outbox_claimed
            )
            or (
                outbox_state == "DELIVERED"
                and outbox_delivered == 1
                and outbox_token is None
                and outbox_claimed is None
                and outbox_lease is None
            )
        ):
            raise invalid
        for timestamp in (outbox_claimed, outbox_lease):
            if timestamp is not None and (
                isinstance(timestamp, bool)
                or not isinstance(timestamp, int)
                or not 0 <= timestamp <= _MAX_SAFE_INTEGER
            ):
                raise invalid
    if seen_commits != committed_ids or seen_controls != set(controls):
        raise invalid
    if len(trust_by_sequence) != len(committed_ids) + len(controls):
        raise invalid

    conflict_sequences: dict[str, list[int]] = {}
    for (
        commit_id,
        original,
        original_public,
        original_workflow,
        original_node,
        original_attempt,
        conflicting,
        public,
        conflicting_workflow,
        conflicting_node,
        conflicting_attempt,
        sequence,
        audit,
        claim_json,
    ) in connection.execute(
        "SELECT commit_id,original_request_digest,original_public_request_digest,"
        "original_workflow_id,original_node_id,original_attempt_id,"
        "conflicting_request_digest,conflicting_public_request_digest,"
        "conflicting_workflow_id,conflicting_node_id,conflicting_attempt_id,"
        "observation_sequence,audit_event_id,conflict_claim_json FROM commit_conflicts"
    ):
        indexed = commit_index.get(str(commit_id))
        try:
            claim = _loads(str(claim_json))
            if not isinstance(claim, dict) or claim_json != _json(claim):
                raise ValueError("invalid conflict claim")
            if claim.get("kind") == "atomic" and set(claim) == {
                "kind",
                "request",
                "supersede_old",
            }:
                conflict_request = _request_from_json(_json(claim["request"]))
                expected_conflicting = _operation_identity(
                    conflict_request,
                    cast("str | None", claim["supersede_old"]),
                )
                expected_public = _public_request_digest(conflict_request)
                conflict_workflow_expected = conflict_request.subject.workflow_id
                conflict_node_expected = conflict_request.subject.node_id
                conflict_attempt_expected = conflict_request.subject.attempt_id
                supersede_old = claim["supersede_old"]
            elif claim.get("kind") == "recovery" and set(claim) == {
                "kind",
                "commit_id",
                "request_digest",
            }:
                expected_conflicting = str(claim["request_digest"])
                expected_public = expected_conflicting
                if indexed is None:
                    raise ValueError("recovery conflict lacks original operation")
                conflict_workflow_expected = indexed[2].subject.workflow_id
                conflict_node_expected = indexed[2].subject.node_id
                conflict_attempt_expected = indexed[2].subject.attempt_id
                supersede_old = None
            else:
                raise ValueError("invalid conflict claim")
        except Exception as error:
            raise invalid from error
        expected_audit = _audit_id("conflict", str(commit_id), expected_conflicting)
        expected_audit_json = _json(
            {
                "kind": FailureCode.COMMIT_ID_EQUIVOCATION.value,
                "subject": commit_id,
                **(
                    {"old_certificate_digest": supersede_old}
                    if isinstance(supersede_old, str)
                    else {}
                ),
            }
        )
        if (
            indexed is None
            or original != indexed[0]
            or original_public != public_by_commit.get(str(commit_id))
            or original_workflow != indexed[1]
            or original_node != indexed[2].subject.node_id
            or original_attempt != indexed[2].subject.attempt_id
            or conflicting != expected_conflicting
            or public != expected_public
            or conflicting_workflow != conflict_workflow_expected
            or conflicting_node != conflict_node_expected
            or conflicting_attempt != conflict_attempt_expected
            or audit != expected_audit
            or audits.get(str(audit)) != expected_audit_json
            or not isinstance(sequence, int)
            or sequence <= 0
        ):
            raise invalid
        conflict_sequences.setdefault(str(commit_id), []).append(sequence)
    if any(
        sorted(values) != list(range(1, len(values) + 1))
        for values in conflict_sequences.values()
    ):
        raise invalid
    return _SemanticSnapshot(dict(certificates), dict(latest), dict(envelope_sizes))


def _schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_STATEMENTS:
        if statement in _SEMANTIC_CHECKPOINT_TRIGGERS:
            continue
        connection.execute(statement)


def _insert_context(connection: _AuthorityConnection, context: CommitContext) -> None:
    connection.execute(
        "INSERT INTO logical_nodes VALUES (?, ?, ?, ?)",
        (
            context.logical_node_state.workflow_id,
            context.logical_node_state.node_id,
            context.logical_node_state.current_node_version,
            context.logical_node_state.current_certificate_digest,
        ),
    )
    connection.execute(
        "INSERT INTO candidates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            context.subject.workflow_id,
            context.subject.node_id,
            context.subject.attempt_id,
            context.subject.agent_id,
            context.candidate_state.lifecycle.value,
            context.logical_node_state.current_node_version,
            None,
            _json(context.subject.to_object()),
            _json(context.governance.to_object()),
            _json([item.to_object() for item in context.predecessors]),
            None,
            context.audit_event_id,
            None,
        ),
    )


def _certificate_shell(
    subject: object, context: object, predecessors: object
) -> dict[str, object]:
    # A model-only helper for the reader's typed context projection.
    return {
        "header": {
            "protocol_version": "APCC-1.0-draft",
            "certificate_type": "apcc.commit-certificate",
            "encoding_profile": "APCC-CJ1",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
            "authority_store_id": "reader",
            "commit_authority_key_id": "reader",
            "certificate_sequence": "1",
        },
        "subject": subject,
        "context": context,
        "evidence": {
            "producer_statement": {
                "protocol_version": "APCC-1.0-draft",
                "statement_type": "apcc.producer-statement",
                "producer_key_id": "x",
                "workflow_id": "x",
                "node_id": "x",
                "attempt_id": "x",
                "agent_id": "x",
                "actor_authority": "x",
                "input_digest": "x",
                "output_digest": "x",
                "predecessor_root": "x",
                "expected_node_version": "0",
                "commit_id": "x",
                "nonce": "x",
                "issued_at_ms": "0",
                "expires_at_ms": "1",
            },
            "producer_statement_digest": "x",
            "policy_statement": {
                "protocol_version": "APCC-1.0-draft",
                "statement_type": "apcc.policy-statement",
                "policy_key_id": "x",
                "proposal_digest": "x",
                "decision": "allow",
                "policy_id": "x",
                "policy_version": "x",
                "policy_epoch": "x",
                "workflow_id": "x",
                "node_id": "x",
                "attempt_id": "x",
                "issued_at_ms": "0",
                "expires_at_ms": "1",
            },
            "policy_statement_digest": "x",
            "authority_statement": {
                "protocol_version": "APCC-1.0-draft",
                "statement_type": "apcc.authority-statement",
                "authority_key_id": "x",
                "proposal_digest": "x",
                "agent_id": "x",
                "producer_key_id": "x",
                "actor_authority": "x",
                "authority_root": "x",
                "authority_epoch": "x",
                "agent_revocation_generation": "0",
                "workflow_revocation_generation": "0",
                "workflow_epoch": "x",
                "workflow_id": "x",
                "node_id": "x",
                "attempt_id": "x",
                "issued_at_ms": "0",
                "expires_at_ms": "1",
            },
            "authority_statement_digest": "x",
        },
        "decision": {
            "outcome": "committed",
            "reason": "x",
            "commit_id": "x",
            "nonce": "x",
            "committed_at_ms": "1",
        },
        "bindings": {
            "expected_node_version": "0",
            "committed_node_version": "1",
            "predecessor_root": "x",
            "predecessors": predecessors,
        },
        "signatures": {
            "producer": {"algorithm": "Ed25519", "key_id": "x", "signature_b64u": "x"},
            "policy_authority": {
                "algorithm": "Ed25519",
                "key_id": "x",
                "signature_b64u": "x",
            },
            "authority_registry": {
                "algorithm": "Ed25519",
                "key_id": "x",
                "signature_b64u": "x",
            },
        },
    }


def _replay(
    connection: _AuthorityConnection, commit_id: str, request_digest: str
) -> CommitResult:
    row = connection.execute(
        "SELECT request_digest FROM commit_index WHERE commit_id=?", (commit_id,)
    ).fetchone()
    if row is None:
        return CommitResult(
            CommitDecision(
                commit_id,
                RequestOutcome.DENIED,
                FailureCode.AUTHORITY_FROM_RECOVERY_DENIED,
            ),
            None,
            None,
            None,
            _audit_id("missing", commit_id, request_digest),
        )
    public_replay = connection.execute(
        "SELECT 1 FROM request_index WHERE request_digest=? AND commit_id=?",
        (request_digest, commit_id),
    ).fetchone()
    if row[0] != request_digest and public_replay is None:
        conflict = connection.execute(
            "SELECT audit_event_id FROM commit_conflicts WHERE commit_id=? "
            "AND conflicting_request_digest=?",
            (commit_id, request_digest),
        ).fetchone()
        if conflict is None:
            conflict = connection.execute(
                "SELECT audit_event_id FROM commit_conflicts WHERE commit_id=? "
                "AND conflicting_public_request_digest=?",
                (commit_id, request_digest),
            ).fetchone()
        return CommitResult(
            CommitDecision(
                commit_id, RequestOutcome.CONFLICTED, FailureCode.COMMIT_ID_EQUIVOCATION
            ),
            None,
            None,
            None,
            _row_text(conflict[0])
            if conflict is not None
            else _audit_id("conflict", commit_id, request_digest),
        )
    decision = connection.execute(
        "SELECT outcome, reason, audit_event_id, certificate_digest FROM apcc_decisions WHERE commit_id=?",
        (commit_id,),
    ).fetchone()
    if decision is None:
        raise ValueError("APCC commit index has no decision")
    outcome = RequestOutcome(_row_text(decision[0]))
    if outcome is not RequestOutcome.COMMITTED:
        return CommitResult(
            CommitDecision(commit_id, outcome, FailureCode(_row_text(decision[1]))),
            None,
            None,
            None,
            _row_text(decision[2]),
        )
    certificate = connection.execute(
        "SELECT certificate_json, envelope, certificate_digest FROM certificates WHERE commit_id=?",
        (commit_id,),
    ).fetchone()
    if certificate is None:
        raise ValueError("committed APCC decision has no certificate")
    return CommitResult(
        CommitDecision(commit_id, outcome, _row_text(decision[1])),
        _row_bytes(certificate[0]),
        _row_bytes(certificate[1]),
        _row_optional_text(certificate[2]),
        _row_text(decision[2]),
    )


def _supersession_replay(
    connection: _AuthorityConnection, commit_id: str, request_digest: str
) -> SupersessionResult:
    conflict = connection.execute(
        "SELECT audit_event_id FROM commit_conflicts WHERE commit_id=? AND conflicting_request_digest=?",
        (commit_id, request_digest),
    ).fetchone()
    if conflict is not None:
        result = CommitResult(
            CommitDecision(
                commit_id,
                RequestOutcome.CONFLICTED,
                FailureCode.COMMIT_ID_EQUIVOCATION,
            ),
            None,
            None,
            None,
            _row_text(conflict[0]),
        )
    else:
        indexed = connection.execute(
            "SELECT request_digest FROM commit_index WHERE commit_id=?",
            (commit_id,),
        ).fetchone()
        if indexed is None:
            raise ValueError("APCC supersession has no durable commit identity")
        result = _replay(
            connection,
            commit_id,
            _row_text(indexed[0]),
        )
    audit = connection.execute(
        "SELECT event_json FROM audit_events WHERE audit_event_id=?",
        (result.audit_event_id,),
    ).fetchone()
    if audit is None:
        raise ValueError("APCC supersession has no durable audit identity")
    event = _loads(_row_text(audit[0]))
    if not isinstance(event, dict):
        raise ValueError("APCC supersession audit payload is invalid")
    old = event.get("old_certificate_digest")
    if not isinstance(old, str):
        raise ValueError("APCC result is not a supersession")
    if result.decision.outcome is RequestOutcome.DENIED:
        return SupersessionDenied(result, old)
    if result.decision.outcome is RequestOutcome.CONFLICTED:
        return SupersessionConflicted(result, old)
    assert result.certificate_digest is not None
    edge = connection.execute(
        "SELECT edge_id FROM supersession_edges WHERE new_digest=?",
        (result.certificate_digest,),
    ).fetchone()
    outbox = connection.execute(
        "SELECT event_id FROM apcc_outbox WHERE event_kind='COMMIT' AND operation_id=?",
        (commit_id,),
    ).fetchone()
    if edge is None or outbox is None:
        raise ValueError("committed supersession has incomplete durable identities")
    return SupersessionCommitted(
        result,
        old,
        result.certificate_digest,
        _row_text(edge[0]),
        _row_text(outbox[0]),
    )


def _outbox_id(path: Path, commit_id: str) -> str:
    connection = _connect(path)
    try:
        row = connection.execute(
            "SELECT event_id FROM apcc_outbox WHERE event_kind='COMMIT' AND operation_id=?",
            (commit_id,),
        ).fetchone()
        return row[0] if row else ""
    finally:
        connection.close()
