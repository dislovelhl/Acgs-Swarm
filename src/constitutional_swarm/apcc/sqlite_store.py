"""SQLite realization of the storage-neutral APCC authority port.

The database contains only public configuration and durable authority facts.
Private signing material is supplied by a fresh ``AuthorityRuntime`` to each
writer process and is never persisted.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Iterator, Protocol, cast

from .codec import (
    canonical_statement,
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
from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthorityRuntime,
    AuthorityClock,
    AuthoritySigningRole,
    CommitContext,
    CommitContextRequest,
    CommitResult,
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
    verify_causal_closure,
    verify_historical,
)

_APPLICATION_ID = 0x41504343  # ASCII "APCC"
_SCHEMA_VERSION = 1
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class _FaultProbe(Protocol):
    def hit(self, point: str) -> None: ...


class _SQLitePredecessorResolver:
    """Resolve and adjacency-check certificates in the active write transaction."""

    def __init__(self, connection: sqlite3.Connection) -> None:
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
            payload = bytes(row[1])
            envelope = bytes(row[2])
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


def _has_later_generation_revocation(
    connection: sqlite3.Connection, certificate: CommitCertificate
) -> bool:
    actor = connection.execute(
        "SELECT generation FROM actor_revocations WHERE workflow_id=? AND actor_id=?",
        (certificate.subject.workflow_id, certificate.subject.agent_id),
    ).fetchone()
    if actor is not None and int(actor[0]) > int(
        certificate.context.agent_revocation_generation
    ):
        return True
    workflow = connection.execute(
        "SELECT generation FROM workflow_revocations WHERE workflow_id=?",
        (certificate.subject.workflow_id,),
    ).fetchone()
    return workflow is not None and int(workflow[0]) > int(
        certificate.context.workflow_revocation_generation
    )


def _latest_disposition(
    connection: sqlite3.Connection, certificate_digest: str
) -> CertificateDisposition | None:
    row = connection.execute(
        "SELECT disposition FROM certificate_dispositions "
        "WHERE certificate_digest=? ORDER BY event_sequence DESC LIMIT 1",
        (certificate_digest,),
    ).fetchone()
    return None if row is None else CertificateDisposition(row[0])


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
    connection: sqlite3.Connection,
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


class SQLiteAuthorityReader:
    """Signer-free APCC reader.  It never opens a writer transaction."""

    def __init__(self, path: Path, authority_store_id: str) -> None:
        self.database_path = Path(path)
        self.authority_store_id = authority_store_id

    @classmethod
    def open(cls, path: Path) -> SQLiteAuthorityReader:
        connection = _connect_reader(path)
        try:
            connection.execute("BEGIN")
            config_text = _validate_schema(connection)
            config = _config_from_object(_loads(config_text))
            connection.commit()
            return cls(Path(path), config.authority_store_id)
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
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def read_logical_node(self, workflow_id: str, node_id: str) -> LogicalNodeState:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT version, certificate_digest FROM logical_nodes "
                "WHERE workflow_id = ? AND node_id = ?",
                (workflow_id, node_id),
            ).fetchone()
            if row is None:
                return LogicalNodeState(workflow_id, node_id, "0", None)
            return LogicalNodeState(workflow_id, node_id, str(row[0]), row[1])

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
                    _loads(candidate[1]), _loads(candidate[2]), _loads(candidate[3])
                )
            ).subject
            certificate = CommitCertificate.from_object(
                _certificate_shell(
                    _loads(candidate[1]), _loads(candidate[2]), _loads(candidate[3])
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
                    logical_row[1],
                )
            )
            return CommitContext(
                subject,
                certificate.context,
                CandidateState(
                    request.workflow_id,
                    request.node_id,
                    request.attempt_id,
                    CandidateLifecycle(candidate[0]),
                ),
                logical,
                certificate.bindings.predecessors,
                candidate[4],
            )

    def replay_commit(self, request: ReplayCommitRequest) -> CommitResult:
        with self._read_transaction() as connection:
            return _replay(connection, request.commit_id, request.request_digest)

    def get_certificate(self, commit_id: str) -> bytes | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT envelope FROM certificates WHERE commit_id = ?", (commit_id,)
            ).fetchone()
            return None if row is None else bytes(row[0])

    def get_outbox_event(self, commit_id: str) -> PersistedOutboxEvent:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT event_id, event_json, audit_event_id, delivered FROM apcc_outbox "
                "WHERE event_kind='COMMIT' AND operation_id = ?",
                (commit_id,),
            ).fetchone()
            if row is None:
                raise ValueError("no APCC outbox event for commit")
            return PersistedOutboxEvent(row[0], bytes(row[1]), row[2], not bool(row[3]))


class SQLiteAuthorityStore(SQLiteAuthorityReader):
    """Single-writer, ``BEGIN IMMEDIATE`` APCC authority store."""

    def __init__(
        self,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: _FaultProbe | None = None,
    ) -> None:
        super().__init__(path, config.authority_store_id)
        self._config = config
        self._runtime = runtime
        self._probe = probe

    @classmethod
    def provision(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[CommitContext, ...],
    ) -> None:
        path = Path(path)
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
                for context in initial_contexts:
                    _insert_context(connection, context)
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
    def open(  # type: ignore[override]
        cls, path: Path, config: APCCAuthorityConfig, runtime: AuthorityRuntime
    ) -> SQLiteAuthorityStore:
        return cls._open(path, config, runtime, None)

    @classmethod
    def _open_with_probe(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: _FaultProbe,
    ) -> SQLiteAuthorityStore:
        return cls._open(path, config, runtime, probe)

    @classmethod
    def _open(
        cls,
        path: Path,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        probe: _FaultProbe | None,
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
        finally:
            connection.close()
        if reader.authority_store_id != config.authority_store_id:
            raise ValueError("APCC authority store identity mismatch")
        for role, binding in (
            (AuthoritySigningRole.COMMIT, config.commit_trust),
            (AuthoritySigningRole.STATUS, config.status_trust),
        ):
            if (
                bytes(runtime.key_provider.public_key(role, binding.key_id))
                != binding.public_key
            ):
                raise ValueError(
                    "APCC runtime signer does not match public configuration"
                )
        return cls(Path(path), config, runtime, probe)

    def _hit(self, point: str) -> None:
        if self._probe is not None:
            self._probe.hit(point)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = _connect(self.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def stage_result(self, request: StageResultRequest) -> StageResultResult:
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
                and bytes(row[1]) != request.result_bytes
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
                audit = _audit_id(
                    "stage",
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                    request.subject.output_digest,
                    request.expected_node_version,
                )
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
        return self._commit(request, supersede_old=None)

    def _commit(
        self, request: AtomicCommitRequest, supersede_old: str | None
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
                    return _replay(connection, request.commit_id, request_digest)
                return self._conflict(
                    connection,
                    request.commit_id,
                    request_digest,
                    _public_request_digest(request),
                    request.subject.workflow_id,
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
            self._hit("after_commit_before_response")
        return result

    def _preflight(
        self,
        connection: sqlite3.Connection,
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
        if actor_generation is not None and int(actor_generation[0]) > int(
            request.context.agent_revocation_generation
        ):
            return FailureCode.ACTOR_REVOKED
        workflow_generation = connection.execute(
            "SELECT generation FROM workflow_revocations WHERE workflow_id=?",
            (request.subject.workflow_id,),
        ).fetchone()
        if workflow_generation is not None and int(workflow_generation[0]) > int(
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
                payload = bytes(row[3])
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
        connection: sqlite3.Connection,
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
        connection: sqlite3.Connection,
        commit_id: str,
        digest: str,
        public_request_digest: str,
        conflicting_workflow_id: str,
        conflict_claim_json: str,
        supersede_old: str | None = None,
    ) -> CommitResult:
        audit = _audit_id("conflict", commit_id, digest)
        existing = connection.execute(
            "SELECT audit_event_id FROM commit_conflicts WHERE commit_id=? AND conflicting_request_digest=?",
            (commit_id, digest),
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
                existing[0],
            )
        original = connection.execute(
            "SELECT request_digest, workflow_id FROM commit_index WHERE commit_id=?",
            (commit_id,),
        ).fetchone()
        sequence = connection.execute(
            "SELECT COUNT(*) FROM commit_conflicts WHERE commit_id=?", (commit_id,)
        ).fetchone()
        connection.execute(
            "INSERT INTO commit_conflicts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                commit_id,
                str(original[0]) if original else "",
                digest,
                public_request_digest,
                str(original[1]) if original else "",
                conflicting_workflow_id,
                int(sequence[0]) + 1 if sequence else 1,
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
        with self._transaction() as connection:
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
                prior_generation = int(existing[0]) if existing is not None else 0
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
                prior_generation = int(existing[0]) if existing is not None else 0
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

    def current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus:
        b64u_decode(request_nonce, expected_length=16)
        with self._read_transaction() as connection:
            _validate_semantic_integrity(connection, self._config)
            row = connection.execute(
                "SELECT commit_id, workflow_id, node_id, sequence, certificate_json, envelope "
                "FROM certificates WHERE certificate_digest=?",
                (certificate_digest,),
            ).fetchone()
            if row is None:
                raise ValueError("unknown APCC certificate")
            historical = verify_historical(bytes(row[5]), trust=_trust(self._config))
            if not historical.ok or historical.certificate is None:
                code = (
                    historical.code or FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH
                )
                raise ValueError(code.value)
            certificate = historical.certificate
            payload = bytes(row[4])
            if (
                sha256_digest(payload) != certificate_digest
                or encode_certificate(certificate) != payload
                or certificate.decision.commit_id != row[0]
                or certificate.subject.workflow_id != row[1]
                or certificate.subject.node_id != row[2]
                or isinstance(row[3], bool)
                or not isinstance(row[3], int)
                or certificate.header.certificate_sequence != str(row[3])
            ):
                raise ValueError(
                    FailureCode.AUTHORITY_STATUS_CERTIFICATE_MISMATCH.value
                )
            disposition = _latest_disposition(connection, certificate_digest)
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
            if self._persisted_causal_error(connection, certificate_digest) is not None:
                status_value = AuthorityStatusValue.REVOKED
            # These fields bind the certificate's issuance generation.  A later
            # revocation is represented by the signed current-status value, not
            # by rewriting historical certificate context.
            actor_generation = certificate.context.agent_revocation_generation
            workflow_generation = certificate.context.workflow_revocation_generation
            if _has_later_generation_revocation(connection, certificate):
                status_value = AuthorityStatusValue.REVOKED
            latest = connection.execute(
                "SELECT sequence, entry_digest FROM trust_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest is None:
                seq, head = "0", sha256_digest(b"APCC-1/trust-log/genesis")
            else:
                seq, head = str(latest[0]), latest[1]
            now_value = _trusted_now(self._runtime.clock)
            lifetime = int(self._config.freshness.issued_status_lifetime_ms)
            if now_value > _MAX_SAFE_INTEGER - lifetime:
                raise ValueError(FailureCode.INVALID_DECIMAL_STRING.value)
            now = str(now_value)
            next_update = str(now_value + lifetime)
            unsigned = AuthorityStatus(
                "APCC-1.0-draft",
                "apcc.authority-status",
                self.authority_store_id,
                self._config.status_trust.key_id,
                request_nonce,
                certificate_digest,
                str(row[3]),
                seq,
                head,
                status_value,
                actor_generation,
                workflow_generation,
                superseded,
                now,
                next_update,
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
            return replace(unsigned, signature=signature)

    def _request_causal_error(
        self, connection: sqlite3.Connection, root: CommitCertificate
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
        resolver = _SQLitePredecessorResolver(connection)
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
        self, connection: sqlite3.Connection, digest: str
    ) -> FailureCode | None:
        resolver = _SQLitePredecessorResolver(connection)
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
                _validate_semantic_integrity(connection, self._config)
                head = connection.execute(
                    "SELECT event_sequence,event_id,event_json,state,lease_until_ms "
                    "FROM apcc_outbox WHERE state<>'DELIVERED' "
                    "ORDER BY event_sequence LIMIT 1"
                ).fetchone()
                if head is None or (
                    head[3] == "CLAIMED" and head[4] is not None and int(head[4]) > now
                ):
                    connection.commit()
                    break
                claimed = connection.execute(
                    "UPDATE apcc_outbox SET state='CLAIMED',lease_token=?,lease_claimed_ms=?,lease_until_ms=?,delivered=0 "
                    "WHERE event_sequence=? AND (state='PENDING' OR (state='CLAIMED' AND lease_until_ms<=?))",
                    (token, now, now + lease_ms, head[0], now),
                ).rowcount
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
                    release.execute(
                        "UPDATE apcc_outbox SET state='PENDING',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=0 "
                        "WHERE event_id=? AND state='CLAIMED' AND lease_token=?",
                        (event_id, token),
                    )
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
                changed = finalize.execute(
                    "UPDATE apcc_outbox SET state='DELIVERED',lease_token=NULL,lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=1 "
                    "WHERE event_id=? AND state='CLAIMED' AND lease_token=?",
                    (event_id, token),
                ).rowcount
                if changed == 1:
                    delivered_ids.append(event_id)
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
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return OutboxRecoveryResult(str(len(delivered_ids)), str(pending), audit)

    def _next_sequence(self, connection: sqlite3.Connection) -> str:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM certificates"
        ).fetchone()
        sequence = int(row[0]) + 1
        if sequence > _MAX_SAFE_INTEGER:
            raise ValueError(FailureCode.SIZE_LIMIT_EXCEEDED.value)
        return str(sequence)

    def _append_trust(
        self,
        connection: sqlite3.Connection,
        kind: str,
        subject: str,
        audit_event_id: str,
    ) -> tuple[str, str]:
        previous = connection.execute(
            "SELECT sequence, entry_digest FROM trust_log ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous[0]) + 1 if previous else 1
        prior = previous[1] if previous else sha256_digest(b"APCC-1/trust-log/genesis")
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


_SCHEMA_STATEMENTS = (
    "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE logical_nodes (workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, version TEXT NOT NULL CHECK(version <> '' AND version NOT GLOB '*[^0-9]*' AND (version='0' OR version NOT GLOB '0*')), certificate_digest TEXT REFERENCES certificates(certificate_digest) DEFERRABLE INITIALLY DEFERRED, PRIMARY KEY(workflow_id,node_id))",
    "CREATE TABLE candidates (workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, attempt_id TEXT NOT NULL, agent_id TEXT NOT NULL, lifecycle TEXT NOT NULL CHECK(lifecycle IN ('EXECUTING','RESULT_STAGED','EVIDENCE_ASSEMBLED','COMMIT_PENDING','QUARANTINED')), expected_version TEXT NOT NULL, result BLOB, subject_json TEXT NOT NULL, context_json TEXT NOT NULL, predecessors_json TEXT NOT NULL, proposal_digest TEXT, audit_event_id TEXT NOT NULL, proposal_json TEXT, PRIMARY KEY(workflow_id,node_id,attempt_id))",
    "CREATE TABLE commit_index (commit_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, workflow_id TEXT NOT NULL, request_json TEXT NOT NULL)",
    "CREATE TABLE request_index (request_digest TEXT PRIMARY KEY, commit_id TEXT NOT NULL UNIQUE REFERENCES commit_index(commit_id))",
    "CREATE TABLE nonce_ledger (nonce TEXT PRIMARY KEY NOT NULL, commit_id TEXT NOT NULL UNIQUE REFERENCES commit_index(commit_id))",
    "CREATE TABLE evidence_refs (commit_id TEXT PRIMARY KEY REFERENCES commit_index(commit_id), producer_digest TEXT NOT NULL, policy_digest TEXT NOT NULL, authority_digest TEXT NOT NULL)",
    f"CREATE TABLE certificates (certificate_digest TEXT PRIMARY KEY NOT NULL, commit_id TEXT UNIQUE NOT NULL REFERENCES commit_index(commit_id), certificate_json BLOB NOT NULL, envelope BLOB NOT NULL, workflow_id TEXT NOT NULL, node_id TEXT NOT NULL, sequence INTEGER NOT NULL UNIQUE CHECK(typeof(sequence)='integer' AND sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}))",
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
    "CREATE TABLE commit_conflicts (commit_id TEXT NOT NULL, original_request_digest TEXT NOT NULL, conflicting_request_digest TEXT NOT NULL, conflicting_public_request_digest TEXT NOT NULL, original_workflow_id TEXT NOT NULL, conflicting_workflow_id TEXT NOT NULL, observation_sequence INTEGER NOT NULL, audit_event_id TEXT NOT NULL, conflict_claim_json TEXT NOT NULL, PRIMARY KEY(commit_id, conflicting_request_digest))",
    "CREATE TRIGGER certificate_dispositions_no_update BEFORE UPDATE ON certificate_dispositions BEGIN SELECT RAISE(ABORT, 'certificate dispositions are append-only'); END",
    "CREATE TRIGGER certificate_dispositions_no_delete BEFORE DELETE ON certificate_dispositions BEGIN SELECT RAISE(ABORT, 'certificate dispositions are append-only'); END",
    "CREATE TRIGGER certificate_dispositions_validate_insert BEFORE INSERT ON certificate_dispositions WHEN NOT ((NEW.event_sequence=1 AND NEW.disposition='CURRENT' AND NOT EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest)) OR (NEW.event_sequence=2 AND NEW.disposition IN ('REVOKED','SUPERSEDED') AND EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest AND event_sequence=1 AND disposition='CURRENT') AND NOT EXISTS (SELECT 1 FROM certificate_dispositions WHERE certificate_digest=NEW.certificate_digest AND event_sequence=2))) BEGIN SELECT RAISE(ABORT, 'invalid certificate disposition transition'); END",
    "CREATE TRIGGER trust_log_no_update BEFORE UPDATE ON trust_log BEGIN SELECT RAISE(ABORT, 'trust log is append-only'); END",
    "CREATE TRIGGER trust_log_no_delete BEFORE DELETE ON trust_log BEGIN SELECT RAISE(ABORT, 'trust log is append-only'); END",
    "CREATE TRIGGER control_events_no_update BEFORE UPDATE ON control_events BEGIN SELECT RAISE(ABORT, 'control events are immutable'); END",
    "CREATE TRIGGER control_events_no_delete BEFORE DELETE ON control_events BEGIN SELECT RAISE(ABORT, 'control events are immutable'); END",
    "CREATE TRIGGER apcc_outbox_identity_no_update BEFORE UPDATE ON apcc_outbox WHEN NEW.event_sequence<>OLD.event_sequence OR NEW.event_id<>OLD.event_id OR NEW.event_kind<>OLD.event_kind OR NEW.operation_id<>OLD.operation_id OR NEW.event_json<>OLD.event_json OR NEW.audit_event_id<>OLD.audit_event_id OR NEW.trust_sequence<>OLD.trust_sequence BEGIN SELECT RAISE(ABORT, 'outbox identity is immutable'); END",
    "CREATE TRIGGER apcc_outbox_no_delete BEFORE DELETE ON apcc_outbox BEGIN SELECT RAISE(ABORT, 'outbox is append-only'); END",
    "CREATE INDEX idx_apcc_outbox_pending ON apcc_outbox(state,lease_until_ms,event_sequence)",
    "CREATE INDEX idx_apcc_outbox_head ON apcc_outbox(event_sequence) WHERE state<>'DELIVERED'",
    "CREATE INDEX idx_nonce_ledger_nonce ON nonce_ledger(nonce)",
    "CREATE INDEX idx_supersession_new_digest ON supersession_edges(new_digest)",
)


def _normalize_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


_SCHEMA_FINGERPRINT = sha256_digest(
    "\n".join(_normalize_schema_sql(item) for item in _SCHEMA_STATEMENTS).encode()
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


def _validate_schema(connection: sqlite3.Connection) -> str:
    invalid = ValueError("APCC SQLite store schema validation failed")
    if connection.execute("PRAGMA journal_mode").fetchone() != ("wal",):
        raise invalid
    if connection.execute("PRAGMA application_id").fetchone() != (_APPLICATION_ID,):
        raise invalid
    if connection.execute("PRAGMA user_version").fetchone() != (_SCHEMA_VERSION,):
        raise invalid
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
            "SELECT key, value FROM metadata WHERE key IN ('config','schema_fingerprint')"
        )
    }
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
    parsed_config = _config_from_object(config_object)
    _validate_semantic_integrity(connection, parsed_config)
    return config


def _validate_semantic_integrity(
    connection: sqlite3.Connection, config: APCCAuthorityConfig
) -> None:
    invalid = ValueError("APCC SQLite store semantic validation failed")
    certificates: dict[str, CommitCertificate] = {}
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
            detached = decode_envelope(bytes(envelope))
            if (
                detached.payload != bytes(payload)
                or detached.payload_sha256 != digest
                or sha256_digest(bytes(payload)) != digest
            ):
                raise invalid
            certificate = decode_certificate(bytes(payload))
            historical = verify_historical(bytes(envelope), trust=_trust(config))
            if not historical.ok or historical.certificate != certificate:
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

    latest: dict[str, CertificateDisposition] = {}
    for digest, event_sequence, disposition in connection.execute(
        "SELECT certificate_digest, event_sequence, disposition FROM certificate_dispositions ORDER BY certificate_digest,event_sequence"
    ):
        if digest not in certificates:
            raise invalid
        current = CertificateDisposition(disposition)
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
        elif result is None or sha256_digest(bytes(result)) != subject.output_digest:
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
                workflow,
                node,
                attempt,
                subject.output_digest,
                expected_version,
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
        if (
            not isinstance(sequence, int)
            or sequence != expected
            or sequence > _MAX_SAFE_INTEGER
            or audit_id not in audits
            or prior_digest != trust_prior
        ):
            raise invalid
        try:
            entry = _loads(entry_json)
        except Exception as error:
            raise invalid from error
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {"sequence", "prior_digest", "kind", "subject", "audit_event_id"}
            or entry_json != _json(entry)
            or entry.get("sequence") != str(sequence)
            or entry.get("prior_digest") != trust_prior
            or entry.get("audit_event_id") != audit_id
            or entry.get("kind") not in {"commit", "control"}
            or not isinstance(entry.get("subject"), str)
            or sha256_digest(entry_json.encode("utf-8")) != entry_digest
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

    superseded_new: set[str] = set()
    outgoing: dict[str, str] = {}
    incoming: dict[str, str] = {}
    for edge_id, old_digest, new_digest, nonce in connection.execute(
        "SELECT edge_id,old_digest,new_digest,nonce FROM supersession_edges"
    ):
        old = certificates.get(str(old_digest))
        new = certificates.get(str(new_digest))
        if old is None or new is None:
            raise invalid
        decision = decisions.get(new.decision.commit_id)
        try:
            audit_object = _loads(audits[decision[2]]) if decision is not None else None
        except Exception as error:
            raise invalid from error
        operation = commit_index[new.decision.commit_id]
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
            or operation[3] != old_digest
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
        (
            operation,
            scope,
            workflow,
            target,
            generation,
            claimed_generation,
            reason,
            audit,
            payload,
            digest,
        ) = row
        payload_bytes = bytes(payload)
        control_object = {
            "scope": scope,
            "workflow_id": workflow,
            "target_id": target,
            "generation": generation,
            "claimed_generation": claimed_generation,
            "reason": reason,
            "audit_event_id": audit,
        }
        expected_audit = _audit_id(
            "revoke",
            str(scope),
            str(workflow),
            str(target),
            str(claimed_generation),
        )
        expected_audit_object = {
            "kind": "revoked",
            "subject": target,
            "scope": scope,
            "workflow_id": workflow,
            **({"generation": generation} if generation is not None else {}),
        }
        if (
            operation != expected_audit
            or audit != expected_audit
            or audits.get(str(audit)) != _json(expected_audit_object)
            or payload_bytes != _json(control_object).encode("utf-8")
            or sha256_digest(payload_bytes) != digest
        ):
            raise invalid
        if scope == RevocationScope.CERTIFICATE.value:
            if (
                generation is not None
                or latest.get(str(target)) is not CertificateDisposition.REVOKED
            ):
                raise invalid
        else:
            try:
                canonical = str(
                    _canonical_positive_decimal(generation, maximum=_MAX_SAFE_INTEGER)
                )
            except ValueError as error:
                raise invalid from error
            if canonical != generation:
                raise invalid
        controls[str(operation)] = (
            str(scope),
            str(workflow),
            str(target),
            generation,
            str(audit),
            payload_bytes,
            str(digest),
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
        (str(workflow), str(actor)): int(generation)
        for workflow, actor, generation in connection.execute(
            "SELECT workflow_id,actor_id,generation FROM actor_revocations"
        )
    }
    actual_workflow = {
        str(workflow): int(generation)
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
        (
            sequence,
            event_id,
            kind,
            operation,
            payload,
            audit,
            trust_sequence,
            state,
            token,
            claimed,
            lease,
            delivered,
        ) = row
        if sequence != trust_sequence or trust_by_sequence.get(int(sequence)) is None:
            raise invalid
        trust_kind, trust_subject, trust_audit = trust_by_sequence[int(sequence)]
        if audit != trust_audit:
            raise invalid
        if kind == "COMMIT":
            decision = decisions.get(str(operation))
            if decision is None or decision[0] != RequestOutcome.COMMITTED.value:
                raise invalid
            digest = str(decision[3])
            certificate = certificates[digest]
            expected_payload = encode_certificate(certificate)
            if (
                audit != decision[2]
                or trust_kind != "commit"
                or trust_subject != digest
                or event_id != _audit_id("outbox", "COMMIT", str(operation), digest)
            ):
                raise invalid
            seen_commits.add(str(operation))
        else:
            control = controls.get(str(operation))
            if control is None:
                raise invalid
            expected_payload = control[5]
            if (
                audit != control[4]
                or trust_kind != "control"
                or trust_subject != operation
                or event_id
                != _audit_id("outbox", "CONTROL", str(operation), control[6])
            ):
                raise invalid
            seen_controls.add(str(operation))
        if bytes(payload) != expected_payload or not (
            (
                state == "PENDING"
                and delivered == 0
                and token is None
                and claimed is None
                and lease is None
            )
            or (
                state == "CLAIMED"
                and delivered == 0
                and token is not None
                and claimed is not None
                and lease is not None
                and lease >= claimed
            )
            or (
                state == "DELIVERED"
                and delivered == 1
                and token is None
                and claimed is None
                and lease is None
            )
        ):
            raise invalid
        for timestamp in (claimed, lease):
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
        conflicting,
        public,
        original_workflow,
        conflicting_workflow,
        sequence,
        audit,
        claim_json,
    ) in connection.execute(
        "SELECT commit_id,original_request_digest,conflicting_request_digest,conflicting_public_request_digest,original_workflow_id,conflicting_workflow_id,observation_sequence,audit_event_id,conflict_claim_json FROM commit_conflicts"
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
                supersede_old = claim["supersede_old"]
            elif claim.get("kind") == "recovery" and set(claim) == {
                "kind",
                "commit_id",
                "request_digest",
            }:
                expected_conflicting = str(claim["request_digest"])
                expected_public = expected_conflicting
                conflict_workflow_expected = ""
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
            or original_workflow != indexed[1]
            or conflicting != expected_conflicting
            or public != expected_public
            or conflicting_workflow != conflict_workflow_expected
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


def _schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)


def _insert_context(connection: sqlite3.Connection, context: CommitContext) -> None:
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
    connection: sqlite3.Connection, commit_id: str, request_digest: str
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
            "AND (conflicting_request_digest=? OR conflicting_public_request_digest=?)",
            (commit_id, request_digest, request_digest),
        ).fetchone()
        return CommitResult(
            CommitDecision(
                commit_id, RequestOutcome.CONFLICTED, FailureCode.COMMIT_ID_EQUIVOCATION
            ),
            None,
            None,
            None,
            conflict[0]
            if conflict is not None
            else _audit_id("conflict", commit_id, request_digest),
        )
    decision = connection.execute(
        "SELECT outcome, reason, audit_event_id, certificate_digest FROM apcc_decisions WHERE commit_id=?",
        (commit_id,),
    ).fetchone()
    if decision is None:
        raise ValueError("APCC commit index has no decision")
    outcome = RequestOutcome(decision[0])
    if outcome is not RequestOutcome.COMMITTED:
        return CommitResult(
            CommitDecision(commit_id, outcome, FailureCode(decision[1])),
            None,
            None,
            None,
            decision[2],
        )
    certificate = connection.execute(
        "SELECT certificate_json, envelope, certificate_digest FROM certificates WHERE commit_id=?",
        (commit_id,),
    ).fetchone()
    if certificate is None:
        raise ValueError("committed APCC decision has no certificate")
    return CommitResult(
        CommitDecision(commit_id, outcome, decision[1]),
        bytes(certificate[0]),
        bytes(certificate[1]),
        certificate[2],
        decision[2],
    )


def _supersession_replay(
    connection: sqlite3.Connection, commit_id: str, request_digest: str
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
            conflict[0],
        )
    else:
        result = _replay(
            connection,
            commit_id,
            cast(
                str,
                connection.execute(
                    "SELECT request_digest FROM commit_index WHERE commit_id=?",
                    (commit_id,),
                ).fetchone()[0],
            ),
        )
    audit = connection.execute(
        "SELECT event_json FROM audit_events WHERE audit_event_id=?",
        (result.audit_event_id,),
    ).fetchone()
    if audit is None:
        raise ValueError("APCC supersession has no durable audit identity")
    event = cast("dict[str, object]", _loads(audit[0]))
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
        result, old, result.certificate_digest, edge[0], outbox[0]
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
