"""PostgreSQL 17 realization of the APCC authority store."""

from __future__ import annotations

import re
import secrets
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Protocol, TypeVar, cast

import psycopg
from psycopg import sql

from .model import AuthorityStatus, CommitDecision, FailureCode, RequestOutcome
from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthoritySigningRole,
    AuthorityRuntime,
    AuthorityObservationStatusSigner,
    CommitContext,
    CommitResult,
    CurrentStatusRequest,
    OutboxRecoveryRequest,
    OutboxRecoveryResult,
    ProposeCommitRequest,
    ProposeCommitResult,
    RecoveryRequest,
    RevocationRequest,
    RevocationResult,
    RevocationScope,
    SupersessionRequest,
    SupersessionResult,
    StageResultRequest,
    StageResultResult,
)
from .crypto import sha256_digest
from .sqlite_store import (
    _AUTHORITY_SCHEMA_VERSION,
    _AuthorityReaderCore,
    _AuthorityStoreCore,
    _SEMANTIC_CHECKPOINT_GENESIS,
    _SemanticSnapshot,
    _SCHEMA_VERSION_INCOMPATIBLE,
    _MAX_SAFE_INTEGER,
    _audit_id,
    _canonical_positive_decimal,
    _checkpoint_semantic_snapshot,
    _config_from_object,
    _config_object,
    _insert_context,
    _json,
    _loads,
    _operation_identity,
    _replay,
    _seal_semantic_checkpoint,
    _supersession_replay,
    _trusted_now,
    _validate_semantic_integrity,
    _verify_semantic_checkpoint,
    _write_audit,
)

_SCHEMA_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
_RESERVED_SCHEMAS = frozenset({"public", "pg_catalog", "information_schema"})
_RESERVED_ROLES = frozenset(
    {"public", "current_role", "current_user", "session_user", "none"}
)
_RETRYABLE_SQLSTATES = frozenset({"40001", "40P01"})
_AMBIGUOUS_SQLSTATES = frozenset({"40003", "08007"})
_LEASE_DURATION_MS = 30_000
_COMPATIBILITY_IDENTIFIERS = {
    "apcc_decisions": "decisions",
    "apcc_outbox": "outbox",
}
_BASE_CATALOG_PROFILE = "apcc-base-v1"
_GCB_CATALOG_PROFILE = "gcb-attached-v1"
_ResultT = TypeVar("_ResultT")


class _Probe(Protocol):
    def hit(self, point: str, connection: object) -> None: ...


@dataclass(frozen=True, slots=True)
class PostgresRetryPolicy:
    max_attempts: int = 3

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")


class _Cursor:
    def __init__(self, cursor: psycopg.Cursor[tuple[object, ...]]) -> None:
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self) -> tuple[object, ...] | None:
        return self._cursor.fetchone()

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._cursor.fetchall()

    def __iter__(self) -> Iterator[tuple[object, ...]]:
        return iter(self._cursor)


class _Connection:
    def __init__(self, raw: psycopg.Connection[tuple[object, ...]]) -> None:
        self.raw = raw
        self.checkpoint_attested = False

    def execute(self, query: str, parameters: tuple[object, ...] = ()) -> _Cursor:
        adapted = _adapt_sql(query)
        cursor = self.raw.execute(adapted.encode("utf-8"), parameters or None)
        return _Cursor(cursor)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()


def _validate_schema_name(schema: str) -> None:
    folded = schema.casefold()
    if (
        _SCHEMA_RE.fullmatch(schema) is None
        or folded in _RESERVED_SCHEMAS
        or folded.startswith("pg_")
    ):
        raise ValueError("unsafe APCC PostgreSQL schema name")


def _validate_role_name(role: str) -> None:
    folded = role.casefold()
    if (
        _SCHEMA_RE.fullmatch(role) is None
        or folded in _RESERVED_ROLES
        or folded.startswith("pg_")
    ):
        raise ValueError("unsafe APCC PostgreSQL role name")


def _quoted_identifier(identifier: str) -> str:
    if _SCHEMA_RE.fullmatch(identifier) is None:
        raise ValueError("unsafe APCC PostgreSQL identifier")
    return f'"{identifier}"'


def _connect(dsn: str, schema: str, *, autocommit: bool = False) -> _Connection:
    _validate_schema_name(schema)
    raw = psycopg.connect(dsn, autocommit=True)
    try:
        raw.execute(
            sql.SQL("SET search_path TO pg_catalog, {}, pg_temp").format(
                sql.Identifier(schema)
            )
        )
        if not autocommit:
            raw.autocommit = False
        return _Connection(raw)
    except Exception:
        raw.close()
        raise


def _replace_compatibility_tokens(query: str) -> str:
    """Translate the bounded SQLite dialect outside literals and comments."""

    output: list[str] = []
    index = 0
    quote: str | None = None
    dollar_tag: str | None = None
    while index < len(query):
        character = query[index]
        pair = query[index : index + 2]
        if dollar_tag is not None:
            if query.startswith(dollar_tag, index):
                output.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
            else:
                output.append(character)
                index += 1
            continue
        if quote is not None:
            output.append(character)
            index += 1
            if character == quote:
                if index < len(query) and query[index] == quote:
                    output.append(query[index])
                    index += 1
                else:
                    quote = None
            continue
        if pair == "--":
            newline = query.find("\n", index)
            if newline < 0:
                output.append(query[index:])
                break
            output.append(query[index:newline])
            index = newline
            continue
        if pair == "/*":
            end = query.find("*/", index + 2)
            if end < 0:
                output.append(query[index:])
                break
            output.append(query[index : end + 2])
            index = end + 2
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(character)
            index += 1
            continue
        if character == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", query[index:])
            if match is not None:
                dollar_tag = match.group(0)
                output.append(dollar_tag)
                index += len(dollar_tag)
                continue
        if character == "?":
            output.append("%s")
            index += 1
            continue
        if character.isascii() and (character.isalpha() or character == "_"):
            end = index + 1
            while end < len(query):
                token_character = query[end]
                if not (
                    token_character.isascii()
                    and (token_character.isalnum() or token_character == "_")
                ):
                    break
                end += 1
            token = query[index:end]
            output.append(_COMPATIBILITY_IDENTIFIERS.get(token.casefold(), token))
            index = end
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _adapt_sql(query: str) -> str:
    query = _replace_compatibility_tokens(query)
    if re.match(r"\s*INSERT\s+OR\s+REPLACE\s+INTO\s+actor_revocations\b", query):
        query = re.sub(r"INSERT\s+OR\s+REPLACE", "INSERT", query, count=1)
        query += (
            " ON CONFLICT (workflow_id,actor_id) DO UPDATE "
            "SET generation=EXCLUDED.generation"
        )
    elif re.match(r"\s*INSERT\s+OR\s+REPLACE\s+INTO\s+workflow_revocations\b", query):
        query = re.sub(r"INSERT\s+OR\s+REPLACE", "INSERT", query, count=1)
        query += (
            " ON CONFLICT (workflow_id) DO UPDATE SET generation=EXCLUDED.generation"
        )
    if query.strip().upper() == "BEGIN IMMEDIATE":
        query = "BEGIN"
    return query


_POSTGRES_TABLES = (
    """CREATE TABLE metadata (
        key TEXT CONSTRAINT metadata_pkey PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE commit_index (
        commit_id TEXT CONSTRAINT commit_index_pkey PRIMARY KEY,
        request_digest TEXT NOT NULL,
        workflow_id TEXT NOT NULL,
        request_json TEXT NOT NULL
    )""",
    """CREATE TABLE audit_events (
        audit_event_id TEXT CONSTRAINT audit_events_pkey PRIMARY KEY,
        event_json TEXT NOT NULL
    )""",
    f"""CREATE TABLE certificates (
        certificate_digest TEXT CONSTRAINT certificates_pkey PRIMARY KEY,
        commit_id TEXT NOT NULL CONSTRAINT certificates_commit_id_key UNIQUE
            REFERENCES commit_index(commit_id),
        certificate_json BYTEA NOT NULL,
        envelope BYTEA NOT NULL,
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        sequence BIGINT NOT NULL CONSTRAINT certificates_sequence_key UNIQUE,
        CONSTRAINT certificates_sequence_check
            CHECK (sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER})
    )""",
    """CREATE TABLE logical_nodes (
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        version TEXT NOT NULL,
        certificate_digest TEXT,
        CONSTRAINT logical_nodes_pkey PRIMARY KEY (workflow_id,node_id),
        CONSTRAINT logical_nodes_version_check CHECK (
            version ~ '^(0|[1-9][0-9]*)$'
            AND length(version) <= 16
            AND version::numeric <= 9007199254740991
        ),
        CONSTRAINT logical_nodes_certificate_digest_fkey
            FOREIGN KEY (certificate_digest)
            REFERENCES certificates(certificate_digest)
            DEFERRABLE INITIALLY DEFERRED
    )""",
    """CREATE TABLE candidates (
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        lifecycle TEXT NOT NULL,
        expected_version TEXT NOT NULL,
        result BYTEA,
        subject_json TEXT NOT NULL,
        context_json TEXT NOT NULL,
        predecessors_json TEXT NOT NULL,
        proposal_digest TEXT,
        audit_event_id TEXT NOT NULL,
        proposal_json TEXT,
        CONSTRAINT candidates_pkey PRIMARY KEY (workflow_id,node_id,attempt_id),
        CONSTRAINT candidates_lifecycle_check CHECK (
            lifecycle IN (
                'EXECUTING','RESULT_STAGED','EVIDENCE_ASSEMBLED',
                'COMMIT_PENDING','QUARANTINED'
            )
        )
    )""",
    f"""CREATE TABLE commit_output_refs (
        commit_id TEXT CONSTRAINT commit_output_refs_pkey PRIMARY KEY
            REFERENCES certificates(commit_id),
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        output_digest TEXT NOT NULL,
        output_size BIGINT NOT NULL,
        CONSTRAINT commit_output_refs_output_size_check
            CHECK (output_size BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT commit_output_refs_candidate_fkey
            FOREIGN KEY (workflow_id,node_id,attempt_id)
            REFERENCES candidates(workflow_id,node_id,attempt_id)
    )""",
    """CREATE TABLE request_index (
        request_digest TEXT CONSTRAINT request_index_pkey PRIMARY KEY,
        commit_id TEXT NOT NULL CONSTRAINT request_index_commit_id_key UNIQUE
            REFERENCES commit_index(commit_id)
    )""",
    """CREATE TABLE nonce_ledger (
        nonce TEXT CONSTRAINT nonce_ledger_pkey PRIMARY KEY,
        commit_id TEXT NOT NULL CONSTRAINT nonce_ledger_commit_id_key UNIQUE
            REFERENCES commit_index(commit_id)
    )""",
    """CREATE TABLE evidence_refs (
        commit_id TEXT CONSTRAINT evidence_refs_pkey PRIMARY KEY
            REFERENCES commit_index(commit_id),
        producer_digest TEXT NOT NULL,
        policy_digest TEXT NOT NULL,
        authority_digest TEXT NOT NULL
    )""",
    """CREATE TABLE decisions (
        commit_id TEXT CONSTRAINT decisions_pkey PRIMARY KEY
            REFERENCES commit_index(commit_id),
        outcome TEXT NOT NULL,
        reason TEXT NOT NULL,
        audit_event_id TEXT NOT NULL CONSTRAINT decisions_audit_event_id_key UNIQUE
            REFERENCES audit_events(audit_event_id),
        certificate_digest TEXT,
        nonce TEXT NOT NULL,
        nonce_owner_commit_id TEXT NOT NULL,
        CONSTRAINT decisions_outcome_check
            CHECK (outcome IN ('COMMITTED','DENIED','CONFLICTED')),
        CONSTRAINT decisions_certificate_shape
            CHECK ((outcome='COMMITTED')=(certificate_digest IS NOT NULL)),
        CONSTRAINT decisions_certificate_digest_fkey
            FOREIGN KEY (certificate_digest)
            REFERENCES certificates(certificate_digest)
            DEFERRABLE INITIALLY DEFERRED,
        CONSTRAINT decisions_nonce_owner_commit_id_fkey
            FOREIGN KEY (nonce_owner_commit_id)
            REFERENCES commit_index(commit_id)
            DEFERRABLE INITIALLY DEFERRED
    )""",
    """CREATE TABLE certificate_dispositions (
        certificate_digest TEXT NOT NULL
            REFERENCES certificates(certificate_digest),
        event_sequence BIGINT NOT NULL,
        disposition TEXT NOT NULL,
        CONSTRAINT certificate_dispositions_pkey
            PRIMARY KEY (certificate_digest,event_sequence),
        CONSTRAINT certificate_dispositions_sequence_check
            CHECK (event_sequence IN (1,2)),
        CONSTRAINT certificate_dispositions_value_check
            CHECK (disposition IN ('CURRENT','REVOKED','SUPERSEDED'))
    )""",
    """CREATE TABLE predecessor_edges (
        child_commit_id TEXT NOT NULL REFERENCES certificates(commit_id),
        predecessor_digest TEXT NOT NULL REFERENCES certificates(certificate_digest),
        CONSTRAINT predecessor_edges_pkey
            PRIMARY KEY (child_commit_id,predecessor_digest)
    )""",
    """CREATE TABLE supersession_edges (
        edge_id TEXT CONSTRAINT supersession_edges_pkey PRIMARY KEY,
        old_digest TEXT NOT NULL REFERENCES certificates(certificate_digest),
        new_digest TEXT NOT NULL REFERENCES certificates(certificate_digest),
        nonce TEXT NOT NULL
    )""",
    f"""CREATE TABLE workflow_revocations (
        workflow_id TEXT CONSTRAINT workflow_revocations_pkey PRIMARY KEY,
        generation TEXT NOT NULL,
        CONSTRAINT workflow_revocations_generation_check CHECK (
            generation ~ '^[1-9][0-9]{{0,15}}$'
            AND generation::numeric <= {_MAX_SAFE_INTEGER}
        )
    )""",
    f"""CREATE TABLE actor_revocations (
        workflow_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        generation TEXT NOT NULL,
        CONSTRAINT actor_revocations_pkey PRIMARY KEY (workflow_id,actor_id),
        CONSTRAINT actor_revocations_generation_check CHECK (
            generation ~ '^[1-9][0-9]{{0,15}}$'
            AND generation::numeric <= {_MAX_SAFE_INTEGER}
        )
    )""",
    f"""CREATE TABLE trust_log (
        sequence BIGINT CONSTRAINT trust_log_pkey PRIMARY KEY,
        audit_event_id TEXT NOT NULL CONSTRAINT trust_log_audit_event_id_key UNIQUE
            REFERENCES audit_events(audit_event_id),
        prior_digest TEXT NOT NULL,
        entry_digest TEXT NOT NULL CONSTRAINT trust_log_entry_digest_key UNIQUE,
        entry_json TEXT NOT NULL,
        CONSTRAINT trust_log_sequence_check
            CHECK (sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER})
    )""",
    """CREATE TABLE control_events (
        operation_id TEXT CONSTRAINT control_events_pkey PRIMARY KEY,
        scope TEXT NOT NULL,
        workflow_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        generation TEXT,
        claimed_generation TEXT NOT NULL,
        reason TEXT NOT NULL,
        audit_event_id TEXT NOT NULL CONSTRAINT control_events_audit_event_id_key
            UNIQUE REFERENCES audit_events(audit_event_id),
        payload BYTEA NOT NULL,
        payload_digest TEXT NOT NULL CONSTRAINT control_events_payload_digest_key
            UNIQUE,
        CONSTRAINT control_events_scope_check
            CHECK (scope IN ('CERTIFICATE','ACTOR','WORKFLOW')),
        CONSTRAINT control_events_generation_shape
            CHECK ((scope='CERTIFICATE')=(generation IS NULL))
    )""",
    f"""CREATE TABLE outbox (
        event_sequence BIGINT CONSTRAINT outbox_pkey PRIMARY KEY,
        event_id TEXT NOT NULL CONSTRAINT outbox_event_id_key UNIQUE,
        event_kind TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        event_json BYTEA NOT NULL,
        audit_event_id TEXT NOT NULL CONSTRAINT outbox_audit_event_id_key UNIQUE
            REFERENCES audit_events(audit_event_id),
        trust_sequence BIGINT NOT NULL CONSTRAINT outbox_trust_sequence_key UNIQUE
            REFERENCES trust_log(sequence),
        state TEXT NOT NULL,
        lease_token TEXT,
        lease_claimed_ms BIGINT,
        lease_until_ms BIGINT,
        delivered SMALLINT NOT NULL,
        commit_id TEXT GENERATED ALWAYS AS (
            CASE WHEN event_kind='COMMIT' THEN operation_id ELSE NULL END
        ) STORED,
        CONSTRAINT outbox_event_kind_check CHECK (event_kind IN ('COMMIT','CONTROL')),
        CONSTRAINT outbox_sequence_check
            CHECK (event_sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT outbox_claimed_time_check CHECK (
            lease_claimed_ms IS NULL
            OR lease_claimed_ms BETWEEN 0 AND {_MAX_SAFE_INTEGER}
        ),
        CONSTRAINT outbox_lease_time_check CHECK (
            lease_until_ms IS NULL
            OR lease_until_ms BETWEEN 0 AND {_MAX_SAFE_INTEGER}
        ),
        CONSTRAINT outbox_delivered_check CHECK (delivered IN (0,1)),
        CONSTRAINT outbox_event_operation_key UNIQUE (event_kind,operation_id),
        CONSTRAINT outbox_state_shape CHECK (
            (state='PENDING' AND delivered=0 AND lease_token IS NULL
                AND lease_claimed_ms IS NULL AND lease_until_ms IS NULL)
            OR (state='CLAIMED' AND delivered=0 AND lease_token IS NOT NULL
                AND lease_claimed_ms IS NOT NULL AND lease_until_ms IS NOT NULL
                AND lease_until_ms>=lease_claimed_ms)
            OR (state='DELIVERED' AND delivered=1 AND lease_token IS NULL
                AND lease_claimed_ms IS NULL AND lease_until_ms IS NULL)
        )
    )""",
    """CREATE TABLE commit_conflicts (
        commit_id TEXT NOT NULL,
        original_request_digest TEXT NOT NULL,
        original_public_request_digest TEXT NOT NULL,
        original_workflow_id TEXT NOT NULL,
        original_node_id TEXT NOT NULL,
        original_attempt_id TEXT NOT NULL,
        conflicting_request_digest TEXT NOT NULL,
        conflicting_public_request_digest TEXT NOT NULL,
        conflicting_workflow_id TEXT NOT NULL,
        conflicting_node_id TEXT NOT NULL,
        conflicting_attempt_id TEXT NOT NULL,
        observation_sequence BIGINT NOT NULL,
        audit_event_id TEXT NOT NULL,
        conflict_claim_json TEXT NOT NULL,
        CONSTRAINT commit_conflicts_pkey
            PRIMARY KEY (
                commit_id,conflicting_workflow_id,conflicting_node_id,
                conflicting_attempt_id,conflicting_request_digest,
                conflicting_public_request_digest
            )
    )""",
    """CREATE TABLE workflow_authority (
        workflow_id TEXT CONSTRAINT workflow_authority_pkey PRIMARY KEY
    )""",
    f"""CREATE TABLE semantic_checkpoint (
        singleton SMALLINT CONSTRAINT semantic_checkpoint_pkey PRIMARY KEY,
        change_sequence BIGINT NOT NULL,
        prior_digest TEXT NOT NULL,
        checkpoint_digest TEXT NOT NULL,
        key_id TEXT NOT NULL,
        signature TEXT NOT NULL,
        CONSTRAINT semantic_checkpoint_singleton_check CHECK (singleton=1),
        CONSTRAINT semantic_checkpoint_sequence_check
            CHECK (change_sequence BETWEEN 0 AND {_MAX_SAFE_INTEGER})
    )""",
)

_POSTGRES_GCB_TABLES = (
    f"""CREATE TABLE gcb_store_meta (
        singleton SMALLINT CONSTRAINT gcb_store_meta_pkey PRIMARY KEY,
        profile TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        authority_store_id TEXT NOT NULL CONSTRAINT gcb_store_meta_store_id_key UNIQUE,
        sealed SMALLINT NOT NULL,
        CONSTRAINT gcb_store_meta_singleton_check CHECK (singleton=1),
        CONSTRAINT gcb_store_meta_profile_check CHECK (profile='{_GCB_CATALOG_PROFILE}'),
        CONSTRAINT gcb_store_meta_schema_version_check
            CHECK (schema_version='{_AUTHORITY_SCHEMA_VERSION}'),
        CONSTRAINT gcb_store_meta_sealed_check CHECK (sealed=1)
    )""",
    f"""CREATE TABLE gcb_workflows (
        workflow_id TEXT CONSTRAINT gcb_workflows_pkey PRIMARY KEY,
        generation BIGINT NOT NULL,
        policy_version TEXT NOT NULL,
        policy_digest TEXT NOT NULL,
        policy_epoch BIGINT NOT NULL,
        verifier_policy_id TEXT NOT NULL,
        authority_root TEXT NOT NULL,
        authority_epoch BIGINT NOT NULL,
        revocation_generation BIGINT NOT NULL,
        state_version BIGINT NOT NULL,
        CONSTRAINT gcb_workflows_generation_check CHECK
            (generation BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_workflows_policy_epoch_check CHECK
            (policy_epoch BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_workflows_authority_epoch_check CHECK
            (authority_epoch BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_workflows_revocation_generation_check CHECK
            (revocation_generation BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_workflows_state_version_check CHECK
            (state_version BETWEEN 0 AND {_MAX_SAFE_INTEGER})
    )""",
    f"""CREATE TABLE gcb_agents (
        workflow_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        public_key BYTEA NOT NULL,
        key_id TEXT NOT NULL,
        capabilities TEXT NOT NULL,
        authority_epoch BIGINT NOT NULL,
        revocation_epoch BIGINT NOT NULL,
        revoked SMALLINT NOT NULL DEFAULT 0,
        CONSTRAINT gcb_agents_pkey PRIMARY KEY (workflow_id,agent_id),
        CONSTRAINT gcb_agents_workflow_fkey FOREIGN KEY (workflow_id)
            REFERENCES gcb_workflows(workflow_id),
        CONSTRAINT gcb_agents_authority_epoch_check CHECK
            (authority_epoch BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_agents_revocation_epoch_check CHECK
            (revocation_epoch BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_agents_revoked_check CHECK (revoked IN (0,1))
    )""",
    f"""CREATE TABLE gcb_nodes (
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        status TEXT NOT NULL,
        version BIGINT NOT NULL,
        input_digest TEXT NOT NULL,
        required_capabilities TEXT NOT NULL,
        predecessors TEXT NOT NULL,
        attempt_id TEXT,
        claimed_by TEXT,
        artifact_id TEXT,
        result_digest TEXT,
        commit_id TEXT,
        receipt_digest TEXT,
        tainted SMALLINT NOT NULL DEFAULT 0,
        CONSTRAINT gcb_nodes_pkey PRIMARY KEY (workflow_id,node_id),
        CONSTRAINT gcb_nodes_workflow_commit_key UNIQUE (workflow_id,commit_id),
        CONSTRAINT gcb_nodes_workflow_fkey FOREIGN KEY (workflow_id)
            REFERENCES gcb_workflows(workflow_id),
        CONSTRAINT gcb_nodes_status_check CHECK (status IN (
            'blocked','ready','claimed','result_produced','governed_committed',
            'denied','revoked','superseded'
        )),
        CONSTRAINT gcb_nodes_version_check CHECK
            (version BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_nodes_tainted_check CHECK (tainted IN (0,1))
    )""",
    """CREATE TABLE gcb_staged_artifacts (
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        output_digest TEXT NOT NULL,
        CONSTRAINT gcb_staged_artifacts_pkey
            PRIMARY KEY (workflow_id,node_id,attempt_id),
        CONSTRAINT gcb_staged_artifacts_workflow_artifact_key
            UNIQUE (workflow_id,artifact_id),
        CONSTRAINT gcb_staged_artifacts_node_fkey
            FOREIGN KEY (workflow_id,node_id)
            REFERENCES gcb_nodes(workflow_id,node_id)
    )""",
    f"""CREATE TABLE gcb_revoked_roots (
        workflow_id TEXT NOT NULL,
        root_node_id TEXT NOT NULL,
        generation BIGINT NOT NULL,
        event_id TEXT NOT NULL CONSTRAINT gcb_revoked_roots_event_id_key UNIQUE,
        reason TEXT NOT NULL,
        CONSTRAINT gcb_revoked_roots_pkey PRIMARY KEY (workflow_id,root_node_id),
        CONSTRAINT gcb_revoked_roots_node_fkey
            FOREIGN KEY (workflow_id,root_node_id)
            REFERENCES gcb_nodes(workflow_id,node_id),
        CONSTRAINT gcb_revoked_roots_generation_check CHECK
            (generation BETWEEN 0 AND {_MAX_SAFE_INTEGER})
    )""",
    f"""CREATE TABLE gcb_decisions (
        commit_id TEXT CONSTRAINT gcb_decisions_pkey PRIMARY KEY,
        request_hash TEXT NOT NULL,
        outcome TEXT NOT NULL,
        reason TEXT NOT NULL,
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        state_version BIGINT NOT NULL,
        nonce TEXT NOT NULL,
        CONSTRAINT gcb_decisions_outcome_check
            CHECK (outcome IN ('COMMITTED','DENIED','CONFLICTED')),
        CONSTRAINT gcb_decisions_state_version_check CHECK
            (state_version BETWEEN 0 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_decisions_apcc_commit_fkey FOREIGN KEY (commit_id)
            REFERENCES commit_index(commit_id),
        CONSTRAINT gcb_decisions_node_fkey FOREIGN KEY (workflow_id,node_id)
            REFERENCES gcb_nodes(workflow_id,node_id)
    )""",
    """CREATE TABLE gcb_receipt_evidence (
        commit_id TEXT CONSTRAINT gcb_receipt_evidence_pkey PRIMARY KEY,
        receipt_material TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        verdict_material TEXT NOT NULL,
        verdict_digest TEXT NOT NULL,
        CONSTRAINT gcb_receipt_evidence_commit_fkey FOREIGN KEY (commit_id)
            REFERENCES gcb_decisions(commit_id)
    )""",
    f"""CREATE TABLE gcb_outbox (
        event_sequence BIGINT CONSTRAINT gcb_outbox_pkey PRIMARY KEY,
        event_id TEXT NOT NULL CONSTRAINT gcb_outbox_event_id_key UNIQUE,
        commit_id TEXT NOT NULL CONSTRAINT gcb_outbox_commit_id_key UNIQUE,
        workflow_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        dispatched SMALLINT NOT NULL DEFAULT 0,
        CONSTRAINT gcb_outbox_event_sequence_check
            CHECK (event_sequence BETWEEN 1 AND {_MAX_SAFE_INTEGER}),
        CONSTRAINT gcb_outbox_dispatched_check CHECK (dispatched IN (0,1)),
        CONSTRAINT gcb_outbox_apcc_sequence_fkey FOREIGN KEY (event_sequence)
            REFERENCES outbox(event_sequence),
        CONSTRAINT gcb_outbox_apcc_event_fkey FOREIGN KEY (event_id)
            REFERENCES outbox(event_id),
        CONSTRAINT gcb_outbox_commit_fkey FOREIGN KEY (commit_id)
            REFERENCES gcb_decisions(commit_id)
    )""",
)

_POSTGRES_FUNCTIONS = (
    """CREATE FUNCTION apcc_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql SET search_path FROM CURRENT AS $apcc$
    BEGIN
        RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE='55000';
    END
    $apcc$""",
    """CREATE FUNCTION apcc_validate_disposition() RETURNS trigger
    LANGUAGE plpgsql SET search_path FROM CURRENT AS $apcc$
    BEGIN
        IF NEW.event_sequence=1 AND NEW.disposition='CURRENT'
           AND NOT EXISTS (
               SELECT 1 FROM certificate_dispositions
               WHERE certificate_digest=NEW.certificate_digest
           ) THEN
            RETURN NEW;
        END IF;
        IF NEW.event_sequence=2
           AND NEW.disposition IN ('REVOKED','SUPERSEDED')
           AND EXISTS (
               SELECT 1 FROM certificate_dispositions
               WHERE certificate_digest=NEW.certificate_digest
                 AND event_sequence=1 AND disposition='CURRENT'
           )
           AND NOT EXISTS (
               SELECT 1 FROM certificate_dispositions
               WHERE certificate_digest=NEW.certificate_digest
                 AND event_sequence=2
           ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'invalid certificate disposition transition'
            USING ERRCODE='23514';
    END
    $apcc$""",
    """CREATE FUNCTION apcc_validate_outbox_identity() RETURNS trigger
    LANGUAGE plpgsql SET search_path FROM CURRENT AS $apcc$
    BEGIN
        IF NEW.event_sequence IS DISTINCT FROM OLD.event_sequence
           OR NEW.event_id IS DISTINCT FROM OLD.event_id
           OR NEW.event_kind IS DISTINCT FROM OLD.event_kind
           OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
           OR NEW.event_json IS DISTINCT FROM OLD.event_json
           OR NEW.audit_event_id IS DISTINCT FROM OLD.audit_event_id
           OR NEW.trust_sequence IS DISTINCT FROM OLD.trust_sequence THEN
            RAISE EXCEPTION 'outbox identity is immutable' USING ERRCODE='55000';
        END IF;
        RETURN NEW;
    END
    $apcc$""",
    """CREATE FUNCTION apcc_protect_committed_candidate() RETURNS trigger
    LANGUAGE plpgsql SET search_path FROM CURRENT AS $apcc$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM commit_output_refs
            WHERE workflow_id=OLD.workflow_id AND node_id=OLD.node_id
              AND attempt_id=OLD.attempt_id
        ) AND (
            TG_OP='DELETE'
            OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
            OR NEW.node_id IS DISTINCT FROM OLD.node_id
            OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
            OR NEW.subject_json IS DISTINCT FROM OLD.subject_json
            OR NEW.result IS DISTINCT FROM OLD.result
        ) THEN
            RAISE EXCEPTION 'committed candidate output is immutable'
                USING ERRCODE='55000';
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END
    $apcc$""",
    f"""CREATE FUNCTION apcc_mark_semantic_dirty() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $apcc$
    BEGIN
        UPDATE semantic_checkpoint SET
            change_sequence=change_sequence OPERATOR(pg_catalog.+) 1,
            prior_digest=CASE
                WHEN checkpoint_digest OPERATOR(pg_catalog.<>) ''
                    THEN checkpoint_digest
                ELSE prior_digest
            END,
            checkpoint_digest='',
            signature=''
        WHERE singleton OPERATOR(pg_catalog.=) 1
          AND change_sequence OPERATOR(pg_catalog.<) {_MAX_SAFE_INTEGER};
        IF FOUND THEN
            RETURN NULL;
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM semantic_checkpoint
            WHERE singleton OPERATOR(pg_catalog.=) 1
        ) THEN
            RAISE EXCEPTION 'semantic checkpoint missing'
                USING ERRCODE='55000';
        ELSE
            RAISE EXCEPTION 'semantic checkpoint sequence exhausted'
                USING ERRCODE='22003';
        END IF;
        RETURN NULL;
    END
    $apcc$""",
)

_POSTGRES_CHECKPOINT_TABLES = (
    "metadata",
    "logical_nodes",
    "candidates",
    "commit_output_refs",
    "commit_index",
    "request_index",
    "nonce_ledger",
    "evidence_refs",
    "certificates",
    "audit_events",
    "decisions",
    "certificate_dispositions",
    "predecessor_edges",
    "supersession_edges",
    "workflow_revocations",
    "actor_revocations",
    "trust_log",
    "control_events",
    "outbox",
    "commit_conflicts",
    "workflow_authority",
)

_POSTGRES_CHECKPOINT_TRIGGERS = tuple(
    "CREATE TRIGGER apcc_semantic_dirty_"
    f"{table}_{operation.casefold()} AFTER {operation} ON {table} "
    "FOR EACH STATEMENT EXECUTE FUNCTION apcc_mark_semantic_dirty()"
    for table in _POSTGRES_CHECKPOINT_TABLES
    for operation in ("INSERT", "UPDATE", "DELETE", "TRUNCATE")
)

_POSTGRES_TRIGGERS = (
    "CREATE TRIGGER certificate_dispositions_no_update BEFORE UPDATE ON certificate_dispositions FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER certificate_dispositions_no_delete BEFORE DELETE ON certificate_dispositions FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER certificate_dispositions_validate_insert BEFORE INSERT ON certificate_dispositions FOR EACH ROW EXECUTE FUNCTION apcc_validate_disposition()",
    "CREATE TRIGGER trust_log_no_update BEFORE UPDATE ON trust_log FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER trust_log_no_delete BEFORE DELETE ON trust_log FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER control_events_no_update BEFORE UPDATE ON control_events FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER control_events_no_delete BEFORE DELETE ON control_events FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER outbox_identity_no_update BEFORE UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION apcc_validate_outbox_identity()",
    "CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER commit_output_refs_no_update BEFORE UPDATE ON commit_output_refs FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER commit_output_refs_no_delete BEFORE DELETE ON commit_output_refs FOR EACH ROW EXECUTE FUNCTION apcc_reject_mutation()",
    "CREATE TRIGGER candidates_protect_committed_update BEFORE UPDATE ON candidates FOR EACH ROW EXECUTE FUNCTION apcc_protect_committed_candidate()",
    "CREATE TRIGGER candidates_protect_committed_delete BEFORE DELETE ON candidates FOR EACH ROW EXECUTE FUNCTION apcc_protect_committed_candidate()",
    *_POSTGRES_CHECKPOINT_TRIGGERS,
)

_POSTGRES_INDEXES = (
    "CREATE INDEX idx_apcc_outbox_pending ON outbox(state,lease_until_ms,event_sequence)",
    "CREATE INDEX idx_apcc_outbox_head ON outbox(event_sequence) WHERE state<>'DELIVERED'",
    "CREATE INDEX idx_nonce_ledger_nonce ON nonce_ledger(nonce)",
    "CREATE INDEX idx_supersession_new_digest ON supersession_edges(new_digest)",
    "CREATE INDEX idx_commit_conflicts_exact ON commit_conflicts(commit_id,conflicting_workflow_id,conflicting_node_id,conflicting_attempt_id,conflicting_request_digest,conflicting_public_request_digest)",
)

_POSTGRES_GCB_CHECKPOINT_TABLES = (
    "gcb_store_meta",
    "gcb_workflows",
    "gcb_agents",
    "gcb_nodes",
    "gcb_staged_artifacts",
    "gcb_revoked_roots",
    "gcb_decisions",
    "gcb_receipt_evidence",
    "gcb_outbox",
)

_POSTGRES_GCB_CHECKPOINT_TRIGGERS = tuple(
    "CREATE TRIGGER apcc_semantic_dirty_"
    f"{table}_{operation.casefold()} AFTER {operation} ON {table} "
    "FOR EACH STATEMENT EXECUTE FUNCTION apcc_mark_semantic_dirty()"
    for table in _POSTGRES_GCB_CHECKPOINT_TABLES
    for operation in ("INSERT", "UPDATE", "DELETE", "TRUNCATE")
)

_POSTGRES_GCB_INDEXES = (
    "CREATE INDEX idx_gcb_outbox_pending ON gcb_outbox(event_sequence) WHERE dispatched=0",
)

_POSTGRES_SCHEMA_STATEMENTS = (
    *_POSTGRES_TABLES,
    *_POSTGRES_FUNCTIONS,
    *_POSTGRES_TRIGGERS,
    *_POSTGRES_INDEXES,
)

_POSTGRES_BOOTSTRAP_STATEMENTS = (
    *_POSTGRES_TABLES,
    *_POSTGRES_FUNCTIONS,
    *_POSTGRES_INDEXES,
)

_POSTGRES_GCB_SCHEMA_STATEMENTS = (
    *_POSTGRES_SCHEMA_STATEMENTS,
    *_POSTGRES_GCB_TABLES,
    *_POSTGRES_GCB_CHECKPOINT_TRIGGERS,
    *_POSTGRES_GCB_INDEXES,
)

_POSTGRES_GCB_BOOTSTRAP_STATEMENTS = (
    *_POSTGRES_BOOTSTRAP_STATEMENTS,
    *_POSTGRES_GCB_TABLES,
    *_POSTGRES_GCB_INDEXES,
)

_POSTGRES_GCB_TRIGGERS = (
    *_POSTGRES_TRIGGERS,
    *_POSTGRES_GCB_CHECKPOINT_TRIGGERS,
)


def _apply_privilege_contract(
    connection: _Connection,
    schema: str,
    runtime_role: str,
    observer_role: str,
) -> None:
    _validate_schema_name(schema)
    _validate_role_name(runtime_role)
    _validate_role_name(observer_role)
    quoted_schema = _quoted_identifier(schema)
    quoted_runtime = _quoted_identifier(runtime_role)
    quoted_observer = _quoted_identifier(observer_role)
    checkpoint = f'{quoted_schema}."semantic_checkpoint"'
    connection.execute(f"REVOKE ALL ON SCHEMA {quoted_schema} FROM PUBLIC")
    connection.execute(f"GRANT USAGE ON SCHEMA {quoted_schema} TO {quoted_runtime}")
    connection.execute(
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {quoted_schema} FROM PUBLIC"
    )
    connection.execute(
        "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "
        f"{quoted_schema} TO {quoted_runtime}"
    )
    connection.execute(f"REVOKE ALL ON TABLE {checkpoint} FROM {quoted_runtime}")
    connection.execute(f"GRANT SELECT ON TABLE {checkpoint} TO {quoted_runtime}")
    connection.execute(
        "GRANT UPDATE(checkpoint_digest,signature) ON TABLE "
        f"{checkpoint} TO {quoted_runtime}"
    )
    connection.execute(
        f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {quoted_schema} FROM PUBLIC"
    )
    connection.execute(
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {quoted_schema} FROM PUBLIC"
    )
    connection.execute(f"REVOKE ALL ON SCHEMA {quoted_schema} FROM {quoted_observer}")
    connection.execute(f"GRANT USAGE ON SCHEMA {quoted_schema} TO {quoted_observer}")
    connection.execute(
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {quoted_schema} FROM {quoted_observer}"
    )
    connection.execute(
        f"GRANT SELECT ON ALL TABLES IN SCHEMA {quoted_schema} TO {quoted_observer}"
    )
    connection.execute(
        f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {quoted_schema} FROM {quoted_observer}"
    )
    connection.execute(
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {quoted_schema} FROM {quoted_observer}"
    )


def _normalize_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


_POSTGRES_SCHEMA_FINGERPRINT = sha256_digest(
    (
        f"schema-version={_AUTHORITY_SCHEMA_VERSION}\n"
        + "\n".join(
            _normalize_schema_sql(statement)
            for statement in _POSTGRES_SCHEMA_STATEMENTS
        )
    ).encode("utf-8")
)

_POSTGRES_GCB_SCHEMA_FINGERPRINT = sha256_digest(
    (
        f"schema-version={_AUTHORITY_SCHEMA_VERSION}\n"
        f"catalog-profile={_GCB_CATALOG_PROFILE}\n"
        + "\n".join(
            _normalize_schema_sql(statement)
            for statement in _POSTGRES_GCB_SCHEMA_STATEMENTS
        )
    ).encode("utf-8")
)

# PostgreSQL 17 pg_catalog signature of the native manifest above.  It covers
# relation flags, every user column/default, every constraint definition, all
# indexes (including constraint indexes), triggers, and function bodies.
_POSTGRES_CATALOG_FINGERPRINT = "s-gycb2MocWE-vCFg3fyKw9tSRPK0ayWSKxg9dMfU9w"
_POSTGRES_GCB_CATALOG_FINGERPRINT = "I6wSWNo5hxurvso3xkof5pVhkbVtvPfUknuNu-qK3SE"


def _validate_server_version_num(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("APCC PostgreSQL catalog requires PostgreSQL 17")
    try:
        server_version = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("APCC PostgreSQL catalog requires PostgreSQL 17") from error
    if not 170000 <= server_version < 180000:
        raise ValueError("APCC PostgreSQL catalog requires PostgreSQL 17")


def _join_catalog_array(values: object, *, allow_single_delimited: bool = False) -> str:
    if not isinstance(values, (list, tuple)) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError("invalid PostgreSQL catalog array")
    if allow_single_delimited and len(values) > 1:
        raise ValueError("ambiguous PostgreSQL catalog array")
    if any(value == "" for value in values):
        raise ValueError("ambiguous PostgreSQL catalog array")
    if any("," in value for value in values) and not (
        allow_single_delimited and len(values) == 1
    ):
        raise ValueError("ambiguous PostgreSQL catalog array")
    return ",".join(values)


def _normalize_catalog_text(
    value: object, schema: str, owner_role: str, runtime_role: str, observer_role: str
) -> object:
    if not isinstance(value, str):
        return value
    replacements = {
        schema: "<schema>",
        owner_role: "<owner>",
        runtime_role: "<runtime>",
        observer_role: "<observer>",
    }
    if value in replacements:
        return replacements[value]
    output: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("--", index):
            end = value.find("\n", index)
            if end < 0:
                output.append(value[index:])
                break
            output.append(value[index : end + 1])
            index = end + 1
            continue
        if value.startswith("/*", index):
            end = index + 2
            depth = 1
            while end < len(value) and depth:
                if value.startswith("/*", end):
                    depth += 1
                    end += 2
                elif value.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("unterminated PostgreSQL catalog text")
            output.append(value[index:end])
            index = end
            continue
        if value[index] == "'":
            end = index + 1
            closed = False
            while end < len(value):
                if value[end] == "'":
                    end += 1
                    if end < len(value) and value[end] == "'":
                        end += 1
                        continue
                    closed = True
                    break
                end += 1
            if not closed:
                raise ValueError("unterminated PostgreSQL catalog text")
            output.append(value[index:end])
            index = end
            continue
        if value[index] == "$":
            tag = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", value[index:])
            if tag is not None:
                delimiter = tag.group(0)
                end = value.find(delimiter, index + len(delimiter))
                if end < 0:
                    raise ValueError("unterminated PostgreSQL catalog text")
                end += len(delimiter)
                output.append(value[index:end])
                index = end
                continue
        if value[index] == '"':
            end = index + 1
            identifier: list[str] = []
            closed = False
            while end < len(value):
                if value[end] == '"':
                    if end + 1 < len(value) and value[end + 1] == '"':
                        identifier.append('"')
                        end += 2
                        continue
                    end += 1
                    closed = True
                    break
                identifier.append(value[end])
                end += 1
            if not closed:
                raise ValueError("unterminated PostgreSQL catalog text")
            replacement = replacements.get("".join(identifier))
            output.append(replacement if replacement is not None else value[index:end])
            index = end
            continue
        identifier_match = re.match(r"[A-Za-z_][A-Za-z0-9_$]*", value[index:])
        if identifier_match is not None:
            token = identifier_match.group(0)
            output.append(replacements.get(token, token))
            index += len(token)
            continue
        output.append(value[index])
        index += 1
    return "".join(output)


def _validate_dependency_identity_rows(
    rows: list[tuple[object, ...]],
    schema: str,
    owner_role: str,
    runtime_role: str,
    observer_role: str,
) -> None:
    replacements = {
        schema: "<schema>",
        owner_role: "<owner>",
        runtime_role: "<runtime>",
        observer_role: "<observer>",
    }
    reserved_markers = frozenset(replacements.values())
    descriptions: dict[
        tuple[str, str], tuple[str, tuple[str, ...], tuple[str, ...]]
    ] = {}
    addresses: dict[
        tuple[str, str, tuple[str, ...], tuple[str, ...]], tuple[str, str]
    ] = {}
    for row in rows:
        if len(row) != 11:
            raise ValueError("invalid PostgreSQL dependency identity row")
        for class_column, description_column, address_column in ((0, 3, 5), (1, 4, 8)):
            class_name = row[class_column]
            description = row[description_column]
            object_type = row[address_column]
            object_names = row[address_column + 1]
            object_args = row[address_column + 2]
            if (
                not isinstance(class_name, str)
                or not isinstance(description, str)
                or not isinstance(object_type, str)
                or not isinstance(object_names, (list, tuple))
                or not isinstance(object_args, (list, tuple))
                or not all(isinstance(value, str) for value in object_names)
                or not all(isinstance(value, str) for value in object_args)
                or any(
                    value in reserved_markers for value in (*object_names, *object_args)
                )
            ):
                raise ValueError("invalid PostgreSQL dependency identity row")
            normalized_description = _normalize_catalog_text(
                description, schema, owner_role, runtime_role, observer_role
            )
            normalized_address = (
                object_type,
                tuple(
                    replacements[value] if value in replacements else value
                    for value in object_names
                ),
                tuple(
                    replacements[value] if value in replacements else value
                    for value in object_args
                ),
            )
            description_key = (class_name, str(normalized_description))
            prior_address = descriptions.setdefault(description_key, normalized_address)
            if prior_address != normalized_address:
                raise ValueError("PostgreSQL dependency identity collision")
            address_key = (class_name, *normalized_address)
            prior_description = addresses.setdefault(address_key, description_key)
            if prior_description != description_key:
                raise ValueError("PostgreSQL dependency identity collision")


def _catalog_manifest(
    connection: _Connection,
    schema: str,
    owner_role: str,
    runtime_role: str,
    observer_role: str,
) -> dict[str, object]:
    try:
        version = connection.execute("SHOW server_version_num").fetchone()
    except Exception as error:
        raise ValueError("APCC PostgreSQL catalog version validation failed") from error
    if version is None or len(version) != 1 or not isinstance(version[0], (int, str)):
        raise ValueError("APCC PostgreSQL catalog version validation failed")
    _validate_server_version_num(version[0])
    schema_identity = connection.execute(
        "SELECT n.nspname,pg_get_userbyid(n.nspowner) FROM pg_namespace n "
        "WHERE n.nspname=%s",
        (schema,),
    ).fetchall()
    database_identity = connection.execute(
        "SELECT d.datallowconn,d.datistemplate,d.datacl IS NULL,"
        "pg_get_userbyid(d.datdba) FROM pg_database d "
        "WHERE d.datname=current_database()"
    ).fetchall()
    database_acls = connection.execute(
        "SELECT CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_database d "
        "CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,"
        "acldefault('d',d.datdba))) x WHERE d.datname=current_database()"
    ).fetchall()
    schema_acls = connection.execute(
        "SELECT CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_namespace n "
        "CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,"
        "acldefault('n',n.nspowner))) x WHERE n.nspname=%s",
        (schema,),
    ).fetchall()
    relations = connection.execute(
        "SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,"
        "c.relforcerowsecurity,pg_get_userbyid(c.relowner) "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relkind IN ('r','p') ORDER BY c.relname",
        (schema,),
    ).fetchall()
    classes = connection.execute(
        "SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,"
        "c.relforcerowsecurity,c.relisshared,c.relispartition,c.relacl IS NULL,"
        "coalesce(c.reloptions,ARRAY[]::text[]),"
        "coalesce(pg_get_expr(c.relpartbound,c.oid,true),''),"
        "pg_get_userbyid(c.relowner) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s ORDER BY c.relkind,c.relname",
        (schema,),
    ).fetchall()
    relation_acls = connection.execute(
        "SELECT c.relname,CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,"
        "acldefault('r',c.relowner))) x WHERE n.nspname=%s "
        "AND c.relkind IN ('r','p')",
        (schema,),
    ).fetchall()
    class_acls = connection.execute(
        "SELECT c.relname,c.relkind,CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault("
        "CASE WHEN c.relkind='S' THEN 's'::\"char\" ELSE 'r'::\"char\" END,"
        "c.relowner))) x WHERE n.nspname=%s",
        (schema,),
    ).fetchall()
    columns = connection.execute(
        "SELECT c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),"
        "a.attnotnull,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),'') "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_attribute a ON a.attrelid=c.oid "
        "LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
        "WHERE n.nspname=%s AND c.relkind IN ('r','p') AND a.attnum>0 "
        "AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
        (schema,),
    ).fetchall()
    column_acls = connection.execute(
        "SELECT c.relname,a.attname,CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_attribute a ON a.attrelid=c.oid "
        "CROSS JOIN LATERAL aclexplode(a.attacl) x "
        "WHERE n.nspname=%s AND a.attnum>0 "
        "AND NOT a.attisdropped AND a.attacl IS NOT NULL",
        (schema,),
    ).fetchall()
    constraints = connection.execute(
        "SELECT c.relname,k.conname,k.contype,k.condeferrable,k.condeferred,"
        "k.convalidated,pg_get_constraintdef(k.oid,true) "
        "FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s "
        "ORDER BY c.relname,k.conname",
        (schema,),
    ).fetchall()
    indexes = connection.execute(
        "SELECT t.relname,i.relname,x.indisunique,x.indisprimary,x.indisvalid,"
        "x.indisready,x.indislive,pg_get_indexdef(i.oid) "
        "FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid "
        "JOIN pg_class t ON t.oid=x.indrelid "
        "JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=%s "
        "ORDER BY t.relname,i.relname",
        (schema,),
    ).fetchall()
    rules = connection.execute(
        "SELECT c.relname,r.rulename,r.ev_type,r.ev_enabled,r.is_instead,"
        "pg_get_ruledef(r.oid,true) FROM pg_rewrite r "
        "JOIN pg_class c ON c.oid=r.ev_class "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s ORDER BY c.relname,r.rulename",
        (schema,),
    ).fetchall()
    triggers = connection.execute(
        "SELECT c.relname,CASE WHEN t.tgisinternal THEN '<internal>' ELSE t.tgname END,"
        "t.tgenabled,t.tgisinternal,t.tgtype,pn.nspname,p.proname,"
        "coalesce(k.conname,''),coalesce(src.relname,''),coalesce(dst.relname,''),"
        "CASE WHEN t.tgisinternal THEN '' ELSE pg_get_triggerdef(t.oid,true) END "
        "FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_proc p ON p.oid=t.tgfoid "
        "JOIN pg_namespace pn ON pn.oid=p.pronamespace "
        "LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint "
        "LEFT JOIN pg_class src ON src.oid=k.conrelid "
        "LEFT JOIN pg_class dst ON dst.oid=k.confrelid "
        "WHERE n.nspname=%s ORDER BY c.relname,t.tgisinternal,t.tgtype,p.proname",
        (schema,),
    ).fetchall()
    functions = connection.execute(
        "SELECT p.proname,p.prokind,p.provolatile,p.proparallel,p.prosecdef,"
        "p.proleakproof,coalesce(p.proconfig,ARRAY[]::text[]),l.lanname,"
        "pg_get_function_result(p.oid),pg_get_function_arguments(p.oid),p.prosrc,"
        "pg_get_userbyid(p.proowner) "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname=%s ORDER BY p.proname",
        (schema,),
    ).fetchall()
    function_acls = connection.execute(
        "SELECT p.proname,CASE WHEN x.grantee=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(x.grantee) END,pg_get_userbyid(x.grantor),"
        "x.privilege_type,x.is_grantable FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid=p.pronamespace "
        "CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,"
        "acldefault('f',p.proowner))) x WHERE n.nspname=%s",
        (schema,),
    ).fetchall()
    types = connection.execute(
        "SELECT t.typname,t.typtype,t.typcategory,t.typispreferred,t.typisdefined,"
        "t.typnotnull,t.typacl IS NULL,format_type(t.typbasetype,t.typtypmod),"
        "t.typtypmod,t.typndims,coalesce(t.typdefault,''),"
        "coalesce(coll.collname,''),coalesce(format_type(r.rngsubtype,NULL),'') "
        "FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace "
        "LEFT JOIN pg_collation coll ON coll.oid=t.typcollation "
        "LEFT JOIN pg_range r ON r.rngtypid=t.oid "
        "WHERE n.nspname=%s ORDER BY t.typname",
        (schema,),
    ).fetchall()
    type_attributes = connection.execute(
        "SELECT t.typname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),"
        "a.attnotnull,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),'') "
        "FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace "
        "JOIN pg_class c ON c.oid=t.typrelid "
        "JOIN pg_attribute a ON a.attrelid=c.oid "
        "LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
        "WHERE n.nspname=%s AND a.attnum>0 AND NOT a.attisdropped "
        "ORDER BY t.typname,a.attnum",
        (schema,),
    ).fetchall()
    enums = connection.execute(
        "SELECT t.typname,e.enumsortorder,e.enumlabel FROM pg_enum e "
        "JOIN pg_type t ON t.oid=e.enumtypid "
        "JOIN pg_namespace n ON n.oid=t.typnamespace "
        "WHERE n.nspname=%s ORDER BY t.typname,e.enumsortorder",
        (schema,),
    ).fetchall()
    operators = connection.execute(
        "SELECT o.oprname,o.oprkind,o.oprcanmerge,o.oprcanhash,"
        "format_type(o.oprleft,NULL),format_type(o.oprright,NULL),"
        "format_type(o.oprresult,NULL),o.oprcode::regprocedure::text "
        "FROM pg_operator o JOIN pg_namespace n ON n.oid=o.oprnamespace "
        "WHERE n.nspname=%s ORDER BY o.oprname,o.oprkind",
        (schema,),
    ).fetchall()
    casts = connection.execute(
        "SELECT format_type(c.castsource,NULL),format_type(c.casttarget,NULL),"
        "c.castcontext,c.castmethod,coalesce(c.castfunc::regprocedure::text,'') "
        "FROM pg_cast c JOIN pg_type s ON s.oid=c.castsource "
        "JOIN pg_namespace sn ON sn.oid=s.typnamespace "
        "JOIN pg_type t ON t.oid=c.casttarget "
        "JOIN pg_namespace tn ON tn.oid=t.typnamespace "
        "WHERE sn.nspname=%s OR tn.nspname=%s ORDER BY 1,2",
        (schema, schema),
    ).fetchall()
    collations = connection.execute(
        "SELECT c.collname,c.collprovider,c.collisdeterministic,c.collencoding,"
        "c.collcollate,c.collctype,coalesce(c.colllocale,''),"
        "coalesce(c.collicurules,'') FROM pg_collation c "
        "JOIN pg_namespace n ON n.oid=c.collnamespace "
        "WHERE n.nspname=%s ORDER BY c.collname",
        (schema,),
    ).fetchall()
    extensions = connection.execute(
        "SELECT e.extname,e.extversion,e.extrelocatable,n.nspname "
        "FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace "
        "WHERE n.nspname=%s ORDER BY e.extname",
        (schema,),
    ).fetchall()
    policies = connection.execute(
        "SELECT c.relname,p.polname,p.polcmd,p.polpermissive,"
        "coalesce((SELECT array_agg(role_name ORDER BY role_name) FROM ("
        "SELECT CASE WHEN role_oid=0 THEN 'PUBLIC' "
        "ELSE pg_get_userbyid(role_oid) END AS role_name "
        "FROM unnest(p.polroles) role_oid) policy_roles),ARRAY[]::text[]),"
        "coalesce(pg_get_expr(p.polqual,p.polrelid,true),''),"
        "coalesce(pg_get_expr(p.polwithcheck,p.polrelid,true),'') "
        "FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s ORDER BY c.relname,p.polname",
        (schema,),
    ).fetchall()
    foreign_tables = connection.execute(
        "SELECT c.relname,s.srvname,coalesce(f.ftoptions,ARRAY[]::text[]) "
        "FROM pg_foreign_table f JOIN pg_class c ON c.oid=f.ftrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_foreign_server s ON s.oid=f.ftserver "
        "WHERE n.nspname=%s ORDER BY c.relname",
        (schema,),
    ).fetchall()
    inheritance = connection.execute(
        "SELECT child.relname,parent_namespace.nspname,parent.relname,i.inhseqno,"
        "i.inhdetachpending FROM pg_inherits i "
        "JOIN pg_class child ON child.oid=i.inhrelid "
        "JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace "
        "JOIN pg_class parent ON parent.oid=i.inhparent "
        "JOIN pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace "
        "WHERE child_namespace.nspname=%s ORDER BY child.relname,i.inhseqno",
        (schema,),
    ).fetchall()
    partitioned_tables = connection.execute(
        "SELECT c.relname,p.partstrat,p.partnatts,p.partdefid<>0,"
        "pg_get_partkeydef(c.oid) FROM pg_partitioned_table p "
        "JOIN pg_class c ON c.oid=p.partrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s ORDER BY c.relname",
        (schema,),
    ).fetchall()
    operator_families = connection.execute(
        "SELECT f.opfname,a.amname,pg_get_userbyid(f.opfowner) "
        "FROM pg_opfamily f JOIN pg_namespace n ON n.oid=f.opfnamespace "
        "JOIN pg_am a ON a.oid=f.opfmethod WHERE n.nspname=%s ORDER BY 1,2",
        (schema,),
    ).fetchall()
    operator_classes = connection.execute(
        "SELECT c.opcname,a.amname,c.opcdefault,format_type(c.opcintype,NULL),"
        "coalesce(format_type(c.opckeytype,NULL),''),f.opfname,"
        "pg_get_userbyid(c.opcowner) FROM pg_opclass c "
        "JOIN pg_namespace n ON n.oid=c.opcnamespace "
        "JOIN pg_am a ON a.oid=c.opcmethod JOIN pg_opfamily f ON f.oid=c.opcfamily "
        "WHERE n.nspname=%s ORDER BY 1,2",
        (schema,),
    ).fetchall()
    access_method_operators = connection.execute(
        "SELECT f.opfname,a.amname,o.amopstrategy,o.amoppurpose,"
        "format_type(o.amoplefttype,NULL),format_type(o.amoprighttype,NULL),"
        "o.amopopr::regoperator::text,coalesce(sort_family.opfname,'') "
        "FROM pg_amop o JOIN pg_opfamily f ON f.oid=o.amopfamily "
        "JOIN pg_namespace n ON n.oid=f.opfnamespace "
        "JOIN pg_am a ON a.oid=f.opfmethod "
        "LEFT JOIN pg_opfamily sort_family ON sort_family.oid=o.amopsortfamily "
        "WHERE n.nspname=%s ORDER BY 1,2,3,5,6",
        (schema,),
    ).fetchall()
    access_method_procedures = connection.execute(
        "SELECT f.opfname,a.amname,p.amprocnum,format_type(p.amproclefttype,NULL),"
        "format_type(p.amprocrighttype,NULL),p.amproc::regprocedure::text "
        "FROM pg_amproc p JOIN pg_opfamily f ON f.oid=p.amprocfamily "
        "JOIN pg_namespace n ON n.oid=f.opfnamespace "
        "JOIN pg_am a ON a.oid=f.opfmethod WHERE n.nspname=%s "
        "ORDER BY 1,2,3,4,5",
        (schema,),
    ).fetchall()
    conversions = connection.execute(
        "SELECT c.conname,pg_encoding_to_char(c.conforencoding),"
        "pg_encoding_to_char(c.contoencoding),c.condefault,"
        "c.conproc::regprocedure::text,pg_get_userbyid(c.conowner) "
        "FROM pg_conversion c JOIN pg_namespace n ON n.oid=c.connamespace "
        "WHERE n.nspname=%s ORDER BY c.conname",
        (schema,),
    ).fetchall()
    text_search_objects = connection.execute(
        "SELECT 'configuration',c.cfgname,pg_get_userbyid(c.cfgowner),p.prsname "
        "FROM pg_ts_config c JOIN pg_namespace n ON n.oid=c.cfgnamespace "
        "JOIN pg_ts_parser p ON p.oid=c.cfgparser WHERE n.nspname=%s UNION ALL "
        "SELECT 'dictionary',d.dictname,pg_get_userbyid(d.dictowner),t.tmplname "
        "FROM pg_ts_dict d JOIN pg_namespace n ON n.oid=d.dictnamespace "
        "JOIN pg_ts_template t ON t.oid=d.dicttemplate WHERE n.nspname=%s UNION ALL "
        "SELECT 'parser',p.prsname,NULL,p.prsstart::regprocedure::text "
        "FROM pg_ts_parser p JOIN pg_namespace n ON n.oid=p.prsnamespace "
        "WHERE n.nspname=%s UNION ALL "
        "SELECT 'template',t.tmplname,NULL,t.tmpllexize::regprocedure::text "
        "FROM pg_ts_template t JOIN pg_namespace n ON n.oid=t.tmplnamespace "
        "WHERE n.nspname=%s ORDER BY 1,2",
        (schema,) * 4,
    ).fetchall()
    extended_statistics = connection.execute(
        "SELECT s.stxname,pg_get_userbyid(s.stxowner),c.relname,s.stxkeys::text,"
        "ARRAY(SELECT kind::text FROM unnest(s.stxkind) kind),"
        "coalesce(pg_get_expr(s.stxexprs,s.stxrelid,true),'') "
        "FROM pg_statistic_ext s JOIN pg_namespace n ON n.oid=s.stxnamespace "
        "JOIN pg_class c ON c.oid=s.stxrelid WHERE n.nspname=%s ORDER BY s.stxname",
        (schema,),
    ).fetchall()
    event_triggers = connection.execute(
        "SELECT e.evtname,e.evtevent,e.evtenabled,e.evtfoid::regprocedure::text,"
        "coalesce(e.evttags,ARRAY[]::text[]) FROM pg_event_trigger e "
        "ORDER BY e.evtname"
    ).fetchall()
    default_acls = connection.execute(
        "SELECT pg_get_userbyid(d.defaclrole),coalesce(n.nspname,''),d.defaclobjtype,"
        "CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,"
        "pg_get_userbyid(x.grantor),x.privilege_type,x.is_grantable "
        "FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace "
        "CROSS JOIN LATERAL aclexplode(d.defaclacl) x "
        "WHERE d.defaclrole IN ((SELECT oid FROM pg_roles WHERE rolname=%s),"
        "(SELECT oid FROM pg_roles WHERE rolname=%s),"
        "(SELECT oid FROM pg_roles WHERE rolname=%s)) OR n.nspname=%s",
        (owner_role, runtime_role, observer_role, schema),
    ).fetchall()
    role_settings = connection.execute(
        "SELECT s.setdatabase=0,pg_get_userbyid(s.setrole),"
        "coalesce(s.setconfig,ARRAY[]::text[]) FROM pg_db_role_setting s "
        "WHERE s.setrole IN ((SELECT oid FROM pg_roles WHERE rolname=%s),"
        "(SELECT oid FROM pg_roles WHERE rolname=%s),"
        "(SELECT oid FROM pg_roles WHERE rolname=%s))",
        (owner_role, runtime_role, observer_role),
    ).fetchall()
    memberships = connection.execute(
        "SELECT granted.rolname,member.rolname,grantor.rolname,m.admin_option,"
        "m.inherit_option,m.set_option FROM pg_auth_members m "
        "JOIN pg_roles granted ON granted.oid=m.roleid "
        "JOIN pg_roles member ON member.oid=m.member "
        "JOIN pg_roles grantor ON grantor.oid=m.grantor "
        "WHERE granted.rolname IN (%s,%s,%s) OR member.rolname IN (%s,%s,%s)",
        (
            owner_role,
            runtime_role,
            observer_role,
            owner_role,
            runtime_role,
            observer_role,
        ),
    ).fetchall()
    dependencies = connection.execute(
        "WITH schema_objects AS ("
        "SELECT 'pg_class'::regclass::oid classid,c.oid objid FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_proc'::regclass::oid,p.oid FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_type'::regclass::oid,t.oid FROM pg_type t "
        "JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_constraint'::regclass::oid,k.oid FROM pg_constraint k "
        "JOIN pg_namespace n ON n.oid=k.connamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_rewrite'::regclass::oid,r.oid FROM pg_rewrite r "
        "JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s UNION ALL SELECT 'pg_trigger'::regclass::oid,t.oid "
        "FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND NOT t.tgisinternal) "
        "SELECT d.classid::regclass::text,d.refclassid::regclass::text,d.deptype,"
        "pg_describe_object(d.classid,d.objid,d.objsubid),"
        "pg_describe_object(d.refclassid,d.refobjid,d.refobjsubid),"
        "(pg_identify_object_as_address(d.classid,d.objid,d.objsubid)).type,"
        "(pg_identify_object_as_address(d.classid,d.objid,d.objsubid)).object_names,"
        "(pg_identify_object_as_address(d.classid,d.objid,d.objsubid)).object_args,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,d.refobjsubid)).type,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,d.refobjsubid)).object_names,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,d.refobjsubid)).object_args "
        "FROM pg_depend d JOIN schema_objects o "
        "ON o.classid=d.classid AND o.objid=d.objid ORDER BY 1,2,3,4,5",
        (schema,) * 6,
    ).fetchall()
    _validate_dependency_identity_rows(
        dependencies, schema, owner_role, runtime_role, observer_role
    )
    dependencies = [tuple(row[:5]) for row in dependencies]
    supported_dependency_classes = {
        "pg_attrdef",
        "pg_authid",
        "pg_class",
        "pg_collation",
        "pg_constraint",
        "pg_extension",
        "pg_language",
        "pg_namespace",
        "pg_opfamily",
        "pg_opclass",
        "pg_operator",
        "pg_proc",
        "pg_rewrite",
        "pg_trigger",
        "pg_type",
    }
    dependency_classes = {str(value) for row in dependencies for value in row[:2]}
    if not dependency_classes <= supported_dependency_classes:
        raise ValueError("APCC PostgreSQL catalog has unhandled dependency class")
    shared_dependencies = connection.execute(
        "WITH schema_objects AS ("
        "SELECT 'pg_namespace'::regclass::oid classid,n.oid objid "
        "FROM pg_namespace n WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_class'::regclass::oid,c.oid FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_proc'::regclass::oid,p.oid FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 'pg_type'::regclass::oid,t.oid FROM pg_type t "
        "JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=%s) "
        "SELECT d.classid::regclass::text,d.refclassid::regclass::text,d.deptype,"
        "pg_describe_object(d.classid,d.objid,0),"
        "pg_describe_object(d.refclassid,d.refobjid,0),"
        "(pg_identify_object_as_address(d.classid,d.objid,0)).type,"
        "(pg_identify_object_as_address(d.classid,d.objid,0)).object_names,"
        "(pg_identify_object_as_address(d.classid,d.objid,0)).object_args,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,0)).type,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,0)).object_names,"
        "(pg_identify_object_as_address(d.refclassid,d.refobjid,0)).object_args "
        "FROM pg_shdepend d JOIN schema_objects o "
        "ON o.classid=d.classid AND o.objid=d.objid "
        "WHERE d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) "
        "ORDER BY 1,2,3,4,5",
        (schema,) * 4,
    ).fetchall()
    _validate_dependency_identity_rows(
        shared_dependencies, schema, owner_role, runtime_role, observer_role
    )
    shared_dependencies = [tuple(row[:5]) for row in shared_dependencies]
    supported_shared_dependency_classes = {
        "pg_authid",
        "pg_class",
        "pg_namespace",
        "pg_proc",
        "pg_type",
    }
    shared_dependency_classes = {
        str(value) for row in shared_dependencies for value in row[:2]
    }
    if not shared_dependency_classes <= supported_shared_dependency_classes:
        raise ValueError(
            "APCC PostgreSQL catalog has unhandled shared dependency class"
        )
    roles = connection.execute(
        "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,"
        "rolreplication,rolbypassrls,rolconfig IS NULL "
        "FROM pg_roles WHERE rolname IN (%s,%s,%s)",
        (owner_role, runtime_role, observer_role),
    ).fetchall()

    identity_replacements = {
        schema: "<schema>",
        owner_role: "<owner>",
        runtime_role: "<runtime>",
        observer_role: "<observer>",
    }

    def normalized(
        rows: list[tuple[object, ...]],
        *,
        identity_columns: frozenset[int] = frozenset(),
        definition_columns: frozenset[int] = frozenset(),
        array_columns: frozenset[int] = frozenset(),
        structured_setting_columns: frozenset[int] = frozenset(),
        role_array_columns: frozenset[int] = frozenset(),
    ) -> list[list[object]]:
        def normalize_value(column: int, value: object) -> object:
            if column in array_columns:
                value = _join_catalog_array(value)
            if column in structured_setting_columns:
                value = _join_catalog_array(value, allow_single_delimited=True)
            if column in identity_columns and isinstance(value, str):
                return identity_replacements.get(value, value)
            if column in definition_columns:
                return _normalize_catalog_text(
                    value, schema, owner_role, runtime_role, observer_role
                )
            if column in role_array_columns:
                if not isinstance(value, (list, tuple)) or not all(
                    isinstance(role_name, str) for role_name in value
                ):
                    raise ValueError("invalid PostgreSQL catalog role array")
                return _join_catalog_array(
                    [
                        identity_replacements.get(role_name, role_name)
                        for role_name in value
                    ]
                )
            return value

        normalized_rows = [
            [normalize_value(column, value) for column, value in enumerate(row)]
            for row in rows
        ]
        return sorted(normalized_rows, key=_json)

    return {
        "server_major": 17,
        "database": normalized(database_identity, identity_columns=frozenset({3})),
        "database_acls": normalized(database_acls, identity_columns=frozenset({0, 1})),
        "schema": normalized(schema_identity, identity_columns=frozenset({0, 1})),
        "schema_acls": normalized(schema_acls, identity_columns=frozenset({0, 1})),
        "relations": normalized(relations, identity_columns=frozenset({5})),
        "classes": normalized(
            classes,
            identity_columns=frozenset({10}),
            definition_columns=frozenset({9}),
            array_columns=frozenset({8}),
        ),
        "relation_acls": normalized(relation_acls, identity_columns=frozenset({1, 2})),
        "class_acls": normalized(class_acls, identity_columns=frozenset({2, 3})),
        "columns": normalized(columns, definition_columns=frozenset({3, 6})),
        "column_acls": normalized(column_acls, identity_columns=frozenset({2, 3})),
        "constraints": normalized(constraints, definition_columns=frozenset({6})),
        "indexes": normalized(indexes, definition_columns=frozenset({7})),
        "rules": normalized(rules, definition_columns=frozenset({5})),
        "triggers": normalized(
            triggers,
            identity_columns=frozenset({5}),
            definition_columns=frozenset({10}),
        ),
        "functions": normalized(
            functions,
            identity_columns=frozenset({11}),
            definition_columns=frozenset({6, 8, 9}),
            structured_setting_columns=frozenset({6}),
        ),
        "function_acls": normalized(function_acls, identity_columns=frozenset({1, 2})),
        "types": normalized(types, definition_columns=frozenset({7, 12})),
        "type_attributes": normalized(
            type_attributes, definition_columns=frozenset({3, 6})
        ),
        "enums": normalized(enums),
        "operators": normalized(operators, definition_columns=frozenset({4, 5, 6, 7})),
        "casts": normalized(casts, definition_columns=frozenset({0, 1, 4})),
        "collations": normalized(collations),
        "extensions": normalized(extensions, identity_columns=frozenset({3})),
        "policies": normalized(
            policies,
            definition_columns=frozenset({5, 6}),
            role_array_columns=frozenset({4}),
        ),
        "foreign_tables": normalized(foreign_tables, array_columns=frozenset({2})),
        "inheritance": normalized(inheritance, identity_columns=frozenset({1})),
        "partitioned_tables": normalized(
            partitioned_tables, definition_columns=frozenset({4})
        ),
        "operator_families": normalized(
            operator_families, identity_columns=frozenset({2})
        ),
        "operator_classes": normalized(
            operator_classes,
            identity_columns=frozenset({6}),
            definition_columns=frozenset({3, 4}),
        ),
        "access_method_operators": normalized(
            access_method_operators, definition_columns=frozenset({4, 5, 6})
        ),
        "access_method_procedures": normalized(
            access_method_procedures, definition_columns=frozenset({3, 4, 5})
        ),
        "conversions": normalized(
            conversions,
            identity_columns=frozenset({5}),
            definition_columns=frozenset({4}),
        ),
        "text_search_objects": normalized(
            text_search_objects,
            identity_columns=frozenset({2}),
            definition_columns=frozenset({3}),
        ),
        "extended_statistics": normalized(
            extended_statistics,
            identity_columns=frozenset({1}),
            definition_columns=frozenset({5}),
            array_columns=frozenset({4}),
        ),
        "event_triggers": normalized(
            event_triggers,
            definition_columns=frozenset({3}),
            array_columns=frozenset({4}),
        ),
        "default_acls": normalized(
            default_acls, identity_columns=frozenset({0, 1, 3, 4})
        ),
        "role_settings": normalized(
            role_settings,
            identity_columns=frozenset({1}),
            definition_columns=frozenset({2}),
            structured_setting_columns=frozenset({2}),
        ),
        "memberships": normalized(memberships, identity_columns=frozenset({0, 1, 2})),
        "dependencies": normalized(dependencies, definition_columns=frozenset({3, 4})),
        "shared_dependencies": normalized(
            shared_dependencies, definition_columns=frozenset({3, 4})
        ),
        "roles": normalized(roles, identity_columns=frozenset({0})),
    }


def _catalog_fingerprint(
    connection: _Connection,
    schema: str,
    owner_role: str,
    runtime_role: str,
    observer_role: str,
) -> str:
    manifest = _catalog_manifest(
        connection, schema, owner_role, runtime_role, observer_role
    )
    return sha256_digest(_json(manifest).encode("utf-8"))


def _trusted_sibling_schemas(
    connection: _Connection,
    schema: str,
    runtime_role: str,
    observer_role: str,
) -> list[str]:
    owner_row = connection.execute(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s",
        (schema,),
    ).fetchone()
    if owner_row is None or not isinstance(owner_row[0], str):
        raise ValueError("APCC authority store schema validation failed")
    owner_role = owner_row[0]
    candidates = connection.execute(
        "SELECT n.nspname FROM pg_namespace n WHERE n.nspname<>%s "
        "AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname=%s) "
        "AND n.nspname<>'information_schema' AND n.nspname !~ '^pg_' "
        "AND NOT EXISTS (SELECT required.name FROM (VALUES "
        "('metadata'),('candidates'),('logical_nodes'),('semantic_checkpoint')) "
        "required(name) WHERE NOT EXISTS (SELECT 1 FROM pg_class c "
        "WHERE c.relnamespace=n.oid AND c.relname=required.name)) "
        "ORDER BY n.nspname",
        (schema, schema),
    ).fetchall()
    trusted: list[str] = []
    try:
        for row in candidates:
            candidate = row[0]
            if not isinstance(candidate, str):
                raise ValueError("APCC authority store schema validation failed")
            connection.execute(
                f"SET LOCAL search_path TO pg_catalog,{_quoted_identifier(candidate)},"
                "pg_temp"
            )
            fingerprint = _catalog_fingerprint(
                connection,
                candidate,
                owner_role,
                runtime_role,
                observer_role,
            )
            if fingerprint in {
                _POSTGRES_CATALOG_FINGERPRINT,
                _POSTGRES_GCB_CATALOG_FINGERPRINT,
            }:
                trusted.append(candidate)
            else:
                raise ValueError("APCC authority store schema validation failed")
    finally:
        connection.execute(
            f"SET LOCAL search_path TO pg_catalog,{_quoted_identifier(schema)},pg_temp"
        )
    return trusted


def _validate_external_capability_contract(
    connection: _Connection,
    schema: str,
    runtime_role: str,
    observer_role: str,
) -> None:
    invalid = ValueError("APCC authority store schema validation failed")
    trusted_siblings = _trusted_sibling_schemas(
        connection, schema, runtime_role, observer_role
    )
    cross_boundary_inheritance = connection.execute(
        "SELECT 1 FROM pg_inherits i "
        "JOIN pg_class child ON child.oid=i.inhrelid "
        "JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace "
        "JOIN pg_class parent ON parent.oid=i.inhparent "
        "JOIN pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace "
        "WHERE (child_namespace.nspname=%s)<>(parent_namespace.nspname=%s) "
        "AND (child_namespace.nspname=%s OR parent_namespace.nspname=%s) LIMIT 1",
        (schema, schema, schema, schema),
    ).fetchone()
    if cross_boundary_inheritance is not None:
        raise invalid
    external_trigger_or_foreign_write = connection.execute(
        "WITH RECURSIVE role_names(role_name,role_oid) AS ("
        "SELECT rolname,oid FROM pg_roles WHERE rolname IN (%s,%s)),"
        "relation_edges(source_oid,target_oid,edge_operation,check_role_oid,"
        "use_origin_check,requires_acl,target_attributes,preserve_attributes) AS ("
        "SELECT r.ev_class,d.refobjid,edge.operation,source.relowner,"
        "(source.relkind='v' AND EXISTS (SELECT 1 FROM "
        "pg_options_to_table(coalesce(source.reloptions,ARRAY[]::text[])) option "
        "WHERE option.option_name='security_invoker' "
        "AND option.option_value::boolean)),true,CASE WHEN source.relkind='v' "
        "AND (SELECT count(*) FROM pg_attribute source_attribute "
        "WHERE source_attribute.attrelid=source.oid AND source_attribute.attnum>0 "
        "AND NOT source_attribute.attisdropped)=1 THEN NULLIF(ARRAY("
        "SELECT DISTINCT mapped.refobjsubid::smallint FROM pg_depend mapped "
        "WHERE mapped.classid='pg_rewrite'::regclass AND mapped.objid=r.oid "
        "AND mapped.refclassid='pg_class'::regclass "
        "AND mapped.refobjid=d.refobjid AND mapped.refobjsubid>0 "
        "ORDER BY mapped.refobjsubid::smallint),ARRAY[]::smallint[]) "
        "ELSE NULL END,false "
        "FROM pg_rewrite r JOIN pg_class source ON source.oid=r.ev_class "
        "JOIN pg_depend d "
        "ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid "
        "CROSS JOIN LATERAL (VALUES (CASE WHEN r.rulename='_RETURN' THEN '*' "
        "WHEN r.ev_type='1' THEN 'S' WHEN r.ev_type='2' THEN 'U' "
        "WHEN r.ev_type='3' THEN 'I' "
        "WHEN r.ev_type='4' THEN 'D' END)) edge(operation) "
        "WHERE d.refclassid='pg_class'::regclass AND d.refobjsubid>=0 "
        "AND r.ev_enabled IN ('O','A') AND edge.operation IS NOT NULL UNION "
        "SELECT i.inhparent,i.inhrelid,'*',0::oid,false,false,NULL::smallint[],true "
        "FROM pg_inherits i),"
        "rewrite_functions(source_oid,function_oid,edge_operation) AS ("
        "SELECT r.ev_class,d.refobjid,edge.operation FROM pg_rewrite r "
        "JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid "
        "CROSS JOIN LATERAL (VALUES (CASE WHEN r.rulename='_RETURN' THEN '*' "
        "WHEN r.ev_type='1' THEN 'S' WHEN r.ev_type='2' THEN 'U' "
        "WHEN r.ev_type='3' THEN 'I' WHEN r.ev_type='4' THEN 'D' END)) "
        "edge(operation) WHERE r.ev_enabled IN ('O','A') "
        "AND d.refclassid='pg_proc'::regclass AND edge.operation IS NOT NULL UNION "
        "SELECT r.ev_class,o.oprcode,edge.operation FROM pg_rewrite r "
        "JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid "
        "JOIN pg_operator o ON d.refclassid='pg_operator'::regclass "
        "AND o.oid=d.refobjid CROSS JOIN LATERAL (VALUES (CASE "
        "WHEN r.rulename='_RETURN' THEN '*' WHEN r.ev_type='1' THEN 'S' "
        "WHEN r.ev_type='2' THEN 'U' WHEN r.ev_type='3' THEN 'I' "
        "WHEN r.ev_type='4' THEN 'D' END)) edge(operation) "
        "WHERE r.ev_enabled IN ('O','A') AND edge.operation IS NOT NULL UNION "
        "SELECT r.ev_class,c.castfunc,edge.operation FROM pg_rewrite r "
        "JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid "
        "JOIN pg_cast c ON d.refclassid='pg_cast'::regclass AND c.oid=d.refobjid "
        "CROSS JOIN LATERAL (VALUES (CASE WHEN r.rulename='_RETURN' THEN '*' "
        "WHEN r.ev_type='1' THEN 'S' WHEN r.ev_type='2' THEN 'U' "
        "WHEN r.ev_type='3' THEN 'I' WHEN r.ev_type='4' THEN 'D' END)) "
        "edge(operation) WHERE r.ev_enabled IN ('O','A') AND c.castfunc<>0 "
        "AND edge.operation IS NOT NULL),"
        "capability_seeds(principal_name,principal_oid,relation_oid,operation,"
        "attribute_numbers) AS ("
        "SELECT DISTINCT role.role_name,role.role_oid,c.oid,operation.name,CASE "
        "WHEN (CASE operation.name "
        "WHEN 'I' THEN has_table_privilege(role.role_name,c.oid,'INSERT') "
        "WHEN 'U' THEN has_table_privilege(role.role_name,c.oid,'UPDATE') "
        "WHEN 'S' THEN has_table_privilege(role.role_name,c.oid,'SELECT') "
        "ELSE true END) THEN NULL::smallint[] ELSE ARRAY(SELECT a.attnum "
        "FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 "
        "AND NOT a.attisdropped AND has_column_privilege(role.role_name,c.oid,a.attnum,"
        "CASE operation.name WHEN 'I' THEN 'INSERT' WHEN 'U' THEN 'UPDATE' "
        "ELSE 'SELECT' END) ORDER BY a.attnum)::smallint[] END "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN role_names role "
        "CROSS JOIN (VALUES ('I'),('U'),('D'),('T'),('S')) operation(name) "
        "WHERE n.nspname<>%s AND NOT (n.nspname=ANY(%s)) "
        "AND n.nspname<>'information_schema' AND n.nspname !~ '^pg_' "
        "AND c.relkind IN ('r','p','v','m','f') "
        "AND has_schema_privilege(role.role_name,n.oid,'USAGE') AND CASE operation.name "
        "WHEN 'I' THEN has_table_privilege(role.role_name,c.oid,'INSERT') OR "
        "has_any_column_privilege(role.role_name,c.oid,'INSERT') "
        "WHEN 'U' THEN has_table_privilege(role.role_name,c.oid,'UPDATE') OR "
        "has_any_column_privilege(role.role_name,c.oid,'UPDATE') "
        "WHEN 'D' THEN has_table_privilege(role.role_name,c.oid,'DELETE') "
        "WHEN 'T' THEN has_table_privilege(role.role_name,c.oid,'TRUNCATE') "
        "WHEN 'S' THEN has_table_privilege(role.role_name,c.oid,'SELECT') OR "
        "has_any_column_privilege(role.role_name,c.oid,'SELECT') END),"
        "reachable(principal_name,principal_oid,check_oid,relation_oid,operation,"
        "attribute_numbers) AS ("
        "SELECT principal_name,principal_oid,principal_oid,relation_oid,operation,"
        "attribute_numbers "
        "FROM capability_seeds UNION "
        "SELECT path.principal_name,path.principal_oid,CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END,"
        "edge.target_oid,path.operation,CASE "
        "WHEN edge.preserve_attributes AND path.attribute_numbers IS NULL "
        "THEN NULL::smallint[] WHEN edge.preserve_attributes AND (SELECT count(*) "
        "FROM pg_attribute source_attribute JOIN pg_attribute target_attribute "
        "ON target_attribute.attrelid=edge.target_oid "
        "AND target_attribute.attname=source_attribute.attname "
        "AND target_attribute.attnum>0 AND NOT target_attribute.attisdropped "
        "WHERE source_attribute.attrelid=edge.source_oid "
        "AND source_attribute.attnum=ANY(path.attribute_numbers) "
        "AND source_attribute.attnum>0 AND NOT source_attribute.attisdropped)="
        "cardinality(path.attribute_numbers) THEN ARRAY(SELECT "
        "target_attribute.attnum::smallint FROM pg_attribute source_attribute "
        "JOIN pg_attribute target_attribute ON target_attribute.attrelid=edge.target_oid "
        "AND target_attribute.attname=source_attribute.attname "
        "AND target_attribute.attnum>0 AND NOT target_attribute.attisdropped "
        "WHERE source_attribute.attrelid=edge.source_oid "
        "AND source_attribute.attnum=ANY(path.attribute_numbers) "
        "AND source_attribute.attnum>0 AND NOT source_attribute.attisdropped "
        "ORDER BY source_attribute.attnum) WHEN edge.preserve_attributes "
        "THEN NULL::smallint[] ELSE edge.target_attributes END "
        "FROM reachable path JOIN relation_edges edge "
        "ON edge.source_oid=path.relation_oid "
        "AND edge.edge_operation IN ('*',path.operation) "
        "JOIN pg_class target ON target.oid=edge.target_oid "
        "JOIN pg_namespace target_namespace ON target_namespace.oid=target.relnamespace "
        "WHERE (NOT edge.requires_acl OR (has_schema_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target_namespace.oid,'USAGE') AND CASE path.operation "
        "WHEN 'I' THEN has_table_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'INSERT') OR has_any_column_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'INSERT') WHEN 'U' THEN has_table_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'UPDATE') OR has_any_column_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'UPDATE') WHEN 'D' THEN has_table_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'DELETE') WHEN 'T' THEN has_table_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'TRUNCATE') ELSE has_table_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'SELECT') OR has_any_column_privilege(pg_get_userbyid(CASE "
        "WHEN edge.use_origin_check THEN path.principal_oid "
        "WHEN edge.check_role_oid<>0 THEN edge.check_role_oid ELSE path.check_oid END),"
        "target.oid,'SELECT') END))),"
        "attribute_types(principal_name,principal_oid,check_oid,source_oid,operation,"
        "attribute_numbers,type_oid) AS ("
        "SELECT reached.principal_name,reached.principal_oid,reached.check_oid,"
        "a.attrelid,reached.operation,reached.attribute_numbers,a.atttypid "
        "FROM pg_attribute a JOIN reachable reached "
        "ON reached.relation_oid=a.attrelid WHERE a.attnum>0 "
        "AND NOT a.attisdropped AND (reached.attribute_numbers IS NULL "
        "OR a.attnum=ANY(reached.attribute_numbers)) UNION "
        "SELECT reached.principal_name,reached.principal_oid,reached.check_oid,"
        "index.indrelid,reached.operation,reached.attribute_numbers,"
        "index_attribute.atttypid FROM reachable reached JOIN pg_index index "
        "ON index.indrelid=reached.relation_oid CROSS JOIN LATERAL "
        "unnest(index.indkey::smallint[]) WITH ORDINALITY key(attnum,ordinality) "
        "JOIN pg_attribute index_attribute "
        "ON index_attribute.attrelid=index.indexrelid "
        "AND index_attribute.attnum=key.ordinality WHERE key.attnum=0 "
        "AND index.indislive AND ((reached.operation='S' AND index.indisvalid) "
        "OR (reached.operation IN ('I','U') AND index.indisready)) UNION "
        "SELECT types.principal_name,types.principal_oid,types.check_oid,"
        "types.source_oid,types.operation,types.attribute_numbers,nested.type_oid "
        "FROM attribute_types types "
        "JOIN pg_type t ON t.oid=types.type_oid CROSS JOIN LATERAL ("
        "SELECT t.typbasetype type_oid WHERE t.typbasetype<>0 UNION "
        "SELECT t.typelem WHERE t.typelem<>0 UNION "
        "SELECT range.rngtypid FROM pg_range range "
        "WHERE range.rngmultitypid=t.oid UNION "
        "SELECT range.rngsubtype FROM pg_range range "
        "WHERE range.rngtypid=t.oid OR range.rngmultitypid=t.oid UNION "
        "SELECT a.atttypid FROM pg_attribute a WHERE a.attrelid=t.typrelid "
        "AND t.typrelid<>0 AND a.attnum>0 AND NOT a.attisdropped) nested),"
        "expression_roots(source_oid,class_oid,object_oid,operation,policy_role,"
        "attribute_number,acl_independent) AS ("
        "SELECT d.adrelid,'pg_attrdef'::regclass,d.oid,operation.name,NULL::oid,"
        "CASE WHEN a.attgenerated='' THEN d.adnum ELSE NULL::smallint END,"
        "false "
        "FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid "
        "AND a.attnum=d.adnum CROSS JOIN (VALUES ('I'),('U')) operation(name) "
        "WHERE operation.name IN ('I','U') UNION "
        "SELECT k.conrelid,'pg_constraint'::regclass,k.oid,operation.name,NULL::oid,"
        "NULL::smallint,false "
        "FROM pg_constraint k CROSS JOIN (VALUES ('I'),('U')) operation(name) "
        "WHERE k.conrelid<>0 AND k.contype IN ('c','x') UNION "
        "SELECT types.source_oid,'pg_constraint'::regclass,k.oid,operation.name,"
        "NULL::oid,NULL::smallint,false "
        "FROM attribute_types types JOIN pg_constraint k ON k.contypid=types.type_oid "
        "CROSS JOIN LATERAL (VALUES (types.operation)) operation(name) "
        "WHERE k.contype='c' AND types.operation IN ('I','U') UNION "
        "SELECT policy.polrelid,'pg_policy'::regclass,policy.oid,operation.name,"
        "policy_role.role_oid,NULL::smallint,false FROM pg_policy policy "
        "JOIN pg_class relation "
        "ON relation.oid=policy.polrelid CROSS JOIN LATERAL "
        "unnest(policy.polroles) policy_role(role_oid) "
        "CROSS JOIN (VALUES ('S'),('I'),('U'),('D')) operation(name) "
        "WHERE relation.relrowsecurity AND (policy.polcmd='*' OR "
        "(policy.polcmd='r' AND operation.name IN ('S','U','D')) OR "
        "(policy.polcmd='a' AND operation.name='I') OR "
        "(policy.polcmd='w' AND operation.name='U') OR "
        "(policy.polcmd='d' AND operation.name='D')) UNION "
        "SELECT index.indrelid,'pg_class'::regclass,index.indexrelid,"
        "operation.name,NULL::oid,NULL::smallint,true FROM pg_index index "
        "CROSS JOIN (VALUES ('I'),('U')) operation(name) "
        "WHERE index.indislive AND index.indisready "
        "AND (index.indexprs IS NOT NULL OR index.indpred IS NOT NULL) UNION "
        "SELECT partition.partrelid,'pg_class'::regclass,partition.partrelid,"
        "operation.name,NULL::oid,-1::smallint,false "
        "FROM pg_partitioned_table partition "
        "CROSS JOIN (VALUES ('S'),('I'),('U'),('D')) operation(name) "
        "WHERE partition.partexprs IS NOT NULL),"
        "expression_functions(source_oid,operation,policy_role,attribute_number,"
        "acl_independent,function_oid) AS ("
        "SELECT root.source_oid,root.operation,root.policy_role,root.attribute_number,"
        "root.acl_independent,"
        "d.refobjid "
        "FROM expression_roots root JOIN pg_depend d ON d.classid=root.class_oid "
        "AND d.objid=root.object_oid WHERE d.refclassid='pg_proc'::regclass UNION "
        "SELECT root.source_oid,root.operation,root.policy_role,root.attribute_number,"
        "root.acl_independent,"
        "operator.oprcode "
        "FROM expression_roots root JOIN pg_depend d ON d.classid=root.class_oid "
        "AND d.objid=root.object_oid JOIN pg_operator operator "
        "ON d.refclassid='pg_operator'::regclass AND operator.oid=d.refobjid UNION "
        "SELECT root.source_oid,root.operation,root.policy_role,root.attribute_number,"
        "root.acl_independent,"
        "cast_row.castfunc "
        "FROM expression_roots root JOIN pg_depend d ON d.classid=root.class_oid "
        "AND d.objid=root.object_oid JOIN pg_cast cast_row "
        "ON d.refclassid='pg_cast'::regclass AND cast_row.oid=d.refobjid "
        "WHERE cast_row.castfunc<>0 UNION "
        "SELECT root.source_oid,root.operation,root.policy_role,root.attribute_number,"
        "root.acl_independent,support.function_oid FROM expression_roots root "
        "JOIN pg_depend d ON d.classid=root.class_oid AND d.objid=root.object_oid "
        "JOIN pg_type type ON d.refclassid='pg_type'::regclass "
        "AND type.oid=d.refobjid CROSS JOIN LATERAL unnest("
        "ARRAY[type.typinput,type.typreceive,type.typsubscript]) "
        "support(function_oid) WHERE support.function_oid<>0),"
        "index_callbacks(source_oid,operation,function_oid) AS ("
        "SELECT index.indrelid,operation.name,procedure.amproc "
        "FROM pg_index index CROSS JOIN (VALUES ('I'),('U'),('S')) operation(name) "
        "CROSS JOIN LATERAL unnest(index.indclass::oid[]) class_oid "
        "JOIN pg_opclass class ON class.oid=class_oid "
        "JOIN pg_am class_method ON class_method.oid=class.opcmethod "
        "JOIN pg_amproc procedure ON procedure.amprocfamily=class.opcfamily "
        "AND procedure.amproclefttype=class.opcintype "
        "AND procedure.amprocrighttype=class.opcintype "
        "AND ((class_method.amname='btree' AND procedure.amprocnum=1) OR "
        "(class_method.amname='hash' AND procedure.amprocnum IN (1,2)) OR "
        "class_method.amname NOT IN ('btree','hash')) "
        "WHERE index.indislive AND ((operation.name='S' AND index.indisvalid) OR "
        "(operation.name IN ('I','U') AND index.indisready)) UNION "
        "SELECT index.indrelid,operation.name,method.amhandler "
        "FROM pg_index index JOIN pg_class index_relation "
        "ON index_relation.oid=index.indexrelid JOIN pg_am method "
        "ON method.oid=index_relation.relam "
        "CROSS JOIN (VALUES ('I'),('U'),('S')) operation(name) "
        "WHERE index.indislive AND ((operation.name='S' AND index.indisvalid) OR "
        "(operation.name IN ('I','U') AND index.indisready)) "
        "AND method.amhandler<>0 UNION "
        "SELECT constraint_row.conrelid,operation.name,operator.oprcode "
        "FROM pg_constraint constraint_row JOIN pg_index index "
        "ON index.indexrelid=constraint_row.conindid "
        "CROSS JOIN LATERAL unnest(constraint_row.conexclop) operator_oid "
        "JOIN pg_operator operator ON operator.oid=operator_oid "
        "CROSS JOIN (VALUES ('I'),('U')) operation(name) "
        "WHERE constraint_row.contype='x' AND index.indislive AND index.indisready UNION "
        "SELECT index.indrelid,operation.name,procedure.amproc FROM pg_index index "
        "CROSS JOIN LATERAL unnest(index.indclass::oid[]) class_oid "
        "JOIN pg_opclass class ON class.oid=class_oid JOIN pg_am method "
        "ON method.oid=class.opcmethod JOIN pg_amproc procedure "
        "ON procedure.amprocfamily=class.opcfamily "
        "AND procedure.amproclefttype=class.opcintype "
        "AND procedure.amprocrighttype=class.opcintype "
        "AND procedure.amprocnum=CASE method.amname WHEN 'btree' THEN 5 "
        "WHEN 'gist' THEN 10 WHEN 'spgist' THEN 7 WHEN 'gin' THEN 7 "
        "WHEN 'brin' THEN 5 ELSE 0 END CROSS JOIN "
        "(VALUES ('S'),('I'),('U'),('D')) operation(name) "
        "WHERE index.indislive AND ((operation.name IN ('S','D') "
        "AND index.indisvalid) OR (operation.name IN ('I','U') "
        "AND index.indisready)) AND method.amname IN "
        "('btree','gist','spgist','gin','brin')) ,"
        "partition_callbacks(source_oid,operation,attribute_numbers,function_oid) AS ("
        "SELECT partition.partrelid,operation.name,CASE WHEN key.attnum=0 "
        "THEN NULL::smallint[] ELSE ARRAY[key.attnum]::smallint[] END,procedure.amproc "
        "FROM pg_partitioned_table partition CROSS JOIN LATERAL "
        "unnest(partition.partattrs::smallint[],partition.partclass::oid[]) "
        "WITH ORDINALITY key(attnum,class_oid,key_ordinal) JOIN pg_opclass class "
        "ON class.oid=key.class_oid JOIN pg_am partition_method "
        "ON partition_method.oid=class.opcmethod JOIN pg_amproc procedure "
        "ON procedure.amprocfamily=class.opcfamily AND (("
        "procedure.amproclefttype=class.opcintype "
        "AND procedure.amprocrighttype=class.opcintype) OR "
        "(class.opckeytype<>0 AND procedure.amproclefttype=class.opckeytype "
        "AND procedure.amprocrighttype=class.opckeytype)) "
        "AND ((partition.partstrat IN ('l','r') "
        "AND partition_method.amname='btree' AND procedure.amprocnum=1) OR "
        "(partition.partstrat='h' AND partition_method.amname='hash' "
        "AND procedure.amprocnum=2)) CROSS JOIN "
        "(VALUES ('S'),('I'),('U'),('D')) operation(name) "
        "WHERE operation.name<>'D' OR partition.partstrat='r'),"
        "relation_type_functions(principal_name,principal_oid,check_oid,source_oid,"
        "operation,function_oid) AS ("
        "SELECT types.principal_name,types.principal_oid,types.check_oid,"
        "types.source_oid,types.operation,support.function_oid "
        "FROM attribute_types types JOIN pg_type type ON type.oid=types.type_oid "
        "CROSS JOIN LATERAL unnest(CASE types.operation "
        "WHEN 'S' THEN ARRAY[type.typoutput,type.typsend,type.typsubscript] "
        "WHEN 'U' THEN ARRAY[type.typinput,type.typreceive,type.typsubscript] "
        "ELSE ARRAY[type.typinput,type.typreceive] END) "
        "support(function_oid) WHERE types.operation IN ('S','I','U') "
        "AND support.function_oid<>0 UNION "
        "SELECT types.principal_name,types.principal_oid,types.check_oid,"
        "types.source_oid,types.operation,range.rngcanonical "
        "FROM attribute_types types JOIN pg_range range "
        "ON range.rngtypid=types.type_oid OR range.rngmultitypid=types.type_oid "
        "WHERE types.operation IN ('I','U') AND range.rngcanonical<>0),"
        "default_type_opclass_functions(principal_name,principal_oid,check_oid,"
        "source_oid,operation,function_oid) AS (SELECT DISTINCT "
        "types.principal_name,types.principal_oid,types.check_oid,types.source_oid,"
        "types.operation,procedure.amproc FROM attribute_types types "
        "JOIN pg_opclass class ON class.opcintype=types.type_oid AND class.opcdefault "
        "JOIN pg_am method ON method.oid=class.opcmethod JOIN pg_amproc procedure "
        "ON procedure.amprocfamily=class.opcfamily "
        "AND procedure.amproclefttype=class.opcintype "
        "AND procedure.amprocrighttype=class.opcintype WHERE types.operation='S' "
        "AND ((method.amname='btree' AND procedure.amprocnum IN (1,2,3)) OR "
        "(method.amname='hash' AND procedure.amprocnum=1))),"
        "range_index_functions(principal_name,principal_oid,check_oid,source_oid,"
        "operation,function_oid) AS ("
        "SELECT DISTINCT types.principal_name,types.principal_oid,types.check_oid,"
        "types.source_oid,types.operation,range.rngsubdiff "
        "FROM attribute_types types JOIN pg_range range "
        "ON range.rngtypid=types.type_oid WHERE (types.operation='S' OR "
        "(types.operation IN ('I','U') AND EXISTS (SELECT 1 FROM pg_index index "
        "JOIN pg_class index_relation ON index_relation.oid=index.indexrelid "
        "JOIN pg_am method ON method.oid=index_relation.relam "
        "WHERE index.indrelid=types.source_oid AND method.amname='gist' "
        "AND index.indislive AND index.indisready))) "
        "AND range.rngsubdiff<>0 UNION SELECT DISTINCT "
        "types.principal_name,types.principal_oid,types.check_oid,types.source_oid,"
        "types.operation,procedure.amproc FROM attribute_types types "
        "JOIN pg_range range ON range.rngtypid=types.type_oid "
        "JOIN pg_opclass subtype_class ON subtype_class.oid=range.rngsubopc "
        "JOIN pg_amproc procedure ON procedure.amprocfamily=subtype_class.opcfamily "
        "AND procedure.amproclefttype=subtype_class.opcintype "
        "AND procedure.amprocrighttype=subtype_class.opcintype "
        "AND procedure.amprocnum=1 JOIN pg_index index "
        "ON index.indrelid=types.source_oid JOIN pg_class index_relation "
        "ON index_relation.oid=index.indexrelid JOIN pg_am method "
        "ON method.oid=index_relation.relam AND method.amname='gist' "
        "WHERE types.operation IN ('S','I','U') AND index.indislive "
        "AND ((types.operation='S' AND index.indisvalid) OR "
        "(types.operation IN ('I','U') AND index.indisready))),"
        "index_cross_type_callbacks(source_oid,operation,operator_oid,function_oid,"
        "acl_independent) AS ("
        "SELECT index.indrelid,'S',operator.oid,operator.oprcode,false "
        "FROM pg_index index "
        "CROSS JOIN LATERAL unnest(index.indclass::oid[]) class_oid "
        "JOIN pg_opclass class ON class.oid=class_oid "
        "JOIN pg_amop family_operator ON family_operator.amopfamily=class.opcfamily "
        "AND family_operator.amoppurpose IN ('s','o') "
        "AND family_operator.amoplefttype=class.opcintype "
        "AND family_operator.amoprighttype<>class.opcintype "
        "JOIN pg_operator operator ON operator.oid=family_operator.amopopr "
        "WHERE index.indislive AND index.indisvalid UNION "
        "SELECT index.indrelid,'S',operator.oid,procedure.amproc,true "
        "FROM pg_index index "
        "CROSS JOIN LATERAL unnest(index.indclass::oid[]) class_oid "
        "JOIN pg_opclass class ON class.oid=class_oid "
        "JOIN pg_am method ON method.oid=class.opcmethod "
        "JOIN pg_amop family_operator ON family_operator.amopfamily=class.opcfamily "
        "AND family_operator.amoppurpose IN ('s','o') "
        "AND family_operator.amoplefttype=class.opcintype "
        "AND family_operator.amoprighttype<>class.opcintype "
        "JOIN pg_operator operator ON operator.oid=family_operator.amopopr "
        "JOIN pg_amproc procedure ON procedure.amprocfamily=class.opcfamily "
        "AND procedure.amproclefttype=family_operator.amoplefttype "
        "AND procedure.amprocrighttype=family_operator.amoprighttype "
        "AND ((method.amname='btree' AND procedure.amprocnum=1) OR "
        "(method.amname='hash' AND procedure.amprocnum IN (1,2))) "
        "WHERE index.indislive AND index.indisvalid),"
        "partition_cross_type_callbacks(source_oid,operation,operator_oid,"
        "function_oid,acl_independent) AS (SELECT partition.partrelid,"
        "operation.name,operator.oid,operator.oprcode,false "
        "FROM pg_partitioned_table partition CROSS JOIN LATERAL "
        "unnest(partition.partclass::oid[]) WITH ORDINALITY "
        "class_entry(class_oid,key_ordinal) JOIN pg_opclass class "
        "ON class.oid=class_entry.class_oid JOIN pg_am method "
        "ON method.oid=class.opcmethod JOIN pg_amop family_operator "
        "ON family_operator.amopfamily=class.opcfamily "
        "AND family_operator.amoplefttype=class.opcintype "
        "AND family_operator.amoprighttype<>class.opcintype "
        "AND family_operator.amoppurpose='s' JOIN pg_operator operator "
        "ON operator.oid=family_operator.amopopr CROSS JOIN "
        "(VALUES ('S'),('U'),('D')) operation(name) WHERE "
        "((partition.partstrat IN ('l','r') AND method.amname='btree' "
        "AND family_operator.amopstrategy BETWEEN 1 AND 5) OR "
        "(partition.partstrat='h' AND method.amname='hash' "
        "AND family_operator.amopstrategy=1)) UNION SELECT partition.partrelid,"
        "operation.name,operator.oid,procedure.amproc,true "
        "FROM pg_partitioned_table partition CROSS JOIN LATERAL "
        "unnest(partition.partclass::oid[]) WITH ORDINALITY "
        "class_entry(class_oid,key_ordinal) JOIN pg_opclass class "
        "ON class.oid=class_entry.class_oid JOIN pg_am method "
        "ON method.oid=class.opcmethod JOIN pg_amop family_operator "
        "ON family_operator.amopfamily=class.opcfamily "
        "AND family_operator.amoplefttype=class.opcintype "
        "AND family_operator.amoprighttype<>class.opcintype "
        "AND family_operator.amoppurpose='s' JOIN pg_operator operator "
        "ON operator.oid=family_operator.amopopr JOIN pg_amproc procedure "
        "ON procedure.amprocfamily=class.opcfamily "
        "AND ((method.amname='btree' AND procedure.amprocnum=1 "
        "AND procedure.amproclefttype=family_operator.amoplefttype "
        "AND procedure.amprocrighttype=family_operator.amoprighttype) OR "
        "(method.amname='hash' AND procedure.amprocnum=2 "
        "AND procedure.amproclefttype=family_operator.amoprighttype "
        "AND procedure.amprocrighttype=family_operator.amoprighttype)) "
        "CROSS JOIN (VALUES ('S'),('U'),('D')) operation(name) WHERE "
        "((partition.partstrat IN ('l','r') AND method.amname='btree' "
        "AND family_operator.amopstrategy BETWEEN 1 AND 5) OR "
        "(partition.partstrat='h' AND method.amname='hash' "
        "AND family_operator.amopstrategy=1))) "
        "SELECT n.nspname,c.relname,path.operation,c.relkind FROM reachable path "
        "JOIN pg_class c ON c.oid=path.relation_oid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE (path.operation<>'S' AND n.nspname=%s) "
        "OR c.relkind='f' OR (c.relkind IN ('r','m') AND c.relam<>0 "
        "AND NOT EXISTS (SELECT 1 FROM pg_am table_method "
        "JOIN pg_proc handler ON handler.oid=table_method.amhandler "
        "JOIN pg_namespace handler_namespace ON handler_namespace.oid=handler.pronamespace "
        "WHERE table_method.oid=c.relam AND table_method.amname='heap' "
        "AND handler_namespace.nspname='pg_catalog' "
        "AND NOT EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=handler.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e'))) OR EXISTS (SELECT 1 "
        "FROM pg_partitioned_table partition CROSS JOIN LATERAL "
        "unnest(partition.partcollation::oid[]) collation_oid "
        "JOIN pg_collation collation_row ON collation_row.oid=collation_oid "
        "JOIN pg_namespace collation_namespace "
        "ON collation_namespace.oid=collation_row.collnamespace "
        "WHERE partition.partrelid=c.oid AND collation_oid<>0 AND ("
        "collation_namespace.nspname<>'pg_catalog' OR "
        "NOT collation_row.collisdeterministic "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_collation'::regclass "
        "AND extension_dependency.objid=collation_row.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e'))) OR EXISTS ("
        "SELECT 1 FROM pg_rewrite active_rule WHERE active_rule.ev_class=c.oid "
        "AND active_rule.rulename<>'_RETURN' "
        "AND active_rule.ev_enabled IN ('O','A') AND CASE path.operation "
        "WHEN 'S' THEN active_rule.ev_type='1' WHEN 'U' THEN active_rule.ev_type='2' "
        "WHEN 'I' THEN active_rule.ev_type='3' WHEN 'D' THEN active_rule.ev_type='4' "
        "ELSE false END) OR EXISTS ("
        "SELECT 1 FROM pg_trigger t "
        "WHERE t.tgrelid=c.oid AND NOT t.tgisinternal AND t.tgenabled IN ('O','A') "
        "AND (CASE path.operation WHEN 'I' THEN t.tgtype & 4 "
        "WHEN 'U' THEN t.tgtype & 16 WHEN 'D' THEN t.tgtype & 8 "
        "WHEN 'T' THEN t.tgtype & 32 ELSE 0 END)<>0) OR EXISTS ("
        "SELECT 1 FROM pg_constraint k JOIN pg_class child ON child.oid=k.conrelid "
        "JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace "
        "WHERE k.contype='f' AND k.confrelid=c.oid AND child_namespace.nspname=%s "
        "AND ((path.operation='U' AND k.confupdtype IN ('c','n','d')) OR "
        "(path.operation='D' AND k.confdeltype IN ('c','n','d'))) "
        "AND EXISTS (SELECT 1 FROM pg_trigger action_trigger "
        "WHERE action_trigger.tgconstraint=k.oid AND action_trigger.tgrelid=c.oid "
        "AND action_trigger.tgisinternal "
        "AND action_trigger.tgenabled IN ('O','A'))) OR EXISTS ("
        "SELECT 1 FROM rewrite_functions dependency "
        "JOIN pg_proc p ON p.oid=dependency.function_oid "
        "JOIN pg_namespace function_namespace ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.edge_operation IN ('*',path.operation) "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s)) "
        "AND has_function_privilege(path.principal_name,p.oid,'EXECUTE')) OR EXISTS ("
        "SELECT 1 FROM expression_functions dependency "
        "JOIN pg_proc p ON p.oid=dependency.function_oid "
        "JOIN pg_namespace function_namespace ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND (dependency.attribute_number IS NULL OR dependency.operation<>'U' OR "
        "has_table_privilege(path.principal_name,c.oid,'UPDATE') OR "
        "(dependency.attribute_number=-1 AND EXISTS (SELECT 1 FROM pg_depend "
        "partition_dependency WHERE partition_dependency.classid='pg_class'::regclass "
        "AND partition_dependency.objid=c.oid "
        "AND partition_dependency.refclassid='pg_class'::regclass "
        "AND partition_dependency.refobjid=c.oid "
        "AND partition_dependency.refobjsubid>0 "
        "AND has_column_privilege(path.principal_name,c.oid,"
        "partition_dependency.refobjsubid::smallint,'UPDATE'))) OR "
        "has_column_privilege(path.principal_name,c.oid,"
        "dependency.attribute_number,'UPDATE')) "
        "AND (dependency.policy_role IS NULL OR ((dependency.policy_role=0 "
        "OR pg_has_role(path.check_oid,dependency.policy_role,'USAGE')) "
        "AND (c.relforcerowsecurity OR NOT pg_has_role(path.check_oid,c.relowner,'USAGE')) "
        "AND NOT EXISTS (SELECT 1 FROM pg_roles check_role "
        "WHERE check_role.oid=path.check_oid "
        "AND (check_role.rolsuper OR check_role.rolbypassrls)))) "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s)) "
        "AND (dependency.acl_independent OR "
        "has_function_privilege(path.principal_name,p.oid,'EXECUTE'))) OR EXISTS ("
        "SELECT 1 FROM index_callbacks dependency "
        "JOIN pg_proc p ON p.oid=dependency.function_oid "
        "JOIN pg_namespace function_namespace ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s))) OR EXISTS ("
        "SELECT 1 FROM partition_callbacks dependency JOIN pg_proc p "
        "ON p.oid=dependency.function_oid JOIN pg_namespace function_namespace "
        "ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation AND (path.operation IN ('I','U') OR "
        "path.attribute_numbers IS NULL "
        "OR dependency.attribute_numbers IS NULL OR "
        "path.attribute_numbers&&dependency.attribute_numbers) "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s))) OR EXISTS ("
        "SELECT 1 FROM default_type_opclass_functions dependency JOIN pg_proc p "
        "ON p.oid=dependency.function_oid JOIN pg_namespace function_namespace "
        "ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND dependency.principal_name=path.principal_name "
        "AND dependency.principal_oid=path.principal_oid "
        "AND dependency.check_oid=path.check_oid "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s))) OR EXISTS ("
        "SELECT 1 FROM relation_type_functions dependency "
        "JOIN pg_proc p ON p.oid=dependency.function_oid "
        "JOIN pg_namespace function_namespace ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND dependency.principal_name=path.principal_name "
        "AND dependency.principal_oid=path.principal_oid "
        "AND dependency.check_oid=path.check_oid "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s))) OR EXISTS ("
        "SELECT 1 FROM range_index_functions dependency JOIN pg_proc p "
        "ON p.oid=dependency.function_oid JOIN pg_namespace function_namespace "
        "ON function_namespace.oid=p.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND dependency.principal_name=path.principal_name "
        "AND dependency.principal_oid=path.principal_oid "
        "AND dependency.check_oid=path.check_oid "
        "AND (function_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (function_namespace.nspname=ANY(%s))) OR EXISTS ("
        "SELECT 1 FROM index_cross_type_callbacks dependency "
        "JOIN pg_operator operator ON operator.oid=dependency.operator_oid "
        "JOIN pg_namespace operator_namespace ON operator_namespace.oid=operator.oprnamespace "
        "JOIN pg_proc callback ON callback.oid=dependency.function_oid "
        "JOIN pg_namespace callback_namespace ON callback_namespace.oid=callback.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND has_schema_privilege(path.principal_name,operator_namespace.oid,'USAGE') "
        "AND has_function_privilege(path.principal_name,operator.oprcode,'EXECUTE') "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) "
        "AND (dependency.acl_independent OR "
        "has_function_privilege(path.principal_name,callback.oid,'EXECUTE'))) OR "
        "EXISTS (SELECT 1 FROM partition_cross_type_callbacks dependency "
        "JOIN pg_operator operator ON operator.oid=dependency.operator_oid "
        "JOIN pg_namespace operator_namespace "
        "ON operator_namespace.oid=operator.oprnamespace JOIN pg_proc callback "
        "ON callback.oid=dependency.function_oid JOIN pg_namespace callback_namespace "
        "ON callback_namespace.oid=callback.pronamespace "
        "WHERE dependency.source_oid=path.relation_oid "
        "AND dependency.operation=path.operation "
        "AND has_schema_privilege(path.principal_name,operator_namespace.oid,'USAGE') "
        "AND has_function_privilege(path.principal_name,operator.oprcode,'EXECUTE') "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) "
        "AND (dependency.acl_independent OR "
        "has_function_privilege(path.principal_name,callback.oid,'EXECUTE')))"
        " LIMIT 1",
        (
            runtime_role,
            observer_role,
            schema,
            trusted_siblings,
            schema,
            schema,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
        ),
    ).fetchone()
    if external_trigger_or_foreign_write is not None:
        raise invalid
    direct_type_capability = connection.execute(
        "WITH RECURSIVE role_names(role_name) AS (VALUES (%s),(%s)),"
        "type_seeds(principal_name,type_oid) AS ("
        "SELECT role.role_name,type.oid FROM pg_type type "
        "JOIN pg_namespace namespace ON namespace.oid=type.typnamespace "
        "CROSS JOIN role_names role WHERE namespace.nspname<>%s "
        "AND NOT (namespace.nspname=ANY(%s)) "
        "AND has_schema_privilege(role.role_name,namespace.oid,'USAGE') "
        "AND has_type_privilege(role.role_name,type.oid,'USAGE') UNION "
        "SELECT role.role_name,signature.type_oid FROM pg_proc function "
        "JOIN pg_namespace namespace ON namespace.oid=function.pronamespace "
        "CROSS JOIN role_names role CROSS JOIN LATERAL unnest("
        "coalesce(function.proallargtypes,function.proargtypes::oid[]) || "
        "ARRAY[function.prorettype] || CASE WHEN function.provariadic<>0 "
        "THEN ARRAY[function.provariadic] ELSE ARRAY[]::oid[] END) "
        "signature(type_oid) WHERE namespace.nspname<>%s "
        "AND NOT (namespace.nspname=ANY(%s)) "
        "AND has_schema_privilege(role.role_name,namespace.oid,'USAGE') "
        "AND has_function_privilege(role.role_name,function.oid,'EXECUTE') UNION "
        "SELECT role.role_name,signature.type_oid FROM pg_operator operator "
        "JOIN pg_namespace namespace ON namespace.oid=operator.oprnamespace "
        "CROSS JOIN role_names role CROSS JOIN LATERAL unnest("
        "ARRAY[operator.oprleft,operator.oprright,operator.oprresult]) "
        "signature(type_oid) WHERE signature.type_oid<>0 "
        "AND namespace.nspname<>%s AND NOT (namespace.nspname=ANY(%s)) "
        "AND has_schema_privilege(role.role_name,namespace.oid,'USAGE') "
        "AND has_function_privilege(role.role_name,operator.oprcode,'EXECUTE') UNION "
        "SELECT role.role_name,signature.type_oid FROM pg_cast cast_row "
        "JOIN pg_type source_type ON source_type.oid=cast_row.castsource "
        "JOIN pg_namespace source_namespace "
        "ON source_namespace.oid=source_type.typnamespace "
        "JOIN pg_type target_type ON target_type.oid=cast_row.casttarget "
        "JOIN pg_namespace target_namespace "
        "ON target_namespace.oid=target_type.typnamespace "
        "CROSS JOIN role_names role CROSS JOIN LATERAL (VALUES "
        "(source_type.oid),(target_type.oid)) signature(type_oid) "
        "WHERE has_schema_privilege(role.role_name,source_namespace.oid,'USAGE') "
        "AND has_type_privilege(role.role_name,source_type.oid,'USAGE') "
        "AND has_schema_privilege(role.role_name,target_namespace.oid,'USAGE') "
        "AND has_type_privilege(role.role_name,target_type.oid,'USAGE')),"
        "type_closure(principal_name,type_oid) AS ("
        "SELECT principal_name,type_oid FROM type_seeds UNION "
        "SELECT closure.principal_name,nested.type_oid FROM type_closure closure "
        "JOIN pg_type type ON type.oid=closure.type_oid CROSS JOIN LATERAL ("
        "SELECT type.typbasetype type_oid WHERE type.typbasetype<>0 UNION "
        "SELECT type.typelem WHERE type.typelem<>0 UNION "
        "SELECT range.rngtypid FROM pg_range range "
        "WHERE range.rngmultitypid=type.oid UNION "
        "SELECT range.rngsubtype FROM pg_range range "
        "WHERE range.rngtypid=type.oid OR range.rngmultitypid=type.oid UNION "
        "SELECT attribute.atttypid FROM pg_attribute attribute "
        "WHERE attribute.attrelid=type.typrelid AND type.typrelid<>0 "
        "AND attribute.attnum>0 AND NOT attribute.attisdropped) nested),"
        "type_functions(principal_name,function_oid,acl_independent) AS ("
        "SELECT closure.principal_name,support.function_oid,false "
        "FROM type_closure closure "
        "JOIN pg_type type ON type.oid=closure.type_oid CROSS JOIN LATERAL "
        "unnest(ARRAY[type.typinput,type.typoutput,type.typreceive,type.typsend]) "
        "support(function_oid) WHERE support.function_oid<>0 UNION "
        "SELECT closure.principal_name,type.typsubscript,true "
        "FROM type_closure closure JOIN pg_type type ON type.oid=closure.type_oid "
        "WHERE type.typsubscript<>0 UNION "
        "SELECT closure.principal_name,range.rngcanonical,true "
        "FROM type_closure closure "
        "JOIN pg_range range ON range.rngtypid=closure.type_oid "
        "OR range.rngmultitypid=closure.type_oid WHERE range.rngcanonical<>0 UNION "
        "SELECT closure.principal_name,procedure.amproc,true "
        "FROM type_closure closure "
        "JOIN pg_range range ON range.rngtypid=closure.type_oid "
        "OR range.rngmultitypid=closure.type_oid "
        "JOIN pg_opclass class ON class.oid=range.rngsubopc "
        "JOIN pg_amproc procedure ON procedure.amprocfamily=class.opcfamily "
        "AND procedure.amproclefttype=class.opcintype "
        "AND procedure.amprocrighttype=class.opcintype UNION "
        "SELECT closure.principal_name,dependency.refobjid,false "
        "FROM type_closure closure "
        "JOIN pg_constraint constraint_row ON constraint_row.contypid=closure.type_oid "
        "JOIN pg_depend dependency ON dependency.classid='pg_constraint'::regclass "
        "AND dependency.objid=constraint_row.oid "
        "WHERE dependency.refclassid='pg_proc'::regclass UNION "
        "SELECT closure.principal_name,operator.oprcode,false "
        "FROM type_closure closure "
        "JOIN pg_constraint constraint_row ON constraint_row.contypid=closure.type_oid "
        "JOIN pg_depend dependency ON dependency.classid='pg_constraint'::regclass "
        "AND dependency.objid=constraint_row.oid "
        "JOIN pg_operator operator ON dependency.refclassid='pg_operator'::regclass "
        "AND operator.oid=dependency.refobjid) "
        "SELECT 1 FROM type_functions capability JOIN pg_proc function "
        "ON function.oid=capability.function_oid JOIN pg_namespace namespace "
        "ON namespace.oid=function.pronamespace WHERE "
        "(namespace.nspname NOT IN ('pg_catalog','information_schema') OR EXISTS ("
        "SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=function.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (namespace.nspname=ANY(%s)) "
        "AND (capability.acl_independent OR has_function_privilege("
        "capability.principal_name,function.oid,'EXECUTE')) LIMIT 1",
        (
            runtime_role,
            observer_role,
            schema,
            trusted_siblings,
            schema,
            trusted_siblings,
            schema,
            trusted_siblings,
            trusted_siblings,
        ),
    ).fetchone()
    if direct_type_capability is not None:
        raise invalid
    oid_bound_callable = connection.execute(
        "WITH RECURSIVE role_names(role_name) AS (VALUES (%s),(%s)),"
        "default_types(routine_oid,type_oid) AS ("
        "SELECT dependency.objid,dependency.refobjid FROM pg_depend dependency "
        "WHERE dependency.classid='pg_proc'::regclass "
        "AND dependency.refclassid='pg_type'::regclass UNION "
        "SELECT types.routine_oid,nested.type_oid FROM default_types types "
        "JOIN pg_type type ON type.oid=types.type_oid CROSS JOIN LATERAL ("
        "SELECT type.typbasetype type_oid WHERE type.typbasetype<>0 UNION "
        "SELECT type.typelem WHERE type.typelem<>0 UNION "
        "SELECT range.rngtypid FROM pg_range range "
        "WHERE range.rngmultitypid=type.oid UNION "
        "SELECT range.rngsubtype FROM pg_range range "
        "WHERE range.rngtypid=type.oid OR range.rngmultitypid=type.oid UNION "
        "SELECT attribute.atttypid FROM pg_attribute attribute "
        "WHERE attribute.attrelid=type.typrelid AND type.typrelid<>0 "
        "AND attribute.attnum>0 AND NOT attribute.attisdropped) nested),"
        "default_functions(routine_oid,function_oid,acl_independent) AS ("
        "SELECT dependency.objid,dependency.refobjid,false FROM pg_depend dependency "
        "WHERE dependency.classid='pg_proc'::regclass "
        "AND dependency.refclassid='pg_proc'::regclass UNION "
        "SELECT dependency.objid,operator.oprcode,false FROM pg_depend dependency "
        "JOIN pg_operator operator ON dependency.refclassid='pg_operator'::regclass "
        "AND operator.oid=dependency.refobjid "
        "WHERE dependency.classid='pg_proc'::regclass UNION "
        "SELECT dependency.objid,cast_row.castfunc,false FROM pg_depend dependency "
        "JOIN pg_cast cast_row ON dependency.refclassid='pg_cast'::regclass "
        "AND cast_row.oid=dependency.refobjid WHERE dependency.classid='pg_proc'::regclass "
        "AND cast_row.castfunc<>0 UNION "
        "SELECT types.routine_oid,support.function_oid,true FROM default_types types "
        "JOIN pg_type type ON type.oid=types.type_oid CROSS JOIN LATERAL unnest("
        "ARRAY[type.typinput,type.typoutput,type.typreceive,type.typsend,"
        "type.typsubscript]) support(function_oid) WHERE support.function_oid<>0 UNION "
        "SELECT types.routine_oid,range.rngcanonical,true FROM default_types types "
        "JOIN pg_range range ON range.rngtypid=types.type_oid "
        "OR range.rngmultitypid=types.type_oid WHERE range.rngcanonical<>0 UNION "
        "SELECT types.routine_oid,dependency.refobjid,false FROM default_types types "
        "JOIN pg_constraint constraint_row ON constraint_row.contypid=types.type_oid "
        "JOIN pg_depend dependency ON dependency.classid='pg_constraint'::regclass "
        "AND dependency.objid=constraint_row.oid "
        "WHERE dependency.refclassid='pg_proc'::regclass UNION "
        "SELECT types.routine_oid,operator.oprcode,false FROM default_types types "
        "JOIN pg_constraint constraint_row ON constraint_row.contypid=types.type_oid "
        "JOIN pg_depend dependency ON dependency.classid='pg_constraint'::regclass "
        "AND dependency.objid=constraint_row.oid "
        "JOIN pg_operator operator ON dependency.refclassid='pg_operator'::regclass "
        "AND operator.oid=dependency.refobjid) "
        "SELECT 1 FROM pg_operator operator "
        "JOIN pg_namespace operator_namespace "
        "ON operator_namespace.oid=operator.oprnamespace "
        "JOIN pg_proc callback ON callback.oid=operator.oprcode "
        "JOIN pg_namespace callback_namespace ON callback_namespace.oid=callback.pronamespace "
        "CROSS JOIN role_names role WHERE operator_namespace.nspname<>%s "
        "AND NOT (operator_namespace.nspname=ANY(%s)) "
        "AND callback.prosecdef "
        "AND has_schema_privilege(role.role_name,operator_namespace.oid,'USAGE') "
        "AND has_function_privilege(role.role_name,callback.oid,'EXECUTE') "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) UNION ALL "
        "SELECT 1 FROM pg_cast cast_row "
        "JOIN pg_type source_type ON source_type.oid=cast_row.castsource "
        "JOIN pg_namespace source_namespace "
        "ON source_namespace.oid=source_type.typnamespace "
        "JOIN pg_type target_type ON target_type.oid=cast_row.casttarget "
        "JOIN pg_namespace target_namespace "
        "ON target_namespace.oid=target_type.typnamespace "
        "JOIN pg_proc callback ON callback.oid=cast_row.castfunc "
        "JOIN pg_namespace callback_namespace ON callback_namespace.oid=callback.pronamespace "
        "CROSS JOIN role_names role WHERE cast_row.castfunc<>0 "
        "AND callback.prosecdef "
        "AND has_schema_privilege(role.role_name,source_namespace.oid,'USAGE') "
        "AND has_type_privilege(role.role_name,source_type.oid,'USAGE') "
        "AND has_schema_privilege(role.role_name,target_namespace.oid,'USAGE') "
        "AND has_type_privilege(role.role_name,target_type.oid,'USAGE') "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) UNION ALL "
        "SELECT 1 FROM pg_proc routine "
        "JOIN pg_namespace routine_namespace ON routine_namespace.oid=routine.pronamespace "
        "JOIN pg_proc callback ON callback.oid=routine.prosupport "
        "JOIN pg_namespace callback_namespace ON callback_namespace.oid=callback.pronamespace "
        "CROSS JOIN role_names role WHERE routine.prosupport<>0 "
        "AND routine_namespace.nspname<>%s "
        "AND NOT (routine_namespace.nspname=ANY(%s)) "
        "AND has_schema_privilege(role.role_name,routine_namespace.oid,'USAGE') "
        "AND has_function_privilege(role.role_name,routine.oid,'EXECUTE') "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) UNION ALL "
        "SELECT 1 FROM pg_proc routine "
        "JOIN pg_namespace routine_namespace ON routine_namespace.oid=routine.pronamespace "
        "JOIN default_functions dependency ON dependency.routine_oid=routine.oid "
        "JOIN pg_proc callback ON callback.oid=dependency.function_oid "
        "JOIN pg_namespace callback_namespace ON callback_namespace.oid=callback.pronamespace "
        "CROSS JOIN role_names role WHERE routine.pronargdefaults>0 "
        "AND routine_namespace.nspname<>%s "
        "AND NOT (routine_namespace.nspname=ANY(%s)) "
        "AND has_schema_privilege(role.role_name,routine_namespace.oid,'USAGE') "
        "AND has_function_privilege(role.role_name,routine.oid,'EXECUTE') "
        "AND (dependency.acl_independent OR "
        "has_function_privilege(role.role_name,callback.oid,'EXECUTE')) "
        "AND (callback_namespace.nspname NOT IN ('pg_catalog','information_schema') "
        "OR EXISTS (SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=callback.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) "
        "AND NOT (callback_namespace.nspname=ANY(%s)) LIMIT 1",
        (
            runtime_role,
            observer_role,
            schema,
            trusted_siblings,
            trusted_siblings,
            trusted_siblings,
            schema,
            trusted_siblings,
            trusted_siblings,
            schema,
            trusted_siblings,
            trusted_siblings,
        ),
    ).fetchone()
    if oid_bound_callable is not None:
        raise invalid
    external_executable_function = connection.execute(
        "SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname<>%s AND NOT (n.nspname=ANY(%s)) AND p.prosecdef "
        "AND (n.nspname NOT IN ('pg_catalog','information_schema') OR EXISTS ("
        "SELECT 1 FROM pg_depend extension_dependency "
        "WHERE extension_dependency.classid='pg_proc'::regclass "
        "AND extension_dependency.objid=p.oid "
        "AND extension_dependency.refclassid='pg_extension'::regclass "
        "AND extension_dependency.deptype='e')) AND ("
        "(has_schema_privilege(%s,n.oid,'USAGE') AND "
        "has_function_privilege(%s,p.oid,'EXECUTE')) OR "
        "(has_schema_privilege(%s,n.oid,'USAGE') AND "
        "has_function_privilege(%s,p.oid,'EXECUTE'))) LIMIT 1",
        (
            schema,
            trusted_siblings,
            runtime_role,
            runtime_role,
            observer_role,
            observer_role,
        ),
    ).fetchone()
    if external_executable_function is not None:
        raise invalid


def _validate_logical_replication_contract(
    connection: _Connection, schema: str
) -> None:
    invalid = ValueError("APCC authority store schema validation failed")
    replica_identity = connection.execute(
        "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relkind IN ('r','p') "
        "AND c.relreplident<>'d' LIMIT 1",
        (schema,),
    ).fetchone()
    if replica_identity is not None:
        raise invalid
    replica_identity_index = connection.execute(
        "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND i.indisreplident LIMIT 1",
        (schema,),
    ).fetchone()
    if replica_identity_index is not None:
        raise invalid
    publication_membership = connection.execute(
        "SELECT 1 FROM pg_publication p WHERE p.puballtables UNION ALL "
        "SELECT 1 FROM pg_publication_rel pr JOIN pg_class c ON c.oid=pr.prrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s UNION ALL "
        "SELECT 1 FROM pg_publication_namespace pn JOIN pg_namespace n "
        "ON n.oid=pn.pnnspid WHERE n.nspname=%s LIMIT 1",
        (schema, schema),
    ).fetchone()
    if publication_membership is not None:
        raise invalid


def _validate_parameter_contract(
    connection: _Connection, runtime_role: str, observer_role: str
) -> None:
    invalid = ValueError("APCC authority store schema validation failed")
    state = connection.execute(
        "SELECT current_setting('session_replication_role'),"
        "has_parameter_privilege(%s,'session_replication_role','SET'),"
        "has_parameter_privilege(%s,'session_replication_role','ALTER SYSTEM'),"
        "has_parameter_privilege(%s,'session_replication_role','SET'),"
        "has_parameter_privilege(%s,'session_replication_role','ALTER SYSTEM')",
        (runtime_role, runtime_role, observer_role, observer_role),
    ).fetchone()
    if state != ("origin", False, False, False, False):
        raise invalid
    public_acl = connection.execute(
        "SELECT 1 FROM pg_parameter_acl p "
        "CROSS JOIN LATERAL aclexplode(p.paracl) x "
        "LEFT JOIN pg_roles grantee ON grantee.oid=x.grantee "
        "WHERE p.parname='session_replication_role' "
        "AND (x.grantee=0 OR grantee.rolname IN (%s,%s)) "
        "AND x.privilege_type IN ('SET','ALTER SYSTEM') LIMIT 1",
        (runtime_role, observer_role),
    ).fetchone()
    if public_acl is not None:
        raise invalid


def _validate_role_contract(
    connection: _Connection,
    schema: str,
    owner_role: str,
    runtime_role: str,
    observer_role: str,
    *,
    expected_role: str,
) -> None:
    invalid = ValueError("APCC PostgreSQL privilege contract validation failed")
    _validate_role_name(owner_role)
    _validate_role_name(runtime_role)
    _validate_role_name(observer_role)
    if len({owner_role, runtime_role, observer_role}) != 3:
        raise invalid
    schema_owner = connection.execute(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s",
        (schema,),
    ).fetchone()
    if schema_owner != (owner_role,):
        raise invalid
    rows = {
        str(row[0]): tuple(row[1:])
        for row in connection.execute(
            "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
            "rolcanlogin,rolreplication,rolbypassrls,rolconfig IS NULL FROM pg_roles "
            "WHERE rolname IN (%s,%s,%s)",
            (owner_role, runtime_role, observer_role),
        )
    }
    if rows != {
        owner_role: (False, False, False, False, False, False, False, True),
        runtime_role: (False, False, False, False, True, False, False, True),
        observer_role: (False, False, False, False, True, False, False, True),
    }:
        raise invalid
    membership = connection.execute(
        "SELECT 1 FROM pg_auth_members m "
        "JOIN pg_roles member_role ON member_role.oid=m.member "
        "JOIN pg_roles granted_role ON granted_role.oid=m.roleid "
        "WHERE member_role.rolname IN (%s,%s,%s) "
        "OR granted_role.rolname IN (%s,%s,%s) LIMIT 1",
        (
            owner_role,
            runtime_role,
            observer_role,
            owner_role,
            runtime_role,
            observer_role,
        ),
    ).fetchone()
    if membership is not None:
        raise invalid
    role_setting = connection.execute(
        "SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole "
        "WHERE r.rolname IN (%s,%s,%s) LIMIT 1",
        (owner_role, runtime_role, observer_role),
    ).fetchone()
    if role_setting is not None:
        raise invalid
    default_acl = connection.execute(
        "SELECT 1 FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole "
        "JOIN pg_namespace n ON n.oid=d.defaclnamespace "
        "WHERE n.nspname=%s AND r.rolname IN (%s,%s,%s) LIMIT 1",
        (schema, owner_role, runtime_role, observer_role),
    ).fetchone()
    if default_acl is not None:
        raise invalid
    if expected_role not in {owner_role, runtime_role, observer_role}:
        raise invalid
    identity = connection.execute("SELECT session_user,current_user").fetchone()
    if (
        identity is None
        or identity[1] != expected_role
        or (expected_role != owner_role and identity[0] != expected_role)
        or (
            expected_role == owner_role and identity[0] in {runtime_role, observer_role}
        )
    ):
        raise invalid
    database_create = connection.execute(
        "SELECT has_database_privilege(%s,current_database(),'CREATE')",
        (expected_role,),
    ).fetchone()
    if database_create != (False,):
        raise invalid
    for protected_role in (owner_role, runtime_role, observer_role):
        database_contract = connection.execute(
            "SELECT has_database_privilege(%s,current_database(),'CONNECT'),"
            "has_database_privilege(%s,current_database(),'CREATE'),"
            "has_database_privilege(%s,current_database(),'TEMPORARY')",
            (protected_role, protected_role, protected_role),
        ).fetchone()
        if database_contract != (True, False, False):
            raise invalid
    schema_ready = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname='metadata')",
        (schema,),
    ).fetchone()
    if schema_ready == (False,):
        return
    if schema_ready != (True,):
        raise invalid
    for protected_role, expected in (
        (owner_role, (True, True)),
        (runtime_role, (True, False)),
        (observer_role, (True, False)),
    ):
        schema_contract = connection.execute(
            "SELECT has_schema_privilege(%s,%s,'USAGE'),"
            "has_schema_privilege(%s,%s,'CREATE')",
            (protected_role, schema, protected_role, schema),
        ).fetchone()
        if schema_contract != expected:
            raise invalid
    observer_relation_contract = connection.execute(
        """SELECT count(*),
        bool_and(has_table_privilege(%s,c.oid,'SELECT')),
        bool_and(NOT has_table_privilege(%s,c.oid,'INSERT')),
        bool_and(NOT has_table_privilege(%s,c.oid,'UPDATE')),
        bool_and(NOT has_table_privilege(%s,c.oid,'DELETE')),
        bool_and(NOT has_table_privilege(%s,c.oid,'TRUNCATE')),
        bool_and(NOT has_table_privilege(%s,c.oid,'REFERENCES')),
        bool_and(NOT has_table_privilege(%s,c.oid,'TRIGGER')),
        bool_and(NOT has_table_privilege(%s,c.oid,'MAINTAIN'))
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f')""",
        (observer_role,) * 8 + (schema,),
    ).fetchone()
    if (
        observer_relation_contract is None
        or observer_relation_contract[0] == 0
        or observer_relation_contract[1:] != (True,) * 8
    ):
        raise invalid
    runtime_relation_contract = connection.execute(
        """SELECT count(*),
        bool_and(has_table_privilege(%s,c.oid,'SELECT')),
        bool_and(CASE WHEN c.relname='semantic_checkpoint'
            THEN NOT has_table_privilege(%s,c.oid,'INSERT')
            ELSE has_table_privilege(%s,c.oid,'INSERT') END),
        bool_and(CASE WHEN c.relname='semantic_checkpoint'
            THEN NOT has_table_privilege(%s,c.oid,'UPDATE')
            ELSE has_table_privilege(%s,c.oid,'UPDATE') END),
        bool_and(CASE WHEN c.relname='semantic_checkpoint'
            THEN NOT has_table_privilege(%s,c.oid,'DELETE')
            ELSE has_table_privilege(%s,c.oid,'DELETE') END),
        bool_and(NOT has_table_privilege(%s,c.oid,'TRUNCATE')),
        bool_and(NOT has_table_privilege(%s,c.oid,'REFERENCES')),
        bool_and(NOT has_table_privilege(%s,c.oid,'TRIGGER')),
        bool_and(NOT has_table_privilege(%s,c.oid,'MAINTAIN'))
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f')""",
        (runtime_role,) * 11 + (schema,),
    ).fetchone()
    if (
        runtime_relation_contract is None
        or runtime_relation_contract[0] == 0
        or runtime_relation_contract[1:] != (True,) * 8
    ):
        raise invalid
    for protected_role in (runtime_role, observer_role):
        function_contract = connection.execute(
            "SELECT count(*),bool_and(NOT has_function_privilege(%s,p.oid,'EXECUTE')) "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname=%s",
            (protected_role, schema),
        ).fetchone()
        if (
            function_contract is None
            or function_contract[0] == 0
            or function_contract[1] is not True
        ):
            raise invalid
        sequence_contract = connection.execute(
            "SELECT count(*),coalesce(bool_and(NOT has_sequence_privilege(%s,c.oid,'USAGE') "
            "AND NOT has_sequence_privilege(%s,c.oid,'SELECT') "
            "AND NOT has_sequence_privilege(%s,c.oid,'UPDATE')),true) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND c.relkind='S'",
            (protected_role, protected_role, protected_role, schema),
        ).fetchone()
        if sequence_contract is None or sequence_contract[1] is not True:
            raise invalid


def _validate_foreign_key_integrity(connection: _Connection, schema: str) -> None:
    invalid = ValueError("APCC authority store schema validation failed")
    foreign_keys = connection.execute(
        """SELECT k.conname,k.convalidated,k.confmatchtype,
        child_namespace.nspname,child.relname,
        parent_namespace.nspname,parent.relname,
        array_agg(child_attribute.attname ORDER BY key_column.ordinality),
        array_agg(parent_attribute.attname ORDER BY key_column.ordinality)
        FROM pg_constraint k
        JOIN pg_class child ON child.oid=k.conrelid
        JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace
        JOIN pg_class parent ON parent.oid=k.confrelid
        JOIN pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace
        CROSS JOIN LATERAL unnest(k.conkey,k.confkey) WITH ORDINALITY
            AS key_column(child_number,parent_number,ordinality)
        JOIN pg_attribute child_attribute
            ON child_attribute.attrelid=child.oid
            AND child_attribute.attnum=key_column.child_number
        JOIN pg_attribute parent_attribute
            ON parent_attribute.attrelid=parent.oid
            AND parent_attribute.attnum=key_column.parent_number
        WHERE child_namespace.nspname=%s AND k.contype='f'
        GROUP BY k.oid,k.conname,k.convalidated,k.confmatchtype,
            child_namespace.nspname,child.relname,
            parent_namespace.nspname,parent.relname
        ORDER BY child.relname,k.conname""",
        (schema,),
    ).fetchall()
    for row in foreign_keys:
        (
            _,
            validated,
            match_type,
            child_namespace,
            child_table,
            parent_namespace,
            parent_table,
            child_keys,
            parent_keys,
        ) = row
        if validated is not True or match_type != "s":
            raise invalid
        if (
            not isinstance(child_namespace, str)
            or not isinstance(child_table, str)
            or not isinstance(parent_namespace, str)
            or not isinstance(parent_table, str)
        ):
            raise invalid
        if not isinstance(child_keys, list) or not isinstance(parent_keys, list):
            raise invalid
        if len(child_keys) == 0 or len(child_keys) != len(parent_keys):
            raise invalid
        child_identifiers = [_quoted_identifier(str(value)) for value in child_keys]
        parent_identifiers = [_quoted_identifier(str(value)) for value in parent_keys]
        present = " AND ".join(f"child.{key} IS NOT NULL" for key in child_identifiers)
        joined = " AND ".join(
            f"parent.{parent_key} IS NOT DISTINCT FROM child.{child_key}"
            for child_key, parent_key in zip(
                child_identifiers, parent_identifiers, strict=True
            )
        )
        child_relation = sql.Identifier(child_namespace, child_table).as_string()
        parent_relation = sql.Identifier(parent_namespace, parent_table).as_string()
        orphan = connection.execute(
            f"SELECT 1 FROM {child_relation} child "
            f"WHERE {present} AND NOT EXISTS (SELECT 1 FROM "
            f"{parent_relation} parent WHERE {joined}) "
            "LIMIT 1"
        ).fetchone()
        if orphan is not None:
            raise invalid


def _semantic_config(
    connection: _Connection,
    schema: str,
    *,
    access_role: str = "runtime",
    catalog_profile: str = _BASE_CATALOG_PROFILE,
) -> APCCAuthorityConfig:
    invalid = ValueError("APCC authority store schema validation failed")
    try:
        values = {
            str(key): str(value)
            for key, value in connection.execute(
                "SELECT key,value FROM metadata ORDER BY key"
            )
        }
    except Exception as error:
        raise invalid from error
    if values.get("schema_version") != _AUTHORITY_SCHEMA_VERSION:
        raise ValueError(_SCHEMA_VERSION_INCOMPATIBLE)
    try:
        metadata_keys = {
            "config",
            "postgres_owner_role",
            "postgres_runtime_role",
            "postgres_observer_role",
            "schema_fingerprint",
            "schema_version",
        }
        if catalog_profile == _GCB_CATALOG_PROFILE:
            metadata_keys |= {"catalog_fingerprint", "catalog_profile"}
        elif catalog_profile != _BASE_CATALOG_PROFILE:
            raise invalid
        if set(values) != metadata_keys:
            raise invalid
        owner_role = values["postgres_owner_role"]
        runtime_role = values["postgres_runtime_role"]
        observer_role = values["postgres_observer_role"]
        expected_role = {
            "owner": owner_role,
            "runtime": runtime_role,
            "observer": observer_role,
        }[access_role]
        _validate_role_contract(
            connection,
            schema,
            owner_role,
            runtime_role,
            observer_role,
            expected_role=expected_role,
        )
        actual_catalog = _catalog_fingerprint(
            connection, schema, owner_role, runtime_role, observer_role
        )
        expected_catalog = (
            _POSTGRES_GCB_CATALOG_FINGERPRINT
            if catalog_profile == _GCB_CATALOG_PROFILE
            else _POSTGRES_CATALOG_FINGERPRINT
        )
        if actual_catalog != expected_catalog:
            raise invalid
        _validate_parameter_contract(connection, runtime_role, observer_role)
        _validate_external_capability_contract(
            connection, schema, runtime_role, observer_role
        )
        _validate_logical_replication_contract(connection, schema)
        expected_schema = (
            _POSTGRES_GCB_SCHEMA_FINGERPRINT
            if catalog_profile == _GCB_CATALOG_PROFILE
            else _POSTGRES_SCHEMA_FINGERPRINT
        )
        _validate_foreign_key_integrity(connection, schema)
        if values["schema_fingerprint"] != expected_schema:
            raise invalid
        if catalog_profile == _GCB_CATALOG_PROFILE and (
            values["catalog_profile"] != _GCB_CATALOG_PROFILE
            or values["catalog_fingerprint"] != expected_catalog
        ):
            raise invalid
        config_object = _loads(values["config"])
        if _json(config_object) != values["config"]:
            raise invalid
        config = _config_from_object(config_object)
        if catalog_profile == _GCB_CATALOG_PROFILE:
            store_meta = connection.execute(
                "SELECT singleton,profile,schema_version,authority_store_id,sealed "
                "FROM gcb_store_meta"
            ).fetchall()
            if store_meta != [
                (
                    1,
                    _GCB_CATALOG_PROFILE,
                    _AUTHORITY_SCHEMA_VERSION,
                    config.authority_store_id,
                    1,
                )
            ]:
                raise invalid
        return config
    except ValueError as error:
        raise invalid from error
    except Exception as error:
        raise invalid from error


def _validate_semantics(
    connection: _Connection, config: APCCAuthorityConfig
) -> _SemanticSnapshot:
    try:
        return _validate_semantic_integrity(connection, config)
    except Exception as error:
        raise ValueError("APCC authority store semantic validation failed") from error


def _attest_store(
    connection: _Connection,
    schema: str,
    *,
    access_role: str = "runtime",
    catalog_profile: str = _BASE_CATALOG_PROFILE,
) -> APCCAuthorityConfig:
    config = _semantic_config(
        connection,
        schema,
        access_role=access_role,
        catalog_profile=catalog_profile,
    )
    _validate_semantics(connection, config)
    _verify_semantic_checkpoint(
        connection,
        config,
        (
            _POSTGRES_GCB_SCHEMA_FINGERPRINT
            if catalog_profile == _GCB_CATALOG_PROFILE
            else _POSTGRES_SCHEMA_FINGERPRINT
        ),
    )
    return config


def _validate_runtime_signers(
    config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
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


def _attest_and_seal_fresh_bootstrap(
    connection: _Connection,
    schema: str,
    expected_config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
    *,
    catalog_profile: str = _BASE_CATALOG_PROFILE,
) -> None:
    config = _semantic_config(
        connection,
        schema,
        access_role="owner",
        catalog_profile=catalog_profile,
    )
    if config != expected_config:
        raise ValueError("APCC authority store configuration mismatch")
    _validate_semantics(connection, config)
    sealed = _verify_semantic_checkpoint(
        connection,
        config,
        (
            _POSTGRES_GCB_SCHEMA_FINGERPRINT
            if catalog_profile == _GCB_CATALOG_PROFILE
            else _POSTGRES_SCHEMA_FINGERPRINT
        ),
        allow_initial_unsealed=True,
    )
    if sealed:
        raise ValueError("APCC authority bootstrap checkpoint was already sealed")
    _seal_semantic_checkpoint(
        connection,
        config,
        runtime,
        (
            _POSTGRES_GCB_SCHEMA_FINGERPRINT
            if catalog_profile == _GCB_CATALOG_PROFILE
            else _POSTGRES_SCHEMA_FINGERPRINT
        ),
    )
    if (
        _attest_store(
            connection,
            schema,
            access_role="owner",
            catalog_profile=catalog_profile,
        )
        != expected_config
    ):
        raise ValueError("APCC authority store configuration mismatch")


class PostgresAuthorityReader(_AuthorityReaderCore):
    def __init__(
        self,
        dsn: str,
        schema: str,
        config: APCCAuthorityConfig,
        status_signer: AuthorityObservationStatusSigner | None = None,
    ) -> None:
        super().__init__(config.authority_store_id, status_signer)
        self._dsn = dsn
        self.schema_name = schema
        self._config = config

    @classmethod
    def open(
        cls,
        dsn: str,
        *,
        schema: str,
        status_signer: AuthorityObservationStatusSigner | None = None,
    ) -> PostgresAuthorityReader:
        _validate_schema_name(schema)
        connection = _connect(dsn, schema)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            config = _attest_store(connection, schema, access_role="observer")
            connection.commit()
            return cls(dsn, schema, config, status_signer)
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _connection(self) -> _Connection:
        return _connect(self._dsn, self.schema_name)

    @contextmanager
    def _read_transaction(self) -> Iterator[_Connection]:
        connection = self._connection()
        try:
            # One immutable snapshot prevents a valid concurrent authority write
            # from being mistaken for a torn semantic state while attesting.
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            config = _semantic_config(
                connection, self.schema_name, access_role="observer"
            )
            if config.authority_store_id != self.authority_store_id:
                raise ValueError("APCC authority store identity mismatch")
            _verify_semantic_checkpoint(
                connection,
                config,
                _POSTGRES_SCHEMA_FINGERPRINT,
            )
            yield connection
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def close(self) -> None:
        pass


class PostgresAuthorityStore(_AuthorityStoreCore):
    def __init__(
        self,
        dsn: str,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy,
        probe: _Probe | None,
        catalog_profile: str = _BASE_CATALOG_PROFILE,
    ) -> None:
        super().__init__(config, runtime)
        self._dsn = dsn
        self.schema_name = schema
        self.authority_store_id = config.authority_store_id
        self._retry_policy = retry_policy
        self._postgres_probe = probe
        self._catalog_profile = catalog_profile
        self._local = threading.local()

    def _connection(self) -> _Connection:
        return _connect(self._dsn, self.schema_name)

    def _observation_current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus:
        """Issue status after ordered admission locks and a fresh read snapshot."""
        request = CurrentStatusRequest(certificate_digest, request_nonce)
        connection = self._connection()
        try:
            connection.raw.autocommit = True
            workflow_row = connection.execute(
                "SELECT workflow_id FROM certificates WHERE certificate_digest=%s",
                (certificate_digest,),
            ).fetchone()
            if workflow_row is None or not isinstance(workflow_row[0], str):
                raise ValueError("unknown APCC certificate")
            workflow_id = workflow_row[0]
            for lock_key, discriminator in (
                (
                    f"APCC-1/workflow/{self.authority_store_id}/"
                    f"{self.schema_name}/{workflow_id}",
                    0,
                ),
                (
                    f"APCC-1/certificate/{self.authority_store_id}/"
                    f"{self.schema_name}/{certificate_digest}",
                    2,
                ),
                (
                    f"APCC-1/trust-head/{self.authority_store_id}/{self.schema_name}",
                    1,
                ),
            ):
                connection.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s,%s))",
                    (lock_key, discriminator),
                )
            connection.raw.autocommit = False
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            rechecked = connection.execute(
                "SELECT workflow_id FROM certificates WHERE certificate_digest=%s",
                (certificate_digest,),
            ).fetchone()
            if rechecked != (workflow_id,):
                raise ValueError("APCC certificate workflow changed during status read")
            provisioned = _semantic_config(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            _verify_semantic_checkpoint(
                connection, self._config, _POSTGRES_SCHEMA_FINGERPRINT
            )
            connection.checkpoint_attested = True
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
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def stage_result(self, request: StageResultRequest) -> StageResultResult:
        self._local.workflow_id = request.subject.workflow_id
        try:
            return self._retry_known_abort(
                "result staging",
                lambda: super(PostgresAuthorityStore, self).stage_result(request),
            )
        finally:
            self._local.workflow_id = None

    def assemble_evidence(
        self, request: AssembleEvidenceRequest
    ) -> AssembleEvidenceResult:
        self._local.workflow_id = request.proposal.subject.workflow_id
        try:
            return self._retry_known_abort(
                "evidence assembly",
                lambda: super(PostgresAuthorityStore, self).assemble_evidence(request),
            )
        finally:
            self._local.workflow_id = None

    def propose_commit(self, request: ProposeCommitRequest) -> ProposeCommitResult:
        self._local.workflow_id = request.proposal.subject.workflow_id
        try:
            return self._retry_known_abort(
                "commit proposal",
                lambda: super(PostgresAuthorityStore, self).propose_commit(request),
            )
        finally:
            self._local.workflow_id = None

    def _retry_known_abort(
        self, label: str, operation: Callable[[], _ResultT]
    ) -> _ResultT:
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                return operation()
            except Exception as error:
                sqlstate = getattr(error, "sqlstate", None)
                if sqlstate not in _RETRYABLE_SQLSTATES:
                    raise
                if attempt == self._retry_policy.max_attempts:
                    raise RuntimeError(
                        f"PostgreSQL {label} transaction {sqlstate} exhausted "
                        f"after {attempt} attempts"
                    ) from error
        raise AssertionError("unreachable PostgreSQL mutation retry state")

    @classmethod
    def provision(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[CommitContext, ...],
        runtime_role: str,
        observer_role: str,
        runtime: AuthorityRuntime,
    ) -> None:
        cls._provision(
            dsn,
            schema=schema,
            config=config,
            initial_contexts=initial_contexts,
            runtime_role=runtime_role,
            observer_role=observer_role,
            runtime=runtime,
            catalog_profile=_BASE_CATALOG_PROFILE,
        )

    @classmethod
    def _provision_gcb(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[CommitContext, ...],
        runtime_role: str,
        observer_role: str,
        runtime: AuthorityRuntime,
    ) -> None:
        cls._provision(
            dsn,
            schema=schema,
            config=config,
            initial_contexts=initial_contexts,
            runtime_role=runtime_role,
            observer_role=observer_role,
            runtime=runtime,
            catalog_profile=_GCB_CATALOG_PROFILE,
        )

    @classmethod
    def _provision(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[CommitContext, ...],
        runtime_role: str,
        observer_role: str,
        runtime: AuthorityRuntime,
        catalog_profile: str,
    ) -> None:
        _validate_schema_name(schema)
        _validate_role_name(runtime_role)
        _validate_role_name(observer_role)
        _validate_runtime_signers(config, runtime)
        connection = _connect(dsn, schema)
        try:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 1777827371))",
                (f"APCC-1/provision/{schema}",),
            )
            occupied = connection.execute(
                "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=%s UNION ALL "
                "SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname=%s LIMIT 1",
                (schema, schema),
            ).fetchone()
            if occupied is not None:
                raise ValueError("APCC PostgreSQL schema is already provisioned")
            owner_row = connection.execute(
                "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s",
                (schema,),
            ).fetchone()
            if owner_row is None or not isinstance(owner_row[0], str):
                raise ValueError("APCC PostgreSQL privilege contract validation failed")
            owner_role = owner_row[0]
            _validate_role_name(owner_role)
            if owner_role == runtime_role:
                raise ValueError("APCC PostgreSQL privilege contract validation failed")
            connection.execute(f"SET LOCAL ROLE {_quoted_identifier(owner_role)}")
            connection.execute(
                f"SET LOCAL search_path TO {_quoted_identifier(schema)},"
                "pg_catalog,pg_temp"
            )
            _validate_role_contract(
                connection,
                schema,
                owner_role,
                runtime_role,
                observer_role,
                expected_role=owner_role,
            )
            bootstrap_statements = (
                _POSTGRES_GCB_BOOTSTRAP_STATEMENTS
                if catalog_profile == _GCB_CATALOG_PROFILE
                else _POSTGRES_BOOTSTRAP_STATEMENTS
            )
            for statement in bootstrap_statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES ('config',%s)",
                (_json(_config_object(config)),),
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES ('schema_fingerprint',%s)",
                (
                    _POSTGRES_GCB_SCHEMA_FINGERPRINT
                    if catalog_profile == _GCB_CATALOG_PROFILE
                    else _POSTGRES_SCHEMA_FINGERPRINT,
                ),
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES ('schema_version',%s)",
                (_AUTHORITY_SCHEMA_VERSION,),
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES "
                "('postgres_owner_role',%s),('postgres_runtime_role',%s),"
                "('postgres_observer_role',%s)",
                (owner_role, runtime_role, observer_role),
            )
            if catalog_profile == _GCB_CATALOG_PROFILE:
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES "
                    "('catalog_profile',%s),('catalog_fingerprint',%s)",
                    (
                        _GCB_CATALOG_PROFILE,
                        _POSTGRES_GCB_CATALOG_FINGERPRINT,
                    ),
                )
                connection.execute(
                    "INSERT INTO gcb_store_meta(singleton,profile,schema_version,"
                    "authority_store_id,sealed) VALUES (1,%s,%s,%s,1)",
                    (
                        _GCB_CATALOG_PROFILE,
                        _AUTHORITY_SCHEMA_VERSION,
                        config.authority_store_id,
                    ),
                )
            workflows: set[str] = set()
            for context in initial_contexts:
                _insert_context(connection, context)
                workflows.add(context.subject.workflow_id)
            for workflow_id in sorted(workflows):
                connection.execute(
                    "INSERT INTO workflow_authority(workflow_id) VALUES (%s)",
                    (workflow_id,),
                )
            connection.execute(
                "INSERT INTO semantic_checkpoint(singleton,change_sequence,"
                "prior_digest,checkpoint_digest,key_id,signature) "
                "VALUES (1,0,%s,'',%s,'')",
                (_SEMANTIC_CHECKPOINT_GENESIS, config.commit_trust.key_id),
            )
            trigger_statements = (
                _POSTGRES_GCB_TRIGGERS
                if catalog_profile == _GCB_CATALOG_PROFILE
                else _POSTGRES_TRIGGERS
            )
            for statement in trigger_statements:
                connection.execute(statement)
            _apply_privilege_contract(connection, schema, runtime_role, observer_role)
            _attest_and_seal_fresh_bootstrap(
                connection,
                schema,
                config,
                runtime,
                catalog_profile=catalog_profile,
            )
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    @classmethod
    def open(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy | None = None,
    ) -> PostgresAuthorityStore:
        return cls._open(
            dsn,
            schema,
            config,
            runtime,
            retry_policy or PostgresRetryPolicy(),
            None,
            _BASE_CATALOG_PROFILE,
        )

    @classmethod
    def _open_gcb(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy | None = None,
    ) -> PostgresAuthorityStore:
        return cls._open(
            dsn,
            schema,
            config,
            runtime,
            retry_policy or PostgresRetryPolicy(),
            None,
            _GCB_CATALOG_PROFILE,
        )

    @classmethod
    def _open_with_probe(
        cls,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy,
        probe: _Probe,
    ) -> PostgresAuthorityStore:
        return cls._open(
            dsn,
            schema,
            config,
            runtime,
            retry_policy,
            probe,
            _BASE_CATALOG_PROFILE,
        )

    @classmethod
    def _open(
        cls,
        dsn: str,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy,
        probe: _Probe | None,
        catalog_profile: str,
    ) -> PostgresAuthorityStore:
        _validate_schema_name(schema)
        _validate_runtime_signers(config, runtime)
        store = cls(
            dsn,
            schema,
            config,
            runtime,
            retry_policy,
            probe,
            catalog_profile,
        )
        store._open_and_ensure_semantic_checkpoint()
        return store

    def _open_and_ensure_semantic_checkpoint(self) -> None:
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            connection = _connect(self._dsn, self.schema_name)
            try:
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                provisioned = _attest_store(
                    connection,
                    self.schema_name,
                    catalog_profile=self._catalog_profile,
                )
                if provisioned != self._config:
                    raise ValueError(
                        "APCC authority configuration does not match provisioned store"
                    )
                connection.commit()
                return
            except Exception as error:
                try:
                    connection.rollback()
                except Exception:
                    pass
                sqlstate = getattr(error, "sqlstate", None)
                if sqlstate not in _RETRYABLE_SQLSTATES:
                    raise
                if attempt == self._retry_policy.max_attempts:
                    raise RuntimeError(
                        "PostgreSQL writer open transaction "
                        f"{sqlstate} exhausted after {attempt} attempts"
                    ) from error
            finally:
                connection.close()

    @contextmanager
    def _read_transaction(self) -> Iterator[_Connection]:
        connection = self._connection()
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            provisioned = _semantic_config(
                connection,
                self.schema_name,
                catalog_profile=self._catalog_profile,
            )
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            _verify_semantic_checkpoint(
                connection,
                self._config,
                (
                    _POSTGRES_GCB_SCHEMA_FINGERPRINT
                    if self._catalog_profile == _GCB_CATALOG_PROFILE
                    else _POSTGRES_SCHEMA_FINGERPRINT
                ),
            )
            connection.checkpoint_attested = True
            yield connection
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _attest_batch_snapshot(
        self, connection: object, certificate_digests: Sequence[str] = ()
    ) -> _SemanticSnapshot:
        """The PostgreSQL read transaction attests before yielding its snapshot."""
        if (
            not isinstance(connection, _Connection)
            or not connection.checkpoint_attested
        ):
            raise ValueError("APCC PostgreSQL batch snapshot was not attested")
        return _checkpoint_semantic_snapshot(connection, certificate_digests)

    def _validate_mutation_checkpoint(
        self,
        connection: _Connection,
        provisioned: APCCAuthorityConfig | None = None,
    ) -> None:
        if provisioned is None:
            provisioned = _semantic_config(connection, self.schema_name)
        if provisioned != self._config:
            raise ValueError(
                "APCC authority configuration does not match provisioned store"
            )
        _verify_semantic_checkpoint(
            connection,
            self._config,
            _POSTGRES_SCHEMA_FINGERPRINT,
        )

    def _seal_mutation_checkpoint(self, connection: _Connection) -> None:
        _seal_semantic_checkpoint(
            connection,
            self._config,
            self._runtime,
            _POSTGRES_SCHEMA_FINGERPRINT,
        )

    @contextmanager
    def _transaction(self) -> Iterator[_Connection]:
        if self._catalog_profile == _GCB_CATALOG_PROFILE:
            raise ValueError(
                "APCC PostgreSQL GCB-attached mutations require projection support"
            )
        connection = _connect(self._dsn, self.schema_name)
        self._local.connection = connection
        try:
            # Admission locks are session-scoped so every waiter acquires them
            # before PostgreSQL creates its REPEATABLE READ snapshot.  Their
            # global order is never inverted: workflow, optional certificate,
            # then the store-global trust head.  Closing this one-use connection
            # releases all admission locks on every success and failure path.
            connection.raw.autocommit = True
            workflow_id = getattr(self._local, "workflow_id", None)
            if workflow_id is not None:
                connection.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                    (
                        f"APCC-1/workflow/{self.authority_store_id}/"
                        f"{self.schema_name}/{workflow_id}",
                    ),
                )
            certificate_digest = getattr(self._local, "certificate_digest", None)
            if certificate_digest is not None:
                connection.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s, 2))",
                    (
                        f"APCC-1/certificate/{self.authority_store_id}/"
                        f"{self.schema_name}/{certificate_digest}",
                    ),
                )
            if bool(getattr(self._local, "requires_trust_lock", False)):
                if self._postgres_probe is not None:
                    self._postgres_probe.hit("before_trust_head_lock", connection)
                connection.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s, 1))",
                    (
                        f"APCC-1/trust-head/{self.authority_store_id}/"
                        f"{self.schema_name}",
                    ),
                )
            connection.raw.autocommit = False
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            if workflow_id is not None:
                connection.execute(
                    "SELECT workflow_id FROM workflow_authority "
                    "WHERE workflow_id=%s FOR UPDATE",
                    (workflow_id,),
                ).fetchone()
            if certificate_digest is not None:
                connection.execute(
                    "SELECT certificate_digest FROM certificates "
                    "WHERE certificate_digest=%s FOR UPDATE",
                    (certificate_digest,),
                ).fetchone()
            checkpoint = connection.execute(
                "SELECT singleton FROM semantic_checkpoint WHERE singleton=1 FOR UPDATE"
            ).fetchone()
            if checkpoint != (1,):
                raise ValueError("APCC authority semantic checkpoint validation failed")
            if self._postgres_probe is not None:
                self._postgres_probe.hit("before_mutation_attestation", connection)
            self._validate_mutation_checkpoint(connection)
            yield connection
            self._seal_mutation_checkpoint(connection)
            connection.commit()
            if self._postgres_probe is not None:
                self._postgres_probe.hit(
                    "after_transaction_commit_before_return", connection
                )
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            self._local.connection = None
            connection.close()

    def _hit(self, point: str) -> None:
        connection = getattr(self._local, "connection", None)
        if self._postgres_probe is None or connection is None:
            return
        emitted = (
            "before_atomic_authority_write"
            if point in {"before_verification", "before_supersession_verification"}
            else point
        )
        self._postgres_probe.hit(emitted, connection)

    @staticmethod
    def _is_ambiguous(error: Exception) -> bool:
        sqlstate = getattr(error, "sqlstate", None)
        return sqlstate in _AMBIGUOUS_SQLSTATES or isinstance(
            error,
            (ConnectionError, psycopg.OperationalError, psycopg.InterfaceError),
        )

    def _fresh_commit_classification(
        self,
        request: AtomicCommitRequest,
        supersede_old: str | None,
        probe_point: str,
    ) -> tuple[str, CommitResult | None]:
        request_digest = _operation_identity(request, supersede_old)
        connection = _connect(self._dsn, self.schema_name)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            if self._postgres_probe is not None:
                self._postgres_probe.hit(probe_point, connection)
            provisioned = _attest_store(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            row = connection.execute(
                "SELECT request_digest FROM commit_index WHERE commit_id=%s",
                (request.commit_id,),
            ).fetchone()
            classification: tuple[str, CommitResult | None]
            if row is None:
                classification = ("absent", None)
            elif row[0] != request_digest:
                classification = ("mismatch", None)
            else:
                classification = (
                    "exact",
                    _replay(
                        connection,
                        request.commit_id,
                        request_digest,
                    ),
                )
            connection.commit()
            return classification
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _fresh_recovery_classification(
        self, request: RecoveryRequest, probe_point: str | None = None
    ) -> tuple[str | None, CommitResult | None]:
        connection = _connect(self._dsn, self.schema_name)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            if probe_point is not None and self._postgres_probe is not None:
                self._postgres_probe.hit(probe_point, connection)
            provisioned = _attest_store(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            row = connection.execute(
                "SELECT request_digest,workflow_id FROM commit_index "
                "WHERE commit_id=%s",
                (request.commit_id,),
            ).fetchone()
            classification: tuple[str | None, CommitResult | None]
            if row is None:
                result = CommitResult(
                    CommitDecision(
                        request.commit_id,
                        RequestOutcome.DENIED,
                        FailureCode.AUTHORITY_FROM_RECOVERY_DENIED,
                    ),
                    None,
                    None,
                    None,
                    _audit_id(
                        "recovery-missing", request.commit_id, request.request_digest
                    ),
                )
                classification = (None, result)
            else:
                workflow_id = str(row[1])
                public_replay = connection.execute(
                    "SELECT 1 FROM request_index "
                    "WHERE request_digest=%s AND commit_id=%s",
                    (request.request_digest, request.commit_id),
                ).fetchone()
                persisted_conflict = connection.execute(
                    "SELECT 1 FROM commit_conflicts WHERE commit_id=%s "
                    "AND conflicting_request_digest=%s "
                    "AND conflicting_public_request_digest=%s",
                    (
                        request.commit_id,
                        request.request_digest,
                        request.request_digest,
                    ),
                ).fetchone()
                if (
                    row[0] == request.request_digest
                    or public_replay is not None
                    or persisted_conflict is not None
                ):
                    classification = (
                        workflow_id,
                        _replay(
                            connection,
                            request.commit_id,
                            request.request_digest,
                        ),
                    )
                else:
                    classification = (workflow_id, None)
            connection.commit()
            return classification
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def recover(self, request: RecoveryRequest) -> CommitResult:
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                workflow_id, recovered = self._fresh_recovery_classification(request)
                if recovered is not None:
                    return recovered
                assert workflow_id is not None
                self._local.workflow_id = workflow_id
                self._local.requires_trust_lock = True
                try:
                    return super().recover(request)
                finally:
                    self._local.workflow_id = None
                    self._local.requires_trust_lock = False
            except Exception as error:
                sqlstate = getattr(error, "sqlstate", None)
                retryable = sqlstate in _RETRYABLE_SQLSTATES
                ambiguous = sqlstate == "23505" or self._is_ambiguous(error)
                if not retryable and not ambiguous:
                    raise
                if ambiguous:
                    point = (
                        "after_23505_rollback_before_authoritative_reread"
                        if sqlstate == "23505"
                        else "before_ambiguous_recovery"
                    )
                    _, recovered = self._fresh_recovery_classification(request, point)
                    if recovered is not None:
                        return recovered
                if attempt == self._retry_policy.max_attempts:
                    raise RuntimeError(
                        "PostgreSQL recovery transaction "
                        f"{sqlstate or 'connection-loss'} exhausted after "
                        f"{attempt} attempts"
                    ) from error
        raise AssertionError("unreachable PostgreSQL recovery retry state")

    def _commit_with_retries(
        self, request: AtomicCommitRequest, supersede_old: str | None
    ) -> CommitResult:
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                return super()._commit(request, supersede_old)
            except Exception as error:
                sqlstate = getattr(error, "sqlstate", None)
                if sqlstate in _RETRYABLE_SQLSTATES:
                    if attempt < self._retry_policy.max_attempts:
                        continue
                    raise RuntimeError(
                        "PostgreSQL authority transaction "
                        f"{sqlstate} exhausted after {attempt} attempts"
                    ) from error
                if sqlstate == "23505" or self._is_ambiguous(error):
                    point = (
                        "after_23505_rollback_before_authoritative_reread"
                        if sqlstate == "23505"
                        else "before_ambiguous_recovery"
                    )
                    state, recovered = self._fresh_commit_classification(
                        request, supersede_old, point
                    )
                    if state == "exact":
                        assert recovered is not None
                        return recovered
                    if state == "mismatch":
                        return super()._commit(request, supersede_old)
                    if attempt < self._retry_policy.max_attempts:
                        continue
                    raise RuntimeError(
                        "PostgreSQL authority transaction completion was "
                        f"unresolved after {attempt} attempts"
                    ) from error
                raise
        raise AssertionError("unreachable PostgreSQL retry state")

    def atomic_commit(self, request: AtomicCommitRequest) -> CommitResult:
        self._local.workflow_id = request.subject.workflow_id
        self._local.requires_trust_lock = True
        try:
            result = self._commit_with_retries(request, None)
            try:
                self._probe_fresh("after_commit_before_response")
            except Exception as error:
                if not self._is_ambiguous(error):
                    raise
                state, recovered = self._fresh_commit_classification(
                    request, None, "before_ambiguous_recovery"
                )
                if state == "exact":
                    assert recovered is not None
                    return recovered
                if state == "mismatch":
                    return super()._commit(request, None)
                raise RuntimeError(
                    "PostgreSQL authority transaction completion is absent after "
                    "the commit response boundary"
                ) from error
            return result
        finally:
            self._local.workflow_id = None
            self._local.requires_trust_lock = False

    def supersede(self, request: SupersessionRequest) -> SupersessionResult:
        self._local.workflow_id = request.new_proposal.subject.workflow_id
        self._local.certificate_digest = request.old_certificate_digest
        self._local.requires_trust_lock = True
        try:
            request_digest = _operation_identity(
                request.new_proposal, request.old_certificate_digest
            )
            self._commit_with_retries(
                request.new_proposal, request.old_certificate_digest
            )
            with self._read_transaction() as connection:
                return _supersession_replay(
                    connection,
                    request.new_proposal.commit_id,
                    request_digest,
                )
        finally:
            self._local.workflow_id = None
            self._local.certificate_digest = None
            self._local.requires_trust_lock = False

    def revoke(self, request: RevocationRequest) -> RevocationResult:
        self._local.workflow_id = request.workflow_id
        if request.scope is RevocationScope.CERTIFICATE:
            self._local.certificate_digest = request.target_id
        self._local.requires_trust_lock = True
        try:
            for attempt in range(1, self._retry_policy.max_attempts + 1):
                try:
                    return super().revoke(request)
                except Exception as error:
                    sqlstate = getattr(error, "sqlstate", None)
                    retryable = sqlstate in _RETRYABLE_SQLSTATES
                    ambiguous = sqlstate == "23505" or self._is_ambiguous(error)
                    if not retryable and not ambiguous:
                        raise
                    if ambiguous:
                        point = (
                            "after_23505_rollback_before_authoritative_reread"
                            if sqlstate == "23505"
                            else "before_ambiguous_recovery"
                        )
                        recovered = self._fresh_revocation(request, point)
                        if recovered is not None:
                            return recovered
                    if attempt == self._retry_policy.max_attempts:
                        raise RuntimeError(
                            "PostgreSQL revocation transaction "
                            f"{sqlstate or 'connection-loss'} exhausted after "
                            f"{attempt} attempts"
                        ) from error
            raise AssertionError("unreachable PostgreSQL revocation retry state")
        finally:
            self._local.certificate_digest = None
            self._local.workflow_id = None
            self._local.requires_trust_lock = False

    def _fresh_revocation(
        self, request: RevocationRequest, probe_point: str
    ) -> RevocationResult | None:
        audit = _audit_id(
            "revoke",
            request.scope.value,
            request.workflow_id,
            request.target_id,
            request.next_generation,
        )
        expected_generation = (
            None
            if request.scope is RevocationScope.CERTIFICATE
            else str(
                _canonical_positive_decimal(
                    request.next_generation, maximum=_MAX_SAFE_INTEGER
                )
            )
        )
        connection = _connect(self._dsn, self.schema_name)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            if self._postgres_probe is not None:
                self._postgres_probe.hit(probe_point, connection)
            provisioned = _attest_store(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            row = connection.execute(
                "SELECT scope,workflow_id,target_id,generation,claimed_generation,"
                "reason,audit_event_id FROM control_events WHERE operation_id=%s",
                (audit,),
            ).fetchone()
            if row is None:
                result = None
            elif row == (
                request.scope.value,
                request.workflow_id,
                request.target_id,
                expected_generation,
                request.next_generation,
                request.reason,
                audit,
            ):
                result = RevocationResult(
                    request.scope, request.target_id, request.next_generation, audit
                )
            else:
                raise ValueError("APCC revocation recovery binding mismatch")
            connection.commit()
            return result
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _probe_fresh(self, point: str) -> None:
        if self._postgres_probe is None:
            return
        connection = _connect(self._dsn, self.schema_name)
        try:
            self._postgres_probe.hit(point, connection)
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def _outbox_transaction(
        self, label: str, operation: Callable[[_Connection], _ResultT]
    ) -> _ResultT:
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            connection: _Connection | None = None
            try:
                connection = _connect(self._dsn, self.schema_name)
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                provisioned = _semantic_config(connection, self.schema_name)
                checkpoint = connection.execute(
                    "SELECT singleton FROM semantic_checkpoint "
                    "WHERE singleton=1 FOR UPDATE"
                ).fetchone()
                if checkpoint != (1,):
                    raise ValueError(
                        "APCC authority semantic checkpoint validation failed"
                    )
                if self._postgres_probe is not None:
                    self._postgres_probe.hit("before_outbox_attestation", connection)
                self._validate_mutation_checkpoint(connection, provisioned)
                result = operation(connection)
                self._seal_mutation_checkpoint(connection)
                connection.commit()
                return result
            except Exception as error:
                if connection is not None:
                    try:
                        connection.rollback()
                    except Exception:
                        pass
                sqlstate = getattr(error, "sqlstate", None)
                if sqlstate not in _RETRYABLE_SQLSTATES:
                    raise
                if attempt == self._retry_policy.max_attempts:
                    raise RuntimeError(
                        f"PostgreSQL {label} transaction {sqlstate} exhausted "
                        f"after {attempt} attempts"
                    ) from error
            finally:
                if connection is not None:
                    connection.close()
        raise AssertionError("unreachable PostgreSQL outbox retry state")

    def recover_outbox(self, request: OutboxRecoveryRequest) -> OutboxRecoveryResult:
        maximum = _canonical_positive_decimal(request.max_items, maximum=1000)
        delivered: list[str] = []
        for _ in range(maximum):
            token, now = secrets.token_hex(32), _trusted_now(self._runtime.clock)
            if now > _MAX_SAFE_INTEGER - _LEASE_DURATION_MS:
                raise ValueError("INVALID_DECIMAL_STRING")

            def claim(
                connection: _Connection,
            ) -> tuple[bool, str, bytes] | None:
                row = connection.execute(
                    "SELECT event_sequence,event_id,event_json FROM outbox "
                    "WHERE state='PENDING' OR "
                    "(state='CLAIMED' AND lease_until_ms<=%s) "
                    "ORDER BY event_sequence FOR UPDATE SKIP LOCKED LIMIT 1",
                    (now,),
                ).fetchone()
                if row is None:
                    return None
                claimed = connection.execute(
                    "UPDATE outbox SET state='CLAIMED',lease_token=%s,"
                    "lease_claimed_ms=%s,lease_until_ms=%s,delivered=0 "
                    "WHERE event_sequence=%s AND (state='PENDING' OR "
                    "(state='CLAIMED' AND lease_until_ms<=%s))",
                    (token, now, now + _LEASE_DURATION_MS, row[0], now),
                ).rowcount
                return claimed == 1, str(row[1]), bytes(cast("bytes", row[2]))

            claimed_event = self._outbox_transaction("outbox claim", claim)
            if claimed_event is None:
                break
            claimed, event_id, payload = claimed_event
            if not claimed:
                continue
            try:
                self._runtime.outbox_sink.deliver(event_id, payload)
            except Exception:

                def release(connection: _Connection) -> None:
                    connection.execute(
                        "UPDATE outbox SET state='PENDING',lease_token=NULL,"
                        "lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=0 "
                        "WHERE event_id=%s AND state='CLAIMED' AND lease_token=%s",
                        (event_id, token),
                    )

                self._outbox_transaction("outbox release", release)
                raise

            def finalize(connection: _Connection) -> int:
                return connection.execute(
                    "UPDATE outbox SET state='DELIVERED',lease_token=NULL,"
                    "lease_claimed_ms=NULL,lease_until_ms=NULL,delivered=1 "
                    "WHERE event_id=%s AND state='CLAIMED' AND lease_token=%s",
                    (event_id, token),
                ).rowcount

            if self._outbox_transaction("outbox finalize", finalize) == 1:
                delivered.append(event_id)
        audit = _audit_id("outbox-delivered", *(delivered if delivered else ["none"]))

        def audit_and_count(connection: _Connection) -> tuple[object, ...] | None:
            if delivered:
                existing = connection.execute(
                    "SELECT 1 FROM audit_events WHERE audit_event_id=%s", (audit,)
                ).fetchone()
                if existing is None:
                    _write_audit(
                        connection,
                        audit,
                        "outbox_delivered",
                        "outbox",
                    )
            return connection.execute(
                "SELECT count(*) FROM outbox WHERE state<>'DELIVERED'"
            ).fetchone()

        pending_row = self._outbox_transaction("outbox audit", audit_and_count)
        if pending_row is None:
            pending = 0
        else:
            pending_value = pending_row[0]
            if not isinstance(pending_value, (int, str)):
                raise ValueError("APCC outbox pending count is invalid")
            pending = int(pending_value)
        return OutboxRecoveryResult(str(len(delivered)), str(pending), audit)

    def close(self) -> None:
        pass
