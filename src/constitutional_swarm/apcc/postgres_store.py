"""PostgreSQL 17 realization of the APCC authority store."""

from __future__ import annotations

import re
import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Protocol, TypeVar, cast

import psycopg
from psycopg import sql

from .model import CommitDecision, FailureCode, RequestOutcome
from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthoritySigningRole,
    AuthorityRuntime,
    CommitContext,
    CommitResult,
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
    _AuthorityReaderCore,
    _AuthorityStoreCore,
    _MAX_SAFE_INTEGER,
    _audit_id,
    _canonical_positive_decimal,
    _config_from_object,
    _config_object,
    _insert_context,
    _json,
    _loads,
    _operation_identity,
    _replay,
    _supersession_replay,
    _trusted_now,
    _validate_semantic_integrity,
    _write_audit,
)

_SCHEMA_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
_RESERVED_SCHEMAS = frozenset({"public", "pg_catalog", "information_schema"})
_RETRYABLE_SQLSTATES = frozenset({"40001", "40P01"})
_AMBIGUOUS_SQLSTATES = frozenset({"40003", "08007"})
_LEASE_DURATION_MS = 30_000
_COMPATIBILITY_IDENTIFIERS = {
    "apcc_decisions": "decisions",
    "apcc_outbox": "outbox",
}
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


def _connect(dsn: str, schema: str, *, autocommit: bool = False) -> _Connection:
    _validate_schema_name(schema)
    raw = psycopg.connect(dsn, autocommit=True)
    try:
        raw.execute(
            sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(schema))
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
        conflicting_request_digest TEXT NOT NULL,
        conflicting_public_request_digest TEXT NOT NULL,
        original_workflow_id TEXT NOT NULL,
        conflicting_workflow_id TEXT NOT NULL,
        observation_sequence BIGINT NOT NULL,
        audit_event_id TEXT NOT NULL,
        conflict_claim_json TEXT NOT NULL,
        CONSTRAINT commit_conflicts_pkey
            PRIMARY KEY (commit_id,conflicting_request_digest)
    )""",
    """CREATE TABLE workflow_authority (
        workflow_id TEXT CONSTRAINT workflow_authority_pkey PRIMARY KEY
    )""",
)

_POSTGRES_FUNCTIONS = (
    """CREATE FUNCTION apcc_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $apcc$
    BEGIN
        RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE='55000';
    END
    $apcc$""",
    """CREATE FUNCTION apcc_validate_disposition() RETURNS trigger
    LANGUAGE plpgsql AS $apcc$
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
    LANGUAGE plpgsql AS $apcc$
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
)

_POSTGRES_INDEXES = (
    "CREATE INDEX idx_apcc_outbox_pending ON outbox(state,lease_until_ms,event_sequence)",
    "CREATE INDEX idx_apcc_outbox_head ON outbox(event_sequence) WHERE state<>'DELIVERED'",
    "CREATE INDEX idx_nonce_ledger_nonce ON nonce_ledger(nonce)",
    "CREATE INDEX idx_supersession_new_digest ON supersession_edges(new_digest)",
)

_POSTGRES_SCHEMA_STATEMENTS = (
    *_POSTGRES_TABLES,
    *_POSTGRES_FUNCTIONS,
    *_POSTGRES_TRIGGERS,
    *_POSTGRES_INDEXES,
)


def _normalize_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


_POSTGRES_SCHEMA_FINGERPRINT = sha256_digest(
    "\n".join(
        _normalize_schema_sql(statement) for statement in _POSTGRES_SCHEMA_STATEMENTS
    ).encode("utf-8")
)

# PostgreSQL 17 pg_catalog signature of the native manifest above.  It covers
# relation flags, every user column/default, every constraint definition, all
# indexes (including constraint indexes), triggers, and function bodies.
_POSTGRES_CATALOG_FINGERPRINT = "Ip9-ne8ue5Npj8TTvF2TtnlpC7ybrd17NQZJft5u5Qo"


def _normalize_catalog_text(value: object, schema: str) -> object:
    if not isinstance(value, str):
        return value
    normalized = value.replace(f'"{schema}".', "<schema>.")
    normalized = re.sub(rf"\b{re.escape(schema)}\.", "<schema>.", normalized)
    return _normalize_schema_sql(normalized)


def _catalog_manifest(connection: _Connection, schema: str) -> dict[str, object]:
    relations = connection.execute(
        "SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,"
        "c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relkind IN ('r','p') ORDER BY c.relname",
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
    triggers = connection.execute(
        "SELECT c.relname,t.tgname,t.tgenabled,p.proname,pg_get_triggerdef(t.oid,true) "
        "FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_proc p ON p.oid=t.tgfoid "
        "WHERE n.nspname=%s AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
        (schema,),
    ).fetchall()
    functions = connection.execute(
        "SELECT p.proname,p.prokind,p.provolatile,p.proparallel,p.prosecdef,"
        "p.proleakproof,coalesce(array_to_string(p.proconfig,','),''),l.lanname,"
        "pg_get_function_result(p.oid),pg_get_function_arguments(p.oid),p.prosrc "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname=%s ORDER BY p.proname",
        (schema,),
    ).fetchall()

    def normalized(rows: list[tuple[object, ...]]) -> list[list[object]]:
        return [
            [_normalize_catalog_text(value, schema) for value in row] for row in rows
        ]

    return {
        "relations": normalized(relations),
        "columns": normalized(columns),
        "constraints": normalized(constraints),
        "indexes": normalized(indexes),
        "triggers": normalized(triggers),
        "functions": normalized(functions),
    }


def _catalog_fingerprint(connection: _Connection, schema: str) -> str:
    return sha256_digest(_json(_catalog_manifest(connection, schema)).encode("utf-8"))


def _semantic_config(connection: _Connection, schema: str) -> APCCAuthorityConfig:
    invalid = ValueError("APCC authority store schema validation failed")
    try:
        if _catalog_fingerprint(connection, schema) != _POSTGRES_CATALOG_FINGERPRINT:
            raise invalid
        values = {
            str(key): str(value)
            for key, value in connection.execute(
                "SELECT key,value FROM metadata ORDER BY key"
            )
        }
        if set(values) != {"config", "schema_fingerprint"}:
            raise invalid
        if values["schema_fingerprint"] != _POSTGRES_SCHEMA_FINGERPRINT:
            raise invalid
        config_object = _loads(values["config"])
        if _json(config_object) != values["config"]:
            raise invalid
        return _config_from_object(config_object)
    except ValueError as error:
        raise invalid from error
    except Exception as error:
        raise invalid from error


def _validate_semantics(connection: _Connection, config: APCCAuthorityConfig) -> None:
    try:
        _validate_semantic_integrity(connection, config)
    except Exception as error:
        raise ValueError("APCC authority store semantic validation failed") from error


def _attest_store(connection: _Connection, schema: str) -> APCCAuthorityConfig:
    config = _semantic_config(connection, schema)
    _validate_semantics(connection, config)
    return config


class PostgresAuthorityReader(_AuthorityReaderCore):
    def __init__(self, dsn: str, schema: str, authority_store_id: str) -> None:
        super().__init__(authority_store_id)
        self._dsn = dsn
        self.schema_name = schema

    @classmethod
    def open(cls, dsn: str, *, schema: str) -> PostgresAuthorityReader:
        _validate_schema_name(schema)
        connection = _connect(dsn, schema)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            config = _attest_store(connection, schema)
            connection.commit()
            return cls(dsn, schema, config.authority_store_id)
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
            config = _attest_store(connection, self.schema_name)
            if config.authority_store_id != self.authority_store_id:
                raise ValueError("APCC authority store identity mismatch")
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
    ) -> None:
        super().__init__(config, runtime)
        self._dsn = dsn
        self.schema_name = schema
        self.authority_store_id = config.authority_store_id
        self._retry_policy = retry_policy
        self._postgres_probe = probe
        self._local = threading.local()

    def _connection(self) -> _Connection:
        return _connect(self._dsn, self.schema_name)

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
    ) -> None:
        _validate_schema_name(schema)
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
            for statement in _POSTGRES_SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES ('config',%s)",
                (_json(_config_object(config)),),
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES ('schema_fingerprint',%s)",
                (_POSTGRES_SCHEMA_FINGERPRINT,),
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
            provisioned = _attest_store(connection, schema)
            if provisioned != config:
                raise ValueError("APCC authority store configuration mismatch")
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
            dsn, schema, config, runtime, retry_policy or PostgresRetryPolicy(), None
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
        return cls._open(dsn, schema, config, runtime, retry_policy, probe)

    @classmethod
    def _open(
        cls,
        dsn: str,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: PostgresRetryPolicy,
        probe: _Probe | None,
    ) -> PostgresAuthorityStore:
        _validate_schema_name(schema)
        connection = _connect(dsn, schema)
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            provisioned = _attest_store(connection, schema)
            if provisioned != config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
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
        return cls(dsn, schema, config, runtime, retry_policy, probe)

    @contextmanager
    def _read_transaction(self) -> Iterator[_Connection]:
        connection = self._connection()
        try:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            provisioned = _attest_store(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
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

    @contextmanager
    def _transaction(self) -> Iterator[_Connection]:
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
            if self._postgres_probe is not None:
                self._postgres_probe.hit("before_mutation_attestation", connection)
            provisioned = _attest_store(connection, self.schema_name)
            if provisioned != self._config:
                raise ValueError(
                    "APCC authority configuration does not match provisioned store"
                )
            yield connection
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
                    "AND (conflicting_request_digest=%s "
                    "OR conflicting_public_request_digest=%s)",
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
                if self._postgres_probe is not None:
                    self._postgres_probe.hit("before_outbox_attestation", connection)
                provisioned = _attest_store(connection, self.schema_name)
                if provisioned != self._config:
                    raise ValueError(
                        "APCC authority configuration does not match provisioned store"
                    )
                result = operation(connection)
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
