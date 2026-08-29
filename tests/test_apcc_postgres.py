"""Real PostgreSQL 17 APCC authority-store contract."""

from __future__ import annotations

import base64
import ast
import hashlib
import importlib
import inspect
import multiprocessing
import os
import re
import secrets
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast, get_type_hints, runtime_checkable

import pytest

from constitutional_swarm.apcc.codec import (
    decode_authority_status,
    encode_authority_status,
)

from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    AuthorityStatusValue,
    FailureCode,
    RequestOutcome,
    Signature,
    SupersessionValue,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AtomicCommitRequest,
    AuthorityObservationRequest,
    AuthorityObservationState,
    AuthorityObservationStore,
    AuthorityReader,
    AuthorityRuntime,
    AuthoritySigningRole,
    AuthorityStore,
    CommitContextRequest,
    CommitResult,
    CurrentStatusRequest,
    LogicalNodeStatusRequest,
    OutboxRecoveryRequest,
    OutboxRecoveryResult,
    RecoveryRequest,
    ReplayCommitRequest,
    RevocationRequest,
    RevocationResult,
    RevocationScope,
    StatusFreshnessPolicy,
    SupersessionCommitted,
    SupersessionRequest,
)
from constitutional_swarm.apcc.sqlite_store import (
    _operation_identity,
    _public_request_digest,
)
from constitutional_swarm.apcc.verifier import verify_current
from tests.apcc_conformance import (
    AuthoritySnapshot,
    AuthorityStoreHarness,
    FaultProbe,
    assert_authority_store_conforms,
    assert_authority_store_extended_conforms,
    assert_pending_proposal_identity_is_exact_conforms,
    assert_stage_after_commit_pending_cannot_regress_conforms,
)


_DSN_ENV = "APCC_POSTGRES_DSN"
_SCHEMA_RE = re.compile(r"\Aapcc_test_[a-z0-9_]{1,48}\Z")
_ROLE_RE = re.compile(r"\Aapcc_test_[0-9a-f]{24}_(?:owner|runtime|observer)\Z")
_RETRYABLE_SQLSTATES = ("40001", "40P01")
_AMBIGUOUS_SQLSTATES: tuple[str | None, ...] = ("40003", "08007", None)
_ROLE_SEEDS = tuple(bytes(range(start, start + 32)) for start in range(0, 192, 32))
_MIN_MAX_CONNECTIONS = 105
_BENCHMARK_MAX_CONNECTIONS = 200
_CHECKPOINT_GUARDED_TABLES = (
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


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...

    def fetchall(self) -> list[tuple[object, ...]]: ...


class _Connection(Protocol):
    def execute(self, query: str, parameters: tuple[object, ...] = ()) -> _Cursor: ...

    def close(self) -> None: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def cursor(self) -> Any: ...

    def __enter__(self) -> _Connection: ...

    def __exit__(self, *exc: object) -> None: ...


@runtime_checkable
class _Psycopg(Protocol):
    def connect(self, dsn: str, *, autocommit: bool = False) -> _Connection: ...


class _RetryPolicy(Protocol):
    max_attempts: int


class _RetryPolicyFactory(Protocol):
    def __call__(self, *, max_attempts: int) -> _RetryPolicy: ...


class _PostgresReader(AuthorityReader, AuthorityObservationStore, Protocol):
    authority_store_id: str
    schema_name: str

    def close(self) -> None: ...


class _PostgresStore(AuthorityStore, Protocol):
    authority_store_id: str
    schema_name: str

    def _observation_current_status(
        self, certificate_digest: str, request_nonce: str
    ) -> AuthorityStatus: ...

    def close(self) -> None: ...


class _PostgresStoreFactory(Protocol):
    def provision(
        self,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        initial_contexts: tuple[object, ...],
        runtime_role: str,
        observer_role: str,
        runtime: AuthorityRuntime,
    ) -> None: ...

    def open(
        self,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: _RetryPolicy | None = None,
    ) -> _PostgresStore: ...

    def _open_with_probe(
        self,
        dsn: str,
        *,
        schema: str,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
        retry_policy: _RetryPolicy,
        probe: _TransactionProbe,
    ) -> _PostgresStore: ...


class _PostgresReaderFactory(Protocol):
    def open(
        self, dsn: str, *, schema: str, status_signer: object | None = None
    ) -> _PostgresReader: ...


@dataclass(frozen=True, slots=True)
class _StatusSignerAdapter:
    store: _PostgresStore

    def current_status(self, certificate_digest: str, request_nonce: str) -> bytes:
        return encode_authority_status(
            self.store._observation_current_status(certificate_digest, request_nonce)
        )


class _TransactionProbe(Protocol):
    def hit(self, point: str, connection: _Connection) -> None: ...


@dataclass(frozen=True, slots=True)
class _ConformanceProbeAdapter:
    probe: FaultProbe

    def hit(self, point: str, connection: _Connection) -> None:
        del connection
        self.probe.hit(point)


@dataclass(frozen=True, slots=True)
class _Modules:
    psycopg: _Psycopg
    store_factory: _PostgresStoreFactory
    reader_factory: _PostgresReaderFactory
    retry_policy_factory: _RetryPolicyFactory
    support: ModuleType


@dataclass(slots=True)
class _PostgresEnvironment:
    dsn: str
    runtime_dsn: str
    observer_dsn: str
    schema_prefix: str
    ownership_token: str
    owner_role: str
    runtime_role: str
    observer_role: str
    modules: _Modules
    created_schemas: set[str] = field(default_factory=set)

    def schema(self, label: str) -> str:
        suffix = hashlib.sha256(label.encode("utf-8")).hexdigest()[:10]
        schema = f"{self.schema_prefix}_{suffix}"
        _validate_owned_schema(schema)
        with self.modules.psycopg.connect(self.dsn, autocommit=True) as connection:
            if schema not in self.created_schemas:
                connection.execute(
                    f'CREATE SCHEMA "{schema}" AUTHORIZATION "{self.owner_role}"'
                )
                owner_comment = _schema_owner_comment(self.ownership_token)
                connection.execute(
                    f"COMMENT ON SCHEMA \"{schema}\" IS '{owner_comment}'"
                )
                self.created_schemas.add(schema)
            owner = connection.execute(
                "SELECT obj_description(%s::regnamespace, 'pg_namespace')",
                (schema,),
            ).fetchone()
            assert owner == (_schema_owner_comment(self.ownership_token),)
        return schema


def _validate_owned_schema(schema: str) -> None:
    if _SCHEMA_RE.fullmatch(schema) is None:
        raise AssertionError(f"unsafe PostgreSQL test schema: {schema!r}")


def _validate_owned_role(role: str) -> None:
    if _ROLE_RE.fullmatch(role) is None:
        raise AssertionError(f"unsafe PostgreSQL test role: {role!r}")


def _schema_owner_comment(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{24}", token) is None:
        raise AssertionError("unsafe PostgreSQL test ownership token")
    return f"apcc-test-owner:{token}"


def _runtime_dsn(dsn: str, role: str) -> str:
    _validate_owned_role(role)
    make_conninfo = cast(
        "Callable[..., str]",
        getattr(importlib.import_module("psycopg.conninfo"), "make_conninfo"),
    )
    return make_conninfo(dsn, user=role)


def _require_psycopg(module: ModuleType) -> _Psycopg:
    if not isinstance(module, _Psycopg):
        raise ImportError("psycopg module does not expose connect")
    return module


def _future_modules() -> _Modules:
    psycopg_module = _require_psycopg(importlib.import_module("psycopg"))
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    support = importlib.import_module("tests.test_apcc_sqlite")
    return _Modules(
        psycopg=psycopg_module,
        store_factory=getattr(store_module, "PostgresAuthorityStore"),
        reader_factory=getattr(store_module, "PostgresAuthorityReader"),
        retry_policy_factory=getattr(store_module, "PostgresRetryPolicy"),
        support=support,
    )


@pytest.fixture
def postgres_environment() -> Iterator[_PostgresEnvironment]:
    dsn = os.getenv(_DSN_ENV)
    if not dsn:
        pytest.skip(f"set {_DSN_ENV} to run real PostgreSQL APCC contracts")
    try:
        modules = _future_modules()
    except ImportError as error:
        pytest.fail(
            f"{_DSN_ENV} is set but PostgreSQL APCC prerequisites are absent: {error}"
        )
    with modules.psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute("SHOW server_version_num").fetchone()
        capacity = connection.execute("SHOW max_connections").fetchone()
    assert row is not None
    assert isinstance(row[0], (int, str))
    assert int(row[0]) >= 170000, "APCC PostgreSQL contract requires PostgreSQL 17+"
    assert capacity is not None
    assert isinstance(capacity[0], (int, str))
    assert int(capacity[0]) >= _MIN_MAX_CONNECTIONS, (
        f"APCC PostgreSQL contract requires max_connections >= "
        f"{_MIN_MAX_CONNECTIONS}; benchmark profile remains "
        f"{_BENCHMARK_MAX_CONNECTIONS}"
    )
    token = secrets.token_hex(12)
    prefix = f"apcc_test_{token}"
    _validate_owned_schema(prefix)
    owner_role = f"{prefix}_owner"
    runtime_role = f"{prefix}_runtime"
    observer_role = f"{prefix}_observer"
    _validate_owned_role(owner_role)
    _validate_owned_role(runtime_role)
    _validate_owned_role(observer_role)
    created_roles: list[str] = []
    try:
        with modules.psycopg.connect(dsn, autocommit=True) as connection:
            database = connection.execute("SELECT current_database()").fetchone()
            assert database is not None and isinstance(database[0], str)
            quoted_database = '"' + database[0].replace('"', '""') + '"'
            connection.execute(
                f"REVOKE TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
            )
            for role, login in (
                (owner_role, False),
                (runtime_role, True),
                (observer_role, True),
            ):
                connection.execute(
                    f'CREATE ROLE "{role}" '
                    f"{'LOGIN' if login else 'NOLOGIN'} NOINHERIT NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                created_roles.append(role)
                connection.execute(
                    f"COMMENT ON ROLE \"{role}\" IS '{_schema_owner_comment(token)}'"
                )
            connection.execute(
                f'REVOKE ALL ON DATABASE {quoted_database} FROM "{observer_role}"'
            )
            connection.execute(
                f'GRANT CONNECT ON DATABASE {quoted_database} TO "{observer_role}"'
            )
        environment = _PostgresEnvironment(
            dsn,
            _runtime_dsn(dsn, runtime_role),
            _runtime_dsn(dsn, observer_role),
            prefix,
            token,
            owner_role,
            runtime_role,
            observer_role,
            modules,
        )
        yield environment
    finally:
        with modules.psycopg.connect(dsn, autocommit=True) as connection:
            rows = connection.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name LIKE %s",
                (f"{prefix}_%",),
            ).fetchall()
            for (schema_name,) in rows:
                assert isinstance(schema_name, str)
                _validate_owned_schema(schema_name)
                owner = connection.execute(
                    "SELECT obj_description(%s::regnamespace, 'pg_namespace')",
                    (schema_name,),
                ).fetchone()
                assert owner == (_schema_owner_comment(token),), (
                    f"refusing to drop schema without exact ownership token: "
                    f"{schema_name}"
                )
                connection.execute(f'DROP SCHEMA "{schema_name}" CASCADE')
            for role in reversed(created_roles):
                _validate_owned_role(role)
                comment = connection.execute(
                    "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles "
                    "WHERE rolname=%s",
                    (role,),
                ).fetchone()
                assert comment == (_schema_owner_comment(token),), (
                    f"refusing to drop role without exact ownership token: {role}"
                )
                database = connection.execute("SELECT current_database()").fetchone()
                assert database is not None and isinstance(database[0], str)
                quoted_database = '"' + database[0].replace('"', '""') + '"'
                connection.execute(
                    f'REVOKE ALL ON DATABASE {quoted_database} FROM "{role}"'
                )
                connection.execute(f'DROP ROLE "{role}"')


def _support(environment: _PostgresEnvironment, name: str) -> Callable[..., object]:
    value = getattr(environment.modules.support, name)
    assert callable(value)
    return value


def _config(environment: _PostgresEnvironment) -> APCCAuthorityConfig:
    value = _support(environment, "_config")()
    assert isinstance(value, APCCAuthorityConfig)
    return value


def _runtime(environment: _PostgresEnvironment) -> AuthorityRuntime:
    value = _support(environment, "_runtime")()
    assert isinstance(value, AuthorityRuntime)
    return value


def _request(
    environment: _PostgresEnvironment, **changes: object
) -> AtomicCommitRequest:
    value = _support(environment, "_request")(**changes)
    assert isinstance(value, AtomicCommitRequest)
    return value


def _nonce(index: int) -> str:
    return base64.urlsafe_b64encode(index.to_bytes(16, "big")).rstrip(b"=").decode()


def _initial_contexts(environment: _PostgresEnvironment) -> tuple[object, ...]:
    value = _support(environment, "_initial_contexts")()
    assert isinstance(value, tuple)
    return value


def _snapshot(
    environment: _PostgresEnvironment, store: AuthorityStore
) -> AuthoritySnapshot:
    schema = getattr(store, "schema_name", None)
    assert isinstance(schema, str)
    _validate_owned_schema(schema)
    with environment.modules.psycopg.connect(
        environment.dsn, autocommit=True
    ) as connection:
        table_rows = connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=%s ORDER BY table_name",
            (schema,),
        ).fetchall()
        contents: dict[str, tuple[bytes, ...]] = {}
        for (table_name,) in table_rows:
            assert isinstance(table_name, str)
            if table_name == "semantic_checkpoint":
                continue
            rows = connection.execute(
                f'SELECT * FROM "{schema}"."{table_name}" ORDER BY ctid'
            ).fetchall()
            contents[table_name] = tuple(repr(row).encode("utf-8") for row in rows)
    pointers = tuple(
        row
        for name, rows in contents.items()
        if "node" in name or "pointer" in name or "certificate" in name
        for row in rows
    )
    return AuthoritySnapshot(contents, pointers)


def _checkpoint_row(
    environment: _PostgresEnvironment, schema: str
) -> tuple[int, str, str, str, str]:
    with environment.modules.psycopg.connect(
        environment.dsn, autocommit=True
    ) as connection:
        row = connection.execute(
            f"SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
            f'FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        ).fetchone()
    assert row is not None
    assert len(row) == 5
    sequence, prior_digest, checkpoint_digest, key_id, signature = row
    assert isinstance(sequence, int) and not isinstance(sequence, bool)
    assert isinstance(prior_digest, str)
    assert isinstance(checkpoint_digest, str)
    assert isinstance(key_id, str)
    assert isinstance(signature, str)
    return sequence, prior_digest, checkpoint_digest, key_id, signature


def _harness(environment: _PostgresEnvironment) -> AuthorityStoreHarness:
    opened: dict[str, _PostgresStore] = {}

    def open_store(path: Path, probe: FaultProbe | None) -> _PostgresStore:
        schema = environment.schema(str(path))
        config = _config(environment)
        if schema not in opened:
            environment.modules.store_factory.provision(
                environment.dsn,
                schema=schema,
                config=config,
                initial_contexts=_initial_contexts(environment),
                runtime_role=environment.runtime_role,
                observer_role=environment.observer_role,
                runtime=_runtime(environment),
            )
        if probe is None:
            store = environment.modules.store_factory.open(
                environment.runtime_dsn,
                schema=schema,
                config=config,
                runtime=_runtime(environment),
            )
        else:
            store = environment.modules.store_factory._open_with_probe(
                environment.runtime_dsn,
                schema=schema,
                config=config,
                runtime=_runtime(environment),
                retry_policy=environment.modules.retry_policy_factory(max_attempts=1),
                probe=_ConformanceProbeAdapter(probe),
            )
        opened[schema] = store
        return store

    def reopen_store(path: Path) -> _PostgresStore:
        schema = environment.schema(str(path))
        return environment.modules.store_factory.open(
            environment.runtime_dsn,
            schema=schema,
            config=_config(environment),
            runtime=_runtime(environment),
        )

    support = environment.modules.support
    return AuthorityStoreHarness(
        open_store=open_store,
        reopen_store=reopen_store,
        make_request=lambda **changes: _request(environment, **changes),
        trust=getattr(support, "valid_vector")().trust,
        snapshot=lambda store: _snapshot(environment, store),
        stage_request=getattr(support, "_stage_request"),
        assemble_evidence_request=getattr(support, "_assemble_evidence_request"),
        propose_commit_request=getattr(support, "_propose_commit_request"),
        outbox_event=getattr(support, "_outbox_event"),
        assert_conflict_and_audit_delta=getattr(support, "_only_conflict_and_audit"),
        assert_denied_decision_delta=getattr(
            support, "_only_denied_decision_and_audit"
        ),
        assert_missing_recovery_delta=getattr(support, "_missing_recovery_delta"),
        assert_outbox_delivery_delta=getattr(support, "_only_outbox_delivery"),
    )


def _advance(
    environment: _PostgresEnvironment,
    store: AuthorityStore,
    request: AtomicCommitRequest,
) -> None:
    support = environment.modules.support
    store.stage_result(getattr(support, "_stage_request")(request))
    store.assemble_evidence(getattr(support, "_assemble_evidence_request")(request))
    store.propose_commit(getattr(support, "_propose_commit_request")(request))


def _corrupt_candidate_proposal_digest(
    environment: _PostgresEnvironment,
    schema: str,
    request: AtomicCommitRequest,
) -> None:
    with environment.modules.psycopg.connect(
        environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
        corrupted = connection.execute(
            f'SELECT proposal_digest FROM "{schema}"."candidates" '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        ).fetchone()
    assert corrupted == ("tampered",)


def _apply_valid_test_mutation_and_reseal(
    environment: _PostgresEnvironment,
    schema: str,
    query: str,
    parameters: tuple[object, ...],
) -> None:
    """Apply test-only valid state setup through the authenticated checkpoint."""

    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    connect = cast(
        "Callable[[str, str], _Connection]", getattr(store_module, "_connect")
    )
    attest_store = cast(
        "Callable[[_Connection, str], APCCAuthorityConfig]",
        getattr(store_module, "_attest_store"),
    )
    validate_semantics = cast(
        "Callable[[_Connection, APCCAuthorityConfig], object]",
        getattr(store_module, "_validate_semantics"),
    )
    seal_checkpoint = cast(
        "Callable[[_Connection, APCCAuthorityConfig, AuthorityRuntime, str], None]",
        getattr(store_module, "_seal_semantic_checkpoint"),
    )
    schema_fingerprint = getattr(store_module, "_POSTGRES_SCHEMA_FINGERPRINT")
    assert isinstance(schema_fingerprint, str)
    connection = connect(environment.runtime_dsn, schema)
    config = _config(environment)
    try:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        row = connection.execute(
            "SELECT singleton FROM semantic_checkpoint WHERE singleton=1 FOR UPDATE"
        ).fetchone()
        assert row == (1,)
        assert attest_store(connection, schema) == config
        connection.execute(query, parameters)
        validate_semantics(connection, config)
        seal_checkpoint(
            connection,
            config,
            _runtime(environment),
            schema_fingerprint,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _reseal_test_checkpoint_without_attestation(
    environment: _PostgresEnvironment, schema: str
) -> None:
    """Restore a valid checkpoint after proving an out-of-band exploit."""

    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    connection = getattr(store_module, "_connect")(environment.runtime_dsn, schema)
    try:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        assert connection.execute(
            "SELECT singleton FROM semantic_checkpoint WHERE singleton=1 FOR UPDATE"
        ).fetchone() == (1,)
        getattr(store_module, "_seal_semantic_checkpoint")(
            connection,
            _config(environment),
            _runtime(environment),
            getattr(store_module, "_POSTGRES_SCHEMA_FINGERPRINT"),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _single_store(
    environment: _PostgresEnvironment, label: str = "authority"
) -> tuple[str, _PostgresStore]:
    schema = environment.schema(label)
    config = _config(environment)
    environment.modules.store_factory.provision(
        environment.dsn,
        schema=schema,
        config=config,
        initial_contexts=_initial_contexts(environment),
        runtime_role=environment.runtime_role,
        observer_role=environment.observer_role,
        runtime=_runtime(environment),
    )
    return schema, environment.modules.store_factory.open(
        environment.runtime_dsn,
        schema=schema,
        config=config,
        runtime=_runtime(environment),
    )


def test_postgres_normal_commit_does_not_open_a_probe_connection(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _single_store(postgres_environment, "no_probe_connection")
    request = _request(
        postgres_environment, commit_id="no-probe-connection", nonce_byte=119
    )
    _advance(postgres_environment, store, request)
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    original_connect = cast(
        "Callable[[str, str], _Connection]", getattr(store_module, "_connect")
    )
    connection_count = 0

    def counted_connect(dsn: str, schema: str) -> _Connection:
        nonlocal connection_count
        connection_count += 1
        return original_connect(dsn, schema)

    monkeypatch.setattr(store_module, "_connect", counted_connect)
    assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED
    assert connection_count == 1


def test_postgres_public_api_matches_the_sqlite_authority_contract(
    postgres_environment: _PostgresEnvironment,
) -> None:
    store_factory = postgres_environment.modules.store_factory
    reader_factory = postgres_environment.modules.reader_factory
    provision = inspect.signature(store_factory.provision).parameters
    writer_open = inspect.signature(store_factory.open).parameters
    reader_open = inspect.signature(reader_factory.open).parameters
    assert set(provision) == {
        "dsn",
        "schema",
        "config",
        "initial_contexts",
        "runtime_role",
        "observer_role",
        "runtime",
    }
    assert set(writer_open) == {
        "dsn",
        "schema",
        "config",
        "runtime",
        "retry_policy",
    }
    assert set(reader_open) == {"dsn", "schema", "status_signer"}
    assert provision["config"].default is inspect.Parameter.empty
    assert provision["runtime_role"].default is inspect.Parameter.empty
    assert provision["observer_role"].default is inspect.Parameter.empty
    assert provision["runtime"].default is inspect.Parameter.empty
    assert writer_open["config"].default is inspect.Parameter.empty
    assert writer_open["runtime"].default is inspect.Parameter.empty
    assert get_type_hints(store_factory.open)["return"] is not object
    forbidden = {"private_seed", "legacy", "sidecar", "disable"}
    parameter_names = set(provision) | set(writer_open) | set(reader_open)
    assert not any(
        fragment in parameter.lower()
        for fragment in forbidden
        for parameter in parameter_names
    )


def test_postgres_sql_adaptation_is_lexically_bounded(
    postgres_environment: _PostgresEnvironment,
) -> None:
    del postgres_environment
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    adapt_sql = getattr(store_module, "_adapt_sql")
    query = (
        "SELECT '?', \"apcc_outbox\", $$? apcc_decisions$$ "
        "FROM apcc_outbox -- ? apcc_decisions\n"
        "WHERE event_id=? /* ? apcc_outbox */"
    )
    assert adapt_sql(query) == (
        "SELECT '?', \"apcc_outbox\", $$? apcc_decisions$$ "
        "FROM outbox -- ? apcc_decisions\n"
        "WHERE event_id=%s /* ? apcc_outbox */"
    )


def test_postgres_uses_a_locked_workflow_guard(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "workflow_guard")
    request = _request(postgres_environment, commit_id="pg-guard", nonce_byte=101)
    _advance(postgres_environment, store, request)
    pool = ThreadPoolExecutor(max_workers=1)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn
    ) as locker:
        locked = locker.execute(
            f'SELECT workflow_id FROM "{schema}"."workflow_authority" '
            "WHERE workflow_id=%s FOR UPDATE",
            (request.subject.workflow_id,),
        ).fetchone()
        assert locked == (request.subject.workflow_id,)
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn
        ) as observer:
            rows = observer.execute(
                "SELECT mode, granted FROM pg_locks "
                "WHERE pid=pg_backend_pid() OR relation=%s::regclass",
                (f"{schema}.workflow_authority",),
            ).fetchall()
        assert rows
        contender = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        future = pool.submit(contender.atomic_commit, request)
        with pytest.raises(FutureTimeoutError):
            future.result(timeout=0.25)
    committed = future.result(timeout=10)
    pool.shutdown(wait=True)
    assert committed.decision.outcome is RequestOutcome.COMMITTED


def test_postgres_public_types_do_not_inherit_concrete_sqlite_backends() -> None:
    postgres_module = importlib.import_module(
        "constitutional_swarm.apcc.postgres_store"
    )
    sqlite_module = importlib.import_module("constitutional_swarm.apcc.sqlite_store")

    assert not issubclass(
        getattr(postgres_module, "PostgresAuthorityReader"),
        getattr(sqlite_module, "SQLiteAuthorityReader"),
    )
    assert not issubclass(
        getattr(postgres_module, "PostgresAuthorityStore"),
        getattr(sqlite_module, "SQLiteAuthorityStore"),
    )


def test_postgres_satisfies_backend_neutral_authority_conformance(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_authority_store_conforms(_harness(postgres_environment), tmp_path)


def test_postgres_satisfies_extended_backend_neutral_conformance(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_authority_store_extended_conforms(_harness(postgres_environment), tmp_path)


def test_postgres_pending_proposal_identity_is_immutable(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_pending_proposal_identity_is_exact_conforms(
        _harness(postgres_environment), tmp_path
    )


def test_postgres_pending_candidate_cannot_regress_to_result_staged(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_stage_after_commit_pending_cannot_regress_conforms(
        _harness(postgres_environment), tmp_path
    )


@pytest.mark.parametrize("namespace", ("commit_id", "nonce", "both"))
@pytest.mark.parametrize("cross_workflow", (False, True))
def test_postgres_global_idempotency_races_are_store_wide(
    postgres_environment: _PostgresEnvironment,
    namespace: str,
    cross_workflow: bool,
) -> None:
    schema, setup = _single_store(
        postgres_environment, f"global_{namespace}_{cross_workflow}"
    )
    left = _request(postgres_environment, commit_id="global-left", nonce_byte=102)
    right = _request(
        postgres_environment,
        commit_id="global-left"
        if namespace in {"commit_id", "both"}
        else "global-right",
        nonce_byte=102 if namespace in {"nonce", "both"} else 103,
        workflow_id="workflow-2" if cross_workflow else "workflow-1",
        attempt_id=(
            "attempt-2" if not cross_workflow and namespace != "both" else "attempt-1"
        ),
    )
    _advance(postgres_environment, setup, left)
    if right != left:
        _advance(postgres_environment, setup, right)
    barrier = threading.Barrier(2)

    def commit(request: AtomicCommitRequest) -> CommitResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        barrier.wait()
        return store.atomic_commit(request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(commit, (left, right)))
    if namespace == "both" and not cross_workflow:
        assert left == right
        assert results[0] == results[1]
        assert results[0].decision.outcome is RequestOutcome.COMMITTED
        return
    assert (
        sum(result.decision.outcome is RequestOutcome.COMMITTED for result in results)
        == 1
    )
    loser = next(
        result
        for result in results
        if result.decision.outcome is not RequestOutcome.COMMITTED
    )
    expected = (
        RequestOutcome.CONFLICTED
        if namespace in {"commit_id", "both"}
        else RequestOutcome.DENIED
    )
    assert loser.decision.outcome is expected
    expected_reason = (
        FailureCode.COMMIT_ID_EQUIVOCATION
        if namespace in {"commit_id", "both"}
        else FailureCode.NONCE_REPLAY
    )
    assert loser.decision.reason is expected_reason


def test_postgres_distinct_requests_with_both_global_ids_still_conflict(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, setup = _single_store(postgres_environment, "distinct_both_race")
    left = _request(postgres_environment, commit_id="global-both", nonce_byte=103)
    right = _request(
        postgres_environment,
        commit_id="global-both",
        nonce_byte=103,
        node_id="root",
    )
    _advance(postgres_environment, setup, left)
    _advance(postgres_environment, setup, right)
    barrier = threading.Barrier(2)

    def commit(request: AtomicCommitRequest) -> CommitResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        barrier.wait()
        return store.atomic_commit(request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(commit, (left, right)))
    assert {result.decision.outcome for result in results} == {
        RequestOutcome.COMMITTED,
        RequestOutcome.CONFLICTED,
    }
    loser = next(
        result
        for result in results
        if result.decision.outcome is RequestOutcome.CONFLICTED
    )
    assert loser.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION


def test_postgres_one_hundred_connection_contention_has_one_exact_winner(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _single_store(postgres_environment, "hundred_connections")
    request = _request(postgres_environment, commit_id="pg-100", nonce_byte=104)
    _advance(postgres_environment, store, request)
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    original_connect = getattr(store_module, "_connect")
    opened_connections: list[object] = []
    opened_connections_lock = threading.Lock()

    def counted_connect(dsn: str, schema: str) -> object:
        connection = original_connect(dsn, schema)
        with opened_connections_lock:
            opened_connections.append(connection)
        return connection

    monkeypatch.setattr(store_module, "_connect", counted_connect)
    barrier = threading.Barrier(100)

    def contend(_: int) -> CommitResult:
        barrier.wait(timeout=30)
        return store.atomic_commit(request)

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = tuple(pool.map(contend, range(100)))
    assert len(results) == 100
    assert len(opened_connections) == 100
    assert len(set(results)) == 1
    assert results[0].decision.outcome is RequestOutcome.COMMITTED


@dataclass(slots=True)
class _IsolationProbe:
    watched_point: str
    observations: list[str] = field(default_factory=list)

    def hit(self, point: str, connection: _Connection) -> None:
        if point != self.watched_point:
            return
        row = connection.execute("SHOW transaction_isolation").fetchone()
        assert row is not None
        assert isinstance(row[0], str)
        self.observations.append(row[0])


def test_postgres_mutations_attest_inside_repeatable_read_transactions(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "mutation_rr_probe")
    probe = _IsolationProbe("before_mutation_attestation")
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=3),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id="mutation-rr-probe", nonce_byte=131
    )

    _advance(postgres_environment, store, request)
    assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED
    assert probe.observations == ["repeatable read"] * 4


def test_postgres_outbox_attests_inside_repeatable_read_transactions(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "outbox_rr_probe")
    probe = _IsolationProbe("before_outbox_attestation")
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=3),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id="outbox-rr-probe", nonce_byte=132
    )
    _advance(postgres_environment, store, request)
    store.atomic_commit(request)

    result = store.recover_outbox(OutboxRecoveryRequest("1"))

    assert result.delivered_count == "1"
    assert probe.observations == ["repeatable read"] * 3


@dataclass(slots=True)
class _SqlStateProbe:
    sqlstate: str
    failures_remaining: int
    hits: int = 0
    transaction_ids: list[object] = field(default_factory=list)

    def hit(self, point: str, connection: _Connection) -> None:
        if point != "before_atomic_authority_write":
            return
        transaction = connection.execute("SELECT txid_current()").fetchone()
        assert transaction is not None
        self.transaction_ids.append(transaction[0])
        if self.failures_remaining == 0:
            return
        assert self.sqlstate in (*_RETRYABLE_SQLSTATES, "23505", "40003", "08007")
        self.hits += 1
        self.failures_remaining -= 1
        connection.execute(
            "DO $apcc$ BEGIN RAISE EXCEPTION 'apcc injected server fault' "
            f"USING ERRCODE = '{self.sqlstate}'; END $apcc$"
        )


@pytest.mark.parametrize("sqlstate", _RETRYABLE_SQLSTATES)
def test_postgres_known_aborts_retry_the_whole_transaction_with_a_bound(
    postgres_environment: _PostgresEnvironment, sqlstate: str
) -> None:
    schema, _ = _single_store(postgres_environment, f"retry_{sqlstate}")
    probe = _SqlStateProbe(sqlstate, failures_remaining=2)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=3),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id=f"retry-{sqlstate}", nonce_byte=105
    )
    _advance(postgres_environment, store, request)
    assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED
    assert probe.hits == 2
    assert len(set(probe.transaction_ids)) == 3


@pytest.mark.parametrize("sqlstate", _RETRYABLE_SQLSTATES)
def test_postgres_retry_exhaustion_is_stable_and_writes_nothing(
    postgres_environment: _PostgresEnvironment, sqlstate: str
) -> None:
    schema, setup = _single_store(postgres_environment, f"exhaust_{sqlstate}")
    probe = _SqlStateProbe(sqlstate, failures_remaining=4)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=3),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id=f"exhaust-{sqlstate}", nonce_byte=106
    )
    _advance(postgres_environment, store, request)
    before = _snapshot(postgres_environment, setup)
    with pytest.raises(RuntimeError, match=f"{sqlstate}.*3"):
        store.atomic_commit(request)
    assert probe.hits == 3
    assert len(set(probe.transaction_ids)) == 3
    assert _snapshot(postgres_environment, setup) == before


@dataclass(slots=True)
class _RecordingProbe:
    points: list[str]
    observations: list[tuple[str, object, object]] = field(default_factory=list)
    unique_failures_remaining: int = 0

    def hit(self, point: str, connection: _Connection) -> None:
        self.points.append(point)
        if point not in {
            "before_atomic_authority_write",
            "after_23505_rollback_before_authoritative_reread",
        }:
            return
        row = connection.execute("SELECT txid_current(), pg_backend_pid()").fetchone()
        assert row is not None
        self.observations.append((point, row[0], row[1]))
        if point == "before_atomic_authority_write" and self.unique_failures_remaining:
            self.unique_failures_remaining -= 1
            connection.execute(
                "DO $apcc$ BEGIN RAISE EXCEPTION 'injected unique race' "
                "USING ERRCODE = '23505'; END $apcc$"
            )


def test_postgres_23505_rolls_back_then_classifies_by_fresh_authoritative_read(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "unique_reread")
    request = _request(postgres_environment, commit_id="pg-23505", nonce_byte=107)
    probe = _RecordingProbe([], unique_failures_remaining=1)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=2),
        probe=probe,
    )
    _advance(postgres_environment, store, request)
    result = store.atomic_commit(request)
    assert result.decision.outcome is RequestOutcome.COMMITTED
    assert "after_23505_rollback_before_authoritative_reread" in probe.points
    writes = tuple(
        observation
        for observation in probe.observations
        if observation[0] == "before_atomic_authority_write"
    )
    rereads = tuple(
        observation
        for observation in probe.observations
        if observation[0] == "after_23505_rollback_before_authoritative_reread"
    )
    assert len(writes) == 2
    assert len(rereads) == 1
    assert rereads[0][1] not in {observation[1] for observation in writes}
    assert rereads[0][2] not in {observation[2] for observation in writes}
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn,
        schema=schema,
        status_signer=_StatusSignerAdapter(store),
    )
    assert (
        reader.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        )
        == result
    )


class _ClientSideResponseLoss(ConnectionError):
    """Typed client failure with no server SQLSTATE."""

    sqlstate: None = None


@dataclass(slots=True)
class _AmbiguousCompletionProbe:
    sqlstate: str | None
    fired: bool = False
    backend_pids: list[object] = field(default_factory=list)
    client_error: _ClientSideResponseLoss | None = None

    def hit(self, point: str, connection: _Connection) -> None:
        if point == "before_ambiguous_recovery":
            row = connection.execute("SELECT pg_backend_pid()").fetchone()
            assert row is not None
            self.backend_pids.append(row[0])
            return
        if point != "after_commit_before_response" or self.fired:
            return
        self.fired = True
        row = connection.execute("SELECT pg_backend_pid()").fetchone()
        assert row is not None
        self.backend_pids.append(row[0])
        if self.sqlstate is None:
            self.client_error = _ClientSideResponseLoss(
                "client lost the committed response"
            )
            raise self.client_error
        else:
            connection.execute(
                "DO $apcc$ BEGIN RAISE EXCEPTION 'ambiguous completion' "
                f"USING ERRCODE = '{self.sqlstate}'; END $apcc$"
            )


@dataclass(slots=True)
class _CommitBoundaryResponseLossProbe:
    armed: bool = False
    fired: bool = False
    backend_pids: list[object] = field(default_factory=list)

    def hit(self, point: str, connection: _Connection) -> None:
        if point == "before_atomic_authority_write":
            self.armed = True
            return
        if (
            point == "after_transaction_commit_before_return"
            and self.armed
            and not self.fired
        ):
            self.fired = True
            row = connection.execute("SELECT pg_backend_pid()").fetchone()
            assert row is not None
            self.backend_pids.append(row[0])
            raise _ClientSideResponseLoss("lost the driver COMMIT response")
        if point == "before_ambiguous_recovery":
            row = connection.execute("SELECT pg_backend_pid()").fetchone()
            assert row is not None
            self.backend_pids.append(row[0])


@pytest.mark.parametrize("sqlstate", _AMBIGUOUS_SQLSTATES)
def test_postgres_ambiguous_completion_recovers_on_a_fresh_connection(
    postgres_environment: _PostgresEnvironment, sqlstate: str | None
) -> None:
    schema, _ = _single_store(postgres_environment, f"ambiguous_{sqlstate}")
    probe = _AmbiguousCompletionProbe(sqlstate)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=1),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id=f"ambiguous-{sqlstate}", nonce_byte=108
    )
    _advance(postgres_environment, store, request)
    recovered = store.atomic_commit(request)
    assert probe.fired
    if sqlstate is None:
        assert probe.client_error is not None
        assert probe.client_error.sqlstate is None
    else:
        assert probe.client_error is None
    assert len(probe.backend_pids) == 2
    assert probe.backend_pids[0] != probe.backend_pids[1]
    fresh = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert fresh.authority_store_id == _config(postgres_environment).authority_store_id
    assert (
        fresh.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        )
        == recovered
    )
    recovery_store = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
    )
    mismatch_request = RecoveryRequest(request.commit_id, "different-request-digest")
    mismatch = recovery_store.recover(mismatch_request)
    assert mismatch.decision.outcome is RequestOutcome.CONFLICTED
    assert mismatch.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
    assert recovery_store.recover(mismatch_request) == mismatch


def test_postgres_driver_commit_response_loss_uses_fresh_exact_recovery(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "driver_commit_loss")
    probe = _CommitBoundaryResponseLossProbe()
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=1),
        probe=probe,
    )
    request = _request(
        postgres_environment, commit_id="driver-commit-loss", nonce_byte=113
    )
    _advance(postgres_environment, store, request)
    recovered = store.atomic_commit(request)
    assert recovered.decision.outcome is RequestOutcome.COMMITTED
    assert probe.fired
    assert len(probe.backend_pids) == 2
    assert probe.backend_pids[0] != probe.backend_pids[1]
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert (
        reader.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        )
        == recovered
    )


@pytest.mark.parametrize("same_digest", (True, False), ids=("same", "distinct"))
def test_postgres_concurrent_recovery_conflicts_are_serialized(
    postgres_environment: _PostgresEnvironment, same_digest: bool
) -> None:
    schema, store = _single_store(
        postgres_environment, f"concurrent_recovery_{same_digest}"
    )
    request = _request(
        postgres_environment,
        commit_id=f"concurrent-recovery-{same_digest}",
        nonce_byte=120 if same_digest else 121,
    )
    _advance(postgres_environment, store, request)
    assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED
    worker_count = 24
    digests = tuple(
        "recovery-conflict-same" if same_digest else f"recovery-conflict-{index}"
        for index in range(worker_count)
    )
    barrier = threading.Barrier(worker_count)

    def recover(index: int) -> CommitResult:
        concurrent_store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        barrier.wait(timeout=30)
        return concurrent_store.recover(
            RecoveryRequest(request.commit_id, digests[index])
        )

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = tuple(pool.map(recover, range(worker_count)))

    assert all(
        result.decision.outcome is RequestOutcome.CONFLICTED for result in results
    )
    assert all(
        result.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
        for result in results
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        rows = connection.execute(
            f"SELECT conflicting_request_digest,observation_sequence "
            f'FROM "{schema}"."commit_conflicts" WHERE commit_id=%s '
            "ORDER BY observation_sequence,conflicting_request_digest",
            (request.commit_id,),
        ).fetchall()
    expected_count = 1 if same_digest else worker_count
    assert len(rows) == expected_count
    assert tuple(cast(int, row[1]) for row in rows) == tuple(
        range(1, expected_count + 1)
    )
    if same_digest:
        assert len({result.audit_event_id for result in results}) == 1


def _assert_status_verdict(
    environment: _PostgresEnvironment,
    committed: CommitResult,
    status: AuthorityStatus,
    request_nonce: str,
    expected_code: FailureCode | None,
) -> None:
    assert committed.certificate_envelope_bytes is not None
    verdict = verify_current(
        committed.certificate_envelope_bytes,
        trust=getattr(environment.modules.support, "valid_vector")().trust,
        authority_status=status,
        request_nonce=request_nonce,
        now_ms=status.this_update_ms,
        highest_trust_log_sequence=status.trust_log_sequence,
        highest_trust_log_head=status.trust_log_head,
        maximum_staleness_ms="5000",
    )
    assert verdict.ok is (expected_code is None)
    assert verdict.code is expected_code


@dataclass(slots=True)
class _TrustHeadBarrierProbe:
    barrier: threading.Barrier
    backend_pids: list[object] = field(default_factory=list)

    def hit(self, point: str, connection: _Connection) -> None:
        if point != "before_trust_head_lock":
            return
        row = connection.execute("SELECT pg_backend_pid()").fetchone()
        assert row is not None
        self.backend_pids.append(row[0])
        self.barrier.wait(timeout=10)


@dataclass(slots=True)
class _ControlRetryProbe:
    failures_remaining: int
    transaction_ids: list[object] = field(default_factory=list)

    def hit(self, point: str, connection: _Connection) -> None:
        if point != "before_revocation_trust_log_write":
            return
        row = connection.execute("SELECT txid_current()").fetchone()
        assert row is not None
        self.transaction_ids.append(row[0])
        if self.failures_remaining:
            self.failures_remaining -= 1
            connection.execute(
                "DO $apcc$ BEGIN RAISE EXCEPTION 'retry whole control transaction' "
                "USING ERRCODE = '40001'; END $apcc$"
            )


def test_postgres_cross_workflow_revocations_serialize_the_global_trust_head(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "global_trust_head")
    probe = _TrustHeadBarrierProbe(threading.Barrier(2))

    def revoke(workflow_id: str) -> RevocationResult:
        store = postgres_environment.modules.store_factory._open_with_probe(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
            retry_policy=postgres_environment.modules.retry_policy_factory(
                max_attempts=3
            ),
            probe=probe,
        )
        return store.revoke(
            RevocationRequest(
                RevocationScope.WORKFLOW,
                workflow_id,
                workflow_id,
                "1",
                "cross-workflow trust-head serialization",
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(revoke, ("workflow-1", "workflow-2")))
    assert len(probe.backend_pids) == 2
    assert probe.backend_pids[0] != probe.backend_pids[1]
    assert {result.target_id for result in results} == {"workflow-1", "workflow-2"}
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        trust_rows = connection.execute(
            f'SELECT sequence,prior_digest,entry_digest FROM "{schema}"."trust_log" '
            "ORDER BY sequence"
        ).fetchall()
    assert [row[0] for row in trust_rows] == [1, 2]
    assert trust_rows[1][1] == trust_rows[0][2]


def test_postgres_retries_the_whole_revocation_transaction(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "control_retry")
    probe = _ControlRetryProbe(failures_remaining=1)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=2),
        probe=probe,
    )
    result = store.revoke(
        RevocationRequest(
            RevocationScope.ACTOR,
            "workflow-1",
            "agent-1",
            "4",
            "retry the complete control mutation",
        )
    )
    assert result.resulting_generation == "4"
    assert len(probe.transaction_ids) == 2
    assert len(set(probe.transaction_ids)) == 2


@pytest.mark.parametrize("operation", ("revoke", "supersede", "status"))
def test_postgres_revocation_supersession_and_status_races_are_linearizable(
    postgres_environment: _PostgresEnvironment, operation: str
) -> None:
    schema, setup = _single_store(postgres_environment, f"race_{operation}")
    original_request = _request(
        postgres_environment, commit_id=f"race-{operation}-old", nonce_byte=109
    )
    _advance(postgres_environment, setup, original_request)
    original = setup.atomic_commit(original_request)
    certificate_digest = original.certificate_digest
    assert certificate_digest is not None
    before_race = _snapshot(postgres_environment, setup)
    replacement: AtomicCommitRequest | None = None
    if operation == "supersede":
        replacement = _request(
            postgres_environment,
            commit_id="race-replacement",
            nonce_byte=110,
            expected_node_version="1",
            attempt_id="replacement",
        )
        _advance(postgres_environment, setup, replacement)
    barrier = threading.Barrier(2)
    status_nonces = tuple(
        base64.urlsafe_b64encode(bytes([worker + 1]) * 16).rstrip(b"=").decode("ascii")
        for worker in range(2)
    )

    def race(worker: int) -> object:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        barrier.wait()
        if operation == "revoke":
            return store.revoke(
                RevocationRequest(
                    RevocationScope.CERTIFICATE,
                    original_request.subject.workflow_id,
                    certificate_digest,
                    "1",
                    "postgres race",
                )
            )
        if operation == "supersede":
            assert replacement is not None
            return store.supersede(SupersessionRequest(certificate_digest, replacement))
        return store.current_status(
            certificate_digest,
            status_nonces[worker],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(race, range(2)))
    if operation == "revoke":
        for result in results:
            assert isinstance(result, RevocationResult)
            assert result.scope is RevocationScope.CERTIFICATE
            assert result.target_id == certificate_digest
            assert result.resulting_generation == "1"
        assert results[0] == results[1]
        after_race = _snapshot(postgres_environment, setup)
        changed = {
            table
            for table in set(before_race.tables) | set(after_race.tables)
            if before_race.tables.get(table) != after_race.tables.get(table)
        }
        assert changed == {
            "certificate_dispositions",
            "control_events",
            "trust_log",
            "audit_events",
            "outbox",
        }
        for table in (
            "certificate_dispositions",
            "control_events",
            "trust_log",
            "audit_events",
            "outbox",
        ):
            assert len(after_race.tables[table]) == len(before_race.tables[table]) + 1
        status = setup.current_status(certificate_digest, status_nonces[0])
        assert status.status is AuthorityStatusValue.REVOKED
        _assert_status_verdict(
            postgres_environment,
            original,
            status,
            status_nonces[0],
            FailureCode.AUTHORITY_STATUS_REVOKED,
        )
        return
    if operation == "supersede":
        for result in results:
            assert isinstance(result, SupersessionCommitted)
            assert result.old_certificate_digest == certificate_digest
            assert (
                result.new_certificate_digest == result.commit_result.certificate_digest
            )
            assert result.commit_result.decision.outcome is RequestOutcome.COMMITTED
        assert results[0] == results[1]
        replacement_result = results[0]
        assert isinstance(replacement_result, SupersessionCommitted)
        node = setup.read_logical_node(
            original_request.subject.workflow_id, original_request.subject.node_id
        )
        assert node.current_node_version == "2"
        assert (
            node.current_certificate_digest == replacement_result.new_certificate_digest
        )
        status = setup.current_status(certificate_digest, status_nonces[0])
        assert status.superseded is SupersessionValue.YES
        _assert_status_verdict(
            postgres_environment,
            original,
            status,
            status_nonces[0],
            FailureCode.AUTHORITY_STATUS_SUPERSEDED,
        )
        return
    invariant_bodies: list[tuple[str, ...]] = []
    for nonce, result in zip(status_nonces, results, strict=True):
        assert isinstance(result, AuthorityStatus)
        assert result.request_nonce == nonce
        assert result.certificate_digest == certificate_digest
        assert result.status is AuthorityStatusValue.CURRENT
        assert result.superseded is SupersessionValue.NO
        _assert_status_verdict(postgres_environment, original, result, nonce, None)
        invariant_bodies.append(
            (
                result.certificate_sequence,
                result.trust_log_sequence,
                result.trust_log_head,
                result.actor_revocation_generation,
                result.workflow_revocation_generation,
            )
        )
    assert invariant_bodies[0] == invariant_bodies[1]


def test_postgres_skip_locked_outbox_has_one_persisted_event_identity(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, setup = _single_store(postgres_environment, "skip_locked_outbox")
    locked_request = _request(
        postgres_environment, commit_id="pg-outbox-locked", nonce_byte=111
    )
    available_request = _request(
        postgres_environment,
        commit_id="pg-outbox-available",
        nonce_byte=112,
        workflow_id="workflow-2",
    )
    for request in (locked_request, available_request):
        _advance(postgres_environment, setup, request)
        setup.atomic_commit(request)
    locked_event = setup.get_outbox_event(locked_request.commit_id)
    available_event = setup.get_outbox_event(available_request.commit_id)
    assert locked_event.pending and available_event.pending

    def recover(_: int) -> OutboxRecoveryResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        return store.recover_outbox(OutboxRecoveryRequest(max_items="1"))

    with ThreadPoolExecutor(max_workers=1) as pool:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn
        ) as locker:
            locked = locker.execute(
                f'SELECT event_id FROM "{schema}"."outbox" '
                "WHERE commit_id=%s FOR UPDATE",
                (locked_request.commit_id,),
            ).fetchone()
            assert locked == (locked_event.event_id,)
            skipped = pool.submit(recover, 0).result(timeout=5)
            assert skipped.delivered_count == "1"
            assert setup.get_outbox_event(locked_request.commit_id).pending
            assert not setup.get_outbox_event(available_request.commit_id).pending
    released = recover(1)
    assert released.delivered_count == "1"
    assert not setup.get_outbox_event(locked_request.commit_id).pending
    assert (
        setup.get_outbox_event(locked_request.commit_id).event_id
        == locked_event.event_id
    )
    assert (
        setup.get_outbox_event(available_request.commit_id).event_id
        == available_event.event_id
    )


@dataclass(slots=True)
class _BlockingOutboxSink:
    started: threading.Event = field(default_factory=threading.Event)
    duplicate_started: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    deliveries: list[tuple[str, bytes]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def deliver(self, event_id: str, payload: bytes) -> None:
        with self.lock:
            self.deliveries.append((event_id, payload))
            if len(self.deliveries) == 1:
                self.started.set()
            else:
                self.duplicate_started.set()
        if not self.release.wait(timeout=10):
            raise TimeoutError("test outbox sink was not released")


@dataclass(slots=True)
class _RecordingOutboxSink:
    fail_once: bool = False
    deliveries: list[tuple[str, bytes]] = field(default_factory=list)

    def deliver(self, event_id: str, payload: bytes) -> None:
        self.deliveries.append((event_id, payload))
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("injected sink failure")


def _store_with_sink(
    environment: _PostgresEnvironment,
    label: str,
    sink: _BlockingOutboxSink | _RecordingOutboxSink,
) -> tuple[str, _PostgresStore, AuthorityRuntime]:
    schema = environment.schema(label)
    config = _config(environment)
    environment.modules.store_factory.provision(
        environment.dsn,
        schema=schema,
        config=config,
        initial_contexts=_initial_contexts(environment),
        runtime_role=environment.runtime_role,
        observer_role=environment.observer_role,
        runtime=_runtime(environment),
    )
    runtime = replace(_runtime(environment), outbox_sink=sink)
    store = environment.modules.store_factory.open(
        environment.runtime_dsn,
        schema=schema,
        config=config,
        runtime=runtime,
    )
    return schema, store, runtime


def test_postgres_same_event_has_one_active_delivery_lease(
    postgres_environment: _PostgresEnvironment,
) -> None:
    sink = _BlockingOutboxSink()
    schema, setup, runtime = _store_with_sink(
        postgres_environment, "exclusive_outbox_lease", sink
    )
    request = _request(
        postgres_environment, commit_id="exclusive-outbox", nonce_byte=114
    )
    _advance(postgres_environment, setup, request)
    setup.atomic_commit(request)

    def recover() -> OutboxRecoveryResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=runtime,
        )
        return store.recover_outbox(OutboxRecoveryRequest("1"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(recover)
        if not sink.started.wait(timeout=5):
            first.result(timeout=1)
            pytest.fail("first outbox worker did not reach the sink")
        second = pool.submit(recover)
        duplicate_delivery = sink.duplicate_started.wait(timeout=0.75)
        sink.release.set()
        results = (first.result(timeout=10), second.result(timeout=10))
    assert not duplicate_delivery
    assert len(sink.deliveries) == 1
    assert sorted(result.delivered_count for result in results) == ["0", "1"]


def test_postgres_active_outbox_lease_blocks_then_expiry_reclaims(
    postgres_environment: _PostgresEnvironment,
) -> None:
    sink = _RecordingOutboxSink()
    schema, store, runtime = _store_with_sink(
        postgres_environment, "outbox_lease_expiry", sink
    )
    request = _request(postgres_environment, commit_id="lease-expiry", nonce_byte=115)
    _advance(postgres_environment, store, request)
    store.atomic_commit(request)
    now = runtime.clock.now_ms()
    _apply_valid_test_mutation_and_reseal(
        postgres_environment,
        schema,
        "UPDATE outbox SET state='CLAIMED',lease_token='owner',"
        "lease_claimed_ms=%s,lease_until_ms=%s,delivered=0",
        (now, now + 1000),
    )
    blocked = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert blocked.delivered_count == "0"
    assert sink.deliveries == []
    _apply_valid_test_mutation_and_reseal(
        postgres_environment,
        schema,
        "UPDATE outbox SET lease_claimed_ms=%s,lease_until_ms=%s",
        (now - 2, now - 1),
    )
    reclaimed = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert reclaimed.delivered_count == "1"
    assert len(sink.deliveries) == 1


def test_postgres_sink_failure_releases_the_exact_outbox_lease(
    postgres_environment: _PostgresEnvironment,
) -> None:
    sink = _RecordingOutboxSink(fail_once=True)
    schema, store, _runtime_value = _store_with_sink(
        postgres_environment, "outbox_release", sink
    )
    request = _request(postgres_environment, commit_id="lease-release", nonce_byte=116)
    _advance(postgres_environment, store, request)
    store.atomic_commit(request)
    with pytest.raises(RuntimeError, match="injected sink failure"):
        store.recover_outbox(OutboxRecoveryRequest("1"))
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        row = connection.execute(
            f"SELECT state,lease_token,lease_claimed_ms,lease_until_ms "
            f'FROM "{schema}"."outbox" WHERE operation_id=%s',
            (request.commit_id,),
        ).fetchone()
    assert row == ("PENDING", None, None, None)
    assert store.recover_outbox(OutboxRecoveryRequest("1")).delivered_count == "1"


def test_postgres_accepts_a_generic_safe_schema_identifier(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema = f"tenant_{secrets.token_hex(12)}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE SCHEMA "{schema}" AUTHORIZATION '
            f'"{postgres_environment.owner_role}"'
        )
    try:
        config = _config(postgres_environment)
        postgres_environment.modules.store_factory.provision(
            postgres_environment.dsn,
            schema=schema,
            config=config,
            initial_contexts=_initial_contexts(postgres_environment),
            runtime_role=postgres_environment.runtime_role,
            observer_role=postgres_environment.observer_role,
            runtime=_runtime(postgres_environment),
        )
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=config,
            runtime=_runtime(postgres_environment),
        )
        assert store.authority_store_id == config.authority_store_id
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(f'DROP SCHEMA "{schema}" CASCADE')


@pytest.mark.parametrize(
    "schema", ("public", "pg_catalog", "information_schema", "bad-name", "x;DROP")
)
def test_postgres_rejects_reserved_or_unsafe_schema_identifiers(
    postgres_environment: _PostgresEnvironment, schema: str
) -> None:
    with pytest.raises(ValueError, match="unsafe APCC PostgreSQL schema name"):
        postgres_environment.modules.store_factory.provision(
            postgres_environment.dsn,
            schema=schema,
            config=_config(postgres_environment),
            initial_contexts=_initial_contexts(postgres_environment),
            runtime_role=postgres_environment.runtime_role,
            observer_role=postgres_environment.observer_role,
            runtime=_runtime(postgres_environment),
        )


def test_postgres_provisions_the_native_schema_manifest(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "native_manifest")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        fingerprint = connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=\'schema_fingerprint\''
        ).fetchone()
        schema_version = connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=\'schema_version\''
        ).fetchone()
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname=%s", (schema,)
            ).fetchall()
        }
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT trigger_name FROM information_schema.triggers "
                "WHERE trigger_schema=%s",
                (schema,),
            ).fetchall()
        }
        checkpoint = connection.execute(
            f"SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
            f'FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        ).fetchone()
    assert fingerprint is not None and len(str(fingerprint[0])) == 43
    assert schema_version == ("3",)
    assert {
        "idx_apcc_outbox_pending",
        "idx_apcc_outbox_head",
        "idx_nonce_ledger_nonce",
        "idx_supersession_new_digest",
    } <= indexes
    assert {
        "certificate_dispositions_no_update",
        "certificate_dispositions_no_delete",
        "certificate_dispositions_validate_insert",
        "trust_log_no_update",
        "trust_log_no_delete",
        "control_events_no_update",
        "control_events_no_delete",
        "outbox_identity_no_update",
        "outbox_no_delete",
    } <= triggers
    assert {
        "apcc_semantic_dirty_candidates_insert",
        "apcc_semantic_dirty_certificates_update",
        "apcc_semantic_dirty_outbox_delete",
        "apcc_semantic_dirty_workflow_authority_insert",
    } <= triggers
    assert checkpoint is not None
    assert isinstance(checkpoint[0], int) and checkpoint[0] >= 0
    assert isinstance(checkpoint[1], str) and len(checkpoint[1]) == 43
    assert isinstance(checkpoint[2], str) and len(checkpoint[2]) == 43
    assert checkpoint[3] == _config(postgres_environment).commit_trust.key_id
    assert isinstance(checkpoint[4], str) and checkpoint[4]


def _provision_gcb_profile(
    environment: _PostgresEnvironment, label: str
) -> tuple[str, APCCAuthorityConfig, AuthorityRuntime]:
    schema = environment.schema(label)
    config = _config(environment)
    runtime = _runtime(environment)
    provision_gcb = cast(
        "Callable[..., None]",
        getattr(environment.modules.store_factory, "_provision_gcb"),
    )
    provision_gcb(
        environment.dsn,
        schema=schema,
        config=config,
        initial_contexts=_initial_contexts(environment),
        runtime_role=environment.runtime_role,
        observer_role=environment.observer_role,
        runtime=runtime,
    )
    return schema, config, runtime


def _open_gcb_profile(
    environment: _PostgresEnvironment,
    schema: str,
    config: APCCAuthorityConfig,
    runtime: AuthorityRuntime,
) -> _PostgresStore:
    open_gcb = cast(
        "Callable[..., _PostgresStore]",
        getattr(environment.modules.store_factory, "_open_gcb"),
    )
    return open_gcb(
        environment.runtime_dsn,
        schema=schema,
        config=config,
        runtime=runtime,
    )


def test_postgres_gcb_profile_provisions_exact_attached_catalog(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, config, runtime = _provision_gcb_profile(
        postgres_environment, "gcb_attached_catalog"
    )
    store = _open_gcb_profile(postgres_environment, schema, config, runtime)
    assert store.authority_store_id == config.authority_store_id
    required = {
        "gcb_store_meta",
        "gcb_workflows",
        "gcb_agents",
        "gcb_nodes",
        "gcb_staged_artifacts",
        "gcb_revoked_roots",
        "gcb_decisions",
        "gcb_receipt_evidence",
        "gcb_outbox",
    }
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=%s",
                (schema,),
            ).fetchall()
        }
        profile = connection.execute(
            f"SELECT profile,schema_version,authority_store_id,sealed "
            f'FROM "{schema}"."gcb_store_meta" '
            "WHERE singleton=1"
        ).fetchone()
        material_types = connection.execute(
            "SELECT table_name,column_name,data_type FROM information_schema.columns "
            "WHERE table_schema=%s AND table_name LIKE 'gcb_%%' "
            "AND column_name IN ('capabilities','required_capabilities','predecessors',"
            "'artifact_json','request_hash','receipt_material','verdict_material')",
            (schema,),
        ).fetchall()
        indexes = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=%s "
                "AND tablename LIKE 'gcb_%%'",
                (schema,),
            ).fetchall()
        }
        foreign_keys = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT c.conname,pg_get_constraintdef(c.oid,true) "
                "FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace "
                "WHERE n.nspname=%s AND c.contype='f' AND c.conname LIKE 'gcb_%%'",
                (schema,),
            ).fetchall()
        }
    assert required <= tables
    assert len(tables) == 31
    assert profile == ("gcb-attached-v1", "3", config.authority_store_id, 1)
    assert material_types
    assert all(row[2] == "text" for row in material_types)
    assert "idx_gcb_outbox_pending" in indexes
    assert "WHERE (dispatched = 0)" in indexes["idx_gcb_outbox_pending"]
    assert ".commit_index(commit_id)" in foreign_keys["gcb_decisions_apcc_commit_fkey"]
    assert ".outbox(event_sequence)" in foreign_keys["gcb_outbox_apcc_sequence_fkey"]
    assert ".outbox(event_id)" in foreign_keys["gcb_outbox_apcc_event_fkey"]
    gated_request = _request(
        postgres_environment,
        commit_id="gcb-profile-mutation-gate",
        nonce_byte=121,
    )
    with pytest.raises(ValueError, match="require projection support"):
        _advance(
            postgres_environment,
            store,
            gated_request,
        )
    with pytest.raises(ValueError, match="require projection support"):
        store.atomic_commit(gated_request)


def test_postgres_gcb_profile_is_fail_closed_across_open_paths(
    postgres_environment: _PostgresEnvironment,
) -> None:
    combined_schema, config, runtime = _provision_gcb_profile(
        postgres_environment, "gcb_cross_open_combined"
    )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=combined_schema,
            config=config,
            runtime=runtime,
        )

    base_schema, _store = _single_store(postgres_environment, "gcb_cross_open_base")
    with pytest.raises(ValueError, match="schema validation failed"):
        _open_gcb_profile(postgres_environment, base_schema, config, runtime)


def test_postgres_gcb_profile_rejects_catalog_tamper(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, config, runtime = _provision_gcb_profile(
        postgres_environment, "gcb_catalog_tamper"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'ALTER TABLE "{schema}"."gcb_nodes" ADD COLUMN escape TEXT')
    with pytest.raises(ValueError, match="schema validation failed"):
        _open_gcb_profile(postgres_environment, schema, config, runtime)


def test_postgres_gcb_profile_is_fresh_only(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, config, runtime = _provision_gcb_profile(
        postgres_environment, "gcb_fresh_only"
    )
    provision_gcb = cast(
        "Callable[..., None]",
        getattr(postgres_environment.modules.store_factory, "_provision_gcb"),
    )
    with pytest.raises(ValueError, match="already provisioned"):
        provision_gcb(
            postgres_environment.dsn,
            schema=schema,
            config=config,
            initial_contexts=_initial_contexts(postgres_environment),
            runtime_role=postgres_environment.runtime_role,
            observer_role=postgres_environment.observer_role,
            runtime=runtime,
        )


def test_postgres_v1_store_fails_with_explicit_schema_incompatibility(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "incompatible_v1")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f"UPDATE \"{schema}\".\"metadata\" SET value='1' WHERE key='schema_version'"
        )

    with pytest.raises(ValueError, match="authority schema version is incompatible"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
    with pytest.raises(ValueError, match="authority schema version is incompatible"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


def test_postgres_checkpoint_trigger_cannot_be_shadowed_by_pg_temp(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_pg_temp_shadow")
    request = _request(
        postgres_environment,
        commit_id="checkpoint-pg-temp-shadow",
        nonce_byte=139,
    )
    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(request)
    )
    before = _checkpoint_row(postgres_environment, schema)

    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn
    ) as connection:
        connection.execute(
            "CREATE TEMP TABLE semantic_checkpoint "
            f'(LIKE "{schema}"."semantic_checkpoint" INCLUDING ALL)'
        )
        connection.execute(
            "INSERT INTO pg_temp.semantic_checkpoint SELECT * FROM "
            f'"{schema}"."semantic_checkpoint"'
        )
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
        real = connection.execute(
            f"SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
            f'FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        ).fetchone()
        shadow = connection.execute(
            "SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
            "FROM pg_temp.semantic_checkpoint WHERE singleton=1"
        ).fetchone()

    assert real is not None
    assert isinstance(real[0], int) and not isinstance(real[0], bool)
    assert real[0] > before[0]
    assert real[2] == ""
    assert real[4] == ""
    assert shadow == before


@pytest.mark.parametrize("table", _CHECKPOINT_GUARDED_TABLES)
def test_postgres_truncate_dirties_checkpoint_for_every_guarded_table(
    postgres_environment: _PostgresEnvironment,
    table: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"checkpoint_truncate_{table}")
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    assert tuple(getattr(store_module, "_POSTGRES_CHECKPOINT_TABLES")) == (
        _CHECKPOINT_GUARDED_TABLES
    )
    before = _checkpoint_row(postgres_environment, schema)

    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'TRUNCATE TABLE "{schema}"."{table}" CASCADE')

    after = _checkpoint_row(postgres_environment, schema)
    assert after[0] > before[0]
    assert after[2] == ""
    assert after[4] == ""


def test_postgres_missing_checkpoint_aborts_guarded_dml_without_mutation(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_missing")
    request = _request(
        postgres_environment,
        commit_id="checkpoint-missing",
        nonce_byte=140,
    )
    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(request)
    )

    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'DELETE FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        )
        with pytest.raises(Exception) as error:
            connection.execute(
                f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
                "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
                (
                    request.subject.workflow_id,
                    request.subject.node_id,
                    request.subject.attempt_id,
                ),
            )
        persisted = connection.execute(
            f'SELECT proposal_digest FROM "{schema}"."candidates" '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        ).fetchone()

    assert getattr(error.value, "sqlstate", None) == "55000"
    assert persisted == (None,)


def test_postgres_provision_never_commits_unsealed_populated_state(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema = postgres_environment.schema("checkpoint_bootstrap_sealed")
    postgres_environment.modules.store_factory.provision(
        postgres_environment.dsn,
        schema=schema,
        config=_config(postgres_environment),
        initial_contexts=_initial_contexts(postgres_environment),
        runtime_role=postgres_environment.runtime_role,
        observer_role=postgres_environment.observer_role,
        runtime=_runtime(postgres_environment),
    )

    checkpoint = _checkpoint_row(postgres_environment, schema)
    assert checkpoint[2]
    assert checkpoint[4]


def test_postgres_runtime_role_is_nonprivileged_and_commits_normally(
    postgres_environment: _PostgresEnvironment,
) -> None:
    _, store = _single_store(postgres_environment, "runtime_normal_commit")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        identity = connection.execute(
            "SELECT current_user,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
            "rolcanlogin,rolreplication,rolbypassrls FROM pg_roles "
            "WHERE rolname=current_user"
        ).fetchone()
    assert identity == (
        postgres_environment.runtime_role,
        False,
        False,
        False,
        False,
        True,
        False,
        False,
    )
    request = _request(postgres_environment, commit_id="runtime-normal", nonce_byte=141)
    _advance(postgres_environment, store, request)
    assert store.atomic_commit(request).decision.outcome is RequestOutcome.COMMITTED


def test_postgres_observer_role_is_exact_select_only_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _store = _single_store(postgres_environment, "observer_acl")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute("SELECT session_user,current_user").fetchone() == (
            postgres_environment.observer_role,
            postgres_environment.observer_role,
        )
        assert connection.execute(
            f'SELECT count(*) FROM "{schema}"."metadata"'
        ).fetchone() == (6,)
        denied = (
            f"INSERT INTO \"{schema}\".\"metadata\" VALUES ('x','y')",
            f'UPDATE "{schema}"."metadata" SET value=value',
            f'DELETE FROM "{schema}"."metadata"',
            f'TRUNCATE "{schema}"."metadata"',
            f'CREATE TABLE "{schema}"."observer_escape"(x int)',
            "CREATE TEMP TABLE observer_temp_escape(x int)",
            f'COPY "{schema}"."metadata" FROM \'/etc/passwd\'',
            f'COPY "{schema}"."metadata" TO PROGRAM \'false\'',
            f'CREATE FUNCTION "{schema}".observer_escape() RETURNS int '
            "LANGUAGE sql AS 'SELECT 1'",
            f'UPDATE "{schema}"."semantic_checkpoint" SET checkpoint_digest=checkpoint_digest',
        )
        for statement in denied:
            try:
                connection.execute(statement)
            except Exception:
                pass
            else:
                pytest.fail(f"observer unexpectedly executed: {statement}")
        function = connection.execute(
            "SELECT p.oid::regprocedure::text,has_function_privilege(current_user,p.oid,'EXECUTE') "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname=%s ORDER BY p.proname LIMIT 1",
            (schema,),
        ).fetchone()
        assert function is not None and function[1] is False
        assert connection.execute(
            "SELECT has_table_privilege(current_user,%s::regclass,'MAINTAIN')",
            (f'"{schema}"."metadata"',),
        ).fetchone() == (False,)
        with connection.cursor().copy(
            f'COPY (SELECT key FROM "{schema}"."metadata" ORDER BY key) TO STDOUT'
        ) as copy:
            assert b"config" in b"".join(bytes(chunk) for chunk in copy)
        with pytest.raises(Exception):
            with connection.cursor().copy(
                f'COPY "{schema}"."metadata" FROM STDIN'
            ) as copy:
                copy.write_row(("observer-copy", "denied"))


@pytest.mark.parametrize(
    "operation",
    (
        "checkpoint_delete",
        "checkpoint_sequence",
        "checkpoint_prior",
        "checkpoint_key",
        "truncate",
        "disable_trigger",
        "drop_trigger",
        "alter_table",
        "schema_create",
    ),
)
def test_postgres_runtime_role_cannot_escape_checkpoint_authority(
    postgres_environment: _PostgresEnvironment,
    operation: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"runtime_denied_{operation}")
    statements = {
        "checkpoint_delete": (
            f'DELETE FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        ),
        "checkpoint_sequence": (
            f'UPDATE "{schema}"."semantic_checkpoint" '
            "SET change_sequence=change_sequence+1 WHERE singleton=1"
        ),
        "checkpoint_prior": (
            f'UPDATE "{schema}"."semantic_checkpoint" '
            "SET prior_digest='tampered' WHERE singleton=1"
        ),
        "checkpoint_key": (
            f'UPDATE "{schema}"."semantic_checkpoint" '
            "SET key_id='tampered' WHERE singleton=1"
        ),
        "truncate": f'TRUNCATE TABLE "{schema}"."candidates"',
        "disable_trigger": (
            f'ALTER TABLE "{schema}"."candidates" DISABLE TRIGGER '
            "apcc_semantic_dirty_candidates_update"
        ),
        "drop_trigger": (
            "DROP TRIGGER apcc_semantic_dirty_candidates_update ON "
            f'"{schema}"."candidates"'
        ),
        "alter_table": (f'ALTER TABLE "{schema}"."candidates" ADD COLUMN bypass TEXT'),
        "schema_create": f'CREATE TABLE "{schema}"."bypass" (value TEXT)',
    }
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        with pytest.raises(Exception) as error:
            connection.execute(statements[operation])
    assert getattr(error.value, "sqlstate", None) == "42501"


def test_postgres_runtime_raw_dml_cannot_replay_the_prior_checkpoint(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "runtime_checkpoint_replay")
    request = _request(
        postgres_environment,
        commit_id="runtime-checkpoint-replay",
        nonce_byte=142,
    )
    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(request)
    )
    before = _checkpoint_row(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
        dirty = connection.execute(
            f"SELECT change_sequence,prior_digest,checkpoint_digest,key_id,signature "
            f'FROM "{schema}"."semantic_checkpoint" WHERE singleton=1'
        ).fetchone()
        assert dirty is not None
        assert isinstance(dirty[0], int) and not isinstance(dirty[0], bool)
        assert dirty[0] > before[0]
        assert dirty[2] == "" and dirty[4] == ""
        connection.execute(
            f'UPDATE "{schema}"."semantic_checkpoint" '
            "SET checkpoint_digest=%s,signature=%s WHERE singleton=1",
            (before[2], before[4]),
        )

    with pytest.raises(ValueError, match="semantic checkpoint validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("opener", ("reader", "writer"))
@pytest.mark.parametrize("target", ("schema", "relation", "function"))
def test_postgres_open_rejects_owner_drift(
    postgres_environment: _PostgresEnvironment,
    opener: str,
    target: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"owner_drift_{opener}_{target}")
    alter = {
        "schema": f'ALTER SCHEMA "{schema}" OWNER TO apcc',
        "relation": f'ALTER TABLE "{schema}"."candidates" OWNER TO apcc',
        "function": (
            f'ALTER FUNCTION "{schema}"."apcc_mark_semantic_dirty"() OWNER TO apcc'
        ),
    }[target]
    restore = {
        "schema": (
            f'ALTER SCHEMA "{schema}" OWNER TO "{postgres_environment.owner_role}"'
        ),
        "relation": (
            f'ALTER TABLE "{schema}"."candidates" OWNER TO '
            f'"{postgres_environment.owner_role}"'
        ),
        "function": (
            f'ALTER FUNCTION "{schema}"."apcc_mark_semantic_dirty"() OWNER TO '
            f'"{postgres_environment.owner_role}"'
        ),
    }[target]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(alter)
    try:
        with pytest.raises(ValueError, match="schema validation failed"):
            if opener == "reader":
                postgres_environment.modules.reader_factory.open(
                    postgres_environment.observer_dsn, schema=schema
                )
            else:
                postgres_environment.modules.store_factory.open(
                    postgres_environment.runtime_dsn,
                    schema=schema,
                    config=_config(postgres_environment),
                    runtime=_runtime(postgres_environment),
                )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(restore)


@pytest.mark.parametrize("opener", ("reader", "writer"))
@pytest.mark.parametrize("target", ("schema", "relation", "function"))
def test_postgres_open_rejects_acl_drift(
    postgres_environment: _PostgresEnvironment,
    opener: str,
    target: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"acl_drift_{opener}_{target}")
    grant = {
        "schema": f'GRANT CREATE ON SCHEMA "{schema}" TO PUBLIC',
        "relation": f'GRANT TRUNCATE ON "{schema}"."candidates" TO PUBLIC',
        "function": (
            f'GRANT EXECUTE ON FUNCTION "{schema}".'
            '"apcc_mark_semantic_dirty"() TO PUBLIC'
        ),
    }[target]
    revoke = grant.replace("GRANT", "REVOKE", 1).replace(" TO PUBLIC", " FROM PUBLIC")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(grant)
    try:
        with pytest.raises(ValueError, match="schema validation failed"):
            if opener == "reader":
                postgres_environment.modules.reader_factory.open(
                    postgres_environment.observer_dsn, schema=schema
                )
            else:
                postgres_environment.modules.store_factory.open(
                    postgres_environment.runtime_dsn,
                    schema=schema,
                    config=_config(postgres_environment),
                    runtime=_runtime(postgres_environment),
                )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(revoke)


def test_postgres_runtime_and_public_function_acl_is_exact(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "function_acl")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        public_execute = connection.execute(
            "SELECT p.proname FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,"
            "acldefault('f',p.proowner))) x "
            "WHERE n.nspname=%s AND x.grantee=0 "
            "AND x.privilege_type='EXECUTE'",
            (schema,),
        ).fetchall()
    assert public_execute == []


def test_postgres_admin_dsn_is_not_accepted_as_runtime(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "admin_not_runtime")
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.dsn, schema=schema
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


@pytest.mark.parametrize("batch_size", (1, 100, 1000))
def test_postgres_status_batch_uses_one_repeatable_read_checkpoint_attestation(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    batch_size: int,
) -> None:
    _, store = _single_store(postgres_environment, f"checkpoint_batch_{batch_size}")
    request = _request(
        postgres_environment,
        commit_id=f"checkpoint-batch-{batch_size}",
        nonce_byte=118,
    )
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    original_verify = getattr(store_module, "_verify_semantic_checkpoint")
    original_connection = cast(
        "Callable[[], _Connection]", getattr(store, "_connection")
    )
    provider_type = type(_runtime(postgres_environment).key_provider)
    status_signature_count = cast(
        "Callable[[], int]", getattr(provider_type, "status_signature_count")
    )
    attestations = 0
    connections = 0
    observations: list[tuple[object, object, object]] = []

    def open_connection() -> _Connection:
        nonlocal connections
        connections += 1
        return original_connection()

    def verify_checkpoint(*args: object, **kwargs: object) -> object:
        nonlocal attestations
        attestations += 1
        connection = cast("_Connection", args[0])
        observations.append(
            (
                connection.execute("SHOW transaction_isolation").fetchone(),
                connection.execute("SHOW transaction_read_only").fetchone(),
                connection.execute("SELECT txid_current()").fetchone(),
            )
        )
        return original_verify(*args, **kwargs)

    def forbid_full_scan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("hot status batch performed a whole-store semantic scan")

    monkeypatch.setattr(store, "_connection", open_connection)
    monkeypatch.setattr(store_module, "_verify_semantic_checkpoint", verify_checkpoint)
    monkeypatch.setattr(store_module, "_validate_semantics", forbid_full_scan)
    requests = tuple(
        CurrentStatusRequest(
            committed.certificate_digest,
            base64.urlsafe_b64encode(index.to_bytes(16, "big"))
            .rstrip(b"=")
            .decode("ascii"),
        )
        for index in range(1, batch_size + 1)
    )

    before_signatures = status_signature_count()
    results = store.current_status_batch(requests)

    assert tuple(result.request for result in results) == requests
    assert connections == 1
    assert attestations == 1
    assert len(observations) == 1
    assert observations[0][0:2] == (("repeatable read",), ("on",))
    assert isinstance(observations[0][2], tuple)
    assert status_signature_count() - before_signatures == batch_size


def test_postgres_hot_mutation_verifies_and_reseals_checkpoint_without_full_scan(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _single_store(postgres_environment, "checkpoint_hot_mutation")
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    original_verify = getattr(store_module, "_verify_semantic_checkpoint")
    original_seal = getattr(store_module, "_seal_semantic_checkpoint")
    verifications = 0
    seals = 0

    def verify_checkpoint(*args: object, **kwargs: object) -> object:
        nonlocal verifications
        verifications += 1
        return original_verify(*args, **kwargs)

    def seal_checkpoint(*args: object, **kwargs: object) -> object:
        nonlocal seals
        seals += 1
        return original_seal(*args, **kwargs)

    def forbid_full_scan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("hot mutation performed a whole-store semantic scan")

    monkeypatch.setattr(store_module, "_verify_semantic_checkpoint", verify_checkpoint)
    monkeypatch.setattr(store_module, "_seal_semantic_checkpoint", seal_checkpoint)
    monkeypatch.setattr(store_module, "_validate_semantics", forbid_full_scan)
    request = _request(
        postgres_environment,
        commit_id="checkpoint-hot-mutation",
        nonce_byte=121,
    )

    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(request)
    )

    assert verifications == 1
    assert seals == 1


def test_postgres_rolled_back_raw_write_does_not_dirty_signed_checkpoint(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_raw_rollback")
    seed = _request(
        postgres_environment,
        commit_id="checkpoint-raw-rollback-seed",
        nonce_byte=127,
    )
    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(seed)
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                seed.subject.workflow_id,
                seed.subject.node_id,
                seed.subject.attempt_id,
            ),
        )
        connection.rollback()
    target = _request(
        postgres_environment,
        commit_id="checkpoint-after-raw-rollback",
        nonce_byte=128,
        attempt_id="checkpoint-after-raw-rollback",
    )

    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(target)
    )


def test_postgres_invalid_checkpoint_signature_blocks_mutation_and_reopen(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_bad_signature")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."semantic_checkpoint" SET signature=%s '
            "WHERE singleton=1",
            (base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii"),),
        )
    request = _request(
        postgres_environment,
        commit_id="checkpoint-bad-signature",
        nonce_byte=129,
    )
    stage = getattr(postgres_environment.modules.support, "_stage_request")(request)

    with pytest.raises(ValueError, match="semantic checkpoint validation failed"):
        store.stage_result(stage)
    with pytest.raises(ValueError, match="semantic checkpoint validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_checkpoint_seal_failure_rolls_back_mutation(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_seal_rollback")
    sqlite_module = importlib.import_module("constitutional_swarm.apcc.sqlite_store")
    checkpoint_domain = getattr(sqlite_module, "_SEMANTIC_CHECKPOINT_DOMAIN")
    assert isinstance(checkpoint_domain, bytes)
    provider_type = type(_runtime(postgres_environment).key_provider)
    original_sign = cast(
        "Callable[[object, AuthoritySigningRole, str, bytes, bytes], Signature]",
        getattr(provider_type, "sign"),
    )

    def fail_checkpoint_seal(
        instance: object,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        if role is AuthoritySigningRole.COMMIT and domain == checkpoint_domain:
            raise RuntimeError("injected PostgreSQL checkpoint seal failure")
        return original_sign(instance, role, key_id, domain, canonical_body)

    monkeypatch.setattr(provider_type, "sign", fail_checkpoint_seal)
    request = _request(
        postgres_environment,
        commit_id="checkpoint-seal-rollback",
        nonce_byte=130,
    )
    before = _snapshot(postgres_environment, store)
    before_checkpoint = _checkpoint_row(postgres_environment, schema)

    with pytest.raises(RuntimeError, match="checkpoint seal failure"):
        store.stage_result(
            getattr(postgres_environment.modules.support, "_stage_request")(request)
        )

    assert _snapshot(postgres_environment, store) == before
    assert _checkpoint_row(postgres_environment, schema) == before_checkpoint


def test_postgres_reopen_full_scan_rejects_tamper_with_replayed_checkpoint(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "checkpoint_replay_reopen")
    request = _request(
        postgres_environment,
        commit_id="checkpoint-replay-reopen",
        nonce_byte=131,
    )
    _advance(postgres_environment, store, request)
    store.atomic_commit(request)
    checkpoint = _checkpoint_row(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
        connection.execute(
            f'UPDATE "{schema}"."semantic_checkpoint" SET change_sequence=%s,'
            "prior_digest=%s,checkpoint_digest=%s,key_id=%s,signature=%s "
            "WHERE singleton=1",
            checkpoint,
        )

    with pytest.raises(ValueError, match="semantic validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
    with pytest.raises(ValueError, match="semantic validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


def test_postgres_status_batch_observes_one_pre_revocation_snapshot(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _single_store(postgres_environment, "status_batch_revocation_snapshot")
    request = _request(
        postgres_environment,
        commit_id="status-batch-revocation-snapshot",
        nonce_byte=132,
    )
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    status_requests = tuple(
        CurrentStatusRequest(committed.certificate_digest, _nonce(index))
        for index in range(1, 101)
    )
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    connection_type = getattr(store_module, "_Connection")
    original_execute = cast(
        "Callable[[object, str, tuple[object, ...]], _Cursor]",
        connection_type.execute,
    )
    main_thread = threading.get_ident()
    snapshot_established = threading.Event()
    release = threading.Event()
    armed = True
    gate = threading.Lock()

    def execute_with_barrier(
        connection: object,
        query: str,
        parameters: tuple[object, ...] = (),
    ) -> _Cursor:
        nonlocal armed
        cursor = original_execute(connection, query, parameters)
        if threading.get_ident() != main_thread and query.startswith(
            "SELECT change_sequence,prior_digest,checkpoint_digest"
        ):
            with gate:
                should_pause = armed
                armed = False
            if should_pause:
                snapshot_established.set()
                if not release.wait(timeout=10):
                    raise TimeoutError("status batch snapshot barrier was not released")
        return cursor

    monkeypatch.setattr(connection_type, "execute", execute_with_barrier)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.current_status_batch, status_requests)
        if not snapshot_established.wait(timeout=10):
            release.set()
            future.result(timeout=1)
            pytest.fail("status batch did not establish its repeatable-read snapshot")
        try:
            revoked = store.revoke(
                RevocationRequest(
                    RevocationScope.CERTIFICATE,
                    request.subject.workflow_id,
                    committed.certificate_digest,
                    "1",
                    "deterministic batch snapshot race",
                )
            )
            assert revoked.resulting_generation == "1"
        finally:
            release.set()
        results = future.result(timeout=10)

    assert tuple(result.request for result in results) == status_requests
    assert {result.status.status for result in results} == {
        AuthorityStatusValue.CURRENT
    }
    assert len({result.status.trust_log_sequence for result in results}) == 1
    assert len({result.status.trust_log_head for result in results}) == 1
    assert (
        store.current_status(committed.certificate_digest, _nonce(101)).status
        is AuthorityStatusValue.REVOKED
    )


def test_postgres_dirty_checkpoint_rejects_whole_status_batch_before_signing(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "status_batch_dirty")
    committed_request = _request(
        postgres_environment,
        commit_id="status-batch-dirty-committed",
        nonce_byte=133,
    )
    _advance(postgres_environment, store, committed_request)
    committed = store.atomic_commit(committed_request)
    assert committed.certificate_digest is not None
    corrupt = _request(
        postgres_environment,
        commit_id="status-batch-dirty-unrelated",
        nonce_byte=134,
        workflow_id="workflow-2",
    )
    store.stage_result(
        getattr(postgres_environment.modules.support, "_stage_request")(corrupt)
    )
    _corrupt_candidate_proposal_digest(postgres_environment, schema, corrupt)
    requests = tuple(
        CurrentStatusRequest(committed.certificate_digest, _nonce(index))
        for index in range(1, 101)
    )
    provider_type = type(_runtime(postgres_environment).key_provider)
    status_signature_count = cast(
        "Callable[[], int]", getattr(provider_type, "status_signature_count")
    )
    before_signatures = status_signature_count()
    before = _snapshot(postgres_environment, store)

    with pytest.raises(ValueError, match="semantic checkpoint validation failed"):
        store.current_status_batch(requests)

    assert status_signature_count() == before_signatures
    assert _snapshot(postgres_environment, store) == before


def test_postgres_status_signer_failure_returns_no_partial_batch(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, store = _single_store(postgres_environment, "status_batch_signer_failure")
    request = _request(
        postgres_environment,
        commit_id="status-batch-signer-failure",
        nonce_byte=135,
    )
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    requests = tuple(
        CurrentStatusRequest(committed.certificate_digest, _nonce(index))
        for index in range(1, 101)
    )
    provider_type = type(_runtime(postgres_environment).key_provider)
    original_sign = cast(
        "Callable[[object, AuthoritySigningRole, str, bytes, bytes], Signature]",
        getattr(provider_type, "sign"),
    )
    status_calls = 0

    def fail_one_status_signature(
        instance: object,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        nonlocal status_calls
        if role is AuthoritySigningRole.STATUS:
            status_calls += 1
            if status_calls == 37:
                raise RuntimeError("injected PostgreSQL status signer failure")
        return original_sign(instance, role, key_id, domain, canonical_body)

    monkeypatch.setattr(provider_type, "sign", fail_one_status_signature)
    before = _snapshot(postgres_environment, store)
    before_checkpoint = _checkpoint_row(postgres_environment, schema)

    with pytest.raises(RuntimeError, match="status signer failure"):
        store.current_status_batch(requests)

    assert status_calls == 37
    assert _snapshot(postgres_environment, store) == before
    assert _checkpoint_row(postgres_environment, schema) == before_checkpoint


def test_postgres_logical_status_batch_preserves_order_and_duplicate_nodes(
    postgres_environment: _PostgresEnvironment,
) -> None:
    _, store = _single_store(postgres_environment, "logical_status_batch_order")
    request = _request(
        postgres_environment,
        commit_id="logical-status-batch-order",
        nonce_byte=136,
    )
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    assert committed.certificate_digest is not None
    requests = (
        LogicalNodeStatusRequest("workflow-1", "node-1", _nonce(1)),
        LogicalNodeStatusRequest("workflow-1", "missing", _nonce(2)),
        LogicalNodeStatusRequest("workflow-1", "node-1", _nonce(3)),
    )

    results = store.logical_node_status_batch(requests)

    assert tuple(result.request for result in results) == requests
    assert (
        results[0].logical_node.current_certificate_digest
        == committed.certificate_digest
    )
    assert results[0].commit_id == request.commit_id
    assert results[0].status is not None
    assert results[1].logical_node.current_node_version == "0"
    assert results[1].commit_id is None
    assert results[1].status is None
    assert results[2].status is not None
    assert results[0].status.request_nonce != results[2].status.request_nonce


def test_postgres_batch_rejects_duplicate_nonce_before_opening_transaction(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _single_store(postgres_environment, "logical_status_batch_duplicate")
    opened = False

    def forbidden_connection() -> _Connection:
        nonlocal opened
        opened = True
        raise AssertionError("transaction opened before batch validation")

    monkeypatch.setattr(store, "_connection", forbidden_connection)
    duplicate = (
        LogicalNodeStatusRequest("workflow-1", "node-1", _nonce(1)),
        LogicalNodeStatusRequest("workflow-1", "node-2", _nonce(1)),
    )

    with pytest.raises(ValueError, match="duplicate"):
        store.logical_node_status_batch(duplicate)
    assert opened is False


def test_postgres_concurrent_writers_leave_one_valid_signed_checkpoint(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, setup = _single_store(postgres_environment, "checkpoint_concurrent_writers")
    requests = (
        _request(
            postgres_environment,
            commit_id="checkpoint-concurrent-left",
            nonce_byte=137,
        ),
        _request(
            postgres_environment,
            commit_id="checkpoint-concurrent-right",
            nonce_byte=138,
            workflow_id="workflow-2",
        ),
    )
    for request in requests:
        _advance(postgres_environment, setup, request)
    stores = tuple(
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        for _ in requests
    )
    barrier = threading.Barrier(2)

    def commit(index: int) -> CommitResult:
        barrier.wait()
        return stores[index].atomic_commit(requests[index])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(commit, range(2)))

    assert all(
        result.decision.outcome is RequestOutcome.COMMITTED for result in results
    )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()
    postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
    ).close()


@pytest.mark.parametrize("tamper", ("index", "constraint", "column", "fingerprint"))
def test_postgres_reader_and_writer_open_reject_structural_schema_tamper(
    postgres_environment: _PostgresEnvironment, tamper: str
) -> None:
    schema, _ = _single_store(postgres_environment, f"schema_tamper_{tamper}")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if tamper == "index":
            connection.execute(f'DROP INDEX "{schema}"."idx_apcc_outbox_head"')
        elif tamper == "constraint":
            connection.execute(
                f'ALTER TABLE "{schema}"."outbox" DROP CONSTRAINT outbox_state_shape'
            )
        elif tamper == "column":
            connection.execute(
                f'ALTER TABLE "{schema}"."candidates" ADD COLUMN injected TEXT'
            )
        else:
            connection.execute(
                f'UPDATE "{schema}"."metadata" SET value=\'wrong\' '
                "WHERE key='schema_fingerprint'"
            )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


@pytest.mark.parametrize(
    "attack",
    (
        "rule_also",
        "rule_instead",
        "internal_ri_trigger",
        "view",
        "materialized_view",
        "sequence",
        "composite_type",
        "domain",
        "policy",
        "default_acl",
        "role_setting",
    ),
)
def test_postgres_open_rejects_hidden_catalog_and_acl_attacks(
    postgres_environment: _PostgresEnvironment,
    attack: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"catalog_attack_{attack}")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if attack == "rule_also":
            connection.execute(
                f'CREATE RULE injected_rule_also AS ON UPDATE TO "{schema}"."candidates" '
                "DO ALSO NOTIFY apcc_injected"
            )
        elif attack == "rule_instead":
            connection.execute(
                f"CREATE RULE injected_rule_instead AS ON DELETE TO "
                f'"{schema}"."audit_events" DO INSTEAD NOTHING'
            )
        elif attack == "internal_ri_trigger":
            row = connection.execute(
                "SELECT t.tgname,c.relname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid=t.tgrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=%s AND t.tgisinternal ORDER BY t.tgname LIMIT 1",
                (schema,),
            ).fetchone()
            assert row is not None
            trigger_name, table_name = map(str, row)
            connection.execute(
                f'ALTER TABLE "{schema}"."{table_name}" '
                f'DISABLE TRIGGER "{trigger_name}"'
            )
        elif attack == "view":
            connection.execute(
                f'CREATE VIEW "{schema}"."injected_view" AS SELECT 1 AS value'
            )
        elif attack == "materialized_view":
            connection.execute(
                f'CREATE MATERIALIZED VIEW "{schema}"."injected_matview" '
                "AS SELECT 1 AS value"
            )
        elif attack == "sequence":
            connection.execute(f'CREATE SEQUENCE "{schema}"."injected_sequence"')
        elif attack == "composite_type":
            connection.execute(
                f'CREATE TYPE "{schema}"."injected_composite" AS (value TEXT)'
            )
        elif attack == "domain":
            connection.execute(f'CREATE DOMAIN "{schema}"."injected_domain" AS TEXT')
        elif attack == "policy":
            connection.execute(
                f'CREATE POLICY injected_policy ON "{schema}"."candidates" USING (true)'
            )
        elif attack == "default_acl":
            connection.execute(
                f"ALTER DEFAULT PRIVILEGES FOR ROLE "
                f'"{postgres_environment.owner_role}" IN SCHEMA "{schema}" '
                "GRANT SELECT ON TABLES TO PUBLIC"
            )
        else:
            connection.execute(
                f'ALTER ROLE "{postgres_environment.runtime_role}" '
                "IN DATABASE apcc_test SET search_path=pg_catalog"
            )

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


def test_postgres_catalog_manifest_covers_security_sensitive_pg17_surfaces() -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    source = inspect.getsource(getattr(store_module, "_catalog_manifest"))

    for catalog in (
        "pg_rewrite",
        "pg_default_acl",
        "pg_db_role_setting",
        "pg_policy",
        "pg_type",
        "pg_operator",
        "pg_cast",
        "pg_collation",
        "pg_extension",
        "pg_depend",
        "pg_shdepend",
        "pg_inherits",
        "pg_partitioned_table",
        "pg_opfamily",
        "pg_opclass",
        "pg_amop",
        "pg_amproc",
        "pg_conversion",
        "pg_ts_config",
        "pg_statistic_ext",
        "pg_event_trigger",
    ):
        assert catalog in source
    assert "CASE WHEN t.tgisinternal THEN '<internal>'" in source
    assert "coalesce(k.conname,'')" in source
    assert "_validate_foreign_key_integrity(connection, schema)" in inspect.getsource(
        getattr(store_module, "_semantic_config")
    )


def test_postgres_catalog_normalization_preserves_distinct_literal_material() -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    normalize = getattr(store_module, "_normalize_catalog_text")

    assert normalize("SELECT 'A  B'", "s", "o", "r", "v") == "SELECT 'A  B'"
    assert normalize("SELECT 'A B'", "s", "o", "r", "v") == "SELECT 'A B'"


@pytest.mark.parametrize("version", (170000, "170000", 179999, "179999"))
def test_postgres_catalog_accepts_only_supported_pg17_version_values(
    version: object,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")

    assert getattr(store_module, "_validate_server_version_num")(version) is None


@pytest.mark.parametrize(
    "version", (169999, 180000, None, "", True, "seventeen", object())
)
def test_postgres_catalog_rejects_unsupported_or_malformed_version_values(
    version: object,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")

    with pytest.raises(ValueError, match="requires PostgreSQL 17"):
        getattr(store_module, "_validate_server_version_num")(version)


def test_postgres_catalog_show_version_error_fails_closed_without_later_query() -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")

    class FailingVersionConnection:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def execute(
            self, query: object, _parameters: tuple[object, ...] = ()
        ) -> object:
            self.queries.append(str(query))
            raise RuntimeError("injected SHOW failure")

    connection = FailingVersionConnection()
    with pytest.raises(ValueError, match="catalog version validation failed"):
        getattr(store_module, "_catalog_manifest")(
            connection,
            "authority_schema",
            "authority_owner",
            "authority_runtime",
            "authority_observer",
        )
    assert connection.queries == ["SHOW server_version_num"]


def test_postgres_catalog_normalization_only_rewrites_sql_identifiers() -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    normalize = getattr(store_module, "_normalize_catalog_text")
    schema = "identity_scope"
    owner = "identity_scope_owner"
    runtime = "identity_scope_runtime"
    observer = "identity_scope_observer"
    definition = (
        "SELECT identity_scope.metadata, 'identity_scope', "
        "$body$identity_scope identity_scope_owner$body$ "
        "-- identity_scope_runtime\n"
        "/* identity_scope_observer /* identity_scope_owner */ "
        "identity_scope_runtime */ identity_scope_owner.value"
    )

    assert normalize(definition, schema, owner, runtime, observer) == (
        "SELECT <schema>.metadata, 'identity_scope', "
        "$body$identity_scope identity_scope_owner$body$ "
        "-- identity_scope_runtime\n"
        "/* identity_scope_observer /* identity_scope_owner */ "
        "identity_scope_runtime */ <owner>.value"
    )
    assert (
        normalize(
            "identity_scope_ownerish identity_scope_owner",
            schema,
            owner,
            runtime,
            observer,
        )
        == "identity_scope_ownerish <owner>"
    )
    assert (
        normalize(
            "SELECT '<schema>', '<owner>', '<runtime>', '<observer>'",
            schema,
            owner,
            runtime,
            observer,
        )
        == "SELECT '<schema>', '<owner>', '<runtime>', '<observer>'"
    )


def test_postgres_manifest_preserves_function_source_and_orders_policy_roles(
    postgres_environment: _PostgresEnvironment,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    schema, _ = _single_store(postgres_environment, "typed_manifest")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{schema}"."literal_identity_material"() '
            "RETURNS TEXT LANGUAGE sql AS $function$ SELECT "
            f"'{schema} {postgres_environment.owner_role} <schema>' "
            "$function$"
        )
        connection.execute(
            f'CREATE POLICY "symbolic_roles" ON "{schema}"."candidates" TO '
            f'"{postgres_environment.runtime_role}",'
            f'"{postgres_environment.observer_role}" USING (true)'
        )
        connection.execute("RESET ROLE")
        connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
        manifest = getattr(store_module, "_catalog_manifest")(
            getattr(store_module, "_Connection")(connection),
            schema,
            postgres_environment.owner_role,
            postgres_environment.runtime_role,
            postgres_environment.observer_role,
        )

    function_row = next(
        row for row in manifest["functions"] if row[0] == "literal_identity_material"
    )
    assert function_row[10] == (
        f" SELECT '{schema} {postgres_environment.owner_role} <schema>' "
    )
    policy_row = next(row for row in manifest["policies"] if row[1] == "symbolic_roles")
    assert policy_row[4] == "<observer>,<runtime>"


@pytest.mark.parametrize("grantee", ("observer", "PUBLIC"))
def test_postgres_open_rejects_external_updatable_view_column_write_capability(
    postgres_environment: _PostgresEnvironment,
    grantee: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"external_view_capability_{grantee.lower()}"
    )
    external_schema = postgres_environment.schema(
        f"external_capability_scope_{grantee.lower()}"
    )
    grantee_sql = (
        f'"{postgres_environment.observer_role}"' if grantee == "observer" else "PUBLIC"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."metadata_write_path" AS '
            f'SELECT key,value FROM "{schema}"."metadata"'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO {grantee_sql}'
        )
        connection.execute(
            f"GRANT INSERT(key,value),UPDATE(value) ON "
            f'"{external_schema}"."metadata_write_path" TO {grantee_sql}'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn
    ) as connection:
        raw_insert = connection.execute(
            f'INSERT INTO "{external_schema}"."metadata_write_path" VALUES '
            "('external-capability-proof','reachable')"
        )
        assert getattr(raw_insert, "rowcount", None) == 1
        connection.rollback()

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_external_select_only_and_unrelated_write_paths_are_isolated(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "external_capability_isolation")
    external_schema = postgres_environment.schema("external_capability_isolation_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."protected_read_path" AS '
            f'SELECT key,value FROM "{schema}"."metadata"'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."unrelated" '
            "(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."unrelated_write_path" AS '
            f'SELECT key,value FROM "{external_schema}"."unrelated"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."protected_read_path" '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f"GRANT INSERT(key,value),UPDATE(value) ON "
            f'"{external_schema}"."unrelated_write_path" '
            f'TO "{postgres_environment.observer_role}"'
        )

    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_open_rejects_recursive_external_view_write_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "recursive_external_view")
    external_schema = postgres_environment.schema("recursive_external_view_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."view_a" AS '
            f'SELECT key,value FROM "{schema}"."metadata"'
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."view_b" AS '
            f'SELECT key,value FROM "{external_schema}"."view_a"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT UPDATE(value) ON "{external_schema}"."view_b" '
            f'TO "{postgres_environment.observer_role}"'
        )

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    ("trigger_shape", "grantee", "function_owner"),
    (
        ("before_row", "observer", "authority_owner"),
        ("after_statement_transition", "observer", "admin"),
        ("deferred_constraint", "observer", "authority_owner"),
        ("partition_leaf", "PUBLIC", "admin"),
    ),
)
def test_postgres_open_rejects_trigger_mediated_external_write_capability(
    postgres_environment: _PostgresEnvironment,
    trigger_shape: str,
    grantee: str,
    function_owner: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"external_trigger_{trigger_shape}_{grantee.lower()}"
    )
    external_schema = postgres_environment.schema(
        f"external_trigger_scope_{trigger_shape}_{grantee.lower()}"
    )
    grantee_sql = (
        f'"{postgres_environment.observer_role}"' if grantee == "observer" else "PUBLIC"
    )
    proof_key = f"trigger-proof-{trigger_shape}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if trigger_shape == "partition_leaf":
            connection.execute(
                f'CREATE TABLE "{external_schema}"."write_parent" (id BIGINT) '
                "PARTITION BY RANGE (id)"
            )
            connection.execute(
                f'CREATE TABLE "{external_schema}"."write_leaf" PARTITION OF '
                f'"{external_schema}"."write_parent" FOR VALUES FROM (0) TO (100)'
            )
            trigger_table = "write_leaf"
            write_table = "write_parent"
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."write_target" (id BIGINT)'
            )
            trigger_table = "write_target"
            write_table = "write_target"
        connection.execute("RESET ROLE")
        if function_owner == "authority_owner":
            connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."trigger_rewrite"() '
            "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $function$ "
            "BEGIN EXECUTE $dynamic$INSERT INTO "
            f'"{schema}"."metadata"(key,value) VALUES '
            f"('{proof_key}','reachable') ON CONFLICT(key) DO UPDATE "
            "SET value=excluded.value$dynamic$; RETURN NEW; END $function$"
        )
        if function_owner == "authority_owner":
            connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."trigger_rewrite"() '
            "FROM PUBLIC"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."trigger_rewrite"() '
            f'FROM "{postgres_environment.runtime_role}",'
            f'"{postgres_environment.observer_role}"'
        )
        if trigger_shape == "before_row" or trigger_shape == "partition_leaf":
            trigger_sql = (
                f'CREATE TRIGGER "external_trigger" BEFORE INSERT ON '
                f'"{external_schema}"."{trigger_table}" FOR EACH ROW EXECUTE '
                f'FUNCTION "{external_schema}"."trigger_rewrite"()'
            )
        elif trigger_shape == "after_statement_transition":
            trigger_sql = (
                f'CREATE TRIGGER "external_trigger" AFTER INSERT ON '
                f'"{external_schema}"."{trigger_table}" REFERENCING NEW TABLE AS '
                "inserted_rows FOR EACH STATEMENT EXECUTE FUNCTION "
                f'"{external_schema}"."trigger_rewrite"()'
            )
        else:
            trigger_sql = (
                f'CREATE CONSTRAINT TRIGGER "external_trigger" AFTER INSERT ON '
                f'"{external_schema}"."{trigger_table}" DEFERRABLE INITIALLY '
                "DEFERRED FOR EACH ROW EXECUTE FUNCTION "
                f'"{external_schema}"."trigger_rewrite"()'
            )
        connection.execute(trigger_sql)
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO {grantee_sql}'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."{write_table}" TO {grantee_sql}'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."{write_table}" VALUES (1)'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("benign_shape", ("disabled", "not_writable", "replica_only"))
def test_postgres_external_trigger_without_effective_capability_is_accepted(
    postgres_environment: _PostgresEnvironment,
    benign_shape: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"benign_trigger_{benign_shape}")
    external_schema = postgres_environment.schema(
        f"benign_trigger_{benign_shape}_scope"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."write_target" (id BIGINT)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."benign_trigger"() '
            "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $function$ "
            "BEGIN RETURN NEW; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."benign_trigger"() FROM PUBLIC'
        )
        connection.execute(
            f'CREATE TRIGGER "benign_trigger" BEFORE INSERT ON '
            f'"{external_schema}"."write_target" FOR EACH ROW EXECUTE FUNCTION '
            f'"{external_schema}"."benign_trigger"()'
        )
        if benign_shape == "disabled":
            connection.execute(
                f'ALTER TABLE "{external_schema}"."write_target" '
                'DISABLE TRIGGER "benign_trigger"'
            )
            connection.execute(
                f'GRANT USAGE ON SCHEMA "{external_schema}" '
                f'TO "{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT INSERT ON "{external_schema}"."write_target" '
                f'TO "{postgres_environment.observer_role}"'
            )
        elif benign_shape == "replica_only":
            connection.execute(
                f'ALTER TABLE "{external_schema}"."write_target" '
                'ENABLE REPLICA TRIGGER "benign_trigger"'
            )
            connection.execute(
                f'GRANT USAGE ON SCHEMA "{external_schema}" '
                f'TO "{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT INSERT ON "{external_schema}"."write_target" '
                f'TO "{postgres_environment.observer_role}"'
            )

    if benign_shape == "replica_only":
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            connection.execute(
                f'INSERT INTO "{external_schema}"."write_target" VALUES (1)'
            )

    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("edge_direction", ("external_child", "external_parent"))
def test_postgres_open_rejects_cross_boundary_inheritance_in_both_directions(
    postgres_environment: _PostgresEnvironment,
    edge_direction: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"inheritance_{edge_direction}")
    external_schema = postgres_environment.schema(f"inheritance_{edge_direction}_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if edge_direction == "external_child":
            connection.execute(
                f'CREATE TABLE "{external_schema}"."metadata_child" () '
                f'INHERITS ("{schema}"."metadata")'
            )
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."metadata_parent" '
                "(key TEXT, value TEXT)"
            )
            connection.execute(
                f'ALTER TABLE "{schema}"."metadata" INHERIT '
                f'"{external_schema}"."metadata_parent"'
            )
        connection.execute("RESET ROLE")

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("edge_direction", ("external_leaf", "external_parent"))
def test_postgres_open_rejects_cross_boundary_partitions_in_both_directions(
    postgres_environment: _PostgresEnvironment,
    edge_direction: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"partition_{edge_direction}")
    external_schema = postgres_environment.schema(f"partition_{edge_direction}_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if edge_direction == "external_leaf":
            connection.execute(
                f'CREATE TABLE "{schema}"."protected_partition_parent" '
                "(id BIGINT) PARTITION BY RANGE (id)"
            )
            connection.execute(
                f'CREATE TABLE "{external_schema}"."external_leaf" PARTITION OF '
                f'"{schema}"."protected_partition_parent" '
                "FOR VALUES FROM (0) TO (100)"
            )
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."external_partition_parent" '
                "(id BIGINT) PARTITION BY RANGE (id)"
            )
            connection.execute(
                f'CREATE TABLE "{schema}"."protected_leaf" PARTITION OF '
                f'"{external_schema}"."external_partition_parent" '
                "FOR VALUES FROM (0) TO (100)"
            )
        connection.execute("RESET ROLE")

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_catalog_array_serialization_rejects_delimiter_collisions() -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    join_catalog_array = getattr(store_module, "_join_catalog_array")

    assert join_catalog_array(["alpha", "beta"]) == "alpha,beta"
    with pytest.raises(ValueError, match="ambiguous PostgreSQL catalog array"):
        join_catalog_array([""])
    with pytest.raises(ValueError, match="ambiguous PostgreSQL catalog array"):
        join_catalog_array(["alpha,beta"])
    with pytest.raises(ValueError, match="ambiguous PostgreSQL catalog array"):
        join_catalog_array(["alpha", "beta"], allow_single_delimited=True)


def test_postgres_policy_role_serialization_rejects_comma_role_collision(
    postgres_environment: _PostgresEnvironment,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    schema, _ = _single_store(postgres_environment, "policy_role_collision")
    comma_role = f"{postgres_environment.schema_prefix}_comma,role"
    assert len(comma_role) <= 63
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE ROLE "{comma_role}" NOLOGIN NOINHERIT NOSUPERUSER '
            "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE POLICY "comma_role" ON "{schema}"."candidates" '
            f'TO "{comma_role}" USING (true)'
        )
        connection.execute("RESET ROLE")
        connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
        try:
            with pytest.raises(ValueError, match="ambiguous PostgreSQL catalog array"):
                getattr(store_module, "_catalog_manifest")(
                    getattr(store_module, "_Connection")(connection),
                    schema,
                    postgres_environment.owner_role,
                    postgres_environment.runtime_role,
                    postgres_environment.observer_role,
                )
        finally:
            connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
            connection.execute(f'DROP POLICY "comma_role" ON "{schema}"."candidates"')
            connection.execute("RESET ROLE")
            connection.execute(f'DROP ROLE "{comma_role}"')


@pytest.mark.parametrize(
    "definition", ("SELECT 'unterminated", "SELECT $body$unterminated", "/* nested")
)
def test_postgres_catalog_normalization_rejects_unterminated_lexer_states(
    definition: str,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")

    with pytest.raises(ValueError, match="unterminated PostgreSQL catalog text"):
        getattr(store_module, "_normalize_catalog_text")(
            definition, "schema", "owner", "runtime", "observer"
        )


def test_postgres_dependency_identity_validation_rejects_description_collision() -> (
    None
):
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    rows: list[tuple[object, ...]] = [
        (
            "pg_class",
            "pg_namespace",
            "n",
            "table schema.target",
            "schema schema",
            "table",
            ["schema", "target"],
            [],
            "schema",
            ["schema"],
            [],
        ),
        (
            "pg_class",
            "pg_namespace",
            "n",
            "table schema.target",
            "schema schema",
            "table",
            ["schema", "different_target"],
            [],
            "schema",
            ["schema"],
            [],
        ),
    ]

    with pytest.raises(ValueError, match="dependency identity collision"):
        getattr(store_module, "_validate_dependency_identity_rows")(
            rows, "schema", "owner", "runtime", "observer"
        )


@pytest.mark.parametrize(
    ("owner", "grantee"), (("authority_owner", "observer"), ("admin", "PUBLIC"))
)
def test_postgres_open_rejects_external_security_definer_write_capability(
    postgres_environment: _PostgresEnvironment,
    owner: str,
    grantee: str,
) -> None:
    schema, _ = _single_store(postgres_environment, "external_security_definer")
    external_schema = postgres_environment.schema("external_security_definer_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if owner == "authority_owner":
            connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."rewrite_metadata"() '
            "RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $function$ "
            f'BEGIN UPDATE "{schema}"."metadata" SET value=value; END '
            "$function$"
        )
        if owner == "authority_owner":
            connection.execute("RESET ROLE")
        grantee_sql = (
            f'"{postgres_environment.observer_role}"'
            if grantee == "observer"
            else "PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO {grantee_sql}'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."rewrite_metadata"() '
            f"TO {grantee_sql}"
        )

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    "tamper",
    (
        "replica_identity_full",
        "replica_identity_nothing",
        "replica_identity_index",
        "publication_direct",
        "publication_schema",
        "publication_all",
    ),
)
def test_postgres_open_rejects_logical_replication_catalog_state(
    postgres_environment: _PostgresEnvironment,
    tamper: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"replication_{tamper}")
    publication = f"{postgres_environment.schema_prefix}_publication"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if tamper == "replica_identity_full":
            connection.execute(
                f'ALTER TABLE "{schema}"."metadata" REPLICA IDENTITY FULL'
            )
        elif tamper == "replica_identity_nothing":
            connection.execute(
                f'ALTER TABLE "{schema}"."metadata" REPLICA IDENTITY NOTHING'
            )
        elif tamper == "replica_identity_index":
            connection.execute(
                f'ALTER TABLE "{schema}"."metadata" REPLICA IDENTITY USING INDEX '
                '"metadata_pkey"'
            )
        elif tamper == "publication_direct":
            connection.execute(
                f'CREATE PUBLICATION "{publication}" FOR TABLE "{schema}"."metadata"'
            )
        elif tamper == "publication_schema":
            connection.execute(
                f'CREATE PUBLICATION "{publication}" FOR TABLES IN SCHEMA "{schema}"'
            )
        else:
            connection.execute(f'CREATE PUBLICATION "{publication}" FOR ALL TABLES')
    try:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    finally:
        if tamper.startswith("publication_"):
            with postgres_environment.modules.psycopg.connect(
                postgres_environment.dsn, autocommit=True
            ) as connection:
                connection.execute(f'DROP PUBLICATION "{publication}"')


@pytest.mark.parametrize("independent_fixture", (1, 2))
@pytest.mark.parametrize("catalog_profile", ("base", "gcb"))
def test_postgres_fresh_base_and_gcb_catalog_fingerprints_are_deterministic(
    postgres_environment: _PostgresEnvironment,
    independent_fixture: int,
    catalog_profile: str,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        role_rows = connection.execute(
            "SELECT rolname,oid FROM pg_roles WHERE rolname IN (%s,%s,%s) "
            "ORDER BY rolname",
            (
                postgres_environment.owner_role,
                postgres_environment.runtime_role,
                postgres_environment.observer_role,
            ),
        ).fetchall()
        assert {row[0] for row in role_rows} == {
            postgres_environment.owner_role,
            postgres_environment.runtime_role,
            postgres_environment.observer_role,
        }
        assert len({row[1] for row in role_rows}) == 3
        if independent_fixture == 2:
            filler_role = f"{postgres_environment.schema_prefix}_filler"
            filler_schema = postgres_environment.schema("deterministic_filler")
            connection.execute(f'CREATE ROLE "{filler_role}" NOLOGIN')
            try:
                connection.execute(
                    f'CREATE TABLE "{filler_schema}"."oid_history" (id BIGINT)'
                )
                connection.execute(f'DROP SCHEMA "{filler_schema}" CASCADE')
            finally:
                connection.execute(f'DROP ROLE "{filler_role}"')
    if catalog_profile == "base":
        schema, _ = _single_store(
            postgres_environment, f"deterministic_base_{independent_fixture}"
        )
        expected = getattr(store_module, "_POSTGRES_CATALOG_FINGERPRINT")
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
    else:
        schema, config, runtime = _provision_gcb_profile(
            postgres_environment, f"deterministic_gcb_{independent_fixture}"
        )
        expected = getattr(store_module, "_POSTGRES_GCB_CATALOG_FINGERPRINT")
        _open_gcb_profile(postgres_environment, schema, config, runtime).close()
    catalog_fingerprint = getattr(store_module, "_catalog_fingerprint")
    wrapped_connection = getattr(store_module, "_Connection")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        wrapped = wrapped_connection(connection)
        connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
        assert (
            catalog_fingerprint(
                wrapped,
                schema,
                postgres_environment.owner_role,
                postgres_environment.runtime_role,
                postgres_environment.observer_role,
            )
            == expected
        )


def test_postgres_catalog_fingerprints_ignore_distinct_role_names_and_oid_history(
    postgres_environment: _PostgresEnvironment,
) -> None:
    modules = postgres_environment.modules
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    second_token = secrets.token_hex(12)
    second_prefix = f"apcc_test_{second_token}"
    second_owner = f"{second_prefix}_owner"
    second_runtime = f"{second_prefix}_runtime"
    second_observer = f"{second_prefix}_observer"
    filler_roles = [f"{second_prefix}_filler_{index}" for index in range(3)]
    for role in (second_owner, second_runtime, second_observer):
        _validate_owned_role(role)
    assert all(
        re.fullmatch(rf"{re.escape(second_prefix)}_filler_[0-2]", role)
        for role in filler_roles
    )
    created_roles: list[str] = []
    second_environment: _PostgresEnvironment | None = None
    restore_first_observer_connect = False

    def manifest_for(
        environment: _PostgresEnvironment, schema: str
    ) -> dict[str, object]:
        with modules.psycopg.connect(environment.dsn, autocommit=True) as connection:
            connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
            return cast(
                "dict[str, object]",
                getattr(store_module, "_catalog_manifest")(
                    getattr(store_module, "_Connection")(connection),
                    schema,
                    environment.owner_role,
                    environment.runtime_role,
                    environment.observer_role,
                ),
            )

    def fingerprint_for(environment: _PostgresEnvironment, schema: str) -> str:
        with modules.psycopg.connect(environment.dsn, autocommit=True) as connection:
            connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
            return cast(
                "str",
                getattr(store_module, "_catalog_fingerprint")(
                    getattr(store_module, "_Connection")(connection),
                    schema,
                    environment.owner_role,
                    environment.runtime_role,
                    environment.observer_role,
                ),
            )

    try:
        first_base, first_store = _single_store(
            postgres_environment, "distinct_roles_base"
        )
        first_store.close()
        first_gcb, first_config, first_runtime = _provision_gcb_profile(
            postgres_environment, "distinct_roles_gcb"
        )
        _open_gcb_profile(
            postgres_environment, first_gcb, first_config, first_runtime
        ).close()
        first_base_manifest = manifest_for(postgres_environment, first_base)
        first_gcb_manifest = manifest_for(postgres_environment, first_gcb)
        first_base_fingerprint = fingerprint_for(postgres_environment, first_base)
        first_gcb_fingerprint = fingerprint_for(postgres_environment, first_gcb)

        with modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            filler_schema = postgres_environment.schema("distinct_roles_oid_filler")
            connection.execute(
                f'CREATE TABLE "{filler_schema}"."oid_history" (id BIGINT)'
            )
            connection.execute(f'DROP SCHEMA "{filler_schema}" CASCADE')
            for filler_role in filler_roles:
                connection.execute(f'CREATE ROLE "{filler_role}" NOLOGIN')
                connection.execute(f'DROP ROLE "{filler_role}"')
            database = connection.execute("SELECT current_database()").fetchone()
            assert database is not None and isinstance(database[0], str)
            quoted_database = '"' + database[0].replace('"', '""') + '"'
            connection.execute(
                f"REVOKE ALL ON DATABASE {quoted_database} FROM "
                f'"{postgres_environment.observer_role}"'
            )
            restore_first_observer_connect = True
            for role, login in (
                (second_observer, True),
                (second_owner, False),
                (second_runtime, True),
            ):
                connection.execute(
                    f'CREATE ROLE "{role}" '
                    f"{'LOGIN' if login else 'NOLOGIN'} NOINHERIT NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                created_roles.append(role)
                connection.execute(
                    f'COMMENT ON ROLE "{role}" IS '
                    f"'{_schema_owner_comment(second_token)}'"
                )
            connection.execute(
                f'REVOKE ALL ON DATABASE {quoted_database} FROM "{second_observer}"'
            )
            connection.execute(
                f'GRANT CONNECT ON DATABASE {quoted_database} TO "{second_observer}"'
            )

        second_environment = _PostgresEnvironment(
            postgres_environment.dsn,
            _runtime_dsn(postgres_environment.dsn, second_runtime),
            _runtime_dsn(postgres_environment.dsn, second_observer),
            second_prefix,
            second_token,
            second_owner,
            second_runtime,
            second_observer,
            modules,
        )
        second_base, second_store = _single_store(
            second_environment, "distinct_roles_base"
        )
        second_store.close()
        second_gcb, second_config, second_runtime_value = _provision_gcb_profile(
            second_environment, "distinct_roles_gcb"
        )
        _open_gcb_profile(
            second_environment, second_gcb, second_config, second_runtime_value
        ).close()

        with modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            role_rows = connection.execute(
                "SELECT rolname,oid FROM pg_roles WHERE rolname=ANY(%s)",
                (
                    [
                        postgres_environment.owner_role,
                        postgres_environment.runtime_role,
                        postgres_environment.observer_role,
                        second_owner,
                        second_runtime,
                        second_observer,
                    ],
                ),
            ).fetchall()
        assert len(role_rows) == 6
        assert len({row[0] for row in role_rows}) == 6
        assert len({row[1] for row in role_rows}) == 6

        second_base_manifest = manifest_for(second_environment, second_base)
        second_gcb_manifest = manifest_for(second_environment, second_gcb)
        assert first_base_manifest == second_base_manifest
        assert first_gcb_manifest == second_gcb_manifest
        assert first_base_fingerprint == getattr(
            store_module, "_POSTGRES_CATALOG_FINGERPRINT"
        )
        assert first_gcb_fingerprint == getattr(
            store_module, "_POSTGRES_GCB_CATALOG_FINGERPRINT"
        )
        for environment, schema, expected in (
            (
                second_environment,
                second_base,
                getattr(store_module, "_POSTGRES_CATALOG_FINGERPRINT"),
            ),
            (
                second_environment,
                second_gcb,
                getattr(store_module, "_POSTGRES_GCB_CATALOG_FINGERPRINT"),
            ),
        ):
            assert fingerprint_for(environment, schema) == expected
    finally:
        if second_environment is not None:
            with modules.psycopg.connect(
                postgres_environment.dsn, autocommit=True
            ) as connection:
                rows = connection.execute(
                    "SELECT schema_name FROM information_schema.schemata "
                    "WHERE schema_name LIKE %s",
                    (f"{second_prefix}_%",),
                ).fetchall()
                for (schema_name,) in rows:
                    assert isinstance(schema_name, str)
                    _validate_owned_schema(schema_name)
                    owner = connection.execute(
                        "SELECT obj_description(%s::regnamespace, 'pg_namespace')",
                        (schema_name,),
                    ).fetchone()
                    assert owner == (_schema_owner_comment(second_token),)
                    connection.execute(f'DROP SCHEMA "{schema_name}" CASCADE')
        with modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            database = connection.execute("SELECT current_database()").fetchone()
            assert database is not None and isinstance(database[0], str)
            quoted_database = '"' + database[0].replace('"', '""') + '"'
            for role in reversed(created_roles):
                comment = connection.execute(
                    "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles "
                    "WHERE rolname=%s",
                    (role,),
                ).fetchone()
                assert comment == (_schema_owner_comment(second_token),)
                connection.execute(
                    f'REVOKE ALL ON DATABASE {quoted_database} FROM "{role}"'
                )
                connection.execute(f'DROP ROLE "{role}"')
            if restore_first_observer_connect:
                connection.execute(
                    f"GRANT CONNECT ON DATABASE {quoted_database} TO "
                    f'"{postgres_environment.observer_role}"'
                )


def test_postgres_shadow_operator_cannot_suppress_dirty_sequence(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "shadow_operator")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        before = connection.execute(
            f'SELECT change_sequence FROM "{schema}"."semantic_checkpoint"'
        ).fetchone()
        assert before is not None and isinstance(before[0], int)
        connection.execute(
            f'CREATE FUNCTION "{schema}".shadow_add(BIGINT,INTEGER) '
            "RETURNS BIGINT LANGUAGE SQL IMMUTABLE AS 'SELECT $1'"
        )
        connection.execute(
            f'CREATE OPERATOR "{schema}".+ (LEFTARG=BIGINT,RIGHTARG=INTEGER,'
            f'FUNCTION="{schema}".shadow_add)'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        result = connection.execute(
            f'UPDATE "{schema}"."candidates" SET lifecycle=lifecycle'
        )
        rowcount = getattr(result, "rowcount", None)
        assert isinstance(rowcount, int) and rowcount > 0
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        after = connection.execute(
            f'SELECT change_sequence FROM "{schema}"."semantic_checkpoint"'
        ).fetchone()
    assert after == (before[0] + 1,)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_default_acl_updatable_view_rejects_observer_open_before_insert(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "default_acl_view")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'ALTER DEFAULT PRIVILEGES FOR ROLE "{postgres_environment.owner_role}" '
            f'IN SCHEMA "{schema}" GRANT INSERT ON TABLES '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE VIEW "{schema}"."observer_metadata_write" AS '
            f'SELECT key,value FROM "{schema}"."metadata"'
        )
        connection.execute("RESET ROLE")
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_fk_orphan_is_rejected_even_with_catalog_fingerprint_bypassed(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, _ = _single_store(postgres_environment, "independent_fk_integrity")
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        trigger = connection.execute(
            "SELECT t.tgname FROM pg_trigger t JOIN pg_constraint k "
            "ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND c.relname='evidence_refs' "
            "AND k.conname='evidence_refs_commit_id_fkey'",
            (schema,),
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute(
            f'ALTER TABLE "{schema}"."evidence_refs" DISABLE TRIGGER "{trigger[0]}"'
        )
        connection.execute(
            f'INSERT INTO "{schema}"."evidence_refs" VALUES '
            "('orphan','producer','policy','authority')"
        )
        wrapped = getattr(store_module, "_Connection")(connection)
        tampered_fingerprint = getattr(store_module, "_catalog_fingerprint")(
            wrapped,
            schema,
            postgres_environment.owner_role,
            postgres_environment.runtime_role,
            postgres_environment.observer_role,
        )
    monkeypatch.setattr(
        store_module, "_POSTGRES_CATALOG_FINGERPRINT", tampered_fingerprint
    )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_do_instead_rule_external_action_is_detected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "rule_instead_external")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        candidate_count = connection.execute(
            f'SELECT count(*) FROM "{schema}"."candidates"'
        ).fetchone()
        assert candidate_count is not None and isinstance(candidate_count[0], int)
        assert candidate_count[0] > 0
        connection.execute(
            f"CREATE RULE injected_external_action AS ON DELETE TO "
            f'"{schema}"."candidates" DO INSTEAD INSERT INTO '
            f'"{schema}"."audit_events" VALUES '
            "('injected-rule-event','{\"source\":\"rule\"}')"
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        result = connection.execute(f'DELETE FROM "{schema}"."candidates"')
        assert getattr(result, "rowcount", None) == 0
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert (
            connection.execute(
                f'SELECT count(*) FROM "{schema}"."candidates"'
            ).fetchone()
            == candidate_count
        )
        assert connection.execute(
            f'SELECT event_json FROM "{schema}"."audit_events" '
            "WHERE audit_event_id='injected-rule-event'"
        ).fetchone() == ('{"source":"rule"}',)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_all_authority_reads_revalidate_semantic_integrity(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "semantic_reads")
    request = _request(
        postgres_environment, commit_id="semantic-read-tamper", nonce_byte=117
    )
    _advance(postgres_environment, store, request)
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'UPDATE "{schema}"."candidates" SET proposal_digest=\'tampered\' '
            "WHERE workflow_id=%s AND node_id=%s AND attempt_id=%s",
            (
                request.subject.workflow_id,
                request.subject.node_id,
                request.subject.attempt_id,
            ),
        )
    context_request = CommitContextRequest(
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.subject.agent_id,
    )
    reads = (
        lambda: reader.read_commit_context(context_request),
        lambda: reader.read_logical_node(
            request.subject.workflow_id, request.subject.node_id
        ),
        lambda: reader.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        ),
        lambda: reader.get_certificate(request.commit_id),
        lambda: reader.get_outbox_event(request.commit_id),
        lambda: store.read_commit_context(context_request),
        lambda: store.recover_outbox(OutboxRecoveryRequest(max_items="1")),
    )
    for read in reads:
        with pytest.raises(
            ValueError, match=r"semantic (?:checkpoint )?validation failed"
        ):
            read()
    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )


@pytest.mark.parametrize(
    "operation",
    (
        "stage_result",
        "assemble_evidence",
        "propose_commit",
        "atomic_commit",
        "recover",
        "revoke",
        "supersede",
        "recover_outbox",
    ),
)
def test_postgres_every_mutation_rejects_unrelated_semantic_corruption(
    postgres_environment: _PostgresEnvironment,
    operation: str,
) -> None:
    schema, store = _single_store(postgres_environment, f"mutation_attest_{operation}")
    target = _request(
        postgres_environment,
        commit_id=f"mutation-attest-{operation}",
        nonce_byte=122,
    )
    support = postgres_environment.modules.support
    invoke: Callable[[], object]
    if operation == "stage_result":
        invoke = partial(store.stage_result, getattr(support, "_stage_request")(target))
    elif operation == "assemble_evidence":
        store.stage_result(getattr(support, "_stage_request")(target))
        invoke = partial(
            store.assemble_evidence,
            getattr(support, "_assemble_evidence_request")(target),
        )
    elif operation == "propose_commit":
        store.stage_result(getattr(support, "_stage_request")(target))
        store.assemble_evidence(getattr(support, "_assemble_evidence_request")(target))
        invoke = partial(
            store.propose_commit,
            getattr(support, "_propose_commit_request")(target),
        )
    elif operation == "atomic_commit":
        _advance(postgres_environment, store, target)
        invoke = partial(store.atomic_commit, target)
    elif operation == "recover":
        invoke = partial(
            store.recover,
            RecoveryRequest("absent-corruption-target", "absent-request-digest"),
        )
    elif operation == "revoke":
        invoke = partial(
            store.revoke,
            RevocationRequest(
                RevocationScope.ACTOR,
                "workflow-1",
                "agent-1",
                "4",
                "unrelated store corruption",
            ),
        )
    elif operation == "supersede":
        _advance(postgres_environment, store, target)
        committed = store.atomic_commit(target)
        assert committed.certificate_digest is not None
        replacement = _request(
            postgres_environment,
            commit_id="mutation-attest-replacement",
            nonce_byte=123,
            expected_node_version="1",
            attempt_id="mutation-attest-replacement",
        )
        _advance(postgres_environment, store, replacement)
        invoke = partial(
            store.supersede,
            SupersessionRequest(committed.certificate_digest or "", replacement),
        )
    else:
        _advance(postgres_environment, store, target)
        store.atomic_commit(target)
        invoke = partial(store.recover_outbox, OutboxRecoveryRequest("1"))

    corrupt = _request(
        postgres_environment,
        commit_id=f"corrupt-seed-{operation}",
        nonce_byte=124,
        workflow_id="workflow-2",
    )
    _advance(postgres_environment, store, corrupt)
    _corrupt_candidate_proposal_digest(postgres_environment, schema, corrupt)
    before = _snapshot(postgres_environment, store)

    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        invoke()
    assert _snapshot(postgres_environment, store) == before
    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("operation", ("reader_open", "writer_open", "outbox"))
def test_postgres_attestation_uses_one_snapshot_during_concurrent_valid_commit(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    schema, setup = _single_store(postgres_environment, f"snapshot_attest_{operation}")
    if operation == "outbox":
        pending = _request(
            postgres_environment,
            commit_id="snapshot-existing-outbox",
            nonce_byte=125,
        )
        _advance(postgres_environment, setup, pending)
        setup.atomic_commit(pending)
    concurrent = _request(
        postgres_environment,
        commit_id=f"snapshot-concurrent-{operation}",
        nonce_byte=126,
        workflow_id="workflow-2",
    )
    _advance(postgres_environment, setup, concurrent)

    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    connection_type = getattr(store_module, "_Connection")
    original_execute = cast(
        "Callable[[object, str, tuple[object, ...]], _Cursor]",
        connection_type.execute,
    )
    main_thread = threading.get_ident()
    query_finished = threading.Event()
    release = threading.Event()
    gate = threading.Lock()
    armed = True

    def execute_with_barrier(
        connection: object,
        query: str,
        parameters: tuple[object, ...] = (),
    ) -> _Cursor:
        nonlocal armed
        cursor = original_execute(connection, query, parameters)
        should_pause = False
        barrier_query = (
            "SELECT c.relname,c.relkind,c.relpersistence"
            if operation == "outbox"
            else "SELECT certificate_digest, commit_id, certificate_json"
        )
        if threading.get_ident() != main_thread and query.startswith(barrier_query):
            with gate:
                if armed:
                    armed = False
                    should_pause = True
        if should_pause:
            query_finished.set()
            if not release.wait(timeout=10):
                raise TimeoutError("attestation barrier was not released")
        return cursor

    monkeypatch.setattr(connection_type, "execute", execute_with_barrier)

    def attest() -> object:
        if operation == "reader_open":
            return postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
        if operation == "writer_open":
            return postgres_environment.modules.store_factory.open(
                postgres_environment.runtime_dsn,
                schema=schema,
                config=_config(postgres_environment),
                runtime=_runtime(postgres_environment),
            )
        return setup.recover_outbox(OutboxRecoveryRequest("1"))

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(attest)
        if not query_finished.wait(timeout=10):
            release.set()
            future.result(timeout=1)
            pytest.fail("attestation did not reach the deterministic barrier")
        try:
            assert (
                setup.atomic_commit(concurrent).decision.outcome
                is RequestOutcome.COMMITTED
            )
        finally:
            release.set()
        result = future.result(timeout=10)
    if operation == "outbox":
        assert isinstance(result, OutboxRecoveryResult)
        assert result.delivered_count == "1"
    else:
        cast("_PostgresReader | _PostgresStore", result).close()


@dataclass(slots=True)
class _CorruptingOutboxSink:
    environment: _PostgresEnvironment
    schema: str
    corrupt: AtomicCommitRequest
    fail_after_corruption: bool
    claimed_state: tuple[object, ...] | None = None

    def deliver(self, event_id: str, payload: bytes) -> None:
        del payload
        _corrupt_candidate_proposal_digest(self.environment, self.schema, self.corrupt)
        with self.environment.modules.psycopg.connect(
            self.environment.dsn, autocommit=True
        ) as connection:
            self.claimed_state = connection.execute(
                f"SELECT state,lease_token,lease_claimed_ms,lease_until_ms,delivered "
                f'FROM "{self.schema}"."outbox" WHERE event_id=%s',
                (event_id,),
            ).fetchone()
        assert self.claimed_state is not None
        assert self.claimed_state[0] == "CLAIMED"
        if self.fail_after_corruption:
            raise RuntimeError("sink failed after corruption")


@pytest.mark.parametrize("sink_failure", (False, True))
def test_postgres_outbox_post_claim_mutations_reattest_same_store_snapshot(
    postgres_environment: _PostgresEnvironment,
    sink_failure: bool,
) -> None:
    schema = postgres_environment.schema(f"outbox_post_claim_{sink_failure}")
    config = _config(postgres_environment)
    postgres_environment.modules.store_factory.provision(
        postgres_environment.dsn,
        schema=schema,
        config=config,
        initial_contexts=_initial_contexts(postgres_environment),
        runtime_role=postgres_environment.runtime_role,
        observer_role=postgres_environment.observer_role,
        runtime=_runtime(postgres_environment),
    )
    corrupt = _request(
        postgres_environment,
        commit_id="outbox-post-claim-corrupt",
        nonce_byte=127,
        workflow_id="workflow-2",
    )
    sink = _CorruptingOutboxSink(postgres_environment, schema, corrupt, sink_failure)
    runtime = replace(_runtime(postgres_environment), outbox_sink=sink)
    store = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=config,
        runtime=runtime,
    )
    _advance(postgres_environment, store, corrupt)
    pending = _request(
        postgres_environment,
        commit_id="outbox-post-claim-pending",
        nonce_byte=128,
    )
    _advance(postgres_environment, store, pending)
    store.atomic_commit(pending)

    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        store.recover_outbox(OutboxRecoveryRequest("1"))
    assert sink.claimed_state is not None
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        persisted = connection.execute(
            f"SELECT state,lease_token,lease_claimed_ms,lease_until_ms,delivered "
            f'FROM "{schema}"."outbox" WHERE operation_id=%s',
            (pending.commit_id,),
        ).fetchone()
    assert persisted == sink.claimed_state
    with pytest.raises(ValueError, match=r"semantic (?:checkpoint )?validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("sqlstate", _RETRYABLE_SQLSTATES)
def test_postgres_outbox_attestation_retries_the_complete_claim_transaction(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    sqlstate: str,
) -> None:
    schema, setup = _single_store(postgres_environment, f"outbox_retry_{sqlstate}")
    request = _request(
        postgres_environment,
        commit_id=f"outbox-retry-{sqlstate}",
        nonce_byte=129,
    )
    _advance(postgres_environment, setup, request)
    setup.atomic_commit(request)
    store = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=2),
    )
    store_type = type(store)
    original_validate = cast(
        "Callable[[object, _Connection, APCCAuthorityConfig | None], None]",
        getattr(store_type, "_validate_mutation_checkpoint"),
    )
    failures_remaining = 1
    transaction_ids: list[object] = []

    def validate_with_abort(
        instance: object,
        connection: _Connection,
        provisioned: APCCAuthorityConfig | None = None,
    ) -> None:
        nonlocal failures_remaining
        transaction = connection.execute("SELECT txid_current()").fetchone()
        assert transaction is not None
        transaction_ids.append(transaction[0])
        if failures_remaining:
            failures_remaining -= 1
            connection.execute(
                "DO $apcc$ BEGIN RAISE EXCEPTION 'retry outbox attestation' "
                f"USING ERRCODE = '{sqlstate}'; END $apcc$"
            )
        original_validate(instance, connection, provisioned)

    monkeypatch.setattr(
        store_type, "_validate_mutation_checkpoint", validate_with_abort
    )
    result = store.recover_outbox(OutboxRecoveryRequest("1"))
    assert result.delivered_count == "1"
    assert len(transaction_ids) >= 2
    assert transaction_ids[0] != transaction_ids[1]


def test_postgres_outbox_attestation_retry_exhaustion_is_bounded_and_atomic(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, setup = _single_store(postgres_environment, "outbox_retry_exhaustion")
    request = _request(
        postgres_environment,
        commit_id="outbox-retry-exhaustion",
        nonce_byte=130,
    )
    _advance(postgres_environment, setup, request)
    setup.atomic_commit(request)
    store = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
        retry_policy=postgres_environment.modules.retry_policy_factory(max_attempts=2),
    )
    store_type = type(store)
    attempts = 0

    def always_abort(
        _instance: object,
        connection: _Connection,
        _provisioned: APCCAuthorityConfig | None = None,
    ) -> None:
        nonlocal attempts
        attempts += 1
        connection.execute(
            "DO $apcc$ BEGIN RAISE EXCEPTION 'exhaust outbox attestation' "
            "USING ERRCODE = '40001'; END $apcc$"
        )
        raise AssertionError("PostgreSQL did not raise the injected SQLSTATE")

    monkeypatch.setattr(store_type, "_validate_mutation_checkpoint", always_abort)
    before = _snapshot(postgres_environment, store)
    with pytest.raises(RuntimeError, match="outbox claim.*40001.*2"):
        store.recover_outbox(OutboxRecoveryRequest("1"))
    assert attempts == 2
    assert _snapshot(postgres_environment, store) == before


def test_postgres_bootstrap_reopen_is_public_only_and_persists_no_private_seed(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "public_bootstrap")
    request = _request(postgres_environment, commit_id="pg-secrets", nonce_byte=112)
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    before = _snapshot(postgres_environment, store)
    store.close()
    reopened = postgres_environment.modules.store_factory.open(
        postgres_environment.runtime_dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
    )
    assert (
        reopened.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        )
        == committed
    )
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert reader.authority_store_id == reopened.authority_store_id
    assert _snapshot(postgres_environment, reopened) == before
    persisted_atoms: list[bytes] = []
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        tables = connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=%s ORDER BY table_name",
            (schema,),
        ).fetchall()
        for (table_name,) in tables:
            assert isinstance(table_name, str)
            for row in connection.execute(
                f'SELECT * FROM "{schema}"."{table_name}"'
            ).fetchall():
                persisted_atoms.extend(
                    value if isinstance(value, bytes) else str(value).encode("utf-8")
                    for value in row
                    if value is not None
                )
    for seed in _ROLE_SEEDS:
        encodings = {
            seed,
            seed.hex().encode("ascii"),
            seed.hex().upper().encode("ascii"),
            base64.b64encode(seed),
            base64.b64encode(seed).rstrip(b"="),
            base64.urlsafe_b64encode(seed),
            base64.urlsafe_b64encode(seed).rstrip(b"="),
        }
        assert not any(
            encoding in atom for encoding in encodings for atom in persisted_atoms
        )
    base_config = _config(postgres_environment)
    changed = replace(
        base_config,
        authority_store_id="changed-store",
        commit_trust=replace(base_config.commit_trust, scope=("changed-store",)),
        status_trust=replace(base_config.status_trust, scope=("changed-store",)),
        freshness=StatusFreshnessPolicy("5000", "1000"),
    )
    with pytest.raises(ValueError):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=changed,
            runtime=_runtime(postgres_environment),
        )
    assert _snapshot(postgres_environment, reopened) == before


def test_postgres_matrix_is_explicit_and_non_mocked() -> None:
    assert len(_RETRYABLE_SQLSTATES) == 2
    assert len(_AMBIGUOUS_SQLSTATES) == 3
    assert len(_ROLE_SEEDS) == 6
    assert _MIN_MAX_CONNECTIONS == 105
    assert _BENCHMARK_MAX_CONNECTIONS == 200
    assert Counter(_RETRYABLE_SQLSTATES) == Counter({"40001": 1, "40P01": 1})
    source = Path(__file__).read_text(encoding="utf-8")
    imported_modules = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "unittest.mock" not in imported_modules


def test_postgres_observer_reads_one_complete_repeatable_read_snapshot(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "observer_snapshot")
    request = _request(
        postgres_environment,
        commit_id="observer-snapshot",
        nonce_byte=131,
    )
    _advance(postgres_environment, store, request)
    committed = store.atomic_commit(request)
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn,
        schema=schema,
        status_signer=_StatusSignerAdapter(store),
    )
    target = AuthorityObservationRequest(
        "APCC-1.0-draft",
        "apcc.authority-observation-request",
        _config(postgres_environment).authority_store_id,
        request.subject.workflow_id,
        request.subject.node_id,
        request.subject.attempt_id,
        request.commit_id,
        _operation_identity(request, None),
        _public_request_digest(request),
        _nonce(132),
    )

    snapshot = reader.observe_authority(target)

    assert snapshot.state is AuthorityObservationState.COMMITTED
    assert snapshot.certificate_digest == committed.certificate_digest
    assert snapshot.certificate_envelope_bytes == committed.certificate_envelope_bytes
    assert snapshot.outbox_state == "PENDING"
    assert snapshot.current_status_evidence is not None
    assert not hasattr(reader, "atomic_commit")


def test_postgres_observer_never_returns_a_torn_supersession_tuple(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "observer_snapshot_race")
    original_request = _request(
        postgres_environment,
        commit_id="observer-race-old",
        nonce_byte=133,
    )
    _advance(postgres_environment, store, original_request)
    original = store.atomic_commit(original_request)
    assert original.certificate_digest is not None
    original_digest = original.certificate_digest
    replacement = _request(
        postgres_environment,
        commit_id="observer-race-new",
        nonce_byte=134,
        expected_node_version="1",
        attempt_id="observer-race-new-attempt",
    )
    _advance(postgres_environment, store, replacement)
    target = AuthorityObservationRequest(
        "APCC-1.0-draft",
        "apcc.authority-observation-request",
        _config(postgres_environment).authority_store_id,
        original_request.subject.workflow_id,
        original_request.subject.node_id,
        original_request.subject.attempt_id,
        original_request.commit_id,
        _operation_identity(original_request, None),
        _public_request_digest(original_request),
        _nonce(135),
    )
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn,
        schema=schema,
        status_signer=_StatusSignerAdapter(store),
    )
    started = threading.Event()

    def writer() -> None:
        started.wait()
        store.supersede(SupersessionRequest(original_digest, replacement))

    thread = threading.Thread(target=writer)
    thread.start()
    started.set()
    snapshots = [reader.observe_authority(target) for _ in range(40)]
    thread.join(5)
    assert not thread.is_alive()

    for snapshot in snapshots:
        assert snapshot.current_status_evidence is not None
        status = decode_authority_status(snapshot.current_status_evidence)
        if snapshot.logical_node.current_certificate_digest == original_digest:
            assert status.status is AuthorityStatusValue.CURRENT
            assert status.superseded is SupersessionValue.NO
        else:
            assert status.status is AuthorityStatusValue.CURRENT
            assert status.superseded is SupersessionValue.YES


def test_postgres_observer_credentials_are_child_loaded_and_not_exposed(
    postgres_environment: _PostgresEnvironment,
) -> None:
    from constitutional_swarm.authority_service import (
        AuthorityObserverBackendRef,
        _receive_observer_postgres_credential,
    )

    schema, _store = _single_store(postgres_environment, "observer_credential_boundary")
    marker = f"observer-secret-{secrets.token_hex(12)}"
    observer_dsn = f"{postgres_environment.observer_dsn} application_name={marker}"
    backend = AuthorityObserverBackendRef(
        "postgresql", "dedicated-pg17-test-instance", None, schema
    )
    assert marker not in repr(backend)
    receive, send = multiprocessing.get_context("spawn").Pipe(duplex=False)
    send.send_bytes(observer_dsn.encode("utf-8"))
    send.close()
    assert _receive_observer_postgres_credential(receive) == observer_dsn
    assert receive.closed
    assert marker not in repr(backend)
    assert postgres_environment.runtime_dsn not in repr(backend)


def test_postgres_revoked_observer_login_cannot_reconnect_and_fresh_login_attests(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _store = _single_store(postgres_environment, "observer_login_rotation")
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert reader.authority_store_id == _config(postgres_environment).authority_store_id
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as administrator:
        administrator.execute(
            f'ALTER ROLE "{postgres_environment.observer_role}" NOLOGIN'
        )
    try:
        with pytest.raises(Exception):
            postgres_environment.modules.psycopg.connect(
                postgres_environment.observer_dsn
            )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as administrator:
            administrator.execute(
                f'ALTER ROLE "{postgres_environment.observer_role}" LOGIN'
            )
    fresh = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert fresh.authority_store_id == reader.authority_store_id


@pytest.mark.parametrize(
    "query_marker",
    (
        "SELECT 1 FROM pg_inherits i",
        "WITH RECURSIVE role_names",
        "SELECT 1 FROM pg_publication p",
        "current_setting('session_replication_role')",
        "FROM pg_parameter_acl",
        "SELECT k.conname,k.convalidated",
        "WHERE child.",
    ),
)
def test_postgres_catalog_and_integrity_query_errors_fail_closed(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    query_marker: str,
) -> None:
    schema, _ = _single_store(postgres_environment, "query_error")
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    connection_type = getattr(store_module, "_Connection")
    original_execute = connection_type.execute

    def injected_execute(
        connection: object, query: str, parameters: tuple[object, ...] = ()
    ) -> object:
        if query_marker in query:
            raise RuntimeError(f"injected query failure: {query_marker}")
        return original_execute(connection, query, parameters)

    monkeypatch.setattr(connection_type, "execute", injected_execute)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_full_catalog_and_fk_checks_run_once_per_authority_transaction(
    postgres_environment: _PostgresEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, store = _single_store(postgres_environment, "attestation_query_count")
    for sibling_number in range(2):
        _single_store(postgres_environment, f"attestation_base_{sibling_number}")
        _provision_gcb_profile(
            postgres_environment, f"attestation_gcb_{sibling_number}"
        )
    request = _request(
        postgres_environment, commit_id="attestation-query-count", nonce_byte=125
    )
    _advance(postgres_environment, store, request)
    store.atomic_commit(request)
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    function_names = (
        "_catalog_fingerprint",
        "_trusted_sibling_schemas",
        "_validate_foreign_key_integrity",
        "_validate_external_capability_contract",
        "_validate_logical_replication_contract",
        "_validate_parameter_contract",
    )
    counts: Counter[tuple[str, int]] = Counter()
    raw_connections: list[object] = []

    def wrap(name: str) -> Callable[..., object]:
        original = getattr(store_module, name)

        def counted(connection: object, *args: object, **kwargs: object) -> object:
            raw = getattr(connection, "raw")
            if not any(existing is raw for existing in raw_connections):
                raw_connections.append(raw)
            counts[(name, id(raw))] += 1
            return original(connection, *args, **kwargs)

        return counted

    for function_name in function_names:
        monkeypatch.setattr(store_module, function_name, wrap(function_name))

    target = _request(
        postgres_environment,
        commit_id="attestation-query-count-stage",
        attempt_id="attempt-query-count-stage",
        nonce_byte=126,
    )
    operations: tuple[Callable[[], object], ...] = (
        lambda: store.stage_result(
            getattr(postgres_environment.modules.support, "_stage_request")(target)
        ),
        lambda: reader.get_certificate(request.commit_id),
        lambda: reader.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        ),
        lambda: store.recover_outbox(OutboxRecoveryRequest(max_items="1")),
    )
    for operation in operations:
        counts.clear()
        raw_connections.clear()
        operation()
        assert counts
        assert set(name for name, _ in counts) == set(function_names)
        assert all(
            count == (5 if name == "_catalog_fingerprint" else 1)
            for (name, _), count in counts.items()
        )


@pytest.mark.parametrize(
    "drift",
    (
        "body",
        "config",
        "owner",
        "extra_trigger",
        "trigger_shape",
        "checkpoint_rule",
        "checkpoint_check",
        "extra_index",
        "column_default",
        "overload",
        "dependency_view",
        "removed_canonical_triggers",
    ),
)
def test_postgres_trusted_sibling_catalog_drift_fails_closed(
    postgres_environment: _PostgresEnvironment,
    drift: str,
) -> None:
    target_schema, _ = _single_store(postgres_environment, f"sibling_target_{drift}")
    sibling_schema, _ = _single_store(postgres_environment, f"sibling_drift_{drift}")
    owner_role = postgres_environment.owner_role
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{owner_role}"')
        if drift == "body":
            connection.execute(
                f'CREATE OR REPLACE FUNCTION "{sibling_schema}".'
                '"apcc_mark_semantic_dirty"() RETURNS trigger LANGUAGE plpgsql '
                "SECURITY DEFINER SET search_path FROM CURRENT AS $drift$ "
                "BEGIN RETURN NULL; END $drift$"
            )
        elif drift == "config":
            connection.execute(
                f'ALTER FUNCTION "{sibling_schema}"."apcc_mark_semantic_dirty"() '
                "SET search_path TO pg_catalog"
            )
        elif drift == "owner":
            connection.execute("RESET ROLE")
            connection.execute(
                f'ALTER FUNCTION "{sibling_schema}"."apcc_mark_semantic_dirty"() '
                f'OWNER TO "{postgres_environment.runtime_role}"'
            )
        elif drift == "extra_trigger":
            connection.execute(
                f'CREATE FUNCTION "{sibling_schema}"."extra_dirty"() RETURNS trigger '
                "LANGUAGE plpgsql SECURITY DEFINER AS $drift$ BEGIN RETURN NEW; "
                "END $drift$"
            )
            connection.execute(
                f'CREATE TRIGGER "extra_dirty" BEFORE INSERT ON '
                f'"{sibling_schema}"."metadata" FOR EACH ROW EXECUTE FUNCTION '
                f'"{sibling_schema}"."extra_dirty"()'
            )
        elif drift == "trigger_shape":
            connection.execute(
                f'DROP TRIGGER "apcc_semantic_dirty_metadata_insert" ON '
                f'"{sibling_schema}"."metadata"'
            )
            connection.execute(
                f'CREATE TRIGGER "apcc_semantic_dirty_metadata_insert" BEFORE INSERT ON '
                f'"{sibling_schema}"."metadata" FOR EACH ROW EXECUTE FUNCTION '
                f'"{sibling_schema}"."apcc_mark_semantic_dirty"()'
            )
        elif drift == "checkpoint_rule":
            connection.execute(
                f'CREATE RULE "checkpoint_block" AS ON UPDATE TO '
                f'"{sibling_schema}"."semantic_checkpoint" DO INSTEAD NOTHING'
            )
        elif drift == "checkpoint_check":
            connection.execute(
                f'ALTER TABLE "{sibling_schema}"."semantic_checkpoint" DROP '
                "CONSTRAINT semantic_checkpoint_sequence_check"
            )
        elif drift == "extra_index":
            connection.execute(
                f'CREATE INDEX "metadata_value_extra" ON '
                f'"{sibling_schema}"."metadata"(value)'
            )
        elif drift == "column_default":
            connection.execute(
                f'ALTER TABLE "{sibling_schema}"."metadata" ALTER COLUMN value '
                "SET DEFAULT 'drift'"
            )
        elif drift == "overload":
            connection.execute(
                f'CREATE FUNCTION "{sibling_schema}".'
                '"apcc_mark_semantic_dirty"(integer) RETURNS integer '
                "LANGUAGE sql AS 'SELECT $1'"
            )
        elif drift == "dependency_view":
            connection.execute(
                f'CREATE VIEW "{sibling_schema}"."metadata_dependency" AS '
                f'SELECT value FROM "{sibling_schema}"."metadata"'
            )
        else:
            triggers = connection.execute(
                "SELECT c.relname,t.tgname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid=t.tgrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=%s AND NOT t.tgisinternal",
                (sibling_schema,),
            ).fetchall()
            for relation, trigger in triggers:
                connection.execute(
                    f'DROP TRIGGER "{trigger}" ON "{sibling_schema}"."{relation}"'
                )
        connection.execute("RESET ROLE")

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=target_schema
        )


def test_postgres_reached_trusted_invoker_trigger_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "invoker_trigger_reject")
    external_schema = postgres_environment.schema("invoker_trigger_reject_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."target" (id BIGINT)')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."invoker_trigger"() RETURNS trigger '
            "LANGUAGE plpgsql AS $function$ BEGIN RETURN NEW; END $function$"
        )
        connection.execute(
            f'CREATE TRIGGER "invoker_trigger" BEFORE INSERT ON '
            f'"{external_schema}"."target" FOR EACH ROW EXECUTE FUNCTION '
            f'"{external_schema}"."invoker_trigger"()'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."target" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."target" VALUES (1)')
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("execute_grant", ("observer", "PUBLIC", "revoked"))
def test_postgres_select_view_function_dependency_is_fail_closed_by_execute_acl(
    postgres_environment: _PostgresEnvironment,
    execute_grant: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"select_function_{execute_grant}")
    external_schema = postgres_environment.schema(
        f"select_function_{execute_grant}_scope"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."source" (id BIGINT)')
        connection.execute(f'INSERT INTO "{external_schema}"."source" VALUES (1)')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."transform"(BIGINT) RETURNS BIGINT '
            "LANGUAGE sql AS 'SELECT $1 + 1'"
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."transformed" AS SELECT '
            f'"{external_schema}"."transform"(id) AS id FROM '
            f'"{external_schema}"."source"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."transformed" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."transform"(BIGINT) '
            "FROM PUBLIC"
        )
        if execute_grant == "observer":
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{external_schema}"."transform"(BIGINT) '
                f'TO "{postgres_environment.observer_role}"'
            )
        elif execute_grant == "PUBLIC":
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{external_schema}"."transform"(BIGINT) '
                "TO PUBLIC"
            )
    if execute_grant == "revoked":
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.InsufficientPrivilege
            ):
                connection.execute(f'SELECT * FROM "{external_schema}"."transformed"')
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
    else:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            assert connection.execute(
                f'SELECT * FROM "{external_schema}"."transformed"'
            ).fetchall() == [(2,)]
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )


def test_postgres_reached_executable_extension_member_function_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "extension_function")
    external_schema = postgres_environment.schema("extension_function_scope")
    installed_by_test = False
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        installed_by_test = (
            connection.execute(
                "SELECT 1 FROM pg_extension WHERE extname='postgres_fdw'"
            ).fetchone()
            is None
        )
        if installed_by_test:
            connection.execute("CREATE EXTENSION postgres_fdw")
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."source" (id BIGINT)')
        connection.execute(f'INSERT INTO "{external_schema}"."source" VALUES (1)')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."extension_transform"(BIGINT) '
            "RETURNS BIGINT LANGUAGE sql VOLATILE AS 'SELECT $1 + 1'"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            "ALTER EXTENSION postgres_fdw ADD FUNCTION "
            f'"{external_schema}"."extension_transform"(BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."transformed" AS SELECT '
            f'"{external_schema}"."extension_transform"(id) AS id FROM '
            f'"{external_schema}"."source"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."transformed" TO '
            f'"{postgres_environment.observer_role}"'
        )
    try:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            assert connection.execute(
                f'SELECT * FROM "{external_schema}"."transformed"'
            ).fetchall() == [(2,)]
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(f'DROP VIEW "{external_schema}"."transformed"')
            if installed_by_test:
                connection.execute("DROP EXTENSION postgres_fdw")
            else:
                connection.execute(
                    "ALTER EXTENSION postgres_fdw DROP FUNCTION "
                    f'"{external_schema}"."extension_transform"(BIGINT)'
                )


@pytest.mark.parametrize(
    "capability",
    (
        "observer_execute",
        "update_default",
        "split_runtime_execute",
        "revoked",
        "select_only",
        "unrelated_update",
    ),
)
def test_postgres_stored_default_capability_preserves_principal_and_operation(
    postgres_environment: _PostgresEnvironment,
    capability: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"stored_default_{capability}")
    table_schema = postgres_environment.schema(f"stored_default_table_{capability}")
    function_schema = postgres_environment.schema(
        f"stored_default_function_{capability}"
    )
    proof_key = f"stored-default-{capability}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{function_schema}"."authority_effect"() '
            "RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{function_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable'); RETURN 7; END $function$"
        )
        connection.execute(
            f'CREATE TABLE "{table_schema}"."defaults" '
            f'(value BIGINT DEFAULT "{function_schema}"."authority_effect"(), '
            "unrelated BIGINT NOT NULL DEFAULT 0)"
        )
        if capability in {"update_default", "unrelated_update"}:
            connection.execute(
                f'INSERT INTO "{table_schema}"."defaults"(value) VALUES (1)'
            )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{function_schema}"."authority_effect"() '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{table_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        if capability == "select_only":
            connection.execute(
                f'GRANT SELECT ON "{table_schema}"."defaults" TO '
                f'"{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{function_schema}".'
                f'"authority_effect"() TO "{postgres_environment.observer_role}"'
            )
        elif capability == "update_default":
            connection.execute(
                f'GRANT UPDATE(value) ON "{table_schema}"."defaults" TO '
                f'"{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{function_schema}".'
                f'"authority_effect"() TO "{postgres_environment.observer_role}"'
            )
        elif capability == "unrelated_update":
            connection.execute(
                f'GRANT UPDATE(unrelated) ON "{table_schema}"."defaults" TO '
                f'"{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT SELECT(unrelated) ON "{table_schema}"."defaults" TO '
                f'"{postgres_environment.observer_role}"'
            )
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{function_schema}".'
                f'"authority_effect"() TO "{postgres_environment.observer_role}"'
            )
        else:
            connection.execute(
                f'GRANT INSERT ON "{table_schema}"."defaults" TO '
                f'"{postgres_environment.observer_role}"'
            )
            if capability == "observer_execute":
                connection.execute(
                    f'GRANT EXECUTE ON FUNCTION "{function_schema}".'
                    f'"authority_effect"() TO "{postgres_environment.observer_role}"'
                )
            elif capability == "split_runtime_execute":
                connection.execute(
                    f'GRANT EXECUTE ON FUNCTION "{function_schema}".'
                    f'"authority_effect"() TO "{postgres_environment.runtime_role}"'
                )
    if capability in {"observer_execute", "update_default"}:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            if capability == "update_default":
                connection.execute(
                    f'UPDATE "{table_schema}"."defaults" SET value=DEFAULT'
                )
            else:
                connection.execute(
                    f'INSERT INTO "{table_schema}"."defaults" DEFAULT VALUES'
                )
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            assert connection.execute(
                f'SELECT value FROM "{schema}"."metadata" WHERE key=%s',
                (proof_key,),
            ).fetchone() == ("reachable",)
            connection.execute(
                f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            )
        _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    elif capability in {"split_runtime_execute", "revoked"}:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.observer_dsn, autocommit=True
        ) as connection:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.InsufficientPrivilege
            ):
                connection.execute(
                    f'INSERT INTO "{table_schema}"."defaults" DEFAULT VALUES'
                )
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
    else:
        if capability == "unrelated_update":
            with postgres_environment.modules.psycopg.connect(
                postgres_environment.observer_dsn, autocommit=True
            ) as connection:
                result = connection.execute(
                    f'UPDATE "{table_schema}"."defaults" SET unrelated=unrelated + 1'
                )
                assert result.rowcount == 1
            with postgres_environment.modules.psycopg.connect(
                postgres_environment.dsn, autocommit=True
            ) as connection:
                assert (
                    connection.execute(
                        f'SELECT 1 FROM "{schema}"."metadata" WHERE key=%s',
                        (proof_key,),
                    ).fetchone()
                    is None
                )
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


def test_postgres_replica_only_external_rule_is_inactive_at_origin(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "replica_rule")
    external_schema = postgres_environment.schema("replica_rule_scope")
    proof_key = "replica-rule-inactive"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."source" (id BIGINT)')
        connection.execute(
            f'CREATE RULE "replica_effect" AS ON INSERT TO '
            f'"{external_schema}"."source" DO ALSO INSERT INTO '
            f'"{schema}"."metadata"(key,value) VALUES '
            f"('{proof_key}','unexpected')"
        )
        connection.execute(
            f'ALTER TABLE "{external_schema}"."source" '
            'ENABLE REPLICA RULE "replica_effect"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."source" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."source" VALUES (1)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert (
            connection.execute(
                f'SELECT 1 FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            ).fetchone()
            is None
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_insert_rule_with_update_action_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "insert_rule_update_action")
    external_schema = postgres_environment.schema("insert_rule_update_action_scope")
    proof_key = "insert-rule-update-action"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."source" (id BIGINT)')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."target" (id BIGINT PRIMARY KEY)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."target" VALUES (1)')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."update_effect"() '
            "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN NEW; END $function$"
        )
        connection.execute(
            f'CREATE TRIGGER "update_effect" BEFORE UPDATE ON '
            f'"{external_schema}"."target" FOR EACH ROW EXECUTE FUNCTION '
            f'"{external_schema}"."update_effect"()'
        )
        connection.execute(
            f'CREATE RULE "insert_updates_target" AS ON INSERT TO '
            f'"{external_schema}"."source" DO ALSO UPDATE '
            f'"{external_schema}"."target" SET id=id WHERE id=NEW.id'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."update_effect"() FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."source" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT UPDATE ON "{external_schema}"."target" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."source" VALUES (1)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    "expression_kind",
    (
        "check",
        "generated",
        "expression_index",
        "partial_index",
        "rls_using",
        "rls_with_check",
        "rls_update",
        "rls_delete",
        "rls_all_with_check",
        "rls_select_on_update",
    ),
)
def test_postgres_reached_stored_expression_dependencies_are_rejected(
    postgres_environment: _PostgresEnvironment,
    expression_kind: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"stored_expression_{expression_kind}"
    )
    table_schema = postgres_environment.schema(
        f"stored_expression_table_{expression_kind}"
    )
    function_schema = postgres_environment.schema(
        f"stored_expression_function_{expression_kind}"
    )
    proof_key = f"stored-expression-{expression_kind}"
    effectful = expression_kind in {
        "check",
        "rls_using",
        "rls_with_check",
        "rls_update",
        "rls_delete",
        "rls_all_with_check",
        "rls_select_on_update",
    }
    returns_boolean = expression_kind in {
        "check",
        "partial_index",
        "rls_using",
        "rls_with_check",
        "rls_update",
        "rls_delete",
        "rls_all_with_check",
        "rls_select_on_update",
    }
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if effectful:
            connection.execute(
                f'CREATE FUNCTION "{function_schema}"."expression"(BIGINT) '
                "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
                f'SET search_path TO pg_catalog,"{function_schema}",pg_temp '
                "AS $function$ BEGIN "
                f'INSERT INTO "{schema}"."metadata"(key,value) '
                f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
                "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
            )
        else:
            return_type = "BOOLEAN" if returns_boolean else "BIGINT"
            expression = "$1 > 0" if returns_boolean else "$1 + 1"
            connection.execute(
                f'CREATE FUNCTION "{function_schema}"."expression"(BIGINT) '
                f"RETURNS {return_type} LANGUAGE sql IMMUTABLE SECURITY DEFINER "
                f"AS 'SELECT {expression}'"
            )
        connection.execute(
            f'CREATE TABLE "{table_schema}"."subject" (id BIGINT NOT NULL)'
        )
        if expression_kind == "check":
            connection.execute(
                f'ALTER TABLE "{table_schema}"."subject" ADD CONSTRAINT '
                f'"effect_check" CHECK ("{function_schema}"."expression"(id))'
            )
        elif expression_kind == "generated":
            connection.execute(
                f'ALTER TABLE "{table_schema}"."subject" ADD COLUMN generated BIGINT '
                f'GENERATED ALWAYS AS ("{function_schema}"."expression"(id)) STORED'
            )
        elif expression_kind == "expression_index":
            connection.execute(
                f'CREATE INDEX "effect_expression" ON "{table_schema}"."subject" '
                f'(("{function_schema}"."expression"(id)))'
            )
        elif expression_kind == "partial_index":
            connection.execute(
                f'CREATE INDEX "effect_partial" ON "{table_schema}"."subject" (id) '
                f'WHERE "{function_schema}"."expression"(id)'
            )
        else:
            connection.execute(
                f'ALTER TABLE "{table_schema}"."subject" ENABLE ROW LEVEL SECURITY'
            )
            policy_command = {
                "rls_using": "SELECT",
                "rls_with_check": "INSERT",
                "rls_update": "UPDATE",
                "rls_delete": "DELETE",
                "rls_all_with_check": "ALL",
                "rls_select_on_update": "SELECT",
            }[expression_kind]
            policy_expression = {
                "rls_using": f'USING ("{function_schema}"."expression"(id))',
                "rls_with_check": (
                    f'WITH CHECK ("{function_schema}"."expression"(id))'
                ),
                "rls_update": (
                    f'USING ("{function_schema}"."expression"(id)) '
                    f'WITH CHECK ("{function_schema}"."expression"(id))'
                ),
                "rls_delete": f'USING ("{function_schema}"."expression"(id))',
                "rls_all_with_check": (
                    f'WITH CHECK ("{function_schema}"."expression"(id))'
                ),
                "rls_select_on_update": (
                    f'USING ("{function_schema}"."expression"(id))'
                ),
            }[expression_kind]
            connection.execute(
                f'CREATE POLICY "effect_policy" ON "{table_schema}"."subject" '
                f'FOR {policy_command} TO "{postgres_environment.observer_role}" '
                f"{policy_expression}"
            )
            if expression_kind in {
                "rls_using",
                "rls_update",
                "rls_delete",
                "rls_select_on_update",
            }:
                connection.execute(f'INSERT INTO "{table_schema}"."subject" VALUES (1)')
            if expression_kind in {"rls_update", "rls_delete"}:
                connection.execute(
                    f'CREATE POLICY "visible_rows" ON "{table_schema}"."subject" '
                    f'FOR SELECT TO "{postgres_environment.observer_role}" USING (true)'
                )
            elif expression_kind == "rls_select_on_update":
                connection.execute(
                    f'CREATE POLICY "permitted_update" ON '
                    f'"{table_schema}"."subject" FOR UPDATE TO '
                    f'"{postgres_environment.observer_role}" USING (true) '
                    "WITH CHECK (true)"
                )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{function_schema}"."expression"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{function_schema}"."expression"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{table_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        privilege = {
            "rls_using": "SELECT",
            "rls_update": "SELECT, UPDATE",
            "rls_delete": "SELECT, DELETE",
            "rls_select_on_update": "SELECT, UPDATE",
        }.get(expression_kind, "INSERT")
        connection.execute(
            f'GRANT {privilege} ON "{table_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if expression_kind == "rls_using":
            assert connection.execute(
                f'SELECT id FROM "{table_schema}"."subject"'
            ).fetchall() == [(1,)]
        elif expression_kind in {"rls_update", "rls_select_on_update"}:
            result = connection.execute(
                f'UPDATE "{table_schema}"."subject" SET id=id + 1'
            )
            assert result.rowcount == 1
        elif expression_kind == "rls_delete":
            result = connection.execute(f'DELETE FROM "{table_schema}"."subject"')
            assert result.rowcount == 1
        else:
            connection.execute(f'INSERT INTO "{table_schema}"."subject" VALUES (1)')
    if effectful:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            assert connection.execute(
                f'SELECT value FROM "{schema}"."metadata" WHERE key=%s',
                (proof_key,),
            ).fetchone() == ("reachable",)
            connection.execute(
                f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            )
        _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    "policy_case", ("public", "nonapplicable", "owner_bypass", "owner_force")
)
def test_postgres_rls_expression_respects_principal_and_owner_semantics(
    postgres_environment: _PostgresEnvironment,
    policy_case: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"rls_principal_{policy_case}")
    table_schema = postgres_environment.schema(f"rls_table_{policy_case}")
    function_schema = postgres_environment.schema(f"rls_function_{policy_case}")
    proof_key = f"rls-principal-{policy_case}"
    policy_role = (
        "PUBLIC"
        if policy_case == "public"
        else f'"{postgres_environment.runtime_role}"'
        if policy_case == "nonapplicable"
        else f'"{postgres_environment.observer_role}"'
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{function_schema}"."policy_effect"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{function_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE TABLE "{table_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(f'INSERT INTO "{table_schema}"."subject" VALUES (1)')
        connection.execute(
            f'ALTER TABLE "{table_schema}"."subject" ENABLE ROW LEVEL SECURITY'
        )
        connection.execute(
            f'CREATE POLICY "effect_policy" ON "{table_schema}"."subject" '
            f"FOR SELECT TO {policy_role} "
            f'USING ("{function_schema}"."policy_effect"(id))'
        )
        connection.execute("RESET ROLE")
        if policy_case in {"owner_bypass", "owner_force"}:
            connection.execute(
                f'ALTER TABLE "{table_schema}"."subject" OWNER TO '
                f'"{postgres_environment.observer_role}"'
            )
        if policy_case == "owner_force":
            connection.execute(
                f'ALTER TABLE "{table_schema}"."subject" FORCE ROW LEVEL SECURITY'
            )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{function_schema}"."policy_effect"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{function_schema}"."policy_effect"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{table_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{table_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        rows = connection.execute(
            f'SELECT id FROM "{table_schema}"."subject"'
        ).fetchall()
    effect_expected = policy_case in {"public", "owner_force"}
    assert rows == ([(1,)] if policy_case != "nonapplicable" else [])
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        effect = connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone()
        assert effect == (("reachable",) if effect_expected else None)
        if effect_expected:
            connection.execute(
                f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            )
    if effect_expected:
        _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


@pytest.mark.parametrize("security_invoker", (False, True))
def test_postgres_rls_view_identity_uses_view_check_as_and_original_invoker(
    postgres_environment: _PostgresEnvironment,
    security_invoker: bool,
) -> None:
    label = "invoker" if security_invoker else "definer"
    schema, _ = _single_store(postgres_environment, f"rls_view_{label}")
    external_schema = postgres_environment.schema(f"rls_view_scope_{label}")
    proof_key = f"rls-view-{label}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."policy_effect"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
        connection.execute(
            f'ALTER TABLE "{external_schema}"."subject" ENABLE ROW LEVEL SECURITY'
        )
        connection.execute(
            f'CREATE POLICY "effect_policy" ON "{external_schema}"."subject" '
            f'FOR SELECT TO "{postgres_environment.observer_role}" '
            f'USING ("{external_schema}"."policy_effect"(id))'
        )
        view_option = " WITH (security_invoker=true)" if security_invoker else ""
        connection.execute(
            f'CREATE VIEW "{external_schema}"."subject_view"{view_option} AS '
            f'SELECT id FROM "{external_schema}"."subject"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."policy_effect"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject_view" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."policy_effect"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
        if security_invoker:
            connection.execute(
                f'GRANT SELECT ON "{external_schema}"."subject" TO '
                f'"{postgres_environment.observer_role}"'
            )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject_view"'
        ).fetchall() == [(1,)]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        effect = connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone()
        assert effect == (("reachable",) if security_invoker else None)
        if security_invoker:
            connection.execute(
                f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            )
    if security_invoker:
        _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    # The directly callable SECURITY DEFINER function remains independently
    # forbidden even when default view-owner RLS semantics bypass its policy.
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    "view_case",
    (
        "definer_force",
        "security_invoker",
        "security_invoker_on",
        "security_invoker_yes",
        "security_invoker_one",
        "owner_bypass",
        "nonapplicable",
    ),
)
def test_postgres_nested_view_rls_uses_separate_invoker_and_check_as_identities(
    postgres_environment: _PostgresEnvironment,
    view_case: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"view_check_as_{view_case}")
    external_schema = postgres_environment.schema(f"view_check_as_scope_{view_case}")
    proof_key = f"view-check-as-{view_case}"
    policy_role = (
        postgres_environment.observer_role
        if view_case == "nonapplicable"
        else postgres_environment.owner_role
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."policy_effect"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
        connection.execute(
            f'ALTER TABLE "{external_schema}"."subject" ENABLE ROW LEVEL SECURITY'
        )
        if view_case != "owner_bypass":
            connection.execute(
                f'ALTER TABLE "{external_schema}"."subject" FORCE ROW LEVEL SECURITY'
            )
        connection.execute(
            f'CREATE POLICY "effect_policy" ON "{external_schema}"."subject" '
            f'FOR SELECT TO "{policy_role}" '
            f'USING ("{external_schema}"."policy_effect"(id))'
        )
        view_option = {
            "security_invoker": " WITH (security_invoker=true)",
            "security_invoker_on": " WITH (security_invoker=on)",
            "security_invoker_yes": " WITH (security_invoker=yes)",
            "security_invoker_one": " WITH (security_invoker=1)",
        }.get(view_case, "")
        connection.execute(
            f'CREATE VIEW "{external_schema}"."inner_view"{view_option} AS '
            f'SELECT id FROM "{external_schema}"."subject"'
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."outer_view" AS '
            f'SELECT id FROM "{external_schema}"."inner_view"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.runtime_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."outer_view" TO '
            f'"{postgres_environment.runtime_role}"'
        )
        if view_case in {
            "security_invoker",
            "security_invoker_on",
            "security_invoker_yes",
            "security_invoker_one",
        }:
            connection.execute(
                f'GRANT SELECT ON "{external_schema}"."inner_view", '
                f'"{external_schema}"."subject" TO '
                f'"{postgres_environment.runtime_role}"'
            )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.runtime_dsn, autocommit=True
    ) as connection:
        rows = connection.execute(
            f'SELECT id FROM "{external_schema}"."outer_view"'
        ).fetchall()
    effect_expected = view_case == "definer_force"
    assert rows == ([(1,)] if view_case in {"definer_force", "owner_bypass"} else [])
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        effect = connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone()
        assert effect == (("reachable",) if effect_expected else None)
        if effect_expected:
            connection.execute(
                f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            )
    if effect_expected:
        _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.store_factory.open(
                postgres_environment.runtime_dsn,
                schema=schema,
                config=_config(postgres_environment),
                runtime=_runtime(postgres_environment),
            )
    else:
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        ).close()


def test_postgres_not_ready_expression_index_is_not_a_dml_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "not_ready_index")
    external_schema = postgres_environment.schema("not_ready_index_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."fail_build"(BIGINT) '
            "RETURNS BIGINT LANGUAGE sql IMMUTABLE AS "
            "'SELECT 1 / ($1 - $1)'"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
        with pytest.raises(postgres_environment.modules.psycopg.errors.DivisionByZero):
            connection.execute(
                f'CREATE INDEX CONCURRENTLY "not_ready_expression" ON '
                f'"{external_schema}"."subject" '
                f'(("{external_schema}"."fail_build"(id)))'
            )
        connection.execute("RESET ROLE")
        state = connection.execute(
            "SELECT i.indislive,i.indisready FROM pg_index i "
            "JOIN pg_class c ON c.oid=i.indexrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND c.relname='not_ready_expression'",
            (external_schema,),
        ).fetchone()
        assert state == (True, False)
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_reachable_index_opclass_callback_ignores_function_acl(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "index_opclass_callback")
    external_schema = postgres_environment.schema("index_opclass_callback_scope")
    proof_key = "index-opclass-callback"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; "
            "RETURN CASE WHEN $1 < $2 THEN -1 WHEN $1 > $2 THEN 1 ELSE 0 END; "
            "END $function$"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."effect_compare"(BIGINT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1),(2)')
        connection.execute(
            f'CREATE INDEX "effect_index" ON "{external_schema}"."subject" '
            f'USING btree (id "{external_schema}"."effect_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}".'
            '"effect_compare"(BIGINT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (3)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_btree_in_range_support_is_a_select_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "btree_in_range")
    external_schema = postgres_environment.schema("btree_in_range_scope")
    proof_key = "btree-in-range"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_in"(cstring) '
            f'RETURNS "{external_schema}"."effect_type" AS \'int8in\' '
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") RETURNS cstring AS \'int8out\' '
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_type" (INPUT='
            f'"{external_schema}"."effect_in", OUTPUT='
            f'"{external_schema}"."effect_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        for name, internal_name, result in (
            ("lt", "int8lt", "BOOLEAN"),
            ("le", "int8le", "BOOLEAN"),
            ("eq", "int8eq", "BOOLEAN"),
            ("ge", "int8ge", "BOOLEAN"),
            ("gt", "int8gt", "BOOLEAN"),
            ("cmp", "btint8cmp", "INTEGER"),
        ):
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."effect_{name}"('
                f'"{external_schema}"."effect_type",'
                f'"{external_schema}"."effect_type") RETURNS {result} '
                f"AS '{internal_name}' LANGUAGE internal IMMUTABLE STRICT"
            )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_in_range"('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type",BIGINT,BOOLEAN,BOOLEAN) '
            "RETURNS BOOLEAN "
            "LANGUAGE plpgsql SECURITY DEFINER STABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN "
            "pg_catalog.in_range($1::text::bigint,$2::text::bigint,$3,$4,$5); "
            "END $function$"
        )
        for symbol, function in (
            ("<", "effect_lt"),
            ("<=", "effect_le"),
            ("=", "effect_eq"),
            (">=", "effect_ge"),
            (">", "effect_gt"),
        ):
            connection.execute(
                f'CREATE OPERATOR "{external_schema}".{symbol} (LEFTARG='
                f'"{external_schema}"."effect_type", RIGHTARG='
                f'"{external_schema}"."effect_type", FUNCTION='
                f'"{external_schema}"."{function}")'
            )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_ops" '
            f'DEFAULT FOR TYPE "{external_schema}"."effect_type" USING btree AS '
            f'OPERATOR 1 "{external_schema}".< ('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'OPERATOR 2 "{external_schema}".<= ('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'OPERATOR 3 "{external_schema}".= ('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'OPERATOR 4 "{external_schema}".>= ('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'OPERATOR 5 "{external_schema}".> ('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'FUNCTION 1 "{external_schema}"."effect_cmp"('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type"), '
            f'FUNCTION 3 "{external_schema}"."effect_in_range"('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type",BIGINT,BOOLEAN,BOOLEAN)'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.owner_role}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(id "{external_schema}"."effect_type" NOT NULL)'
        )
        connection.execute(
            f"INSERT INTO \"{external_schema}\".\"subject\" VALUES ('1'),('2'),('3')"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_in_range"('
            f'"{external_schema}"."effect_type",'
            f'"{external_schema}"."effect_type",BIGINT,BOOLEAN,BOOLEAN) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        with pytest.raises(
            postgres_environment.modules.psycopg.errors.FeatureNotSupported,
            match="INSERT is not allowed in a non-volatile function",
        ):
            connection.execute(
                f"SELECT count(*) OVER (ORDER BY id RANGE BETWEEN 1 PRECEDING "
                f'AND CURRENT ROW) FROM "{external_schema}"."subject"'
            ).fetchall()
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_reachable_exclusion_operator_callback_ignores_function_acl(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "exclusion_callback")
    external_schema = postgres_environment.schema("exclusion_callback_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_overlap"(box,box) '
            "RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN RETURN $1 OPERATOR(pg_catalog.&&) $2; END $function$"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OPERATOR "{external_schema}".&&& ('
            "LEFTARG=box, RIGHTARG=box, "
            f'PROCEDURE="{external_schema}"."effect_overlap", '
            f'COMMUTATOR=OPERATOR("{external_schema}".&&&))'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_box_ops" '
            "FOR TYPE box USING gist AS "
            f'OPERATOR 3 "{external_schema}".&&& (box,box), '
            "FUNCTION 1 pg_catalog.gist_box_consistent(internal,box,smallint,oid,internal), "
            "FUNCTION 2 pg_catalog.gist_box_union(internal,internal), "
            "FUNCTION 5 pg_catalog.gist_box_penalty(internal,internal,internal), "
            "FUNCTION 6 pg_catalog.gist_box_picksplit(internal,internal), "
            "FUNCTION 7 pg_catalog.gist_box_same(box,box,internal)"
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (area box NOT NULL)'
        )
        connection.execute(
            f'ALTER TABLE "{external_schema}"."subject" ADD CONSTRAINT '
            f'"no_overlap" EXCLUDE USING gist (area '
            f'"{external_schema}"."effect_box_ops" WITH '
            f'OPERATOR("{external_schema}".&&&))'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" '
            "VALUES (box(point(0,0),point(1,1)))"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_overlap"(box,box) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        with pytest.raises(
            postgres_environment.modules.psycopg.errors.ExclusionViolation
        ):
            connection.execute(
                f'INSERT INTO "{external_schema}"."subject" '
                "VALUES (box(point(0,0),point(1,1)))"
            )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_builtin_gist_index_callbacks_are_accepted(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "builtin_gist")
    external_schema = postgres_environment.schema("builtin_gist_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (area box NOT NULL)'
        )
        connection.execute(
            f'CREATE INDEX "area_gist" ON "{external_schema}"."subject" '
            "USING gist (area)"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" '
            "VALUES (box(point(0,0),point(1,1)))"
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_user_defined_builtin_supported_type_graph_is_accepted(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "external_type")
    external_schema = postgres_environment.schema("external_type_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TYPE "{external_schema}"."state" AS ENUM (\'ready\')'
        )
        connection.execute(
            f'CREATE DOMAIN "{external_schema}"."positive_id" AS BIGINT '
            "CHECK (VALUE > 0)"
        )
        connection.execute(f'CREATE TYPE "{external_schema}"."payload" AS (id BIGINT)')
        connection.execute(
            f'CREATE TYPE "{external_schema}"."span" AS RANGE (SUBTYPE=BIGINT)'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."typed_values" '
            f'(state "{external_schema}"."state", '
            f'states "{external_schema}"."state"[], '
            f'id "{external_schema}"."positive_id", '
            f'payload "{external_schema}"."payload", '
            f'span "{external_schema}"."span")'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."typed_values" VALUES '
            "('ready',ARRAY['ready']::"
            f'"{external_schema}"."state"[],1,ROW(1),\'[1,2)\')'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."state",'
            f'"{external_schema}"."positive_id",'
            f'"{external_schema}"."payload",'
            f'"{external_schema}"."span" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT,INSERT ON "{external_schema}"."typed_values" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."typed_values" VALUES '
            "('ready',ARRAY['ready']::"
            f'"{external_schema}"."state"[],2,ROW(2),\'[2,3)\')'
        )
        assert connection.execute(
            f'SELECT count(*) FROM "{external_schema}"."typed_values"'
        ).fetchall() == [(2,)]
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_reachable_custom_type_io_callback_ignores_function_acl(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "custom_type_io")
    external_schema = postgres_environment.schema("custom_type_io_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_in"(cstring) '
            f'RETURNS "{external_schema}"."effect_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_type" ('
            f'INPUT="{external_schema}"."effect_in", '
            f'OUTPUT="{external_schema}"."effect_out", '
            "INTERNALLENGTH=8, PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(value "{external_schema}"."effect_type")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_in"(cstring), '
            f'"{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (\'3\')')
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_reachable_range_canonical_callback_ignores_function_acl(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "range_canonical")
    external_schema = postgres_environment.schema("range_canonical_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_range"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") RETURNS '
            f'"{external_schema}"."effect_range" '
            "AS 'int8range_canonical' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, "
            f'CANONICAL="{external_schema}"."effect_canonical")'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(value "{external_schema}"."effect_range")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_range" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" VALUES (\'[1,4]\')'
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize(
    ("operation", "indexed", "rejected"),
    (("insert", False, False), ("insert", True, True), ("select", False, True)),
)
def test_postgres_range_subdiff_tracks_gist_maintenance_and_select_planning(
    postgres_environment: _PostgresEnvironment,
    operation: str,
    indexed: bool,
    rejected: bool,
) -> None:
    label = f"{operation}_{'indexed' if indexed else 'bare'}"
    schema, _ = _single_store(postgres_environment, f"range_subdiff_{label}")
    external_schema = postgres_environment.schema(f"range_subdiff_scope_{label}")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_subdiff"(BIGINT,BIGINT) '
            "RETURNS DOUBLE PRECISION AS 'int8range_subdiff' "
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, "
            f'SUBTYPE_DIFF="{external_schema}"."effect_subdiff")'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(value "{external_schema}"."effect_range")'
        )
        if indexed:
            connection.execute(
                f'CREATE INDEX "value_gist" ON "{external_schema}"."subject" '
                "USING gist (value)"
            )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}".'
            '"effect_subdiff"(BIGINT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_range" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT {operation.upper()} ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if operation == "insert":
            connection.execute(
                f'INSERT INTO "{external_schema}"."subject" VALUES (\'[1,4]\')'
            )
        else:
            assert (
                connection.execute(
                    f'SELECT value FROM "{external_schema}"."subject"'
                ).fetchall()
                == []
            )
    if rejected:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


def test_postgres_domain_check_dependency_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "domain_check")
    table_schema = postgres_environment.schema("domain_check_table")
    domain_schema = postgres_environment.schema("domain_check_type")
    proof_key = "domain-check-effect"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{domain_schema}"."domain_check"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{domain_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable'); RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE DOMAIN "{domain_schema}"."checked_bigint" AS BIGINT '
            f'CHECK ("{domain_schema}"."domain_check"(VALUE))'
        )
        connection.execute(
            f'CREATE TABLE "{table_schema}"."subject" '
            f'(value "{domain_schema}"."checked_bigint")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{domain_schema}"."domain_check"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{domain_schema}"."domain_check"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{table_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{table_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{table_schema}"."subject" VALUES (1)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("grant_execute", (False, True))
def test_postgres_direct_accessible_domain_check_requires_effective_execute(
    postgres_environment: _PostgresEnvironment,
    grant_execute: bool,
) -> None:
    label = "granted" if grant_execute else "revoked"
    schema, _ = _single_store(postgres_environment, f"direct_domain_check_{label}")
    external_schema = postgres_environment.schema(f"direct_domain_check_scope_{label}")
    proof_key = "direct-domain-check"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_check"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE DOMAIN "{external_schema}"."effect_domain" AS BIGINT '
            f'CHECK ("{external_schema}"."effect_check"(VALUE))'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_check"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_domain" TO '
            f'"{postgres_environment.observer_role}"'
        )
        if grant_execute:
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{external_schema}"."effect_check"'
                f'(BIGINT) TO "{postgres_environment.observer_role}"'
            )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if grant_execute:
            assert connection.execute(
                f'SELECT 1::"{external_schema}"."effect_domain"'
            ).fetchone() == (1,)
        else:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.InsufficientPrivilege
            ):
                connection.execute(f'SELECT 1::"{external_schema}"."effect_domain"')
    if not grant_execute:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
        return
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("grant_execute", (False, True))
def test_postgres_direct_accessible_type_io_requires_effective_execute(
    postgres_environment: _PostgresEnvironment,
    grant_execute: bool,
) -> None:
    label = "granted" if grant_execute else "revoked"
    schema, _ = _single_store(postgres_environment, f"direct_type_io_{label}")
    external_schema = postgres_environment.schema(f"direct_type_io_scope_{label}")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_in"(cstring) '
            f'RETURNS "{external_schema}"."effect_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_type" (INPUT='
            f'"{external_schema}"."effect_in", OUTPUT='
            f'"{external_schema}"."effect_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_in"(cstring), '
            f'"{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.observer_role}"'
        )
        if grant_execute:
            connection.execute(
                f'GRANT EXECUTE ON FUNCTION "{external_schema}"."effect_in"'
                f'(cstring), "{external_schema}"."effect_out"('
                f'"{external_schema}"."effect_type") TO '
                f'"{postgres_environment.observer_role}"'
            )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if grant_execute:
            assert connection.execute(
                f'SELECT \'7\'::"{external_schema}"."effect_type"::text'
            ).fetchone() == ("7",)
        else:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.InsufficientPrivilege
            ):
                connection.execute(
                    f'SELECT \'7\'::"{external_schema}"."effect_type"::text'
                )
    if not grant_execute:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
        return
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_direct_type_without_namespace_usage_is_not_reachable(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "direct_type_no_namespace")
    external_schema = postgres_environment.schema("direct_type_no_namespace_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."hidden_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_in"(cstring) '
            f'RETURNS "{external_schema}"."hidden_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."hidden_type" (INPUT='
            f'"{external_schema}"."hidden_in", OUTPUT='
            f'"{external_schema}"."hidden_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        assert connection.execute(
            "SELECT has_type_privilege(%s, %s, 'USAGE'), "
            "has_schema_privilege(%s, %s, 'USAGE')",
            (
                postgres_environment.observer_role,
                f"{external_schema}.hidden_type",
                postgres_environment.observer_role,
                external_schema,
            ),
        ).fetchone() == (True, False)
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_typmod_and_analyze_callbacks_are_not_ordinary_dml_capabilities(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "type_non_dml_callbacks")
    external_schema = postgres_environment.schema("type_non_dml_callbacks_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_type"')
        function_definitions = (
            ("effect_in", "(cstring)", f'"{external_schema}"."effect_type"', "int8in"),
            (
                "effect_out",
                f'("{external_schema}"."effect_type")',
                "cstring",
                "int8out",
            ),
            ("effect_typmod_in", "(cstring[])", "integer", "varchartypmodin"),
            ("effect_typmod_out", "(integer)", "cstring", "varchartypmodout"),
            ("effect_analyze", "(internal)", "boolean", "array_typanalyze"),
        )
        for name, arguments, return_type, internal_name in function_definitions:
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."{name}"{arguments} '
                f"RETURNS {return_type} AS '{internal_name}' LANGUAGE internal "
                "IMMUTABLE STRICT"
            )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_type" (INPUT='
            f'"{external_schema}"."effect_in", OUTPUT='
            f'"{external_schema}"."effect_out", TYPMOD_IN='
            f'"{external_schema}"."effect_typmod_in", TYPMOD_OUT='
            f'"{external_schema}"."effect_typmod_out", ANALYZE='
            f'"{external_schema}"."effect_analyze", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_in"(cstring), '
            f'"{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type"), '
            f'"{external_schema}"."effect_typmod_in"(cstring[]), '
            f'"{external_schema}"."effect_typmod_out"(integer), '
            f'"{external_schema}"."effect_analyze"(internal) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.observer_role}"'
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_direct_accessible_subscript_handler_ignores_execute_acl(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "direct_subscript")
    external_schema = postgres_environment.schema("direct_subscript_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_in"(cstring) '
            f'RETURNS "{external_schema}"."effect_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_subscript"(internal) '
            "RETURNS internal AS 'array_subscript_handler' "
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_type" (INPUT='
            f'"{external_schema}"."effect_in", OUTPUT='
            f'"{external_schema}"."effect_out", SUBSCRIPT='
            f'"{external_schema}"."effect_subscript", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_in"(cstring), '
            f'"{external_schema}"."effect_out"('
            f'"{external_schema}"."effect_type"), '
            f'"{external_schema}"."effect_subscript"(internal) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_type" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_generated_stored_expression_tracks_updated_dependency_columns(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "generated_dependency")
    external_schema = postgres_environment.schema("generated_dependency_scope")
    proof_key = "generated-dependency"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_write"(BIGINT) '
            "RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN $1; END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_value"(BIGINT) '
            "RETURNS BIGINT LANGUAGE sql SECURITY DEFINER IMMUTABLE "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            f'AS \'SELECT "{external_schema}"."effect_write"($1)\''
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f"(base BIGINT, generated BIGINT GENERATED ALWAYS AS "
            f'("{external_schema}"."effect_value"(base)) STORED)'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject"(base) VALUES (1)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_value"(BIGINT), '
            f'"{external_schema}"."effect_write"(BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT UPDATE(base) ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."effect_value"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'UPDATE "{external_schema}"."subject" SET base=2')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_select_usable_index_callbacks_are_capabilities(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "select_index_callback")
    external_schema = postgres_environment.schema("select_index_callback_scope")
    proof_key = "select-index-callback"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; "
            "RETURN CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END; "
            "END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_equal"(BIGINT,BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN $1=$2; END $function$"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OPERATOR "{external_schema}".=== (LEFTARG=BIGINT, '
            f'RIGHTARG=BIGINT, FUNCTION="{external_schema}"."effect_equal")'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            f'OPERATOR 3 "{external_schema}".=== (BIGINT,BIGINT), '
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."effect_compare"(BIGINT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" '
            "SELECT value FROM generate_series(1,200) value"
        )
        connection.execute(
            f'CREATE INDEX "effect_index" ON "{external_schema}"."subject" '
            f'USING btree (id "{external_schema}"."effect_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(f'VACUUM "{external_schema}"."subject"')
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_compare"'
            f'(BIGINT,BIGINT), "{external_schema}"."effect_equal"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."effect_equal"'
            f'(BIGINT,BIGINT) TO "{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute("SET enable_seqscan=off")
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject" WHERE '
            f'id OPERATOR("{external_schema}".===) 2'
        ).fetchall() == [(2,)]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_spgist_opckeytype_support_callback_is_a_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "spgist_opckeytype")
    external_schema = postgres_environment.schema("spgist_opckeytype_scope")
    proof_key = "spgist-opckeytype"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_write"(POLYGON) '
            "RETURNS BOX LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN box($1); END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_compress"(POLYGON) '
            "RETURNS BOX LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            f'AS \'SELECT "{external_schema}"."effect_write"($1)\''
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_poly_ops" '
            "FOR TYPE POLYGON USING spgist AS "
            "STORAGE BOX, "
            "OPERATOR 1 pg_catalog.<< (POLYGON,POLYGON), "
            "OPERATOR 2 pg_catalog.&< (POLYGON,POLYGON), "
            "OPERATOR 3 pg_catalog.&& (POLYGON,POLYGON), "
            "OPERATOR 4 pg_catalog.&> (POLYGON,POLYGON), "
            "OPERATOR 5 pg_catalog.>> (POLYGON,POLYGON), "
            "OPERATOR 6 pg_catalog.~= (POLYGON,POLYGON), "
            "OPERATOR 7 pg_catalog.@> (POLYGON,POLYGON), "
            "OPERATOR 8 pg_catalog.<@ (POLYGON,POLYGON), "
            "OPERATOR 9 pg_catalog.&<| (POLYGON,POLYGON), "
            "OPERATOR 10 pg_catalog.<<| (POLYGON,POLYGON), "
            "OPERATOR 11 pg_catalog.|>> (POLYGON,POLYGON), "
            "OPERATOR 12 pg_catalog.|&> (POLYGON,POLYGON), "
            "FUNCTION 1 pg_catalog.spg_bbox_quad_config(internal,internal), "
            "FUNCTION 2 pg_catalog.spg_box_quad_choose(internal,internal), "
            "FUNCTION 3 pg_catalog.spg_box_quad_picksplit(internal,internal), "
            "FUNCTION 4 pg_catalog.spg_box_quad_inner_consistent(internal,internal), "
            "FUNCTION 5 pg_catalog.spg_box_quad_leaf_consistent(internal,internal), "
            f'FUNCTION 6 "{external_schema}"."effect_compress"(POLYGON)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (shape POLYGON NOT NULL)'
        )
        connection.execute(
            f'CREATE INDEX "effect_spgist" ON "{external_schema}"."subject" '
            f'USING spgist (shape "{external_schema}"."effect_poly_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_write"(POLYGON), '
            f'"{external_schema}"."effect_compress"(POLYGON) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" VALUES '
            "(polygon '((0,0),(0,1),(1,1),(1,0))')"
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("index_state", ("invalid", "not_live"))
def test_postgres_non_query_usable_index_callback_is_benign_for_select_only(
    postgres_environment: _PostgresEnvironment,
    index_state: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"index_control_{index_state}")
    external_schema = postgres_environment.schema(f"index_control_scope_{index_state}")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER AS 'btint8cmp' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."control_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."compare"(BIGINT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(
            f'CREATE INDEX "control_index" ON "{external_schema}"."subject" '
            f'USING btree (id "{external_schema}"."control_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."compare"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            "UPDATE pg_index SET indisvalid=false, indislive=%s "
            "WHERE indexrelid=%s::regclass",
            (index_state != "not_live", f"{external_schema}.control_index"),
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize(
    ("operation", "valid", "ready", "rejected"),
    (
        ("select", False, True, False),
        ("delete", False, True, False),
        ("select", True, True, True),
        ("insert", False, True, True),
        ("update", False, False, False),
    ),
)
def test_postgres_index_options_callback_uses_operation_specific_index_state(
    postgres_environment: _PostgresEnvironment,
    operation: str,
    valid: bool,
    ready: bool,
    rejected: bool,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"index_options_{operation}_{valid}_{ready}"
    )
    external_schema = postgres_environment.schema(
        f"index_options_scope_{operation}_{valid}_{ready}"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."options"(internal) '
            "RETURNS void AS 'gtsvector_options' LANGUAGE internal IMMUTABLE"
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."options_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.btint8cmp(BIGINT,BIGINT), "
            f'FUNCTION 5 "{external_schema}"."options"(internal)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(
            f'CREATE INDEX "options_index" ON "{external_schema}"."subject" '
            f'(id "{external_schema}"."options_ops" (siglen=1))'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            "UPDATE pg_index SET indisvalid=%s,indisready=%s "
            "WHERE indexrelid=%s::regclass",
            (valid, ready, f"{external_schema}.options_index"),
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT {operation.upper()} ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    if rejected:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


@pytest.mark.parametrize("unused_member", ("same_family_cross_type", "other_family"))
def test_postgres_unused_operator_family_callback_is_benign(
    postgres_environment: _PostgresEnvironment,
    unused_member: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"unused_amproc_{unused_member}")
    external_schema = postgres_environment.schema(
        f"unused_amproc_scope_{unused_member}"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        argument_type = (
            "TEXT" if unused_member == "same_family_cross_type" else "BIGINT"
        )
        internal_name = "bttextcmp" if argument_type == "TEXT" else "btint8cmp"
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."unused_compare"('
            f"{argument_type},{argument_type}) RETURNS INTEGER AS '{internal_name}' "
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE OPERATOR FAMILY "{external_schema}"."used_family" USING btree'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."used_ops" '
            f'FOR TYPE BIGINT USING btree FAMILY "{external_schema}"."used_family" AS '
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.btint8cmp(BIGINT,BIGINT)"
        )
        family = "used_family"
        if unused_member == "other_family":
            family = "unused_family"
            connection.execute(
                f'CREATE OPERATOR FAMILY "{external_schema}"."{family}" USING btree'
            )
        connection.execute(
            f'ALTER OPERATOR FAMILY "{external_schema}"."{family}" USING btree ADD '
            f"FUNCTION 1 ({argument_type},{argument_type}) "
            f'"{external_schema}"."unused_compare"({argument_type},{argument_type})'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(
            f'CREATE INDEX "used_index" ON "{external_schema}"."subject" '
            f'USING btree (id "{external_schema}"."used_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."unused_compare"('
            f"{argument_type},{argument_type}) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("operation", ("SELECT", "INSERT", "UPDATE"))
def test_postgres_column_only_capability_does_not_reach_hidden_column_callbacks(
    postgres_environment: _PostgresEnvironment,
    operation: str,
) -> None:
    label = operation.lower()
    schema, _ = _single_store(postgres_environment, f"column_type_provenance_{label}")
    external_schema = postgres_environment.schema(
        f"column_type_provenance_scope_{label}"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."hidden_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_in"(cstring) '
            f'RETURNS "{external_schema}"."hidden_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."hidden_type" (INPUT='
            f'"{external_schema}"."hidden_in", OUTPUT='
            f'"{external_schema}"."hidden_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'REVOKE ALL ON TYPE "{external_schema}"."hidden_type" FROM PUBLIC'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."hidden_in"(cstring), '
            f'"{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."hidden_type" TO '
            f'"{postgres_environment.owner_role}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(safe BIGINT, hidden "{external_schema}"."hidden_type")'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject"(safe) VALUES (1)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT {operation}(safe) ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            "SELECT has_column_privilege(current_user, %s, 'safe', %s)",
            (f"{external_schema}.subject", operation),
        ).fetchone() == (True,)
        assert connection.execute(
            "SELECT has_type_privilege(current_user, %s, 'USAGE')",
            (f"{external_schema}.hidden_type",),
        ).fetchone() == (False,)
        if operation == "SELECT":
            assert connection.execute(
                f'SELECT safe FROM "{external_schema}"."subject"'
            ).fetchall() == [(1,)]
        elif operation == "INSERT":
            connection.execute(
                f'INSERT INTO "{external_schema}"."subject"(safe) VALUES (2)'
            )
        else:
            connection.execute(f'UPDATE "{external_schema}"."subject" SET safe=2')
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("range_surface", ("range", "multirange", "domain"))
def test_postgres_direct_range_canonical_closure_includes_multirange(
    postgres_environment: _PostgresEnvironment,
    range_surface: str,
) -> None:
    label = range_surface
    schema, _ = _single_store(postgres_environment, f"direct_{label}_canonical")
    external_schema = postgres_environment.schema(f"direct_{label}_canonical_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_range"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") RETURNS '
            f'"{external_schema}"."effect_range" '
            "AS 'int8range_canonical' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, MULTIRANGE_TYPE_NAME="
            f'"{external_schema}"."effect_multirange", '
            f'CANONICAL="{external_schema}"."effect_canonical")'
        )
        connection.execute(
            f'CREATE DOMAIN "{external_schema}"."effect_domain" AS '
            f'"{external_schema}"."effect_range"'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_range" TO '
            f'"{postgres_environment.observer_role}"'
        )
        if range_surface == "domain":
            connection.execute(
                f'GRANT USAGE ON TYPE "{external_schema}"."effect_domain" TO '
                f'"{postgres_environment.observer_role}"'
            )
    range_expression = f'"{external_schema}"."effect_range"(1,4,\'[)\')'
    expression = {
        "range": range_expression,
        "multirange": (f'"{external_schema}"."effect_multirange"({range_expression})'),
        "domain": f'({range_expression})::"{external_schema}"."effect_domain"',
    }[range_surface]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(f"SELECT {expression} IS NOT NULL").fetchone() == (
            True,
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_direct_range_subtype_opclass_callback_is_a_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "range_subtype_opclass")
    external_schema = postgres_environment.schema("range_subtype_opclass_scope")
    proof_key = "range-subtype-opclass"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_write"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; "
            "RETURN CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END; "
            "END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            f'AS \'SELECT "{external_schema}"."effect_write"($1,$2)\''
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_int8_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."effect_compare"(BIGINT,BIGINT)'
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, SUBTYPE_OPCLASS="
            f'"{external_schema}"."effect_int8_ops")'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_write"'
            f'(BIGINT,BIGINT), "{external_schema}"."effect_compare"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_range" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT "{external_schema}"."effect_range"(1,4,\'[)\') IS NOT NULL'
        ).fetchone() == (True,)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_insert_rule_invoker_function_dependency_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "insert_rule_function")
    external_schema = postgres_environment.schema("insert_rule_function_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(f'CREATE TABLE "{external_schema}"."source" (id BIGINT)')
        connection.execute(f'CREATE TABLE "{external_schema}"."effects" (id BIGINT)')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."transform"(BIGINT) '
            "RETURNS BIGINT LANGUAGE sql AS 'SELECT $1 + 1'"
        )
        connection.execute(
            f'CREATE RULE "invoke_transform" AS ON INSERT TO '
            f'"{external_schema}"."source" DO ALSO INSERT INTO '
            f'"{external_schema}"."effects" VALUES '
            f'("{external_schema}"."transform"(NEW.id))'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."transform"(BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."source" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."effects" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."transform"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."source" VALUES (1)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."effects"'
        ).fetchall() == [(2,)]
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("sibling_count", (0, 1, 5))
def test_postgres_attestation_latency_reports_linear_sibling_catalog_cost(
    postgres_environment: _PostgresEnvironment,
    sibling_count: int,
) -> None:
    schema, store = _single_store(postgres_environment, "sibling_latency_target")
    for sibling_number in range(sibling_count):
        if sibling_number % 2:
            _provision_gcb_profile(
                postgres_environment, f"sibling_latency_gcb_{sibling_number}"
            )
        else:
            _single_store(
                postgres_environment, f"sibling_latency_base_{sibling_number}"
            )
    request = _request(
        postgres_environment,
        commit_id=f"sibling-latency-{sibling_count}",
        nonce_byte=127 + sibling_count,
    )
    _advance(postgres_environment, store, request)
    commit_started = time.perf_counter()
    result = store.atomic_commit(request)
    commit_seconds = time.perf_counter() - commit_started
    read_started = time.perf_counter()
    reader = postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    )
    assert reader.get_certificate(request.commit_id) is not None
    reader.close()
    read_seconds = time.perf_counter() - read_started
    assert result.decision.outcome is RequestOutcome.COMMITTED
    print(
        "linear sibling catalog attestation timing: "
        f"siblings={sibling_count} commit={commit_seconds:.6f}s read={read_seconds:.6f}s"
    )
    assert commit_seconds < 5.0 and read_seconds < 5.0


@pytest.mark.parametrize("grantee", ("runtime", "observer", "PUBLIC"))
def test_postgres_parameter_set_grants_fail_closed_and_revocation_recovers(
    postgres_environment: _PostgresEnvironment,
    grantee: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"parameter_acl_{grantee.lower()}")
    grantee_sql = {
        "runtime": f'"{postgres_environment.runtime_role}"',
        "observer": f'"{postgres_environment.observer_role}"',
        "PUBLIC": "PUBLIC",
    }[grantee]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f"GRANT SET ON PARAMETER session_replication_role TO {grantee_sql}"
        )
    try:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.store_factory.open(
                postgres_environment.runtime_dsn,
                schema=schema,
                config=_config(postgres_environment),
                runtime=_runtime(postgres_environment),
            )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(
                f"REVOKE SET ON PARAMETER session_replication_role FROM {grantee_sql}"
            )

    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_active_replica_session_and_replication_trigger_bypass_fail_closed(
    postgres_environment: _PostgresEnvironment,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    schema, _ = _single_store(postgres_environment, "active_replica_setting")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as administrator:
        administrator.execute(
            f"GRANT SET ON PARAMETER session_replication_role TO "
            f'"{postgres_environment.runtime_role}"'
        )
    try:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as administrator:
            checkpoint_before = administrator.execute(
                f'SELECT * FROM "{schema}"."semantic_checkpoint"'
            ).fetchone()
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.runtime_dsn, autocommit=True
        ) as connection:
            connection.execute(f'SET search_path TO pg_catalog,"{schema}",pg_temp')
            connection.execute("SET session_replication_role=replica")
            assert connection.execute(
                "SELECT current_setting('session_replication_role')"
            ).fetchone() == ("replica",)
            connection.execute(
                f'DELETE FROM "{schema}"."candidates" WHERE lifecycle=\'EXECUTING\''
            )
            connection.execute(f'DELETE FROM "{schema}"."workflow_authority"')
            with pytest.raises(ValueError, match="schema validation failed"):
                getattr(store_module, "_semantic_config")(
                    getattr(store_module, "_Connection")(connection), schema
                )
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as administrator:
            checkpoint_after = administrator.execute(
                f'SELECT * FROM "{schema}"."semantic_checkpoint"'
            ).fetchone()
        assert checkpoint_after == checkpoint_before
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as administrator:
            administrator.execute(
                f"REVOKE SET ON PARAMETER session_replication_role FROM "
                f'"{postgres_environment.runtime_role}"'
            )


def test_postgres_origin_replication_setting_without_parameter_acl_is_accepted(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "origin_parameter_setting")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn
    ) as connection:
        assert connection.execute(
            "SELECT current_setting('session_replication_role')"
        ).fetchone() == ("origin",)
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_parameter_alter_system_grant_fails_closed(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "parameter_alter_system")
    runtime_role = postgres_environment.runtime_role
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            "GRANT ALTER SYSTEM ON PARAMETER session_replication_role TO "
            f'"{runtime_role}"'
        )
    try:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(
                "REVOKE ALTER SYSTEM ON PARAMETER session_replication_role FROM "
                f'"{runtime_role}"'
            )

    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


def test_postgres_unrelated_role_parameter_grant_is_isolated(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "unrelated_parameter_acl")
    unrelated_role = f"{postgres_environment.schema_prefix}_unrelated"
    assert len(unrelated_role) <= 63
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE ROLE "{unrelated_role}" NOLOGIN')
        connection.execute(
            f'COMMENT ON ROLE "{unrelated_role}" IS '
            f"'{_schema_owner_comment(postgres_environment.ownership_token)}'"
        )
        connection.execute(
            f'GRANT SET ON PARAMETER session_replication_role TO "{unrelated_role}"'
        )
    try:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            comment = connection.execute(
                "SELECT shobj_description(oid,'pg_authid') FROM pg_roles "
                "WHERE rolname=%s",
                (unrelated_role,),
            ).fetchone()
            assert comment == (
                _schema_owner_comment(postgres_environment.ownership_token),
            )
            connection.execute(
                f"REVOKE SET ON PARAMETER session_replication_role FROM "
                f'"{unrelated_role}"'
            )
            connection.execute(f'DROP ROLE "{unrelated_role}"')


@pytest.mark.parametrize(
    ("trigger_shape", "grantee"),
    (
        ("before_row", "observer"),
        ("after_statement", "PUBLIC"),
        ("deferred_constraint", "runtime"),
        ("partition_leaf", "observer"),
    ),
)
def test_postgres_open_rejects_composed_view_to_trigger_write_capability(
    postgres_environment: _PostgresEnvironment,
    trigger_shape: str,
    grantee: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"composed_trigger_{trigger_shape}_{grantee.lower()}"
    )
    external_schema = postgres_environment.schema(
        f"composed_trigger_scope_{trigger_shape}_{grantee.lower()}"
    )
    proof_key = f"composed-trigger-{trigger_shape}-{grantee.lower()}"
    grantee_sql = {
        "runtime": f'"{postgres_environment.runtime_role}"',
        "observer": f'"{postgres_environment.observer_role}"',
        "PUBLIC": "PUBLIC",
    }[grantee]
    raw_dsn = (
        postgres_environment.runtime_dsn
        if grantee == "runtime"
        else postgres_environment.observer_dsn
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if trigger_shape == "partition_leaf":
            connection.execute(
                f'CREATE TABLE "{external_schema}"."trigger_parent" '
                "(id BIGINT) PARTITION BY RANGE (id)"
            )
            connection.execute(
                f'CREATE TABLE "{external_schema}"."trigger_base" PARTITION OF '
                f'"{external_schema}"."trigger_parent" '
                "FOR VALUES FROM (0) TO (100)"
            )
            write_base = "trigger_parent"
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."trigger_base" (id BIGINT)'
            )
            write_base = "trigger_base"
        connection.execute(
            f'CREATE VIEW "{external_schema}"."trigger_view_a" AS SELECT id FROM '
            f'"{external_schema}"."{write_base}"'
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."trigger_view_b" AS SELECT id FROM '
            f'"{external_schema}"."trigger_view_a"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."composed_trigger"() '
            "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $function$ "
            "BEGIN EXECUTE $dynamic$INSERT INTO "
            f'"{schema}"."metadata"(key,value) VALUES '
            f"('{proof_key}','reachable') ON CONFLICT(key) DO UPDATE "
            "SET value=excluded.value$dynamic$; RETURN NEW; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."composed_trigger"() '
            "FROM PUBLIC"
        )
        if trigger_shape in {"before_row", "partition_leaf"}:
            trigger_sql = (
                f'CREATE TRIGGER "composed_trigger" BEFORE INSERT ON '
                f'"{external_schema}"."trigger_base" FOR EACH ROW EXECUTE FUNCTION '
                f'"{external_schema}"."composed_trigger"()'
            )
        elif trigger_shape == "after_statement":
            trigger_sql = (
                f'CREATE TRIGGER "composed_trigger" AFTER INSERT ON '
                f'"{external_schema}"."trigger_base" REFERENCING NEW TABLE AS rows '
                "FOR EACH STATEMENT EXECUTE FUNCTION "
                f'"{external_schema}"."composed_trigger"()'
            )
        else:
            trigger_sql = (
                f'CREATE CONSTRAINT TRIGGER "composed_trigger" AFTER INSERT ON '
                f'"{external_schema}"."trigger_base" DEFERRABLE INITIALLY DEFERRED '
                "FOR EACH ROW EXECUTE FUNCTION "
                f'"{external_schema}"."composed_trigger"()'
            )
        connection.execute(trigger_sql)
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO {grantee_sql}'
        )
        connection.execute(
            f'GRANT INSERT(id) ON "{external_schema}"."trigger_view_b" TO {grantee_sql}'
        )
    with postgres_environment.modules.psycopg.connect(
        raw_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."trigger_view_b"(id) VALUES (1)'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("capability", ("direct_column", "view_proxy", "select_only"))
def test_postgres_foreign_write_surfaces_are_opaque_and_fail_closed(
    postgres_environment: _PostgresEnvironment,
    capability: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"fdw_{capability}")
    external_schema = postgres_environment.schema(f"fdw_surface_{capability}")
    remote_schema = postgres_environment.schema(f"fdw_remote_{capability}")
    server = f"{postgres_environment.schema_prefix}_fdw_{capability}"
    assert len(server) <= 63
    extension_was_installed = False
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        extension_was_installed = (
            connection.execute(
                "SELECT 1 FROM pg_extension WHERE extname='postgres_fdw'"
            ).fetchone()
            is not None
        )
        if not extension_was_installed:
            connection.execute("CREATE EXTENSION postgres_fdw")
        connection.execute(
            f'CREATE TABLE "{remote_schema}"."remote_effect" '
            "(id BIGINT PRIMARY KEY,payload TEXT NOT NULL)"
        )
        connection.execute(
            f'CREATE SERVER "{server}" FOREIGN DATA WRAPPER postgres_fdw '
            "OPTIONS (dbname 'apcc_test')"
        )
        connection.execute(
            f'CREATE USER MAPPING FOR "{postgres_environment.observer_role}" '
            f"SERVER \"{server}\" OPTIONS (user 'apcc',password_required 'false')"
        )
        connection.execute(
            f'CREATE USER MAPPING FOR CURRENT_USER SERVER "{server}" '
            "OPTIONS (user 'apcc',password_required 'false')"
        )
        connection.execute(
            f'CREATE FOREIGN TABLE "{external_schema}"."foreign_effect" '
            "(id BIGINT,payload TEXT) "
            f"SERVER \"{server}\" OPTIONS (schema_name '{remote_schema}',"
            "table_name 'remote_effect')"
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."foreign_effect_view" AS SELECT '
            f'id,payload FROM "{external_schema}"."foreign_effect"'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        target = (
            "foreign_effect_view" if capability == "view_proxy" else "foreign_effect"
        )
        privilege = "SELECT" if capability == "select_only" else "INSERT(id,payload)"
        connection.execute(
            f'GRANT {privilege} ON "{external_schema}"."{target}" TO '
            f'"{postgres_environment.observer_role}"'
        )
    try:
        if capability != "select_only":
            with postgres_environment.modules.psycopg.connect(
                postgres_environment.observer_dsn, autocommit=True
            ) as connection:
                connection.execute(
                    f'INSERT INTO "{external_schema}"."{target}"(id,payload) '
                    "VALUES (1,'remote-write')"
                )
            with postgres_environment.modules.psycopg.connect(
                postgres_environment.dsn, autocommit=True
            ) as connection:
                assert connection.execute(
                    f'SELECT payload FROM "{remote_schema}"."remote_effect" WHERE id=1'
                ).fetchone() == ("remote-write",)
            with pytest.raises(ValueError, match="schema validation failed"):
                postgres_environment.modules.reader_factory.open(
                    postgres_environment.observer_dsn, schema=schema
                )
        else:
            with pytest.raises(ValueError, match="schema validation failed"):
                postgres_environment.modules.reader_factory.open(
                    postgres_environment.observer_dsn, schema=schema
                )
    finally:
        with postgres_environment.modules.psycopg.connect(
            postgres_environment.dsn, autocommit=True
        ) as connection:
            connection.execute(f'DROP SERVER "{server}" CASCADE')
            if not extension_was_installed:
                connection.execute("DROP EXTENSION postgres_fdw")


@pytest.mark.parametrize(
    ("operation", "action", "grantee"),
    (
        ("DELETE", "CASCADE", "observer"),
        ("DELETE", "SET NULL", "PUBLIC"),
        ("UPDATE", "SET DEFAULT", "runtime"),
    ),
)
def test_postgres_composed_view_to_fk_actions_fail_closed(
    postgres_environment: _PostgresEnvironment,
    operation: str,
    action: str,
    grantee: str,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    label = f"view_fk_{operation.lower()}_{action.lower().replace(' ', '_')}"
    schema, _ = _single_store(postgres_environment, label)
    external_schema = postgres_environment.schema(f"{label}_external")
    grantee_sql = {
        "runtime": f'"{postgres_environment.runtime_role}"',
        "observer": f'"{postgres_environment.observer_role}"',
        "PUBLIC": "PUBLIC",
    }[grantee]
    raw_dsn = (
        postgres_environment.runtime_dsn
        if grantee == "runtime"
        else postgres_environment.observer_dsn
    )
    action_clause = f"ON {operation} {action}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."same_name" (id BIGINT PRIMARY KEY)'
        )
        connection.execute(
            f'CREATE TABLE "{schema}"."same_name" '
            "(child_id BIGINT PRIMARY KEY,parent_id BIGINT DEFAULT 0,"
            f'FOREIGN KEY(parent_id) REFERENCES "{external_schema}"."same_name"(id) '
            f"{action_clause})"
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."same_name" VALUES (0),(1)'
        )
        connection.execute(f'INSERT INTO "{schema}"."same_name" VALUES (10,1)')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."parent_view" AS SELECT id FROM '
            f'"{external_schema}"."same_name"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO {grantee_sql}'
        )
        privilege = "UPDATE(id)" if operation == "UPDATE" else "DELETE"
        connection.execute(
            f'GRANT {privilege} ON "{external_schema}"."parent_view" TO {grantee_sql}'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."parent_view" TO {grantee_sql}'
        )
    with postgres_environment.modules.psycopg.connect(
        raw_dsn, autocommit=True
    ) as connection:
        if operation == "UPDATE":
            connection.execute(
                f'UPDATE "{external_schema}"."parent_view" SET id=2 WHERE id=1'
            )
        else:
            connection.execute(
                f'DELETE FROM "{external_schema}"."parent_view" WHERE id=1'
            )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        child = connection.execute(
            f'SELECT parent_id FROM "{schema}"."same_name" WHERE child_id=10'
        ).fetchone()
        if action == "CASCADE":
            assert child is None
        elif action == "SET NULL":
            assert child == (None,)
        else:
            assert child == (0,)
        wrapped = getattr(store_module, "_Connection")(connection)
        with pytest.raises(ValueError, match="schema validation failed"):
            getattr(store_module, "_validate_external_capability_contract")(
                wrapped,
                schema,
                postgres_environment.runtime_role,
                postgres_environment.observer_role,
            )

    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("action", ("NO ACTION", "RESTRICT"))
def test_postgres_non_mutating_external_fk_actions_remain_benign(
    postgres_environment: _PostgresEnvironment,
    action: str,
) -> None:
    store_module = importlib.import_module("constitutional_swarm.apcc.postgres_store")
    label = f"benign_fk_{action.lower().replace(' ', '_')}"
    schema, _ = _single_store(postgres_environment, label)
    external_schema = postgres_environment.schema(f"{label}_external")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."same_name" (id BIGINT PRIMARY KEY)'
        )
        connection.execute(
            f'CREATE TABLE "{schema}"."same_name" '
            "(child_id BIGINT PRIMARY KEY,parent_id BIGINT,"
            f'FOREIGN KEY(parent_id) REFERENCES "{external_schema}"."same_name"(id) '
            f"ON DELETE {action})"
        )
        connection.execute(f'INSERT INTO "{external_schema}"."same_name" VALUES (1)')
        connection.execute(f'INSERT INTO "{schema}"."same_name" VALUES (10,1)')
        connection.execute(
            f'CREATE VIEW "{external_schema}"."parent_view" AS SELECT id FROM '
            f'"{external_schema}"."same_name"'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT DELETE ON "{external_schema}"."parent_view" TO '
            f'"{postgres_environment.observer_role}"'
        )
        wrapped = getattr(store_module, "_Connection")(connection)
        getattr(store_module, "_validate_external_capability_contract")(
            wrapped,
            schema,
            postgres_environment.runtime_role,
            postgres_environment.observer_role,
        )
        getattr(store_module, "_validate_foreign_key_integrity")(wrapped, schema)


def test_postgres_relation_multirange_reaches_range_canonical_without_type_usage(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "relation_multirange_canonical")
    external_schema = postgres_environment.schema("relation_multirange_canonical_scope")
    proof_key = "relation-multirange-canonical"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."effect_range"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") RETURNS '
            f'"{external_schema}"."effect_range" '
            "AS 'int8range_canonical' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, MULTIRANGE_TYPE_NAME="
            f'"{external_schema}"."effect_multirange", '
            f'CANONICAL="{external_schema}"."effect_canonical")'
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_write"('
            f'"{external_schema}"."effect_range") RETURNS '
            f'"{external_schema}"."effect_range" '
            "LANGUAGE plpgsql SECURITY DEFINER VOLATILE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN $1; END $function$"
        )
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range") RETURNS '
            f'"{external_schema}"."effect_range" '
            "LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            f'AS \'SELECT "{external_schema}"."effect_write"($1)\''
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(value "{external_schema}"."effect_multirange")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON TYPE "{external_schema}"."effect_range", '
            f'"{external_schema}"."subject" FROM PUBLIC'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."effect_canonical"('
            f'"{external_schema}"."effect_range"), '
            f'"{external_schema}"."effect_write"('
            f'"{external_schema}"."effect_range") FROM PUBLIC'
        )
        assert connection.execute(
            "SELECT has_type_privilege(%s,%s::regtype,'USAGE'),"
            "has_type_privilege(%s,%s::regtype,'USAGE'),"
            "has_type_privilege(%s,%s::regtype,'USAGE')",
            (
                postgres_environment.observer_role,
                f'"{external_schema}"."effect_range"',
                postgres_environment.observer_role,
                f'"{external_schema}"."effect_multirange"',
                postgres_environment.observer_role,
                f'"{external_schema}"."subject"',
            ),
        ).fetchone() == (False, False, False)
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" VALUES (\'{{[1,4)}}\')'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_callable_hidden_domain_signature_reaches_bound_check(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "callable_hidden_domain")
    external_schema = postgres_environment.schema("callable_hidden_domain_scope")
    hidden_schema = postgres_environment.schema("callable_hidden_domain_hidden")
    proof_key = "callable-hidden-domain"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_check"(BIGINT) '
            "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN true; END $function$"
        )
        connection.execute(
            f'CREATE DOMAIN "{hidden_schema}"."hidden_domain" AS BIGINT '
            f'CHECK ("{hidden_schema}"."effect_check"(VALUE))'
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."make_hidden"(BIGINT) '
            f'RETURNS "{hidden_schema}"."hidden_domain" LANGUAGE sql '
            "AS 'SELECT $1'"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON TYPE "{hidden_schema}"."hidden_domain" FROM PUBLIC'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{hidden_schema}"."effect_check"(BIGINT), '
            f'"{external_schema}"."make_hidden"(BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{hidden_schema}"."effect_check"(BIGINT), '
            f'"{external_schema}"."make_hidden"(BIGINT) TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT "{external_schema}"."make_hidden"(1)'
        ).fetchone() == (1,)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_partition_key_expression_is_a_routing_capability(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "partition_expression")
    external_schema = postgres_environment.schema("partition_expression_scope")
    hidden_schema = postgres_environment.schema("partition_expression_hidden")
    proof_key = "partition-expression"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_write"(BIGINT) '
            "RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN $1; END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_key"(BIGINT) '
            "RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT "
            f'RETURN "{hidden_schema}"."effect_write"($1)'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f'PARTITION BY RANGE (("{external_schema}"."effect_key"(id)))'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_low" PARTITION OF '
            f'"{external_schema}"."subject" FOR VALUES FROM (0) TO (10)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{hidden_schema}"."effect_write"(BIGINT), '
            f'"{external_schema}"."effect_key"(BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."effect_key"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{hidden_schema}"."effect_write"(BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("orientation", ("forward", "reverse"))
def test_postgres_queryable_cross_type_btree_support_is_a_capability(
    postgres_environment: _PostgresEnvironment,
    orientation: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"cross_type_btree_{orientation}")
    external_schema = postgres_environment.schema(
        f"cross_type_btree_scope_{orientation}"
    )
    hidden_schema = postgres_environment.schema(
        f"cross_type_btree_hidden_{orientation}"
    )
    proof_key = "cross-type-btree"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_equal"(BIGINT,TEXT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS 'SELECT $1=$2::BIGINT'"
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_compare_write"(BIGINT,TEXT) '
            "RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER VOLATILE STRICT "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            "AS $function$ DECLARE right_value BIGINT := $2::BIGINT; BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN CASE WHEN $1<right_value "
            "THEN -1 WHEN $1>right_value THEN 1 ELSE 0 END; END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_compare"(BIGINT,TEXT) '
            "RETURNS INTEGER LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            f'AS \'SELECT "{hidden_schema}"."effect_compare_write"($1,$2)\''
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect_less"(BIGINT,TEXT) '
            "RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            f'AS \'SELECT "{hidden_schema}"."effect_compare_write"($1,$2)<0\''
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."reverse_equal"(TEXT,BIGINT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT $1::BIGINT=$2'"
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."reverse_greater"(TEXT,BIGINT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT $1::BIGINT>$2'"
        )
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."reverse_compare"(TEXT,BIGINT) '
            "RETURNS INTEGER LANGUAGE sql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            f'AS \'SELECT -"{hidden_schema}"."effect_compare_write"($2,$1)\''
        )
        connection.execute("RESET ROLE")
        if orientation == "forward":
            connection.execute(
                f'CREATE OPERATOR "{external_schema}".<~ (LEFTARG=BIGINT, '
                f'RIGHTARG=TEXT, FUNCTION="{hidden_schema}"."effect_less")'
            )
        else:
            connection.execute(
                f'CREATE OPERATOR "{external_schema}".~> (LEFTARG=TEXT, '
                f'RIGHTARG=BIGINT, FUNCTION="{hidden_schema}"."reverse_greater")'
            )
        connection.execute(
            f'CREATE OPERATOR FAMILY "{external_schema}"."effect_family" USING btree'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."effect_ops" '
            f'FOR TYPE BIGINT USING btree FAMILY "{external_schema}"."effect_family" AS '
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.btint8cmp(BIGINT,BIGINT)"
        )
        cross_members = (
            f'OPERATOR 1 "{external_schema}".<~ (BIGINT,TEXT), '
            f'FUNCTION 1 (BIGINT,TEXT) "{hidden_schema}"."effect_compare"(BIGINT,TEXT)'
            if orientation == "forward"
            else f'OPERATOR 5 "{external_schema}".~> (TEXT,BIGINT), '
            f'FUNCTION 1 (TEXT,BIGINT) "{hidden_schema}"."reverse_compare"(TEXT,BIGINT)'
        )
        connection.execute(
            f'ALTER OPERATOR FAMILY "{external_schema}"."effect_family" USING btree '
            f"ADD {cross_members}"
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT NOT NULL)'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" '
            "SELECT value FROM pg_catalog.generate_series(1,5000) AS value"
        )
        connection.execute(
            f'CREATE INDEX "effect_index" ON "{external_schema}"."subject" '
            f'USING btree (id "{external_schema}"."effect_ops")'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{hidden_schema}"."effect_equal"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_less"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_compare"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_compare_write"(BIGINT,TEXT), '
            f'"{hidden_schema}"."reverse_equal"(TEXT,BIGINT), '
            f'"{hidden_schema}"."reverse_greater"(TEXT,BIGINT), '
            f'"{hidden_schema}"."reverse_compare"(TEXT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{hidden_schema}"."effect_equal"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_less"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_compare"(BIGINT,TEXT), '
            f'"{hidden_schema}"."effect_compare_write"(BIGINT,TEXT), '
            f'"{hidden_schema}"."reverse_equal"(TEXT,BIGINT), '
            f'"{hidden_schema}"."reverse_greater"(TEXT,BIGINT), '
            f'"{hidden_schema}"."reverse_compare"(TEXT,BIGINT) TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute("SET enable_seqscan=off")
        connection.execute("SET enable_bitmapscan=off")
        plan = "\n".join(
            row[0]
            for row in connection.execute(
                f'EXPLAIN (COSTS OFF) SELECT id FROM "{external_schema}"."subject" '
                + (
                    f"WHERE id OPERATOR(\"{external_schema}\".<~) '150'::TEXT"
                    if orientation == "forward"
                    else f"WHERE '150'::TEXT OPERATOR(\"{external_schema}\".~>) id"
                )
            ).fetchall()
        )
        assert "Index Only Scan" in plan
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject" '
            + (
                f"WHERE id OPERATOR(\"{external_schema}\".<~) '150'::TEXT"
                if orientation == "forward"
                else f"WHERE '150'::TEXT OPERATOR(\"{external_schema}\".~>) id"
            )
        ).fetchall() == [(value,) for value in range(1, 150)]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if orientation == "forward":
            assert connection.execute(
                f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
            ).fetchone() == ("reachable",)
        else:
            assert (
                connection.execute(
                    f'SELECT value FROM "{schema}"."metadata" WHERE key=%s',
                    (proof_key,),
                ).fetchone()
                is None
            )
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    if orientation == "forward":
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


@pytest.mark.parametrize("orientation", ("direct", "commuted"))
def test_postgres_partition_pruning_reaches_key_left_cross_type_operator(
    postgres_environment: _PostgresEnvironment,
    orientation: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"partition_cross_type_{orientation}"
    )
    external_schema = postgres_environment.schema(
        f"partition_cross_type_scope_{orientation}"
    )
    proof_key = "partition-cross-type"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."cross_less"(BIGINT,TEXT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT $1 < $2::BIGINT'"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."cross_compare"(BIGINT,TEXT) '
            "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT CASE WHEN $1<$2::BIGINT THEN -1 WHEN $1>$2::BIGINT "
            "THEN 1 ELSE 0 END'"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."cross_greater"(TEXT,BIGINT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT $1::BIGINT > $2'"
        )
        connection.execute(
            f'CREATE OPERATOR "{external_schema}".<~ (LEFTARG=BIGINT, '
            f'RIGHTARG=TEXT, FUNCTION="{external_schema}"."cross_less")'
        )
        connection.execute(
            f'CREATE OPERATOR "{external_schema}".~> (LEFTARG=TEXT, '
            f'RIGHTARG=BIGINT, FUNCTION="{external_schema}"."cross_greater", '
            f'COMMUTATOR=OPERATOR("{external_schema}".<~))'
        )
        connection.execute(
            f'CREATE OPERATOR FAMILY "{external_schema}"."partition_family" USING btree'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."partition_ops" '
            f'FOR TYPE BIGINT USING btree FAMILY "{external_schema}"."partition_family" '
            "AS OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.btint8cmp(BIGINT,BIGINT)"
        )
        connection.execute(
            f'ALTER OPERATOR FAMILY "{external_schema}"."partition_family" USING '
            f'btree ADD OPERATOR 1 "{external_schema}".<~ (BIGINT,TEXT), '
            f'OPERATOR 5 "{external_schema}".~> (TEXT,BIGINT), '
            f'FUNCTION 1 (BIGINT,TEXT) "{external_schema}"."cross_compare"(BIGINT,TEXT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f'PARTITION BY RANGE (id "{external_schema}"."partition_ops")'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_low" PARTITION OF '
            f'"{external_schema}"."subject" FOR VALUES FROM (0) TO (100)'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_high" PARTITION OF '
            f'"{external_schema}"."subject" FOR VALUES FROM (100) TO (200)'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" VALUES (10),(110)'
        )
        if orientation == "commuted":
            plan = "\n".join(
                row[0]
                for row in connection.execute(
                    f'EXPLAIN (COSTS OFF) SELECT id FROM "{external_schema}"."subject" '
                    f"WHERE '50'::TEXT OPERATOR(\"{external_schema}\".~>) id"
                ).fetchall()
            )
            assert "subject_low" in plan
            assert "subject_high" not in plan
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."cross_less"('
            "BIGINT,TEXT) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE STRICT "
            "AS $function$ BEGIN RETURN $1<$2::BIGINT; END $function$"
        )
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."cross_greater"('
            "TEXT,BIGINT) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE STRICT "
            "AS $function$ BEGIN RETURN $1::BIGINT>$2; END $function$"
        )
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."cross_compare"('
            "BIGINT,TEXT) RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER "
            "IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN CASE WHEN $1<$2::BIGINT "
            "THEN -1 WHEN $1>$2::BIGINT THEN 1 ELSE 0 END; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."cross_compare"(BIGINT,TEXT), '
            f'"{external_schema}"."cross_less"(BIGINT,TEXT), '
            f'"{external_schema}"."cross_greater"(TEXT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."cross_less"(BIGINT,TEXT), '
            f'"{external_schema}"."cross_greater"(TEXT,BIGINT) '
            f'TO "{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute("SET plan_cache_mode=force_generic_plan")
        connection.execute(
            f"PREPARE partition_cross_probe(TEXT) AS SELECT id FROM "
            f'"{external_schema}"."subject" WHERE '
            + (
                f'id OPERATOR("{external_schema}".<~) $1'
                if orientation == "direct"
                else f'$1 OPERATOR("{external_schema}".~>) id'
            )
        )
        with pytest.raises(
            postgres_environment.modules.psycopg.errors.FeatureNotSupported,
            match="INSERT is not allowed in a non-volatile function",
        ):
            connection.execute("EXECUTE partition_cross_probe('50')").fetchall()
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("strategy", ("list", "range", "hash"))
def test_postgres_builtin_partition_routing_and_pruning_are_accepted(
    postgres_environment: _PostgresEnvironment,
    strategy: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"partition_builtin_{strategy}")
    external_schema = postgres_environment.schema(f"partition_builtin_{strategy}_scope")
    partition_spec = {
        "list": "LIST (id)",
        "range": "RANGE (id)",
        "hash": "HASH (id)",
    }[strategy]
    leaf_spec = {
        "list": "FOR VALUES IN (1)",
        "range": "FOR VALUES FROM (0) TO (10)",
        "hash": "FOR VALUES WITH (MODULUS 1, REMAINDER 0)",
    }[strategy]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f"PARTITION BY {partition_spec}"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
            f'"{external_schema}"."subject" {leaf_spec}'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT,INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject" WHERE id=1'
        ).fetchall() == [(1,)]
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("strategy", ("list", "range", "hash"))
@pytest.mark.parametrize("operation", ("select", "insert", "delete", "truncate"))
def test_postgres_partition_support_callback_matches_runtime_operation(
    postgres_environment: _PostgresEnvironment,
    strategy: str,
    operation: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"partition_support_{strategy}_{operation}"
    )
    external_schema = postgres_environment.schema(
        f"partition_support_scope_{strategy}_{operation}"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if strategy == "hash":
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."route_support"(BIGINT,BIGINT) '
                "RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT AS "
                "'SELECT pg_catalog.hashint8extended($1,$2)'"
            )
            connection.execute(
                f'CREATE OPERATOR CLASS "{external_schema}"."route_ops" '
                "FOR TYPE BIGINT USING hash AS "
                "OPERATOR 1 pg_catalog.= (BIGINT,BIGINT), "
                "FUNCTION 1 pg_catalog.hashint8(BIGINT), "
                f'FUNCTION 2 "{external_schema}"."route_support"(BIGINT,BIGINT)'
            )
            partition_spec = f'HASH (id "{external_schema}"."route_ops")'
            leaf_spec = "FOR VALUES WITH (MODULUS 2, REMAINDER 0)"
        else:
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."route_support"(BIGINT,BIGINT) '
                "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
                "'SELECT CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END'"
            )
            connection.execute(
                f'CREATE OPERATOR CLASS "{external_schema}"."route_ops" '
                "FOR TYPE BIGINT USING btree AS "
                "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
                "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
                "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
                "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
                "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
                f'FUNCTION 1 "{external_schema}"."route_support"(BIGINT,BIGINT)'
            )
            partition_spec = f'{strategy.upper()} (id "{external_schema}"."route_ops")'
            leaf_spec = (
                "FOR VALUES IN (1)"
                if strategy == "list"
                else "FOR VALUES FROM (0) TO (10)"
            )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f"PARTITION BY {partition_spec}"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
            f'"{external_schema}"."subject" {leaf_spec}'
        )
        extra_leaf_spec = {
            "list": "DEFAULT",
            "range": "FOR VALUES FROM (10) TO (20)",
            "hash": "FOR VALUES WITH (MODULUS 2, REMAINDER 1)",
        }[strategy]
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_other" PARTITION OF '
            f'"{external_schema}"."subject" {extra_leaf_spec}'
        )
        if operation != "insert":
            connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (1)')
        connection.execute("RESET ROLE")
        result_type = "BIGINT" if strategy == "hash" else "INTEGER"
        pure_result = (
            "pg_catalog.hashint8extended($1,$2)"
            if strategy == "hash"
            else "CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END"
        )
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."route_support"('
            f"BIGINT,BIGINT) RETURNS {result_type} LANGUAGE plpgsql SECURITY DEFINER "
            "IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            "VALUES ('partition-support','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN "
            f"{pure_result}; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."route_support"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT {operation.upper()} ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    statement = {
        "select": f'SELECT id FROM "{external_schema}"."subject" WHERE id=$1',
        "insert": f'INSERT INTO "{external_schema}"."subject" VALUES (1)',
        "delete": f'DELETE FROM "{external_schema}"."subject"',
        "truncate": f'TRUNCATE "{external_schema}"."subject"',
    }[operation]
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if operation == "select":
            connection.execute("SET plan_cache_mode=force_generic_plan")
            connection.execute(f"PREPARE partition_probe(BIGINT) AS {statement}")
            statement = "EXECUTE partition_probe(1)"
        callback_reached = operation in {"select", "insert"} or (
            operation == "delete" and strategy == "range"
        )
        if callback_reached:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.FeatureNotSupported,
                match="INSERT is not allowed in a non-volatile function",
            ):
                connection.execute(statement)
        else:
            connection.execute(statement)
    if callback_reached:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


def test_postgres_reverse_only_partition_family_member_is_benign_for_bigint_key(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "partition_reverse_only")
    external_schema = postgres_environment.schema("partition_reverse_only_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."reverse_greater"(TEXT,BIGINT) '
            "RETURNS BOOLEAN LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT $1::BIGINT>$2'"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."reverse_compare"(TEXT,BIGINT) '
            "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT CASE WHEN $1::BIGINT<$2 THEN -1 WHEN $1::BIGINT>$2 "
            "THEN 1 ELSE 0 END'"
        )
        connection.execute(
            f'CREATE OPERATOR "{external_schema}".~> (LEFTARG=TEXT,RIGHTARG=BIGINT,'
            f'FUNCTION="{external_schema}"."reverse_greater")'
        )
        connection.execute(
            f'CREATE OPERATOR FAMILY "{external_schema}"."partition_family" USING btree'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."partition_ops" '
            f'FOR TYPE BIGINT USING btree FAMILY "{external_schema}"."partition_family" '
            "AS OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.btint8cmp(BIGINT,BIGINT)"
        )
        connection.execute(
            f'ALTER OPERATOR FAMILY "{external_schema}"."partition_family" USING '
            f'btree ADD OPERATOR 5 "{external_schema}".~> (TEXT,BIGINT), '
            f'FUNCTION 1 (TEXT,BIGINT) "{external_schema}"."reverse_compare"(TEXT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f'PARTITION BY RANGE (id "{external_schema}"."partition_ops")'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
            f'"{external_schema}"."subject" FOR VALUES FROM (0) TO (100)'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (10)')
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."reverse_greater"(TEXT,BIGINT),'
            f'"{external_schema}"."reverse_compare"(TEXT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."reverse_greater"'
            f'(TEXT,BIGINT) TO "{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject" WHERE '
            f"'50'::TEXT OPERATOR(\"{external_schema}\".~>) id"
        ).fetchall() == [(10,)]
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("support_pair", ("probe_probe", "key_probe"))
def test_postgres_hash_partition_cross_type_support_uses_probe_pair(
    postgres_environment: _PostgresEnvironment,
    support_pair: str,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"partition_hash_cross_{support_pair}"
    )
    external_schema = postgres_environment.schema(
        f"partition_hash_cross_{support_pair}_scope"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."probe_hash"(INTEGER,BIGINT) '
            "RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT pg_catalog.hashint4extended($1,$2)'"
        )
        connection.execute(
            f'CREATE OPERATOR FAMILY "{external_schema}"."partition_family" USING hash'
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."partition_ops" '
            f'FOR TYPE BIGINT USING hash FAMILY "{external_schema}"."partition_family" '
            "AS OPERATOR 1 pg_catalog.= (BIGINT,BIGINT), "
            "FUNCTION 1 pg_catalog.hashint8(BIGINT), "
            "FUNCTION 2 pg_catalog.hashint8extended(BIGINT,BIGINT)"
        )
        pair = "INTEGER,INTEGER" if support_pair == "probe_probe" else "BIGINT,INTEGER"
        connection.execute(
            f'ALTER OPERATOR FAMILY "{external_schema}"."partition_family" USING hash '
            "ADD OPERATOR 1 pg_catalog.= (BIGINT,INTEGER), "
            f'FUNCTION 2 ({pair}) "{external_schema}"."probe_hash"(INTEGER,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id BIGINT) '
            f'PARTITION BY HASH (id "{external_schema}"."partition_ops")'
        )
        for remainder in (0, 1):
            connection.execute(
                f'CREATE TABLE "{external_schema}"."subject_{remainder}" PARTITION OF '
                f'"{external_schema}"."subject" FOR VALUES WITH '
                f"(MODULUS 2, REMAINDER {remainder})"
            )
        connection.execute(
            f'INSERT INTO "{external_schema}"."subject" VALUES (10),(11)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."probe_hash"(INTEGER,BIGINT) '
            "RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            "VALUES ('partition-hash-cross','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; "
            "RETURN pg_catalog.hashint4extended($1,$2); END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."probe_hash"(INTEGER,BIGINT) '
            "FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute("SET plan_cache_mode=force_generic_plan")
        connection.execute(
            f"PREPARE partition_hash_probe(INTEGER) AS SELECT id FROM "
            f'"{external_schema}"."subject" WHERE '
            "id OPERATOR(pg_catalog.=) $1"
        )
        if support_pair == "probe_probe":
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.FeatureNotSupported,
                match="INSERT is not allowed in a non-volatile function",
            ):
                connection.execute("EXECUTE partition_hash_probe('10')").fetchall()
        else:
            assert connection.execute(
                "EXECUTE partition_hash_probe('10')"
            ).fetchall() == [(10,)]
    if support_pair == "probe_probe":
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


def test_postgres_multikey_partition_ordinal_alignment_is_accepted(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "partition_multikey")
    external_schema = postgres_environment.schema("partition_multikey_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            "(first_key BIGINT, mixed_key TEXT, last_key BIGINT, extra_key TEXT) "
            "PARTITION BY RANGE (first_key pg_catalog.int8_ops, "
            '(pg_catalog.lower(mixed_key) COLLATE "C") pg_catalog.text_ops, '
            "last_key pg_catalog.int8_ops, "
            "(pg_catalog.length(extra_key)) pg_catalog.int4_ops)"
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_default" PARTITION OF '
            f'"{external_schema}"."subject" DEFAULT'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT,INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        connection.execute(
            f"INSERT INTO \"{external_schema}\".\"subject\" VALUES (1,'Mixed',2,'tail')"
        )
        assert connection.execute(
            f"SELECT first_key,mixed_key,last_key,extra_key FROM "
            f'"{external_schema}"."subject"'
        ).fetchall() == [(1, "Mixed", 2, "tail")]
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize("strategy", ("range", "hash"))
def test_postgres_multikey_partition_second_key_support_is_rejected(
    postgres_environment: _PostgresEnvironment,
    strategy: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"partition_ordinal2_{strategy}")
    external_schema = postgres_environment.schema(
        f"partition_ordinal2_{strategy}_scope"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        if strategy == "hash":
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."second_support"(BIGINT,BIGINT) '
                "RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT AS "
                "'SELECT pg_catalog.hashint8extended($1,$2)'"
            )
            connection.execute(
                f'CREATE OPERATOR CLASS "{external_schema}"."second_ops" '
                "FOR TYPE BIGINT USING hash AS OPERATOR 1 pg_catalog.= (BIGINT,BIGINT), "
                "FUNCTION 1 pg_catalog.hashint8(BIGINT), "
                f'FUNCTION 2 "{external_schema}"."second_support"(BIGINT,BIGINT)'
            )
            partition_spec = (
                f'HASH (first_key, second_key "{external_schema}"."second_ops", '
                "third_key)"
            )
        else:
            connection.execute(
                f'CREATE FUNCTION "{external_schema}"."second_support"(BIGINT,BIGINT) '
                "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
                "'SELECT CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END'"
            )
            connection.execute(
                f'CREATE OPERATOR CLASS "{external_schema}"."second_ops" '
                "FOR TYPE BIGINT USING btree AS "
                "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
                "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
                "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
                "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
                "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
                f'FUNCTION 1 "{external_schema}"."second_support"(BIGINT,BIGINT)'
            )
            partition_spec = (
                f'RANGE (first_key, second_key "{external_schema}"."second_ops", '
                "third_key)"
            )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            "(first_key BIGINT,second_key BIGINT,third_key BIGINT) "
            f"PARTITION BY {partition_spec}"
        )
        if strategy == "hash":
            for remainder in (0, 1):
                connection.execute(
                    f'CREATE TABLE "{external_schema}"."subject_{remainder}" '
                    f'PARTITION OF "{external_schema}"."subject" FOR VALUES WITH '
                    f"(MODULUS 2,REMAINDER {remainder})"
                )
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
                f'"{external_schema}"."subject" FOR VALUES FROM (0,0,0) TO (10,10,10)'
            )
        connection.execute("RESET ROLE")
        result_type = "BIGINT" if strategy == "hash" else "INTEGER"
        result = (
            "pg_catalog.hashint8extended($1,$2)"
            if strategy == "hash"
            else "CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END"
        )
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."second_support"('
            f"BIGINT,BIGINT) RETURNS {result_type} LANGUAGE plpgsql SECURITY DEFINER "
            "IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            "VALUES ('partition-ordinal2','reachable') ON CONFLICT (key) "
            f"DO UPDATE SET value=EXCLUDED.value; RETURN {result}; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."second_support"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        with pytest.raises(
            postgres_environment.modules.psycopg.errors.FeatureNotSupported,
            match="INSERT is not allowed in a non-volatile function",
        ):
            values = "(0,1,1)" if strategy == "range" else "(1,1,1)"
            connection.execute(
                f'INSERT INTO "{external_schema}"."subject" VALUES {values}'
            )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_noncore_partition_collation_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "partition_collation")
    external_schema = postgres_environment.schema("partition_collation_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE COLLATION "{external_schema}"."partition_collation" '
            '(provider=libc,locale="C")'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" (id TEXT) '
            f'PARTITION BY RANGE (id COLLATE "{external_schema}"."partition_collation")'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
            f"\"{external_schema}\".\"subject\" FOR VALUES FROM ('a') TO ('z')"
        )
        connection.execute(f'INSERT INTO "{external_schema}"."subject" VALUES (\'m\')')
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT id FROM "{external_schema}"."subject"'
        ).fetchall() == [("m",)]
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


@pytest.mark.parametrize("attached", (True, False))
def test_postgres_nested_partition_callback_follows_only_attached_child(
    postgres_environment: _PostgresEnvironment,
    attached: bool,
) -> None:
    schema, _ = _single_store(
        postgres_environment,
        f"partition_child_{'attached' if attached else 'detached'}",
    )
    external_schema = postgres_environment.schema(
        f"partition_child_{'attached' if attached else 'detached'}_scope"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."child_compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END'"
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."child_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."child_compare"(BIGINT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."root" (id BIGINT,subkey BIGINT) '
            "PARTITION BY RANGE (id)"
        )
        if attached:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."child" PARTITION OF '
                f'"{external_schema}"."root" FOR VALUES FROM (0) TO (10) '
                f'PARTITION BY RANGE (subkey "{external_schema}"."child_ops")'
            )
        else:
            connection.execute(
                f'CREATE TABLE "{external_schema}"."root_leaf" PARTITION OF '
                f'"{external_schema}"."root" FOR VALUES FROM (0) TO (10)'
            )
            connection.execute(
                f'CREATE TABLE "{external_schema}"."child" (id BIGINT,subkey BIGINT) '
                f'PARTITION BY RANGE (subkey "{external_schema}"."child_ops")'
            )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."child_leaf" PARTITION OF '
            f'"{external_schema}"."child" FOR VALUES FROM (0) TO (10)'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."child_compare"('
            "BIGINT,BIGINT) RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER "
            "IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            "VALUES ('partition-child','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN CASE WHEN $1<$2 THEN -1 "
            "WHEN $1>$2 THEN 1 ELSE 0 END; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."child_compare"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."root" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if attached:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.FeatureNotSupported,
                match="INSERT is not allowed in a non-volatile function",
            ):
                connection.execute(
                    f'INSERT INTO "{external_schema}"."root" VALUES (1,1)'
                )
        else:
            connection.execute(f'INSERT INTO "{external_schema}"."root" VALUES (1,1)')
    if attached:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


@pytest.mark.parametrize(
    ("operation", "rejected"), (("insert", True), ("update", True))
)
def test_postgres_implicit_partition_key_reaches_routing_callback(
    postgres_environment: _PostgresEnvironment,
    operation: str,
    rejected: bool,
) -> None:
    schema, _ = _single_store(postgres_environment, f"partition_implicit_{operation}")
    external_schema = postgres_environment.schema(
        f"partition_implicit_{operation}_scope"
    )
    proof_key = f"partition-implicit-{operation}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."route_compare"(BIGINT,BIGINT) '
            "RETURNS INTEGER LANGUAGE sql IMMUTABLE STRICT AS "
            "'SELECT CASE WHEN $1<$2 THEN -1 WHEN $1>$2 THEN 1 ELSE 0 END'"
        )
        connection.execute(
            f'CREATE OPERATOR CLASS "{external_schema}"."route_ops" '
            "FOR TYPE BIGINT USING btree AS "
            "OPERATOR 1 pg_catalog.< (BIGINT,BIGINT), "
            "OPERATOR 2 pg_catalog.<= (BIGINT,BIGINT), "
            "OPERATOR 3 pg_catalog.= (BIGINT,BIGINT), "
            "OPERATOR 4 pg_catalog.>= (BIGINT,BIGINT), "
            "OPERATOR 5 pg_catalog.> (BIGINT,BIGINT), "
            f'FUNCTION 1 "{external_schema}"."route_compare"(BIGINT,BIGINT)'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            "(route_key BIGINT DEFAULT 5, payload BIGINT) PARTITION BY RANGE "
            f'(route_key "{external_schema}"."route_ops")'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject_leaf" PARTITION OF '
            f'"{external_schema}"."subject" FOR VALUES FROM (0) TO (10)'
        )
        if operation == "update":
            connection.execute(
                f'INSERT INTO "{external_schema}"."subject"(payload) VALUES (1)'
            )
        connection.execute("RESET ROLE")
        connection.execute(
            f'CREATE OR REPLACE FUNCTION "{external_schema}"."route_compare"('
            "BIGINT,BIGINT) RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER "
            "IMMUTABLE STRICT "
            f'SET search_path TO pg_catalog,"{external_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN CASE WHEN $1<$2 THEN -1 "
            "WHEN $1>$2 THEN 1 ELSE 0 END; END $function$"
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."route_compare"'
            "(BIGINT,BIGINT) FROM PUBLIC"
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f"GRANT {operation.upper()}(payload) ON "
            f'"{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    statement = (
        f'INSERT INTO "{external_schema}"."subject"(payload) VALUES (2)'
        if operation == "insert"
        else f'UPDATE "{external_schema}"."subject" SET payload=2'
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if rejected:
            with pytest.raises(
                postgres_environment.modules.psycopg.errors.FeatureNotSupported,
                match="INSERT is not allowed in a non-volatile function",
            ):
                connection.execute(statement)
        else:
            connection.execute(statement)
    if rejected:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


@pytest.mark.parametrize("capability", ["operator", "cast"])
def test_postgres_oid_bound_callable_reaches_hidden_signature_callback(
    postgres_environment: _PostgresEnvironment,
    capability: str,
) -> None:
    schema, _ = _single_store(postgres_environment, f"bound_{capability}")
    external_schema = postgres_environment.schema(f"bound_{capability}_scope")
    hidden_schema = postgres_environment.schema(f"bound_{capability}_hidden")
    proof_key = f"bound-{capability}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        if capability == "operator":
            connection.execute(
                f'CREATE FUNCTION "{hidden_schema}"."effect"(BIGINT,BIGINT) '
                "RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER VOLATILE STRICT "
                f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
                "AS $function$ BEGIN "
                f'INSERT INTO "{schema}"."metadata"(key,value) '
                f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
                "DO UPDATE SET value=EXCLUDED.value; RETURN $1=$2; END $function$"
            )
            connection.execute("RESET ROLE")
            connection.execute(
                f'CREATE OPERATOR "{external_schema}".#=# (LEFTARG=BIGINT, '
                f'RIGHTARG=BIGINT, FUNCTION="{hidden_schema}"."effect")'
            )
            signature = f'"{hidden_schema}"."effect"(BIGINT,BIGINT)'
        else:
            connection.execute(
                f'CREATE TYPE "{external_schema}"."source" AS ENUM (\'ok\')'
            )
            connection.execute(
                f'CREATE FUNCTION "{hidden_schema}"."effect"('
                f'"{external_schema}"."source") RETURNS BIGINT '
                "LANGUAGE plpgsql SECURITY DEFINER VOLATILE STRICT "
                f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
                "AS $function$ BEGIN "
                f'INSERT INTO "{schema}"."metadata"(key,value) '
                f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
                "DO UPDATE SET value=EXCLUDED.value; "
                "RETURN 1; END $function$"
            )
            connection.execute("RESET ROLE")
            connection.execute(
                f'CREATE CAST ("{external_schema}"."source" AS BIGINT) WITH FUNCTION '
                f'"{hidden_schema}"."effect"("{external_schema}"."source") '
                "AS ASSIGNMENT"
            )
            signature = f'"{hidden_schema}"."effect"("{external_schema}"."source")'
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f"GRANT EXECUTE ON FUNCTION {signature} TO "
            f'"{postgres_environment.observer_role}"'
        )
        if capability == "cast":
            connection.execute(
                f'GRANT USAGE ON TYPE "{external_schema}"."source" TO '
                f'"{postgres_environment.observer_role}"'
            )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        if capability == "operator":
            assert connection.execute(
                f'SELECT 1 OPERATOR("{external_schema}".#=#) 1'
            ).fetchone() == (True,)
        else:
            assert connection.execute(
                f'SELECT CAST(\'ok\'::"{external_schema}"."source" AS BIGINT)'
            ).fetchone() == (1,)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_callable_omitted_default_reaches_hidden_callback(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "callable_default")
    external_schema = postgres_environment.schema("callable_default_scope")
    hidden_schema = postgres_environment.schema("callable_default_hidden")
    proof_key = "callable-default"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."effect"() RETURNS BIGINT '
            "LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
            f'SET search_path TO pg_catalog,"{hidden_schema}",pg_temp '
            "AS $function$ BEGIN "
            f'INSERT INTO "{schema}"."metadata"(key,value) '
            f"VALUES ('{proof_key}','reachable') ON CONFLICT (key) "
            "DO UPDATE SET value=EXCLUDED.value; RETURN 1; END $function$"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."call_me"('
            f'value BIGINT DEFAULT "{hidden_schema}"."effect"()) RETURNS BIGINT '
            "LANGUAGE sql AS 'SELECT $1'"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{hidden_schema}"."effect"(), '
            f'"{external_schema}"."call_me"(BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{hidden_schema}"."effect"(), '
            f'"{external_schema}"."call_me"(BIGINT) TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT "{external_schema}"."call_me"()'
        ).fetchone() == (1,)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT value FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        ).fetchone() == ("reachable",)
        connection.execute(
            f'DELETE FROM "{schema}"."metadata" WHERE key=%s', (proof_key,)
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_reached_custom_table_am_materialized_view_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "custom_am_matview")
    external_schema = postgres_environment.schema("custom_am_matview_scope")
    handler = f"apcc_handler_{secrets.token_hex(6)}"
    access_method = f"apcc_am_{secrets.token_hex(6)}"
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."{handler}"(INTERNAL) '
            "RETURNS table_am_handler AS 'heap_tableam_handler' "
            "LANGUAGE internal STRICT"
        )
        connection.execute(
            f'CREATE ACCESS METHOD "{access_method}" TYPE TABLE '
            f'HANDLER "{external_schema}"."{handler}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE MATERIALIZED VIEW "{external_schema}"."subject" '
            f'USING "{access_method}" AS SELECT 1::BIGINT AS id'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_domain_over_range_gist_reaches_subdiff_callback(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "domain_range_subdiff")
    external_schema = postgres_environment.schema("domain_range_subdiff_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."effect_subdiff"(BIGINT,BIGINT) '
            "RETURNS DOUBLE PRECISION AS 'int8range_subdiff' "
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."effect_range" AS RANGE ('
            "SUBTYPE=BIGINT, "
            f'SUBTYPE_DIFF="{external_schema}"."effect_subdiff")'
        )
        connection.execute(
            f'CREATE DOMAIN "{external_schema}"."effect_domain" AS '
            f'"{external_schema}"."effect_range"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."subject" '
            f'(value "{external_schema}"."effect_domain")'
        )
        connection.execute(
            f'CREATE INDEX "value_gist" ON "{external_schema}"."subject" '
            "USING gist (value)"
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}".'
            '"effect_subdiff"(BIGINT,BIGINT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."effect_range", '
            f'"{external_schema}"."effect_domain" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT INSERT ON "{external_schema}"."subject" TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )


def test_postgres_view_column_mapping_does_not_reach_hidden_sibling_column(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "view_column_mapping")
    external_schema = postgres_environment.schema("view_column_mapping_scope")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."hidden_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_in"(cstring) '
            f'RETURNS "{external_schema}"."hidden_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."hidden_type" (INPUT='
            f'"{external_schema}"."hidden_in", OUTPUT='
            f'"{external_schema}"."hidden_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."hidden_type" TO '
            f'"{postgres_environment.owner_role}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."base" '
            f'(safe BIGINT, hidden "{external_schema}"."hidden_type")'
        )
        connection.execute(
            f'CREATE VIEW "{external_schema}"."safe_view" AS '
            f'SELECT safe FROM "{external_schema}"."base"'
        )
        connection.execute(f'INSERT INTO "{external_schema}"."base"(safe) VALUES (1)')
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON TYPE "{external_schema}"."hidden_type" FROM PUBLIC'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."hidden_in"(cstring), '
            f'"{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT(safe) ON "{external_schema}"."safe_view" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT safe FROM "{external_schema}"."safe_view"'
        ).fetchall() == [(1,)]
    postgres_environment.modules.reader_factory.open(
        postgres_environment.observer_dsn, schema=schema
    ).close()


@pytest.mark.parametrize(
    ("selected_column", "rejected"), (("safe", False), ("hidden", True))
)
def test_postgres_inheritance_maps_column_capability_by_name_not_attnum(
    postgres_environment: _PostgresEnvironment,
    selected_column: str,
    rejected: bool,
) -> None:
    schema, _ = _single_store(
        postgres_environment, f"inherit_column_mapping_{selected_column}"
    )
    external_schema = postgres_environment.schema(
        f"inherit_column_mapping_scope_{selected_column}"
    )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(f'CREATE TYPE "{external_schema}"."hidden_type"')
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_in"(cstring) '
            f'RETURNS "{external_schema}"."hidden_type" '
            "AS 'int8in' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") RETURNS cstring '
            "AS 'int8out' LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE TYPE "{external_schema}"."hidden_type" (INPUT='
            f'"{external_schema}"."hidden_in", OUTPUT='
            f'"{external_schema}"."hidden_out", INTERNALLENGTH=8, '
            "PASSEDBYVALUE, ALIGNMENT=double)"
        )
        connection.execute(
            f'GRANT USAGE ON TYPE "{external_schema}"."hidden_type" TO '
            f'"{postgres_environment.owner_role}"'
        )
        connection.execute(f'SET ROLE "{postgres_environment.owner_role}"')
        connection.execute(
            f'CREATE TABLE "{external_schema}"."parent" '
            f'(safe BIGINT, hidden "{external_schema}"."hidden_type")'
        )
        connection.execute(
            f'CREATE TABLE "{external_schema}"."child" '
            f'(hidden "{external_schema}"."hidden_type", safe BIGINT)'
        )
        connection.execute(
            f'ALTER TABLE "{external_schema}"."child" INHERIT '
            f'"{external_schema}"."parent"'
        )
        connection.execute(
            f'INSERT INTO "{external_schema}"."child"(safe,hidden) VALUES (7,\'9\')'
        )
        connection.execute("RESET ROLE")
        connection.execute(
            f'REVOKE ALL ON TYPE "{external_schema}"."hidden_type" FROM PUBLIC'
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{external_schema}"."hidden_in"(cstring), '
            f'"{external_schema}"."hidden_out"('
            f'"{external_schema}"."hidden_type") FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT SELECT({selected_column}) ON "{external_schema}"."parent" TO '
            f'"{postgres_environment.observer_role}"'
        )
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.observer_dsn, autocommit=True
    ) as connection:
        assert connection.execute(
            f'SELECT {selected_column} FROM "{external_schema}"."parent"'
        ).fetchone() == ((7,) if selected_column == "safe" else ("9",))
    if rejected:
        with pytest.raises(ValueError, match="schema validation failed"):
            postgres_environment.modules.reader_factory.open(
                postgres_environment.observer_dsn, schema=schema
            )
    else:
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        ).close()


def test_postgres_callable_planner_support_callback_is_rejected(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, _ = _single_store(postgres_environment, "callable_prosupport")
    external_schema = postgres_environment.schema("callable_prosupport_scope")
    hidden_schema = postgres_environment.schema("callable_prosupport_hidden")
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn, autocommit=True
    ) as connection:
        connection.execute(
            f'CREATE FUNCTION "{hidden_schema}"."planner_support"(INTERNAL) '
            "RETURNS INTERNAL AS 'text_starts_with_support' "
            "LANGUAGE internal IMMUTABLE STRICT"
        )
        connection.execute(
            f'CREATE FUNCTION "{external_schema}"."call_me"(TEXT) RETURNS BOOLEAN '
            "LANGUAGE sql IMMUTABLE STRICT SUPPORT "
            f'"{hidden_schema}"."planner_support" AS \'SELECT $1 IS NOT NULL\''
        )
        connection.execute(
            f'REVOKE ALL ON FUNCTION "{hidden_schema}"."planner_support"(INTERNAL), '
            f'"{external_schema}"."call_me"(TEXT) FROM PUBLIC'
        )
        connection.execute(
            f'GRANT USAGE ON SCHEMA "{external_schema}" TO '
            f'"{postgres_environment.observer_role}"'
        )
        connection.execute(
            f'GRANT EXECUTE ON FUNCTION "{external_schema}"."call_me"(TEXT) TO '
            f'"{postgres_environment.observer_role}"'
        )
    _reseal_test_checkpoint_without_attestation(postgres_environment, schema)
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.reader_factory.open(
            postgres_environment.observer_dsn, schema=schema
        )
