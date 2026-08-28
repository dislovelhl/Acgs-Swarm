"""Real PostgreSQL 17 APCC authority-store contract."""

from __future__ import annotations

import base64
import ast
import hashlib
import importlib
import inspect
import os
import re
import secrets
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast, get_type_hints, runtime_checkable

import pytest

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
_ROLE_RE = re.compile(r"\Aapcc_test_[0-9a-f]{24}_(?:owner|runtime)\Z")
_RETRYABLE_SQLSTATES = ("40001", "40P01")
_AMBIGUOUS_SQLSTATES: tuple[str | None, ...] = ("40003", "08007", None)
_ROLE_SEEDS = tuple(bytes(range(start, start + 32)) for start in range(0, 192, 32))
_MIN_MAX_CONNECTIONS = 105
_BENCHMARK_MAX_CONNECTIONS = 200
_CHECKPOINT_GUARDED_TABLES = (
    "metadata",
    "logical_nodes",
    "candidates",
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

    def __enter__(self) -> _Connection: ...

    def __exit__(self, *exc: object) -> None: ...


@runtime_checkable
class _Psycopg(Protocol):
    def connect(self, dsn: str, *, autocommit: bool = False) -> _Connection: ...


class _RetryPolicy(Protocol):
    max_attempts: int


class _RetryPolicyFactory(Protocol):
    def __call__(self, *, max_attempts: int) -> _RetryPolicy: ...


class _PostgresReader(AuthorityReader, Protocol):
    authority_store_id: str
    schema_name: str

    def close(self) -> None: ...


class _PostgresStore(AuthorityStore, Protocol):
    authority_store_id: str
    schema_name: str

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
    def open(self, dsn: str, *, schema: str) -> _PostgresReader: ...


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
    schema_prefix: str
    ownership_token: str
    owner_role: str
    runtime_role: str
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
    _validate_owned_role(owner_role)
    _validate_owned_role(runtime_role)
    created_roles: list[str] = []
    try:
        with modules.psycopg.connect(dsn, autocommit=True) as connection:
            for role, login in ((owner_role, False), (runtime_role, True)):
                connection.execute(
                    f'CREATE ROLE "{role}" '
                    f"{'LOGIN' if login else 'NOLOGIN'} NOINHERIT NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                created_roles.append(role)
                connection.execute(
                    f"COMMENT ON ROLE \"{role}\" IS '{_schema_owner_comment(token)}'"
                )
        environment = _PostgresEnvironment(
            dsn,
            _runtime_dsn(dsn, runtime_role),
            prefix,
            token,
            owner_role,
            runtime_role,
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
        "runtime",
    }
    assert set(writer_open) == {
        "dsn",
        "schema",
        "config",
        "runtime",
        "retry_policy",
    }
    assert set(reader_open) == {"dsn", "schema"}
    assert provision["config"].default is inspect.Parameter.empty
    assert provision["runtime_role"].default is inspect.Parameter.empty
    assert provision["runtime"].default is inspect.Parameter.empty
    assert writer_open["config"].default is inspect.Parameter.empty
    assert writer_open["runtime"].default is inspect.Parameter.empty
    assert get_type_hints(store_factory.open)["return"] is not object
    forbidden = {"private_seed", "signer", "legacy", "sidecar", "disable"}
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
) -> None:
    schema, setup = _single_store(postgres_environment, "hundred_connections")
    request = _request(postgres_environment, commit_id="pg-100", nonce_byte=104)
    _advance(postgres_environment, setup, request)
    barrier = threading.Barrier(100)

    def contend(_: int) -> CommitResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
        )
        barrier.wait(timeout=30)
        return store.atomic_commit(request)

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = tuple(pool.map(contend, range(100)))
    assert len(results) == 100
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
        postgres_environment.runtime_dsn, schema=schema
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
        postgres_environment.runtime_dsn, schema=schema
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
        postgres_environment.runtime_dsn, schema=schema
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
    assert schema_version == ("2",)
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
            postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
                    postgres_environment.runtime_dsn, schema=schema
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
                    postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
        postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
        )
    with pytest.raises(ValueError, match="schema validation failed"):
        postgres_environment.modules.store_factory.open(
            postgres_environment.runtime_dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
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
        postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
                postgres_environment.runtime_dsn, schema=schema
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
            postgres_environment.runtime_dsn, schema=schema
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
        postgres_environment.runtime_dsn, schema=schema
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
