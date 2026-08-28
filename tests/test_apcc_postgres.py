"""Real PostgreSQL 17 APCC authority-store contract (intentionally RED)."""

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
from pathlib import Path
from types import ModuleType
from typing import Protocol, get_type_hints

import pytest

from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    AuthorityStatusValue,
    FailureCode,
    RequestOutcome,
    SupersessionValue,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AtomicCommitRequest,
    AuthorityReader,
    AuthorityRuntime,
    AuthorityStore,
    CommitResult,
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
)


_DSN_ENV = "APCC_POSTGRES_DSN"
_SCHEMA_RE = re.compile(r"\Aapcc_test_[a-z0-9_]{1,48}\Z")
_RETRYABLE_SQLSTATES = ("40001", "40P01")
_AMBIGUOUS_SQLSTATES: tuple[str | None, ...] = ("40003", "08007", None)
_ROLE_SEEDS = tuple(bytes(range(start, start + 32)) for start in range(0, 192, 32))
_MIN_MAX_CONNECTIONS = 105
_BENCHMARK_MAX_CONNECTIONS = 200


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...

    def fetchall(self) -> list[tuple[object, ...]]: ...


class _Connection(Protocol):
    def execute(self, query: str, parameters: tuple[object, ...] = ()) -> _Cursor: ...

    def close(self) -> None: ...

    def __enter__(self) -> _Connection: ...

    def __exit__(self, *exc: object) -> None: ...


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
    schema_prefix: str
    ownership_token: str
    modules: _Modules
    created_schemas: set[str] = field(default_factory=set)

    def schema(self, label: str) -> str:
        suffix = hashlib.sha256(label.encode("utf-8")).hexdigest()[:10]
        schema = f"{self.schema_prefix}_{suffix}"
        _validate_owned_schema(schema)
        with self.modules.psycopg.connect(self.dsn, autocommit=True) as connection:
            if schema not in self.created_schemas:
                connection.execute(f'CREATE SCHEMA "{schema}"')
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


def _schema_owner_comment(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{24}", token) is None:
        raise AssertionError("unsafe PostgreSQL test ownership token")
    return f"apcc-test-owner:{token}"


def _future_modules() -> _Modules:
    psycopg_module = importlib.import_module("psycopg")
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
    environment = _PostgresEnvironment(dsn, prefix, token, modules)
    try:
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


def _initial_contexts(environment: _PostgresEnvironment) -> tuple[object, ...]:
    value = _support(environment, "_initial_contexts")()
    assert isinstance(value, tuple)
    return value


def _snapshot(
    environment: _PostgresEnvironment, store: AuthorityStore
) -> AuthoritySnapshot:
    schema = store.schema_name
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
            )
        if probe is None:
            store = environment.modules.store_factory.open(
                environment.dsn,
                schema=schema,
                config=config,
                runtime=_runtime(environment),
            )
        else:
            store = environment.modules.store_factory._open_with_probe(
                environment.dsn,
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
            environment.dsn,
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
    )
    return schema, environment.modules.store_factory.open(
        environment.dsn,
        schema=schema,
        config=config,
        runtime=_runtime(environment),
    )


def test_postgres_public_api_matches_the_sqlite_authority_contract(
    postgres_environment: _PostgresEnvironment,
) -> None:
    store_factory = postgres_environment.modules.store_factory
    reader_factory = postgres_environment.modules.reader_factory
    provision = inspect.signature(store_factory.provision).parameters
    writer_open = inspect.signature(store_factory.open).parameters
    reader_open = inspect.signature(reader_factory.open).parameters
    assert set(provision) == {"dsn", "schema", "config", "initial_contexts"}
    assert set(writer_open) == {
        "dsn",
        "schema",
        "config",
        "runtime",
        "retry_policy",
    }
    assert set(reader_open) == {"dsn", "schema"}
    assert provision["config"].default is inspect.Parameter.empty
    assert "runtime" not in provision
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


def test_postgres_uses_read_committed_and_a_locked_workflow_guard(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, store = _single_store(postgres_environment, "workflow_guard")
    request = _request(postgres_environment, commit_id="pg-guard", nonce_byte=101)
    _advance(postgres_environment, store, request)
    pool = ThreadPoolExecutor(max_workers=1)
    with postgres_environment.modules.psycopg.connect(
        postgres_environment.dsn
    ) as locker:
        isolation = locker.execute("SHOW transaction_isolation").fetchone()
        assert isolation == ("read committed",)
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
            postgres_environment.dsn,
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


def test_postgres_satisfies_backend_neutral_authority_conformance(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_authority_store_conforms(_harness(postgres_environment), tmp_path)


def test_postgres_satisfies_extended_backend_neutral_conformance(
    postgres_environment: _PostgresEnvironment, tmp_path: Path
) -> None:
    assert_authority_store_extended_conforms(_harness(postgres_environment), tmp_path)


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
    )
    _advance(postgres_environment, setup, left)
    _advance(postgres_environment, setup, right)
    barrier = threading.Barrier(2)

    def commit(request: AtomicCommitRequest) -> CommitResult:
        store = postgres_environment.modules.store_factory.open(
            postgres_environment.dsn,
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
            postgres_environment.dsn,
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
            postgres_environment.dsn,
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
        postgres_environment.dsn,
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
        postgres_environment.dsn,
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


def test_postgres_23505_rolls_back_then_classifies_by_fresh_authoritative_read(
    postgres_environment: _PostgresEnvironment,
) -> None:
    schema, setup = _single_store(postgres_environment, "unique_reread")
    left = _request(postgres_environment, commit_id="pg-23505", nonce_byte=107)
    right = _request(
        postgres_environment,
        commit_id="pg-23505",
        nonce_byte=108,
        workflow_id="workflow-2",
    )
    _advance(postgres_environment, setup, left)
    _advance(postgres_environment, setup, right)
    probe = _RecordingProbe([])
    barrier = threading.Barrier(2)

    def contend(request: AtomicCommitRequest) -> CommitResult:
        store = postgres_environment.modules.store_factory._open_with_probe(
            postgres_environment.dsn,
            schema=schema,
            config=_config(postgres_environment),
            runtime=_runtime(postgres_environment),
            retry_policy=postgres_environment.modules.retry_policy_factory(
                max_attempts=1
            ),
            probe=probe,
        )
        barrier.wait()
        return store.atomic_commit(request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(contend, (left, right)))
    assert {result.decision.outcome for result in results} == {
        RequestOutcome.COMMITTED,
        RequestOutcome.CONFLICTED,
    }
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
        postgres_environment.dsn, schema=schema
    )
    for request, result in zip((left, right), results, strict=True):
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


@pytest.mark.parametrize("sqlstate", _AMBIGUOUS_SQLSTATES)
def test_postgres_ambiguous_completion_recovers_on_a_fresh_connection(
    postgres_environment: _PostgresEnvironment, sqlstate: str | None
) -> None:
    schema, _ = _single_store(postgres_environment, f"ambiguous_{sqlstate}")
    probe = _AmbiguousCompletionProbe(sqlstate)
    store = postgres_environment.modules.store_factory._open_with_probe(
        postgres_environment.dsn,
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
        postgres_environment.dsn, schema=schema
    )
    assert fresh.authority_store_id == _config(postgres_environment).authority_store_id
    assert (
        fresh.replay_commit(
            ReplayCommitRequest(request.commit_id, request.request_digest)
        )
        == recovered
    )
    recovery_store = postgres_environment.modules.store_factory.open(
        postgres_environment.dsn,
        schema=schema,
        config=_config(postgres_environment),
        runtime=_runtime(postgres_environment),
    )
    mismatch_request = RecoveryRequest(request.commit_id, "different-request-digest")
    mismatch = recovery_store.recover(mismatch_request)
    assert mismatch.decision.outcome is RequestOutcome.CONFLICTED
    assert mismatch.decision.reason is FailureCode.COMMIT_ID_EQUIVOCATION
    assert recovery_store.recover(mismatch_request) == mismatch


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
    assert original.certificate_digest is not None
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
            postgres_environment.dsn,
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
                    original.certificate_digest,
                    "1",
                    "postgres race",
                )
            )
        if operation == "supersede":
            assert replacement is not None
            return store.supersede(
                SupersessionRequest(original.certificate_digest, replacement)
            )
        return store.current_status(
            original.certificate_digest,
            status_nonces[worker],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(race, range(2)))
    if operation == "revoke":
        for result in results:
            assert isinstance(result, RevocationResult)
            assert result.scope is RevocationScope.CERTIFICATE
            assert result.target_id == original.certificate_digest
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
            "trust_log",
            "audit_events",
            "outbox",
        }
        assert len(after_race.tables["certificate_dispositions"]) == len(
            before_race.tables["certificate_dispositions"]
        )
        for table in ("trust_log", "audit_events", "outbox"):
            assert len(after_race.tables[table]) == len(before_race.tables[table]) + 1
        status = setup.current_status(original.certificate_digest, status_nonces[0])
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
            assert result.old_certificate_digest == original.certificate_digest
            assert (
                result.new_certificate_digest == result.commit_result.certificate_digest
            )
            assert result.commit_result.decision.outcome is RequestOutcome.COMMITTED
        assert results[0] == results[1]
        replacement = results[0]
        assert isinstance(replacement, SupersessionCommitted)
        node = setup.read_logical_node(
            original_request.subject.workflow_id, original_request.subject.node_id
        )
        assert node.current_node_version == "2"
        assert node.current_certificate_digest == replacement.new_certificate_digest
        status = setup.current_status(original.certificate_digest, status_nonces[0])
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
        assert result.certificate_digest == original.certificate_digest
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
            postgres_environment.dsn,
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
        postgres_environment.dsn,
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
        postgres_environment.dsn, schema=schema
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
            postgres_environment.dsn,
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
    assert "READ COMMITTED" in source.upper()
