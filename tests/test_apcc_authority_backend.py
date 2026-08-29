from __future__ import annotations

from typing import get_type_hints

from constitutional_swarm.apcc.ports import (
    AuthorityControlStore,
    AuthorityExecutionStore,
    AuthorityStore,
)
from constitutional_swarm.apcc.service import APCCCommitService
from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityStore


def _operations(protocol: type[object]) -> set[str]:
    return {
        name
        for name, member in protocol.__dict__.items()
        if not name.startswith("_") and callable(member)
    }


_READER_OPERATIONS = {
    "read_commit_context",
    "read_logical_node",
    "replay_commit",
    "get_certificate",
    "get_outbox_event",
}


def _capability_double(name: str, operations: set[str]) -> object:
    def unexpected(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("capability double must not be invoked")

    namespace: dict[str, object] = {"authority_store_id": "store-1"}
    namespace.update({operation: unexpected for operation in operations})
    return type(name, (), namespace)()


def test_authority_backend_capabilities_are_split_without_changing_aggregate() -> None:
    assert _operations(AuthorityExecutionStore) == {
        "stage_result",
        "assemble_evidence",
        "propose_commit",
        "atomic_commit",
        "current_status",
        "current_status_batch",
        "logical_node_status_batch",
    }
    assert _operations(AuthorityControlStore) == {
        "revoke",
        "supersede",
        "recover",
        "recover_outbox",
    }
    assert AuthorityExecutionStore in AuthorityStore.__bases__
    assert AuthorityControlStore in AuthorityStore.__bases__


def test_execution_and_control_capabilities_are_structurally_disjoint() -> None:
    execution = _capability_double(
        "ExecutionOnly",
        _READER_OPERATIONS | _operations(AuthorityExecutionStore),
    )
    control = _capability_double(
        "ControlOnly",
        _READER_OPERATIONS | _operations(AuthorityControlStore),
    )

    assert isinstance(execution, AuthorityExecutionStore)
    assert not isinstance(execution, AuthorityControlStore)
    assert not isinstance(execution, AuthorityStore)
    assert isinstance(control, AuthorityControlStore)
    assert not isinstance(control, AuthorityExecutionStore)
    assert not isinstance(control, AuthorityStore)


def test_sqlite_store_satisfies_both_backend_capabilities() -> None:
    store = object.__new__(SQLiteAuthorityStore)
    store.authority_store_id = "store-1"

    assert isinstance(store, AuthorityExecutionStore)
    assert isinstance(store, AuthorityControlStore)
    assert isinstance(store, AuthorityStore)


def test_commit_service_accepts_only_execution_capability() -> None:
    annotations = get_type_hints(APCCCommitService.__init__)

    assert annotations["store"] is AuthorityExecutionStore
