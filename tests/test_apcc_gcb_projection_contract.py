from __future__ import annotations

import ast
import inspect
from dataclasses import FrozenInstanceError, fields, is_dataclass
from typing import Any, cast, get_type_hints

import pytest

from constitutional_swarm.apcc import gcb_projection
from constitutional_swarm.apcc.gcb_projection import (
    _GCBPredecessorFacts,
    _GCBProjectionFacts,
    _GCBProjectionPlan,
    _validate_gcb_projection,
)
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AtomicCommitRequest,
)


def test_projection_contract_module_has_no_storage_or_callable_surface() -> None:
    source = inspect.getsource(gcb_projection)
    imports = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not {"sqlite3", "psycopg", "sqlalchemy"} & imports
    lowered = source.lower()
    for forbidden in ("connection", "cursor", "callback", "execute("):
        assert forbidden not in lowered


def test_projection_contract_records_are_private_frozen_scalar_material() -> None:
    record_types = {
        name: value
        for name, value in vars(gcb_projection).items()
        if name.startswith("_")
        and isinstance(value, type)
        and is_dataclass(value)
        and value.__module__ == gcb_projection.__name__
    }
    assert set(record_types) == {
        "_GCBAgentFacts",
        "_GCBAtomicCommitRequest",
        "_GCBNodeFacts",
        "_GCBPredecessorFacts",
        "_GCBProjectionFacts",
        "_GCBProjectionPlan",
        "_GCBStagedArtifactFacts",
        "_GCBWorkflowFacts",
        "_ValidatedGCBProjection",
    }
    assert record_types["_GCBProjectionPlan"] is _GCBProjectionPlan
    assert record_types["_GCBProjectionFacts"] is _GCBProjectionFacts
    for record_type in record_types.values():
        runtime_type = cast(Any, record_type)
        assert runtime_type.__dataclass_params__.frozen
        assert runtime_type.__slots__
        annotations = get_type_hints(record_type)
        assert not any(
            fragment in field.name
            for field in fields(record_type)
            for fragment in ("callback", "connection", "cursor", "operation", "sql")
        )
        assert object not in annotations.values()
    assert get_type_hints(_GCBPredecessorFacts)["logical_version"] is str


def test_projection_plan_is_immutable() -> None:
    plan = _GCBProjectionPlan(*("value",) * 6, 1, 2, 3, *("value",) * 6)

    with pytest.raises(FrozenInstanceError):
        plan.workflow_id = "changed"  # type: ignore[misc]


def test_projection_validator_accepts_only_data_contracts() -> None:
    annotations = get_type_hints(_validate_gcb_projection)

    assert annotations["config"] is APCCAuthorityConfig
    assert annotations["request"] is AtomicCommitRequest
    assert annotations["plan"] is _GCBProjectionPlan
    assert annotations["facts"] is _GCBProjectionFacts
