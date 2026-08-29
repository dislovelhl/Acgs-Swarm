"""Strict JSON IPC boundary for the privileged APCC authority process."""

from __future__ import annotations

import base64
import array
import json
import math
import multiprocessing
import os
import secrets
import select
import socket
import struct
import threading
import time
from collections.abc import Collection, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field as dataclass_field, replace
from enum import Enum
from typing import Any, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc.codec import encode_authority_status
from constitutional_swarm.apcc.model import Signature
from constitutional_swarm.apcc.observation import (
    AUTHORITY_OBSERVATION_DOMAIN,
    AuthorityObservationRequest,
    ObserverLaunchExpectationsV1,
    SignedAuthorityObservation,
    decode_authority_observation_request,
    decode_observer_launch_attestation,
    decode_signed_authority_observation,
    encode_authority_observation_body,
    encode_authority_observation_request,
    encode_signed_authority_observation,
    verify_signed_authority_observation,
)
from constitutional_swarm.apcc.ports import (
    AuthorityObservationStore,
    OutboxRecoveryRequest,
)
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.authority_isolation import (
    CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
    CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
    ControlledBootEvidence,
    ControlledBootPhase,
    ControlledBootResult,
    IsolationUnavailable,
    consume_secret_file,
    erase_secret,
    harden_current_process,
)
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.execution import ContractStatus, WorkReceipt
from constitutional_swarm.authority_ipc import (
    PROTOCOL,
    b64u_decode,
    canonical_json,
    digest as ipc_digest,
    recv_frame as recv_authenticated_frame,
    send_frame as send_authenticated_frame,
    signed_response,
    verify_response,
)
from constitutional_swarm.governed_commit import (
    AttemptAuthorizationPayload,
    AuthoritativeVerdict,
    CommitDecision,
    CommitOutcome,
    CommitRequest,
    GovernanceBypassDenied,
    GovernedNodeState,
    GovernedReceiptPayload,
    PredecessorBinding,
    SignedGovernedReceipt,
    SignedAttemptAuthorization,
    VerdictDecision,
)

_PREDECESSOR_FIELDS = {
    "node_id",
    "node_version",
    "commit_id",
    "receipt_digest",
    "authoritative_result_digest",
}
_PAYLOAD_STR_FIELDS = {
    "profile",
    "signature_algorithm",
    "key_id",
    "intent",
    "verifier_policy_id",
    "workflow_id",
    "node_id",
    "attempt_id",
    "agent_id",
    "input_digest",
    "output_digest",
    "predecessor_root",
    "policy_version",
    "policy_digest",
    "authority_snapshot_digest",
    "authority_root",
    "nonce",
    "commit_id",
}
_PAYLOAD_INT_FIELDS = {
    "issued_at",
    "expires_at",
    "policy_epoch",
    "authority_epoch",
    "agent_revocation_epoch",
    "workflow_revocation_generation",
    "workflow_generation",
    "state_version",
    "expected_node_state_version",
}
_PAYLOAD_FIELDS = _PAYLOAD_STR_FIELDS | _PAYLOAD_INT_FIELDS | {"predecessor_bindings"}
_VERDICT_STR_FIELDS = {
    "store_id",
    "verifier_policy_id",
    "policy_id",
    "policy_version",
    "verifier_key_id",
    "receipt_digest",
    "workflow_id",
    "node_id",
    "attempt_id",
    "agent_id",
    "reason",
    "signature",
}
_VERDICT_INT_FIELDS = {
    "expected_node_state_version",
    "policy_epoch",
    "authority_epoch",
    "agent_revocation_epoch",
    "workflow_revocation_generation",
    "workflow_generation",
    "issued_at",
    "expires_at",
}
_VERDICT_FIELDS = _VERDICT_STR_FIELDS | _VERDICT_INT_FIELDS | {"decision"}


@dataclass(frozen=True, slots=True)
class AuthorityObserverBackendRef:
    """Spawn-safe non-secret backend binding and optional SQLite path."""

    kind: str
    instance_binding: str
    sqlite_path: str | None = dataclass_field(default=None, repr=False)
    schema: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"sqlite", "postgresql"} or not self.instance_binding:
            raise ValueError("invalid authority observer backend reference")
        if self.kind == "sqlite" and (not self.sqlite_path or self.schema is not None):
            raise ValueError("SQLite observer references require only a local path")
        if self.kind == "postgresql" and (
            self.sqlite_path is not None or not self.schema
        ):
            raise ValueError("PostgreSQL observer references require a schema")


_ARTIFACT_FIELDS = {
    "artifact_id",
    "task_id",
    "agent_id",
    "content_type",
    "content",
    "domain",
    "tags",
    "timestamp",
    "constitutional_hash",
    "parent_artifacts",
    "metadata",
}
_ATTEMPT_STR_FIELDS = {
    "store_id",
    "workflow_id",
    "node_id",
    "attempt_id",
    "agent_id",
    "key_id",
    "nonce",
}
_ATTEMPT_INT_FIELDS = {
    "expected_node_state_version",
    "policy_epoch",
    "authority_epoch",
    "agent_revocation_epoch",
    "workflow_revocation_generation",
    "workflow_generation",
    "issued_at",
    "expires_at",
}
_ATTEMPT_FIELDS = _ATTEMPT_STR_FIELDS | _ATTEMPT_INT_FIELDS
_NODE_STATE_FIELDS = {
    "workflow_id",
    "node_id",
    "status",
    "version",
    "attempt_id",
    "claimed_by",
    "artifact_id",
    "commit_id",
}


def _exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"invalid_{label}")
    return value


def _require_types(
    value: Mapping[str, Any],
    *,
    strings: Collection[str] = (),
    integers: Collection[str] = (),
) -> None:
    if any(type(value[field]) is not str for field in strings):
        raise ValueError("invalid_field_type")
    if any(type(value[field]) is not int for field in integers):
        raise ValueError("invalid_field_type")


def _string_field(value: Mapping[str, Any], field: str) -> str:
    item = value[field]
    if type(item) is not str:
        raise ValueError("invalid_field_type")
    return item


def _integer_field(value: Mapping[str, Any], field: str) -> int:
    item = value[field]
    if type(item) is not int:
        raise ValueError("invalid_field_type")
    return item


def _optional_string_field(value: Mapping[str, Any], field: str) -> str | None:
    item = value[field]
    if item is not None and type(item) is not str:
        raise ValueError("invalid_field_type")
    return item


def _string_tuple_field(value: Mapping[str, Any], field: str) -> tuple[str, ...]:
    raw = value[field]
    if type(raw) is not list:
        raise ValueError("invalid_field_type")
    items: list[str] = []
    for item in raw:
        if type(item) is not str:
            raise ValueError("invalid_field_type")
        items.append(item)
    return tuple(items)


def _float_field(value: Mapping[str, Any], field: str) -> float:
    item = value[field]
    if type(item) not in {int, float}:
        raise ValueError("invalid_field_type")
    return float(item)


def _inert_json_object(value: Any) -> dict[str, Any]:
    raw = _inert_json_value(value)
    if type(raw) is not dict:
        raise ValueError("invalid_field_type")
    result: dict[str, Any] = {}
    for key, item in raw.items():
        if type(key) is not str:
            raise ValueError("invalid_field_type")
        result[key] = item
    return result


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if type(value) is float and not math.isfinite(value):
        raise ValueError("nonfinite_number")
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _inert_json_value(value: Any, *, depth: int = 0) -> Any:
    """Validate scheduler metadata without invoking user-defined protocols."""
    if depth > 32:
        raise ValueError("metadata_nesting_too_deep")
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise TypeError("metadata keys must be exact strings")
        return {
            key: _inert_json_value(item, depth=depth + 1) for key, item in value.items()
        }
    if type(value) in {list, tuple}:
        return [_inert_json_value(item, depth=depth + 1) for item in value]
    if type(value) is float and not math.isfinite(value):
        raise ValueError("nonfinite_number")
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise TypeError("scheduler metadata must contain only inert JSON values")


def _encode_receipt_payload(payload: GovernedReceiptPayload) -> dict[str, Any]:
    return _json_value(asdict(payload))


def _decode_predecessor(value: Any) -> PredecessorBinding:
    body = _exact_object(value, _PREDECESSOR_FIELDS, "predecessor")
    _require_types(
        body,
        strings=_PREDECESSOR_FIELDS - {"node_version"},
        integers={"node_version"},
    )
    return PredecessorBinding(**body)


def _decode_receipt_payload(value: Any) -> GovernedReceiptPayload:
    body = _exact_object(value, _PAYLOAD_FIELDS, "receipt_payload")
    _require_types(body, strings=_PAYLOAD_STR_FIELDS, integers=_PAYLOAD_INT_FIELDS)
    predecessors = body["predecessor_bindings"]
    if not isinstance(predecessors, list):
        raise ValueError("invalid_predecessor_bindings")
    return GovernedReceiptPayload(
        profile=_string_field(body, "profile"),
        signature_algorithm=_string_field(body, "signature_algorithm"),
        key_id=_string_field(body, "key_id"),
        issued_at=_integer_field(body, "issued_at"),
        expires_at=_integer_field(body, "expires_at"),
        intent=_string_field(body, "intent"),
        verifier_policy_id=_string_field(body, "verifier_policy_id"),
        workflow_id=_string_field(body, "workflow_id"),
        node_id=_string_field(body, "node_id"),
        attempt_id=_string_field(body, "attempt_id"),
        agent_id=_string_field(body, "agent_id"),
        input_digest=_string_field(body, "input_digest"),
        output_digest=_string_field(body, "output_digest"),
        predecessor_bindings=tuple(_decode_predecessor(item) for item in predecessors),
        predecessor_root=_string_field(body, "predecessor_root"),
        policy_version=_string_field(body, "policy_version"),
        policy_digest=_string_field(body, "policy_digest"),
        policy_epoch=_integer_field(body, "policy_epoch"),
        authority_snapshot_digest=_string_field(body, "authority_snapshot_digest"),
        authority_root=_string_field(body, "authority_root"),
        authority_epoch=_integer_field(body, "authority_epoch"),
        agent_revocation_epoch=_integer_field(body, "agent_revocation_epoch"),
        workflow_revocation_generation=_integer_field(
            body, "workflow_revocation_generation"
        ),
        workflow_generation=_integer_field(body, "workflow_generation"),
        state_version=_integer_field(body, "state_version"),
        expected_node_state_version=_integer_field(body, "expected_node_state_version"),
        nonce=_string_field(body, "nonce"),
        commit_id=_string_field(body, "commit_id"),
    )


def _encode_commit_request(request: CommitRequest) -> dict[str, Any]:
    return {
        "receipt": {
            "payload": _encode_receipt_payload(request.receipt.payload),
            "signature": request.receipt.signature,
        },
        "verdict": {
            **_json_value(asdict(request.verdict)),
            "decision": request.verdict.decision.value,
        },
    }


def _decode_commit_request(value: Any) -> CommitRequest:
    body = _exact_object(value, {"receipt", "verdict"}, "commit_request")
    receipt = _exact_object(body["receipt"], {"payload", "signature"}, "receipt")
    if type(receipt["signature"]) is not str:
        raise ValueError("invalid_field_type")
    verdict = _exact_object(body["verdict"], _VERDICT_FIELDS, "verdict")
    _require_types(verdict, strings=_VERDICT_STR_FIELDS, integers=_VERDICT_INT_FIELDS)
    if type(verdict["decision"]) is not str:
        raise ValueError("invalid_field_type")
    return CommitRequest(
        SignedGovernedReceipt(
            _decode_receipt_payload(receipt["payload"]),
            _string_field(receipt, "signature"),
        ),
        AuthoritativeVerdict(
            decision=VerdictDecision(_string_field(verdict, "decision")),
            store_id=_string_field(verdict, "store_id"),
            verifier_policy_id=_string_field(verdict, "verifier_policy_id"),
            policy_id=_string_field(verdict, "policy_id"),
            policy_version=_string_field(verdict, "policy_version"),
            verifier_key_id=_string_field(verdict, "verifier_key_id"),
            receipt_digest=_string_field(verdict, "receipt_digest"),
            workflow_id=_string_field(verdict, "workflow_id"),
            node_id=_string_field(verdict, "node_id"),
            attempt_id=_string_field(verdict, "attempt_id"),
            agent_id=_string_field(verdict, "agent_id"),
            expected_node_state_version=_integer_field(
                verdict, "expected_node_state_version"
            ),
            policy_epoch=_integer_field(verdict, "policy_epoch"),
            authority_epoch=_integer_field(verdict, "authority_epoch"),
            agent_revocation_epoch=_integer_field(verdict, "agent_revocation_epoch"),
            workflow_revocation_generation=_integer_field(
                verdict, "workflow_revocation_generation"
            ),
            workflow_generation=_integer_field(verdict, "workflow_generation"),
            issued_at=_integer_field(verdict, "issued_at"),
            expires_at=_integer_field(verdict, "expires_at"),
            reason=_string_field(verdict, "reason"),
            signature=_string_field(verdict, "signature"),
        ),
    )


def _encode_commit_decision(decision: CommitDecision) -> dict[str, Any]:
    return {
        "commit_id": decision.commit_id,
        "outcome": decision.outcome.value,
        "reason": _json_value(decision.reason),
        "workflow_id": decision.workflow_id,
        "node_id": decision.node_id,
        "state_version": decision.state_version,
    }


def _decode_commit_decision(value: Any) -> CommitDecision:
    fields = {
        "commit_id",
        "outcome",
        "reason",
        "workflow_id",
        "node_id",
        "state_version",
    }
    body = _exact_object(value, fields, "commit_decision")
    _require_types(
        body,
        strings=fields - {"state_version"},
        integers={"state_version"},
    )
    return CommitDecision(
        commit_id=_string_field(body, "commit_id"),
        outcome=CommitOutcome(_string_field(body, "outcome")),
        reason=_string_field(body, "reason"),
        workflow_id=_string_field(body, "workflow_id"),
        node_id=_string_field(body, "node_id"),
        state_version=_integer_field(body, "state_version"),
    )


def _encode_artifact(artifact: Artifact | None) -> dict[str, Any] | None:
    if artifact is None:
        return None
    return _json_value(
        {
            "artifact_id": artifact.artifact_id,
            "task_id": artifact.task_id,
            "agent_id": artifact.agent_id,
            "content_type": artifact.content_type,
            "content": artifact.content,
            "domain": artifact.domain,
            "tags": artifact.tags,
            "timestamp": artifact.timestamp,
            "constitutional_hash": artifact.constitutional_hash,
            "parent_artifacts": artifact.parent_artifacts,
            "metadata": artifact.metadata,
        }
    )


def _decode_artifact(value: Any) -> Artifact | None:
    if value is None:
        return None
    body = _exact_object(value, _ARTIFACT_FIELDS, "artifact")
    _require_types(
        body,
        strings={
            "artifact_id",
            "task_id",
            "agent_id",
            "content_type",
            "content",
            "domain",
            "constitutional_hash",
        },
    )
    if (
        not isinstance(body["tags"], list)
        or any(type(item) is not str for item in body["tags"])
        or not isinstance(body["parent_artifacts"], list)
        or any(type(item) is not str for item in body["parent_artifacts"])
        or type(body["timestamp"]) not in {int, float}
        or not isinstance(body["metadata"], dict)
    ):
        raise ValueError("invalid_field_type")
    return Artifact(
        artifact_id=_string_field(body, "artifact_id"),
        task_id=_string_field(body, "task_id"),
        agent_id=_string_field(body, "agent_id"),
        content_type=_string_field(body, "content_type"),
        content=_string_field(body, "content"),
        domain=_string_field(body, "domain"),
        tags=_string_tuple_field(body, "tags"),
        timestamp=_float_field(body, "timestamp"),
        constitutional_hash=_string_field(body, "constitutional_hash"),
        parent_artifacts=_string_tuple_field(body, "parent_artifacts"),
        metadata=_inert_json_object(body["metadata"]),
    )


def _encode_attempt_payload(payload: AttemptAuthorizationPayload) -> dict[str, Any]:
    return _json_value(asdict(payload))


def _decode_attempt_payload(value: Any) -> AttemptAuthorizationPayload:
    body = _exact_object(value, _ATTEMPT_FIELDS, "attempt_payload")
    _require_types(body, strings=_ATTEMPT_STR_FIELDS, integers=_ATTEMPT_INT_FIELDS)
    return AttemptAuthorizationPayload(**body)


def _encode_authorization(
    authorization: SignedAttemptAuthorization,
) -> dict[str, Any]:
    return {
        "payload": _encode_attempt_payload(authorization.payload),
        "signature": authorization.signature,
    }


def _decode_authorization(value: Any) -> SignedAttemptAuthorization:
    body = _exact_object(value, {"payload", "signature"}, "authorization")
    if type(body["signature"]) is not str:
        raise ValueError("invalid_field_type")
    return SignedAttemptAuthorization(
        _decode_attempt_payload(body["payload"]), body["signature"]
    )


def _encode_node_state(state: GovernedNodeState) -> dict[str, Any]:
    return _json_value(asdict(state))


def _decode_node_state(value: Any) -> GovernedNodeState:
    body = _exact_object(value, _NODE_STATE_FIELDS, "node_state")
    _require_types(
        body,
        strings={"workflow_id", "node_id", "status"},
        integers={"version"},
    )
    for field in {"attempt_id", "claimed_by", "artifact_id", "commit_id"}:
        if body[field] is not None and type(body[field]) is not str:
            raise ValueError("invalid_field_type")
    return GovernedNodeState(**body)


def _decode_string_sequence_mapping(
    value: Any, label: str
) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise ValueError(f"invalid_{label}")
    decoded: dict[str, tuple[str, ...]] = {}
    for key, items in value.items():
        if (
            type(key) is not str
            or not isinstance(items, list)
            or any(type(item) is not str for item in items)
        ):
            raise ValueError(f"invalid_{label}")
        decoded[key] = tuple(items)
    return decoded


def _decode_string_mapping(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        type(key) is not str or type(item) is not str for key, item in value.items()
    ):
        raise ValueError(f"invalid_{label}")
    return dict(value)


def _optional_int(value: Any, label: str) -> int | None:
    if value is not None and type(value) is not int:
        raise ValueError(f"invalid_{label}")
    return value


def _trusted_decode(codec: Any, value: Any) -> Any:
    try:
        return codec(value)
    except (TypeError, ValueError) as exc:
        raise GovernanceBypassDenied("authority_unavailable") from exc


class AuthorityOutboxRecoveryError(RuntimeError):
    """Bounded authority-side outbox recovery failure."""


def _recover_outbox(admin: Any) -> None:
    try:
        admin.commit_port._apcc_store.recover_outbox(OutboxRecoveryRequest("100"))
    except Exception as exc:
        raise AuthorityOutboxRecoveryError("outbox_recovery_failed") from exc


def _handle_execution_request(admin: Any, request: Any) -> Any:
    envelope = _exact_object(request, {"operation", "request"}, "request")
    operation = envelope["operation"]
    parameters = envelope["request"]
    if type(operation) is not str or not isinstance(parameters, dict):
        raise ValueError("invalid_request")
    if operation == "health":
        _exact_object(parameters, set(), "health_request")
        return {"authority_pid": os.getpid()}
    if operation == "commit":
        body = _exact_object(parameters, {"commit_request"}, "commit_operation")
        decision = admin.commit(_decode_commit_request(body["commit_request"]))
        _recover_outbox(admin)
        return _encode_commit_decision(decision)
    if operation == "build_request":
        body = _exact_object(parameters, {"receipt"}, "build_request_operation")
        receipt = _exact_object(body["receipt"], {"payload", "signature"}, "receipt")
        if type(receipt["signature"]) is not str:
            raise ValueError("invalid_field_type")
        signed_receipt = SignedGovernedReceipt(
            _decode_receipt_payload(receipt["payload"]), receipt["signature"]
        )
        return _encode_commit_request(admin.build_request(signed_receipt))
    if operation == "authoritative_artifact":
        body = _exact_object(
            parameters,
            {"workflow_id", "artifact_id"},
            "authoritative_artifact_operation",
        )
        _require_types(body, strings={"workflow_id", "artifact_id"})
        return _encode_artifact(
            admin.authoritative_artifact(body["workflow_id"], body["artifact_id"])
        )
    if operation == "attach_workflow":
        fields = {
            "workflow_id",
            "nodes",
            "policy_version",
            "required_capabilities",
            "input_digests",
        }
        body = _exact_object(parameters, fields, "attach_workflow_operation")
        _require_types(body, strings={"workflow_id", "policy_version"})
        states = admin.attach_workflow(
            workflow_id=body["workflow_id"],
            nodes=_decode_string_sequence_mapping(body["nodes"], "nodes"),
            policy_version=body["policy_version"],
            required_capabilities=_decode_string_sequence_mapping(
                body["required_capabilities"], "required_capabilities"
            ),
            input_digests=_decode_string_mapping(
                body["input_digests"], "input_digests"
            ),
        )
        return {node_id: _encode_node_state(state) for node_id, state in states.items()}
    if operation == "node_state":
        body = _exact_object(
            parameters, {"workflow_id", "node_id"}, "node_state_operation"
        )
        _require_types(body, strings={"workflow_id", "node_id"})
        return _encode_node_state(
            admin.node_state(body["workflow_id"], body["node_id"])
        )
    if operation == "workflow_node_states":
        body = _exact_object(
            parameters, {"workflow_id", "node_ids"}, "workflow_node_states_operation"
        )
        _require_types(body, strings={"workflow_id"})
        node_ids = body["node_ids"]
        if type(node_ids) is not list or any(
            type(item) is not str for item in node_ids
        ):
            raise ValueError("invalid_node_ids")
        if not node_ids:
            raise ValueError("empty_node_status_batch")
        if len(node_ids) > 1000:
            raise ValueError("node_status_batch_too_large")
        states = admin.workflow_node_states(body["workflow_id"], tuple(node_ids))
        if len(states) != len(node_ids):
            raise ValueError("node_status_batch_length_mismatch")
        return [_encode_node_state(state) for state in states]
    if operation == "prepare_attempt_authorization":
        fields = {
            "workflow_id",
            "node_id",
            "attempt_id",
            "agent_id",
            "nonce",
            "issued_at",
            "expires_at",
        }
        body = _exact_object(parameters, fields, "prepare_attempt_operation")
        _require_types(
            body,
            strings={"workflow_id", "node_id", "attempt_id", "agent_id", "nonce"},
        )
        return _encode_attempt_payload(
            admin.prepare_attempt_authorization(
                workflow_id=body["workflow_id"],
                node_id=body["node_id"],
                attempt_id=body["attempt_id"],
                agent_id=body["agent_id"],
                nonce=body["nonce"],
                issued_at=_optional_int(body["issued_at"], "issued_at"),
                expires_at=_optional_int(body["expires_at"], "expires_at"),
            )
        )
    if operation == "claim":
        fields = {
            "workflow_id",
            "node_id",
            "attempt_id",
            "agent_id",
            "authorization",
            "required_capabilities",
        }
        body = _exact_object(parameters, fields, "claim_operation")
        _require_types(
            body, strings={"workflow_id", "node_id", "attempt_id", "agent_id"}
        )
        capabilities = body["required_capabilities"]
        if not isinstance(capabilities, list) or any(
            type(item) is not str for item in capabilities
        ):
            raise ValueError("invalid_required_capabilities")
        return _encode_node_state(
            admin.claim(
                workflow_id=body["workflow_id"],
                node_id=body["node_id"],
                attempt_id=body["attempt_id"],
                agent_id=body["agent_id"],
                authorization=_decode_authorization(body["authorization"]),
                required_capabilities=tuple(capabilities),
            )
        )
    if operation == "stage_result":
        fields = {
            "workflow_id",
            "node_id",
            "attempt_id",
            "artifact",
            "authorization",
        }
        body = _exact_object(parameters, fields, "stage_result_operation")
        _require_types(body, strings={"workflow_id", "node_id", "attempt_id"})
        artifact = _decode_artifact(body["artifact"])
        if artifact is None:
            raise ValueError("invalid_artifact")
        return _encode_node_state(
            admin.stage_result(
                workflow_id=body["workflow_id"],
                node_id=body["node_id"],
                attempt_id=body["attempt_id"],
                artifact=artifact,
                authorization=_decode_authorization(body["authorization"]),
            )
        )
    if operation == "prepare_receipt_payload":
        fields = {
            "workflow_id",
            "node_id",
            "attempt_id",
            "agent_id",
            "commit_id",
            "nonce",
            "issued_at",
            "expires_at",
        }
        body = _exact_object(parameters, fields, "prepare_receipt_operation")
        _require_types(
            body,
            strings={
                "workflow_id",
                "node_id",
                "attempt_id",
                "agent_id",
                "commit_id",
                "nonce",
            },
        )
        return _encode_receipt_payload(
            admin.prepare_receipt_payload(
                workflow_id=body["workflow_id"],
                node_id=body["node_id"],
                attempt_id=body["attempt_id"],
                agent_id=body["agent_id"],
                commit_id=body["commit_id"],
                nonce=body["nonce"],
                issued_at=_optional_int(body["issued_at"], "issued_at"),
                expires_at=_optional_int(body["expires_at"], "expires_at"),
            )
        )
    raise LookupError("unknown_operation")


def _handle_admin_request(admin: Any, request: Any) -> Any:
    """Dispatch the exclusive supervisor channel without execution escalation."""
    envelope = _exact_object(request, {"operation", "request"}, "admin_request")
    operation = envelope["operation"]
    parameters = envelope["request"]
    if type(operation) is not str or not isinstance(parameters, dict):
        raise ValueError("invalid_admin_request")
    if operation == "health":
        _exact_object(parameters, set(), "health_request")
        return {"authority_pid": os.getpid()}
    if operation == "create_workflow":
        fields = {
            "workflow_id",
            "nodes",
            "policy_version",
            "required_capabilities",
            "input_digests",
        }
        body = _exact_object(parameters, fields, "create_workflow_operation")
        _require_types(body, strings={"workflow_id", "policy_version"})
        return admin.create_workflow(
            workflow_id=body["workflow_id"],
            nodes=_decode_string_sequence_mapping(body["nodes"], "nodes"),
            policy_version=body["policy_version"],
            required_capabilities=_decode_string_sequence_mapping(
                body["required_capabilities"], "required_capabilities"
            ),
            input_digests=_decode_string_mapping(
                body["input_digests"], "input_digests"
            ),
        )
    if operation == "register_agent":
        body = _exact_object(
            parameters,
            {"workflow_id", "agent_id", "public_key", "capabilities"},
            "register_agent_operation",
        )
        _require_types(body, strings={"workflow_id", "agent_id", "public_key"})
        capabilities = body["capabilities"]
        if not isinstance(capabilities, list) or any(
            type(item) is not str for item in capabilities
        ):
            raise ValueError("invalid_capabilities")
        public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(body["public_key"]))
        return admin.register_agent(
            workflow_id=body["workflow_id"],
            agent_id=body["agent_id"],
            public_key=public_key,
            capabilities=tuple(capabilities),
        )
    if operation == "recover_outbox":
        _exact_object(parameters, set(), "recover_outbox_request")
        _recover_outbox(admin)
        return None
    raise LookupError("unknown_admin_operation")


class _JSONClient:
    __slots__ = (
        "_max_frame_bytes",
        "_channel_socket",
        "_channel_role",
        "_session",
        "_authority_pid",
        "_ipc_public_key",
        "_sequence",
        "_poisoned",
        "_rpc_lock",
    )

    def __init__(self, max_frame_bytes: int) -> None:
        if type(max_frame_bytes) is not int or max_frame_bytes <= 0:
            raise ValueError("max_frame_bytes must be a positive integer")
        self._max_frame_bytes = max_frame_bytes
        self._channel_socket: socket.socket | None = None
        self._channel_role = ""
        self._session = ""
        self._authority_pid = 0
        self._ipc_public_key: bytes | None = None
        self._sequence = 0
        self._poisoned = False
        self._rpc_lock = threading.RLock()

    def _poison(self) -> None:
        self._poisoned = True
        if self._channel_socket is not None:
            self._channel_socket.close()

    def _authenticated_rpc(self, operation: str, request: Mapping[str, Any]) -> Any:
        envelope = {"operation": operation, "request": dict(request)}
        try:
            request_digest = ipc_digest(envelope)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise GovernanceBypassDenied("invalid_request") from exc
        with self._rpc_lock:
            connection = self._channel_socket
            public_key_bytes = self._ipc_public_key
            if self._poisoned or connection is None or public_key_bytes is None:
                raise GovernanceBypassDenied("authority_unavailable")
            self._sequence += 1
            try:
                # Spawn reduction preserves O_NONBLOCK but not the timeout.
                connection.settimeout(2.0)
                send_authenticated_frame(connection, envelope, self._max_frame_bytes)
                response = recv_authenticated_frame(connection, self._max_frame_bytes)
                result, error = verify_response(
                    response,
                    public_key=Ed25519PublicKey.from_public_bytes(public_key_bytes),
                    session=self._session,
                    channel=self._channel_role,
                    sequence=self._sequence,
                    authority_pid=self._authority_pid,
                    request_digest=request_digest,
                )
            except (
                ConnectionError,
                OSError,
                TimeoutError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                self._poison()
                raise GovernanceBypassDenied("authority_unavailable") from exc
        if error is not None:
            message = error.get("message")
            raise GovernanceBypassDenied(
                message
                if isinstance(message, str) and message
                else "authority_unavailable"
            )
        return result

    def close(self) -> None:
        with self._rpc_lock:
            self._poison()

    def _detach_socket(self) -> socket.socket:
        """Transfer the authenticated endpoint exactly once to a spawn child."""
        with self._rpc_lock:
            connection = self._channel_socket
            if self._poisoned or connection is None:
                raise GovernanceBypassDenied("authority_unavailable")
            self._channel_socket = None
            self._poisoned = True
            return connection

    def _reattach_socket(self, connection: socket.socket) -> None:
        """Restore supervisor ownership after a pre-service child abort."""
        with self._rpc_lock:
            if self._channel_socket is not None or not self._poisoned:
                raise RuntimeError("execution channel ownership is ambiguous")
            self._channel_socket = connection
            self._poisoned = False

    def _rpc(self, operation: str, request: Mapping[str, Any]) -> Any:
        return self._authenticated_rpc(operation, request)


_ClientT = TypeVar("_ClientT", bound=_JSONClient)


def _bind_verified_child_channel(
    client_type: type[_ClientT],
    connection: socket.socket,
    *,
    channel_role: str,
    session: str,
    authority_pid: int,
    ipc_public_key: Ed25519PublicKey,
    max_frame_bytes: int,
) -> _ClientT:
    """Bind a channel only after ``start_authority`` verifies readiness."""
    instance = client_type(max_frame_bytes)
    connection.settimeout(2.0)
    instance._channel_socket = connection
    instance._channel_role = channel_role
    instance._session = session
    instance._authority_pid = authority_pid
    instance._ipc_public_key = ipc_public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return instance


class _AuthorityExecutionChannel(_JSONClient):
    """Child-only authenticated authority channel; never a scheduler API."""

    def health(self) -> dict[str, int]:
        result = self._rpc("health", {})
        body = _exact_object(result, {"authority_pid"}, "health_response")
        if type(body["authority_pid"]) is not int:
            raise GovernanceBypassDenied("authority_unavailable")
        return {"authority_pid": body["authority_pid"]}

    def commit(self, request: CommitRequest) -> CommitDecision:
        return _trusted_decode(
            _decode_commit_decision,
            self._rpc("commit", {"commit_request": _encode_commit_request(request)}),
        )

    def build_request(self, receipt: SignedGovernedReceipt) -> CommitRequest:
        return _trusted_decode(
            _decode_commit_request,
            self._rpc(
                "build_request",
                {
                    "receipt": {
                        "payload": _encode_receipt_payload(receipt.payload),
                        "signature": receipt.signature,
                    }
                },
            ),
        )

    def authoritative_artifact(
        self, workflow_id: str, artifact_id: str
    ) -> Artifact | None:
        return _trusted_decode(
            _decode_artifact,
            self._rpc(
                "authoritative_artifact",
                {"workflow_id": workflow_id, "artifact_id": artifact_id},
            ),
        )

    def attach_workflow(
        self,
        *,
        workflow_id: str,
        nodes: Mapping[str, Sequence[str]],
        policy_version: str,
        required_capabilities: Mapping[str, Sequence[str]] | None = None,
        input_digests: Mapping[str, str] | None = None,
    ) -> dict[str, GovernedNodeState]:
        result = self._rpc(
            "attach_workflow",
            {
                "workflow_id": workflow_id,
                "nodes": {key: list(value) for key, value in nodes.items()},
                "policy_version": policy_version,
                "required_capabilities": {
                    key: list(value)
                    for key, value in (required_capabilities or {}).items()
                },
                "input_digests": dict(input_digests or {}),
            },
        )
        if not isinstance(result, dict) or any(type(key) is not str for key in result):
            raise GovernanceBypassDenied("authority_unavailable")
        return {
            node_id: _trusted_decode(_decode_node_state, state)
            for node_id, state in result.items()
        }

    def node_state(self, workflow_id: str, node_id: str) -> GovernedNodeState:
        return self.workflow_node_states(workflow_id, (node_id,))[0]

    def workflow_node_states(
        self, workflow_id: str, node_ids: Sequence[str]
    ) -> tuple[GovernedNodeState, ...]:
        resolved_ids = tuple(node_ids)
        if not resolved_ids:
            raise GovernanceBypassDenied("empty_node_status_batch")
        if len(resolved_ids) > 1000:
            raise GovernanceBypassDenied("node_status_batch_too_large")
        with self._rpc_lock:
            result = self._rpc(
                "workflow_node_states",
                {"workflow_id": workflow_id, "node_ids": list(resolved_ids)},
            )
            if type(result) is not list or len(result) != len(resolved_ids):
                self._poison()
                raise GovernanceBypassDenied("authority_unavailable")
            try:
                states = tuple(
                    _trusted_decode(_decode_node_state, state) for state in result
                )
            except GovernanceBypassDenied:
                self._poison()
                raise
            if any(
                state.workflow_id != workflow_id or state.node_id != node_id
                for node_id, state in zip(resolved_ids, states, strict=True)
            ):
                self._poison()
                raise GovernanceBypassDenied("authority_status_batch_order_mismatch")
            return states

    def prepare_attempt_authorization(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        nonce: str,
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> AttemptAuthorizationPayload:
        return _trusted_decode(
            _decode_attempt_payload,
            self._rpc(
                "prepare_attempt_authorization",
                {
                    "workflow_id": workflow_id,
                    "node_id": node_id,
                    "attempt_id": attempt_id,
                    "agent_id": agent_id,
                    "nonce": nonce,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                },
            ),
        )

    def claim(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        authorization: SignedAttemptAuthorization,
        required_capabilities: Sequence[str] = (),
    ) -> GovernedNodeState:
        return _trusted_decode(
            _decode_node_state,
            self._rpc(
                "claim",
                {
                    "workflow_id": workflow_id,
                    "node_id": node_id,
                    "attempt_id": attempt_id,
                    "agent_id": agent_id,
                    "authorization": _encode_authorization(authorization),
                    "required_capabilities": list(required_capabilities),
                },
            ),
        )

    def stage_result(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        artifact: Artifact,
        authorization: SignedAttemptAuthorization,
    ) -> GovernedNodeState:
        return _trusted_decode(
            _decode_node_state,
            self._rpc(
                "stage_result",
                {
                    "workflow_id": workflow_id,
                    "node_id": node_id,
                    "attempt_id": attempt_id,
                    "artifact": _encode_artifact(artifact),
                    "authorization": _encode_authorization(authorization),
                },
            ),
        )

    def prepare_receipt_payload(
        self,
        *,
        workflow_id: str,
        node_id: str,
        attempt_id: str,
        agent_id: str,
        commit_id: str,
        nonce: str,
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> GovernedReceiptPayload:
        return _trusted_decode(
            _decode_receipt_payload,
            self._rpc(
                "prepare_receipt_payload",
                {
                    "workflow_id": workflow_id,
                    "node_id": node_id,
                    "attempt_id": attempt_id,
                    "agent_id": agent_id,
                    "commit_id": commit_id,
                    "nonce": nonce,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                },
            ),
        )


class AuthorityObserverClient(_JSONClient):
    """Public read-only client pinned to the private-launch readiness key."""

    __slots__ = ("_launch_attestation_digest",)
    _launch_attestation_digest: str

    def __init__(self, max_frame_bytes: int) -> None:
        super().__init__(max_frame_bytes)
        self._launch_attestation_digest = ""

    def observe(
        self, request: AuthorityObservationRequest
    ) -> SignedAuthorityObservation:
        encoded = encode_authority_observation_request(request)
        result = self._rpc(
            "observe",
            {
                "request_b64u": base64.urlsafe_b64encode(encoded)
                .rstrip(b"=")
                .decode("ascii")
            },
        )
        body = _exact_object(result, {"observation_b64u"}, "observation_response")
        encoded_response = body["observation_b64u"]
        if type(encoded_response) is not str:
            raise GovernanceBypassDenied("invalid_observation_response")
        try:
            observation = decode_signed_authority_observation(
                b64u_decode(encoded_response)
            )
            public_key = self._ipc_public_key
            if public_key is None:
                raise ValueError("observer readiness key is unavailable")
            verify_signed_authority_observation(
                observation,
                pinned_public_key=public_key,
                expected_request=request,
                expected_launch_attestation_digest=self._launch_attestation_digest,
                expected_session_id=self._session,
                expected_sequence=str(self._sequence),
            )
        except (TypeError, ValueError) as error:
            self._poison()
            raise GovernanceBypassDenied("invalid_observation_response") from error
        return observation


def _handle_status_sign_request(
    request: Mapping[str, Any], authority_store: Any
) -> dict[str, str]:
    """Derive and sign status inside the authority from two non-normative inputs."""
    envelope = _exact_object(request, {"operation", "request"}, "status_request")
    if envelope["operation"] != "current_status":
        raise LookupError("unknown_status_signing_operation")
    parameters = _exact_object(
        envelope["request"],
        {"certificate_digest", "request_nonce"},
        "status_parameters",
    )
    if any(type(value) is not str for value in parameters.values()):
        raise ValueError("invalid_status_parameters")
    signed = authority_store._observation_current_status(
        parameters["certificate_digest"], parameters["request_nonce"]
    )
    return {"authority_status_b64u": b64u_encode(encode_authority_status(signed))}


class _StatusSigningClient(_JSONClient):
    """Observer-child-only status reader with no other authority operation."""

    def current_status(self, certificate_digest: str, request_nonce: str) -> bytes:
        result = self._rpc(
            "current_status",
            {"certificate_digest": certificate_digest, "request_nonce": request_nonce},
        )
        body = _exact_object(result, {"authority_status_b64u"}, "status_response")
        encoded = body["authority_status_b64u"]
        if type(encoded) is not str:
            raise ValueError("invalid status signing response")
        return b64u_decode(encoded)


def _decode_observer_postgres_credential(raw: bytes) -> str:
    if type(raw) is not bytes or not raw or len(raw) > 4_096 or b"\x00" in raw:
        raise ValueError("invalid PostgreSQL observer credential")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid PostgreSQL observer credential") from error


def _receive_observer_postgres_credential(connection: Any) -> str:
    """Consume exactly one bounded credential frame and close the endpoint."""
    try:
        raw = connection.recv_bytes(4_097)
    except (EOFError, OSError) as error:
        raise ValueError("invalid PostgreSQL observer credential") from error
    finally:
        connection.close()
    return _decode_observer_postgres_credential(raw)


def _observer_child_main(
    backend: AuthorityObserverBackendRef,
    connection: socket.socket,
    status_connection: socket.socket,
    status_session: str,
    authority_pid: int,
    authority_ipc_public_key: bytes,
    readiness: Any,
    launch_nonce: str,
    launch_public: dict[str, str],
    controller_public_key: bytes,
    max_frame_bytes: int,
    credential_connection: Any | None,
) -> None:
    """Serve one isolated read-only observer channel from a spawned child."""
    status_signer: _StatusSigningClient | None = None
    try:
        harden_current_process()
        os.chdir("/")
        os.environ.clear()
        readiness.send({"stage": "HARDENED_READY", "pid": os.getpid(), "dumpable": 0})
        key = Ed25519PrivateKey.generate()
        public_key = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        session = f"session-{secrets.token_urlsafe(24)}"
        key_id = sha256_digest(public_key)
        status_signer = _bind_verified_child_channel(
            _StatusSigningClient,
            status_connection,
            channel_role="status-signing",
            session=status_session,
            authority_pid=authority_pid,
            ipc_public_key=Ed25519PublicKey.from_public_bytes(authority_ipc_public_key),
            max_frame_bytes=max_frame_bytes,
        )
        if backend.kind == "sqlite":
            from pathlib import Path

            from constitutional_swarm.apcc.sqlite_store import SQLiteAuthorityReader

            observer: AuthorityObservationStore = SQLiteAuthorityReader.open(
                Path(backend.sqlite_path or ""), status_signer=status_signer
            )
        else:
            from constitutional_swarm.apcc.postgres_store import PostgresAuthorityReader

            if credential_connection is None:
                raise ValueError("missing PostgreSQL observer credential channel")
            credential_channel = credential_connection
            credential_connection = None
            dsn = _receive_observer_postgres_credential(credential_channel)
            assert backend.schema is not None
            observer = PostgresAuthorityReader.open(
                dsn, schema=backend.schema, status_signer=status_signer
            )
            dsn = ""
        read_transaction = getattr(observer, "_read_transaction", None)
        if read_transaction is None:
            raise TypeError("observer store does not expose attested launch facts")
        with read_transaction() as launch_connection:
            trust_row = launch_connection.execute(
                "SELECT sequence,entry_digest FROM trust_log "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        initial_trust_sequence = "0" if trust_row is None else str(trust_row[0])
        initial_trust_head = (
            sha256_digest(b"APCC-1/trust-log/genesis")
            if trust_row is None
            else str(trust_row[1])
        )
        ready_body = {
            "protocol_version": "APCC-1.0-draft",
            "statement_type": "apcc.observer-launch-attestation",
            **launch_public,
            "observer_pid": str(os.getpid()),
            "launch_nonce": launch_nonce,
            "session_id": session,
            "observer_key_id": key_id,
            "observer_public_key": base64.urlsafe_b64encode(public_key)
            .rstrip(b"=")
            .decode("ascii"),
            "initial_trust_sequence": initial_trust_sequence,
            "initial_trust_head": initial_trust_head,
        }
        readiness.send(ready_body)
        if not readiness.poll(5):
            raise TimeoutError("controller launch attestation timed out")
        launch_attestation = readiness.recv()
        if not isinstance(launch_attestation, dict) or set(launch_attestation) != {
            *ready_body,
            "controller_key_id",
            "controller_signature",
        }:
            raise ValueError("invalid controller launch attestation")
        if any(launch_attestation[key] != value for key, value in ready_body.items()):
            raise ValueError("controller launch attestation binding mismatch")
        from constitutional_swarm.apcc.observation import CONTROLLER_LAUNCH_DOMAIN

        controller_body = {
            key: value
            for key, value in launch_attestation.items()
            if key not in {"controller_key_id", "controller_signature"}
        }
        Ed25519PublicKey.from_public_bytes(controller_public_key).verify(
            b64u_decode(launch_attestation["controller_signature"]),
            CONTROLLER_LAUNCH_DOMAIN + b"\x00" + canonical_json(controller_body),
        )
        launch_attestation_digest = sha256_digest(canonical_json(launch_attestation))
        tcb_ready_body = {
            "stage": "OBSERVER_TCB_READY",
            "pid": os.getpid(),
            "session_id": session,
            "launch_nonce": launch_nonce,
            "launch_attestation_digest": launch_attestation_digest,
            "observer_key_id": key_id,
        }
        tcb_ready = {
            **tcb_ready_body,
            "signature": b64u_encode(
                key.sign(
                    b"APCC-B6-OBSERVER-TCB-READY-V1\x00"
                    + canonical_json(tcb_ready_body)
                )
            ),
        }
        connection.settimeout(2.0)
        readiness.send(tcb_ready)
        readiness.close()
        sequence = 0
        while True:
            try:
                request_envelope = recv_authenticated_frame(connection, max_frame_bytes)
            except (ConnectionError, OSError, TimeoutError, ValueError):
                return
            sequence += 1
            request_digest = ipc_digest(request_envelope)
            try:
                envelope = _exact_object(
                    request_envelope, {"operation", "request"}, "observer_request"
                )
                if envelope["operation"] != "observe":
                    raise LookupError("unknown_observer_operation")
                parameters = _exact_object(
                    envelope["request"], {"request_b64u"}, "observe_request"
                )
                if type(parameters["request_b64u"]) is not str:
                    raise ValueError("invalid_observation_request")
                decoded_request = decode_authority_observation_request(
                    b64u_decode(parameters["request_b64u"])
                )
                snapshot = observer.observe_authority(decoded_request)
                signature = Signature(
                    "Ed25519",
                    key_id,
                    base64.urlsafe_b64encode(
                        key.sign(
                            AUTHORITY_OBSERVATION_DOMAIN
                            + b"\x00"
                            + encode_authority_observation_body(
                                snapshot,
                                launch_attestation_digest=launch_attestation_digest,
                                session_id=session,
                                sequence=str(sequence),
                                request_digest=decoded_request.canonical_digest,
                            )
                        )
                    )
                    .rstrip(b"=")
                    .decode("ascii"),
                )
                signed = SignedAuthorityObservation(
                    snapshot,
                    launch_attestation_digest,
                    session,
                    str(sequence),
                    decoded_request.canonical_digest,
                    key_id,
                    signature,
                )
                encoded = encode_signed_authority_observation(signed)
                result = {
                    "observation_b64u": base64.urlsafe_b64encode(encoded)
                    .rstrip(b"=")
                    .decode("ascii")
                }
                response = signed_response(
                    key=key,
                    session=session,
                    channel="observer",
                    sequence=sequence,
                    authority_pid=os.getpid(),
                    request_digest=request_digest,
                    result=result,
                )
            except Exception as error:
                response = signed_response(
                    key=key,
                    session=session,
                    channel="observer",
                    sequence=sequence,
                    authority_pid=os.getpid(),
                    request_digest=request_digest,
                    error={"code": type(error).__name__, "message": str(error)},
                )
            try:
                send_authenticated_frame(connection, response, max_frame_bytes)
            except (ConnectionError, OSError, ValueError):
                return
    except BaseException as error:
        try:
            readiness.send({"startup_error": type(error).__name__})
        except (BrokenPipeError, OSError):
            pass
        raise
    finally:
        readiness.close()
        connection.close()
        if status_signer is not None:
            status_signer.close()
        else:
            status_connection.close()
        if credential_connection is not None:
            credential_connection.close()


def _safe_close(resource: Any) -> None:
    try:
        resource.close()
    except (AttributeError, OSError):
        pass


def _controlled_boot_result(
    phase: ControlledBootPhase,
    *,
    controller_source_consumed: bool | None = None,
) -> ControlledBootResult:
    publishable = phase in {
        ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
    }
    observer_ready = phase in {
        ControlledBootPhase.OBSERVER_READY,
        ControlledBootPhase.SCHEDULER_STARTING_PUBLISHABLE,
        ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
    }
    return ControlledBootResult(
        profile="linux-controlled-boot-v1",
        phase=phase,
        evidence=(
            ControlledBootEvidence.PUBLISHABLE
            if publishable
            else ControlledBootEvidence.NONPUBLISHABLE
        ),
        authority_source_consumed=True,
        controller_source_consumed=(
            observer_ready
            if controller_source_consumed is None
            else controller_source_consumed
        ),
        observer_ready=observer_ready,
        positive_assumptions=CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
        residual_exclusions=CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
    )


def _abort_process(process: Any) -> None:
    try:
        pid = process.pid
    except ValueError:
        return
    if pid is not None:
        try:
            alive = process.is_alive()
        except (AssertionError, OSError, ValueError):
            alive = False
        if alive:
            try:
                process.terminate()
            except (OSError, ValueError):
                pass
            try:
                process.join(0.5)
            except (AssertionError, OSError, ValueError):
                pass
        try:
            alive = process.is_alive()
        except (AssertionError, OSError, ValueError):
            alive = False
        if alive:
            try:
                if hasattr(process, "kill"):
                    process.kill()
                else:
                    os.kill(pid, 9)
            except (OSError, ValueError):
                pass
            try:
                process.join(1)
            except (AssertionError, OSError, ValueError):
                pass
        try:
            alive = process.is_alive()
        except (AssertionError, OSError, ValueError):
            alive = False
        if alive:
            raise RuntimeError("privileged child did not terminate")
        try:
            process.join(0)
        except (AssertionError, OSError, ValueError):
            pass
    try:
        process.close()
    except (AttributeError, ValueError):
        pass


def _verify_hardened_ready(value: Any, pid: int, role: str) -> None:
    if value != {"stage": "HARDENED_READY", "pid": pid, "dumpable": 0}:
        raise IsolationUnavailable(
            f"ISOLATION_UNAVAILABLE: invalid {role} hardening readiness"
        )


def _verify_observer_tcb_ready(
    value: Any,
    *,
    pid: int,
    session_id: str,
    launch_nonce: str,
    launch_attestation_digest: str,
    observer_key_id: str,
    observer_public_key: Ed25519PublicKey,
) -> None:
    fields = {
        "stage",
        "pid",
        "session_id",
        "launch_nonce",
        "launch_attestation_digest",
        "observer_key_id",
        "signature",
    }
    if type(value) is not dict or set(value) != fields:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: invalid observer TCB readiness"
        )
    expected_body = {
        "stage": "OBSERVER_TCB_READY",
        "pid": pid,
        "session_id": session_id,
        "launch_nonce": launch_nonce,
        "launch_attestation_digest": launch_attestation_digest,
        "observer_key_id": observer_key_id,
    }
    body = {key: value[key] for key in expected_body}
    if body != expected_body or type(value["signature"]) is not str:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: observer TCB readiness binding mismatch"
        )
    try:
        observer_public_key.verify(
            b64u_decode(value["signature"]),
            b"APCC-B6-OBSERVER-TCB-READY-V1\x00" + canonical_json(body),
        )
    except (ValueError, TypeError, InvalidSignature) as error:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: unauthenticated observer TCB readiness"
        ) from error


class _ControllerSigner:
    """Supervisor-held capability for exactly one controller launch signature."""

    __slots__ = ("_process", "_channel", "_used")

    def __init__(self, process: Any, channel: Any) -> None:
        self._process = process
        self._channel = channel
        self._used = False

    def sign(self, candidate: dict[str, object]) -> dict[str, object]:
        if self._used:
            raise GovernanceBypassDenied("controller_signer_already_used")
        self._used = True
        encoded = canonical_json(candidate)
        if len(encoded) > 16_384:
            raise ValueError("controller launch candidate is too large")
        self._channel.send_bytes(encoded)
        if not self._channel.poll(5):
            raise TimeoutError("controller signer timed out")
        try:
            response = self._channel.recv_bytes(16_385)
        except (EOFError, OSError) as error:
            raise RuntimeError("controller signer failed") from error
        try:
            value = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("invalid controller signer response") from error
        if type(value) is not dict:
            raise RuntimeError("invalid controller signer response")
        self.close()
        return value

    def close(self) -> None:
        _safe_close(self._channel)
        _abort_process(self._process)


def _start_controller_signer(reference: Any, secret: bytearray) -> _ControllerSigner:
    from constitutional_swarm.authority_observer import (
        ControllerKeySourceRef,
        controller_signer_child_main,
    )

    sanitized = ControllerKeySourceRef(
        "consumed:controller", reference.expected_public_key
    )
    context = multiprocessing.get_context("spawn")
    with ExitStack() as cleanup:
        cleanup.callback(erase_secret, secret)
        parent, child = context.Pipe(duplex=True)
        cleanup.callback(_safe_close, parent)
        cleanup.callback(_safe_close, child)
        process = context.Process(
            target=controller_signer_child_main,
            args=(sanitized, child),
            name="apcc-controller-signer-child",
        )
        cleanup.callback(_abort_process, process)
        process.start()
        pid = process.pid
        if pid is None:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: controller signer has no process identity"
            )
        child.close()
        if not parent.poll(5):
            raise TimeoutError("controller signer hardening readiness timed out")
        _verify_hardened_ready(parent.recv(), pid, "controller signer")
        parent.send_bytes(secret)
        erase_secret(secret)
        if not parent.poll(5):
            raise TimeoutError("controller signer TCB readiness timed out")
        ready = parent.recv()
        expected = {
            "stage": "TCB_READY",
            "pid": pid,
            "controller_key_id": sha256_digest(reference.expected_public_key),
        }
        if ready != expected:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: controller signer TCB readiness mismatch"
            )
        signer = _ControllerSigner(process, parent)
        cleanup.pop_all()
        return signer


def _start_observer(
    backend: AuthorityObserverBackendRef,
    *,
    status_connection: socket.socket,
    status_session: str,
    authority_pid: int,
    authority_ipc_public_key: bytes,
    max_frame_bytes: int,
    launch_public: dict[str, str],
    controller_signer: _ControllerSigner,
    controller_key_id: str,
    controller_public_key: bytes,
    postgres_observer_dsn: str | None = None,
) -> tuple[Any, AuthorityObserverClient, dict[str, object]]:
    if backend.kind == "postgresql":
        if type(postgres_observer_dsn) is not str:
            raise ValueError("PostgreSQL observer credential is required")
        credential_bytes = postgres_observer_dsn.encode("utf-8")
        _decode_observer_postgres_credential(credential_bytes)
    elif postgres_observer_dsn is not None:
        raise ValueError("SQLite observer does not accept PostgreSQL credentials")
    else:
        credential_bytes = None
    context = multiprocessing.get_context("spawn")
    with ExitStack() as cleanup:
        cleanup.callback(_safe_close, status_connection)
        parent, child = socket.socketpair(socket.AF_UNIX)
        cleanup.callback(_safe_close, parent)
        cleanup.callback(_safe_close, child)
        ready_parent, ready_child = context.Pipe(duplex=True)
        cleanup.callback(_safe_close, ready_parent)
        cleanup.callback(_safe_close, ready_child)
        if credential_bytes is not None:
            credential_recv, credential_send = context.Pipe(duplex=False)
            cleanup.callback(_safe_close, credential_recv)
            cleanup.callback(_safe_close, credential_send)
        else:
            credential_recv, credential_send = None, None
        launch_nonce = (
            base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        )
        process = context.Process(
            target=_observer_child_main,
            args=(
                backend,
                child,
                status_connection,
                status_session,
                authority_pid,
                authority_ipc_public_key,
                ready_child,
                launch_nonce,
                launch_public,
                controller_public_key,
                max_frame_bytes,
                credential_recv,
            ),
            name="apcc-authority-observer-child",
        )
        cleanup.callback(_abort_process, process)
        process.start()
        observer_pid = process.pid
        if observer_pid is None:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: observer child has no process identity"
            )
        child.close()
        status_connection.close()
        ready_child.close()
        if credential_recv is not None:
            credential_recv.close()
        if not ready_parent.poll(5):
            raise TimeoutError("observer hardening readiness timed out")
        hardened = ready_parent.recv()
        _verify_hardened_ready(hardened, observer_pid, "observer")
        if credential_send is not None:
            try:
                assert credential_bytes is not None
                credential_send.send_bytes(credential_bytes)
            finally:
                credential_send.close()
        if not ready_parent.poll(5):
            raise TimeoutError("observer readiness timed out")
        ready = ready_parent.recv()
        if not isinstance(ready, dict) or "startup_error" in ready:
            raise RuntimeError(f"observer startup failed: {ready}")
        fields = {
            "protocol_version",
            "statement_type",
            *launch_public,
            "observer_pid",
            "launch_nonce",
            "session_id",
            "observer_key_id",
            "observer_public_key",
            "initial_trust_sequence",
            "initial_trust_head",
        }
        if set(ready) != fields or (
            ready["protocol_version"] != "APCC-1.0-draft"
            or ready["statement_type"] != "apcc.observer-launch-attestation"
            or ready["observer_pid"] != str(observer_pid)
            or ready["launch_nonce"] != launch_nonce
            or any(ready[key] != value for key, value in launch_public.items())
        ):
            raise RuntimeError("observer readiness binding mismatch")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64u_decode(ready["observer_public_key"])
        )
        if ready["observer_key_id"] != sha256_digest(
            public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ):
            raise RuntimeError("observer readiness key mismatch")
        launch_attestation = controller_signer.sign(ready)
        if launch_attestation.get("controller_key_id") != controller_key_id:
            raise RuntimeError("controller signer identity mismatch")
        ready_parent.send(launch_attestation)
        launch_attestation_digest = sha256_digest(canonical_json(launch_attestation))
        if not ready_parent.poll(5):
            raise TimeoutError("observer TCB readiness timed out")
        _verify_observer_tcb_ready(
            ready_parent.recv(),
            pid=observer_pid,
            session_id=ready["session_id"],
            launch_nonce=launch_nonce,
            launch_attestation_digest=launch_attestation_digest,
            observer_key_id=ready["observer_key_id"],
            observer_public_key=public_key,
        )
        client = _bind_verified_child_channel(
            AuthorityObserverClient,
            parent,
            channel_role="observer",
            session=ready["session_id"],
            authority_pid=observer_pid,
            ipc_public_key=public_key,
            max_frame_bytes=max_frame_bytes,
        )
        client._launch_attestation_digest = launch_attestation_digest
        ready_parent.close()
        cleanup.pop_all()
        return process, client, launch_attestation


class AuthorityAdminClient:
    """Distinct supervisor client; it exposes no execution operations."""

    __slots__ = ("_client",)

    def __init__(self, client: _JSONClient) -> None:
        self._client = client

    def health(self) -> dict[str, int]:
        result = self._client._rpc("health", {})
        body = _exact_object(result, {"authority_pid"}, "health_response")
        if type(body["authority_pid"]) is not int:
            raise GovernanceBypassDenied("authority_unavailable")
        return {"authority_pid": body["authority_pid"]}

    def create_workflow(
        self,
        *,
        workflow_id: str,
        nodes: Mapping[str, Sequence[str]],
        policy_version: str,
        required_capabilities: Mapping[str, Sequence[str]] | None = None,
        input_digests: Mapping[str, str] | None = None,
    ) -> int | None:
        result = self._client._rpc(
            "create_workflow",
            {
                "workflow_id": workflow_id,
                "nodes": {key: list(value) for key, value in nodes.items()},
                "policy_version": policy_version,
                "required_capabilities": {
                    key: list(value)
                    for key, value in (required_capabilities or {}).items()
                },
                "input_digests": dict(input_digests or {}),
            },
        )
        if result is not None and type(result) is not int:
            raise GovernanceBypassDenied("authority_unavailable")
        return result

    def register_agent(
        self,
        *,
        workflow_id: str,
        agent_id: str,
        public_key: Ed25519PublicKey,
        capabilities: Sequence[str] = (),
    ) -> int | None:
        encoded = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        result = self._client._rpc(
            "register_agent",
            {
                "workflow_id": workflow_id,
                "agent_id": agent_id,
                "public_key": base64.urlsafe_b64encode(encoded).rstrip(b"=").decode(),
                "capabilities": list(capabilities),
            },
        )
        if result is not None and type(result) is not int:
            raise GovernanceBypassDenied("authority_unavailable")
        return result

    def recover_outbox(self) -> None:
        self._client._rpc("recover_outbox", {})

    def close(self) -> None:
        self._client.close()


_TASK_NODE_FIELDS = {
    "node_id",
    "title",
    "description",
    "domain",
    "required_capabilities",
    "depends_on",
    "priority",
    "max_budget_tokens",
    "status",
    "claimed_by",
    "artifact_id",
    "metadata",
}


def _encode_task_node(node: Any) -> dict[str, Any]:
    return {
        "node_id": node.node_id,
        "title": node.title,
        "description": node.description,
        "domain": node.domain,
        "required_capabilities": list(node.required_capabilities),
        "depends_on": list(node.depends_on),
        "priority": node.priority,
        "max_budget_tokens": node.max_budget_tokens,
        "status": node.status.value,
        "claimed_by": node.claimed_by,
        "artifact_id": node.artifact_id,
        "metadata": _inert_json_value(node.metadata),
    }


def _decode_task_node(value: Any) -> Any:
    from constitutional_swarm.execution import ExecutionStatus
    from constitutional_swarm.swarm import TaskNode

    body = _exact_object(value, _TASK_NODE_FIELDS, "task_node")
    strings = {"node_id", "title", "description", "domain", "status"}
    _require_types(body, strings=strings, integers={"priority", "max_budget_tokens"})
    for field in ("required_capabilities", "depends_on"):
        if type(body[field]) is not list or any(
            type(item) is not str for item in body[field]
        ):
            raise ValueError("invalid_task_node")
    for field in ("claimed_by", "artifact_id"):
        if body[field] is not None and type(body[field]) is not str:
            raise ValueError("invalid_task_node")
    metadata = _inert_json_object(body["metadata"])
    return TaskNode(
        node_id=_string_field(body, "node_id"),
        title=_string_field(body, "title"),
        description=_string_field(body, "description"),
        domain=_string_field(body, "domain"),
        required_capabilities=_string_tuple_field(body, "required_capabilities"),
        depends_on=_string_tuple_field(body, "depends_on"),
        priority=_integer_field(body, "priority"),
        max_budget_tokens=_integer_field(body, "max_budget_tokens"),
        status=ExecutionStatus(_string_field(body, "status")),
        claimed_by=_optional_string_field(body, "claimed_by"),
        artifact_id=_optional_string_field(body, "artifact_id"),
        metadata=metadata,
    )


def _encode_task_dag(dag: Any) -> dict[str, Any]:
    if type(dag.nodes) is not dict:
        raise TypeError("DAG nodes must be an exact dictionary")
    return {
        "dag_id": dag.dag_id,
        "goal": dag.goal,
        "nodes": {key: _encode_task_node(node) for key, node in dag.nodes.items()},
    }


def _decode_task_dag(value: Any) -> Any:
    from constitutional_swarm.swarm import TaskDAG

    body = _exact_object(value, {"dag_id", "goal", "nodes"}, "task_dag")
    _require_types(body, strings={"dag_id", "goal"})
    if type(body["nodes"]) is not dict or any(
        type(key) is not str for key in body["nodes"]
    ):
        raise ValueError("invalid_task_dag")
    nodes = {key: _decode_task_node(node) for key, node in body["nodes"].items()}
    if any(key != node.node_id for key, node in nodes.items()):
        raise ValueError("task_node_identity_mismatch")
    return TaskDAG(dag_id=body["dag_id"], goal=body["goal"], nodes=nodes)


def _encode_work_receipt(receipt: WorkReceipt) -> dict[str, Any]:
    return {
        "task_id": receipt.task_id,
        "title": receipt.title,
        "description": receipt.description,
        "domain": receipt.domain,
        "required_capabilities": list(receipt.required_capabilities),
        "status": receipt.status.value,
        "claimed_by": receipt.claimed_by,
        "priority": receipt.priority,
    }


def _decode_work_receipt(value: Any) -> WorkReceipt:
    fields = {
        "task_id",
        "title",
        "description",
        "domain",
        "required_capabilities",
        "status",
        "claimed_by",
        "priority",
    }
    body = _exact_object(value, fields, "work_receipt")
    _require_types(
        body,
        strings={"task_id", "title", "description", "domain", "status"},
        integers={"priority"},
    )
    capabilities = body["required_capabilities"]
    if type(capabilities) is not list or any(
        type(item) is not str for item in capabilities
    ):
        raise ValueError("invalid_work_receipt")
    if body["claimed_by"] is not None and type(body["claimed_by"]) is not str:
        raise ValueError("invalid_work_receipt")
    return WorkReceipt(
        task_id=body["task_id"],
        title=body["title"],
        description=body["description"],
        domain=body["domain"],
        required_capabilities=tuple(capabilities),
        status=ContractStatus(body["status"]),
        claimed_by=body["claimed_by"],
        priority=body["priority"],
    )


def _registry_snapshot(registry: CapabilityRegistry) -> dict[str, Any]:
    if type(registry) is not CapabilityRegistry:
        raise TypeError("registry_snapshot must be an exact CapabilityRegistry")
    snapshot: dict[str, Any] = {}
    registrations = registry._by_agent
    if type(registrations) is not dict:
        raise TypeError("registry_snapshot is not inert metadata")
    for agent_id, capabilities in registrations.items():
        if type(agent_id) is not str or type(capabilities) is not list:
            raise TypeError("registry_snapshot is not inert metadata")
        encoded: list[dict[str, Any]] = []
        for capability in capabilities:
            if type(capability) is not Capability:
                raise TypeError("registry_snapshot is not inert metadata")
            encoded.append(
                {
                    "name": capability.name,
                    "domain": capability.domain,
                    "description": capability.description,
                    "model_tier": capability.model_tier,
                    "avg_latency_ms": capability.avg_latency_ms,
                    "cost_per_task": capability.cost_per_task,
                    "tags": list(capability.tags),
                }
            )
        snapshot[agent_id] = _inert_json_value(encoded)
    return snapshot


def _decode_registry_snapshot(value: Any) -> CapabilityRegistry:
    if type(value) is not dict:
        raise ValueError("invalid_registry_snapshot")
    registry = CapabilityRegistry()
    fields = {
        "name",
        "domain",
        "description",
        "model_tier",
        "avg_latency_ms",
        "cost_per_task",
        "tags",
    }
    for agent_id, encoded in value.items():
        if type(agent_id) is not str or type(encoded) is not list:
            raise ValueError("invalid_registry_snapshot")
        capabilities: list[Capability] = []
        for item in encoded:
            body = _exact_object(item, fields, "capability")
            _require_types(
                body,
                strings={"name", "domain", "description", "model_tier"},
            )
            if type(body["avg_latency_ms"]) not in {int, float} or type(
                body["cost_per_task"]
            ) not in {int, float}:
                raise ValueError("invalid_capability")
            if type(body["tags"]) is not list or any(
                type(tag) is not str for tag in body["tags"]
            ):
                raise ValueError("invalid_capability")
            capabilities.append(
                Capability(
                    name=_string_field(body, "name"),
                    domain=_string_field(body, "domain"),
                    description=_string_field(body, "description"),
                    model_tier=_string_field(body, "model_tier"),
                    avg_latency_ms=_float_field(body, "avg_latency_ms"),
                    cost_per_task=_float_field(body, "cost_per_task"),
                    tags=_string_tuple_field(body, "tags"),
                )
            )
        registry.register(agent_id, capabilities)
    return registry


def _scheduler_dispatch(executor: Any, operation: str, request: Any) -> Any:
    body = request if type(request) is dict else None
    if body is None:
        raise ValueError("invalid_scheduler_request")
    if operation == "health":
        _exact_object(body, set(), "health")
        return {"executor_pid": os.getpid()}
    if operation == "load_dag":
        payload = _exact_object(body, {"dag"}, "load_dag")
        executor.load_dag(_decode_task_dag(payload["dag"]))
        return None
    if operation == "available_tasks":
        payload = _exact_object(body, {"agent_id"}, "available_tasks")
        _require_types(payload, strings={"agent_id"})
        return [
            _encode_task_node(node)
            for node in executor.available_tasks(payload["agent_id"])
        ]
    if operation == "prepare_claim":
        payload = _exact_object(body, {"node_id", "agent_id"}, "prepare_claim")
        _require_types(payload, strings={"node_id", "agent_id"})
        return _encode_attempt_payload(
            executor.prepare_claim(payload["node_id"], payload["agent_id"])
        )
    if operation == "claim":
        payload = _exact_object(body, {"node_id", "agent_id", "authorization"}, "claim")
        _require_types(payload, strings={"node_id", "agent_id"})
        return _encode_work_receipt(
            executor.claim(
                payload["node_id"],
                payload["agent_id"],
                _decode_authorization(payload["authorization"]),
            )
        )
    if operation == "produce_result":
        payload = _exact_object(
            body, {"node_id", "artifact", "authorization"}, "produce_result"
        )
        _require_types(payload, strings={"node_id"})
        artifact = _decode_artifact(payload["artifact"])
        if artifact is None:
            raise ValueError("invalid_artifact")
        authorization = (
            None
            if payload["authorization"] is None
            else _decode_authorization(payload["authorization"])
        )
        return _encode_receipt_payload(
            executor.produce_result(
                payload["node_id"], artifact, authorization=authorization
            )
        )
    if operation == "build_request":
        payload = _exact_object(body, {"receipt"}, "build_request")
        receipt = _exact_object(payload["receipt"], {"payload", "signature"}, "receipt")
        if type(receipt["signature"]) is not str:
            raise ValueError("invalid_receipt")
        signed = SignedGovernedReceipt(
            _decode_receipt_payload(receipt["payload"]), receipt["signature"]
        )
        return _encode_commit_request(executor._authority_call("build_request", signed))
    if operation == "commit":
        payload = _exact_object(body, {"request"}, "commit")
        return _encode_commit_decision(
            executor.commit(_decode_commit_request(payload["request"]))
        )
    if operation == "authoritative_artifact":
        payload = _exact_object(body, {"artifact_id"}, "authoritative_artifact")
        _require_types(payload, strings={"artifact_id"})
        return _encode_artifact(executor.authoritative_artifact(payload["artifact_id"]))
    if operation == "is_complete":
        _exact_object(body, set(), "is_complete")
        return executor.is_complete
    if operation == "progress":
        _exact_object(body, set(), "progress")
        return executor.progress
    raise LookupError("unknown_scheduler_operation")


_SCHEDULER_READY_DOMAIN = b"APCC-B6-DORMANT-SCHEDULER-READY-V1"
_SCHEDULER_ACTIVE_DOMAIN = b"APCC-B6-DORMANT-SCHEDULER-ACTIVE-V1"


def _scheduler_signed_message(
    body: Mapping[str, object], key: Ed25519PrivateKey, domain: bytes
) -> bytes:
    return canonical_json(
        {
            **body,
            "signature": b64u_encode(key.sign(domain + b"\x00" + canonical_json(body))),
        }
    )


def _decode_scheduler_ancillary(
    ancillary: list[tuple[int, int, bytes]], flags: int
) -> tuple[int, int]:
    descriptor_size = array.array("i").itemsize
    received_rights: list[int] = []
    for level, kind, raw in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        complete = len(raw) - (len(raw) % descriptor_size)
        decoded = array.array("i")
        decoded.frombytes(raw[:complete])
        received_rights.extend(decoded)
    try:
        if flags & (getattr(socket, "MSG_CTRUNC", 0) | getattr(socket, "MSG_TRUNC", 0)):
            raise ValueError("truncated scheduler activation")
        if len(ancillary) != 1:
            raise ValueError("invalid scheduler descriptor envelope")
        level, kind, raw = ancillary[0]
        if (
            level != socket.SOL_SOCKET
            or kind != socket.SCM_RIGHTS
            or len(raw) != 2 * descriptor_size
        ):
            raise ValueError("invalid scheduler descriptor envelope")
        if len(received_rights) != 2 or any(
            descriptor < 0 for descriptor in received_rights
        ):
            raise ValueError("invalid scheduler descriptor count")
        return received_rights[0], received_rights[1]
    except BaseException:
        for descriptor in set(received_rights):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _receive_scheduler_activation(
    control: socket.socket, max_frame_bytes: int
) -> tuple[dict[str, Any], socket.socket, socket.socket]:
    descriptor_size = array.array("i").itemsize
    payload, ancillary, flags, _address = control.recvmsg(
        max_frame_bytes + 1,
        socket.CMSG_SPACE(2 * descriptor_size),
        getattr(socket, "MSG_CMSG_CLOEXEC", 0),
    )
    descriptors: tuple[int, int] | None = None
    scheduler_socket: socket.socket | None = None
    authority_socket: socket.socket | None = None
    try:
        if not payload and not ancillary:
            raise EOFError("scheduler activation channel closed")
        if not payload or len(payload) > max_frame_bytes:
            raise ValueError("invalid scheduler activation frame")
        descriptors = _decode_scheduler_ancillary(ancillary, flags)
        try:
            message = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid scheduler activation frame") from error
        body = _exact_object(
            message,
            {
                "stage",
                "launch_nonce",
                "scheduler_session",
                "authority_session",
                "authority_pid",
                "ipc_public_key",
                "max_frame_bytes",
                "policy_version",
                "registry_snapshot",
            },
            "scheduler_activation",
        )
        if (
            body["stage"] != "ACTIVATE_SCHEDULER"
            or type(body["launch_nonce"]) is not str
            or type(body["scheduler_session"]) is not str
            or type(body["authority_session"]) is not str
            or type(body["authority_pid"]) is not int
            or type(body["ipc_public_key"]) is not str
            or type(body["max_frame_bytes"]) is not int
            or type(body["policy_version"]) is not str
            or type(body["registry_snapshot"]) is not dict
        ):
            raise ValueError("invalid scheduler activation binding")
        scheduler_socket = socket.socket(fileno=descriptors[0])
        authority_socket = socket.socket(fileno=descriptors[1])
        descriptors = None
        for endpoint in (scheduler_socket, authority_socket):
            if (
                endpoint.family != socket.AF_UNIX
                or endpoint.type != socket.SOCK_STREAM
                or os.get_inheritable(endpoint.fileno())
            ):
                raise ValueError("invalid scheduler activation descriptor type")
        return body, scheduler_socket, authority_socket
    except BaseException:
        if scheduler_socket is not None:
            scheduler_socket.close()
        if authority_socket is not None:
            authority_socket.close()
        if descriptors is not None:
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _dormant_scheduler_child(
    control: socket.socket,
    launch_nonce: str,
    scheduler_session: str,
    max_frame_bytes: int,
) -> None:
    """Harden before secrets exist, then remain inert until descriptor admission."""
    harden_current_process()
    os.chdir("/")
    os.environ.clear()
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = sha256_digest(public_key)
    ready_body = {
        "stage": "DORMANT_SCHEDULER_HARDENED_READY",
        "pid": os.getpid(),
        "role": "scheduler",
        "launch_nonce": launch_nonce,
        "scheduler_session": scheduler_session,
        "scheduler_key_id": key_id,
        "scheduler_public_key": b64u_encode(public_key),
        "dumpable": 0,
    }
    try:
        control.send(
            _scheduler_signed_message(ready_body, key, _SCHEDULER_READY_DOMAIN)
        )
        body, scheduler_socket, authority_socket = _receive_scheduler_activation(
            control, max_frame_bytes
        )
        if (
            body["launch_nonce"] != launch_nonce
            or body["scheduler_session"] != scheduler_session
            or body["max_frame_bytes"] != max_frame_bytes
        ):
            raise ValueError("scheduler activation cross-binding")
        active_body = {
            "stage": "SCHEDULER_ACTIVATED_READY",
            "pid": os.getpid(),
            "launch_nonce": launch_nonce,
            "scheduler_session": scheduler_session,
            "scheduler_key_id": key_id,
        }
        control.send(
            _scheduler_signed_message(active_body, key, _SCHEDULER_ACTIVE_DOMAIN)
        )
    except EOFError:
        control.close()
        return
    except BaseException:
        control.close()
        raise
    control.close()
    from constitutional_swarm.swarm import SwarmExecutor

    scheduler_socket.settimeout(2.0)
    authority_channel = _bind_verified_child_channel(
        _AuthorityExecutionChannel,
        authority_socket,
        channel_role="execution",
        session=body["authority_session"],
        authority_pid=body["authority_pid"],
        ipc_public_key=Ed25519PublicKey.from_public_bytes(
            b64u_decode(body["ipc_public_key"])
        ),
        max_frame_bytes=body["max_frame_bytes"],
    )
    executor = SwarmExecutor(
        _decode_registry_snapshot(body["registry_snapshot"]),
        ArtifactStore(),
        policy_version=body["policy_version"],
    )
    executor._execution_client = authority_channel
    sequence = 0
    try:
        while True:
            envelope = recv_authenticated_frame(scheduler_socket, max_frame_bytes)
            request = _exact_object(
                envelope, {"sequence", "operation", "request"}, "scheduler_envelope"
            )
            if (
                type(request["sequence"]) is not int
                or request["sequence"] != sequence + 1
                or type(request["operation"]) is not str
            ):
                raise ValueError("invalid_scheduler_sequence")
            sequence = request["sequence"]
            try:
                result = _scheduler_dispatch(
                    executor, request["operation"], request["request"]
                )
                response = {"sequence": sequence, "result": result, "error": None}
            except GovernanceBypassDenied as exc:
                response = {
                    "sequence": sequence,
                    "result": None,
                    "error": {"kind": "governance", "message": str(exc)},
                }
            except (KeyError, ValueError, RuntimeError) as exc:
                response = {
                    "sequence": sequence,
                    "result": None,
                    "error": {"kind": type(exc).__name__, "message": str(exc)},
                }
            send_authenticated_frame(scheduler_socket, response, max_frame_bytes)
    except (ConnectionError, OSError, TimeoutError, ValueError):
        pass
    finally:
        authority_channel.close()
        scheduler_socket.close()


def _verify_scheduler_signed_message(
    raw: bytes,
    *,
    expected_body: Mapping[str, object],
    public_key: Ed25519PublicKey | None,
    domain: bytes,
) -> Ed25519PublicKey:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: invalid scheduler readiness"
        ) from error
    if type(value) is not dict or set(value) != {*expected_body, "signature"}:
        raise IsolationUnavailable("ISOLATION_UNAVAILABLE: invalid scheduler readiness")
    body = {key: value[key] for key in expected_body}
    if body != expected_body or type(value["signature"]) is not str:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: scheduler readiness binding mismatch"
        )
    if public_key is None:
        encoded_key = body.get("scheduler_public_key")
        if type(encoded_key) is not str:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: scheduler readiness key missing"
            )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(encoded_key))
        except ValueError as error:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: scheduler readiness key invalid"
            ) from error
    try:
        public_key.verify(
            b64u_decode(value["signature"]),
            domain + b"\x00" + canonical_json(body),
        )
    except (InvalidSignature, TypeError, ValueError) as error:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: unauthenticated scheduler readiness"
        ) from error
    return public_key


class _DormantScheduler:
    """One-shot supervisor capability for a pre-secret hardened scheduler PID."""

    __slots__ = (
        "_process",
        "_control",
        "_launch_nonce",
        "_session",
        "_key_id",
        "_public_key",
        "_max_frame_bytes",
        "_used",
        "_transferred",
    )

    def __init__(
        self,
        process: Any,
        control: socket.socket,
        *,
        launch_nonce: str,
        session: str,
        key_id: str,
        public_key: Ed25519PublicKey,
        max_frame_bytes: int,
    ) -> None:
        self._process = process
        self._control = control
        self._launch_nonce = launch_nonce
        self._session = session
        self._key_id = key_id
        self._public_key = public_key
        self._max_frame_bytes = max_frame_bytes
        self._used = False
        self._transferred = False

    @property
    def pid(self) -> int | None:
        try:
            return self._process.pid
        except ValueError:
            return None

    @property
    def process(self) -> Any:
        return self._process

    @property
    def transferred(self) -> bool:
        return self._transferred

    @property
    def used(self) -> bool:
        return self._used

    def activate(
        self,
        scheduler_socket: socket.socket,
        authority_socket: socket.socket,
        *,
        registry_snapshot: dict[str, Any],
        policy_version: str,
        authority_session: str,
        authority_pid: int,
        ipc_public_key: bytes,
    ) -> None:
        if self._used:
            raise GovernanceBypassDenied("scheduler_rebootstrap_required")
        body = {
            "stage": "ACTIVATE_SCHEDULER",
            "launch_nonce": self._launch_nonce,
            "scheduler_session": self._session,
            "authority_session": authority_session,
            "authority_pid": authority_pid,
            "ipc_public_key": b64u_encode(ipc_public_key),
            "max_frame_bytes": self._max_frame_bytes,
            "policy_version": policy_version,
            "registry_snapshot": registry_snapshot,
        }
        encoded = canonical_json(body)
        if len(encoded) > self._max_frame_bytes:
            raise ValueError("scheduler activation metadata is too large")
        self._used = True
        descriptors = array.array(
            "i", [scheduler_socket.fileno(), authority_socket.fileno()]
        )
        sent = self._control.sendmsg(
            [encoded], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]
        )
        if sent != len(encoded):
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: partial scheduler activation"
            )
        self._transferred = True
        raw = self._control.recv(16_385)
        if not raw or len(raw) > 16_384:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: scheduler activation readiness missing"
            )
        expected: dict[str, object] = {
            "stage": "SCHEDULER_ACTIVATED_READY",
            "pid": self.pid,
            "launch_nonce": self._launch_nonce,
            "scheduler_session": self._session,
            "scheduler_key_id": self._key_id,
        }
        _verify_scheduler_signed_message(
            raw,
            expected_body=expected,
            public_key=self._public_key,
            domain=_SCHEDULER_ACTIVE_DOMAIN,
        )
        self._control.close()

    def close(self) -> None:
        _safe_close(self._control)
        _abort_process(self._process)


def _start_dormant_scheduler(max_frame_bytes: int) -> _DormantScheduler:
    """Spawn and attest the inert scheduler before any bootstrap source is read."""
    if not hasattr(socket, "MSG_CMSG_CLOEXEC"):
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: MSG_CMSG_CLOEXEC is required"
        )
    context = multiprocessing.get_context("spawn")
    with ExitStack() as cleanup:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        cleanup.callback(_safe_close, parent)
        cleanup.callback(_safe_close, child)
        launch_nonce = b64u_encode(os.urandom(32))
        session = f"scheduler-{secrets.token_urlsafe(24)}"
        process = context.Process(
            target=_dormant_scheduler_child,
            args=(child, launch_nonce, session, max_frame_bytes),
            name="apcc-dormant-scheduler-child",
        )
        cleanup.callback(_abort_process, process)
        process.start()
        pid = process.pid
        if pid is None:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: dormant scheduler has no process identity"
            )
        child.close()
        parent.settimeout(5)
        raw = parent.recv(16_385)
        if not raw or len(raw) > 16_384:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: dormant scheduler readiness missing"
            )
        try:
            decoded = json.loads(raw)
            encoded_public = decoded["scheduler_public_key"]
            key_id = decoded["scheduler_key_id"]
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: dormant scheduler readiness malformed"
            ) from error
        if type(encoded_public) is not str or type(key_id) is not str:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: dormant scheduler readiness malformed"
            )
        expected = {
            "stage": "DORMANT_SCHEDULER_HARDENED_READY",
            "pid": pid,
            "role": "scheduler",
            "launch_nonce": launch_nonce,
            "scheduler_session": session,
            "scheduler_key_id": key_id,
            "scheduler_public_key": encoded_public,
            "dumpable": 0,
        }
        public_key = _verify_scheduler_signed_message(
            raw,
            expected_body=expected,
            public_key=None,
            domain=_SCHEDULER_READY_DOMAIN,
        )
        if key_id != sha256_digest(
            public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ):
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: dormant scheduler key mismatch"
            )
        dormant = _DormantScheduler(
            process,
            parent,
            launch_nonce=launch_nonce,
            session=session,
            key_id=key_id,
            public_key=public_key,
            max_frame_bytes=max_frame_bytes,
        )
        cleanup.pop_all()
        return dormant


class _SwarmExecutionHandle:
    """Supervisor-facing typed scheduler RPC; no authority endpoint is exposed."""

    __slots__ = (
        "_socket",
        "_process",
        "_max_frame_bytes",
        "_sequence",
        "_lock",
        "_closed",
        "_on_close",
    )

    def __init__(
        self,
        connection: socket.socket,
        process: Any,
        max_frame_bytes: int,
        on_close: Any | None = None,
    ) -> None:
        self._socket = connection
        self._socket.settimeout(2.0)
        self._process = process
        self._max_frame_bytes = max_frame_bytes
        self._sequence = 0
        self._lock = threading.RLock()
        self._closed = False
        self._on_close = on_close

    @property
    def pid(self) -> int | None:
        try:
            return self._process.pid
        except ValueError:
            return None

    def _rpc(self, operation: str, request: Mapping[str, Any]) -> Any:
        failure: BaseException | None = None
        callback: Any | None = None
        body: dict[str, Any] | None = None
        with self._lock:
            if self._closed:
                raise GovernanceBypassDenied("authority_unavailable")
            self._sequence += 1
            try:
                send_authenticated_frame(
                    self._socket,
                    {
                        "sequence": self._sequence,
                        "operation": operation,
                        "request": dict(request),
                    },
                    self._max_frame_bytes,
                )
                response = recv_authenticated_frame(self._socket, self._max_frame_bytes)
                body = _exact_object(
                    response, {"sequence", "result", "error"}, "scheduler_response"
                )
                if body["sequence"] != self._sequence:
                    raise ValueError("invalid_scheduler_sequence")
            except (
                ConnectionError,
                OSError,
                TimeoutError,
                ValueError,
                TypeError,
            ) as exc:
                callback = self._close_locked()
                failure = exc
        if failure is not None:
            if callback is not None:
                callback()
            raise GovernanceBypassDenied("authority_unavailable") from failure
        if body is None:
            raise GovernanceBypassDenied("authority_unavailable")
        error = body["error"]
        if error is not None:
            detail = _exact_object(error, {"kind", "message"}, "scheduler_error")
            _require_types(detail, strings={"kind", "message"})
            if detail["kind"] == "governance":
                raise GovernanceBypassDenied(detail["message"])
            if detail["kind"] == "KeyError":
                raise KeyError(detail["message"])
            if detail["kind"] == "ValueError":
                raise ValueError(detail["message"])
            raise RuntimeError(detail["message"])
        return body["result"]

    def _close_locked(self) -> Any | None:
        if self._closed:
            return None
        self._closed = True
        self._socket.close()
        _abort_process(self._process)
        return self._on_close

    def health(self) -> dict[str, int]:
        body = _exact_object(
            self._rpc("health", {}), {"executor_pid"}, "executor_health"
        )
        if type(body["executor_pid"]) is not int:
            raise GovernanceBypassDenied("authority_unavailable")
        return {"executor_pid": body["executor_pid"]}

    def load_dag(self, dag: Any) -> None:
        self._rpc("load_dag", {"dag": _encode_task_dag(dag)})

    def available_tasks(self, agent_id: str) -> list[Any]:
        result = self._rpc("available_tasks", {"agent_id": agent_id})
        if type(result) is not list:
            raise GovernanceBypassDenied("authority_unavailable")
        return [_trusted_decode(_decode_task_node, item) for item in result]

    def prepare_claim(self, node_id: str, agent_id: str) -> AttemptAuthorizationPayload:
        return _trusted_decode(
            _decode_attempt_payload,
            self._rpc("prepare_claim", {"node_id": node_id, "agent_id": agent_id}),
        )

    def claim(
        self, node_id: str, agent_id: str, authorization: SignedAttemptAuthorization
    ) -> WorkReceipt:
        return _trusted_decode(
            _decode_work_receipt,
            self._rpc(
                "claim",
                {
                    "node_id": node_id,
                    "agent_id": agent_id,
                    "authorization": _encode_authorization(authorization),
                },
            ),
        )

    def produce_result(
        self,
        node_id: str,
        artifact: Artifact,
        *,
        authorization: SignedAttemptAuthorization | None = None,
    ) -> GovernedReceiptPayload:
        return _trusted_decode(
            _decode_receipt_payload,
            self._rpc(
                "produce_result",
                {
                    "node_id": node_id,
                    "artifact": _encode_artifact(artifact),
                    "authorization": None
                    if authorization is None
                    else _encode_authorization(authorization),
                },
            ),
        )

    def build_request(self, receipt: SignedGovernedReceipt) -> CommitRequest:
        return _trusted_decode(
            _decode_commit_request,
            self._rpc(
                "build_request",
                {
                    "receipt": {
                        "payload": _encode_receipt_payload(receipt.payload),
                        "signature": receipt.signature,
                    }
                },
            ),
        )

    def commit(self, request: CommitRequest) -> CommitDecision:
        return _trusted_decode(
            _decode_commit_decision,
            self._rpc("commit", {"request": _encode_commit_request(request)}),
        )

    def authoritative_artifact(self, artifact_id: str) -> Artifact | None:
        return _trusted_decode(
            _decode_artifact,
            self._rpc("authoritative_artifact", {"artifact_id": artifact_id}),
        )

    @property
    def is_complete(self) -> bool:
        result = self._rpc("is_complete", {})
        if type(result) is not bool:
            raise GovernanceBypassDenied("authority_unavailable")
        return result

    @property
    def progress(self) -> dict[str, int]:
        result = self._rpc("progress", {})
        if type(result) is not dict or any(
            type(key) is not str or type(value) is not int
            for key, value in result.items()
        ):
            raise GovernanceBypassDenied("authority_unavailable")
        return dict(result)

    def close(self) -> None:
        callback: Any | None
        with self._lock:
            callback = self._close_locked()
        if callback is not None:
            callback()

    def __enter__(self) -> _SwarmExecutionHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class AuthorityServiceHandle:
    """Trusted supervisor ownership of one spawn-only authority child."""

    __slots__ = (
        "_process",
        "_execution_channel",
        "admin_client",
        "_session_id",
        "_ipc_public_key",
        "_max_frame_bytes",
        "_status_signing_channel",
        "_authority_config",
        "_authority_source_path",
        "_scheduler_worker",
        "_controlled_boot",
        "_lifecycle_lock",
        "_executors",
        "_observers",
        "_watchers",
        "_watcher_fds",
        "_closed",
    )

    def __init__(
        self,
        process: Any,
        execution_client: _AuthorityExecutionChannel,
        admin_client: AuthorityAdminClient,
        session_id: str,
        ipc_public_key: bytes,
        max_frame_bytes: int,
        status_signing_channel: _StatusSigningClient,
        authority_config: Any,
        authority_source_path: str,
        scheduler_worker: _DormantScheduler,
        controlled_boot: ControlledBootResult,
    ) -> None:
        self._process = process
        self._execution_channel: _AuthorityExecutionChannel | None = execution_client
        self.admin_client = admin_client
        self._session_id = session_id
        self._ipc_public_key = ipc_public_key
        self._max_frame_bytes = max_frame_bytes
        self._status_signing_channel: _StatusSigningClient | None = (
            status_signing_channel
        )
        self._authority_config = authority_config
        self._authority_source_path = authority_source_path
        self._scheduler_worker = scheduler_worker
        self._controlled_boot = controlled_boot
        self._lifecycle_lock = threading.RLock()
        self._executors: list[_SwarmExecutionHandle] = []
        self._observers: list[AuthorityObserverHandle] = []
        self._watchers: list[threading.Thread] = []
        self._watcher_fds: set[int] = set()
        self._closed = False
        self._watch_process_locked("authority", self._process)
        self._watch_process_locked("scheduler", self._scheduler_worker.process)

    @property
    def pid(self) -> int | None:
        try:
            return self._process.pid
        except ValueError:
            return None

    def is_alive(self) -> bool:
        try:
            return self._process.is_alive()
        except ValueError:
            return False

    def health(self) -> dict[str, int]:
        with self._lifecycle_lock:
            self._refresh_liveness_locked()
            if self._closed:
                raise GovernanceBypassDenied("authority_unavailable")
        return self.admin_client.health()

    @property
    def controlled_boot(self) -> ControlledBootResult:
        with self._lifecycle_lock:
            self._refresh_liveness_locked()
            return self._controlled_boot

    @staticmethod
    def _process_is_alive(process: Any) -> bool:
        try:
            readable, _, _ = select.select([process.sentinel], [], [], 0)
            if readable:
                return False
            return process.is_alive()
        except (AssertionError, OSError, ValueError):
            return False

    def _watch_process_locked(self, role: str, process: Any) -> None:
        descriptor: int | None = None
        watcher: threading.Thread | None = None
        try:
            descriptor = os.dup(process.sentinel)
            os.set_inheritable(descriptor, False)
            self._watcher_fds.add(descriptor)
            watcher = threading.Thread(
                target=self._watch_process_sentinel,
                args=(role, descriptor),
                name=f"apcc-{role}-lifecycle-watcher",
                daemon=True,
            )
            self._watchers.append(watcher)
            watcher.start()
        except (AttributeError, OSError, RuntimeError, ValueError) as error:
            if watcher is not None:
                try:
                    self._watchers.remove(watcher)
                except ValueError:
                    pass
            if descriptor is not None:
                self._watcher_fds.discard(descriptor)
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise IsolationUnavailable(
                f"ISOLATION_UNAVAILABLE: {role} watcher registration failed"
            ) from error

    def _watch_process_sentinel(self, role: str, descriptor: int) -> None:
        ready = False
        failed = False
        try:
            readable, _, _ = select.select([descriptor], [], [])
            ready = bool(readable)
        except (OSError, ValueError):
            failed = True
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
            with self._lifecycle_lock:
                self._watcher_fds.discard(descriptor)
        if ready or failed:
            self._component_failed(role)

    def _refresh_liveness_locked(self) -> None:
        if self._controlled_boot.phase in {
            ControlledBootPhase.CLOSING,
            ControlledBootPhase.CLOSED,
            ControlledBootPhase.FAILED,
        }:
            return
        if not self._process_is_alive(self._process):
            self._fail_lifecycle_locked("authority")
            return
        if not self._process_is_alive(self._scheduler_worker.process):
            self._fail_lifecycle_locked("scheduler")
            return
        for observer in self._observers:
            if not self._process_is_alive(observer._process):
                self._fail_lifecycle_locked("observer")
                return

    def _component_failed(self, role: str) -> None:
        with self._lifecycle_lock:
            if self._controlled_boot.phase in {
                ControlledBootPhase.CLOSING,
                ControlledBootPhase.CLOSED,
                ControlledBootPhase.FAILED,
            }:
                return
            self._fail_lifecycle_locked(role)
        self._join_watchers()

    def _fail_lifecycle_locked(
        self, _role: str, *, controller_source_consumed: bool | None = None
    ) -> None:
        controller_consumed = (
            self._controlled_boot.controller_source_consumed
            if controller_source_consumed is None
            else controller_source_consumed
        )
        self._controlled_boot = _controlled_boot_result(
            ControlledBootPhase.FAILED,
            controller_source_consumed=controller_consumed,
        )
        self._closed = True
        self._cleanup_owned_locked()

    def _cleanup_owned_locked(self) -> BaseException | None:
        failure: BaseException | None = None

        def attempt(action: Any) -> None:
            nonlocal failure
            try:
                action()
            except BaseException as error:
                if failure is None:
                    failure = error

        for executor in self._executors:
            attempt(executor.close)
        for observer in self._observers:
            attempt(observer.close)
        attempt(self._scheduler_worker.close)
        if self._execution_channel is not None:
            attempt(self._execution_channel.close)
            self._execution_channel = None
        attempt(self.admin_client.close)
        if self._status_signing_channel is not None:
            attempt(self._status_signing_channel.close)
            self._status_signing_channel = None
        attempt(lambda: _abort_process(self._process))
        return failure

    def _join_watchers(self) -> None:
        current = threading.current_thread()
        for watcher in tuple(self._watchers):
            if watcher is not current and watcher.ident is not None:
                watcher.join(2)

    def spawn_executor(
        self,
        registry: CapabilityRegistry,
        *,
        policy_version: str,
    ) -> _SwarmExecutionHandle:
        """Activate the already-hardened scheduler without creating a process."""
        with self._lifecycle_lock:
            self._refresh_liveness_locked()
            if self._closed:
                raise GovernanceBypassDenied("authority_unavailable")
            phase = self._controlled_boot.phase
            transitions = {
                ControlledBootPhase.AUTHORITY_READY: (
                    ControlledBootPhase.SCHEDULER_STARTING_NONPUBLISHABLE,
                    ControlledBootPhase.SCHEDULER_STARTED_NONPUBLISHABLE,
                ),
                ControlledBootPhase.OBSERVER_READY: (
                    ControlledBootPhase.SCHEDULER_STARTING_PUBLISHABLE,
                    ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
                ),
            }
            if phase not in transitions:
                if phase is ControlledBootPhase.OBSERVER_STARTING:
                    raise GovernanceBypassDenied("observer_starting")
                raise GovernanceBypassDenied("execution_channel_already_composed")
            if (
                not self._controlled_boot.authority_source_consumed
                or os.path.lexists(self._authority_source_path)
                or self._scheduler_worker.pid is None
            ):
                raise GovernanceBypassDenied("ISOLATION_UNAVAILABLE")
            if type(policy_version) is not str or not policy_version:
                raise TypeError("policy_version must be a non-empty string")
            snapshot = _registry_snapshot(registry)
            channel = self._execution_channel
            if channel is None:
                raise GovernanceBypassDenied("execution_channel_already_composed")
            starting_phase, started_phase = transitions[phase]
            self._controlled_boot = _controlled_boot_result(starting_phase)
            with ExitStack() as cleanup:
                supervisor_socket, scheduler_socket = socket.socketpair(socket.AF_UNIX)
                cleanup.callback(_safe_close, supervisor_socket)
                cleanup.callback(_safe_close, scheduler_socket)
                authority_socket = channel._detach_socket()
                cleanup.callback(_safe_close, authority_socket)
                try:
                    authority_pid = self.pid
                    if authority_pid is None:
                        raise IsolationUnavailable(
                            "ISOLATION_UNAVAILABLE: authority identity missing"
                        )
                    self._scheduler_worker.activate(
                        scheduler_socket,
                        authority_socket,
                        registry_snapshot=snapshot,
                        policy_version=policy_version,
                        authority_session=self._session_id,
                        authority_pid=authority_pid,
                        ipc_public_key=self._ipc_public_key,
                    )
                    scheduler_socket.close()
                    authority_socket.close()
                    self._execution_channel = None
                    executor = _SwarmExecutionHandle(
                        supervisor_socket,
                        self._scheduler_worker.process,
                        self._max_frame_bytes,
                        self._executor_closed,
                    )
                    executor.health()
                    self._executors.append(executor)
                    self._controlled_boot = _controlled_boot_result(started_phase)
                    cleanup.pop_all()
                    return executor
                except BaseException:
                    if not self._scheduler_worker.transferred:
                        channel._reattach_socket(authority_socket)
                    if not self._scheduler_worker.used:
                        self._controlled_boot = _controlled_boot_result(phase)
                    else:
                        if self._scheduler_worker.transferred:
                            self._execution_channel = None
                        self._fail_lifecycle_locked("scheduler_activation")
                    raise

    def _executor_closed(self) -> None:
        self._component_failed("scheduler")

    def terminate(self) -> None:
        self.close()

    def join(self, timeout: float | None = None) -> None:
        try:
            self._process.join(timeout)
        except ValueError:
            return

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                terminal = self._controlled_boot.phase
                cleanup_error = (
                    self._cleanup_owned_locked()
                    if terminal is ControlledBootPhase.FAILED
                    else None
                )
            else:
                self._closed = True
                controller_consumed = self._controlled_boot.controller_source_consumed
                self._controlled_boot = _controlled_boot_result(
                    ControlledBootPhase.CLOSING,
                    controller_source_consumed=controller_consumed,
                )
                cleanup_error = self._cleanup_owned_locked()
                if cleanup_error is None:
                    self._controlled_boot = _controlled_boot_result(
                        ControlledBootPhase.CLOSED,
                        controller_source_consumed=controller_consumed,
                    )
                    terminal = ControlledBootPhase.CLOSED
                else:
                    self._controlled_boot = _controlled_boot_result(
                        ControlledBootPhase.FAILED,
                        controller_source_consumed=controller_consumed,
                    )
                    terminal = ControlledBootPhase.FAILED
        self._join_watchers()
        if cleanup_error is not None:
            raise RuntimeError("privileged lifecycle cleanup failed") from cleanup_error

    def __enter__(self) -> AuthorityServiceHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class AuthorityObserverHandle:
    """Separate supervisor-held observation capability and portable launch proof."""

    __slots__ = (
        "_process",
        "client",
        "launch_attestation",
        "_closed",
        "_lock",
        "_on_close",
    )

    def __init__(
        self,
        process: Any,
        client: AuthorityObserverClient,
        launch_attestation: Any,
        on_close: Any | None = None,
    ) -> None:
        self._process = process
        self.client = client
        self.launch_attestation = launch_attestation
        self._closed = False
        self._lock = threading.RLock()
        self._on_close = on_close

    @property
    def pid(self) -> int | None:
        try:
            return self._process.pid
        except ValueError:
            return None

    def close(self) -> None:
        callback: Any | None = None
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self.client.close()
            _abort_process(self._process)
            callback = self._on_close
        if callback is not None:
            callback()

    def __enter__(self) -> AuthorityObserverHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _verify_readiness(
    value: Any, expected_public_key: bytes, pid: int
) -> dict[str, Any]:
    fields = {
        "protocol",
        "authority_pid",
        "key_loader_pid",
        "session",
        "ipc_public_key",
        "signature",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("invalid authority readiness message")
    signature = value["signature"]
    body = {key: item for key, item in value.items() if key != "signature"}
    if (
        body["protocol"] != PROTOCOL
        or body["authority_pid"] != pid
        or body["key_loader_pid"] != pid
        or type(body["session"]) is not str
        or type(body["ipc_public_key"]) is not str
        or type(signature) is not str
    ):
        raise RuntimeError("authority readiness identity mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(expected_public_key).verify(
            b64u_decode(signature), canonical_json(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise RuntimeError("authority readiness signature mismatch") from exc
    return body


def start_authority(
    config: Any, *, readiness_timeout: float = 5.0
) -> AuthorityServiceHandle:
    """Pre-harden the scheduler, then irreversibly bootstrap the authority."""
    from constitutional_swarm.authority_child import (
        AuthorityChildConfig,
        KeySourceRef,
        authority_child_main,
    )

    if type(config) is not AuthorityChildConfig:
        raise TypeError("config must be AuthorityChildConfig")
    harden_current_process()
    if config.key_source.kind != "file":
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: publishable bootstrap requires a one-shot file"
        )
    authority_source_path = config.key_source.location
    context = multiprocessing.get_context("spawn")
    with ExitStack() as cleanup:
        dormant_scheduler = _start_dormant_scheduler(config.max_frame_bytes)
        cleanup.callback(dormant_scheduler.close)
        secret = consume_secret_file(
            authority_source_path,
            maximum_bytes=1_048_576,
            label="authority key bundle",
        )
        cleanup.callback(erase_secret, secret)
        child_config = replace(
            config,
            key_source=KeySourceRef(
                "consumed",
                "consumed:authority",
                config.key_source.expected_identity_public_key,
            ),
        )
        execution_parent, execution_child = socket.socketpair(socket.AF_UNIX)
        cleanup.callback(_safe_close, execution_parent)
        cleanup.callback(_safe_close, execution_child)
        admin_parent, admin_child = socket.socketpair(socket.AF_UNIX)
        cleanup.callback(_safe_close, admin_parent)
        cleanup.callback(_safe_close, admin_child)
        status_parent, status_child = socket.socketpair(socket.AF_UNIX)
        cleanup.callback(_safe_close, status_parent)
        cleanup.callback(_safe_close, status_child)
        ready_parent, ready_child = context.Pipe(duplex=True)
        cleanup.callback(_safe_close, ready_parent)
        cleanup.callback(_safe_close, ready_child)
        if hasattr(socket, "SO_PEERCRED"):
            for endpoint in (execution_parent, admin_parent, status_parent):
                _peer_pid, peer_uid, _peer_gid = struct.unpack(
                    "3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if peer_uid != os.geteuid():
                    raise RuntimeError("authority channel peer ownership mismatch")
        process = context.Process(
            target=authority_child_main,
            args=(
                child_config,
                execution_child,
                admin_child,
                status_child,
                ready_child,
            ),
            name="apcc-authority-child",
        )
        cleanup.callback(_abort_process, process)
        process.start()
        authority_pid = process.pid
        if authority_pid is None:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: authority child has no process identity"
            )
        execution_child.close()
        admin_child.close()
        status_child.close()
        ready_child.close()
        if not ready_parent.poll(readiness_timeout):
            raise TimeoutError("authority hardening readiness timed out")
        _verify_hardened_ready(ready_parent.recv(), authority_pid, "authority")
        ready_parent.send_bytes(secret)
        erase_secret(secret)
        if not ready_parent.poll(readiness_timeout):
            raise TimeoutError("authority readiness timed out")
        ready = ready_parent.recv()
        if isinstance(ready, dict) and "startup_error" in ready:
            raise RuntimeError(
                f"authority startup failed: {ready.get('startup_error')}: "
                f"{ready.get('message', '')}"
            )
        body = _verify_readiness(
            ready, config.key_source.expected_identity_public_key, authority_pid
        )
        ipc_public_key = Ed25519PublicKey.from_public_bytes(
            b64u_decode(body["ipc_public_key"])
        )
        execution = _bind_verified_child_channel(
            _AuthorityExecutionChannel,
            execution_parent,
            channel_role="execution",
            session=body["session"],
            authority_pid=authority_pid,
            ipc_public_key=ipc_public_key,
            max_frame_bytes=config.max_frame_bytes,
        )
        admin_transport = _bind_verified_child_channel(
            _JSONClient,
            admin_parent,
            channel_role="admin",
            session=body["session"],
            authority_pid=authority_pid,
            ipc_public_key=ipc_public_key,
            max_frame_bytes=config.max_frame_bytes,
        )
        status_transport = _bind_verified_child_channel(
            _StatusSigningClient,
            status_parent,
            channel_role="status-signing",
            session=body["session"],
            authority_pid=authority_pid,
            ipc_public_key=ipc_public_key,
            max_frame_bytes=config.max_frame_bytes,
        )
        handle = AuthorityServiceHandle(
            process,
            execution,
            AuthorityAdminClient(admin_transport),
            body["session"],
            b64u_decode(body["ipc_public_key"]),
            child_config.max_frame_bytes,
            status_transport,
            child_config,
            authority_source_path,
            dormant_scheduler,
            _controlled_boot_result(ControlledBootPhase.AUTHORITY_READY),
        )
        cleanup.pop_all()
        ready_parent.close()
        return handle


def start_authority_observer(
    authority_handle: AuthorityServiceHandle,
    launch: Any,
    *,
    postgres_observer_dsn: str | None = None,
) -> AuthorityObserverHandle:
    """Establish observation and reap all watcher ownership on failed admission."""
    try:
        return _start_authority_observer_transaction(
            authority_handle,
            launch,
            postgres_observer_dsn=postgres_observer_dsn,
        )
    finally:
        if (
            type(authority_handle) is AuthorityServiceHandle
            and authority_handle._controlled_boot.phase is ControlledBootPhase.FAILED
        ):
            authority_handle._join_watchers()


def _start_authority_observer_transaction(
    authority_handle: AuthorityServiceHandle,
    launch: Any,
    *,
    postgres_observer_dsn: str | None = None,
) -> AuthorityObserverHandle:
    """Atomically establish publishable observation before scheduler launch."""
    if type(authority_handle) is not AuthorityServiceHandle:
        raise TypeError("authority_handle must be AuthorityServiceHandle")
    harden_current_process()
    with authority_handle._lifecycle_lock:
        phase = authority_handle._controlled_boot.phase
        if phase is not ControlledBootPhase.AUTHORITY_READY:
            if phase in {
                ControlledBootPhase.SCHEDULER_STARTING_NONPUBLISHABLE,
                ControlledBootPhase.SCHEDULER_STARTED_NONPUBLISHABLE,
                ControlledBootPhase.SCHEDULER_STARTING_PUBLISHABLE,
                ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
            }:
                raise GovernanceBypassDenied("observer_must_precede_scheduler")
            if phase in {
                ControlledBootPhase.OBSERVER_STARTING,
                ControlledBootPhase.OBSERVER_READY,
            }:
                raise GovernanceBypassDenied("observer_already_started")
            raise GovernanceBypassDenied("ISOLATION_UNAVAILABLE")
        status_channel = authority_handle._status_signing_channel
        authority_handle._controlled_boot = _controlled_boot_result(
            ControlledBootPhase.OBSERVER_STARTING
        )
        try:
            observer = _start_authority_observer_locked(
                authority_handle,
                launch,
                postgres_observer_dsn=postgres_observer_dsn,
            )
            authority_handle._observers.append(observer)
            authority_handle._watch_process_locked("observer", observer._process)
            authority_handle._controlled_boot = _controlled_boot_result(
                ControlledBootPhase.OBSERVER_READY
            )
            authority_handle._refresh_liveness_locked()
            if authority_handle._controlled_boot.phase is ControlledBootPhase.FAILED:
                raise IsolationUnavailable(
                    "ISOLATION_UNAVAILABLE: observer exited during admission"
                )
        except BaseException:
            source_path = getattr(
                getattr(launch, "controller_key_source", None), "location", None
            )
            source_consumed = bool(
                isinstance(source_path, str) and not os.path.lexists(source_path)
            )
            if (
                authority_handle._status_signing_channel is status_channel
                and not source_consumed
            ):
                authority_handle._controlled_boot = _controlled_boot_result(
                    ControlledBootPhase.AUTHORITY_READY
                )
            else:
                authority_handle._fail_lifecycle_locked(
                    "observer_start",
                    controller_source_consumed=source_consumed,
                )
            raise
        return observer


def _start_authority_observer_locked(
    authority_handle: AuthorityServiceHandle,
    launch: Any,
    *,
    postgres_observer_dsn: str | None,
) -> AuthorityObserverHandle:
    """Start the observer while the authority lifecycle lock is held."""
    from constitutional_swarm.authority_child import AuthorityChildConfig
    from constitutional_swarm.authority_observer import (
        AuthorityObserverLaunchConfig,
    )

    authority_config = authority_handle._authority_config
    if type(authority_config) is not AuthorityChildConfig:
        raise TypeError("authority handle configuration is invalid")
    if type(launch) is not AuthorityObserverLaunchConfig:
        raise TypeError("launch must be AuthorityObserverLaunchConfig")
    authority = authority_config.authority
    if launch.authority_store_id != authority.authority_store_id:
        raise ValueError("observer launch authority-store binding mismatch")
    controller_public = launch.controller_key_source.expected_public_key
    forbidden_material = {
        authority_config.key_source.expected_identity_public_key,
        *(binding.public_key for binding in authority.trust_bindings),
    }
    if controller_public in forbidden_material:
        raise ValueError("controller key must be distinct from every authority role")
    if launch.backend_kind == "sqlite":
        if postgres_observer_dsn is not None:
            raise ValueError("SQLite observer does not accept PostgreSQL credentials")
        from constitutional_swarm.apcc.sqlite_store import (
            _AUTHORITY_SCHEMA_VERSION,
            _SCHEMA_FINGERPRINT,
        )

        backend = AuthorityObserverBackendRef(
            "sqlite", launch.backend_instance, authority_config.database_path
        )
        schema_version = _AUTHORITY_SCHEMA_VERSION
        schema_fingerprint = _SCHEMA_FINGERPRINT
    else:
        if type(postgres_observer_dsn) is not str:
            raise ValueError("PostgreSQL observer credential is required")
        _decode_observer_postgres_credential(postgres_observer_dsn.encode("utf-8"))
        from constitutional_swarm.apcc.postgres_store import (
            _AUTHORITY_SCHEMA_VERSION,
            _POSTGRES_CATALOG_FINGERPRINT,
        )

        backend = AuthorityObserverBackendRef(
            "postgresql", launch.backend_instance, None, launch.backend_schema
        )
        schema_version = _AUTHORITY_SCHEMA_VERSION
        schema_fingerprint = _POSTGRES_CATALOG_FINGERPRINT
    controller_source_path = launch.controller_key_source.location
    controller_secret = consume_secret_file(
        controller_source_path,
        maximum_bytes=256,
        label="observer controller key",
    )
    controller_signer = _start_controller_signer(
        launch.controller_key_source, controller_secret
    )
    with ExitStack() as signer_cleanup:
        signer_cleanup.callback(controller_signer.close)
        issued = int(time.time() * 1000)
        launch_public = {
            "experiment_id": launch.experiment_id,
            "run_id": launch.run_id,
            "authority_store_id": launch.authority_store_id,
            "backend_kind": launch.backend_kind,
            "backend_instance_digest": sha256_digest(
                canonical_json(
                    {
                        "kind": launch.backend_kind,
                        "instance": launch.backend_instance,
                        "schema": launch.backend_schema,
                    }
                )
            ),
            "schema_version": schema_version,
            "schema_fingerprint": schema_fingerprint,
            "status_key_id": authority.status_trust.key_id,
            "not_before_ms": str(issued),
            "not_after_ms": str(issued + 300_000),
        }
        status_channel = authority_handle._status_signing_channel
        if status_channel is None:
            raise GovernanceBypassDenied("observer_already_started")
        status_socket = status_channel._detach_socket()
        authority_handle._status_signing_channel = None
        authority_pid = authority_handle.pid
        if authority_pid is None:
            status_socket.close()
            raise RuntimeError("authority child has no process identity")
        process, client, attestation_object = _start_observer(
            backend,
            status_connection=status_socket,
            status_session=authority_handle._session_id,
            authority_pid=authority_pid,
            authority_ipc_public_key=authority_handle._ipc_public_key,
            max_frame_bytes=authority_config.max_frame_bytes,
            launch_public=launch_public,
            controller_signer=controller_signer,
            controller_key_id=launch.controller_key_id,
            controller_public_key=controller_public,
            postgres_observer_dsn=postgres_observer_dsn,
        )
        signer_cleanup.pop_all()
    try:
        attestation = decode_observer_launch_attestation(
            canonical_json(attestation_object)
        )
        attestation.verify(
            pinned_controller_public_key=controller_public,
            expected=ObserverLaunchExpectationsV1(
                **{
                    name: getattr(attestation, name)
                    for name in ObserverLaunchExpectationsV1.__dataclass_fields__
                }
            ),
            now_ms=int(time.time() * 1000),
        )
    except BaseException:
        client.close()
        _abort_process(process)
        raise
    return AuthorityObserverHandle(
        process,
        client,
        attestation,
        lambda: authority_handle._component_failed("observer"),
    )
