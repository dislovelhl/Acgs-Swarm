"""Strict JSON IPC boundary for the privileged APCC authority process."""

from __future__ import annotations

import base64
import json
import math
import multiprocessing
import os
import socket
import struct
import threading
from collections.abc import Collection, Mapping, Sequence
from dataclasses import asdict
from enum import Enum
from typing import Any, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.apcc.ports import OutboxRecoveryRequest
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.execution import ContractStatus, WorkReceipt
from constitutional_swarm.authority_ipc import (
    PROTOCOL,
    b64u_decode,
    canonical_json,
    digest as ipc_digest,
    recv_frame as recv_authenticated_frame,
    send_frame as send_authenticated_frame,
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


def _swarm_execution_child(
    scheduler_socket: socket.socket,
    authority_socket: socket.socket,
    registry_snapshot: dict[str, Any],
    policy_version: str,
    session: str,
    authority_pid: int,
    ipc_public_key: bytes,
    max_frame_bytes: int,
) -> None:
    """Fixed scheduler child; it never imports or executes caller agent code."""
    from constitutional_swarm.swarm import SwarmExecutor

    scheduler_socket.settimeout(2.0)
    authority_channel = _bind_verified_child_channel(
        _AuthorityExecutionChannel,
        authority_socket,
        channel_role="execution",
        session=session,
        authority_pid=authority_pid,
        ipc_public_key=Ed25519PublicKey.from_public_bytes(ipc_public_key),
        max_frame_bytes=max_frame_bytes,
    )
    executor = SwarmExecutor(
        _decode_registry_snapshot(registry_snapshot),
        ArtifactStore(),
        policy_version=policy_version,
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


class _SwarmExecutionHandle:
    """Supervisor-facing typed scheduler RPC; no authority endpoint is exposed."""

    __slots__ = (
        "_socket",
        "_process",
        "_max_frame_bytes",
        "_sequence",
        "_lock",
        "_closed",
    )

    def __init__(
        self, connection: socket.socket, process: Any, max_frame_bytes: int
    ) -> None:
        self._socket = connection
        self._socket.settimeout(2.0)
        self._process = process
        self._max_frame_bytes = max_frame_bytes
        self._sequence = 0
        self._lock = threading.RLock()
        self._closed = False

    @property
    def pid(self) -> int | None:
        return self._process.pid

    def _rpc(self, operation: str, request: Mapping[str, Any]) -> Any:
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
                self.close()
                raise GovernanceBypassDenied("authority_unavailable") from exc
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
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._socket.close()
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(2)

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
        "_executors",
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
    ) -> None:
        self._process = process
        self._execution_channel: _AuthorityExecutionChannel | None = execution_client
        self.admin_client = admin_client
        self._session_id = session_id
        self._ipc_public_key = ipc_public_key
        self._max_frame_bytes = max_frame_bytes
        self._executors: list[_SwarmExecutionHandle] = []
        self._closed = False

    @property
    def pid(self) -> int | None:
        return self._process.pid

    def is_alive(self) -> bool:
        return self._process.is_alive()

    def health(self) -> dict[str, int]:
        return self.admin_client.health()

    def spawn_executor(
        self,
        registry: CapabilityRegistry,
        *,
        policy_version: str,
    ) -> _SwarmExecutionHandle:
        """Transfer the one execution endpoint to a fixed, separate scheduler."""
        if self._closed:
            raise GovernanceBypassDenied("authority_unavailable")
        if type(policy_version) is not str or not policy_version:
            raise TypeError("policy_version must be a non-empty string")
        snapshot = _registry_snapshot(registry)
        channel = self._execution_channel
        if channel is None:
            raise GovernanceBypassDenied("execution_channel_already_composed")
        authority_socket = channel._detach_socket()
        self._execution_channel = None
        context = multiprocessing.get_context("spawn")
        supervisor_socket, scheduler_socket = socket.socketpair(socket.AF_UNIX)
        process = context.Process(
            target=_swarm_execution_child,
            args=(
                scheduler_socket,
                authority_socket,
                snapshot,
                policy_version,
                self._session_id,
                self.pid,
                self._ipc_public_key,
                self._max_frame_bytes,
            ),
            name="apcc-swarm-execution-child",
        )
        try:
            process.start()
        except BaseException:
            supervisor_socket.close()
            scheduler_socket.close()
            authority_socket.close()
            raise
        scheduler_socket.close()
        authority_socket.close()
        executor = _SwarmExecutionHandle(
            supervisor_socket, process, self._max_frame_bytes
        )
        try:
            executor.health()
        except BaseException:
            executor.close()
            raise
        self._executors.append(executor)
        return executor

    def terminate(self) -> None:
        if self._process.is_alive():
            self._process.terminate()

    def join(self, timeout: float | None = None) -> None:
        self._process.join(timeout)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for executor in self._executors:
            executor.close()
        if self._execution_channel is not None:
            self._execution_channel.close()
            self._execution_channel = None
        self.admin_client.close()
        self.terminate()
        self.join(2)

    def __enter__(self) -> AuthorityServiceHandle:
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
    """Spawn a pathless authority and return its two non-interchangeable clients."""
    from constitutional_swarm.authority_child import (
        AuthorityChildConfig,
        authority_child_main,
    )

    if type(config) is not AuthorityChildConfig:
        raise TypeError("config must be AuthorityChildConfig")
    context = multiprocessing.get_context("spawn")
    execution_parent, execution_child = socket.socketpair(socket.AF_UNIX)
    admin_parent, admin_child = socket.socketpair(socket.AF_UNIX)
    if hasattr(socket, "SO_PEERCRED"):
        for endpoint in (execution_parent, admin_parent):
            _peer_pid, peer_uid, _peer_gid = struct.unpack(
                "3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if peer_uid != os.geteuid():
                raise RuntimeError("authority channel peer ownership mismatch")
    ready_parent, ready_child = context.Pipe(duplex=False)
    process = context.Process(
        target=authority_child_main,
        args=(config, execution_child, admin_child, ready_child),
        name="apcc-authority-child",
    )
    process.start()
    authority_pid = process.pid
    if authority_pid is None:
        raise RuntimeError("authority child has no process identity")
    execution_child.close()
    admin_child.close()
    ready_child.close()
    try:
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
        return AuthorityServiceHandle(
            process,
            execution,
            AuthorityAdminClient(admin_transport),
            body["session"],
            b64u_decode(body["ipc_public_key"]),
            config.max_frame_bytes,
        )
    except BaseException:
        execution_parent.close()
        admin_parent.close()
        process.terminate()
        process.join(1)
        raise
    finally:
        ready_parent.close()
