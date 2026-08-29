"""Private, data-only contract for the built-in governed-commit projection."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import b64u_decode
from .ports import APCCAuthorityConfig, AtomicCommitRequest

_GCB_RECEIPT_PROFILE = "acgs-swarm/gcb-receipt/v1"
_GCB_SIGNATURE_ALGORITHM = "Ed25519"
_GCB_COMMIT_INTENT = "governed_commit"
_GCB_VERDICT_DOMAIN = b"ACGS-SWARM\x00GCB\x00VERDICT\x00V1\x00"


class _GCBProjectionCheckpoint(Enum):
    """Fixed, raise-only test checkpoints in the closed GCB projection."""

    BEFORE_LEGACY_WRITE = "before_legacy_write"
    AFTER_NODE_WRITE = "after_node_write"
    AFTER_WORKFLOW_WRITE = "after_workflow_write"
    AFTER_DECISION_WRITE = "after_decision_write"
    AFTER_EVIDENCE_WRITE = "after_evidence_write"
    AFTER_OUTBOX_WRITE = "after_outbox_write"
    AFTER_CHILD_UNLOCK = "after_child_unlock"
    AFTER_ATTESTATION = "after_attestation"


@dataclass(frozen=True, slots=True)
class _GCBProjectionPlan:
    """Immutable semantic values for the one built-in projection."""

    workflow_id: str
    node_id: str
    attempt_id: str
    agent_id: str
    commit_id: str
    nonce: str
    expected_node_version: int
    committed_node_version: int
    expected_workflow_state_version: int
    policy_digest: str
    request_hash: str
    receipt_material: str
    receipt_digest: str
    verdict_material: str
    verdict_digest: str


@dataclass(frozen=True, slots=True)
class _GCBWorkflowFacts:
    generation: int
    policy_version: str
    policy_digest: str
    policy_epoch: int
    verifier_policy_id: str
    authority_root: str
    authority_epoch: int
    revocation_generation: int
    state_version: int


@dataclass(frozen=True, slots=True)
class _GCBNodeFacts:
    status: str
    version: int
    input_digest: str
    required_capabilities: tuple[str, ...]
    predecessors: tuple[str, ...]
    attempt_id: str
    claimed_by: str
    result_digest: str
    tainted: int


@dataclass(frozen=True, slots=True)
class _GCBAgentFacts:
    public_key: bytes
    key_id: str
    capabilities: tuple[str, ...]
    authority_epoch: int
    revocation_epoch: int
    revoked: int


@dataclass(frozen=True, slots=True)
class _GCBStagedArtifactFacts:
    artifact_json: str
    output_digest: str


@dataclass(frozen=True, slots=True)
class _GCBPredecessorFacts:
    node_id: str
    status: str
    commit_id: str | None
    result_digest: str
    tainted: int
    logical_version: str
    certificate_digest: str | None


@dataclass(frozen=True, slots=True)
class _GCBProjectionFacts:
    workflow: _GCBWorkflowFacts
    node: _GCBNodeFacts
    agent: _GCBAgentFacts
    staged: _GCBStagedArtifactFacts
    seal_store_id: str
    predecessors: tuple[_GCBPredecessorFacts, ...]
    revoked_closure: bool
    now_seconds: int


@dataclass(frozen=True, slots=True)
class _ValidatedGCBProjection:
    legacy_node_version: int
    next_workflow_state_version: int
    artifact_json: str


@dataclass(frozen=True, slots=True)
class _GCBAtomicCommitRequest(AtomicCommitRequest):
    """Internal APCC request carrying only an immutable semantic plan."""

    _gcb_projection_plan: _GCBProjectionPlan


class _GCBProjectionDenied(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _GCBProjectionFault(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _gcb_material_object(value: str, *, label: str) -> dict[str, object]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1_048_576:
        raise _GCBProjectionDenied(f"invalid_{label}_material")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise _GCBProjectionDenied(f"invalid_{label}_material")
            result[key] = item
        return result

    def number(_: str) -> object:
        raise _GCBProjectionDenied(f"invalid_{label}_material")

    try:
        parsed = json.loads(value, object_pairs_hook=pairs, parse_constant=number)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise _GCBProjectionDenied(f"invalid_{label}_material") from error
    if not isinstance(parsed, dict) or _canonical_json(parsed) != value:
        raise _GCBProjectionDenied(f"invalid_{label}_material")
    return parsed


def _gcb_exact_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _GCBProjectionDenied(f"invalid_{label}")
    return value


def _gcb_decimal(value: object, *, label: str) -> int:
    if not isinstance(value, str) or (
        not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise _GCBProjectionDenied(f"invalid_{label}")
    return int(value)


def _gcb_seconds(statement: object, field: str) -> int:
    if not isinstance(statement, Mapping):
        raise _GCBProjectionDenied("projection_request_mismatch")
    milliseconds = _gcb_decimal(statement.get(field), label=field)
    if milliseconds % 1000:
        raise _GCBProjectionDenied("projection_request_mismatch")
    return milliseconds // 1000


def _gcb_string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise _GCBProjectionDenied(f"invalid_{label}")
    items = tuple(value)
    if len(set(items)) != len(items):
        raise _GCBProjectionDenied(f"invalid_{label}")
    return items


def _validate_gcb_projection(
    config: APCCAuthorityConfig,
    request: AtomicCommitRequest,
    plan: _GCBProjectionPlan,
    facts: _GCBProjectionFacts,
) -> _ValidatedGCBProjection:
    """Validate one projection using only immutable material and scalar facts."""
    expected_node_version, committed_node_version, workflow_state_version = (
        _validate_gcb_projection_identity(request, plan)
    )

    workflow = facts.workflow
    node = facts.node
    agent = facts.agent
    staged = facts.staged
    legacy_node_version = _gcb_exact_int(node.version, label="legacy_node_version")
    if (
        node.status != "result_produced"
        or legacy_node_version != 2 + bool(node.predecessors)
        or node.input_digest != request.subject.input_digest
        or node.attempt_id != plan.attempt_id
        or node.claimed_by != plan.agent_id
        or node.result_digest != request.subject.output_digest
        or node.tainted != 0
        or staged.output_digest != request.subject.output_digest
        or agent.key_id != request.signatures.producer.key_id
        or agent.authority_epoch != workflow.authority_epoch
        or agent.revocation_epoch != int(request.context.agent_revocation_generation)
        or agent.revoked != 0
        or workflow.policy_digest != plan.policy_digest
        or workflow.state_version != workflow_state_version
    ):
        raise _GCBProjectionDenied("stale_or_mismatched_projection_state")
    if facts.revoked_closure:
        raise _GCBProjectionDenied("node_tainted_by_revocation")
    if not set(node.required_capabilities).issubset(agent.capabilities):
        raise _GCBProjectionDenied("authority_or_capability_denied")

    producer_binding = next(
        (
            binding
            for binding in config.producer_trust
            if binding.key_id == agent.key_id
            and binding.public_key == agent.public_key
            and binding.scope
            == (
                plan.agent_id,
                request.subject.actor_authority,
                request.context.authority_root,
            )
        ),
        None,
    )
    if producer_binding is None:
        raise _GCBProjectionDenied("authority_or_capability_denied")
    if (
        request.context.policy_version != workflow.policy_version
        or int(request.context.policy_epoch) != workflow.policy_epoch
        or request.context.policy_id != workflow.verifier_policy_id
        or request.context.authority_root != workflow.authority_root
        or int(request.context.authority_epoch) != workflow.authority_epoch
        or int(request.context.workflow_revocation_generation)
        != workflow.revocation_generation
        or int(request.context.workflow_epoch) != workflow.generation
    ):
        raise _GCBProjectionDenied("stale_or_mismatched_projection_context")

    predecessor_by_node = {item.node_id: item for item in request.bindings.predecessors}
    if set(predecessor_by_node) != set(node.predecessors) or any(
        item.workflow_id != plan.workflow_id for item in predecessor_by_node.values()
    ):
        raise _GCBProjectionDenied("predecessor_binding_mismatch")
    persisted_predecessors = {item.node_id: item for item in facts.predecessors}
    if set(persisted_predecessors) != set(node.predecessors):
        raise _GCBProjectionDenied("predecessor_binding_mismatch")
    for predecessor_id in node.predecessors:
        predecessor = persisted_predecessors[predecessor_id]
        binding = predecessor_by_node[predecessor_id]
        if (
            predecessor.status != "governed_committed"
            or predecessor.commit_id != binding.commit_id
            or predecessor.result_digest != binding.output_digest
            or predecessor.tainted != 0
            or predecessor.logical_version != binding.committed_node_version
            or predecessor.certificate_digest != binding.certificate_digest
        ):
            raise _GCBProjectionDenied("predecessor_binding_mismatch")

    return _validate_gcb_projection_material(
        config,
        request,
        plan,
        facts,
        expected_node_version,
        workflow_state_version,
        legacy_node_version,
    )


def _validate_gcb_projection_identity(
    request: AtomicCommitRequest, plan: _GCBProjectionPlan
) -> tuple[int, int, int]:
    """Validate the plan/request identity before any durable facts are loaded."""
    string_fields = (
        plan.workflow_id,
        plan.node_id,
        plan.attempt_id,
        plan.agent_id,
        plan.commit_id,
        plan.nonce,
        plan.policy_digest,
        plan.request_hash,
        plan.receipt_material,
        plan.receipt_digest,
        plan.verdict_material,
        plan.verdict_digest,
    )
    if any(not isinstance(value, str) or not value for value in string_fields):
        raise _GCBProjectionDenied("projection_plan_type_mismatch")
    expected_node_version = _gcb_exact_int(
        plan.expected_node_version, label="expected_node_version"
    )
    committed_node_version = _gcb_exact_int(
        plan.committed_node_version, label="committed_node_version"
    )
    workflow_state_version = _gcb_exact_int(
        plan.expected_workflow_state_version, label="workflow_state_version"
    )
    if (
        plan.workflow_id != request.subject.workflow_id
        or plan.node_id != request.subject.node_id
        or plan.attempt_id != request.subject.attempt_id
        or plan.agent_id != request.subject.agent_id
        or plan.commit_id != request.commit_id
        or plan.nonce != request.nonce
        or str(expected_node_version) != request.bindings.expected_node_version
        or committed_node_version != expected_node_version + 1
        or str(committed_node_version) != request.bindings.committed_node_version
    ):
        raise _GCBProjectionDenied("projection_request_mismatch")
    return expected_node_version, committed_node_version, workflow_state_version


def _validate_gcb_projection_material(
    config: APCCAuthorityConfig,
    request: AtomicCommitRequest,
    plan: _GCBProjectionPlan,
    facts: _GCBProjectionFacts,
    expected_node_version: int,
    workflow_state_version: int,
    legacy_node_version: int,
) -> _ValidatedGCBProjection:
    """Validate canonical receipt and verdict material."""
    producer = request.evidence.producer_statement
    issued_at = _gcb_seconds(producer, "issued_at_ms")
    expires_at = _gcb_seconds(producer, "expires_at_ms")
    receipt_signature = base64.b64encode(
        b64u_decode(request.signatures.producer.signature_b64u, expected_length=64)
    ).decode("ascii")
    predecessor_bindings = [
        {
            "node_id": item.node_id,
            "node_version": int(item.committed_node_version),
            "commit_id": item.commit_id,
            "receipt_digest": item.certificate_digest,
            "authoritative_result_digest": item.output_digest,
        }
        for item in sorted(request.bindings.predecessors, key=lambda item: item.node_id)
    ]
    receipt_payload: dict[str, object] = {
        "profile": _GCB_RECEIPT_PROFILE,
        "signature_algorithm": _GCB_SIGNATURE_ALGORITHM,
        "key_id": request.signatures.producer.key_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "intent": _GCB_COMMIT_INTENT,
        "verifier_policy_id": request.context.policy_id,
        "workflow_id": plan.workflow_id,
        "node_id": plan.node_id,
        "attempt_id": plan.attempt_id,
        "agent_id": plan.agent_id,
        "input_digest": request.subject.input_digest,
        "output_digest": request.subject.output_digest,
        "predecessor_bindings": predecessor_bindings,
        "predecessor_root": request.bindings.predecessor_root,
        "policy_version": request.context.policy_version,
        "policy_digest": plan.policy_digest,
        "policy_epoch": int(request.context.policy_epoch),
        "authority_snapshot_digest": request.subject.actor_authority,
        "authority_root": request.context.authority_root,
        "authority_epoch": int(request.context.authority_epoch),
        "agent_revocation_epoch": int(request.context.agent_revocation_generation),
        "workflow_revocation_generation": int(
            request.context.workflow_revocation_generation
        ),
        "workflow_generation": int(request.context.workflow_epoch),
        "state_version": workflow_state_version,
        "expected_node_state_version": expected_node_version,
        "nonce": plan.nonce,
        "commit_id": plan.commit_id,
    }
    receipt_body = _gcb_material_object(plan.receipt_material, label="receipt")
    if receipt_body != {"payload": receipt_payload, "signature": receipt_signature}:
        raise _GCBProjectionDenied("projection_receipt_mismatch")
    if (
        hashlib.sha256(plan.receipt_material.encode()).hexdigest()
        != plan.receipt_digest
    ):
        raise _GCBProjectionDenied("projection_receipt_digest_mismatch")

    verdict = _gcb_material_object(plan.verdict_material, label="verdict")
    expected_verdict_keys = {
        "decision",
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
        "expected_node_state_version",
        "policy_epoch",
        "authority_epoch",
        "agent_revocation_epoch",
        "workflow_revocation_generation",
        "workflow_generation",
        "issued_at",
        "expires_at",
        "reason",
        "signature",
    }
    if set(verdict) != expected_verdict_keys:
        raise _GCBProjectionDenied("projection_verdict_mismatch")
    policy_binding = next(
        (
            binding
            for binding in config.policy_trust
            if binding.scope
            == (
                request.context.policy_id,
                request.context.policy_version,
                request.context.policy_epoch,
            )
        ),
        None,
    )
    if policy_binding is None:
        raise _GCBProjectionDenied("untrusted_policy_binding")
    verdict_issued = _gcb_exact_int(verdict["issued_at"], label="verdict_issued_at")
    verdict_expires = _gcb_exact_int(verdict["expires_at"], label="verdict_expires_at")
    expected_verdict = {
        "decision": "allow",
        "store_id": facts.seal_store_id,
        "verifier_policy_id": request.context.policy_id,
        "policy_id": request.context.policy_id,
        "policy_version": request.context.policy_version,
        "verifier_key_id": policy_binding.key_id,
        "receipt_digest": plan.receipt_digest,
        "workflow_id": plan.workflow_id,
        "node_id": plan.node_id,
        "attempt_id": plan.attempt_id,
        "agent_id": plan.agent_id,
        "expected_node_state_version": expected_node_version,
        "policy_epoch": int(request.context.policy_epoch),
        "authority_epoch": int(request.context.authority_epoch),
        "agent_revocation_epoch": int(request.context.agent_revocation_generation),
        "workflow_revocation_generation": int(
            request.context.workflow_revocation_generation
        ),
        "workflow_generation": int(request.context.workflow_epoch),
    }
    if any(verdict.get(key) != value for key, value in expected_verdict.items()):
        raise _GCBProjectionDenied("projection_verdict_mismatch")
    signature = verdict["signature"]
    if (
        not isinstance(verdict["reason"], str)
        or not isinstance(signature, str)
        or verdict_issued > facts.now_seconds + 30
        or verdict_expires < facts.now_seconds
        or verdict_expires <= verdict_issued
    ):
        raise _GCBProjectionDenied("invalid_projection_verdict")
    unsigned_verdict = {
        key: value for key, value in verdict.items() if key != "signature"
    }
    try:
        Ed25519PublicKey.from_public_bytes(policy_binding.public_key).verify(
            base64.b64decode(signature, validate=True),
            _GCB_VERDICT_DOMAIN
            + json.dumps(
                unsigned_verdict, sort_keys=True, separators=(",", ":")
            ).encode("ascii"),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise _GCBProjectionDenied("invalid_projection_verdict_signature") from error
    if (
        hashlib.sha256(plan.verdict_material.encode()).hexdigest()
        != plan.verdict_digest
    ):
        raise _GCBProjectionDenied("projection_verdict_digest_mismatch")
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "payload": receipt_payload,
                "signature": receipt_signature,
                "verdict": verdict,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if request_hash != plan.request_hash:
        raise _GCBProjectionDenied("projection_request_hash_mismatch")
    return _ValidatedGCBProjection(
        legacy_node_version,
        workflow_state_version + 1,
        facts.staged.artifact_json,
    )
