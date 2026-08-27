from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
from dataclasses import dataclass
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.verifier import (
    CausalClosureLimits,
    FailureCode,
    ScopedTrust,
    TrustBinding,
    TrustRole,
    verify_causal_closure,
    verify_current,
    verify_historical,
)


SEEDS = {
    "producer": bytes(range(32)),
    "policy": bytes(range(32, 64)),
    "authority": bytes(range(64, 96)),
    "commit": bytes(range(96, 128)),
    "status": bytes(range(128, 160)),
}
DOMAINS = {
    "producer": b"APCC-PROPOSAL-V1",
    "policy": b"APCC-POLICY-V1",
    "authority": b"APCC-AUTHORITY-V1",
    "commit": b"APCC-COMMIT-V1",
    "status": b"APCC-AUTHORITY-STATUS-V1",
}


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical(value: Any) -> bytes:
    """Test-local APCC-CJ1 construction only; never imported by implementation."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return _b64u(hashlib.sha256(value).digest())


def _public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _signature(seed: bytes, domain: bytes, body: bytes, key_id: str) -> dict[str, str]:
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signature_b64u": _b64u(
            Ed25519PrivateKey.from_private_bytes(seed).sign(domain + b"\x00" + body)
        ),
    }


@dataclass(frozen=True)
class ValidVector:
    envelope: bytes
    payload: dict[str, Any]
    status: dict[str, Any]
    trust: ScopedTrust


def _seal(payload: dict[str, Any]) -> bytes:
    inner = _canonical(payload)
    envelope = {
        "envelope_type": "apcc.detached-certificate-envelope",
        "payload_b64u": _b64u(inner),
        "payload_sha256": _digest(inner),
        "seal": _signature(SEEDS["commit"], DOMAINS["commit"], inner, "commit-key"),
    }
    return _canonical(envelope)


def _status(payload: dict[str, Any]) -> dict[str, Any]:
    body = {
        "protocol_version": "APCC-1.0-draft",
        "statement_type": "apcc.authority-status",
        "authority_store_id": "store-1",
        "status_key_id": "status-key",
        "request_nonce": _b64u(bytes(range(16))),
        "certificate_digest": _digest(_canonical(payload)),
        "certificate_sequence": "42",
        "trust_log_sequence": "42",
        "trust_log_head": _digest(b"trust-log-head"),
        "status": "current",
        "actor_revocation_generation": "3",
        "workflow_revocation_generation": "4",
        "superseded": "no",
        "this_update_ms": "1760000000000",
        "next_update_ms": "1760000005000",
    }
    return {
        "body": body,
        "signature": _signature(
            SEEDS["status"], DOMAINS["status"], _canonical(body), "status-key"
        ),
    }


def valid_vector() -> ValidVector:
    authority_root = _digest(b"authority-root")
    predecessor = {
        "workflow_id": "workflow-1",
        "node_id": "node-0",
        "committed_node_version": "7",
        "commit_id": "commit-0",
        "certificate_digest": _digest(b"predecessor-certificate"),
        "output_digest": _digest(b"predecessor-output"),
    }
    predecessor_root = _digest(_canonical([predecessor]))
    nonce = _b64u(bytes(range(16)))
    producer = {
        "protocol_version": "APCC-1.0-draft",
        "statement_type": "apcc.producer-statement",
        "producer_key_id": "producer-key",
        "workflow_id": "workflow-1",
        "node_id": "node-1",
        "attempt_id": "attempt-1",
        "agent_id": "agent-1",
        "actor_authority": "authority:ns:execute",
        "input_digest": _digest(b"input"),
        "output_digest": _digest(b"output"),
        "predecessor_root": predecessor_root,
        "expected_node_version": "7",
        "commit_id": "commit-1",
        "nonce": nonce,
        "issued_at_ms": "1760000000000",
        "expires_at_ms": "1760000005000",
    }
    producer_bytes = _canonical(producer)
    proposal_digest = _digest(producer_bytes)
    policy = {
        "protocol_version": "APCC-1.0-draft",
        "statement_type": "apcc.policy-statement",
        "policy_key_id": "policy-key",
        "proposal_digest": proposal_digest,
        "decision": "allow",
        "policy_id": "policy-1",
        "policy_version": "7",
        "policy_epoch": "11",
        "workflow_id": "workflow-1",
        "node_id": "node-1",
        "attempt_id": "attempt-1",
        "issued_at_ms": "1760000000000",
        "expires_at_ms": "1760000005000",
    }
    authority = {
        "protocol_version": "APCC-1.0-draft",
        "statement_type": "apcc.authority-statement",
        "authority_key_id": "authority-key",
        "proposal_digest": proposal_digest,
        "agent_id": "agent-1",
        "producer_key_id": "producer-key",
        "actor_authority": "authority:ns:execute",
        "authority_root": authority_root,
        "authority_epoch": "5",
        "agent_revocation_generation": "3",
        "workflow_revocation_generation": "4",
        "workflow_epoch": "9",
        "workflow_id": "workflow-1",
        "node_id": "node-1",
        "attempt_id": "attempt-1",
        "issued_at_ms": "1760000000000",
        "expires_at_ms": "1760000005000",
    }
    payload = {
        "header": {
            "protocol_version": "APCC-1.0-draft",
            "certificate_type": "apcc.commit-certificate",
            "encoding_profile": "APCC-CJ1",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
            "authority_store_id": "store-1",
            "commit_authority_key_id": "commit-key",
            "certificate_sequence": "42",
        },
        "subject": {
            key: producer[key]
            for key in (
                "workflow_id",
                "node_id",
                "attempt_id",
                "agent_id",
                "actor_authority",
                "input_digest",
                "output_digest",
            )
        },
        "context": {
            "policy_id": "policy-1",
            "policy_version": "7",
            "policy_epoch": "11",
            "authority_root": authority["authority_root"],
            "authority_epoch": "5",
            "agent_revocation_generation": "3",
            "workflow_revocation_generation": "4",
            "workflow_epoch": "9",
        },
        "evidence": {
            "producer_statement": producer,
            "producer_statement_digest": proposal_digest,
            "policy_statement": policy,
            "policy_statement_digest": _digest(_canonical(policy)),
            "authority_statement": authority,
            "authority_statement_digest": _digest(_canonical(authority)),
        },
        "decision": {
            "outcome": "committed",
            "reason": "policy-approved",
            "commit_id": "commit-1",
            "nonce": nonce,
            "committed_at_ms": "1760000001000",
        },
        "bindings": {
            "expected_node_version": "7",
            "committed_node_version": "8",
            "predecessor_root": predecessor_root,
            "predecessors": [predecessor],
        },
        "signatures": {
            "producer": _signature(
                SEEDS["producer"], DOMAINS["producer"], producer_bytes, "producer-key"
            ),
            "policy_authority": _signature(
                SEEDS["policy"], DOMAINS["policy"], _canonical(policy), "policy-key"
            ),
            "authority_registry": _signature(
                SEEDS["authority"],
                DOMAINS["authority"],
                _canonical(authority),
                "authority-key",
            ),
        },
    }
    return ValidVector(
        _seal(payload),
        payload,
        _status(payload),
        ScopedTrust(
            (
                TrustBinding(
                    TrustRole.PRODUCER,
                    ("agent-1", "authority:ns:execute", authority_root),
                    "producer-key",
                    _public(SEEDS["producer"]),
                ),
                TrustBinding(
                    TrustRole.POLICY,
                    ("policy-1", "7", "11"),
                    "policy-key",
                    _public(SEEDS["policy"]),
                ),
                TrustBinding(
                    TrustRole.REGISTRY,
                    (authority_root, "5"),
                    "authority-key",
                    _public(SEEDS["authority"]),
                ),
                TrustBinding(
                    TrustRole.COMMIT,
                    ("store-1",),
                    "commit-key",
                    _public(SEEDS["commit"]),
                ),
                TrustBinding(
                    TrustRole.STATUS,
                    ("store-1",),
                    "status-key",
                    _public(SEEDS["status"]),
                ),
            )
        ),
    )


def _rebuild(
    vector: ValidVector,
    payload: dict[str, Any] | None = None,
    status: dict[str, Any] | None = None,
) -> ValidVector:
    payload = payload or vector.payload
    return ValidVector(
        _seal(payload), payload, status or _status(payload), vector.trust
    )


def _resign_statement(
    payload: dict[str, Any], statement_name: str, signature_name: str
) -> None:
    seed, domain, key_id = {
        "producer": (SEEDS["producer"], DOMAINS["producer"], "producer-key"),
        "policy_authority": (SEEDS["policy"], DOMAINS["policy"], "policy-key"),
        "authority_registry": (
            SEEDS["authority"],
            DOMAINS["authority"],
            "authority-key",
        ),
    }[signature_name]
    statement = payload["evidence"][statement_name]
    payload["evidence"][f"{statement_name}_digest"] = _digest(_canonical(statement))
    payload["signatures"][signature_name] = _signature(
        seed, domain, _canonical(statement), key_id
    )


def _historical(vector: ValidVector):
    return verify_historical(vector.envelope, trust=vector.trust)


def _current(
    vector: ValidVector,
    *,
    request_nonce: str | None = None,
    highest_trust_log_sequence: str = "42",
    highest_trust_log_head: str | None = None,
):
    return verify_current(
        vector.envelope,
        trust=vector.trust,
        authority_status=vector.status,
        request_nonce=request_nonce or _b64u(bytes(range(16))),
        now_ms="1760000001000",
        highest_trust_log_sequence=highest_trust_log_sequence,
        highest_trust_log_head=highest_trust_log_head or _digest(b"trust-log-head"),
        maximum_staleness_ms="5000",
    )


def _parent_vector() -> ValidVector:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    predecessor = vector.payload["bindings"]["predecessors"][0]
    payload["subject"].update(
        node_id=predecessor["node_id"],
        attempt_id="attempt-0",
        output_digest=predecessor["output_digest"],
    )
    producer = payload["evidence"]["producer_statement"]
    producer.update(
        node_id=predecessor["node_id"],
        attempt_id="attempt-0",
        output_digest=predecessor["output_digest"],
        expected_node_version="6",
        commit_id=predecessor["commit_id"],
    )
    payload["decision"]["commit_id"] = predecessor["commit_id"]
    payload["bindings"].update(
        expected_node_version="6",
        committed_node_version=predecessor["committed_node_version"],
        predecessors=[],
        predecessor_root=_digest(_canonical([])),
    )
    producer["predecessor_root"] = payload["bindings"]["predecessor_root"]
    for statement_name, signature_name in (
        ("producer_statement", "producer"),
        ("policy_statement", "policy_authority"),
        ("authority_statement", "authority_registry"),
    ):
        statement = payload["evidence"][statement_name]
        if statement_name != "producer_statement":
            statement.update(node_id=predecessor["node_id"], attempt_id="attempt-0")
        _resign_statement(payload, statement_name, signature_name)
    proposal_digest = payload["evidence"]["producer_statement_digest"]
    for statement_name, signature_name in (
        ("policy_statement", "policy_authority"),
        ("authority_statement", "authority_registry"),
    ):
        payload["evidence"][statement_name]["proposal_digest"] = proposal_digest
        _resign_statement(payload, statement_name, signature_name)
    return _rebuild(vector, payload)


def _predecessor_reference(parent: ValidVector) -> dict[str, str]:
    return {
        "workflow_id": parent.payload["subject"]["workflow_id"],
        "node_id": parent.payload["subject"]["node_id"],
        "committed_node_version": parent.payload["bindings"]["committed_node_version"],
        "commit_id": parent.payload["decision"]["commit_id"],
        "certificate_digest": _digest(_canonical(parent.payload)),
        "output_digest": parent.payload["subject"]["output_digest"],
    }


def _child_for_parents(
    parents: tuple[ValidVector, ...],
    *,
    node_id: str = "node-1",
    attempt_id: str = "attempt-1",
    commit_id: str = "commit-1",
    expected_version: str = "7",
    output_digest: str | None = None,
) -> ValidVector:
    child = valid_vector()
    payload = copy.deepcopy(child.payload)
    output_digest = output_digest or _digest(b"output")
    payload["subject"].update(
        node_id=node_id,
        attempt_id=attempt_id,
        output_digest=output_digest,
    )
    payload["decision"]["commit_id"] = commit_id
    payload["bindings"].update(
        expected_node_version=expected_version,
        committed_node_version=str(int(expected_version) + 1),
        predecessors=sorted(
            (_predecessor_reference(parent) for parent in parents), key=_canonical
        ),
    )
    payload["bindings"]["predecessor_root"] = _digest(
        _canonical(payload["bindings"]["predecessors"])
    )
    producer = payload["evidence"]["producer_statement"]
    producer.update(
        node_id=node_id,
        attempt_id=attempt_id,
        output_digest=output_digest,
        predecessor_root=payload["bindings"]["predecessor_root"],
        expected_node_version=expected_version,
        commit_id=commit_id,
    )
    _resign_statement(payload, "producer_statement", "producer")
    proposal_digest = payload["evidence"]["producer_statement_digest"]
    for statement_name, signature_name in (
        ("policy_statement", "policy_authority"),
        ("authority_statement", "authority_registry"),
    ):
        payload["evidence"][statement_name].update(
            node_id=node_id,
            attempt_id=attempt_id,
            proposal_digest=proposal_digest,
        )
        _resign_statement(payload, statement_name, signature_name)
    return _rebuild(child, payload)


def _leaf_for_parent(parent: ValidVector) -> ValidVector:
    return _child_for_parents((parent,))


def _with_reference_change(child: ValidVector, field: str, value: str) -> ValidVector:
    payload = copy.deepcopy(child.payload)
    payload["bindings"]["predecessors"][0][field] = value
    payload["bindings"]["predecessor_root"] = _digest(
        _canonical(payload["bindings"]["predecessors"])
    )
    payload["evidence"]["producer_statement"]["predecessor_root"] = payload["bindings"][
        "predecessor_root"
    ]
    _resign_statement(payload, "producer_statement", "producer")
    proposal_digest = payload["evidence"]["producer_statement_digest"]
    for statement_name, signature_name in (
        ("policy_statement", "policy_authority"),
        ("authority_statement", "authority_registry"),
    ):
        payload["evidence"][statement_name]["proposal_digest"] = proposal_digest
        _resign_statement(payload, statement_name, signature_name)
    return _rebuild(child, payload)


def _with_invalid_commit_seal(envelope: bytes) -> bytes:
    outer = json.loads(envelope)
    signature = outer["seal"]["signature_b64u"]
    outer["seal"]["signature_b64u"] = ("A" if signature[0] != "A" else "B") + signature[
        1:
    ]
    return _canonical(outer)


class _Resolver:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
        return self.values.get(certificate_digest)


class _RaisingResolver:
    def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
        raise RuntimeError(certificate_digest)


class _RaisingTrust:
    def resolve(self, role: TrustRole, scope: tuple[str, ...]) -> TrustBinding | None:
        raise RuntimeError((role, scope))


class _RaisingStatus(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("status iteration")

    def __len__(self) -> int:
        return 1


def test_causal_closure_verifies_a_two_edge_digest_pinned_chain() -> None:
    grandparent = _parent_vector()
    parent = _leaf_for_parent(grandparent)
    leaf = _child_for_parents(
        (parent,),
        node_id="node-2",
        attempt_id="attempt-2",
        commit_id="commit-2",
        expected_version="8",
        output_digest=_digest(b"output-2"),
    )
    grandparent_digest = _digest(_canonical(grandparent.payload))
    parent_digest = _digest(_canonical(parent.payload))
    verdict = verify_causal_closure(
        leaf.envelope,
        trust=leaf.trust,
        resolver=_Resolver(
            {
                parent_digest: parent.envelope,
                grandparent_digest: grandparent.envelope,
            }
        ),
    )
    assert verdict.ok


def test_causal_closure_fails_closed_for_missing_and_resolver_exception() -> None:
    parent = _parent_vector()
    leaf = _leaf_for_parent(parent)
    for resolver in (_Resolver({}), _RaisingResolver()):
        verdict = verify_causal_closure(
            leaf.envelope,
            trust=leaf.trust,
            resolver=resolver,
        )
        assert verdict.code is FailureCode.INVALID_PREDECESSOR
    nil_verdict = verify_causal_closure(
        leaf.envelope,
        trust=leaf.trust,
        resolver=None,  # type: ignore[arg-type]
    )
    assert nil_verdict.code is FailureCode.INVALID_PREDECESSOR


@pytest.mark.parametrize(
    ("resolved", "historical_code"),
    (
        (b"{}", FailureCode.MISSING_FIELD),
        (
            _with_invalid_commit_seal(_parent_vector().envelope),
            FailureCode.INVALID_COMMIT_SEAL,
        ),
    ),
)
def test_causal_closure_collapses_found_invalid_predecessor_to_stable_code(
    resolved: bytes, historical_code: FailureCode
) -> None:
    parent = _parent_vector()
    leaf = _leaf_for_parent(parent)
    parent_digest = _digest(_canonical(parent.payload))

    historical = verify_historical(resolved, trust=leaf.trust)
    assert not historical.ok
    assert historical.code is historical_code

    verdict = verify_causal_closure(
        leaf.envelope,
        trust=leaf.trust,
        resolver=_Resolver({parent_digest: resolved}),
    )
    assert verdict.code is FailureCode.INVALID_PREDECESSOR


def test_causal_closure_limits_fail_independently() -> None:
    parent = _parent_vector()
    leaf = _leaf_for_parent(parent)
    parent_digest = _digest(_canonical(parent.payload))
    resolver = _Resolver({parent_digest: parent.envelope})
    cases = (
        (CausalClosureLimits(max_depth=0), FailureCode.DEPTH_LIMIT_EXCEEDED),
        (CausalClosureLimits(max_certificates=1), FailureCode.SIZE_LIMIT_EXCEEDED),
        (
            CausalClosureLimits(max_total_bytes=len(leaf.envelope)),
            FailureCode.SIZE_LIMIT_EXCEEDED,
        ),
    )
    for limits, expected in cases:
        verdict = verify_causal_closure(
            leaf.envelope,
            trust=leaf.trust,
            resolver=resolver,
            limits=limits,
        )
        assert verdict.code is expected


@pytest.mark.parametrize(
    "values",
    (
        (-1, 4096, 64 * 1024 * 1024),
        (64, 0, 64 * 1024 * 1024),
        (64, 4096, 0),
    ),
)
def test_invalid_causal_closure_limits_fail_closed(
    values: tuple[int, int, int],
) -> None:
    vector = valid_vector()
    limits = CausalClosureLimits(*values)
    verdict = verify_causal_closure(
        vector.envelope,
        trust=vector.trust,
        resolver=_Resolver({}),
        limits=limits,
    )
    assert verdict.code is FailureCode.SIZE_LIMIT_EXCEEDED


def test_public_verifiers_fail_closed_for_hostile_trust_and_status() -> None:
    vector = valid_vector()
    for hostile_trust in (_RaisingTrust(), None):
        historical = verify_historical(
            vector.envelope,
            trust=hostile_trust,  # type: ignore[arg-type]
        )
        causal = verify_causal_closure(
            vector.envelope,
            trust=hostile_trust,  # type: ignore[arg-type]
            resolver=_Resolver({}),
        )
        current = verify_current(
            vector.envelope,
            trust=hostile_trust,  # type: ignore[arg-type]
            authority_status=vector.status,
            request_nonce=vector.status["body"]["request_nonce"],
            now_ms="1760000001000",
            highest_trust_log_sequence="42",
            highest_trust_log_head=vector.status["body"]["trust_log_head"],
            maximum_staleness_ms="5000",
        )
        assert historical.code is FailureCode.UNKNOWN_KEY
        assert causal.code is FailureCode.UNKNOWN_KEY
        assert current.code is FailureCode.UNKNOWN_KEY

    hostile_status = verify_current(
        vector.envelope,
        trust=vector.trust,
        authority_status=_RaisingStatus(),
        request_nonce=vector.status["body"]["request_nonce"],
        now_ms="1760000001000",
        highest_trust_log_sequence="42",
        highest_trust_log_head=vector.status["body"]["trust_log_head"],
        maximum_staleness_ms="5000",
    )
    assert hostile_status.code is FailureCode.NONCANONICAL_ENCODING


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("workflow_id", "workflow-2", FailureCode.CROSS_WORKFLOW_PREDECESSOR),
        ("node_id", "other-node", FailureCode.INVALID_PREDECESSOR),
        ("committed_node_version", "6", FailureCode.INVALID_PREDECESSOR),
        ("commit_id", "other-commit", FailureCode.INVALID_PREDECESSOR),
        (
            "certificate_digest",
            _digest(b"other-certificate"),
            FailureCode.INVALID_PREDECESSOR,
        ),
        ("output_digest", _digest(b"other-output"), FailureCode.INVALID_PREDECESSOR),
    ),
)
def test_causal_closure_rejects_each_six_field_edge_mismatch(
    field: str, value: str, expected: FailureCode
) -> None:
    parent = _parent_vector()
    leaf = _with_reference_change(_leaf_for_parent(parent), field, value)
    claimed_digest = leaf.payload["bindings"]["predecessors"][0]["certificate_digest"]
    verdict = verify_causal_closure(
        leaf.envelope,
        trust=leaf.trust,
        resolver=_Resolver({claimed_digest: parent.envelope}),
    )
    assert verdict.code is expected


def test_causal_closure_memoizes_a_shared_ancestor() -> None:
    grandparent = _parent_vector()
    left = _child_for_parents(
        (grandparent,), node_id="node-left", commit_id="commit-left"
    )
    right = _child_for_parents(
        (grandparent,), node_id="node-right", commit_id="commit-right"
    )
    root = _child_for_parents(
        (left, right), node_id="node-root", commit_id="commit-root"
    )
    values = {
        _digest(_canonical(grandparent.payload)): grandparent.envelope,
        _digest(_canonical(left.payload)): left.envelope,
        _digest(_canonical(right.payload)): right.envelope,
    }

    class CountingResolver(_Resolver):
        def __init__(self, items: dict[str, bytes]) -> None:
            super().__init__(items)
            self.calls: dict[str, int] = {}

        def resolve_predecessor(self, certificate_digest: str) -> bytes | None:
            self.calls[certificate_digest] = self.calls.get(certificate_digest, 0) + 1
            return super().resolve_predecessor(certificate_digest)

    resolver = CountingResolver(values)
    verdict = verify_causal_closure(root.envelope, trust=root.trust, resolver=resolver)
    assert verdict.ok
    assert resolver.calls == {digest: 1 for digest in values}


def test_valid_vector_is_independently_canonical_and_verifies_historically_and_currently() -> (
    None
):
    vector = valid_vector()
    assert all(
        len(value) == 43
        for value in (
            _digest(b"input"),
            vector.payload["bindings"]["predecessor_root"],
            vector.status["body"]["certificate_digest"],
        )
    )
    assert len(vector.status["body"]["request_nonce"]) == 22
    assert _historical(vector).ok
    assert _current(vector).ok


def test_current_verifier_requires_a_string_maximum_staleness_bound() -> None:
    vector = valid_vector()
    parameter = inspect.signature(verify_current).parameters["maximum_staleness_ms"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.annotation == "str"

    with pytest.raises(TypeError, match="maximum_staleness_ms"):
        verify_current(  # type: ignore[call-arg]
            vector.envelope,
            trust=vector.trust,
            authority_status=vector.status,
            request_nonce=_b64u(bytes(range(16))),
            now_ms="1760000001000",
            highest_trust_log_sequence="42",
            highest_trust_log_head=_digest(b"trust-log-head"),
        )

    for invalid in ("01", 5000):
        verdict = verify_current(
            vector.envelope,
            trust=vector.trust,
            authority_status=vector.status,
            request_nonce=_b64u(bytes(range(16))),
            now_ms="1760000001000",
            highest_trust_log_sequence="42",
            highest_trust_log_head=_digest(b"trust-log-head"),
            maximum_staleness_ms=invalid,  # type: ignore[arg-type]
        )
        assert verdict.code is FailureCode.INVALID_DECIMAL_STRING


@pytest.mark.parametrize("reuse", ("key_id", "public_key"))
def test_scoped_trust_rejects_cross_role_key_reuse(reuse: str) -> None:
    producer_key_id = "shared-key" if reuse == "key_id" else "producer-key"
    policy_key_id = "shared-key" if reuse == "key_id" else "policy-key"
    producer_public_key = _public(SEEDS["producer"])
    policy_public_key = (
        _public(SEEDS["producer"])
        if reuse == "public_key"
        else _public(SEEDS["policy"])
    )

    with pytest.raises(ValueError, match="cannot be reused across trust roles"):
        ScopedTrust(
            (
                TrustBinding(
                    TrustRole.PRODUCER,
                    ("agent-1", "authority:ns:execute", _digest(b"authority-root")),
                    producer_key_id,
                    producer_public_key,
                ),
                TrustBinding(
                    TrustRole.POLICY,
                    ("policy-1", "7", "11"),
                    policy_key_id,
                    policy_public_key,
                ),
            )
        )


def test_producer_key_cannot_impersonate_policy_role() -> None:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    statement = payload["evidence"]["policy_statement"]
    statement["policy_key_id"] = "producer-key"
    payload["evidence"]["policy_statement_digest"] = _digest(_canonical(statement))
    payload["signatures"]["policy_authority"] = _signature(
        SEEDS["producer"],
        DOMAINS["policy"],
        _canonical(statement),
        "producer-key",
    )

    assert _historical(_rebuild(vector, payload)).code is FailureCode.UNKNOWN_KEY


def test_verifier_rejects_extreme_nesting_before_recursive_json_decode() -> None:
    raw = b"[" * 100_000 + b"]" * 100_000

    assert (
        verify_historical(raw, trust=valid_vector().trust).code
        is FailureCode.DEPTH_LIMIT_EXCEEDED
    )


@pytest.mark.parametrize(
    ("path", "code"),
    (
        ("producer_statement", "STATEMENT_DIGEST_MISMATCH"),
        ("policy_statement", "STATEMENT_DIGEST_MISMATCH"),
        ("authority_statement", "STATEMENT_DIGEST_MISMATCH"),
        ("predecessor_root", "PREDECESSOR_ROOT_MISMATCH"),
        ("subject", "SUBJECT_MISMATCH"),
        ("context", "STALE_POLICY_EPOCH"),
        ("header", "UNKNOWN_PROTOCOL_VERSION"),
    ),
)
def test_historical_verifier_rejects_resealed_targeted_tampering(
    path: str, code: str
) -> None:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    if path.endswith("statement"):
        payload["evidence"][path]["workflow_id"] = "other-workflow"
    elif path == "predecessor_root":
        payload["bindings"][path] = _digest(b"wrong-root")
    elif path == "subject":
        payload["subject"]["agent_id"] = "other-agent"
    elif path == "context":
        payload["context"]["policy_epoch"] = "12"
    else:
        payload["header"]["protocol_version"] = "APCC-unknown"
    verdict = _historical(_rebuild(vector, payload))
    assert verdict.ok is False
    assert verdict.code.name == code


@pytest.mark.parametrize(
    ("signature_name", "code"),
    (
        ("producer", "INVALID_PRODUCER_SIGNATURE"),
        ("policy_authority", "INVALID_POLICY_SIGNATURE"),
        ("authority_registry", "INVALID_AUTHORITY_SIGNATURE"),
    ),
)
def test_historical_verifier_rejects_signature_only_corruption(
    signature_name: str, code: str
) -> None:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    payload["signatures"][signature_name]["signature_b64u"] = _b64u(bytes(64))

    verdict = _historical(_rebuild(vector, payload))

    assert verdict.ok is False
    assert verdict.code.name == code


@pytest.mark.parametrize(
    ("statement_name", "signature_name"),
    (
        ("policy_statement", "policy_authority"),
        ("authority_statement", "authority_registry"),
    ),
)
def test_resealed_re_signed_embedded_attempt_mismatch_is_not_cross_attempt_replay(
    statement_name: str, signature_name: str
) -> None:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    payload["evidence"][statement_name]["attempt_id"] = "attempt-2"
    _resign_statement(payload, statement_name, signature_name)

    verdict = _historical(_rebuild(vector, payload))

    assert verdict.ok is False
    assert verdict.code is FailureCode.ATTEMPT_MISMATCH


@pytest.mark.parametrize(
    ("target", "field", "value", "code"),
    (
        ("header", "protocol_version", "APCC-0.9", "UNKNOWN_PROTOCOL_VERSION"),
        (
            "header",
            "certificate_type",
            "apcc.other-certificate",
            "UNSUPPORTED_CERTIFICATE_TYPE",
        ),
        ("header", "encoding_profile", "JSON", "UNSUPPORTED_ENCODING"),
        ("header", "digest_algorithm", "SHA-1", "UNSUPPORTED_DIGEST_ALGORITHM"),
        (
            "header",
            "signature_algorithm",
            "RSA",
            "UNSUPPORTED_SIGNATURE_ALGORITHM",
        ),
        (
            "producer_statement",
            "protocol_version",
            "APCC-0.9",
            "UNKNOWN_PROTOCOL_VERSION",
        ),
        (
            "policy_statement",
            "statement_type",
            "apcc.unknown-policy",
            "UNSUPPORTED_STATEMENT_TYPE",
        ),
        (
            "policy_statement",
            "decision",
            "deny",
            "SUBJECT_MISMATCH",
        ),
        ("signature", "algorithm", "RSA", "UNSUPPORTED_SIGNATURE_ALGORITHM"),
        ("decision", "outcome", "denied", "ILLEGAL_NODE_STATE"),
        (
            "bindings",
            "committed_node_version",
            "9",
            "NODE_VERSION_CONFLICT",
        ),
    ),
)
def test_historical_verifier_maps_invalid_wire_literals_to_stable_codes(
    target: str, field: str, value: str, code: str
) -> None:
    vector = valid_vector()
    payload = copy.deepcopy(vector.payload)
    if target.endswith("_statement"):
        payload["evidence"][target][field] = value
        signature_name = {
            "producer_statement": "producer",
            "policy_statement": "policy_authority",
            "authority_statement": "authority_registry",
        }[target]
        _resign_statement(payload, target, signature_name)
    elif target == "signature":
        payload["signatures"]["producer"][field] = value
    else:
        payload[target][field] = value

    verdict = _historical(_rebuild(vector, payload))
    assert verdict.ok is False
    assert verdict.code is getattr(FailureCode, code)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("protocol_version", "APCC-0.9", "UNKNOWN_PROTOCOL_VERSION"),
        ("statement_type", "apcc.legacy-status", "UNSUPPORTED_STATEMENT_TYPE"),
        ("signature_algorithm", "RSA", "UNSUPPORTED_SIGNATURE_ALGORITHM"),
    ),
)
def test_current_verifier_maps_invalid_authority_status_literals_to_stable_codes(
    field: str, value: str, code: str
) -> None:
    vector = valid_vector()
    status = copy.deepcopy(vector.status)
    if field == "signature_algorithm":
        status["signature"]["algorithm"] = value
    else:
        status["body"][field] = value
        status["signature"] = _signature(
            SEEDS["status"], DOMAINS["status"], _canonical(status["body"]), "status-key"
        )

    verdict = _current(_rebuild(vector, status=status))
    assert verdict.ok is False
    assert verdict.code is getattr(FailureCode, code)


def test_historical_verifier_rejects_tampered_seal_signature_and_unknown_key() -> None:
    vector = valid_vector()
    envelope = json.loads(vector.envelope)
    envelope["seal"]["signature_b64u"] = _b64u(bytes(64))
    assert (
        _historical(
            ValidVector(
                _canonical(envelope), vector.payload, vector.status, vector.trust
            )
        ).code
        is FailureCode.INVALID_COMMIT_SEAL
    )
    payload = copy.deepcopy(vector.payload)
    payload["signatures"]["producer"]["key_id"] = "unknown-key"
    assert _historical(_rebuild(vector, payload)).code is FailureCode.KEY_ID_MISMATCH

    payload = copy.deepcopy(vector.payload)
    payload["header"]["commit_authority_key_id"] = "unknown-key"
    envelope = json.loads(_seal(payload))
    envelope["seal"]["key_id"] = "unknown-key"
    unknown = ValidVector(_canonical(envelope), payload, _status(payload), vector.trust)
    assert _historical(unknown).code is FailureCode.UNKNOWN_KEY


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("request_nonce", _b64u(b"x" * 16), "AUTHORITY_STATUS_NONCE_MISMATCH"),
        (
            "certificate_digest",
            _digest(b"other"),
            "AUTHORITY_STATUS_CERTIFICATE_MISMATCH",
        ),
        ("actor_revocation_generation", "4", "ACTOR_REVOKED"),
        ("workflow_revocation_generation", "5", "WORKFLOW_REVOKED"),
        ("next_update_ms", "1760000000001", "AUTHORITY_STATUS_EXPIRED"),
        ("this_update_ms", "1760000002000", "ATTESTATION_NOT_YET_VALID"),
        ("trust_log_sequence", "41", "AUTHORITY_STATUS_ROLLBACK"),
        ("trust_log_head", _digest(b"other-head"), "AUTHORITY_STATUS_ROLLBACK"),
        ("status", "revoked", "AUTHORITY_STATUS_REVOKED"),
        ("superseded", "yes", "AUTHORITY_STATUS_SUPERSEDED"),
    ),
)
def test_current_verifier_rejects_each_authority_status_failure(
    field: str, value: str, code: str
) -> None:
    vector = valid_vector()
    status = copy.deepcopy(vector.status)
    status["body"][field] = value
    status["signature"] = _signature(
        SEEDS["status"], DOMAINS["status"], _canonical(status["body"]), "status-key"
    )
    verdict = _current(_rebuild(vector, status=status))
    assert verdict.ok is False
    assert verdict.code.name == code


def test_current_verifier_rejects_invalid_authority_status_signature() -> None:
    vector = valid_vector()
    status = copy.deepcopy(vector.status)
    status["signature"]["signature_b64u"] = _b64u(bytes(64))
    assert (
        _current(_rebuild(vector, status=status)).code
        is FailureCode.AUTHORITY_STATUS_INVALID_SIGNATURE
    )


def test_current_verifier_rejects_noncanonical_actor_revocation_generation() -> None:
    vector = valid_vector()
    status = copy.deepcopy(vector.status)
    status["body"]["actor_revocation_generation"] = "03"
    status["signature"] = _signature(
        SEEDS["status"], DOMAINS["status"], _canonical(status["body"]), "status-key"
    )

    assert (
        _current(_rebuild(vector, status=status)).code
        is FailureCode.INVALID_DECIMAL_STRING
    )


def test_failure_code_enum_exactly_matches_apcc_v1_wire_contract() -> None:
    expected = {
        "MALFORMED_JSON",
        "DUPLICATE_FIELD",
        "UNKNOWN_FIELD",
        "MISSING_FIELD",
        "CASE_MISMATCHED_FIELD",
        "TRAILING_BYTES",
        "NONCANONICAL_ENCODING",
        "INVALID_UNICODE",
        "INVALID_BASE64URL",
        "SIZE_LIMIT_EXCEEDED",
        "DEPTH_LIMIT_EXCEEDED",
        "DUPLICATE_SET_MEMBER",
        "WRONG_JSON_TYPE",
        "INVALID_DECIMAL_STRING",
        "UNKNOWN_PROTOCOL_VERSION",
        "UNSUPPORTED_CERTIFICATE_TYPE",
        "UNSUPPORTED_ENCODING",
        "UNSUPPORTED_DIGEST_ALGORITHM",
        "UNSUPPORTED_SIGNATURE_ALGORITHM",
        "UNSUPPORTED_STATEMENT_TYPE",
        "STATEMENT_DIGEST_MISMATCH",
        "PROPOSAL_DIGEST_MISMATCH",
        "INVALID_PRODUCER_SIGNATURE",
        "INVALID_POLICY_SIGNATURE",
        "INVALID_AUTHORITY_SIGNATURE",
        "INVALID_COMMIT_SEAL",
        "UNKNOWN_KEY",
        "KEY_ID_MISMATCH",
        "ATTESTATION_EXPIRED",
        "ATTESTATION_NOT_YET_VALID",
        "SUBJECT_MISMATCH",
        "ACTOR_AUTHORITY_MISMATCH",
        "INPUT_DIGEST_MISMATCH",
        "OUTPUT_DIGEST_MISMATCH",
        "ATTEMPT_MISMATCH",
        "CROSS_WORKFLOW_REPLAY",
        "CROSS_NODE_REPLAY",
        "CROSS_ATTEMPT_REPLAY",
        "STALE_POLICY_EPOCH",
        "STALE_AUTHORITY_EPOCH",
        "STALE_WORKFLOW_EPOCH",
        "ACTOR_REVOKED",
        "WORKFLOW_REVOKED",
        "INVALID_PREDECESSOR",
        "PREDECESSOR_ROOT_MISMATCH",
        "PREDECESSOR_REPLACED",
        "CROSS_WORKFLOW_PREDECESSOR",
        "NODE_VERSION_CONFLICT",
        "ILLEGAL_NODE_STATE",
        "RESULT_NOT_STAGED",
        "STAGED_RESULT_CONFLICT",
        "QUARANTINED",
        "NONCE_REPLAY",
        "COMMIT_ID_EQUIVOCATION",
        "AUTHORITY_FROM_STAGING_DENIED",
        "AUTHORITY_FROM_RECOVERY_DENIED",
        "AUTHORITY_FROM_OUTBOX_DENIED",
        "LEGACY_STATUS_NOT_AUTHORITATIVE",
        "STORE_UNAVAILABLE",
        "TRANSACTION_ABORTED",
        "SERIALIZATION_RETRY_EXHAUSTED",
        "OUTBOX_DELIVERY_PENDING",
        "AUTHORITY_STATUS_REQUIRED",
        "AUTHORITY_STATUS_NONCE_MISMATCH",
        "AUTHORITY_STATUS_CERTIFICATE_MISMATCH",
        "AUTHORITY_STATUS_EXPIRED",
        "AUTHORITY_STATUS_INVALID_SIGNATURE",
        "AUTHORITY_STATUS_REVOKED",
        "AUTHORITY_STATUS_SUPERSEDED",
        "AUTHORITY_STATUS_ROLLBACK",
    }
    assert {code.name for code in FailureCode} == expected
