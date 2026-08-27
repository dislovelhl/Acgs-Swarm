from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, is_dataclass

import pytest

from constitutional_swarm.apcc.model import (
    AuthorityStatus,
    CandidateLifecycle,
    CandidateState,
    CertificateDisposition,
    CommitCertificate,
    CommitDecision,
    LogicalNodeState,
    RequestOutcome,
)
from constitutional_swarm.apcc.codec import decode_envelope
from constitutional_swarm.apcc.ports import CommitResult
from tests.test_apcc_verifier import _digest, valid_vector


def _certificate() -> CommitCertificate:
    return CommitCertificate.from_object(valid_vector().payload)


@pytest.mark.parametrize(
    "record",
    (
        _certificate(),
        _certificate().header,
        _certificate().subject,
        _certificate().context,
        _certificate().evidence,
        _certificate().decision,
        _certificate().bindings,
        _certificate().signatures,
    ),
)
def test_certificate_models_are_frozen_typed_records(record: object) -> None:
    assert is_dataclass(record)
    with pytest.raises(FrozenInstanceError):
        setattr(record, fields(record)[0].name, "tampered")


def test_certificate_has_exact_seven_objects_and_full_embedded_statement_bodies() -> (
    None
):
    certificate = _certificate()
    assert set(certificate.to_object()) == {
        "header",
        "subject",
        "context",
        "evidence",
        "decision",
        "bindings",
        "signatures",
    }
    for name, statement_type in (
        ("producer_statement", "apcc.producer-statement"),
        ("policy_statement", "apcc.policy-statement"),
        ("authority_statement", "apcc.authority-statement"),
    ):
        body = getattr(certificate.evidence, name)
        assert body["protocol_version"] == "APCC-1.0-draft"
        assert body["statement_type"] == statement_type
        assert "additional" not in body


def test_signature_objects_exclude_public_keys_and_status_binds_actual_certificate_digest() -> (
    None
):
    vector = valid_vector()
    certificate = _certificate()
    status = AuthorityStatus.from_object(vector.status)
    assert set(certificate.signatures.producer.to_object()) == {
        "algorithm",
        "key_id",
        "signature_b64u",
    }
    assert status.request_nonce == vector.status["body"]["request_nonce"]
    assert status.certificate_digest == vector.status["body"]["certificate_digest"]
    assert status.status == "current"


def test_candidate_logical_disposition_and_request_decision_are_distinct() -> None:
    candidate = CandidateState("workflow-1", "node-1", "attempt-1", "COMMIT_PENDING")
    logical = LogicalNodeState("workflow-1", "node-1", "0", None)
    disposition = CertificateDisposition.CURRENT
    decision = CommitDecision("commit-1", "DENIED", "SUBJECT_MISMATCH")
    assert len({type(candidate), type(logical), type(disposition), type(decision)}) == 4


def test_request_outcomes_do_not_turn_exact_replay_into_a_new_decision() -> None:
    """Replay is response metadata, never a fourth immutable decision outcome."""
    assert set(RequestOutcome) == {
        RequestOutcome.COMMITTED,
        RequestOutcome.DENIED,
        RequestOutcome.CONFLICTED,
    }


@pytest.mark.parametrize(
    "non_candidate_lifecycle",
    ("AUTHORITATIVE_COMMITTED", "REVOKED", "SUPERSEDED", "DENIED", "CONFLICTED"),
)
def test_authority_dispositions_and_decisions_cannot_be_candidate_lifecycle(
    non_candidate_lifecycle: str,
) -> None:
    with pytest.raises(ValueError):
        CandidateLifecycle(non_candidate_lifecycle)
    with pytest.raises(ValueError):
        CandidateState("workflow-1", "node-1", "attempt-1", non_candidate_lifecycle)


@pytest.mark.parametrize(
    ("current_node_version", "current_certificate_digest"),
    (
        ("0", "A" * 43),
        ("1", None),
        ("-1", None),
        ("not-a-decimal", None),
    ),
)
def test_logical_node_version_and_certificate_pointer_pairing_is_strict(
    current_node_version: str, current_certificate_digest: str | None
) -> None:
    with pytest.raises(ValueError):
        LogicalNodeState(
            "workflow-1",
            "node-1",
            current_node_version,
            current_certificate_digest,
        )


def test_logical_node_initial_and_committed_pointer_pairings_are_valid() -> None:
    initial = LogicalNodeState("workflow-1", "node-1", "0", None)
    committed = LogicalNodeState("workflow-1", "node-1", "1", "A" * 43)
    assert initial.current_certificate_digest is None
    assert committed.current_certificate_digest == "A" * 43
    assert set(CertificateDisposition) == {
        CertificateDisposition.CURRENT,
        CertificateDisposition.REVOKED,
        CertificateDisposition.SUPERSEDED,
    }


@pytest.mark.parametrize(
    ("path", "invalid_value"),
    (
        (("header", "protocol_version"), "APCC-0.9"),
        (("header", "certificate_type"), "apcc.other-certificate"),
        (("header", "encoding_profile"), "JSON"),
        (("header", "digest_algorithm"), "SHA-1"),
        (("header", "signature_algorithm"), "RSA"),
    ),
)
def test_certificate_model_rejects_unsupported_declared_wire_values(
    path: tuple[str, str], invalid_value: str
) -> None:
    payload = copy.deepcopy(valid_vector().payload)
    payload[path[0]][path[1]] = invalid_value
    with pytest.raises(ValueError):
        CommitCertificate.from_object(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("protocol_version", "APCC-0.9"),
        ("statement_type", "apcc.legacy-status"),
        ("status", "pending"),
        ("superseded", "maybe"),
    ),
)
def test_authority_status_model_rejects_invalid_disposition_values(
    field: str, invalid_value: str
) -> None:
    status = copy.deepcopy(valid_vector().status)
    status["body"][field] = invalid_value
    with pytest.raises(ValueError):
        AuthorityStatus.from_object(status)


@pytest.mark.parametrize(
    ("constructor", "object_name"),
    (
        (CommitCertificate.from_object, "certificate"),
        (AuthorityStatus.from_object, "status"),
    ),
)
def test_model_from_object_rejects_missing_and_unknown_top_level_keys(
    constructor: object, object_name: str
) -> None:
    source = (
        valid_vector().payload
        if object_name == "certificate"
        else valid_vector().status
    )
    missing = copy.deepcopy(source)
    del missing["header" if object_name == "certificate" else "signature"]
    unknown = copy.deepcopy(source)
    unknown["unexpected"] = "value"
    for candidate in (missing, unknown):
        with pytest.raises(ValueError):
            constructor(candidate)  # type: ignore[operator]


def test_commit_result_keeps_payload_and_envelope_bytes_distinct() -> None:
    vector = valid_vector()
    detached = decode_envelope(vector.envelope)
    certificate_payload_bytes = detached.payload
    certificate_envelope_bytes = vector.envelope
    certificate_digest = _digest(certificate_payload_bytes)
    decision = CommitDecision("commit-1", "COMMITTED", "ACCEPTED")
    result = CommitResult(
        decision=decision,
        certificate_payload_bytes=certificate_payload_bytes,
        certificate_envelope_bytes=certificate_envelope_bytes,
        certificate_digest=certificate_digest,
        audit_event_id="audit-1",
    )
    assert (
        result.decision,
        result.certificate_payload_bytes,
        result.certificate_envelope_bytes,
        result.certificate_digest,
        result.audit_event_id,
    ) == (
        decision,
        certificate_payload_bytes,
        certificate_envelope_bytes,
        certificate_digest,
        "audit-1",
    )
    assert result.certificate_digest == _digest(result.certificate_payload_bytes)
    decoded = decode_envelope(result.certificate_envelope_bytes)
    assert decoded.payload == result.certificate_payload_bytes
    assert decoded.payload_sha256 == result.certificate_digest

    with pytest.raises(ValueError):
        CommitResult(
            decision=decision,
            certificate_payload_bytes=certificate_payload_bytes,
            certificate_envelope_bytes=certificate_envelope_bytes,
            certificate_digest="A" * 43,
            audit_event_id="audit-1",
        )
