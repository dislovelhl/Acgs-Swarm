from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.test_apcc_verifier import (  # noqa: E402
    DOMAINS,
    FailureCode,
    SEEDS,
    _b64u,
    _canonical,
    _signature,
    valid_vector,
)

FIXTURES = ROOT / "tests/fixtures/apcc/v1"
GO_ROOT = ROOT / "verifiers/apcc-go"


def _write_fixtures() -> None:
    objects = FIXTURES / "objects"
    objects.mkdir(parents=True, exist_ok=True)

    for path in objects.iterdir():
        if path.is_file():
            path.unlink()

    def put(raw: bytes) -> str:
        name = hashlib.sha256(raw).hexdigest() + ".json"
        (objects / name).write_bytes(raw)
        return "objects/" + name

    def seal(payload: dict[str, object]) -> bytes:
        inner = _canonical(payload)
        return _canonical(
            {
                "envelope_type": "apcc.detached-certificate-envelope",
                "payload_b64u": _b64u(inner),
                "payload_sha256": _b64u(hashlib.sha256(inner).digest()),
                "seal": _signature(
                    SEEDS["commit"], DOMAINS["commit"], inner, "commit-key"
                ),
            }
        )

    vector = valid_vector()
    trust_value = {
        "protocol_version": "APCC-1.0-draft",
        "bindings": [
            {
                "role": item.role.value,
                "scope": list(item.scope),
                "key_id": item.key_id,
                "public_key_b64u": _b64u(item.public_key),
            }
            for item in vector.trust.bindings
        ],
    }
    trust = _canonical(trust_value)
    certificate_ref, trust_ref = put(vector.envelope), put(trust)
    status = _canonical(vector.status)
    inputs = {
        "request_nonce": vector.status["body"]["request_nonce"],
        "now_ms": "1760000001000",
        "highest_trust_log_sequence": "42",
        "highest_trust_log_head": vector.status["body"]["trust_log_head"],
        "maximum_staleness_ms": "5000",
    }

    generated_provenance = [
        "python-independent-constructor",
        "go-independent-verifier",
    ]
    hand_provenance = [
        "hand-authored-anchor",
        "python-independent-verifier",
        "go-independent-verifier",
    ]

    def historical(
        name: str,
        raw: bytes,
        code: str,
        *,
        trust_reference: str = trust_ref,
        vector_provenance: list[str] = generated_provenance,
    ) -> dict[str, object]:
        return {
            "name": name,
            "mode": "historical",
            "certificate": put(raw),
            "trust": trust_reference,
            "expected_code": code,
            "provenance": vector_provenance,
        }

    def current(
        name: str,
        raw_status: bytes | None,
        code: str,
        changes: dict[str, str] | None = None,
        *,
        certificate: str = certificate_ref,
        trust_reference: str = trust_ref,
    ) -> dict[str, object]:
        current_inputs = dict(inputs)
        current_inputs.update(changes or {})
        result: dict[str, object] = {
            "name": name,
            "mode": "current",
            "certificate": certificate,
            "trust": trust_reference,
            "current_inputs": current_inputs,
            "expected_code": code,
            "provenance": generated_provenance,
        }
        if raw_status is not None:
            result["authority_status"] = put(raw_status)
        return result

    def resign_all(payload: dict[str, object]) -> None:
        evidence = payload["evidence"]
        assert isinstance(evidence, dict)
        signatures = payload["signatures"]
        assert isinstance(signatures, dict)
        producer = evidence["producer_statement"]
        policy = evidence["policy_statement"]
        authority = evidence["authority_statement"]
        assert isinstance(producer, dict)
        assert isinstance(policy, dict)
        assert isinstance(authority, dict)
        proposal_digest = _b64u(hashlib.sha256(_canonical(producer)).digest())
        evidence["producer_statement_digest"] = proposal_digest
        policy["proposal_digest"] = proposal_digest
        authority["proposal_digest"] = proposal_digest
        evidence["policy_statement_digest"] = _b64u(
            hashlib.sha256(_canonical(policy)).digest()
        )
        evidence["authority_statement_digest"] = _b64u(
            hashlib.sha256(_canonical(authority)).digest()
        )
        signatures["producer"] = _signature(
            SEEDS["producer"], DOMAINS["producer"], _canonical(producer), "producer-key"
        )
        signatures["policy_authority"] = _signature(
            SEEDS["policy"], DOMAINS["policy"], _canonical(policy), "policy-key"
        )
        signatures["authority_registry"] = _signature(
            SEEDS["authority"],
            DOMAINS["authority"],
            _canonical(authority),
            "authority-key",
        )

    def payload_case(
        name: str,
        code: str,
        mutate: object,
        *,
        resign: bool = False,
        trust_reference: str = trust_ref,
    ) -> dict[str, object]:
        payload = copy.deepcopy(vector.payload)
        assert callable(mutate)
        mutate(payload)
        if resign:
            resign_all(payload)
        return historical(name, seal(payload), code, trust_reference=trust_reference)

    def status_case(
        name: str,
        code: str,
        mutate: object,
        *,
        resign: bool = True,
        changes: dict[str, str] | None = None,
        trust_reference: str = trust_ref,
    ) -> dict[str, object]:
        value = copy.deepcopy(vector.status)
        assert callable(mutate)
        mutate(value)
        if resign:
            value["signature"] = _signature(
                SEEDS["status"],
                DOMAINS["status"],
                _canonical(value["body"]),
                "status-key",
            )
        return current(
            name,
            _canonical(value),
            code,
            changes,
            trust_reference=trust_reference,
        )

    vectors = [
        historical("valid-historical", vector.envelope, "OK"),
        current("valid-current", status, "OK"),
    ]
    outer = json.loads(vector.envelope)
    tampered = copy.deepcopy(outer)
    signature = tampered["seal"]["signature_b64u"]
    tampered["seal"]["signature_b64u"] = (
        "A" if signature[0] != "A" else "B"
    ) + signature[1:]
    unknown = copy.deepcopy(outer)
    unknown["unexpected"] = "x"
    case_mismatch = copy.deepcopy(outer)
    case_mismatch["Envelope_type"] = case_mismatch.pop("envelope_type")
    missing = copy.deepcopy(outer)
    del missing["envelope_type"]
    invalid_b64 = copy.deepcopy(outer)
    invalid_b64["payload_sha256"] = "="
    vectors.extend(
        [
            historical(
                "tampered-commit-seal", _canonical(tampered), "INVALID_COMMIT_SEAL"
            ),
            historical("unknown-envelope-field", _canonical(unknown), "UNKNOWN_FIELD"),
            historical(
                "case-mismatched-envelope-field",
                _canonical(case_mismatch),
                "CASE_MISMATCHED_FIELD",
            ),
            historical("missing-envelope-field", _canonical(missing), "MISSING_FIELD"),
            historical(
                "duplicate-envelope-field",
                b'{"envelope_type":"apcc.detached-certificate-envelope",'
                + vector.envelope[1:],
                "DUPLICATE_FIELD",
            ),
            historical(
                "malformed-json",
                b'{"envelope_type":',
                "MALFORMED_JSON",
                vector_provenance=hand_provenance,
            ),
            historical("trailing-byte", vector.envelope + b"\n", "TRAILING_BYTES"),
            historical(
                "noncanonical-whitespace",
                json.dumps(outer, sort_keys=True).encode(),
                "NONCANONICAL_ENCODING",
            ),
            historical(
                "invalid-unicode", b'{"envelope_type":"\\ud800"}', "INVALID_UNICODE"
            ),
            historical(
                "invalid-base64url", _canonical(invalid_b64), "INVALID_BASE64URL"
            ),
            historical(
                "wrong-json-type",
                b'{"envelope_type":true}',
                "WRONG_JSON_TYPE",
                vector_provenance=hand_provenance,
            ),
            historical(
                "depth-limit",
                b"[" * 9 + b"]" * 9,
                "DEPTH_LIMIT_EXCEEDED",
                vector_provenance=hand_provenance,
            ),
            historical(
                "size-limit",
                b"x" * (((1024 * 1024 * 4 // 3) + 2048) + 1),
                "SIZE_LIMIT_EXCEEDED",
                vector_provenance=hand_provenance,
            ),
        ]
    )

    for literal_name, raw, top_code, nested_code in (
        ("true", b"truex", "TRAILING_BYTES", "MALFORMED_JSON"),
        ("false", b"falsex", "TRAILING_BYTES", "MALFORMED_JSON"),
        ("null", b"nullx", "TRAILING_BYTES", "MALFORMED_JSON"),
        ("number", b"1x", "WRONG_JSON_TYPE", "WRONG_JSON_TYPE"),
    ):
        vectors.append(
            historical(
                f"top-level-malformed-{literal_name}-delimiter",
                raw,
                top_code,
                vector_provenance=hand_provenance,
            )
        )
        vectors.append(
            historical(
                f"nested-malformed-{literal_name}-delimiter",
                b'{"a":' + raw + b"}",
                nested_code,
                vector_provenance=hand_provenance,
            )
        )
    for literal_name, raw in (
        ("true", b"true"),
        ("false", b"false"),
        ("null", b"null"),
        ("number", b"1"),
    ):
        vectors.append(
            historical(
                f"restricted-scalar-{literal_name}",
                raw,
                "WRONG_JSON_TYPE",
                vector_provenance=hand_provenance,
            )
        )

    vectors.extend(
        [
            payload_case(
                "unknown-protocol-version",
                "UNKNOWN_PROTOCOL_VERSION",
                lambda p: p["header"].__setitem__("protocol_version", "APCC-2"),
            ),
            payload_case(
                "unsupported-certificate-type",
                "UNSUPPORTED_CERTIFICATE_TYPE",
                lambda p: p["header"].__setitem__("certificate_type", "other"),
            ),
            payload_case(
                "unsupported-encoding",
                "UNSUPPORTED_ENCODING",
                lambda p: p["header"].__setitem__("encoding_profile", "JSON"),
            ),
            payload_case(
                "unsupported-digest-algorithm",
                "UNSUPPORTED_DIGEST_ALGORITHM",
                lambda p: p["header"].__setitem__("digest_algorithm", "SHA-512"),
            ),
            payload_case(
                "unsupported-signature-algorithm",
                "UNSUPPORTED_SIGNATURE_ALGORITHM",
                lambda p: p["header"].__setitem__("signature_algorithm", "other"),
            ),
            payload_case(
                "unsupported-statement-type",
                "UNSUPPORTED_STATEMENT_TYPE",
                lambda p: p["evidence"]["producer_statement"].__setitem__(
                    "statement_type", "other"
                ),
                resign=True,
            ),
            payload_case(
                "invalid-decimal-string",
                "INVALID_DECIMAL_STRING",
                lambda p: p["header"].__setitem__("certificate_sequence", "042"),
            ),
            payload_case(
                "noncanonical-generation",
                "INVALID_DECIMAL_STRING",
                lambda p: p["context"].__setitem__("agent_revocation_generation", "03"),
            ),
            payload_case(
                "illegal-node-state",
                "ILLEGAL_NODE_STATE",
                lambda p: p["decision"].__setitem__("outcome", "denied"),
            ),
            payload_case(
                "node-version-conflict",
                "NODE_VERSION_CONFLICT",
                lambda p: p["bindings"].__setitem__("committed_node_version", "9"),
            ),
        ]
    )

    duplicate_predecessor = copy.deepcopy(vector.payload)
    duplicate_predecessor["bindings"]["predecessors"].append(
        copy.deepcopy(duplicate_predecessor["bindings"]["predecessors"][0])
    )
    vectors.append(
        historical(
            "duplicate-predecessor", seal(duplicate_predecessor), "DUPLICATE_SET_MEMBER"
        )
    )
    payload = copy.deepcopy(vector.payload)
    payload["evidence"]["producer_statement_digest"] = _b64u(
        hashlib.sha256(b"wrong").digest()
    )
    vectors.append(
        historical(
            "statement-digest-mismatch", seal(payload), "STATEMENT_DIGEST_MISMATCH"
        )
    )

    proposal = copy.deepcopy(vector.payload)
    proposal["evidence"]["policy_statement"]["proposal_digest"] = _b64u(
        hashlib.sha256(b"wrong").digest()
    )
    proposal["evidence"]["policy_statement_digest"] = _b64u(
        hashlib.sha256(_canonical(proposal["evidence"]["policy_statement"])).digest()
    )
    proposal["signatures"]["policy_authority"] = _signature(
        SEEDS["policy"],
        DOMAINS["policy"],
        _canonical(proposal["evidence"]["policy_statement"]),
        "policy-key",
    )
    vectors.append(
        historical(
            "proposal-digest-mismatch", seal(proposal), "PROPOSAL_DIGEST_MISMATCH"
        )
    )

    for role, signature_name, code in (
        ("producer", "producer", "INVALID_PRODUCER_SIGNATURE"),
        ("policy", "policy_authority", "INVALID_POLICY_SIGNATURE"),
        ("authority", "authority_registry", "INVALID_AUTHORITY_SIGNATURE"),
    ):
        broken = copy.deepcopy(vector.payload)
        signature = broken["signatures"][signature_name]["signature_b64u"]
        broken["signatures"][signature_name]["signature_b64u"] = (
            "A" if signature[0] != "A" else "B"
        ) + signature[1:]
        vectors.append(historical(f"invalid-{role}-signature", seal(broken), code))

    missing_producer = copy.deepcopy(trust_value)
    missing_producer["bindings"] = [
        item for item in missing_producer["bindings"] if item["role"] != "producer"
    ]
    wrong_scope = copy.deepcopy(trust_value)
    next(item for item in wrong_scope["bindings"] if item["role"] == "producer")[
        "scope"
    ][0] = "agent-other"
    vectors.extend(
        [
            historical(
                "unknown-producer-key",
                vector.envelope,
                "UNKNOWN_KEY",
                trust_reference=put(_canonical(missing_producer)),
            ),
            historical(
                "producer-scope-mismatch",
                vector.envelope,
                "UNKNOWN_KEY",
                trust_reference=put(_canonical(wrong_scope)),
            ),
            payload_case(
                "signature-key-id-mismatch",
                "KEY_ID_MISMATCH",
                lambda p: p["signatures"]["producer"].__setitem__(
                    "key_id", "other-key"
                ),
            ),
        ]
    )

    binding_cases = [
        (
            "producer-agent-subject-mismatch",
            "SUBJECT_MISMATCH",
            lambda p: p["subject"].__setitem__("agent_id", "agent-other"),
            False,
        ),
        (
            "authority-agent-subject-mismatch",
            "SUBJECT_MISMATCH",
            lambda p: p["evidence"]["authority_statement"].__setitem__(
                "agent_id", "agent-other"
            ),
            True,
        ),
        (
            "policy-deny-subject-mismatch",
            "SUBJECT_MISMATCH",
            lambda p: p["evidence"]["policy_statement"].__setitem__("decision", "deny"),
            True,
        ),
        (
            "decision-commit-subject-mismatch",
            "SUBJECT_MISMATCH",
            lambda p: p["decision"].__setitem__("commit_id", "commit-other"),
            False,
        ),
        (
            "actor-authority-mismatch",
            "ACTOR_AUTHORITY_MISMATCH",
            lambda p: p["subject"].__setitem__("actor_authority", "authority:ns:other"),
            False,
        ),
        (
            "input-digest-mismatch",
            "INPUT_DIGEST_MISMATCH",
            lambda p: p["subject"].__setitem__(
                "input_digest", _b64u(hashlib.sha256(b"other").digest())
            ),
            False,
        ),
        (
            "output-digest-mismatch",
            "OUTPUT_DIGEST_MISMATCH",
            lambda p: p["subject"].__setitem__(
                "output_digest", _b64u(hashlib.sha256(b"other").digest())
            ),
            False,
        ),
        (
            "attempt-mismatch",
            "ATTEMPT_MISMATCH",
            lambda p: p["subject"].__setitem__("attempt_id", "attempt-other"),
            False,
        ),
        (
            "cross-workflow-replay",
            "CROSS_WORKFLOW_REPLAY",
            lambda p: p["subject"].__setitem__("workflow_id", "workflow-other"),
            False,
        ),
        (
            "cross-node-replay",
            "CROSS_NODE_REPLAY",
            lambda p: p["subject"].__setitem__("node_id", "node-other"),
            False,
        ),
        (
            "stale-policy-epoch",
            "STALE_POLICY_EPOCH",
            lambda p: p["context"].__setitem__("policy_epoch", "12"),
            False,
        ),
        (
            "stale-authority-epoch",
            "STALE_AUTHORITY_EPOCH",
            lambda p: p["context"].__setitem__("authority_epoch", "6"),
            False,
        ),
        (
            "stale-workflow-epoch",
            "STALE_WORKFLOW_EPOCH",
            lambda p: p["context"].__setitem__("workflow_epoch", "10"),
            False,
        ),
        (
            "actor-revoked",
            "ACTOR_REVOKED",
            lambda p: p["context"].__setitem__("agent_revocation_generation", "4"),
            False,
        ),
        (
            "workflow-revoked",
            "WORKFLOW_REVOKED",
            lambda p: p["context"].__setitem__("workflow_revocation_generation", "5"),
            False,
        ),
        (
            "predecessor-root-mismatch",
            "PREDECESSOR_ROOT_MISMATCH",
            lambda p: p["bindings"].__setitem__(
                "predecessor_root", _b64u(hashlib.sha256(b"wrong").digest())
            ),
            False,
        ),
    ]
    vectors.extend(
        payload_case(name, code, mutate, resign=resign)
        for name, code, mutate, resign in binding_cases
    )

    cross_predecessor = copy.deepcopy(vector.payload)
    cross_predecessor["bindings"]["predecessors"][0]["workflow_id"] = "workflow-other"
    cross_predecessor["bindings"]["predecessor_root"] = _b64u(
        hashlib.sha256(
            _canonical(cross_predecessor["bindings"]["predecessors"])
        ).digest()
    )
    cross_predecessor["evidence"]["producer_statement"]["predecessor_root"] = (
        cross_predecessor["bindings"]["predecessor_root"]
    )
    resign_all(cross_predecessor)
    vectors.append(
        historical(
            "cross-workflow-predecessor",
            seal(cross_predecessor),
            "CROSS_WORKFLOW_PREDECESSOR",
        )
    )

    for role, statement in (
        ("producer", "producer_statement"),
        ("policy", "policy_statement"),
        ("authority", "authority_statement"),
    ):
        vectors.append(
            payload_case(
                f"{role}-attestation-not-yet-valid",
                "ATTESTATION_NOT_YET_VALID",
                lambda p, s=statement: p["evidence"][s].__setitem__(
                    "issued_at_ms", "1760000002000"
                ),
                resign=True,
            )
        )
        vectors.append(
            payload_case(
                f"{role}-attestation-expired",
                "ATTESTATION_EXPIRED",
                lambda p, s=statement: p["evidence"][s].__setitem__(
                    "expires_at_ms", "1760000000500"
                ),
                resign=True,
            )
        )
    vectors.extend(
        [
            current("authority-status-required", None, "AUTHORITY_STATUS_REQUIRED"),
            status_case(
                "tampered-status-signature",
                "AUTHORITY_STATUS_INVALID_SIGNATURE",
                lambda s: s["signature"].__setitem__(
                    "signature_b64u",
                    ("A" if s["signature"]["signature_b64u"][0] != "A" else "B")
                    + s["signature"]["signature_b64u"][1:],
                ),
                resign=False,
            ),
            current(
                "nonce-mismatch",
                status,
                "AUTHORITY_STATUS_NONCE_MISMATCH",
                {"request_nonce": _b64u(bytes(range(1, 17)))},
            ),
            status_case(
                "status-store-mismatch",
                "AUTHORITY_STATUS_CERTIFICATE_MISMATCH",
                lambda s: s["body"].__setitem__("authority_store_id", "store-other"),
            ),
            status_case(
                "status-certificate-digest-mismatch",
                "AUTHORITY_STATUS_CERTIFICATE_MISMATCH",
                lambda s: s["body"].__setitem__(
                    "certificate_digest", _b64u(hashlib.sha256(b"other").digest())
                ),
            ),
            status_case(
                "status-certificate-sequence-mismatch",
                "AUTHORITY_STATUS_CERTIFICATE_MISMATCH",
                lambda s: s["body"].__setitem__("certificate_sequence", "43"),
            ),
            status_case(
                "status-actor-revoked",
                "ACTOR_REVOKED",
                lambda s: s["body"].__setitem__("actor_revocation_generation", "4"),
            ),
            status_case(
                "status-workflow-revoked",
                "WORKFLOW_REVOKED",
                lambda s: s["body"].__setitem__("workflow_revocation_generation", "5"),
            ),
            status_case(
                "status-not-yet-valid",
                "ATTESTATION_NOT_YET_VALID",
                lambda s: (
                    s["body"].__setitem__("this_update_ms", "1760000002000"),
                    s["body"].__setitem__("next_update_ms", "1760000005000"),
                ),
            ),
            status_case(
                "status-expired",
                "AUTHORITY_STATUS_EXPIRED",
                lambda s: s["body"].__setitem__("next_update_ms", "1760000000500"),
            ),
            current(
                "status-staleness-expired",
                status,
                "AUTHORITY_STATUS_EXPIRED",
                {"maximum_staleness_ms": "500"},
            ),
            current(
                "trust-log-rollback",
                status,
                "AUTHORITY_STATUS_ROLLBACK",
                {"highest_trust_log_sequence": "43"},
            ),
            current(
                "same-sequence-different-head",
                status,
                "AUTHORITY_STATUS_ROLLBACK",
                {
                    "highest_trust_log_head": _b64u(
                        hashlib.sha256(b"other-head").digest()
                    )
                },
            ),
            status_case(
                "status-revoked",
                "AUTHORITY_STATUS_REVOKED",
                lambda s: s["body"].__setitem__("status", "revoked"),
            ),
            status_case(
                "status-unknown-literal",
                "AUTHORITY_STATUS_REVOKED",
                lambda s: s["body"].__setitem__("status", "CURRENT"),
            ),
            status_case(
                "status-superseded",
                "AUTHORITY_STATUS_SUPERSEDED",
                lambda s: s["body"].__setitem__("superseded", "yes"),
            ),
            status_case(
                "status-unknown-superseded-literal",
                "AUTHORITY_STATUS_SUPERSEDED",
                lambda s: s["body"].__setitem__("superseded", "maybe"),
            ),
            current(
                "noncanonical-staleness",
                status,
                "INVALID_DECIMAL_STRING",
                {"maximum_staleness_ms": "05000"},
            ),
        ]
    )

    unreachable = [
        "CROSS_ATTEMPT_REPLAY",
        "INVALID_PREDECESSOR",
        "PREDECESSOR_REPLACED",
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
    ]
    reachable = sorted({code.value for code in FailureCode} - set(unreachable))
    manifest = {
        "protocol_version": "APCC-1.0-draft",
        "content_address_algorithm": "SHA-256",
        "provenance_policy": (
            "Every vector names its byte origin and is evaluated by both independent "
            "implementations."
        ),
        "verifier_reachable_failure_codes": reachable,
        "intentionally_unreachable_store_only_codes": unreachable,
        "vectors": vectors,
    }
    (FIXTURES / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


def test_fixture_manifest_is_content_addressed_and_has_three_origin_anchors() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_bytes())
    reachable = set(manifest["verifier_reachable_failure_codes"])
    unreachable = set(manifest["intentionally_unreachable_store_only_codes"])
    all_codes = {code.value for code in FailureCode}
    assert reachable.isdisjoint(unreachable)
    assert reachable | unreachable == all_codes
    assert {vector["expected_code"] for vector in manifest["vectors"]} == {
        "OK",
        *reachable,
    }

    referenced_objects: set[str] = set()
    corpus_provenance: set[str] = set()
    for vector in manifest["vectors"]:
        vector_provenance = set(vector["provenance"])
        corpus_provenance.update(vector_provenance)
        assert "go-independent-verifier" in vector_provenance
        assert vector_provenance & {
            "python-independent-constructor",
            "hand-authored-anchor",
        }
        references = [vector["certificate"], vector["trust"]]
        if vector.get("authority_status"):
            references.append(vector["authority_status"])
        for reference in references:
            referenced_objects.add(reference)
            raw = (FIXTURES / reference).read_bytes()
            assert Path(reference).stem == hashlib.sha256(raw).hexdigest()

    actual_objects = {
        path.relative_to(FIXTURES).as_posix()
        for path in (FIXTURES / "objects").iterdir()
        if path.is_file()
    }
    assert referenced_objects == actual_objects
    assert corpus_provenance == {
        "hand-authored-anchor",
        "python-independent-constructor",
        "python-independent-verifier",
        "go-independent-verifier",
    }


def _build(binary: Path) -> None:
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/apcc-verify"],
        cwd=GO_ROOT,
        check=True,
    )


def test_go_cli_requires_maximum_staleness_and_emits_exact_result_schema(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "apcc-verify"
    _build(binary)
    manifest = json.loads((FIXTURES / "manifest.json").read_bytes())
    vector = next(
        item for item in manifest["vectors"] if item["name"] == "valid-current"
    )
    inputs = vector["current_inputs"]
    completed = subprocess.run(
        [
            str(binary),
            "current",
            "--certificate",
            str(FIXTURES / vector["certificate"]),
            "--trust",
            str(FIXTURES / vector["trust"]),
            "--authority-status",
            str(FIXTURES / vector["authority_status"]),
            "--request-nonce",
            inputs["request_nonce"],
            "--now-ms",
            inputs["now_ms"],
            "--highest-trust-log-sequence",
            inputs["highest_trust_log_sequence"],
            "--highest-trust-log-head",
            inputs["highest_trust_log_head"],
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert json.loads(completed.stdout) == {
        "certificate_digest": "",
        "code": "CLI_ERROR",
        "mode": "current",
        "ok": False,
        "protocol_version": "APCC-1.0-draft",
    }


def test_python_go_differential_manifest(tmp_path: Path) -> None:
    binary = tmp_path / "apcc-verify"
    _build(binary)
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/check_apcc_differential.py",
            "--go-binary",
            str(binary),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("APCC differential PASS")


if __name__ == "__main__":
    _write_fixtures()
