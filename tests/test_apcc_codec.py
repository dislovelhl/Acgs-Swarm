from __future__ import annotations

import json

import pytest

from constitutional_swarm.apcc.codec import (
    CodecError,
    decode_certificate,
    decode_envelope,
    encode_certificate,
    encode_payload,
)
from tests.test_apcc_model import _certificate
from tests.test_apcc_verifier import valid_vector


def test_cj1_inner_payload_is_exactly_seven_objects_and_canonical() -> None:
    encoded = encode_certificate(_certificate())
    decoded = decode_certificate(encoded)

    assert encode_certificate(decoded) == encoded
    assert set(json.loads(encoded)) == {
        "bindings",
        "context",
        "decision",
        "evidence",
        "header",
        "signatures",
        "subject",
    }
    assert b"\n" not in encoded
    assert json.loads(encoded)["decision"]["outcome"] == "committed"


def test_outer_envelope_is_exact_and_detached() -> None:
    vector = valid_vector()
    encoded = vector.envelope
    object_value = json.loads(encoded)

    assert set(object_value) == {
        "envelope_type",
        "payload_b64u",
        "payload_sha256",
        "seal",
    }
    assert object_value["envelope_type"] == "apcc.detached-certificate-envelope"
    assert object_value["payload_sha256"] == vector.status["body"]["certificate_digest"]
    assert set(object_value["seal"]) == {"algorithm", "key_id", "signature_b64u"}
    assert decode_envelope(encoded).payload == encode_certificate(_certificate())


def test_decoded_envelope_separates_exact_payload_from_its_wire_wrapper() -> None:
    vector = valid_vector()
    detached = decode_envelope(vector.envelope)
    assert detached.payload == json.dumps(
        vector.payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert detached.payload_sha256 == vector.status["body"]["certificate_digest"]
    assert detached.payload != vector.envelope


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        (b'{"header":{},"header":{}}', "DUPLICATE_FIELD"),
        (b'{"Header":{}}', "CASE_MISMATCHED_FIELD"),
        (b'{"additional":"x"}', "UNKNOWN_FIELD"),
        (b'{"header":true}', "WRONG_JSON_TYPE"),
        (b'{"header":null}', "WRONG_JSON_TYPE"),
        (b'{"header":1}', "WRONG_JSON_TYPE"),
        (b'{"header":{}} ', "TRAILING_BYTES"),
        (b'{"header":"\\ud800"}', "INVALID_UNICODE"),
    ),
)
def test_cj1_rejects_malleable_types_and_keys(raw: bytes, code: str) -> None:
    with pytest.raises(CodecError) as raised:
        decode_certificate(raw)
    assert raised.value.code.name == code


def test_cj1_rejects_noncanonical_encoding_and_bad_fixed_width_values() -> None:
    canonical = encode_certificate(_certificate())
    digest = valid_vector().payload["subject"]["input_digest"].encode()
    nonce = valid_vector().payload["decision"]["nonce"].encode()
    malformed_digest = canonical.replace(digest, digest[:-1], 1)
    malformed_nonce = canonical.replace(nonce, nonce[:-1], 1)
    bad_timestamp = canonical.replace(b'"1760000000000"', b'"01760000000000"', 1)
    reordered = json.dumps(
        dict(reversed(list(json.loads(canonical).items()))), separators=(",", ":")
    ).encode()

    for raw, code in (
        (malformed_digest, "INVALID_BASE64URL"),
        (malformed_nonce, "INVALID_BASE64URL"),
        (bad_timestamp, "INVALID_DECIMAL_STRING"),
        (reordered, "NONCANONICAL_ENCODING"),
    ):
        with pytest.raises(CodecError) as raised:
            decode_certificate(raw)
        assert raised.value.code.name == code


def test_cj1_rejects_extreme_nesting_before_recursive_json_decode() -> None:
    raw = b"[" * 100_000 + b"]" * 100_000

    with pytest.raises(CodecError) as raised:
        decode_certificate(raw)

    assert raised.value.code.name == "DEPTH_LIMIT_EXCEEDED"


@pytest.mark.parametrize("key", ("\ue000", "\U00010000"))
def test_cj1_generic_encoder_rejects_non_ascii_property_names(key: str) -> None:
    with pytest.raises(CodecError) as raised:
        encode_payload({key: "value"})

    assert raised.value.code.name == "UNKNOWN_FIELD"
