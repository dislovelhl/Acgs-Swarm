"""Supervisor-only configuration for the isolated APCC authority observer."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import encode_payload
from constitutional_swarm.apcc.crypto import b64u_decode, b64u_encode, sha256_digest
from constitutional_swarm.apcc.observation import CONTROLLER_LAUNCH_DOMAIN


@dataclass(frozen=True, slots=True)
class ControllerKeySourceRef:
    """Opaque supervisor-held controller key source and out-of-band public pin."""

    location: str
    expected_public_key: bytes

    def __post_init__(self) -> None:
        if not self.location or len(self.expected_public_key) != 32:
            raise ValueError("invalid observer controller key source")


@dataclass(frozen=True, slots=True)
class AuthorityObserverLaunchConfig:
    """Explicit publishable-evidence launch binding; there are no defaults."""

    experiment_id: str
    run_id: str
    authority_store_id: str
    backend_kind: str
    backend_instance: str
    backend_schema: str | None
    controller_key_id: str
    controller_key_source: ControllerKeySourceRef

    def __post_init__(self) -> None:
        from constitutional_swarm.apcc.codec import _IDENTIFIER

        for field_name in ("experiment_id", "run_id", "authority_store_id"):
            value = getattr(self, field_name)
            if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"invalid {field_name}")
        if self.backend_kind not in {"sqlite", "postgresql"}:
            raise ValueError("invalid observer backend kind")
        if not self.backend_instance:
            raise ValueError("invalid observer backend instance")
        if self.backend_kind == "sqlite" and self.backend_schema is not None:
            raise ValueError("SQLite observer launch cannot include a schema")
        if self.backend_kind == "postgresql" and not self.backend_schema:
            raise ValueError("PostgreSQL observer launch requires a schema")
        if self.controller_key_id != sha256_digest(
            self.controller_key_source.expected_public_key
        ):
            raise ValueError("controller key id/public key mismatch")


def _decode_controller_key(
    raw: bytes | bytearray, reference: ControllerKeySourceRef
) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(
        b64u_decode(bytes(raw).decode("ascii").strip(), expected_length=32)
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != reference.expected_public_key:
        raise PermissionError("observer controller identity mismatch")
    return key


_LAUNCH_CANDIDATE_FIELDS = {
    "protocol_version",
    "statement_type",
    "experiment_id",
    "run_id",
    "authority_store_id",
    "backend_kind",
    "backend_instance_digest",
    "schema_version",
    "schema_fingerprint",
    "status_key_id",
    "not_before_ms",
    "not_after_ms",
    "observer_pid",
    "launch_nonce",
    "session_id",
    "observer_key_id",
    "observer_public_key",
    "initial_trust_sequence",
    "initial_trust_head",
}


def controller_signer_child_main(
    reference: ControllerKeySourceRef, channel: Any
) -> None:
    """Harden, receive one key, and sign exactly one launch candidate."""
    from constitutional_swarm.authority_isolation import (
        erase_secret,
        harden_current_process,
    )
    from constitutional_swarm.authority_ipc import canonical_json

    try:
        harden_current_process()
        channel.send({"stage": "HARDENED_READY", "pid": os.getpid(), "dumpable": 0})
        secret = bytearray(channel.recv_bytes(257))
        try:
            key = _decode_controller_key(secret, reference)
        finally:
            erase_secret(secret)
        channel.send(
            {
                "stage": "TCB_READY",
                "pid": os.getpid(),
                "controller_key_id": sha256_digest(reference.expected_public_key),
            }
        )
        raw_candidate = channel.recv_bytes(16_385)
        candidate = json.loads(raw_candidate, object_pairs_hook=_reject_duplicate_keys)
        if (
            type(candidate) is not dict
            or set(candidate) != _LAUNCH_CANDIDATE_FIELDS
            or any(type(value) is not str for value in candidate.values())
            or candidate["protocol_version"] != "APCC-1.0-draft"
            or candidate["statement_type"] != "apcc.observer-launch-attestation"
        ):
            raise ValueError("invalid controller launch candidate")
        signed = sign_launch_candidate(
            candidate, key, sha256_digest(reference.expected_public_key)
        )
        channel.send_bytes(canonical_json(signed))
    except EOFError:
        return
    except BaseException as error:
        try:
            channel.send({"startup_error": type(error).__name__})
        except (BrokenPipeError, OSError):
            pass
        raise
    finally:
        channel.close()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate controller launch candidate key")
        result[key] = value
    return result


def sign_launch_candidate(
    candidate: dict[str, object], key: Ed25519PrivateKey, key_id: str
) -> dict[str, object]:
    """Sign one exact child candidate under the controller-only launch domain."""
    body = encode_payload(candidate)
    return {
        **candidate,
        "controller_key_id": key_id,
        "controller_signature": b64u_encode(
            key.sign(CONTROLLER_LAUNCH_DOMAIN + b"\x00" + body)
        ),
    }
