"""Canonical protocol encoders for the future Rust core boundary.

The mesh still accepts the historical Python byte formats for compatibility.
This module makes that explicit by keeping legacy encoders separate from the
versioned, domain-separated encoders that a Rust implementation must target.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any

from constitutional_swarm.mesh import MeshProof, RemoteVoteRequest, ValidationVote
from constitutional_swarm.settlement_store import SettlementRecord

PROTOCOL_VERSION = 1
MESH_HASH_HEX_LENGTH = 32

DOMAIN_CONTENT = "content"
DOMAIN_MESH_PROOF = "mesh-proof"
DOMAIN_REMOTE_VOTE_REQUEST = "remote-vote-request"
DOMAIN_SETTLEMENT_RECORD = "settlement-record"
DOMAIN_SPECTRAL_SPHERE_SNAPSHOT = "spectral-sphere-snapshot"
DOMAIN_VOTE_PAYLOAD = "vote-payload"


def canonical_timestamp(timestamp: float) -> str:
    """Return the protocol timestamp spelling used in signed payloads."""
    return format(float(timestamp), ".17g")


def canonical_json_bytes(domain: str, payload: dict[str, Any], *, version: int = 1) -> bytes:
    """Encode a protocol payload as domain-separated canonical JSON bytes."""
    envelope = {
        "domain": domain,
        "payload": _normalize(payload),
        "version": version,
    }
    body = json.dumps(
        envelope,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"constitutional-swarm/{domain}/v{version}\n{body}".encode()


def protocol_sha256_hex(data: bytes, *, truncate: int | None = None) -> str:
    """Hash protocol bytes with SHA-256 and optionally return a hex prefix."""
    digest = hashlib.sha256(data).hexdigest()
    return digest if truncate is None else digest[:truncate]


def legacy_content_hash(content: str) -> str:
    """Current Python mesh content hash; retained as a compatibility fixture."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:MESH_HASH_HEX_LENGTH]


def canonical_content_hash(content: str) -> str:
    """Versioned content hash for Rust-core fixtures."""
    return protocol_sha256_hex(
        canonical_json_bytes(DOMAIN_CONTENT, {"content": content}),
        truncate=MESH_HASH_HEX_LENGTH,
    )


def legacy_vote_payload_bytes(
    *,
    assignment_id: str,
    voter_id: str,
    approved: bool,
    reason: str,
    constitutional_hash: str,
    content_hash: str,
) -> bytes:
    """Historical colon-joined vote payload used by ``ConstitutionalMesh``."""
    payload = f"{assignment_id}:{voter_id}:{approved}:{reason}:{constitutional_hash}:{content_hash}"
    return payload.encode("utf-8")


def encode_vote_payload_v1(
    *,
    assignment_id: str,
    voter_id: str,
    approved: bool,
    reason: str,
    constitutional_hash: str,
    content_hash: str,
) -> bytes:
    return canonical_json_bytes(
        DOMAIN_VOTE_PAYLOAD,
        {
            "approved": approved,
            "assignment_id": assignment_id,
            "constitutional_hash": constitutional_hash,
            "content_hash": content_hash,
            "reason": reason,
            "voter_id": voter_id,
        },
    )


def legacy_vote_hash(vote: ValidationVote) -> str:
    """Historical validation-vote hash, including the detached signature."""
    payload = (
        f"{vote.assignment_id}:{vote.voter_id}:{vote.approved}"
        f":{vote.reason}:{vote.signature}:{vote.constitutional_hash}:{vote.content_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:MESH_HASH_HEX_LENGTH]


def legacy_remote_vote_request_payload_bytes(
    *,
    assignment_id: str,
    voter_id: str,
    producer_id: str,
    artifact_id: str,
    content: str,
    content_hash: str,
    constitutional_hash: str,
    voter_public_key: str,
    nonce: str,
    timestamp: float,
) -> bytes:
    """Historical colon-joined remote request payload used for signatures."""
    payload = (
        f"{assignment_id}:{voter_id}:{producer_id}:{artifact_id}:"
        f"{content}:{content_hash}:{constitutional_hash}:{voter_public_key}:"
        f"{nonce}:{canonical_timestamp(timestamp)}"
    )
    return payload.encode("utf-8")


def encode_remote_vote_request_signing_payload_v1(request: RemoteVoteRequest) -> bytes:
    return canonical_json_bytes(
        DOMAIN_REMOTE_VOTE_REQUEST,
        {
            "artifact_id": request.artifact_id,
            "assignment_id": request.assignment_id,
            "constitutional_hash": request.constitutional_hash,
            "content": request.content,
            "content_hash": request.content_hash,
            "nonce": request.nonce,
            "producer_id": request.producer_id,
            "timestamp": canonical_timestamp(request.timestamp),
            "voter_id": request.voter_id,
            "voter_public_key": request.voter_public_key,
        },
    )


def encode_remote_vote_request_payload_v1(request: RemoteVoteRequest) -> bytes:
    """Encode the complete remote-vote request envelope.

    Use ``encode_remote_vote_request_signing_payload_v1`` for detached signature
    input. The complete envelope intentionally includes the signer public key
    and signature after they have been produced.
    """
    return canonical_json_bytes(
        DOMAIN_REMOTE_VOTE_REQUEST,
        {
            "artifact_id": request.artifact_id,
            "assignment_id": request.assignment_id,
            "constitutional_hash": request.constitutional_hash,
            "content": request.content,
            "content_hash": request.content_hash,
            "nonce": request.nonce,
            "producer_id": request.producer_id,
            "request_signature": request.request_signature,
            "request_signer_public_key": request.request_signer_public_key,
            "timestamp": canonical_timestamp(request.timestamp),
            "voter_id": request.voter_id,
            "voter_public_key": request.voter_public_key,
        },
    )


def encode_mesh_proof_v1(proof: MeshProof) -> bytes:
    return canonical_json_bytes(
        DOMAIN_MESH_PROOF,
        {
            "accepted": proof.accepted,
            "assignment_id": proof.assignment_id,
            "constitutional_hash": proof.constitutional_hash,
            "content_hash": proof.content_hash,
            "root_hash": proof.root_hash,
            "timestamp": canonical_timestamp(proof.timestamp),
            "vote_hashes": list(proof.vote_hashes),
        },
    )


def encode_settlement_record_v1(record: SettlementRecord) -> bytes:
    return canonical_json_bytes(
        DOMAIN_SETTLEMENT_RECORD,
        {
            "assignment": record.assignment,
            "constitutional_hash": record.constitutional_hash,
            "is_recovered": record.is_recovered,
            "result": record.result,
            "schema_version": record.schema_version,
        },
    )


def encode_spectral_sphere_snapshot_v1(snapshot: dict[str, Any]) -> bytes:
    return canonical_json_bytes(DOMAIN_SPECTRAL_SPHERE_SNAPSHOT, snapshot)


def _normalize(value: Any) -> Any:
    if is_dataclass(value):
        return _normalize(asdict(value))
    if isinstance(value, dict):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, float):
        return canonical_timestamp(value)
    return value


__all__ = [
    "DOMAIN_CONTENT",
    "DOMAIN_MESH_PROOF",
    "DOMAIN_REMOTE_VOTE_REQUEST",
    "DOMAIN_SETTLEMENT_RECORD",
    "DOMAIN_SPECTRAL_SPHERE_SNAPSHOT",
    "DOMAIN_VOTE_PAYLOAD",
    "MESH_HASH_HEX_LENGTH",
    "PROTOCOL_VERSION",
    "canonical_content_hash",
    "canonical_json_bytes",
    "canonical_timestamp",
    "encode_mesh_proof_v1",
    "encode_remote_vote_request_payload_v1",
    "encode_remote_vote_request_signing_payload_v1",
    "encode_settlement_record_v1",
    "encode_spectral_sphere_snapshot_v1",
    "encode_vote_payload_v1",
    "legacy_content_hash",
    "legacy_remote_vote_request_payload_bytes",
    "legacy_vote_hash",
    "legacy_vote_payload_bytes",
    "protocol_sha256_hex",
]
