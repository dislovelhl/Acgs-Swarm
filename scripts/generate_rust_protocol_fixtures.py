#!/usr/bin/env python3
"""Generate deterministic protocol fixtures for a future Rust core."""

from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from constitutional_swarm import AgentDNA, RemoteVoteReplayError
from constitutional_swarm.mesh import MeshProof, RemoteVoteRequest, ValidationVote
from constitutional_swarm.mesh.core import ConstitutionalMesh
from constitutional_swarm.mesh.settlement import _compute_merkle_root
from constitutional_swarm.protocol import (
    canonical_content_hash,
    canonical_timestamp,
    encode_mesh_proof_v1,
    encode_remote_vote_request_payload_v1,
    encode_remote_vote_request_signing_payload_v1,
    encode_settlement_record_v1,
    encode_spectral_sphere_snapshot_v1,
    encode_vote_payload_v1,
    legacy_content_hash,
    legacy_remote_vote_request_payload_bytes,
    protocol_sha256_hex,
)
from constitutional_swarm.settlement_store import JSONLSettlementStore, SettlementRecord
from constitutional_swarm.spectral_sphere import SpectralSphereManifold
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution

DEFAULT_OUTPUT_DIR = REPO_ROOT / "tests" / "fixtures" / "rust_protocol"

ASSIGNMENT_ID = "assign-rust01"
PRODUCER_ID = "producer-alpha"
VOTER_ID = "validator-beta"
ARTIFACT_ID = "artifact-policy-001"
CONTENT = "approve a low-risk deployment after constitutional review"
CONSTITUTIONAL_HASH = "608508a9bd224290"
NONCE = "nonce-rust-protocol-001"
REQUEST_TIMESTAMP = 1_713_456_789.125
VOTE_TIMESTAMP = 1_713_456_790.25
PROOF_TIMESTAMP = 1_713_456_791.5
SETTLED_AT = 1_713_456_792.75


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public_key_hex(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _write_json(output_dir: Path, name: str, payload: dict[str, Any]) -> str:
    data = _json_bytes(payload)
    (output_dir / name).write_bytes(data)
    return protocol_sha256_hex(data)


def _validation_fixture() -> dict[str, Any]:
    dna = AgentDNA(constitution=Constitution.default(), agent_id="rust-fixture", strict=False)
    result = dna.validate(CONTENT)
    return {
        "action": result.action,
        "constitutional_hash": result.constitutional_hash,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "scoring_method": result.scoring_method,
        "valid": result.valid,
        "violations": list(result.violations),
    }


def _spectral_fixture() -> dict[str, Any]:
    manifold = SpectralSphereManifold(num_agents=3, smoothing=0.0)
    manifold.update_trust(0, 1, 0.75)
    manifold.update_trust(1, 2, -0.25)
    manifold.update_trust(2, 0, 0.5)
    projected = manifold.project()
    snapshot = {
        "matrix": projected.matrix,
        "num_agents": manifold.num_agents,
        "power_iterations": projected.power_iterations,
        "radius": manifold.radius,
        "spectral_norm": canonical_timestamp(projected.spectral_norm),
        "trust_updates": [
            {"delta": "0.75", "from_agent": 0, "to_agent": 1},
            {"delta": "-0.25", "from_agent": 1, "to_agent": 2},
            {"delta": "0.5", "from_agent": 2, "to_agent": 0},
        ],
    }
    return {
        "canonical_bytes_hex": encode_spectral_sphere_snapshot_v1(snapshot).hex(),
        "snapshot": snapshot,
    }


def build_fixture_corpus() -> dict[str, dict[str, Any]]:
    content_hash = legacy_content_hash(CONTENT)
    canonical_hash = canonical_content_hash(CONTENT)
    voter_key = _private_key(1)
    request_key = _private_key(2)
    voter_public_key = _public_key_hex(voter_key)
    request_public_key = _public_key_hex(request_key)

    vote_payload = ConstitutionalMesh.build_vote_payload(
        assignment_id=ASSIGNMENT_ID,
        voter_id=VOTER_ID,
        approved=True,
        reason="constitutional check passed",
        constitutional_hash=CONSTITUTIONAL_HASH,
        content_hash=content_hash,
    )
    vote_signature = voter_key.sign(vote_payload).hex()
    vote = ValidationVote(
        assignment_id=ASSIGNMENT_ID,
        voter_id=VOTER_ID,
        approved=True,
        reason="constitutional check passed",
        signature=vote_signature,
        constitutional_hash=CONSTITUTIONAL_HASH,
        content_hash=content_hash,
        timestamp=VOTE_TIMESTAMP,
    )

    remote_payload = legacy_remote_vote_request_payload_bytes(
        assignment_id=ASSIGNMENT_ID,
        voter_id=VOTER_ID,
        producer_id=PRODUCER_ID,
        artifact_id=ARTIFACT_ID,
        content=CONTENT,
        content_hash=content_hash,
        constitutional_hash=CONSTITUTIONAL_HASH,
        voter_public_key=voter_public_key,
        nonce=NONCE,
        timestamp=REQUEST_TIMESTAMP,
    )
    remote_request = RemoteVoteRequest(
        assignment_id=ASSIGNMENT_ID,
        voter_id=VOTER_ID,
        producer_id=PRODUCER_ID,
        artifact_id=ARTIFACT_ID,
        content=CONTENT,
        content_hash=content_hash,
        constitutional_hash=CONSTITUTIONAL_HASH,
        voter_public_key=voter_public_key,
        nonce=NONCE,
        timestamp=REQUEST_TIMESTAMP,
        request_signer_public_key=request_public_key,
        request_signature=request_key.sign(remote_payload).hex(),
    )
    nonce_cache: OrderedDict[str, float] = OrderedDict()
    ConstitutionalMesh.verify_remote_vote_request(
        remote_request,
        nonce_cache=nonce_cache,
        now=REQUEST_TIMESTAMP,
    )
    try:
        ConstitutionalMesh.verify_remote_vote_request(
            remote_request,
            nonce_cache=nonce_cache,
            now=REQUEST_TIMESTAMP + 1.0,
        )
    except RemoteVoteReplayError as exc:
        replay_error = {
            "error_type": type(exc).__name__,
            "message": str(exc),
            "nonce_cache": dict(nonce_cache),
        }
    else:  # pragma: no cover - fixture invariant
        raise AssertionError("remote vote replay was not rejected")

    vote_hashes = (vote.vote_hash,)
    proof = MeshProof(
        assignment_id=ASSIGNMENT_ID,
        content_hash=content_hash,
        constitutional_hash=CONSTITUTIONAL_HASH,
        vote_hashes=vote_hashes,
        root_hash=_compute_merkle_root(
            ASSIGNMENT_ID,
            content_hash,
            CONSTITUTIONAL_HASH,
            vote_hashes,
            True,
        ),
        accepted=True,
        timestamp=PROOF_TIMESTAMP,
    )
    result = {
        "accepted": True,
        "assignment_id": ASSIGNMENT_ID,
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "pending_votes": 0,
        "proof": asdict(proof),
        "quorum_met": True,
        "settled": True,
        "settled_at": SETTLED_AT,
        "votes_against": 0,
        "votes_for": 1,
    }
    assignment = {
        "artifact_id": ARTIFACT_ID,
        "assignment_id": ASSIGNMENT_ID,
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "content_hash": content_hash,
        "is_recovered": True,
        "peers": [VOTER_ID],
        "producer_id": PRODUCER_ID,
        "timestamp": REQUEST_TIMESTAMP,
    }
    settlement = SettlementRecord(
        assignment=assignment,
        result=result,
        constitutional_hash=CONSTITUTIONAL_HASH,
        schema_version=1,
        is_recovered=True,
    )
    settlement_payload = JSONLSettlementStore._payload_from_record(settlement)
    settlement_jsonl_line = json.dumps(settlement_payload, separators=(",", ":"))

    return {
        "content_hashes.json": {
            "canonical_content_hash_v1": canonical_hash,
            "content": CONTENT,
            "legacy_content_hash": content_hash,
        },
        "validation_result.json": _validation_fixture(),
        "vote_payload.json": {
            "canonical_bytes_hex": encode_vote_payload_v1(
                assignment_id=ASSIGNMENT_ID,
                voter_id=VOTER_ID,
                approved=True,
                reason="constitutional check passed",
                constitutional_hash=CONSTITUTIONAL_HASH,
                content_hash=content_hash,
            ).hex(),
            "legacy_bytes_hex": vote_payload.hex(),
            "signature_hex": vote_signature,
            "vote": asdict(vote),
            "vote_hash": vote.vote_hash,
            "voter_public_key": voter_public_key,
        },
        "remote_vote_request.json": {
            "canonical_bytes_hex": encode_remote_vote_request_payload_v1(remote_request).hex(),
            "canonical_signing_bytes_hex": encode_remote_vote_request_signing_payload_v1(
                remote_request
            ).hex(),
            "legacy_bytes_hex": remote_payload.hex(),
            "request": asdict(remote_request),
        },
        "mesh_proof.json": {
            "canonical_bytes_hex": encode_mesh_proof_v1(proof).hex(),
            "proof": asdict(proof),
            "verified": proof.verify(),
        },
        "settlement_record.json": {
            "canonical_bytes_hex": encode_settlement_record_v1(settlement).hex(),
            "jsonl_line": settlement_jsonl_line,
            "record": asdict(settlement),
            "sqlite_row": [
                ASSIGNMENT_ID,
                json.dumps(assignment, separators=(",", ":")),
                json.dumps(result, separators=(",", ":")),
                CONSTITUTIONAL_HASH,
                1,
                1,
            ],
        },
        "replay_rejection.json": replay_error,
        "spectral_sphere_snapshot.json": _spectral_fixture(),
    }


def write_fixture_corpus(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = build_fixture_corpus()
    manifest_entries = {
        filename: _write_json(output_dir, filename, payload)
        for filename, payload in sorted(artifacts.items())
    }
    manifest = {
        "description": "Deterministic protocol fixtures for Rust-core parity gates.",
        "hash_algorithm": "sha256",
        "protocol_version": 1,
        "artifacts": manifest_entries,
    }
    manifest_hash = _write_json(output_dir, "manifest.json", manifest)
    return {**manifest, "manifest_sha256": manifest_hash}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Fixture output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()
    manifest = write_fixture_corpus(args.output_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
