from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from constitutional_swarm import ConstitutionalMesh, RemoteVoteRequest, ValidationVote
from constitutional_swarm.mesh.settlement import MeshProof
from constitutional_swarm.protocol import (
    DOMAIN_MESH_PROOF,
    DOMAIN_REMOTE_VOTE_REQUEST,
    DOMAIN_SETTLEMENT_RECORD,
    DOMAIN_VOTE_PAYLOAD,
    encode_mesh_proof_v1,
    encode_remote_vote_request_payload_v1,
    encode_remote_vote_request_signing_payload_v1,
    encode_settlement_record_v1,
    encode_vote_payload_v1,
    legacy_remote_vote_request_payload_bytes,
    legacy_vote_hash,
    legacy_vote_payload_bytes,
)
from constitutional_swarm.settlement_store import SettlementRecord
from scripts.generate_rust_protocol_fixtures import write_fixture_corpus


def test_legacy_vote_payload_matches_current_mesh_signing_payload() -> None:
    payload = {
        "assignment_id": "assign-1",
        "voter_id": "validator-1",
        "approved": True,
        "reason": "constitutional check passed",
        "constitutional_hash": "608508a9bd224290",
        "content_hash": "abc123",
    }

    assert legacy_vote_payload_bytes(**payload) == ConstitutionalMesh.build_vote_payload(**payload)


def test_legacy_remote_request_payload_matches_current_mesh_payload() -> None:
    payload = {
        "assignment_id": "assign-1",
        "voter_id": "validator-1",
        "producer_id": "producer-1",
        "artifact_id": "artifact-1",
        "content": "hello:with:colons",
        "content_hash": "abc123",
        "constitutional_hash": "608508a9bd224290",
        "voter_public_key": "00" * 32,
        "nonce": "nonce-1",
        "timestamp": 1_713_456_789.125,
    }

    assert legacy_remote_vote_request_payload_bytes(
        **payload
    ) == ConstitutionalMesh.build_remote_vote_request_payload(**payload)


def test_legacy_vote_hash_matches_validation_vote_property() -> None:
    vote = ValidationVote(
        assignment_id="assign-1",
        voter_id="validator-1",
        approved=False,
        reason="policy violation",
        signature="ab" * 64,
        constitutional_hash="608508a9bd224290",
        content_hash="abc123",
        timestamp=1.0,
    )

    assert legacy_vote_hash(vote) == vote.vote_hash


def test_canonical_protocol_encoders_are_domain_separated() -> None:
    vote_bytes = encode_vote_payload_v1(
        assignment_id="assign-1",
        voter_id="validator-1",
        approved=True,
        reason="ok",
        constitutional_hash="608508a9bd224290",
        content_hash="abc123",
    )
    request_bytes = encode_remote_vote_request_payload_v1(
        RemoteVoteRequest(
            assignment_id="assign-1",
            voter_id="validator-1",
            producer_id="producer-1",
            artifact_id="artifact-1",
            content="content",
            content_hash="abc123",
            constitutional_hash="608508a9bd224290",
            voter_public_key="00" * 32,
            nonce="nonce-1",
            timestamp=1.0,
            request_signer_public_key="11" * 32,
            request_signature="22" * 64,
        )
    )
    proof_bytes = encode_mesh_proof_v1(
        MeshProof(
            assignment_id="assign-1",
            content_hash="abc123",
            constitutional_hash="608508a9bd224290",
            vote_hashes=("votehash",),
            root_hash="roothash",
            accepted=True,
            timestamp=1.0,
        )
    )
    settlement_bytes = encode_settlement_record_v1(
        SettlementRecord(
            assignment={"assignment_id": "assign-1"},
            result={"accepted": True},
            constitutional_hash="608508a9bd224290",
            schema_version=1,
            is_recovered=True,
        )
    )

    assert vote_bytes.startswith(f"constitutional-swarm/{DOMAIN_VOTE_PAYLOAD}/v1\n".encode())
    assert request_bytes.startswith(
        f"constitutional-swarm/{DOMAIN_REMOTE_VOTE_REQUEST}/v1\n".encode()
    )
    assert proof_bytes.startswith(f"constitutional-swarm/{DOMAIN_MESH_PROOF}/v1\n".encode())
    assert settlement_bytes.startswith(
        f"constitutional-swarm/{DOMAIN_SETTLEMENT_RECORD}/v1\n".encode()
    )
    assert len({vote_bytes, request_bytes, proof_bytes, settlement_bytes}) == 4


def test_remote_vote_request_signing_payload_excludes_signature_fields() -> None:
    request = RemoteVoteRequest(
        assignment_id="assign-1",
        voter_id="validator-1",
        producer_id="producer-1",
        artifact_id="artifact-1",
        content="content",
        content_hash="abc123",
        constitutional_hash="608508a9bd224290",
        voter_public_key="00" * 32,
        nonce="nonce-1",
        timestamp=1.0,
        request_signer_public_key="11" * 32,
        request_signature="22" * 64,
    )

    signing_payload = encode_remote_vote_request_signing_payload_v1(request)
    envelope_payload = encode_remote_vote_request_payload_v1(request)

    assert signing_payload != envelope_payload
    assert b"request_signature" not in signing_payload
    assert b"request_signer_public_key" not in signing_payload
    assert b"request_signature" in envelope_payload
    assert b"request_signer_public_key" in envelope_payload


def test_rust_protocol_fixture_generator_is_stable(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    first_manifest = write_fixture_corpus(first_dir)
    second_manifest = write_fixture_corpus(second_dir)

    assert first_manifest == second_manifest
    for first_file in sorted(first_dir.iterdir()):
        second_file = second_dir / first_file.name
        assert second_file.read_bytes() == first_file.read_bytes()


def test_checked_in_rust_protocol_fixtures_match_generator(tmp_path: Path) -> None:
    generated_dir = tmp_path / "generated"
    write_fixture_corpus(generated_dir)
    checked_in_dir = Path(__file__).parent / "fixtures" / "rust_protocol"

    for generated_file in sorted(generated_dir.iterdir()):
        checked_in_file = checked_in_dir / generated_file.name
        assert checked_in_file.read_bytes() == generated_file.read_bytes()

    manifest = json.loads((checked_in_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["protocol_version"] == 1
    assert set(manifest["artifacts"]) == {
        "content_hashes.json",
        "mesh_proof.json",
        "remote_vote_request.json",
        "replay_rejection.json",
        "settlement_record.json",
        "spectral_sphere_snapshot.json",
        "validation_result.json",
        "vote_payload.json",
    }
    for artifact, expected_hash in manifest["artifacts"].items():
        digest = sha256((checked_in_dir / artifact).read_bytes()).hexdigest()
        assert digest == expected_hash
