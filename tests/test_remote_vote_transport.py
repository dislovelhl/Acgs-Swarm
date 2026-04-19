"""Tests for remote_vote_transport.py — remote peer vote collection/runtime."""

from __future__ import annotations

import pytest
from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteRequest
from constitutional_swarm.remote_vote_transport import (
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteResponse,
    RemoteVoteServer,
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution

websockets = pytest.importorskip(
    "websockets", reason="websockets not installed — skip remote vote transport tests"
)


def test_remote_vote_request_round_trip() -> None:
    request = RemoteVoteRequest(
        assignment_id="assign-1",
        voter_id="peer-1",
        producer_id="producer-1",
        artifact_id="art-1",
        content="safe content",
        content_hash="abc123",
        constitutional_hash="const-hash",
        voter_public_key="deadbeef",
        request_signer_public_key="feedface",
        request_signature="cafebabe",
    )
    decoded = decode_remote_vote_request(encode_remote_vote_request(request))
    assert decoded == request


def test_remote_vote_response_round_trip() -> None:
    response = RemoteVoteResponse(
        assignment_id="assign-1",
        voter_id="peer-1",
        approved=True,
        reason="ok",
        constitutional_hash="const-hash",
        content_hash="abc123",
        signature="cafebabe",
    )
    decoded = decode_remote_vote_response(encode_remote_vote_response(response))
    assert decoded == response


def test_remote_vote_response_rejects_non_boolean_approved() -> None:
    with pytest.raises(ValueError, match="approved must be a boolean"):
        decode_remote_vote_response(
            '{"assignment_id":"assign-1","voter_id":"peer-1","approved":"false",'
            '"reason":"ok","constitutional_hash":"const-hash","content_hash":"abc123",'
            '"signature":"cafebabe"}'
        )


@pytest.mark.asyncio
async def test_remote_vote_server_round_trip() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=7)
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-1")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")

    async with RemoteVoteServer(peer.handle_vote_request, host="127.0.0.1", port=0) as server:
        client = RemoteVoteClient()
        response = await client.request_vote("127.0.0.1", server.actual_port, request)

    assert response.assignment_id == request.assignment_id
    assert response.voter_id == "peer-1"
    assert response.approved is True
    assert ConstitutionalMesh.verify_vote_signature(
        public_key=request.voter_public_key,
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        approved=response.approved,
        reason=response.reason,
        constitutional_hash=response.constitutional_hash,
        content_hash=response.content_hash,
        signature=response.signature,
    )


@pytest.mark.asyncio
async def test_full_validation_remote_collects_remote_and_local_votes() -> None:
    constitution = Constitution.default()
    mesh = ConstitutionalMesh(constitution, seed=11)
    remote_peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )

    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=remote_peer.public_key_hex)
    mesh.register_local_signer("peer-local-1")
    mesh.register_local_signer("peer-local-2")

    async with RemoteVoteServer(
        remote_peer.handle_vote_request,
        host="127.0.0.1",
        port=0,
    ) as server:
        result = await mesh.full_validation_remote(
            "producer",
            "safe remote-reviewed content",
            "art-remote",
            peer_routes={"peer-remote": ("127.0.0.1", server.actual_port)},
        )

    assert result.accepted is True
    assert result.quorum_met is True
    assert result.proof is not None
    assert result.proof.verify() is True


def test_remote_peer_rejects_tampered_content_hash() -> None:
    constitution = Constitution.default()
    request_signer = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        constitution,
        seed=13,
        request_signing_private_key=request_signer,
    )
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-2")
    mesh.register_local_signer("peer-3")
    assignment = mesh.request_validation("producer", "safe content", "art-2")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    tampered_content = "tampered content"
    tampered = RemoteVoteRequest(
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        producer_id=request.producer_id,
        artifact_id=request.artifact_id,
        content=tampered_content,
        content_hash=request.content_hash,
        constitutional_hash=request.constitutional_hash,
        voter_public_key=request.voter_public_key,
        request_signer_public_key=request.request_signer_public_key,
        request_signature=request_signer.sign(
            ConstitutionalMesh.build_remote_vote_request_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                producer_id=request.producer_id,
                artifact_id=request.artifact_id,
                content=tampered_content,
                content_hash=request.content_hash,
                constitutional_hash=request.constitutional_hash,
                voter_public_key=request.voter_public_key,
            )
        ).hex(),
    )
    with pytest.raises(ValueError, match="content does not match"):
        peer.handle_vote_request(tampered)


def test_remote_peer_rejects_untrusted_request_signer() -> None:
    constitution = Constitution.default()
    trusted_mesh = ConstitutionalMesh(constitution, seed=17)
    untrusted_mesh = ConstitutionalMesh(constitution, seed=18)
    peer = LocalRemotePeer(
        agent_id="peer-1",
        constitution=constitution,
        trusted_request_signers={trusted_mesh.get_request_signing_public_key()},
    )
    untrusted_mesh.register_local_signer("producer")
    untrusted_mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
    untrusted_mesh.register_local_signer("peer-2")
    untrusted_mesh.register_local_signer("peer-3")
    assignment = untrusted_mesh.request_validation("producer", "safe content", "art-3")
    request = untrusted_mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
    with pytest.raises(ValueError, match="not trusted"):
        peer.handle_vote_request(request)


# ---------------------------------------------------------------------------
# Phase 6: Remote vote transport failure-path tests
# ---------------------------------------------------------------------------


class TestDecodeRemoteVoteRequestErrors:
    """Failure paths in decode_remote_vote_request (lines 50-71)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote request"):
            decode_remote_vote_request("{not-json!")

    def test_non_dict_json_array(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request("[1,2,3]")

    def test_non_dict_json_string(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_request('"just a string"')

    @pytest.mark.parametrize("missing_field", [
        "assignment_id",
        "voter_id",
        "producer_id",
        "artifact_id",
        "content",
        "content_hash",
        "constitutional_hash",
        "voter_public_key",
        "request_signer_public_key",
        "request_signature",
    ])
    def test_missing_required_field(self, missing_field: str) -> None:
        full_payload = {
            "assignment_id": "a",
            "voter_id": "v",
            "producer_id": "p",
            "artifact_id": "art",
            "content": "c",
            "content_hash": "ch",
            "constitutional_hash": "const",
            "voter_public_key": "vpk",
            "request_signer_public_key": "rspk",
            "request_signature": "rs",
        }
        del full_payload[missing_field]
        import json
        with pytest.raises(ValueError, match=f"missing {missing_field}"):
            decode_remote_vote_request(json.dumps(full_payload))


class TestDecodeRemoteVoteResponseErrors:
    """Failure paths in decode_remote_vote_response (lines 78-99)."""

    def test_malformed_json(self) -> None:
        with pytest.raises(ValueError, match="Malformed remote vote response"):
            decode_remote_vote_response("not-json{")

    def test_non_dict_json(self) -> None:
        with pytest.raises(ValueError, match="expected object, got"):
            decode_remote_vote_response("[1]")

    def test_missing_required_field(self) -> None:
        import json
        payload = {
            "assignment_id": "a",
            "voter_id": "v",
            "approved": True,
            "reason": "ok",
            "constitutional_hash": "ch",
            # missing content_hash
            "signature": "sig",
        }
        with pytest.raises(ValueError, match="missing content_hash"):
            decode_remote_vote_response(json.dumps(payload))


class TestLocalRemotePeerValidation:
    """Explicit tests for LocalRemotePeer.handle_vote_request guard clauses."""

    def _make_peer_and_request(self) -> tuple[LocalRemotePeer, RemoteVoteRequest]:
        """Create a valid peer + request pair for mutation tests."""
        constitution = Constitution.default()
        mesh = ConstitutionalMesh(constitution, seed=42)
        peer = LocalRemotePeer(
            agent_id="peer-1",
            constitution=constitution,
            trusted_request_signers={mesh.get_request_signing_public_key()},
        )
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("peer-1", vote_public_key=peer.public_key_hex)
        mesh.register_local_signer("peer-2")
        mesh.register_local_signer("peer-3")
        assignment = mesh.request_validation("producer", "safe content", "art-val")
        request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
        return peer, request

    def test_rejects_wrong_voter_id(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_voter = RemoteVoteRequest(
            assignment_id=request.assignment_id,
            voter_id="wrong-peer",
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content=request.content,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            voter_public_key=request.voter_public_key,
            request_signer_public_key=request.request_signer_public_key,
            request_signature=request.request_signature,
        )
        with pytest.raises(ValueError, match="intended for wrong-peer"):
            peer.handle_vote_request(wrong_voter)

    def test_rejects_mismatched_pubkey(self) -> None:
        peer, request = self._make_peer_and_request()
        wrong_key = RemoteVoteRequest(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content=request.content,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            voter_public_key="0000000000000000000000000000000000000000000000000000000000000000",
            request_signer_public_key=request.request_signer_public_key,
            request_signature=request.request_signature,
        )
        with pytest.raises(ValueError, match="public key does not match"):
            peer.handle_vote_request(wrong_key)
