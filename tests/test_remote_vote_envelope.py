"""Security tests for the signed remote-vote request envelope."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import replace

import pytest
from constitutional_swarm import (
    ConstitutionalMesh,
    LocalRemotePeer,
    RemoteVoteReplayError,
    RemoteVoteRequest,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution


def _build_signed_request(
    *,
    nonce: str = "nonce-1",
    timestamp: float = 1_000.0,
) -> tuple[ConstitutionalMesh, LocalRemotePeer, RemoteVoteRequest]:
    constitution = Constitution.default()
    request_signer = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        constitution,
        peers_per_validation=2,
        quorum=2,
        seed=41,
        request_signing_private_key=request_signer,
    )
    peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        replay_window_seconds=300.0,
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-local")
    assignment = mesh.request_validation("producer", "signed envelope content", "art-envelope")
    signature = request_signer.sign(
        ConstitutionalMesh.build_remote_vote_request_payload(
            assignment_id=assignment.assignment_id,
            voter_id="peer-remote",
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content=assignment.content,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            voter_public_key=peer.public_key_hex,
            nonce=nonce,
            timestamp=timestamp,
        )
    ).hex()
    return (
        mesh,
        peer,
        RemoteVoteRequest(
            assignment_id=assignment.assignment_id,
            voter_id="peer-remote",
            producer_id=assignment.producer_id,
            artifact_id=assignment.artifact_id,
            content=assignment.content,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            voter_public_key=peer.public_key_hex,
            nonce=nonce,
            timestamp=timestamp,
            request_signer_public_key=mesh.get_request_signing_public_key(),
            request_signature=signature,
        ),
    )


def test_nonce_reuse_within_window_raises_remote_vote_replay_error() -> None:
    _, _, request = _build_signed_request()
    nonce_cache: OrderedDict[str, float] = OrderedDict()

    assert ConstitutionalMesh.verify_remote_vote_request(
        request,
        nonce_cache=nonce_cache,
        replay_window_seconds=300.0,
        now=request.timestamp,
    )
    with pytest.raises(RemoteVoteReplayError, match="already used"):
        ConstitutionalMesh.verify_remote_vote_request(
            request,
            nonce_cache=nonce_cache,
            replay_window_seconds=300.0,
            now=request.timestamp + 1.0,
        )


def test_nonce_reuse_after_window_expiry_is_accepted() -> None:
    _, _, first_request = _build_signed_request(nonce="reusable-nonce", timestamp=1_000.0)
    _, _, second_request = _build_signed_request(nonce="reusable-nonce", timestamp=1_311.0)
    nonce_cache: OrderedDict[str, float] = OrderedDict()

    assert ConstitutionalMesh.verify_remote_vote_request(
        first_request,
        nonce_cache=nonce_cache,
        replay_window_seconds=300.0,
        now=1_000.0,
    )
    assert ConstitutionalMesh.verify_remote_vote_request(
        second_request,
        nonce_cache=nonce_cache,
        replay_window_seconds=300.0,
        now=1_311.0,
    )


def test_timestamp_outside_replay_window_is_rejected() -> None:
    _, _, request = _build_signed_request(timestamp=500.0)

    with pytest.raises(ValueError, match="outside replay window"):
        ConstitutionalMesh.verify_remote_vote_request(
            request,
            replay_window_seconds=300.0,
            now=901.0,
        )


def test_missing_nonce_or_timestamp_is_rejected_with_clear_error() -> None:
    _, _, request = _build_signed_request()

    with pytest.raises(ValueError, match="missing nonce"):
        ConstitutionalMesh.verify_remote_vote_request(replace(request, nonce=""))
    with pytest.raises(ValueError, match="missing timestamp"):
        ConstitutionalMesh.verify_remote_vote_request(
            replace(request, timestamp=None),  # type: ignore[arg-type]
        )


def test_local_remote_peer_surfaces_replay_error() -> None:
    _, peer, request = _build_signed_request(timestamp=time.time())

    first_response = peer.handle_vote_request(request)
    assert first_response.assignment_id == request.assignment_id
    with pytest.raises(RemoteVoteReplayError, match="already used"):
        peer.handle_vote_request(request)
