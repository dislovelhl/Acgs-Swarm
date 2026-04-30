"""Settlement serialization helpers for Constitutional Mesh.

The mesh runtime owns locking and persistence side effects.  This module owns the
stable wire/disk representation of assignments, proofs, results, and settlement
records so storage compatibility can be tested independently from orchestration.
"""

from __future__ import annotations

from typing import Any

from constitutional_swarm.mesh_types import MeshProof, MeshResult, PeerAssignment
from constitutional_swarm.settlement_store import SettlementRecord


def serialize_assignment(assignment: PeerAssignment) -> dict[str, Any]:
    """Serialize an assignment for durable settlement storage.

    Raw content is intentionally omitted; settled audit records store hashes and
    metadata only to reduce sensitive-data exposure.
    """
    return {
        "assignment_id": assignment.assignment_id,
        "producer_id": assignment.producer_id,
        "artifact_id": assignment.artifact_id,
        "content_hash": assignment.content_hash,
        "peers": list(assignment.peers),
        "constitutional_hash": assignment.constitutional_hash,
        "timestamp": assignment.timestamp,
    }


def deserialize_assignment(data: dict[str, Any]) -> PeerAssignment:
    """Deserialize an assignment from durable settlement storage."""
    return PeerAssignment(
        assignment_id=str(data["assignment_id"]),
        producer_id=str(data["producer_id"]),
        artifact_id=str(data["artifact_id"]),
        content=str(data.get("content", "")),
        content_hash=str(data["content_hash"]),
        peers=tuple(str(peer) for peer in data["peers"]),
        constitutional_hash=str(data["constitutional_hash"]),
        timestamp=float(data["timestamp"]),
    )


def serialize_proof(proof: MeshProof | None) -> dict[str, Any] | None:
    """Serialize a mesh proof, preserving the legacy JSON shape."""
    if proof is None:
        return None
    return {
        "assignment_id": proof.assignment_id,
        "content_hash": proof.content_hash,
        "constitutional_hash": proof.constitutional_hash,
        "vote_hashes": list(proof.vote_hashes),
        "root_hash": proof.root_hash,
        "accepted": proof.accepted,
        "timestamp": proof.timestamp,
    }


def deserialize_proof(data: dict[str, Any] | None) -> MeshProof | None:
    """Deserialize a mesh proof from durable settlement storage."""
    if data is None:
        return None
    return MeshProof(
        assignment_id=str(data["assignment_id"]),
        content_hash=str(data["content_hash"]),
        constitutional_hash=str(data["constitutional_hash"]),
        vote_hashes=tuple(str(vote_hash) for vote_hash in data["vote_hashes"]),
        root_hash=str(data["root_hash"]),
        accepted=bool(data["accepted"]),
        timestamp=float(data["timestamp"]),
    )


def serialize_result(result: MeshResult) -> dict[str, Any]:
    """Serialize a mesh result for durable settlement storage."""
    return {
        "assignment_id": result.assignment_id,
        "accepted": result.accepted,
        "votes_for": result.votes_for,
        "votes_against": result.votes_against,
        "quorum_met": result.quorum_met,
        "pending_votes": result.pending_votes,
        "constitutional_hash": result.constitutional_hash,
        "proof": serialize_proof(result.proof),
        "settled": result.settled,
        "settled_at": result.settled_at,
    }


def deserialize_result(data: dict[str, Any]) -> MeshResult:
    """Deserialize a mesh result from durable settlement storage."""
    return MeshResult(
        assignment_id=str(data["assignment_id"]),
        accepted=bool(data["accepted"]),
        votes_for=int(data["votes_for"]),
        votes_against=int(data["votes_against"]),
        quorum_met=bool(data["quorum_met"]),
        pending_votes=int(data["pending_votes"]),
        constitutional_hash=str(data["constitutional_hash"]),
        proof=deserialize_proof(data.get("proof")),
        settled=bool(data.get("settled", False)),
        settled_at=(float(data["settled_at"]) if data.get("settled_at") is not None else None),
    )


def build_settlement_record(assignment: PeerAssignment, result: MeshResult) -> SettlementRecord:
    """Build the canonical durable settlement record."""
    return SettlementRecord(
        assignment=serialize_assignment(assignment),
        result=serialize_result(result),
        constitutional_hash=assignment.constitutional_hash,
    )
