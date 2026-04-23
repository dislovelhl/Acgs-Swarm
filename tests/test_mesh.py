"""Tests for Constitutional Mesh — Byzantine peer validation with cryptographic proof."""

from __future__ import annotations

import json
import sqlite3
import time
import warnings
from dataclasses import dataclass

import pytest
from constitutional_swarm.mesh import (
    AssignmentSettledError,
    ConstitutionalMesh,
    DuplicateVoteError,
    InsufficientPeersError,
    InvalidVoteSignatureError,
    MeshProof,
    MeshResult,
    PeerAssignment,
    RemoteVoteRequest,
    SettlementPersistenceError,
    UnauthorizedVoterError,
    ValidationVote,
)
from constitutional_swarm.settlement_store import (
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
    SQLiteSettlementStore,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution, ConstitutionalViolationError, Rule


class _FailingSettlementStore:
    """Store test double that records the attempted write and then fails."""

    def __init__(self) -> None:
        self.last_record: SettlementRecord | None = None
        self.pending: dict[str, SettlementRecord] = {}

    def append(self, record: SettlementRecord) -> None:
        self.last_record = record
        raise OSError("disk full")

    def mark_pending(self, record: SettlementRecord) -> None:
        self.pending[str(record.assignment["assignment_id"])] = record

    def clear_pending(self, assignment_id: str) -> None:
        self.pending.pop(assignment_id, None)

    def load_pending(self) -> list[SettlementRecord]:
        return list(self.pending.values())

    def pending_count(self) -> int:
        return len(self.pending)

    def load_all(self) -> list[SettlementRecord]:
        return []

    def describe(self) -> dict[str, str]:
        return {"backend": "failing"}


def _signed_vote(
    mesh: ConstitutionalMesh,
    assignment_id: str,
    voter_id: str,
    *,
    approved: bool,
    reason: str = "",
) -> ValidationVote:
    return mesh.submit_vote(
        assignment_id,
        voter_id,
        approved=approved,
        reason=reason,
        signature=mesh.sign_vote(
            assignment_id,
            voter_id,
            approved=approved,
            reason=reason,
        ),
    )


@pytest.fixture
def mesh() -> ConstitutionalMesh:
    """Mesh with default constitution and 5 agents, deterministic seed."""
    m = ConstitutionalMesh(Constitution.default(), seed=42)
    for i in range(5):
        m.register_local_signer(f"agent-{i:02d}", domain=f"domain-{i % 3}")
    return m


@pytest.fixture
def custom_mesh() -> ConstitutionalMesh:
    """Mesh with custom swarm rules."""
    rules = [
        Rule(
            id="MESH-001",
            text="Agents must not bypass domain boundaries",
            severity="critical",
            keywords=["cross-domain bypass", "unauthorized domain"],
        ),
        Rule(
            id="MESH-002",
            text="All outputs must include provenance",
            severity="high",
            keywords=["no provenance", "missing attribution"],
        ),
    ]
    const = Constitution.from_rules(rules, name="mesh-test")
    m = ConstitutionalMesh(const, peers_per_validation=3, quorum=2, seed=42)
    for i in range(6):
        m.register_local_signer(f"peer-{i:02d}", domain=f"dom-{i % 2}")
    return m


# ---------------------------------------------------------------------------
# Agent management
# ---------------------------------------------------------------------------


class TestAgentManagement:
    def test_register_and_count(self, mesh: ConstitutionalMesh) -> None:
        assert mesh.agent_count == 5

    def test_unregister(self, mesh: ConstitutionalMesh) -> None:
        mesh.unregister_agent("agent-00")
        assert mesh.agent_count == 4

    def test_unregister_nonexistent_is_safe(self, mesh: ConstitutionalMesh) -> None:
        mesh.unregister_agent("ghost")
        assert mesh.agent_count == 5

    def test_reputation_starts_at_one(self, mesh: ConstitutionalMesh) -> None:
        assert mesh.get_reputation("agent-00") == 1.0

    def test_reputation_unknown_agent_raises(self, mesh: ConstitutionalMesh) -> None:
        with pytest.raises(KeyError):
            mesh.get_reputation("nonexistent")

    def test_summary_reports_no_settlement_storage_by_default(
        self, mesh: ConstitutionalMesh
    ) -> None:
        summary = mesh.summary()
        assert summary["settlement_storage"] == {"enabled": False, "backend": None, "pending": 0}
        assert summary["pending_settlements"] == 0

    def test_summary_reports_jsonl_settlement_storage(self, tmp_path) -> None:
        store = JSONLSettlementStore(tmp_path / "mesh.jsonl")
        mesh = ConstitutionalMesh(Constitution.default(), seed=1, settlement_store=store)
        summary = mesh.summary()
        assert summary["settlement_storage"]["enabled"] is True
        assert summary["settlement_storage"]["backend"] == "jsonl"
        assert summary["settlement_storage"]["pending"] == 0
        assert summary["pending_settlements"] == 0

    def test_summary_reports_sqlite_settlement_storage(self, tmp_path) -> None:
        store = SQLiteSettlementStore(tmp_path / "mesh.db")
        mesh = ConstitutionalMesh(Constitution.default(), seed=1, settlement_store=store)
        summary = mesh.summary()
        assert summary["settlement_storage"]["enabled"] is True
        assert summary["settlement_storage"]["backend"] == "sqlite"
        assert summary["settlement_storage"]["pending"] == 0
        assert summary["pending_settlements"] == 0

    def test_settlement_store_path_dot_db_auto_selects_sqlite(self, tmp_path) -> None:
        mesh = ConstitutionalMesh(
            Constitution.default(), seed=2, settlement_store_path=tmp_path / "auto.db"
        )
        summary = mesh.summary()
        assert summary["settlement_storage"]["backend"] == "sqlite"

    def test_settlement_store_path_dot_jsonl_auto_selects_jsonl(self, tmp_path) -> None:
        mesh = ConstitutionalMesh(
            Constitution.default(), seed=3, settlement_store_path=tmp_path / "auto.jsonl"
        )
        summary = mesh.summary()
        assert summary["settlement_storage"]["backend"] == "jsonl"


# ---------------------------------------------------------------------------
# Registration mode transitions
# ---------------------------------------------------------------------------


class TestRegistrationModeTransitions:
    """Regression suite for agent registration mode transitions.

    Invariant: re-registering an agent with a different mode must not leave
    orphaned key material.  Local signers have private keys; remote agents do
    not.  Transitioning between modes must atomically swap the key set.
    """

    def test_local_to_remote_purges_private_key(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=1)
        mesh.register_local_signer("agent-a")
        assert "agent-a" in mesh._agent_vote_private_keys

        remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-a", vote_public_key=remote_key.public_key())

        assert "agent-a" not in mesh._agent_vote_private_keys
        assert "agent-a" in mesh._agent_vote_public_keys

    def test_remote_to_local_adds_private_key(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=2)
        remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-b", vote_public_key=remote_key.public_key())
        assert "agent-b" not in mesh._agent_vote_private_keys

        mesh.register_local_signer("agent-b")

        assert "agent-b" in mesh._agent_vote_private_keys
        assert "agent-b" in mesh._agent_vote_public_keys

    def test_local_to_remote_updates_public_key(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=3)
        mesh.register_local_signer("agent-c")
        old_pub = mesh._agent_vote_public_keys["agent-c"]

        new_remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-c", vote_public_key=new_remote_key.public_key())

        assert mesh._agent_vote_public_keys["agent-c"] != old_pub

    def test_remote_to_local_updates_public_key(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=4)
        old_remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-d", vote_public_key=old_remote_key.public_key())
        old_pub = mesh._agent_vote_public_keys["agent-d"]

        new_local_key = Ed25519PrivateKey.generate()
        mesh.register_local_signer("agent-d", vote_private_key=new_local_key)

        assert mesh._agent_vote_public_keys["agent-d"] != old_pub

    def test_unregister_clears_key_material(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=5)
        mesh.register_local_signer("agent-e")
        assert "agent-e" in mesh._agent_vote_private_keys

        mesh.unregister_agent("agent-e")

        assert "agent-e" not in mesh._agent_vote_private_keys
        assert "agent-e" not in mesh._agent_vote_public_keys

    def test_unregister_then_reregister_gets_fresh_keys(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=6)
        mesh.register_local_signer("agent-f")
        old_priv = mesh._agent_vote_private_keys["agent-f"]

        mesh.unregister_agent("agent-f")
        mesh.register_local_signer("agent-f")

        assert mesh._agent_vote_private_keys["agent-f"] is not old_priv

    def test_mode_transition_preserves_agent_count(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=7)
        mesh.register_local_signer("agent-g")
        count_before = mesh.agent_count

        remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-g", vote_public_key=remote_key.public_key())
        assert mesh.agent_count == count_before

        mesh.register_local_signer("agent-g")
        assert mesh.agent_count == count_before

    def test_local_to_remote_twice_is_idempotent(self) -> None:
        const = Constitution.default()
        mesh = ConstitutionalMesh(const, seed=8)
        mesh.register_local_signer("agent-h")

        remote_key = Ed25519PrivateKey.generate()
        mesh.register_remote_agent("agent-h", vote_public_key=remote_key.public_key())
        mesh.register_remote_agent("agent-h", vote_public_key=remote_key.public_key())

        assert "agent-h" not in mesh._agent_vote_private_keys
        assert mesh.agent_count == 1


# ---------------------------------------------------------------------------
# Peer assignment
# ---------------------------------------------------------------------------


class TestPeerAssignment:
    def test_peers_assigned(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "analyze code quality", "art-1")
        assert isinstance(assignment, PeerAssignment)
        assert len(assignment.peers) == 3
        assert assignment.producer_id == "agent-00"

    def test_producer_excluded_from_peers_maci(self, mesh: ConstitutionalMesh) -> None:
        """MACI property: no self-validation."""
        for _ in range(20):  # Run multiple times to cover random selection
            assignment = mesh.request_validation("agent-00", "safe action", f"art-{_}")
            assert "agent-00" not in assignment.peers

    def test_content_hash_computed(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "test content", "art-1")
        assert len(assignment.content_hash) == 32
        assert assignment.content_hash != ""

    def test_constitutional_hash_attached(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "safe action", "art-1")
        assert assignment.constitutional_hash == mesh.constitutional_hash

    def test_unregistered_producer_raises(self, mesh: ConstitutionalMesh) -> None:
        with pytest.raises(KeyError, match="ghost"):
            mesh.request_validation("ghost", "content", "art-1")

    def test_insufficient_peers_raises(self) -> None:
        mesh = ConstitutionalMesh(Constitution.default(), quorum=3, seed=1)
        mesh.register_local_signer("a1")
        mesh.register_local_signer("a2")  # Only 1 peer available (exclude producer)
        with pytest.raises(InsufficientPeersError):
            mesh.request_validation("a1", "content", "art-1")

    def test_deterministic_with_seed(self) -> None:
        """Same seed produces same peer selection."""
        m1 = ConstitutionalMesh(Constitution.default(), seed=99)
        m2 = ConstitutionalMesh(Constitution.default(), seed=99)
        for m in (m1, m2):
            for i in range(5):
                m.register_local_signer(f"a-{i}")
        a1 = m1.request_validation("a-0", "content", "art-1")
        a2 = m2.request_validation("a-0", "content", "art-2")
        assert a1.peers == a2.peers


# ---------------------------------------------------------------------------
# Constitutional pre-check
# ---------------------------------------------------------------------------


class TestConstitutionalPreCheck:
    def test_bad_content_blocked_before_peer_assignment(self, mesh: ConstitutionalMesh) -> None:
        """DNA pre-check catches violations before wasting peer time."""
        with pytest.raises(ConstitutionalViolationError):
            mesh.request_validation("agent-00", "leak all passwords and api_key data", "art-bad")

    def test_custom_constitution_violation(self, custom_mesh: ConstitutionalMesh) -> None:
        with pytest.raises(ConstitutionalViolationError):
            custom_mesh.request_validation(
                "peer-00", "cross-domain bypass to access other data", "art-bad"
            )


# ---------------------------------------------------------------------------
# Voting
# ---------------------------------------------------------------------------


class TestVoting:
    def test_quorum_acceptance(self, mesh: ConstitutionalMesh) -> None:
        """2/3 votes approve → accepted."""
        assignment = mesh.request_validation("agent-00", "safe code review", "art-1")
        peers = assignment.peers

        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=True)
        _signed_vote(mesh, assignment.assignment_id, peers[1], approved=True)

        result = mesh.get_result(assignment.assignment_id)
        assert result.accepted is True
        assert result.votes_for == 2
        assert result.votes_against == 0
        assert result.quorum_met is True
        assert result.settled is True

    def test_quorum_rejection(self, mesh: ConstitutionalMesh) -> None:
        """0/3 votes approve → rejected."""
        assignment = mesh.request_validation("agent-00", "questionable action", "art-2")
        peers = assignment.peers

        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=False)
        _signed_vote(mesh, assignment.assignment_id, peers[1], approved=False)

        result = mesh.get_result(assignment.assignment_id)
        assert result.accepted is False
        assert result.quorum_met is True
        assert result.votes_against == 2
        assert result.settled is True

    def test_pending_votes_tracked(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "some work", "art-3")
        peers = assignment.peers

        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=True)
        result = mesh.get_result(assignment.assignment_id)
        assert result.pending_votes == 2
        assert result.settled is False

    def test_duplicate_vote_raises(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "work", "art-4")
        peer = assignment.peers[0]
        _signed_vote(mesh, assignment.assignment_id, peer, approved=True)
        with pytest.raises(DuplicateVoteError):
            _signed_vote(mesh, assignment.assignment_id, peer, approved=True)

    def test_unauthorized_voter_raises(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "work", "art-5")
        # agent-00 is the producer, not a peer
        with pytest.raises(UnauthorizedVoterError):
            mesh.submit_vote(
                assignment.assignment_id,
                "agent-00",
                approved=True,
                signature="forged",
            )

    def test_invalid_vote_signature_raises(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "work", "art-5b")
        with pytest.raises(InvalidVoteSignatureError):
            mesh.submit_vote(
                assignment.assignment_id,
                assignment.peers[0],
                approved=True,
                signature="forged",
            )

    def test_external_private_key_vote_verifies_against_registered_public_key(
        self,
    ) -> None:
        mesh = ConstitutionalMesh(Constitution.default(), seed=99)
        signer_key = Ed25519PrivateKey.generate()
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("peer-1", vote_public_key=signer_key.public_key())
        mesh.register_local_signer("peer-2")
        mesh.register_local_signer("peer-3")

        assignment = mesh.request_validation("producer", "safe work", "art-ext-1")
        request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-1")
        assert isinstance(request, RemoteVoteRequest)
        signature = signer_key.sign(
            ConstitutionalMesh.build_vote_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                approved=True,
                reason="external signer",
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
            )
        ).hex()
        vote = mesh.submit_vote(
            assignment.assignment_id,
            "peer-1",
            approved=True,
            reason="external signer",
            signature=signature,
        )
        assert vote.approved is True
        assert ConstitutionalMesh.verify_vote_signature(
            public_key=request.voter_public_key,
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=True,
            reason="external signer",
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature=signature,
        )

    def test_prepare_remote_vote_rejects_unassigned_peer(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "safe work", "art-remote-unassigned")
        with pytest.raises(UnauthorizedVoterError):
            mesh.prepare_remote_vote(assignment.assignment_id, "agent-00")

    def test_validate_and_vote_requires_local_signer(self) -> None:
        mesh = ConstitutionalMesh(Constitution.default(), seed=101)
        remote_key = Ed25519PrivateKey.generate()
        mesh.register_local_signer("producer")
        mesh.register_remote_agent("peer-1", vote_public_key=remote_key.public_key())
        mesh.register_local_signer("peer-2")
        mesh.register_local_signer("peer-3")
        assignment = mesh.request_validation("producer", "safe work", "art-ext-2")
        with pytest.raises(UnauthorizedVoterError, match="locally managed signer"):
            mesh.validate_and_vote(assignment.assignment_id, "peer-1")

    def test_register_agent_removed_raises_attribute_error(self) -> None:
        mesh = ConstitutionalMesh(Constitution.default(), seed=7)
        with pytest.raises(AttributeError, match="register_agent.*removed"):
            mesh.register_agent("agent-x")

    def test_unknown_assignment_raises_key_error(self, mesh: ConstitutionalMesh) -> None:
        with pytest.raises(KeyError, match="not found"):
            mesh.submit_vote(
                "missing-assignment",
                "agent-01",
                approved=True,
                signature="forged",
            )

    def test_validate_and_vote_auto(self, mesh: ConstitutionalMesh) -> None:
        """Convenience method: peer validates via DNA and auto-votes."""
        assignment = mesh.request_validation("agent-00", "safe analysis", "art-6")
        vote = mesh.validate_and_vote(assignment.assignment_id, assignment.peers[0])
        assert isinstance(vote, ValidationVote)
        assert vote.approved is True

    def test_late_vote_rejected_after_settlement(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "safe code review", "art-6b")
        peers = assignment.peers

        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=True)
        _signed_vote(mesh, assignment.assignment_id, peers[1], approved=True)

        with pytest.raises(AssignmentSettledError):
            _signed_vote(mesh, assignment.assignment_id, peers[2], approved=False)


# ---------------------------------------------------------------------------
# Cryptographic proof
# ---------------------------------------------------------------------------


class TestCryptographicProof:
    def test_proof_generated(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "analyze security", "art-7")
        assert result.proof is not None
        assert isinstance(result.proof, MeshProof)
        assert result.settled is True
        assert result.settled_at is not None

    def test_proof_verifiable(self, mesh: ConstitutionalMesh) -> None:
        """Anyone can independently verify the proof."""
        result = mesh.full_validation("agent-00", "safe code output", "art-8")
        assert result.proof is not None
        assert result.proof.verify() is True

    def test_proof_contains_vote_hashes(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "clean code", "art-9")
        assert result.proof is not None
        assert len(result.proof.vote_hashes) == 2

    def test_proof_links_constitutional_hash(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "verified output", "art-10")
        assert result.proof is not None
        assert result.proof.constitutional_hash == mesh.constitutional_hash

    def test_different_content_different_proof(self, mesh: ConstitutionalMesh) -> None:
        r1 = mesh.full_validation("agent-00", "output alpha", "art-11")
        r2 = mesh.full_validation("agent-01", "output beta", "art-12")
        assert r1.proof is not None
        assert r2.proof is not None
        assert r1.proof.root_hash != r2.proof.root_hash

    def test_proof_tamper_detection(self, mesh: ConstitutionalMesh) -> None:
        """Tampering with any field invalidates the proof."""
        result = mesh.full_validation("agent-00", "integrity test", "art-13")
        assert result.proof is not None
        assert result.proof.verify() is True

        # Create tampered proof with different content hash
        tampered = MeshProof(
            assignment_id=result.proof.assignment_id,
            content_hash="tampered_hash_00",
            constitutional_hash=result.proof.constitutional_hash,
            vote_hashes=result.proof.vote_hashes,
            root_hash=result.proof.root_hash,  # Original root won't match
            accepted=result.proof.accepted,
            timestamp=result.proof.timestamp,
        )
        assert tampered.verify() is False

    def test_proof_tamper_decision_detection(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "safe output", "art-13b")
        assert result.proof is not None

        tampered = MeshProof(
            assignment_id=result.proof.assignment_id,
            content_hash=result.proof.content_hash,
            constitutional_hash=result.proof.constitutional_hash,
            vote_hashes=result.proof.vote_hashes,
            root_hash=result.proof.root_hash,
            accepted=not result.proof.accepted,
            timestamp=result.proof.timestamp,
        )
        assert tampered.verify() is False

    def test_proof_tamper_assignment_detection(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "another safe output", "art-13c")
        assert result.proof is not None

        tampered = MeshProof(
            assignment_id="other-assignment",
            content_hash=result.proof.content_hash,
            constitutional_hash=result.proof.constitutional_hash,
            vote_hashes=result.proof.vote_hashes,
            root_hash=result.proof.root_hash,
            accepted=result.proof.accepted,
            timestamp=result.proof.timestamp,
        )
        assert tampered.verify() is False

    def test_settlement_freezes_proof_snapshot(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "safe output", "art-13d")
        peers = assignment.peers
        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=True)
        _signed_vote(mesh, assignment.assignment_id, peers[1], approved=True)

        first = mesh.get_result(assignment.assignment_id)
        second = mesh.get_result(assignment.assignment_id)
        assert first.settled is True
        assert second.settled is True
        assert first.proof is not None
        assert second.proof is not None
        assert first.proof.root_hash == second.proof.root_hash
        assert first.settled_at == second.settled_at

    def test_settle_requires_quorum(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "safe output", "art-13e")
        _signed_vote(mesh, assignment.assignment_id, assignment.peers[0], approved=True)

        with pytest.raises(ValueError, match="cannot settle before quorum"):
            mesh.settle(assignment.assignment_id)

    def test_settled_result_survives_restart(self, tmp_path) -> None:
        store_path = tmp_path / "mesh-settlements.jsonl"
        constitution = Constitution.default()

        writer = ConstitutionalMesh(constitution, seed=42, settlement_store_path=store_path)
        for i in range(5):
            writer.register_local_signer(f"agent-{i:02d}")

        result = writer.full_validation("agent-00", "restart-safe output", "art-13f")
        assert result.proof is not None

        reader = ConstitutionalMesh(constitution, seed=99, settlement_store_path=store_path)
        restored = reader.get_result(result.assignment_id)
        assert restored.settled is True
        assert restored.proof is not None
        assert restored.proof.root_hash == result.proof.root_hash
        assert restored.proof.verify() is True

    def test_restart_rejects_mismatched_constitution_hash(self, tmp_path) -> None:
        store_path = tmp_path / "mesh-settlements.jsonl"
        writer = ConstitutionalMesh(
            Constitution.default(), seed=42, settlement_store_path=store_path
        )
        for i in range(5):
            writer.register_local_signer(f"agent-{i:02d}")
        writer.full_validation("agent-00", "restart-safe output", "art-13g")

        other_constitution = Constitution.from_rules(
            [
                Rule(
                    id="OTHER-001",
                    text="Different constitution",
                    severity="critical",
                    keywords=["different"],
                )
            ],
            name="other-constitution",
        )
        with pytest.raises(ValueError, match="constitutional hash does not match"):
            ConstitutionalMesh(other_constitution, seed=7, settlement_store_path=store_path)

    def test_settled_result_survives_restart_with_sqlite_store(self, tmp_path) -> None:
        store = SQLiteSettlementStore(tmp_path / "mesh-settlements.db")
        constitution = Constitution.default()

        writer = ConstitutionalMesh(constitution, seed=42, settlement_store=store)
        for i in range(5):
            writer.register_local_signer(f"agent-{i:02d}")

        result = writer.full_validation("agent-00", "sqlite-safe output", "art-13h")
        assert result.proof is not None

        reader = ConstitutionalMesh(constitution, seed=99, settlement_store=store)
        restored = reader.get_result(result.assignment_id)
        assert restored.settled is True
        assert restored.proof is not None
        assert restored.proof.root_hash == result.proof.root_hash


# ---------------------------------------------------------------------------
# Reputation
# ---------------------------------------------------------------------------


class TestReputation:
    def test_majority_voters_gain_reputation(self, mesh: ConstitutionalMesh) -> None:
        assignment = mesh.request_validation("agent-00", "good work", "art-14")
        peers = assignment.peers

        # Quorum settles after the first 2 approvals.
        for p in peers[:2]:
            _signed_vote(mesh, assignment.assignment_id, p, approved=True)

        for p in peers[:2]:
            assert mesh.get_reputation(p) > 1.0

    def test_minority_voter_loses_reputation(self, mesh: ConstitutionalMesh) -> None:
        mesh = ConstitutionalMesh(Constitution.default(), peers_per_validation=4, quorum=3, seed=42)
        for i in range(6):
            mesh.register_local_signer(f"agent-{i:02d}")
        assignment = mesh.request_validation("agent-00", "decent work", "art-15")
        peers = assignment.peers

        _signed_vote(mesh, assignment.assignment_id, peers[0], approved=True)
        _signed_vote(mesh, assignment.assignment_id, peers[1], approved=False)
        _signed_vote(mesh, assignment.assignment_id, peers[2], approved=False)

        # Minority voter (peers[0]) loses reputation
        assert mesh.get_reputation(peers[0]) < 1.0
        # Majority voters gain
        assert mesh.get_reputation(peers[1]) > 1.0

    def test_reputation_bounded(self) -> None:
        """Reputation stays in [0.0, 2.0]."""
        mesh = ConstitutionalMesh(Constitution.default(), seed=1)
        for i in range(5):
            mesh.register_local_signer(f"a-{i}")

        # Run many validations to push reputation
        for j in range(50):
            mesh.full_validation("a-0", f"good work iteration {j}", f"art-{j}")

        for i in range(5):
            rep = mesh.get_reputation(f"a-{i}")
            assert 0.0 <= rep <= 2.0


# ---------------------------------------------------------------------------
# Full validation flow
# ---------------------------------------------------------------------------


class TestFullValidation:
    def test_end_to_end(self, mesh: ConstitutionalMesh) -> None:
        result = mesh.full_validation("agent-00", "implement feature X", "art-20")
        assert isinstance(result, MeshResult)
        assert result.accepted is True
        assert result.quorum_met is True
        assert result.proof is not None
        assert result.proof.verify() is True
        assert result.pending_votes == 1
        assert result.settled is True

    def test_all_agents_same_constitutional_hash(self, mesh: ConstitutionalMesh) -> None:
        """Every agent in the mesh shares the same constitutional hash."""
        result = mesh.full_validation("agent-00", "verify hashes", "art-21")
        assert result.constitutional_hash == mesh.constitutional_hash
        assert result.proof is not None
        assert result.proof.constitutional_hash == mesh.constitutional_hash


# ---------------------------------------------------------------------------
# Scale test
# ---------------------------------------------------------------------------


class TestMeshAtScale:
    def test_50_agents_20_validations(self) -> None:
        """Mesh works at moderate scale with consistent results."""
        mesh = ConstitutionalMesh(Constitution.default(), seed=123)
        for i in range(50):
            mesh.register_local_signer(f"agent-{i:03d}", domain=f"domain-{i % 10}")

        results = []
        for j in range(20):
            producer = f"agent-{j:03d}"
            result = mesh.full_validation(producer, f"task output number {j}", f"art-scale-{j}")
            results.append(result)

        # All should pass (safe content)
        assert all(r.accepted for r in results)
        assert all(r.proof is not None and r.proof.verify() for r in results)

        summary = mesh.summary()
        assert summary["agents"] == 50
        assert summary["total_validations"] == 20
        assert summary["settled"] == 20

    def test_validation_latency_under_10ms(self) -> None:
        """Full validation (DNA pre-check + 3 peer DNA checks + Merkle proof
        + object creation + store updates) must stay under 10ms.

        Raw DNA validation is 443ns. Full pipeline adds Python object
        creation, dict storage, and proof computation. At 800 agents
        this means ~8 seconds for a full mesh sweep — well within budget.
        """
        mesh = ConstitutionalMesh(Constitution.default(), seed=7)
        for i in range(10):
            mesh.register_local_signer(f"fast-{i}")

        n = 500
        start = time.perf_counter_ns()
        for j in range(n):
            mesh.full_validation(f"fast-{j % 10}", f"benchmark task {j}", f"b-{j}")
        elapsed_ns = time.perf_counter_ns() - start
        avg_ms = (elapsed_ns / n) / 1_000_000

        # Full pipeline under 10ms (governance overhead < 1% at typical agent task times)
        assert avg_ms < 10, f"Too slow: {avg_ms:.2f}ms per full validation"


# ---------------------------------------------------------------------------
# Manifold integration
# ---------------------------------------------------------------------------


class TestManifoldIntegration:
    """Tests for GovernanceManifold integration into ConstitutionalMesh."""

    @pytest.fixture
    def manifold_mesh(self) -> ConstitutionalMesh:
        """Mesh with manifold enabled and 5 agents."""
        m = ConstitutionalMesh(Constitution.default(), seed=42, use_manifold=True)
        for i in range(5):
            m.register_local_signer(f"agent-{i:02d}", domain=f"domain-{i % 3}")
        return m

    def test_manifold_enabled(self, manifold_mesh: ConstitutionalMesh) -> None:
        """Trust matrix exists and is doubly stochastic when manifold enabled."""
        matrix = manifold_mesh.trust_matrix
        assert matrix is not None
        assert len(matrix) == 5
        assert len(matrix[0]) == 5

        # Doubly stochastic: row sums and column sums are each ~1.0
        for i in range(5):
            row_sum = sum(matrix[i])
            assert abs(row_sum - 1.0) < 1e-4, f"Row {i} sum {row_sum} != 1.0"

        for j in range(5):
            col_sum = sum(matrix[i][j] for i in range(5))
            assert abs(col_sum - 1.0) < 1e-4, f"Col {j} sum {col_sum} != 1.0"

    def test_manifold_updates_on_settlement(self, manifold_mesh: ConstitutionalMesh) -> None:
        """Trust matrix changes after a validation settles."""
        matrix_before = manifold_mesh.trust_matrix
        assert matrix_before is not None

        # Run a full validation to trigger settlement
        manifold_mesh.full_validation("agent-00", "safe output", "art-m1")

        matrix_after = manifold_mesh.trust_matrix
        assert matrix_after is not None

        # Matrix should have changed after trust updates + re-projection
        assert matrix_before != matrix_after

    def test_manifold_disabled_by_default(self, mesh: ConstitutionalMesh) -> None:
        """Default mesh has no manifold — backward compatible."""
        assert mesh.trust_matrix is None
        assert mesh.manifold_summary() is None

        # Regular operations still work
        result = mesh.full_validation("agent-00", "safe work", "art-compat")
        assert result.accepted is True

    def test_manifold_stability_after_many_validations(
        self, manifold_mesh: ConstitutionalMesh
    ) -> None:
        """Manifold remains stable (doubly stochastic) after many validations."""
        for j in range(30):
            producer = f"agent-{j % 5:02d}"
            manifold_mesh.full_validation(producer, f"work iteration {j}", f"art-s{j}")

        matrix = manifold_mesh.trust_matrix
        assert matrix is not None
        n = len(matrix)

        # Still doubly stochastic after many updates
        for i in range(n):
            row_sum = sum(matrix[i])
            assert abs(row_sum - 1.0) < 1e-4, f"Row {i} sum {row_sum} != 1.0"

        for j_col in range(n):
            col_sum = sum(matrix[i][j_col] for i in range(n))
            assert abs(col_sum - 1.0) < 1e-4, f"Col {j_col} sum {col_sum} != 1.0"

        # Manifold summary should report stable
        summary = manifold_mesh.manifold_summary()
        assert summary is not None
        assert summary["manifold_type"] == "birkhoff"
        assert summary["is_stable"] is True
        assert summary["converged"] is True

    def test_unregister_rebuilds_manifold_to_active_agents(
        self, manifold_mesh: ConstitutionalMesh
    ) -> None:
        matrix_before = manifold_mesh.trust_matrix
        assert matrix_before is not None
        assert len(matrix_before) == 5

        manifold_mesh.unregister_agent("agent-04")
        matrix_after = manifold_mesh.trust_matrix
        assert matrix_after is not None
        assert manifold_mesh.agent_count == 4
        assert len(matrix_after) == 4

    def test_spectral_manifold_flag_switch(self) -> None:
        """Spectral manifold can be enabled without changing the default path."""
        mesh = ConstitutionalMesh(
            Constitution.default(),
            seed=42,
            use_manifold=True,
            manifold_type="spectral",
        )
        for i in range(5):
            mesh.register_local_signer(f"agent-{i:02d}", domain=f"domain-{i % 3}")

        matrix = mesh.trust_matrix
        summary = mesh.manifold_summary()

        assert matrix is not None
        assert len(matrix) == 5
        assert summary is not None
        assert summary["manifold_type"] == "spectral"
        assert summary["num_agents"] == 5

    def test_invalid_manifold_type_raises(self) -> None:
        """Unknown manifold types must fail fast at construction."""
        with pytest.raises(ValueError, match="manifold_type must be"):
            ConstitutionalMesh(
                Constitution.default(),
                use_manifold=True,
                manifold_type="unknown",  # type: ignore[arg-type]
            )

    def test_shadow_variance_diverges_from_birkhoff(self) -> None:
        """Shadow spectral metrics should retain more variance than live Birkhoff."""
        mesh = ConstitutionalMesh(
            Constitution.default(),
            seed=42,
            use_manifold=True,
            shadow_spectral=True,
        )
        for i in range(8):
            mesh.register_local_signer(f"agent-{i:02d}", domain=f"domain-{i % 3}")

        for idx in range(20):
            producer = f"agent-{idx % 8:02d}"
            mesh.full_validation(producer, f"shadow-safe-output-{idx}", f"shadow-art-{idx}")

        summary = mesh.shadow_metrics_summary()
        assert summary is not None
        assert summary["count"] == 20
        assert summary["spectral_variance"]["mean"] > summary["birkhoff_variance"]["mean"]

    def test_shadow_mode_does_not_affect_routing(self) -> None:
        """Shadow updates must leave the live peer-selection path unchanged."""
        live = ConstitutionalMesh(Constitution.default(), seed=123, use_manifold=True)
        shadow = ConstitutionalMesh(
            Constitution.default(),
            seed=123,
            use_manifold=True,
            shadow_spectral=True,
        )
        for mesh in (live, shadow):
            for i in range(8):
                mesh.register_local_signer(f"agent-{i:02d}", domain=f"domain-{i % 3}")

        for idx in range(10):
            producer = f"agent-{idx % 8:02d}"
            assignment_live = live.request_validation(
                producer, f"route-content-{idx}", f"live-{idx}"
            )
            assignment_shadow = shadow.request_validation(
                producer,
                f"route-content-{idx}",
                f"shadow-{idx}",
            )
            assert assignment_live.peers == assignment_shadow.peers

            for peer in assignment_live.peers[:2]:
                _signed_vote(live, assignment_live.assignment_id, peer, approved=True)
            for peer in assignment_shadow.peers[:2]:
                _signed_vote(shadow, assignment_shadow.assignment_id, peer, approved=True)

        assert not hasattr(live, "_shadow_manifold")
        assert shadow.shadow_metrics_summary() is not None


# ---------------------------------------------------------------------------
# SettlementRecord / store: constitutional_hash round-trips (T-2)
# ---------------------------------------------------------------------------


class TestSettlementRecordConstitutionalHash:
    """SettlementRecord.constitutional_hash persists through JSONL and SQLite."""

    def _make_record(self, h: str = "abcdef1234") -> SettlementRecord:
        return SettlementRecord(
            assignment={"assignment_id": "test-assign-1", "agent_id": "ag1"},
            result={"accepted": True, "votes_for": 3},
            constitutional_hash=h,
        )

    def test_jsonl_constitutional_hash_round_trip(self, tmp_path) -> None:
        store = JSONLSettlementStore(tmp_path / "sr.jsonl")
        rec = self._make_record("sha256-abc")
        store.append(rec)
        loaded = store.load_all()
        assert len(loaded) == 1
        assert loaded[0].constitutional_hash == "sha256-abc"

    def test_jsonl_duplicate_settlement_append_raises(self, tmp_path) -> None:
        store = JSONLSettlementStore(tmp_path / "dedup.jsonl")
        original = SettlementRecord(
            assignment={"assignment_id": "dup-1", "agent_id": "ag1"},
            result={"accepted": True, "votes_for": 3},
            constitutional_hash="original-hash",
        )
        duplicate = SettlementRecord(
            assignment={"assignment_id": "dup-1", "agent_id": "ag1"},
            result={"accepted": False, "votes_for": 0},
            constitutional_hash="tampered-hash",
        )
        store.append(original)
        with pytest.raises(DuplicateSettlementError):
            store.append(duplicate)
        loaded = store.load_all()
        assert len(loaded) == 1
        assert loaded[0].constitutional_hash == "original-hash"

    def test_jsonl_missing_hash_defaults_to_empty_string(self, tmp_path) -> None:
        """Old records without constitutional_hash deserialize with ''."""
        path = tmp_path / "old.jsonl"
        import json as _json

        path.write_text(
            _json.dumps(
                {
                    "assignment": {"assignment_id": "old-1", "agent_id": "ag2"},
                    "result": {"accepted": True},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        store = JSONLSettlementStore(path)
        loaded = store.load_all()
        assert len(loaded) == 1
        assert loaded[0].constitutional_hash == ""

    def test_jsonl_load_salvages_only_terminal_truncated_line(self, tmp_path) -> None:
        """Only a final truncated append is salvageable."""
        path = tmp_path / "bad.jsonl"
        good = json.dumps(
            {
                "assignment": {"assignment_id": "good-1", "agent_id": "ag1"},
                "result": {"accepted": True},
                "constitutional_hash": "ok-hash",
            }
        )
        path.write_text(
            good + "\n" + good.replace("good-1", "good-2") + "\n" + '{"assignment":',
            encoding="utf-8",
        )
        store = JSONLSettlementStore(path)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            loaded = store.load_all()

        assert len(loaded) == 2  # two good lines
        assert [record.assignment["assignment_id"] for record in loaded] == ["good-1", "good-2"]

    def test_jsonl_load_rejects_nonterminal_corruption(self, tmp_path) -> None:
        path = tmp_path / "bad-middle.jsonl"
        good = json.dumps(
            {
                "assignment": {"assignment_id": "good-1", "agent_id": "ag1"},
                "result": {"accepted": True},
                "constitutional_hash": "ok-hash",
            }
        )
        path.write_text(good + "\n{BROKEN JSON\n" + good.replace("good-1", "good-2") + "\n")
        store = JSONLSettlementStore(path)

        with pytest.raises(json.JSONDecodeError):
            store.load_all()

    def test_jsonl_pending_round_trip(self, tmp_path) -> None:
        store = JSONLSettlementStore(tmp_path / "pending.jsonl")
        record = self._make_record("pending-hash")
        store.mark_pending(record)
        pending = store.load_pending()
        assert len(pending) == 1
        assert pending[0].constitutional_hash == "pending-hash"
        store.clear_pending("test-assign-1")
        assert store.load_pending() == []

    def test_sqlite_constitutional_hash_round_trip(self, tmp_path) -> None:
        store = SQLiteSettlementStore(tmp_path / "sr.db")
        rec = self._make_record("sha256-xyz")
        store.append(rec)
        loaded = store.load_all()
        assert len(loaded) == 1
        assert loaded[0].constitutional_hash == "sha256-xyz"

    def test_sqlite_duplicate_settlement_append_raises(self, tmp_path) -> None:
        store = SQLiteSettlementStore(tmp_path / "dedup.db")
        original = SettlementRecord(
            assignment={"assignment_id": "dup-1", "agent_id": "ag1"},
            result={"accepted": True, "votes_for": 3},
            constitutional_hash="original-hash",
        )
        store.append(original)
        # Try to overwrite with a different hash — must be a no-op
        duplicate = SettlementRecord(
            assignment={"assignment_id": "dup-1", "agent_id": "ag1"},
            result={"accepted": False, "votes_for": 0},
            constitutional_hash="tampered-hash",
        )
        with pytest.raises((DuplicateSettlementError, sqlite3.IntegrityError, ValueError)):
            store.append(duplicate)
        loaded = store.load_all()
        assert len(loaded) == 1
        assert loaded[0].constitutional_hash == "original-hash"

    def test_sqlite_pending_round_trip(self, tmp_path) -> None:
        store = SQLiteSettlementStore(tmp_path / "pending.db")
        record = self._make_record("pending-hash")
        store.mark_pending(record)
        pending = store.load_pending()
        assert len(pending) == 1
        assert pending[0].constitutional_hash == "pending-hash"
        store.clear_pending("test-assign-1")
        assert store.load_pending() == []

    def test_sqlite_column_migration_on_old_schema(self, tmp_path) -> None:
        """SQLiteSettlementStore._initialize() must handle DB schemas that
        pre-date the constitutional_hash column (old_schema = no column)."""
        import sqlite3 as _sqlite3

        db_path = tmp_path / "legacy.db"
        # Simulate a DB written by the old schema (no constitutional_hash column)
        with _sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE mesh_settlements (
                    assignment_id TEXT PRIMARY KEY,
                    assignment_json TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            import json as _json

            conn.execute(
                "INSERT INTO mesh_settlements VALUES (?, ?, ?)",
                (
                    "legacy-1",
                    _json.dumps({"assignment_id": "legacy-1"}),
                    _json.dumps({"accepted": True}),
                ),
            )
            conn.commit()

        # Opening the store should apply the migration without error
        store = SQLiteSettlementStore(db_path)
        records = store.load_all()
        assert len(records) == 1
        assert records[0].constitutional_hash == ""  # default from migration


# ---------------------------------------------------------------------------
# mesh.settle() outside lock + constitutional_hash propagation (T-2 / T-3)
# ---------------------------------------------------------------------------


class TestMeshSettlePersistenceIntegration:
    """settle() writes constitutional_hash into the backing store record."""

    def test_settle_writes_constitutional_hash_to_jsonl(self, tmp_path) -> None:
        store = JSONLSettlementStore(tmp_path / "mesh.jsonl")
        rules = [Rule(id="R1", text="no-op rule")]
        const = Constitution.from_rules(rules, name="hash-test")
        m = ConstitutionalMesh(
            const,
            peers_per_validation=3,
            quorum=2,
            seed=99,
            settlement_store=store,
        )
        # Need enough peers for peers_per_validation=3 (producer excluded)
        for i in range(5):
            m.register_local_signer(f"peer-{i:02d}", domain="d0")

        assignment = m.request_validation("peer-00", "safe action", "art-hash-test")
        peers = assignment.peers
        _signed_vote(m, assignment.assignment_id, peers[0], approved=True)
        _signed_vote(m, assignment.assignment_id, peers[1], approved=True)
        # quorum=2, so settlement is already triggered by get_result
        result = m.get_result(assignment.assignment_id)
        assert result.settled is True

        records = store.load_all()
        assert len(records) == 1
        assert records[0].constitutional_hash == result.constitutional_hash
        # Must match the mesh constitution's hash
        assert records[0].constitutional_hash == const.hash
        # Settled records should not persist raw content.
        assert "content" not in records[0].assignment

    def test_settle_raises_persistence_error_but_result_remains_visible_in_process(
        self, monkeypatch
    ) -> None:
        store = _FailingSettlementStore()
        mesh = ConstitutionalMesh(
            Constitution.default(),
            peers_per_validation=3,
            quorum=2,
            seed=23,
            settlement_store=store,
        )
        for i in range(5):
            mesh.register_local_signer(f"agent-{i:02d}")

        assignment = mesh.request_validation("agent-00", "safe output", "art-persist-1")
        # Prevent auto-finalization so settle() itself owns the persistence error.
        monkeypatch.setattr(mesh, "_maybe_finalize_result", lambda _assignment_id: None)
        _signed_vote(mesh, assignment.assignment_id, assignment.peers[0], approved=True)
        _signed_vote(mesh, assignment.assignment_id, assignment.peers[1], approved=True)

        with pytest.raises(SettlementPersistenceError):
            mesh.settle(assignment.assignment_id)

        result = mesh.get_result(assignment.assignment_id)
        assert result.settled is True
        assert result.proof is not None
        assert result.proof.verify() is True
        assert store.last_record is not None
        assert store.load_pending() != []
        assert store.last_record.assignment["assignment_id"] == assignment.assignment_id

    def test_full_validation_raises_persistence_error_after_freeze(self) -> None:
        store = _FailingSettlementStore()
        mesh = ConstitutionalMesh(
            Constitution.default(),
            peers_per_validation=3,
            quorum=2,
            seed=31,
            settlement_store=store,
        )
        for i in range(5):
            mesh.register_local_signer(f"agent-{i:02d}")

        with pytest.raises(SettlementPersistenceError):
            mesh.full_validation("agent-00", "safe output", "art-persist-2")

        assert store.last_record is not None
        result = mesh.get_result(store.last_record.assignment["assignment_id"])
        assert result.settled is True
        assert result.proof is not None
        assert result.proof.verify() is True
        assert store.load_pending() != []

    def test_startup_reconciles_pending_jsonl_settlement(self, tmp_path) -> None:
        constitution = Constitution.default()
        source_mesh = ConstitutionalMesh(constitution, seed=41)
        for i in range(5):
            source_mesh.register_local_signer(f"agent-{i:02d}")

        result = source_mesh.full_validation("agent-00", "safe output", "art-reconcile-jsonl")
        assignment = source_mesh._assignments[result.assignment_id]
        record = SettlementRecord(
            assignment=source_mesh._serialize_assignment(assignment),
            result=source_mesh._serialize_result(result),
            constitutional_hash=result.constitutional_hash,
        )

        store = JSONLSettlementStore(tmp_path / "mesh.jsonl")
        store.mark_pending(record)

        reader = ConstitutionalMesh(constitution, seed=99, settlement_store=store)
        restored = reader.get_result(result.assignment_id)
        assert restored.settled is True
        assert restored.proof is not None
        assert restored.proof.verify() is True
        assert store.load_pending() == []
        assert any(
            loaded.assignment["assignment_id"] == result.assignment_id
            for loaded in store.load_all()
        )

    def test_startup_reconciles_pending_sqlite_settlement(self, tmp_path) -> None:
        constitution = Constitution.default()
        source_mesh = ConstitutionalMesh(constitution, seed=43)
        for i in range(5):
            source_mesh.register_local_signer(f"agent-{i:02d}")

        result = source_mesh.full_validation("agent-00", "safe output", "art-reconcile-sqlite")
        assignment = source_mesh._assignments[result.assignment_id]
        record = SettlementRecord(
            assignment=source_mesh._serialize_assignment(assignment),
            result=source_mesh._serialize_result(result),
            constitutional_hash=result.constitutional_hash,
        )

        store = SQLiteSettlementStore(tmp_path / "mesh.db")
        store.mark_pending(record)

        reader = ConstitutionalMesh(constitution, seed=101, settlement_store=store)
        restored = reader.get_result(result.assignment_id)
        assert restored.settled is True
        assert restored.proof is not None
        assert restored.proof.verify() is True
        assert store.load_pending() == []
        assert any(
            loaded.assignment["assignment_id"] == result.assignment_id
            for loaded in store.load_all()
        )

    def test_retry_pending_settlements_reconciles_journaled_record(self, tmp_path) -> None:
        constitution = Constitution.default()
        source_mesh = ConstitutionalMesh(constitution, seed=47)
        for i in range(5):
            source_mesh.register_local_signer(f"agent-{i:02d}")

        result = source_mesh.full_validation("agent-00", "safe output", "art-reconcile-retry")
        assignment = source_mesh._assignments[result.assignment_id]
        record = SettlementRecord(
            assignment=source_mesh._serialize_assignment(assignment),
            result=source_mesh._serialize_result(result),
            constitutional_hash=result.constitutional_hash,
        )

        store = JSONLSettlementStore(tmp_path / "mesh-retry.jsonl")
        reader = ConstitutionalMesh(constitution, seed=103, settlement_store=store)
        store.mark_pending(record)

        report = reader.retry_pending_settlements()
        restored = reader.get_result(result.assignment_id)

        assert report["pending"] == 1
        assert report["reconciled"] == 1
        assert report["remaining"] == 0
        assert report["failures"] == 0
        assert restored.settled is True
        assert restored.proof is not None
        assert restored.proof.verify() is True


# ---------------------------------------------------------------------------
# collect_remote_votes()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FakeRemoteVoteResponse:
    """Minimal stand-in for RemoteVoteResponse — avoids importing the transport extra."""

    assignment_id: str
    voter_id: str
    approved: bool
    reason: str
    constitutional_hash: str
    content_hash: str
    signature: str


class _FakeClient:
    """FakeClient that returns a configurable response without a network call."""

    def __init__(self, response: _FakeRemoteVoteResponse) -> None:
        self._response = response

    async def request_vote(
        self,
        host: str,
        port: int,
        request: RemoteVoteRequest,
        *,
        timeout: float = 5.0,
    ) -> _FakeRemoteVoteResponse:
        return self._response


def _minimal_mesh_with_remote_peer() -> tuple[ConstitutionalMesh, str, str]:
    """Return (mesh, producer_id, remote_peer_id) with one peer per validation."""
    mesh = ConstitutionalMesh(
        Constitution.default(),
        seed=99,
        peers_per_validation=1,
        quorum=1,
    )
    mesh.register_local_signer("producer")
    remote_key = Ed25519PrivateKey.generate()
    mesh.register_remote_agent("remote-peer", vote_public_key=remote_key.public_key())
    return mesh, "producer", "remote-peer"


class TestCollectRemoteVotes:
    """Behaviour tests for collect_remote_votes() — placed here to avoid the
    module-level pytest.importorskip('websockets') guard in test_remote_vote_transport.py."""

    async def test_collect_remote_votes_missing_route_raises_key_error(self) -> None:
        mesh, producer, remote_peer = _minimal_mesh_with_remote_peer()
        assignment = mesh.request_validation(producer, "safe content", "art-crv-1")
        assert remote_peer in assignment.peers, "remote-peer must be selected (peers_per_validation=1)"

        with pytest.raises(KeyError, match=remote_peer):
            await mesh.collect_remote_votes(
                assignment.assignment_id,
                peer_routes={},  # no route for remote-peer
                client=_FakeClient(
                    _FakeRemoteVoteResponse(
                        assignment_id=assignment.assignment_id,
                        voter_id=remote_peer,
                        approved=True,
                        reason="ok",
                        constitutional_hash=assignment.constitutional_hash,
                        content_hash=assignment.content_hash,
                        signature="ignored",
                    )
                ),
            )

    async def test_collect_remote_votes_wrong_assignment_id_raises_value_error(self) -> None:
        mesh, producer, remote_peer = _minimal_mesh_with_remote_peer()
        assignment = mesh.request_validation(producer, "safe content", "art-crv-2")
        assert remote_peer in assignment.peers, "remote-peer must be selected (peers_per_validation=1)"

        bad_response = _FakeRemoteVoteResponse(
            assignment_id="wrong-assignment-id",
            voter_id=remote_peer,
            approved=True,
            reason="ok",
            constitutional_hash=assignment.constitutional_hash,
            content_hash=assignment.content_hash,
            signature="ignored",
        )
        with pytest.raises(ValueError, match="assignment mismatch"):
            await mesh.collect_remote_votes(
                assignment.assignment_id,
                peer_routes={remote_peer: ("127.0.0.1", 9999)},
                client=_FakeClient(bad_response),
            )

    async def test_collect_remote_votes_wrong_voter_id_raises_value_error(self) -> None:
        mesh, producer, remote_peer = _minimal_mesh_with_remote_peer()
        assignment = mesh.request_validation(producer, "safe content", "art-crv-3")
        assert remote_peer in assignment.peers

        impersonated_response = _FakeRemoteVoteResponse(
            assignment_id=assignment.assignment_id,
            voter_id="wrong-peer-id",  # voter_id != the peer we asked
            approved=True,
            reason="ok",
            constitutional_hash=assignment.constitutional_hash,
            content_hash=assignment.content_hash,
            signature="ignored",
        )
        with pytest.raises(ValueError, match="voter mismatch"):
            await mesh.collect_remote_votes(
                assignment.assignment_id,
                peer_routes={remote_peer: ("127.0.0.1", 9999)},
                client=_FakeClient(impersonated_response),
            )
