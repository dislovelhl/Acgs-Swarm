"""Freeze the stable eager façade and selected lazy compatibility imports.

Policy (docs/API_COMPATIBILITY.md):
- ``__all__`` is the stable eager façade.
- ``from constitutional_swarm import *`` is an intentional compatibility
  break relative to the pre-1.0.0 research-heavy star-import surface.
- Legacy names remain importable via lazy ``__getattr__`` and are not
  part of the stable façade.
"""

from __future__ import annotations

import constitutional_swarm

STABLE_FACADE = (
    "AgentDNA",
    "Artifact",
    "ArtifactStore",
    "AssignmentSettledError",
    "CANONICALIZATION_ALGORITHM",
    "Capability",
    "CapabilityRegistry",
    "CommitDecision",
    "CommitOutcome",
    "CommitRequest",
    "ConstitutionalMesh",
    "ContractStatus",
    "DAGCompiler",
    "DNADisabledError",
    "DuplicateSettlementError",
    "DuplicateVoteError",
    "ExecutionStatus",
    "GoalSpec",
    "GoalStep",
    "GCB_RECEIPT_PROFILE",
    "GovernanceBypassDenied",
    "GovernedCommitBoundary",
    "GovernedNodeState",
    "GovernedReceiptPayload",
    "GovernanceReceipt",
    "GovernanceReceiptBundle",
    "InsufficientPeersError",
    "InvalidVoteSignatureError",
    "JSONLSettlementStore",
    "MeshHaltedError",
    "MeshSnapshotStaleError",
    "MeshProof",
    "MeshResult",
    "PROFILE_VERSION",
    "PredecessorBinding",
    "PeerAssignment",
    "REQUIRED_ROLES",
    "ReceiptIssue",
    "ReceiptPayload",
    "ReconciliationReport",
    "RecoveredAssignmentError",
    "RemoteVoteReplayError",
    "RemoteVoteRequest",
    "RoleIdentity",
    "SQLiteSettlementStore",
    "SettlementPersistenceError",
    "SettlementRecord",
    "SettlementStore",
    "SignatureRecord",
    "SignedGovernedReceipt",
    "SwarmExecutor",
    "TaskContract",
    "TaskDAG",
    "TaskNode",
    "UnauthorizedVoterError",
    "ValidationVote",
    "ValidatorVote",
    "VerificationVerdict",
    "WorkReceipt",
    "build_receipt",
    "receipt_from_mesh_settlement",
    "settlement_canonical_digest",
    "bundle_from_json",
    "bundle_to_json",
    "canonical_json_bytes",
    "constitutional_dna",
    "payload_digest",
    "predecessor_root",
    "receipt_hash",
    "sign_governed_receipt",
    "verify_bundle",
    "verify_committed_settlement_receipt",
    "verdict_to_json",
)

LAZY_COMPAT = (
    "EvolutionLog",
    "MerkleCRDT",
    "MacAcgsLoop",
    "SpectralSphereManifold",
)


def test_all_is_the_stable_eager_facade() -> None:
    assert tuple(constitutional_swarm.__all__) == STABLE_FACADE


def test_star_import_surface_is_only_the_facade() -> None:
    namespace: dict[str, object] = {}
    exec("from constitutional_swarm import *", namespace)
    imported = {name for name in namespace if not name.startswith("_")}
    assert imported == set(STABLE_FACADE)
    assert "EvolutionLog" not in imported
    assert "MerkleCRDT" not in imported
    assert "MacAcgsLoop" not in imported


def test_lazy_compatibility_names_are_importable_but_not_in_all() -> None:
    for name in LAZY_COMPAT:
        assert name not in constitutional_swarm.__all__
        value = getattr(constitutional_swarm, name)
        assert getattr(value, "__name__", name) == name
