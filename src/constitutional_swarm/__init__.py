"""constitutional_swarm — orchestrator-free constitutional governance runtime.

Stable product surface (eager on ``import constitutional_swarm``):

  * local constitutional checks (``AgentDNA``)
  * DAG compilation and orchestrator-free execution
  * signed mesh voting and settlement
  * v0.1 local DSSE-shaped governance receipts

Research, eval, Bittensor, LangGraph, and benchmark modules remain available
via explicit submodule imports or the lazy compatibility ``__getattr__``
path. They are not part of the default import graph.

This package is not a compliance certificate, SCITT/Sigstore implementation,
or official SWE-bench result.
"""

from __future__ import annotations

import importlib
from typing import Any

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.compiler import DAGCompiler, GoalSpec, GoalStep
from constitutional_swarm.contract import ContractStatus, TaskContract
from constitutional_swarm.dna import AgentDNA, DNADisabledError, constitutional_dna
from constitutional_swarm.execution import ExecutionStatus, WorkReceipt
from constitutional_swarm.governance_receipts import (
    CANONICALIZATION_ALGORITHM,
    PROFILE_VERSION,
    REQUIRED_ROLES,
    GovernanceReceipt,
    GovernanceReceiptBundle,
    ReceiptIssue,
    ReceiptPayload,
    RoleIdentity,
    SignatureRecord,
    ValidatorVote,
    VerificationVerdict,
    build_receipt,
    receipt_from_mesh_settlement,
    settlement_canonical_digest,
    bundle_from_json,
    bundle_to_json,
    canonical_json_bytes,
    payload_digest,
    receipt_hash,
    verify_bundle,
    verdict_to_json,
)
from constitutional_swarm.governed_commit import (
    GCB_RECEIPT_PROFILE,
    CommitDecision,
    CommitOutcome,
    CommitRequest,
    GovernanceBypassDenied,
    GovernedCommitBoundary,
    GovernedNodeState,
    GovernedReceiptPayload,
    PredecessorBinding,
    SignedGovernedReceipt,
    predecessor_root,
    sign_governed_receipt,
)
from constitutional_swarm.mesh import (
    AssignmentSettledError,
    ConstitutionalMesh,
    DuplicateVoteError,
    InsufficientPeersError,
    InvalidVoteSignatureError,
    MeshHaltedError,
    MeshSnapshotStaleError,
    MeshProof,
    MeshResult,
    PeerAssignment,
    ReconciliationReport,
    RecoveredAssignmentError,
    RemoteVoteReplayError,
    RemoteVoteRequest,
    SettlementPersistenceError,
    UnauthorizedVoterError,
    ValidationVote,
)
from constitutional_swarm.settlement_evidence import (
    verify_committed_settlement_receipt,
)
from constitutional_swarm.settlement_store import (
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
    SettlementStore,
    SQLiteSettlementStore,
)
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

# Legacy names stay importable via ``__getattr__`` so existing callers and
# tests keep working. They are not loaded until first attribute access.
_LAZY_ATTRS: dict[str, tuple[str, str]] = {
    "AbliterationAdmissionGate": (
        "constitutional_swarm.node_admission",
        "AbliterationAdmissionGate",
    ),
    "ActivationAdmissionGate": (
        "constitutional_swarm.node_admission",
        "ActivationAdmissionGate",
    ),
    "ActivationProbe": ("constitutional_swarm.node_admission", "ActivationProbe"),
    "AdmissionDecision": ("constitutional_swarm.node_admission", "AdmissionDecision"),
    "AgentCredential": ("constitutional_swarm.federated_bridge", "AgentCredential"),
    "AmendmentProposal": ("constitutional_swarm.epoch_reconfig", "AmendmentProposal"),
    "BallotChoice": ("constitutional_swarm.private_vote", "BallotChoice"),
    "BenchmarkResult": ("constitutional_swarm.bench", "BenchmarkResult"),
    "CommitRecord": ("constitutional_swarm.private_vote", "CommitRecord"),
    "CommitteeSelection": ("constitutional_swarm.validator_set", "CommitteeSelection"),
    "CommitteeSelector": ("constitutional_swarm.validator_set", "CommitteeSelector"),
    "ConflictEvidence": ("constitutional_swarm.quorum_certificate", "ConflictEvidence"),
    "ConstitutionVersion": (
        "constitutional_swarm.epoch_reconfig",
        "ConstitutionVersion",
    ),
    "CredentialStatus": ("constitutional_swarm.federated_bridge", "CredentialStatus"),
    "DAGNode": ("constitutional_swarm.merkle_crdt", "DAGNode"),
    "DashboardRow": ("constitutional_swarm.evolution_log", "DashboardRow"),
    "DebateRecord": ("constitutional_swarm.debate_resolver", "DebateRecord"),
    "DebateResolver": ("constitutional_swarm.debate_resolver", "DebateResolver"),
    "DecelerationBlockedError": (
        "constitutional_swarm.evolution_log",
        "DecelerationBlockedError",
    ),
    "DecelerationRecord": ("constitutional_swarm.evolution_log", "DecelerationRecord"),
    "DimensionMismatchError": (
        "constitutional_swarm.violation_subspace",
        "DimensionMismatchError",
    ),
    "DoubleVoteError": ("constitutional_swarm.private_vote", "DoubleVoteError"),
    "DriftBudget": ("constitutional_swarm.epoch_reconfig", "DriftBudget"),
    "DriftBudgetExceeded": (
        "constitutional_swarm.epoch_reconfig",
        "DriftBudgetExceeded",
    ),
    "DuplicateRecordError": (
        "constitutional_swarm.evolution_log",
        "DuplicateRecordError",
    ),
    "EpochMismatchError": ("constitutional_swarm.epoch_reconfig", "EpochMismatchError"),
    "EvolutionLog": ("constitutional_swarm.evolution_log", "EvolutionLog"),
    "EvolutionViolationError": (
        "constitutional_swarm.evolution_log",
        "EvolutionViolationError",
    ),
    "FaultDomainPolicy": ("constitutional_swarm.validator_set", "FaultDomainPolicy"),
    "FederatedConstitutionBridge": (
        "constitutional_swarm.federated_bridge",
        "FederatedConstitutionBridge",
    ),
    "FederationDecision": (
        "constitutional_swarm.federated_bridge",
        "FederationDecision",
    ),
    "FinalVerdict": ("constitutional_swarm.debate_resolver", "FinalVerdict"),
    "GapRecord": ("constitutional_swarm.evolution_log", "GapRecord"),
    "GovernanceManifold": ("constitutional_swarm.manifold", "GovernanceManifold"),
    "InsufficientQuorumError": (
        "constitutional_swarm.quorum_certificate",
        "InsufficientQuorumError",
    ),
    "InsufficientSamplesError": (
        "constitutional_swarm.violation_subspace",
        "InsufficientSamplesError",
    ),
    "InvalidCertificateError": (
        "constitutional_swarm.quorum_certificate",
        "InvalidCertificateError",
    ),
    "InvalidCommitError": ("constitutional_swarm.private_vote", "InvalidCommitError"),
    "InvalidRevealError": ("constitutional_swarm.private_vote", "InvalidRevealError"),
    "InvalidTransitionError": (
        "constitutional_swarm.epoch_reconfig",
        "InvalidTransitionError",
    ),
    "JointQuorumNotMetError": (
        "constitutional_swarm.epoch_reconfig",
        "JointQuorumNotMetError",
    ),
    "LocalRemotePeer": (
        "constitutional_swarm.remote_vote_transport",
        "LocalRemotePeer",
    ),
    "MacAcgsConfig": ("constitutional_swarm.mac_acgs_loop", "MacAcgsConfig"),
    "MacAcgsCycleResult": ("constitutional_swarm.mac_acgs_loop", "MacAcgsCycleResult"),
    "MacAcgsLoop": ("constitutional_swarm.mac_acgs_loop", "MacAcgsLoop"),
    "ManifoldProjectionResult": (
        "constitutional_swarm.manifold",
        "ManifoldProjectionResult",
    ),
    "MerkleCRDT": ("constitutional_swarm.merkle_crdt", "MerkleCRDT"),
    "MissingPriorEpochError": (
        "constitutional_swarm.evolution_log",
        "MissingPriorEpochError",
    ),
    "MissingRevealError": ("constitutional_swarm.private_vote", "MissingRevealError"),
    "MutationBlockedError": (
        "constitutional_swarm.evolution_log",
        "MutationBlockedError",
    ),
    "NonIncreasingValueError": (
        "constitutional_swarm.evolution_log",
        "NonIncreasingValueError",
    ),
    "PrivacyAccountant": (
        "constitutional_swarm.privacy_accountant",
        "PrivacyAccountant",
    ),
    "PrivacyBudgetExhausted": (
        "constitutional_swarm.privacy_accountant",
        "PrivacyBudgetExhausted",
    ),
    "PrivateBallotBox": ("constitutional_swarm.private_vote", "PrivateBallotBox"),
    "PrivateTally": ("constitutional_swarm.private_vote", "PrivateTally"),
    "QuorumCertificate": (
        "constitutional_swarm.quorum_certificate",
        "QuorumCertificate",
    ),
    "RegressionRecord": ("constitutional_swarm.evolution_log", "RegressionRecord"),
    "RemoteVoteClient": (
        "constitutional_swarm.remote_vote_transport",
        "RemoteVoteClient",
    ),
    "RemoteVoteResponse": (
        "constitutional_swarm.remote_vote_transport",
        "RemoteVoteResponse",
    ),
    "RemoteVoteServer": (
        "constitutional_swarm.remote_vote_transport",
        "RemoteVoteServer",
    ),
    "RevealRecord": ("constitutional_swarm.private_vote", "RevealRecord"),
    "RiskAdaptiveSteering": (
        "constitutional_swarm.violation_subspace",
        "RiskAdaptiveSteering",
    ),
    "SignedVote": ("constitutional_swarm.quorum_certificate", "SignedVote"),
    "SpectralProjectionResult": (
        "constitutional_swarm.spectral_sphere",
        "SpectralProjectionResult",
    ),
    "SpectralSphereManifold": (
        "constitutional_swarm.spectral_sphere",
        "SpectralSphereManifold",
    ),
    "SwarmBenchmark": ("constitutional_swarm.bench", "SwarmBenchmark"),
    "SybilBoundViolation": (
        "constitutional_swarm.validator_set",
        "SybilBoundViolation",
    ),
    "TransitionCertificate": (
        "constitutional_swarm.epoch_reconfig",
        "TransitionCertificate",
    ),
    "ValidatorIdentity": ("constitutional_swarm.validator_set", "ValidatorIdentity"),
    "ValidatorSet": ("constitutional_swarm.validator_set", "ValidatorSet"),
    "VerdictOutcome": ("constitutional_swarm.debate_resolver", "VerdictOutcome"),
    "ViolationSubspace": (
        "constitutional_swarm.violation_subspace",
        "ViolationSubspace",
    ),
    "adversarial_score": (
        "constitutional_swarm.violation_subspace",
        "adversarial_score",
    ),
    "build_certificate": (
        "constitutional_swarm.quorum_certificate",
        "build_certificate",
    ),
    "build_commit": ("constitutional_swarm.private_vote", "build_commit"),
    "build_reveal": ("constitutional_swarm.private_vote", "build_reveal"),
    "build_vote_message": (
        "constitutional_swarm.quorum_certificate",
        "build_vote_message",
    ),
    "compute_nullifier": ("constitutional_swarm.private_vote", "compute_nullifier"),
    "compute_version_digest": (
        "constitutional_swarm.epoch_reconfig",
        "compute_version_digest",
    ),
    "detect_conflict": ("constitutional_swarm.quorum_certificate", "detect_conflict"),
    "evaluate_drift": ("constitutional_swarm.epoch_reconfig", "evaluate_drift"),
    "fit_leace": ("constitutional_swarm.violation_subspace", "fit_leace"),
    "fit_subspace": ("constitutional_swarm.violation_subspace", "fit_subspace"),
    "sinkhorn_knopp": ("constitutional_swarm.manifold", "sinkhorn_knopp"),
    "spectral_sphere_project": (
        "constitutional_swarm.spectral_sphere",
        "spectral_sphere_project",
    ),
    "tally": ("constitutional_swarm.private_vote", "tally"),
    "verify_certificate": (
        "constitutional_swarm.quorum_certificate",
        "verify_certificate",
    ),
    "verify_transition": ("constitutional_swarm.epoch_reconfig", "verify_transition"),
}

_LAZY_MODULES = frozenset(
    {
        "agent_self_evolve",
        "bench",
        "bittensor",
        "debate_resolver",
        "epoch_reconfig",
        "eval",
        "evolution_log",
        "federated_bridge",
        "forensic_benchmark",
        "governance_receipts",
        "governance_receipts_cli",
        "governance_receipts_dsse",
        "langgraph_runtime",
        "latent_dna",
        "mac_acgs_loop",
        "manifold",
        "merkle_crdt",
        "node_admission",
        "privacy_accountant",
        "private_vote",
        "protocol",
        "quorum_certificate",
        "remote_vote_transport",
        "spectral_sphere",
        "swe_bench",
        "swarm_ode",
        "validator_set",
        "violation_subspace",
    }
)

# Optional third-party names that map to an extra. Only used to *annotate*
# ImportError when that specific dependency is missing — other failures
# propagate unchanged.
_OPTIONAL_EXTRA_BY_MODULE: dict[str, tuple[str, str]] = {
    "constitutional_swarm.bittensor": ("bittensor", "bittensor"),
    "constitutional_swarm.langgraph_runtime": ("langgraph", "langgraph"),
    "constitutional_swarm.latent_dna": ("torch", "research"),
    "constitutional_swarm.node_admission": ("numpy", "research"),
    "constitutional_swarm.remote_vote_transport": ("websockets", "transport"),
    "constitutional_swarm.swarm_ode": ("torch", "research"),
    "constitutional_swarm.violation_subspace": ("numpy", "research"),
}


def _annotate_optional_import_error(module_name: str, exc: ImportError) -> ImportError:
    mapping = _OPTIONAL_EXTRA_BY_MODULE.get(module_name)
    if mapping is None:
        return exc
    missing, extra = mapping
    missing_name = getattr(exc, "name", None)
    if missing_name != missing and missing not in str(exc):
        return exc
    hinted = ImportError(
        f"{module_name} requires the optional {extra!r} extra "
        f"(missing dependency {missing!r}). "
        f"Install with: pip install 'constitutional-swarm[{extra}]'"
    )
    hinted.__cause__ = exc
    return hinted


def __getattr__(name: str) -> Any:
    if name in _LAZY_ATTRS:
        module_name, attr = _LAZY_ATTRS[name]
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise _annotate_optional_import_error(module_name, exc) from exc
        value = getattr(module, attr)
        globals()[name] = value
        return value
    if name in _LAZY_MODULES:
        module_name = f"constitutional_swarm.{name}"
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise _annotate_optional_import_error(module_name, exc) from exc
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(_LAZY_ATTRS) | set(_LAZY_MODULES) | set(globals()))


__all__ = [
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
]
