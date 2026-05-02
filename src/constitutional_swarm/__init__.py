"""constitutional_swarm — Manifold-Constrained Constitutional Swarm Mesh.

Orchestrator-free multi-agent governance via embedded Agent DNA,
stigmergic task coordination, constitutional peer validation,
and manifold-constrained trust propagation.

Four breakthrough patterns:
  A. Agent DNA — embedded constitutional validation (443ns/check)
  B. Stigmergic Swarm — DAG-compiled task execution, no orchestrator
  C. Constitutional Mesh — peer-validated Byzantine tolerance
  D. Governance Manifold — Sinkhorn-Knopp projected trust matrices
     guaranteeing bounded influence and compositional stability
     (inspired by mHC, arXiv:2512.24880)
"""

from constitutional_swarm.agency_bridge import (
    AgencyAgentDef,
    AgencyAgentRegistry,
    GovernedAgencyAgent,
    load_agency_agents,
)
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.bench import BenchmarkResult, SwarmBenchmark
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.compiler import DAGCompiler, GoalSpec, GoalStep
from constitutional_swarm.contract import ContractStatus, TaskContract
from constitutional_swarm.debate_resolver import (
    DebateRecord,
    DebateResolver,
    FinalVerdict,
    VerdictOutcome,
)
from constitutional_swarm.dna import AgentDNA, DNADisabledError, constitutional_dna
from constitutional_swarm.epoch_reconfig import (
    AmendmentProposal,
    ConstitutionVersion,
    DriftBudget,
    DriftBudgetExceeded,
    EpochMismatchError,
    InvalidTransitionError,
    JointQuorumNotMetError,
    TransitionCertificate,
    compute_version_digest,
    evaluate_drift,
    verify_transition,
)
from constitutional_swarm.evolution_log import (
    DashboardRow,
    DecelerationBlockedError,
    DecelerationRecord,
    DuplicateRecordError,
    EvolutionLog,
    EvolutionViolationError,
    GapRecord,
    MissingPriorEpochError,
    MutationBlockedError,
    NonIncreasingValueError,
    RegressionRecord,
)
from constitutional_swarm.execution import ExecutionStatus, WorkReceipt
from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
    FederationDecision,
)
from constitutional_swarm.mac_acgs_loop import MacAcgsConfig, MacAcgsCycleResult, MacAcgsLoop
from constitutional_swarm.manifold import (
    GovernanceManifold,
    ManifoldProjectionResult,
    sinkhorn_knopp,
)
from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT
from constitutional_swarm.mesh import (
    AssignmentSettledError,
    ConstitutionalMesh,
    InvalidVoteSignatureError,
    MeshHaltedError,
    MeshProof,
    MeshResult,
    PeerAssignment,
    ReconciliationReport,
    RecoveredAssignmentError,
    RemoteVoteReplayError,
    RemoteVoteRequest,
    SettlementPersistenceError,
    ValidationVote,
)
from constitutional_swarm.privacy_accountant import PrivacyAccountant, PrivacyBudgetExhausted
from constitutional_swarm.private_vote import (
    BallotChoice,
    CommitRecord,
    DoubleVoteError,
    InvalidCommitError,
    InvalidRevealError,
    MissingRevealError,
    PrivateBallotBox,
    PrivateTally,
    RevealRecord,
    build_commit,
    build_reveal,
    compute_nullifier,
    tally,
)
from constitutional_swarm.quorum_certificate import (
    ConflictEvidence,
    InsufficientQuorumError,
    InvalidCertificateError,
    QuorumCertificate,
    SignedVote,
    build_certificate,
    build_vote_message,
    detect_conflict,
    verify_certificate,
)
from constitutional_swarm.remote_vote_transport import (
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteResponse,
    RemoteVoteServer,
)
from constitutional_swarm.settlement_store import (
    SUPPORTED_SETTLEMENT_SCHEMA_VERSIONS,
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
    SettlementSchemaVersionError,
    SettlementStore,
    SQLiteSettlementStore,
)
from constitutional_swarm.spectral_sphere import (
    SpectralProjectionResult,
    SpectralSphereManifold,
    spectral_sphere_project,
)
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode
from constitutional_swarm.validator_set import (
    CommitteeSelection,
    CommitteeSelector,
    FaultDomainPolicy,
    SybilBoundViolation,
    ValidatorIdentity,
    ValidatorSet,
)
from constitutional_swarm.violation_subspace import (
    DimensionMismatchError,
    InsufficientSamplesError,
    RiskAdaptiveSteering,
    ViolationSubspace,
    adversarial_score,
    fit_leace,
    fit_subspace,
)

# Keep broad top-level imports for compatibility with existing tests and callers,
# but advertise only the stable 1.0 surface via __all__.
__all__ = [
    "SUPPORTED_SETTLEMENT_SCHEMA_VERSIONS",
    "AgencyAgentDef",
    "AgencyAgentRegistry",
    "AgentCredential",
    "AgentDNA",
    "AmendmentProposal",
    "Artifact",
    "ArtifactStore",
    "AssignmentSettledError",
    "BallotChoice",
    "BenchmarkResult",
    "Capability",
    "CapabilityRegistry",
    "CommitRecord",
    "CommitteeSelection",
    "CommitteeSelector",
    "ConflictEvidence",
    "ConstitutionVersion",
    "ConstitutionalMesh",
    "ContractStatus",
    "CredentialStatus",
    "DAGCompiler",
    "DAGNode",
    "DNADisabledError",
    "DashboardRow",
    "DebateRecord",
    "DebateResolver",
    "DecelerationBlockedError",
    "DecelerationRecord",
    "DimensionMismatchError",
    "DoubleVoteError",
    "DriftBudget",
    "DriftBudgetExceeded",
    "DuplicateRecordError",
    "DuplicateSettlementError",
    "EpochMismatchError",
    "EvolutionLog",
    "EvolutionViolationError",
    "ExecutionStatus",
    "FaultDomainPolicy",
    "FederatedConstitutionBridge",
    "FederationDecision",
    "FinalVerdict",
    "GapRecord",
    "GoalSpec",
    "GoalStep",
    "GovernanceManifold",
    "GovernedAgencyAgent",
    "InsufficientQuorumError",
    "InsufficientSamplesError",
    "InvalidCertificateError",
    "InvalidCommitError",
    "InvalidRevealError",
    "InvalidTransitionError",
    "InvalidVoteSignatureError",
    "JSONLSettlementStore",
    "JointQuorumNotMetError",
    "LocalRemotePeer",
    "MacAcgsConfig",
    "MacAcgsCycleResult",
    "MacAcgsLoop",
    "ManifoldProjectionResult",
    "MerkleCRDT",
    "MeshHaltedError",
    "MeshProof",
    "MeshResult",
    "MissingPriorEpochError",
    "MissingRevealError",
    "MutationBlockedError",
    "NonIncreasingValueError",
    "PeerAssignment",
    "PrivacyAccountant",
    "PrivacyBudgetExhausted",
    "PrivateBallotBox",
    "PrivateTally",
    "QuorumCertificate",
    "ReconciliationReport",
    "RecoveredAssignmentError",
    "RegressionRecord",
    "RemoteVoteClient",
    "RemoteVoteReplayError",
    "RemoteVoteRequest",
    "RemoteVoteResponse",
    "RemoteVoteServer",
    "RevealRecord",
    "RiskAdaptiveSteering",
    "SQLiteSettlementStore",
    "SettlementPersistenceError",
    "SettlementRecord",
    "SettlementSchemaVersionError",
    "SettlementStore",
    "SignedVote",
    "SpectralProjectionResult",
    "SpectralSphereManifold",
    "SwarmBenchmark",
    "SwarmExecutor",
    "SybilBoundViolation",
    "TaskContract",
    "TaskDAG",
    "TaskNode",
    "TransitionCertificate",
    "ValidationVote",
    "ValidatorIdentity",
    "ValidatorSet",
    "VerdictOutcome",
    "ViolationSubspace",
    "WorkReceipt",
    "adversarial_score",
    "build_certificate",
    "build_commit",
    "build_reveal",
    "build_vote_message",
    "compute_nullifier",
    "compute_version_digest",
    "constitutional_dna",
    "detect_conflict",
    "evaluate_drift",
    "fit_leace",
    "fit_subspace",
    "load_agency_agents",
    "sinkhorn_knopp",
    "spectral_sphere_project",
    "tally",
    "verify_certificate",
    "verify_transition",
]
