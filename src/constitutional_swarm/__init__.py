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

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.bench import BenchmarkResult, SwarmBenchmark
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.compiler import DAGCompiler, GoalSpec
from constitutional_swarm.contract import ContractStatus, TaskContract
from constitutional_swarm.dna import AgentDNA, DNADisabledError, constitutional_dna
from constitutional_swarm.federated_bridge import (
    AgentCredential,
    CredentialStatus,
    FederatedConstitutionBridge,
    FederationDecision,
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
from constitutional_swarm.manifold import (
    GovernanceManifold,
    ManifoldProjectionResult,
    sinkhorn_knopp,
)
from constitutional_swarm.mesh import (
    AssignmentSettledError,
    ConstitutionalMesh,
    InvalidVoteSignatureError,
    MeshHaltedError,
    MeshProof,
    MeshResult,
    PeerAssignment,
    RemoteVoteRequest,
    SettlementPersistenceError,
    ValidationVote,
)
from constitutional_swarm.remote_vote_transport import (
    LocalRemotePeer,
    RemoteVoteClient,
    RemoteVoteResponse,
    RemoteVoteServer,
)
from constitutional_swarm.settlement_store import (
    DuplicateSettlementError,
    JSONLSettlementStore,
    SettlementRecord,
    SettlementStore,
    SQLiteSettlementStore,
)
from constitutional_swarm.debate_resolver import (
    DebateRecord,
    DebateResolver,
    FinalVerdict,
    VerdictOutcome,
)
from constitutional_swarm.mac_acgs_loop import MacAcgsConfig, MacAcgsCycleResult, MacAcgsLoop
from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT
from constitutional_swarm.privacy_accountant import PrivacyAccountant, PrivacyBudgetExhausted
from constitutional_swarm.spectral_sphere import (
    SpectralProjectionResult,
    SpectralSphereManifold,
    spectral_sphere_project,
)
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode

__all__ = [
    "AgentCredential",
    "AgentDNA",
    "Artifact",
    "ArtifactStore",
    "AssignmentSettledError",
    "BenchmarkResult",
    "Capability",
    "CapabilityRegistry",
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
    "DuplicateRecordError",
    "DuplicateSettlementError",
    "EvolutionLog",
    "EvolutionViolationError",
    "ExecutionStatus",
    "FederatedConstitutionBridge",
    "FederationDecision",
    "FinalVerdict",
    "GapRecord",
    "GoalSpec",
    "GovernanceManifold",
    "InvalidVoteSignatureError",
    "JSONLSettlementStore",
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
    "MutationBlockedError",
    "NonIncreasingValueError",
    "PeerAssignment",
    "PrivacyAccountant",
    "PrivacyBudgetExhausted",
    "RegressionRecord",
    "RemoteVoteClient",
    "RemoteVoteRequest",
    "RemoteVoteResponse",
    "RemoteVoteServer",
    "SQLiteSettlementStore",
    "SettlementPersistenceError",
    "SettlementRecord",
    "SettlementStore",
    "SpectralProjectionResult",
    "SpectralSphereManifold",
    "SwarmBenchmark",
    "SwarmExecutor",
    "TaskContract",
    "TaskDAG",
    "TaskNode",
    "ValidationVote",
    "VerdictOutcome",
    "WorkReceipt",
    "constitutional_dna",
    "sinkhorn_knopp",
    "spectral_sphere_project",
]
