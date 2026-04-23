"""Constitutional Mesh — Byzantine-tolerant peer validation with cryptographic proof.

The defensible core of constitutional_swarm. Every agent's output is validated by randomly
assigned peers using the ACGS constitutional engine (443ns). No single
validator bottleneck. Tolerates up to 1/3 faulty/malicious agents.

Cryptographic proof chain:
  1. Producer creates output with constitutional hash
  2. Mesh assigns random peers (producer excluded — MACI)
  3. Each peer validates via embedded DNA (443ns, Rust engine)
  4. Votes are signed with the peer's Ed25519 private key
  5. Quorum result produces a Merkle proof linking:
     - Producer's output hash
     - Each peer's vote + constitutional hash
     - Final acceptance/rejection decision
  6. Anyone can verify the proof independently

No competitor can replicate this: agents constitutionally validating
each other's work, with cryptographic proof, at sub-microsecond cost.
"""

from __future__ import annotations

import hashlib
import math
import random
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from acgs_lite import Constitution
from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.manifold import GovernanceManifold
from constitutional_swarm.settlement_store import (
    JSONLSettlementStore,
    SettlementRecord,
    SettlementStore,
    SQLiteSettlementStore,
)

if TYPE_CHECKING:
    import constitutional_swarm.spectral_sphere as spectral_sphere_mod
    from constitutional_swarm.remote_vote_transport import RemoteVoteClient, RemoteVoteResponse

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InsufficientPeersError(Exception):
    """Not enough peers available for validation."""


class DuplicateVoteError(Exception):
    """Peer already voted on this assignment."""


class UnauthorizedVoterError(Exception):
    """Voter is not assigned to this validation."""


class InvalidVoteSignatureError(Exception):
    """Vote signature is missing or does not match the registered agent key."""


class AssignmentSettledError(Exception):
    """Assignment is already settled; further votes are rejected."""


class MeshHaltedError(RuntimeError):
    """Mesh has been halted — all operations blocked until resumed."""


class SettlementPersistenceError(RuntimeError):
    """Raised when a settled result cannot be persisted after freeze."""


# ---------------------------------------------------------------------------
# Data structures (all frozen — immutable by design)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeerAssignment:
    """A validation assignment linking a producer's output to peer validators."""

    assignment_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    peers: tuple[str, ...]
    constitutional_hash: str
    timestamp: float


@dataclass(frozen=True, slots=True)
class ValidationVote:
    """A peer's Ed25519-signed vote on a producer's output."""

    assignment_id: str
    voter_id: str
    approved: bool
    reason: str
    signature: str
    constitutional_hash: str
    content_hash: str
    timestamp: float

    @property
    def vote_hash(self) -> str:
        """Deterministic hash of this vote for proof chain."""
        payload = (
            f"{self.assignment_id}:{self.voter_id}:{self.approved}"
            f":{self.reason}:{self.signature}:{self.constitutional_hash}:{self.content_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class RemoteVoteRequest:
    """Signable vote request for a public-key-only remote peer."""

    assignment_id: str
    voter_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    constitutional_hash: str
    voter_public_key: str
    request_signer_public_key: str
    request_signature: str


@dataclass(frozen=True, slots=True)
class MeshProof:
    """Cryptographic proof of peer validation.

    A Merkle-style proof linking the producer's output, each peer's vote,
    and the constitutional hash into a single verifiable root.
    Anyone can independently verify this proof.
    """

    assignment_id: str
    content_hash: str
    constitutional_hash: str
    vote_hashes: tuple[str, ...]
    root_hash: str
    accepted: bool
    timestamp: float

    def verify(self) -> bool:
        """Independently verify the proof chain.

        Recomputes the Merkle root from vote hashes and checks
        it matches the stored root.
        """
        recomputed = _compute_merkle_root(
            self.assignment_id,
            self.content_hash,
            self.constitutional_hash,
            self.vote_hashes,
            self.accepted,
        )
        return recomputed == self.root_hash


@dataclass(frozen=True, slots=True)
class MeshResult:
    """Result of a peer validation with cryptographic proof."""

    assignment_id: str
    accepted: bool
    votes_for: int
    votes_against: int
    quorum_met: bool
    pending_votes: int
    constitutional_hash: str
    proof: MeshProof | None
    settled: bool = False
    settled_at: float | None = None


# ---------------------------------------------------------------------------
# Agent info (internal, mutable for reputation tracking)
# ---------------------------------------------------------------------------


@dataclass
class _AgentInfo:
    agent_id: str
    domain: str
    reputation: float = 1.0
    validations_performed: int = 0
    validations_received: int = 0


# ---------------------------------------------------------------------------
# Constitutional Mesh
# ---------------------------------------------------------------------------


class ConstitutionalMesh:
    """Byzantine-tolerant peer validation mesh with cryptographic proof.

    Every agent's output is validated by randomly assigned peers using
    the ACGS constitutional engine. The mesh produces a Merkle proof
    that anyone can independently verify.

    Properties:
    - O(1) governance cost per agent (local DNA validation)
    - Byzantine fault tolerant (tolerates < 1/3 faulty agents)
    - No single validator bottleneck
    - MACI-compliant (no self-validation)
    - Cryptographic proof chain for auditability
    - Sub-microsecond per validation (443ns via Rust engine)
    """

    def __init__(
        self,
        constitution: Constitution,
        *,
        peers_per_validation: int = 3,
        quorum: int = 2,
        seed: int | None = None,
        use_manifold: bool = False,
        manifold_type: Literal["birkhoff", "spectral"] = "birkhoff",
        shadow_spectral: bool = False,
        risk_scoring: bool = False,
        settlement_store_path: str | Path | None = None,
        settlement_store: SettlementStore | None = None,
        request_signing_private_key: Ed25519PrivateKey | bytes | str | None = None,
    ) -> None:
        if quorum > peers_per_validation:
            raise ValueError(
                f"Quorum ({quorum}) cannot exceed peers_per_validation ({peers_per_validation})"
            )
        if manifold_type not in {"birkhoff", "spectral"}:
            raise ValueError(
                f"manifold_type must be 'birkhoff' or 'spectral', got {manifold_type!r}"
            )
        self._constitution = constitution
        self._dna = AgentDNA(
            constitution=constitution,
            agent_id="mesh-validator",
            risk_scoring=risk_scoring,
        )
        self._risk_scoring = risk_scoring
        self._peers_per_validation = peers_per_validation
        self._quorum = quorum
        # Seeded randomness is only used for deterministic peer assignment in tests/benchmarks.
        self._rng = random.Random(seed) if seed is not None else random.SystemRandom()  # noqa: S311
        self._agents: dict[str, _AgentInfo] = {}
        self._agent_vote_public_keys: dict[str, Ed25519PublicKey] = {}
        self._agent_vote_private_keys: dict[str, Ed25519PrivateKey] = {}
        self._request_signing_private_key = (
            Ed25519PrivateKey.generate()
            if request_signing_private_key is None
            else self._coerce_private_key(request_signing_private_key)
        )
        self._request_signing_public_key = self._request_signing_private_key.public_key()
        self._assignments: dict[str, PeerAssignment] = {}
        self._votes: dict[str, list[ValidationVote]] = {}
        self._final_results: dict[str, MeshResult] = {}
        self._use_manifold = use_manifold
        self._manifold_type = manifold_type
        self._manifold: GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold | None = (
            None
        )
        self._shadow_spectral = use_manifold and manifold_type == "birkhoff" and shadow_spectral
        if self._shadow_spectral:
            self._shadow_manifold: spectral_sphere_mod.SpectralSphereManifold | None = None
            self._shadow_metrics: list[dict[str, float | str]] = []
        self._agent_indices: dict[str, int] = {}
        # Trust persistence: keyed by (from_agent_id, to_agent_id)
        # Survives agent churn and constitution rotation when preserve_trust=True.
        self._trust_store: dict[tuple[str, str], float] = {}
        # Archive for departed agents: agent_id → {partner_id: (trust_value, timestamp)}
        # Capped at _TRUST_ARCHIVE_MAX entries; LRU eviction by timestamp.
        self._trust_archive: dict[str, dict[str, tuple[float, float]]] = {}
        self._settled_assignments: set[str] = set()
        self._settled_voters: dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._halted = False
        if settlement_store is not None and settlement_store_path is not None:
            raise ValueError("Specify either settlement_store or settlement_store_path, not both")
        self._settlement_store = settlement_store
        if self._settlement_store is None and settlement_store_path is not None:
            if str(settlement_store_path).endswith(".db"):
                self._settlement_store = SQLiteSettlementStore(settlement_store_path)
            else:
                self._settlement_store = JSONLSettlementStore(settlement_store_path)
        self._load_settlements()
        reconciliation_report = self.retry_pending_settlements()
        if reconciliation_report["failures"] > 0 or reconciliation_report["remaining"] > 0:
            raise SettlementPersistenceError(
                "Pending settlement reconciliation did not complete successfully at startup"
            )

    def _check_halted(self) -> None:
        """Raise if mesh is halted."""
        if self._halted:
            raise MeshHaltedError("Mesh is halted — all operations blocked")

    def halt(self) -> None:
        """Kill switch — halt all mesh operations immediately.

        While halted, request_validation, submit_vote, validate_and_vote,
        and full_validation all raise MeshHaltedError.
        EU AI Act Art. 14(3): human-initiated halt capability.
        """
        with self._lock:
            self._halted = True

    def resume(self) -> None:
        """Resume mesh operations after a halt."""
        with self._lock:
            self._halted = False

    @property
    def is_halted(self) -> bool:
        """Whether the mesh is currently halted."""
        with self._lock:
            return self._halted

    @property
    def constitutional_hash(self) -> str:
        """The constitutional hash shared by all mesh participants."""
        return self._constitution.hash

    @property
    def agent_count(self) -> int:
        """Number of registered agents."""
        with self._lock:
            return len(self._agents)

    # -- Agent management --------------------------------------------------

    def register_remote_agent(
        self,
        agent_id: str,
        domain: str = "",
        *,
        vote_public_key: Ed25519PublicKey | bytes | str,
    ) -> None:
        """Register a remote peer with a public key only.

        The mesh can verify this agent's votes but cannot sign on their behalf.
        """
        with self._lock:
            self._agents[agent_id] = _AgentInfo(agent_id=agent_id, domain=domain)
            self._agent_vote_public_keys[agent_id] = self._coerce_public_key(vote_public_key)
            self._agent_vote_private_keys.pop(agent_id, None)
            if self._use_manifold and agent_id not in self._agent_indices:
                self._agent_indices[agent_id] = len(self._agent_indices)
                self._rebuild_manifold()
                self._restore_archive_for_agent(agent_id)

    def register_local_signer(
        self,
        agent_id: str,
        domain: str = "",
        *,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
    ) -> None:
        """Register an in-process signer whose private key is managed locally."""
        with self._lock:
            self._agents[agent_id] = _AgentInfo(agent_id=agent_id, domain=domain)
            private_key = (
                self._coerce_private_key(vote_private_key)
                if vote_private_key is not None
                else Ed25519PrivateKey.generate()
            )
            self._agent_vote_private_keys[agent_id] = private_key
            self._agent_vote_public_keys[agent_id] = private_key.public_key()
            if self._use_manifold and agent_id not in self._agent_indices:
                self._agent_indices[agent_id] = len(self._agent_indices)
                self._rebuild_manifold()
                self._restore_archive_for_agent(agent_id)

    def register_agent(self, *args: Any, **kwargs: Any) -> None:
        """Removed in v0.3.0. Use register_local_signer() or register_remote_agent()."""
        raise AttributeError(
            "register_agent() removed in v0.3.0. "
            "Use register_local_signer() for local agents or "
            "register_remote_agent() for remote peers. "
            "See https://github.com/dislovelhl/constitutional-swarm/blob/main/MIGRATION.md"
        )

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent from the mesh, archiving their trust relationships."""
        with self._lock:
            self._agents.pop(agent_id, None)
            self._agent_vote_public_keys.pop(agent_id, None)
            self._agent_vote_private_keys.pop(agent_id, None)
            if self._use_manifold and agent_id in self._agent_indices:
                self._archive_trust_for_agent(agent_id)
                # Remove departing agent from trust_store entries
                self._trust_store = {
                    (a, b): v
                    for (a, b), v in self._trust_store.items()
                    if a != agent_id and b != agent_id
                }
                remaining_ids = [
                    existing_agent_id
                    for existing_agent_id, _ in sorted(
                        self._agent_indices.items(), key=lambda item: item[1]
                    )
                    if existing_agent_id != agent_id and existing_agent_id in self._agents
                ]
                self._agent_indices = {
                    existing_agent_id: idx for idx, existing_agent_id in enumerate(remaining_ids)
                }
                self._rebuild_manifold()

    def rotate_constitution(
        self,
        new_constitution: Constitution,
        *,
        preserve_trust: bool = False,
    ) -> None:
        """Replace the mesh constitution with a new one.

        Args:
            new_constitution: The new constitution to apply.
            preserve_trust: If True, carry forward the current trust matrix into
                the new manifold rather than resetting to zero.  Use this when
                the constitution update is a policy amendment (same agents, new
                rules) rather than a full governance reset.  Default False to
                avoid inadvertently carrying adversarial trust state across a
                security-motivated rotation.
        """
        with self._lock:
            if preserve_trust and self._use_manifold:
                self._save_trust_to_store()
            self._constitution = new_constitution
            self._dna = AgentDNA(
                constitution=new_constitution,
                agent_id="mesh-validator",
                risk_scoring=self._risk_scoring,
            )
            if self._use_manifold:
                if preserve_trust:
                    self._rebuild_manifold()
                else:
                    # Hard reset — null manifold first so _save_trust_to_store is a no-op
                    self._manifold = None
                    if self._shadow_spectral:
                        self._shadow_manifold = None
                        self._shadow_metrics = []
                    self._trust_store = {}
                    self._rebuild_manifold()

    def get_reputation(self, agent_id: str) -> float:
        """Get an agent's reputation score."""
        with self._lock:
            info = self._agents.get(agent_id)
            if info is None:
                raise KeyError(f"Agent {agent_id} not registered")
            return info.reputation

    # -- Validation flow ---------------------------------------------------

    def request_validation(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
    ) -> PeerAssignment:
        """Request peer validation of a producer's output.

        Step 1: Constitutional DNA pre-check (443ns). Catches obvious
                violations before wasting peer time.
        Step 2: Select random peers, excluding the producer (MACI).
        Step 3: Return assignment with cryptographic content hash.

        Raises:
            ConstitutionalViolationError: Content violates constitution.
            InsufficientPeersError: Not enough peers available.
            KeyError: Producer not registered.
            MeshHaltedError: Mesh is halted.
        """
        with self._lock:
            self._check_halted()
            if producer_id not in self._agents:
                raise KeyError(f"Producer {producer_id} not registered")

            # Step 1: DNA pre-check — fail fast on constitutional violations.
            # When risk_scoring is enabled, the result carries a semantic risk
            # score that drives adaptive peer selection in Step 2.
            dna_result = self._dna.validate(content)

            # Step 2: Select peers (exclude producer — MACI).
            # Adaptive scaling: high-risk content (score >= 0.5) gets extra
            # peers up to max available, increasing Byzantine fault tolerance.
            available = [aid for aid in self._agents if aid != producer_id]
            base_needed = min(self._peers_per_validation, len(available))
            if self._risk_scoring and dna_result.risk_score >= 0.8:
                # critical — use all available peers
                needed = len(available)
            elif self._risk_scoring and dna_result.risk_score >= 0.5:
                # high — one extra peer
                needed = min(base_needed + 1, len(available))
            else:
                needed = base_needed
            if needed < self._quorum:
                raise InsufficientPeersError(
                    f"Need {self._quorum} peers for quorum, only {needed} available"
                )
            peers = tuple(self._select_peers(available, needed, producer_id))

            # Step 3: Create assignment with content hash
            content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
            assignment = PeerAssignment(
                assignment_id=uuid.uuid4().hex[:12],
                producer_id=producer_id,
                artifact_id=artifact_id,
                content=content,
                content_hash=content_hash,
                peers=peers,
                constitutional_hash=self.constitutional_hash,
                timestamp=time.time(),
            )
            self._assignments[assignment.assignment_id] = assignment
            self._votes[assignment.assignment_id] = []
            self._agents[producer_id].validations_received += 1
            return assignment

    def submit_vote(
        self,
        assignment_id: str,
        voter_id: str,
        *,
        approved: bool,
        reason: str = "",
        signature: str,
    ) -> ValidationVote:
        """Submit a peer's validation vote.

        Each peer validates the content against their constitutional DNA
        and casts an approve/reject vote.

        Raises:
            KeyError: Assignment not found.
            UnauthorizedVoterError: Voter not assigned to this validation.
            DuplicateVoteError: Voter already voted.
            MeshHaltedError: Mesh is halted.
        """
        with self._lock:
            self._check_halted()
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            if assignment_id in self._final_results:
                raise AssignmentSettledError(f"Assignment {assignment_id} is already settled")
            if voter_id not in assignment.peers:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not assigned to validation {assignment_id}"
                )
            if voter_id not in self._agents:
                raise UnauthorizedVoterError(f"{voter_id} is not a registered mesh agent")
            public_key = self._agent_vote_public_keys.get(voter_id)
            if public_key is None:
                raise UnauthorizedVoterError(f"{voter_id} has no registered vote public key")
            try:
                public_key.verify(
                    bytes.fromhex(signature),
                    self._vote_payload_bytes(
                        assignment_id=assignment_id,
                        voter_id=voter_id,
                        approved=approved,
                        reason=reason,
                        constitutional_hash=self.constitutional_hash,
                        content_hash=assignment.content_hash,
                    ),
                )
            except (ValueError, InvalidSignature) as exc:
                raise InvalidVoteSignatureError(
                    f"Invalid vote signature for {voter_id} on {assignment_id}"
                ) from exc

            existing = self._votes.get(assignment_id, [])
            if any(v.voter_id == voter_id for v in existing):
                raise DuplicateVoteError(f"{voter_id} already voted on {assignment_id}")

            vote = ValidationVote(
                assignment_id=assignment_id,
                voter_id=voter_id,
                approved=approved,
                reason=reason,
                signature=signature,
                constitutional_hash=self.constitutional_hash,
                content_hash=assignment.content_hash,
                timestamp=time.time(),
            )
            self._votes[assignment_id] = [*existing, vote]

            if voter_id in self._agents:
                self._agents[voter_id].validations_performed += 1

            # Update reputations if quorum reached
            self._maybe_settle_reputations(assignment_id)

        if self._maybe_finalize_result(assignment_id):
            self.settle(assignment_id)

        return vote

    def get_result(self, assignment_id: str) -> MeshResult:
        """Get the validation result for an assignment.

        Returns the frozen settled result when quorum has been finalized.
        Before settlement, this returns a preview result without a proof.
        """
        with self._lock:
            final = self._final_results.get(assignment_id)
            if final is not None:
                return final

            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            return self._preview_result(assignment)

    def settle(self, assignment_id: str) -> MeshResult:
        """Freeze a quorum result into an immutable proof snapshot.

        The settlement snapshot is written to the backing store *outside* the
        mesh lock so that slow or remote I/O in the store does not block
        concurrent callers.  The in-memory ``_final_results`` entry is written
        first so that concurrent readers see the settled result immediately
        (read-your-writes), then the lock is released before persisting.
        """
        with self._lock:
            final = self._final_results.get(assignment_id)
            if final is not None:
                return final

            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")

            preview = self._preview_result(assignment)
            if not preview.quorum_met:
                raise ValueError(
                    f"Assignment {assignment_id} cannot settle before quorum is reached"
                )

            settled_at = time.time()
            final = MeshResult(
                assignment_id=preview.assignment_id,
                accepted=preview.accepted,
                votes_for=preview.votes_for,
                votes_against=preview.votes_against,
                quorum_met=True,
                pending_votes=preview.pending_votes,
                constitutional_hash=preview.constitutional_hash,
                proof=self._build_proof(
                    assignment,
                    accepted=preview.accepted,
                    timestamp=settled_at,
                ),
                settled=True,
                settled_at=settled_at,
            )
            record = self._build_settlement_record(assignment, final)
        # Persist outside the lock — store I/O must not block mesh operations.
        # A durable pending marker is written first so startup reconciliation can
        # recover frozen-but-not-yet-durable settlements after a crash.
        try:
            if self._settlement_store is not None:
                self._settlement_store.mark_pending(record)
            with self._lock:
                existing = self._final_results.get(assignment_id)
                if existing is not None:
                    return existing
                self._final_results[assignment_id] = final
            self._persist_settlement_record(record)
            if self._settlement_store is not None:
                self._settlement_store.clear_pending(assignment_id)
        except Exception as exc:
            raise SettlementPersistenceError(
                f"Settlement {assignment_id} was frozen in memory but could not be persisted"
            ) from exc
        return final

    def validate_and_vote(
        self,
        assignment_id: str,
        voter_id: str,
    ) -> ValidationVote:
        """Convenience: peer validates content via DNA and auto-votes.

        The peer runs the content through their own constitutional DNA.
        If it passes, they vote approved. If it fails, they vote rejected
        with the violation as the reason.
        """
        with self._lock:
            self._check_halted()
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._assert_assignment_payload_complete(assignment)
            if voter_id not in self._agent_vote_private_keys:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not a locally managed signer; "
                    "use prepare_remote_vote() and submit_vote() for remote peers"
                )
            content = assignment.content

        voter_dna = AgentDNA(
            constitution=self._constitution,
            agent_id=voter_id,
            strict=False,
        )
        result = voter_dna.validate(content)

        if result.valid:
            return self.submit_vote(
                assignment_id,
                voter_id,
                approved=True,
                reason="constitutional check passed",
                signature=self.sign_vote(
                    assignment_id,
                    voter_id,
                    approved=True,
                    reason="constitutional check passed",
                ),
            )
        return self.submit_vote(
            assignment_id,
            voter_id,
            approved=False,
            reason="; ".join(result.violations),
            signature=self.sign_vote(
                assignment_id,
                voter_id,
                approved=False,
                reason="; ".join(result.violations),
            ),
        )

    # -- Bulk operations ---------------------------------------------------

    def full_validation(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
    ) -> MeshResult:
        """End-to-end validation for locally managed signer peers only.

        This path auto-runs peer validation and signatures in-process.
        For remote public-key-only peers, use:
          1. request_validation()
          2. prepare_remote_vote()
          3. remote signer validates + signs externally
          4. submit_vote()
          5. get_result()/settle()
        """
        assignment = self.request_validation(producer_id, content, artifact_id)
        for peer_id in assignment.peers:
            try:
                self.validate_and_vote(assignment.assignment_id, peer_id)
            except AssignmentSettledError:
                break
        return self.settle(assignment.assignment_id)

    async def collect_remote_votes(
        self,
        assignment_id: str,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: RemoteVoteClient | None = None,
        timeout: float = 5.0,
    ) -> MeshResult:
        """Collect votes for an existing assignment from local and remote peers.

        Local signer peers are validated/signed in-process. Public-key-only peers
        receive a `RemoteVoteRequest` over the supplied transport routes.
        """
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            peer_ids = assignment.peers

        try:
            from constitutional_swarm.remote_vote_transport import RemoteVoteClient as _Client
        except ImportError:
            _Client = None

        if client is None:
            if _Client is None:
                raise ImportError(
                    "Remote vote collection requires constitutional_swarm.remote_vote_transport"
                )
            client = _Client()

        for peer_id in peer_ids:
            if assignment_id in self._final_results:
                break
            if peer_id in self._agent_vote_private_keys:
                try:
                    self.validate_and_vote(assignment_id, peer_id)
                except AssignmentSettledError:
                    break
                continue

            route = peer_routes.get(peer_id)
            if route is None:
                raise KeyError(
                    f"No route found for remote peer '{peer_id}'. "
                    f"Pass peer_routes={{'{peer_id}': (host, port), ...}} to collect_remote_votes()."
                )
            request = self.prepare_remote_vote(assignment_id, peer_id)
            response = await client.request_vote(route[0], route[1], request, timeout=timeout)
            self._submit_remote_vote_response(assignment_id, peer_id, response)

        result = self.get_result(assignment_id)
        if result.quorum_met and not result.settled:
            return self.settle(assignment_id)
        return result

    async def full_validation_remote(
        self,
        producer_id: str,
        content: str,
        artifact_id: str,
        *,
        peer_routes: dict[str, tuple[str, int]],
        client: RemoteVoteClient | None = None,
        timeout: float = 5.0,
    ) -> MeshResult:
        """End-to-end validation that supports public-key-only remote peers."""
        assignment = self.request_validation(producer_id, content, artifact_id)
        return await self.collect_remote_votes(
            assignment.assignment_id,
            peer_routes=peer_routes,
            client=client,
            timeout=timeout,
        )

    def prepare_remote_vote(self, assignment_id: str, voter_id: str) -> RemoteVoteRequest:
        """Build a signable vote request for a public-key-only remote peer."""
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            self._assert_assignment_payload_complete(assignment)
            if voter_id not in assignment.peers:
                raise UnauthorizedVoterError(
                    f"{voter_id} is not assigned to validation {assignment_id}"
                )
            public_key = self._agent_vote_public_keys.get(voter_id)
            if public_key is None:
                raise UnauthorizedVoterError(f"{voter_id} has no registered vote public key")
            request_signer_public_key = self.get_request_signing_public_key()
            request_signature = self._request_signing_private_key.sign(
                self.build_remote_vote_request_payload(
                    assignment_id=assignment.assignment_id,
                    voter_id=voter_id,
                    producer_id=assignment.producer_id,
                    artifact_id=assignment.artifact_id,
                    content=assignment.content,
                    content_hash=assignment.content_hash,
                    constitutional_hash=assignment.constitutional_hash,
                    voter_public_key=public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    ).hex(),
                )
            ).hex()
            return RemoteVoteRequest(
                assignment_id=assignment.assignment_id,
                voter_id=voter_id,
                producer_id=assignment.producer_id,
                artifact_id=assignment.artifact_id,
                content=assignment.content,
                content_hash=assignment.content_hash,
                constitutional_hash=assignment.constitutional_hash,
                voter_public_key=public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ).hex(),
                request_signer_public_key=request_signer_public_key,
                request_signature=request_signature,
            )

    def _submit_remote_vote_response(
        self,
        assignment_id: str,
        voter_id: str,
        response: RemoteVoteResponse,
    ) -> ValidationVote:
        if response.assignment_id != assignment_id:
            raise ValueError(
                f"Remote vote response assignment mismatch: {response.assignment_id} != {assignment_id}"
            )
        if response.voter_id != voter_id:
            raise ValueError(
                f"Remote vote response voter mismatch: {response.voter_id} != {voter_id}"
            )
        return self.submit_vote(
            assignment_id,
            voter_id,
            approved=response.approved,
            reason=response.reason,
            signature=response.signature,
        )

    @staticmethod
    def build_remote_vote_request_payload(
        *,
        assignment_id: str,
        voter_id: str,
        producer_id: str,
        artifact_id: str,
        content: str,
        content_hash: str,
        constitutional_hash: str,
        voter_public_key: str,
    ) -> bytes:
        payload = (
            f"{assignment_id}:{voter_id}:{producer_id}:{artifact_id}:"
            f"{content}:{content_hash}:{constitutional_hash}:{voter_public_key}"
        )
        return payload.encode("utf-8")

    @staticmethod
    def verify_remote_vote_request(request: RemoteVoteRequest) -> bool:
        """Verify a remote vote request signature."""
        try:
            public_key = ConstitutionalMesh._coerce_public_key(request.request_signer_public_key)
            public_key.verify(
                bytes.fromhex(request.request_signature),
                ConstitutionalMesh.build_remote_vote_request_payload(
                    assignment_id=request.assignment_id,
                    voter_id=request.voter_id,
                    producer_id=request.producer_id,
                    artifact_id=request.artifact_id,
                    content=request.content,
                    content_hash=request.content_hash,
                    constitutional_hash=request.constitutional_hash,
                    voter_public_key=request.voter_public_key,
                ),
            )
        except (ValueError, InvalidSignature):
            return False
        return True

    @staticmethod
    def _content_matches_hash(content: str, content_hash: str) -> bool:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32] == content_hash

    @classmethod
    def _assert_assignment_payload_complete(cls, assignment: PeerAssignment) -> None:
        if not cls._content_matches_hash(assignment.content, assignment.content_hash):
            raise ValueError(
                f"Assignment {assignment.assignment_id} payload is unavailable or does not match its content hash"
            )

    # -- Stats -------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Mesh statistics."""
        with self._lock:
            total_validations = len(self._assignments)
            total_votes = sum(len(v) for v in self._votes.values())
            settled = len(self._final_results)
        pending_settlements = (
            0 if self._settlement_store is None else self._settlement_store.pending_count()
        )
        settlement_storage = (
            {"enabled": False, "backend": None, "pending": 0}
            if self._settlement_store is None
            else {
                "enabled": True,
                "pending": pending_settlements,
                **self._settlement_store.describe(),
            }
        )
        with self._lock:
            return {
                "agents": len(self._agents),
                "constitutional_hash": self.constitutional_hash,
                "total_validations": total_validations,
                "settled": settled,
                "pending": total_validations - settled,
                "pending_settlements": pending_settlements,
                "total_votes": total_votes,
                "settlement_storage": settlement_storage,
                "avg_reputation": (
                    sum(a.reputation for a in self._agents.values()) / len(self._agents)
                    if self._agents
                    else 0.0
                ),
            }

    # -- Manifold integration ----------------------------------------------

    @property
    def trust_matrix(self) -> tuple[tuple[float, ...], ...] | None:
        """The projected trust matrix, or None if manifold integration is disabled."""
        with self._lock:
            if self._manifold is None:
                return None
            return self._manifold.trust_matrix

    def manifold_summary(self) -> dict[str, Any] | None:
        """Manifold statistics, or None if manifold disabled."""
        with self._lock:
            if self._manifold is None:
                return None
            return {
                "manifold_type": self._manifold_type,
                **self._manifold.summary(),
            }

    def shadow_metrics_summary(self) -> dict[str, Any] | None:
        """Aggregate shadow manifold metrics, or None when shadow mode is inactive."""
        with self._lock:
            metrics = getattr(self, "_shadow_metrics", None)
            if not metrics:
                return None
            return {
                "count": len(metrics),
                "birkhoff_variance": _summarize_metric(metrics, "birkhoff_variance"),
                "spectral_variance": _summarize_metric(metrics, "spectral_variance"),
                "birkhoff_spectral_norm": _summarize_metric(metrics, "birkhoff_spectral_norm"),
                "spectral_spectral_norm": _summarize_metric(metrics, "spectral_spectral_norm"),
            }

    def _select_peers(
        self,
        available: list[str],
        needed: int,
        producer_id: str,
    ) -> list[str]:
        """Select peers, optionally weighted by manifold trust.

        When ``_use_manifold`` is True and the manifold is converged,
        peer selection is weighted by the manifold trust vector from the
        producer to each candidate.  One slot is always filled by random
        selection (exploration) to prevent permanent exclusion of
        low-trust peers.

        Falls back to uniform random sampling when the manifold is
        disabled, not yet converged, or the producer is not indexed.
        """
        if (
            not self._use_manifold
            or self._manifold is None
            or producer_id not in self._agent_indices
        ):
            return list(self._rng.sample(available, k=needed))

        proj = self._manifold.project()
        if not getattr(proj, "converged", True):
            return list(self._rng.sample(available, k=needed))

        producer_idx = self._agent_indices[producer_id]
        trust_row = proj.matrix[producer_idx]

        # Build {agent_id: weight} dict — O(1) lookup, no index() calls
        weight_map: dict[str, float] = {}
        for aid in available:
            idx = self._agent_indices.get(aid)
            w = trust_row[idx] if idx is not None else 0.01
            weight_map[aid] = max(w, 0.01)  # floor to prevent zero-weight exclusion

        if needed >= len(available):
            return list(available)

        # Single-peer case: use weighted selection directly (no exploration slot)
        if needed == 1:
            return [self._weighted_pick(available, [weight_map[a] for a in available])]

        # Reserve 1 slot for pure random (exploration) to prevent
        # permanent exclusion of low-trust peers.
        random_pick = self._rng.choice(available)
        selected = {random_pick}

        # Fill remaining slots via weighted sampling (without replacement)
        remaining_needed = needed - 1
        remaining_pool = [a for a in available if a not in selected]
        remaining_weights = [weight_map[a] for a in remaining_pool]

        for _ in range(remaining_needed):
            if not remaining_pool:
                break
            total = sum(remaining_weights)
            if total <= 0:
                pick = self._rng.choice(remaining_pool)
                pick_idx = remaining_pool.index(pick)
            else:
                r = self._rng.random() * total
                cumulative = 0.0
                pick_idx = len(remaining_pool) - 1
                pick = remaining_pool[pick_idx]
                for j, w in enumerate(remaining_weights):
                    cumulative += w
                    if cumulative >= r:
                        pick_idx = j
                        pick = remaining_pool[j]
                        break
            selected.add(pick)
            # O(1) removal via swap-and-pop (order within remaining_pool does
            # not matter — weighted selection re-evaluates the whole pool each
            # iteration).
            last = len(remaining_pool) - 1
            if pick_idx != last:
                remaining_pool[pick_idx] = remaining_pool[last]
                remaining_weights[pick_idx] = remaining_weights[last]
            remaining_pool.pop()
            remaining_weights.pop()

        return list(selected)

    def _weighted_pick(self, pool: list[str], weights: list[float]) -> str:
        """Pick one item from pool with probability proportional to weights."""
        total = sum(weights)
        if total <= 0:
            return self._rng.choice(pool)
        r = self._rng.random() * total
        cumulative = 0.0
        for j, w in enumerate(weights):
            cumulative += w
            if cumulative >= r:
                return pool[j]
        return pool[-1]

    _TRUST_ARCHIVE_MAX: int = 1000
    _TRUST_DECAY_RATE: float = 0.05  # fraction lost per re-join round

    def _save_trust_to_store(self) -> None:
        """Snapshot current manifold raw trust into _trust_store (by agent_id pair)."""
        if self._manifold is None:
            return
        raw = self._manifold._raw_trust  # direct access — same package
        n = len(raw)
        for aid, i in self._agent_indices.items():
            if i >= n:
                continue  # new agent not yet in old manifold
            for bid, j in self._agent_indices.items():
                if j >= n:
                    continue
                val = raw[i][j]
                if val != 0.0:
                    self._trust_store[(aid, bid)] = val

    def _restore_trust_from_store(
        self,
        manifold: GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold | None = None,
    ) -> None:
        """Replay _trust_store into a freshly built manifold instance."""
        target = self._manifold if manifold is None else manifold
        if target is None:
            return
        for (aid, bid), val in self._trust_store.items():
            i = self._agent_indices.get(aid)
            j = self._agent_indices.get(bid)
            if i is not None and j is not None:
                target._raw_trust[i][j] = val

    def _restore_archive_for_agent(self, agent_id: str) -> None:
        """Restore archived trust for a returning agent with exponential decay."""
        archived = self._trust_archive.pop(agent_id, None)
        if archived is None or self._manifold is None:
            return
        now = time.monotonic()
        i = self._agent_indices.get(agent_id)
        if i is None:
            return
        for partner_id, (val, ts) in archived.items():
            j = self._agent_indices.get(partner_id)
            if j is None:
                continue
            elapsed_rounds = max(0.0, now - ts)
            decayed = val * max(0.0, 1.0 - self._TRUST_DECAY_RATE * elapsed_rounds)
            if decayed > 0.0:
                self._manifold._raw_trust[i][j] = decayed
                self._manifold._raw_trust[j][i] = decayed
                shadow = getattr(self, "_shadow_manifold", None)
                if shadow is not None:
                    shadow._raw_trust[i][j] = decayed
                    shadow._raw_trust[j][i] = decayed

    def _archive_trust_for_agent(self, agent_id: str) -> None:
        """Save departing agent's trust to archive (capped at _TRUST_ARCHIVE_MAX)."""
        if self._manifold is None:
            return
        i = self._agent_indices.get(agent_id)
        if i is None:
            return
        raw = self._manifold._raw_trust
        now = time.monotonic()
        entries: dict[str, tuple[float, float]] = {}
        for partner_id, j in self._agent_indices.items():
            if partner_id == agent_id:
                continue
            val = raw[i][j]
            if val != 0.0:
                entries[partner_id] = (val, now)
        if entries:
            # Evict oldest archive entries if at cap
            while len(self._trust_archive) >= self._TRUST_ARCHIVE_MAX:
                oldest = min(
                    self._trust_archive,
                    key=lambda aid: min(ts for _, ts in self._trust_archive[aid].values()),
                )
                del self._trust_archive[oldest]
            self._trust_archive[agent_id] = entries

    def _rebuild_manifold(self) -> None:
        """Rebuild the manifold with the current number of agents, preserving trust state."""
        self._save_trust_to_store()
        n = len(self._agent_indices)
        if n == 0:
            self._manifold = None
            if self._shadow_spectral:
                self._shadow_manifold = None
            return
        self._manifold = self._build_manifold(n, self._manifold_type)
        self._restore_trust_from_store()
        if self._shadow_spectral:
            self._shadow_manifold = self._build_manifold(n, "spectral")
            self._restore_trust_from_store(self._shadow_manifold)

    def _build_manifold(
        self,
        n: int,
        manifold_type: Literal["birkhoff", "spectral"],
    ) -> GovernanceManifold | spectral_sphere_mod.SpectralSphereManifold:
        """Instantiate the configured manifold type lazily."""
        if manifold_type == "spectral":
            import constitutional_swarm.spectral_sphere as spectral_sphere_mod_local

            return spectral_sphere_mod_local.SpectralSphereManifold(num_agents=n, r=1.0)
        return GovernanceManifold(n)

    # -- Internal ----------------------------------------------------------

    def _maybe_settle_reputations(self, assignment_id: str) -> None:
        """Update reputations when quorum is reached.

        Tracks which voters have already been reputation-adjusted via
        _settled_voters to prevent double-application. Late voters
        arriving after quorum are individually adjusted on arrival.
        Manifold updates are applied exactly once at first settlement.
        """
        result = self.get_result(assignment_id)
        if not result.quorum_met:
            return

        votes = self._votes.get(assignment_id, [])
        majority_approved = result.accepted
        first_settlement = assignment_id not in self._settled_assignments

        settled_voters = self._settled_voters.setdefault(assignment_id, set())

        for vote in votes:
            if vote.voter_id in settled_voters:
                continue
            settled_voters.add(vote.voter_id)
            agent = self._agents.get(vote.voter_id)
            if agent is None:
                continue
            if vote.approved == majority_approved:
                agent.reputation = min(2.0, agent.reputation + 0.01)
            else:
                agent.reputation = max(0.0, agent.reputation - 0.05)

        if first_settlement:
            self._settled_assignments.add(assignment_id)
            if self._manifold is not None:
                assignment = self._assignments[assignment_id]
                producer_idx = self._agent_indices.get(assignment.producer_id)
                if producer_idx is not None:
                    for vote in votes:
                        voter_idx = self._agent_indices.get(vote.voter_id)
                        if voter_idx is None:
                            continue
                        if vote.approved == majority_approved:
                            self._manifold.update_trust(producer_idx, voter_idx, 0.1)
                        else:
                            self._manifold.update_trust(producer_idx, voter_idx, -0.5)
                    self._manifold.project()
                    shadow = getattr(self, "_shadow_manifold", None)
                    if shadow is not None:
                        try:
                            for vote in votes:
                                voter_idx = self._agent_indices.get(vote.voter_id)
                                if voter_idx is None:
                                    continue
                                if vote.approved == majority_approved:
                                    shadow.update_trust(producer_idx, voter_idx, 0.1)
                                else:
                                    shadow.update_trust(producer_idx, voter_idx, -0.5)
                            shadow.project()
                            self._shadow_metrics.append(
                                {
                                    "assignment_id": assignment_id,
                                    "birkhoff_variance": _trust_variance(
                                        self._manifold.trust_matrix
                                    ),
                                    "spectral_variance": _trust_variance(shadow.trust_matrix),
                                    "birkhoff_spectral_norm": _matrix_spectral_norm(
                                        self._manifold.trust_matrix
                                    ),
                                    "spectral_spectral_norm": _matrix_spectral_norm(
                                        shadow.trust_matrix
                                    ),
                                }
                            )
                        except IndexError:
                            # Shadow mode must never interfere with the live routing path.
                            pass

    def _maybe_finalize_result(self, assignment_id: str) -> bool:
        """Return whether the first quorum-reaching result should be frozen."""
        with self._lock:
            if assignment_id in self._final_results:
                return False
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                return False
            return self._preview_result(assignment).quorum_met

    def _preview_result(self, assignment: PeerAssignment) -> MeshResult:
        """Compute the current non-final view of an assignment."""
        votes = self._votes.get(assignment.assignment_id, [])
        votes_for = sum(1 for v in votes if v.approved)
        votes_against = sum(1 for v in votes if not v.approved)
        total_peers = len(assignment.peers)
        pending = total_peers - len(votes)

        accepted = votes_for >= self._quorum
        rejected = votes_against > (total_peers - self._quorum)
        quorum_met = accepted or rejected

        return MeshResult(
            assignment_id=assignment.assignment_id,
            accepted=accepted,
            votes_for=votes_for,
            votes_against=votes_against,
            quorum_met=quorum_met,
            pending_votes=pending,
            constitutional_hash=assignment.constitutional_hash,
            proof=None,
            settled=False,
            settled_at=None,
        )

    def _build_proof(
        self,
        assignment: PeerAssignment,
        *,
        accepted: bool,
        timestamp: float,
    ) -> MeshProof:
        """Build a stable proof snapshot for a settled assignment."""
        votes = self._votes.get(assignment.assignment_id, [])
        vote_hashes = tuple(v.vote_hash for v in votes)
        root_hash = _compute_merkle_root(
            assignment.assignment_id,
            assignment.content_hash,
            assignment.constitutional_hash,
            vote_hashes,
            accepted,
        )
        return MeshProof(
            assignment_id=assignment.assignment_id,
            content_hash=assignment.content_hash,
            constitutional_hash=assignment.constitutional_hash,
            vote_hashes=vote_hashes,
            root_hash=root_hash,
            accepted=accepted,
            timestamp=timestamp,
        )

    def _persist_settlement(self, assignment: PeerAssignment, result: MeshResult) -> None:
        """Append a settled assignment/result snapshot to disk when configured."""
        self._persist_settlement_record(self._build_settlement_record(assignment, result))

    def _persist_settlement_record(self, record: SettlementRecord) -> None:
        """Append a pre-built settlement record when configured."""
        if self._settlement_store is None:
            return
        self._settlement_store.append(record)

    def _load_settlements(self) -> None:
        """Load settled assignments/results from disk when configured."""
        if self._settlement_store is None:
            return

        for record in self._settlement_store.load_all():
            assignment = self._deserialize_assignment(record.assignment)
            result = self._deserialize_result(record.result)
            if assignment.constitutional_hash != self.constitutional_hash:
                raise ValueError(
                    "Persisted settlement constitutional hash does not match current mesh"
                )
            self._assignments[assignment.assignment_id] = assignment
            self._votes.setdefault(assignment.assignment_id, [])
            self._final_results[assignment.assignment_id] = result

    def retry_pending_settlements(self) -> dict[str, int]:
        """Replay durable pending-journal settlements into the primary store."""
        if self._settlement_store is None:
            return {"pending": 0, "reconciled": 0, "remaining": 0, "failures": 0}

        pending_records = self._settlement_store.load_pending()
        reconciled = 0
        failures = 0

        for record in pending_records:
            assignment = self._deserialize_assignment(record.assignment)
            result = self._deserialize_result(record.result)
            if assignment.constitutional_hash != self.constitutional_hash:
                raise ValueError(
                    "Persisted settlement constitutional hash does not match current mesh"
                )

            with self._lock:
                self._assignments.setdefault(assignment.assignment_id, assignment)
                self._votes.setdefault(assignment.assignment_id, [])
                self._final_results.setdefault(assignment.assignment_id, result)

            try:
                self._persist_settlement_record(record)
            except (OSError, RuntimeError, ValueError):
                failures += 1
                continue

            self._settlement_store.clear_pending(assignment.assignment_id)
            reconciled += 1

        remaining = len(self._settlement_store.load_pending())
        return {
            "pending": len(pending_records),
            "reconciled": reconciled,
            "remaining": remaining,
            "failures": failures,
        }

    def _build_settlement_record(
        self, assignment: PeerAssignment, result: MeshResult
    ) -> SettlementRecord:
        return SettlementRecord(
            assignment=self._serialize_assignment(assignment),
            result=self._serialize_result(result),
            constitutional_hash=assignment.constitutional_hash,
        )

    @staticmethod
    def _serialize_assignment(assignment: PeerAssignment) -> dict[str, Any]:
        return {
            "assignment_id": assignment.assignment_id,
            "producer_id": assignment.producer_id,
            "artifact_id": assignment.artifact_id,
            "content_hash": assignment.content_hash,
            "peers": list(assignment.peers),
            "constitutional_hash": assignment.constitutional_hash,
            "timestamp": assignment.timestamp,
        }

    @staticmethod
    def _deserialize_assignment(data: dict[str, Any]) -> PeerAssignment:
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

    @staticmethod
    def _serialize_proof(proof: MeshProof | None) -> dict[str, Any] | None:
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

    @staticmethod
    def _deserialize_proof(data: dict[str, Any] | None) -> MeshProof | None:
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

    def _serialize_result(self, result: MeshResult) -> dict[str, Any]:
        return {
            "assignment_id": result.assignment_id,
            "accepted": result.accepted,
            "votes_for": result.votes_for,
            "votes_against": result.votes_against,
            "quorum_met": result.quorum_met,
            "pending_votes": result.pending_votes,
            "constitutional_hash": result.constitutional_hash,
            "proof": self._serialize_proof(result.proof),
            "settled": result.settled,
            "settled_at": result.settled_at,
        }

    def _deserialize_result(self, data: dict[str, Any]) -> MeshResult:
        return MeshResult(
            assignment_id=str(data["assignment_id"]),
            accepted=bool(data["accepted"]),
            votes_for=int(data["votes_for"]),
            votes_against=int(data["votes_against"]),
            quorum_met=bool(data["quorum_met"]),
            pending_votes=int(data["pending_votes"]),
            constitutional_hash=str(data["constitutional_hash"]),
            proof=self._deserialize_proof(data.get("proof")),
            settled=bool(data.get("settled", False)),
            settled_at=(float(data["settled_at"]) if data.get("settled_at") is not None else None),
        )

    def sign_vote(
        self,
        assignment_id: str,
        voter_id: str,
        *,
        approved: bool,
        reason: str = "",
    ) -> str:
        """Create an Ed25519 vote signature for a registered voter.

        This convenience method exists for local/in-process agents and tests.
        In distributed deployments, agents should hold their own private key and
        produce the same signature client-side.
        """
        with self._lock:
            assignment = self._assignments.get(assignment_id)
            if assignment is None:
                raise KeyError(f"Assignment {assignment_id} not found")
            signing_key = self._agent_vote_private_keys.get(voter_id)
            if signing_key is None:
                raise UnauthorizedVoterError(f"{voter_id} has no registered vote signing key")
            return signing_key.sign(
                self._vote_payload_bytes(
                    assignment_id=assignment_id,
                    voter_id=voter_id,
                    approved=approved,
                    reason=reason,
                    constitutional_hash=self.constitutional_hash,
                    content_hash=assignment.content_hash,
                )
            ).hex()

    def get_vote_public_key(self, agent_id: str) -> str:
        """Return the registered Ed25519 public key as a hex string."""
        with self._lock:
            public_key = self._agent_vote_public_keys.get(agent_id)
            if public_key is None:
                raise KeyError(f"Agent {agent_id} not registered")
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()

    def get_request_signing_public_key(self) -> str:
        """Return the mesh request-signing public key as a hex string."""
        return self._request_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @classmethod
    def verify_vote_signature(
        cls,
        *,
        public_key: Ed25519PublicKey | bytes | str,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
        signature: str,
    ) -> bool:
        """Verify a detached Ed25519 vote signature."""
        key = cls._coerce_public_key(public_key)
        try:
            key.verify(
                bytes.fromhex(signature),
                cls._vote_payload_bytes(
                    assignment_id=assignment_id,
                    voter_id=voter_id,
                    approved=approved,
                    reason=reason,
                    constitutional_hash=constitutional_hash,
                    content_hash=content_hash,
                ),
            )
        except (ValueError, InvalidSignature):
            return False
        return True

    @classmethod
    def build_vote_payload(
        cls,
        *,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
    ) -> bytes:
        """Build the canonical byte payload that remote peers must sign."""
        return cls._vote_payload_bytes(
            assignment_id=assignment_id,
            voter_id=voter_id,
            approved=approved,
            reason=reason,
            constitutional_hash=constitutional_hash,
            content_hash=content_hash,
        )

    @staticmethod
    def _coerce_public_key(value: Ed25519PublicKey | bytes | str) -> Ed25519PublicKey:
        if isinstance(value, Ed25519PublicKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def _coerce_private_key(value: Ed25519PrivateKey | bytes | str) -> Ed25519PrivateKey:
        if isinstance(value, Ed25519PrivateKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def _vote_payload_bytes(
        *,
        assignment_id: str,
        voter_id: str,
        approved: bool,
        reason: str,
        constitutional_hash: str,
        content_hash: str,
    ) -> bytes:
        payload = (
            f"{assignment_id}:{voter_id}:{approved}:{reason}:{constitutional_hash}:{content_hash}"
        )
        return payload.encode("utf-8")


# ---------------------------------------------------------------------------
# Merkle proof computation
# ---------------------------------------------------------------------------


def _compute_merkle_root(
    assignment_id: str,
    content_hash: str,
    constitutional_hash: str,
    vote_hashes: tuple[str, ...],
    accepted: bool,
) -> str:
    """Compute the Merkle root for a validation proof.

    Structure:
        root
        ├── leaf: assignment_id + content_hash + constitutional_hash + accepted
        └── votes_root
            ├── vote_hash_0
            ├── vote_hash_1
            └── vote_hash_N

    This allows independent verification: given the content hash,
    constitutional hash, and vote hashes, anyone can recompute
    the root and verify the proof.
    """
    # Leaf: assignment identity + content + constitutional hash + final decision
    leaf = hashlib.sha256(
        f"{assignment_id}:{content_hash}:{constitutional_hash}:{accepted}".encode()
    ).hexdigest()[:32]

    # Votes subtree: iterative hashing of vote hashes
    if not vote_hashes:
        votes_root = hashlib.sha256(b"empty").hexdigest()[:32]
    else:
        votes_root = vote_hashes[0]
        for vh in vote_hashes[1:]:
            combined = f"{votes_root}:{vh}"
            votes_root = hashlib.sha256(combined.encode()).hexdigest()[:32]

    # Root: combine leaf and votes
    root = hashlib.sha256(f"{leaf}:{votes_root}".encode()).hexdigest()[:32]
    return root


def _trust_variance(matrix: tuple[tuple[float, ...], ...]) -> float:
    """Variance of matrix entries around their mean."""
    values = [value for row in matrix for value in row]
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def _matrix_spectral_norm(
    matrix: tuple[tuple[float, ...], ...],
    *,
    max_iterations: int = 20,
    tol: float = 1e-8,
) -> float:
    """Estimate the matrix spectral norm via power iteration on M^T M."""
    n = len(matrix)
    if n == 0:
        return 0.0
    vector = [1.0 / math.sqrt(n)] * n
    sigma = 0.0
    for _ in range(max_iterations):
        mv = [sum(matrix[i][j] * vector[j] for j in range(n)) for i in range(n)]
        mtmv = [sum(matrix[j][i] * mv[j] for j in range(n)) for i in range(n)]
        new_norm = math.sqrt(sum(value * value for value in mtmv))
        if new_norm < 1e-14:
            return 0.0
        new_sigma = math.sqrt(new_norm)
        vector = [value / new_norm for value in mtmv]
        if abs(new_sigma - sigma) / (sigma + 1e-12) < tol:
            return new_sigma
        sigma = new_sigma
    return sigma


def _summarize_metric(
    metrics: list[dict[str, float | str]],
    key: str,
) -> dict[str, float]:
    """Return mean/min/max for one recorded shadow metric."""
    values = [float(metric[key]) for metric in metrics]
    return {
        "mean": sum(values) / len(values),
        "min": min(values),
        "max": max(values),
    }
