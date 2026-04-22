<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# constitutional_swarm

## Purpose
Top-level Python package implementing the four breakthrough patterns described in the package paper: (A) embedded Agent DNA constitutional validation, (B) stigmergic DAG-compiled swarm execution, (C) Byzantine-tolerant Constitutional Mesh with peer validation, and (D) manifold-constrained trust propagation (Sinkhorn/Birkhoff baseline and the production-direction Spectral Sphere replacement). Also hosts MCFS research modules — latent DNA residual steering, continuous-time swarm ODE, Merkle-CRDT artifact store, violation subspace / LEACE steering, federated/private voting, epoch reconfiguration, and evaluation scaffolds.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Public API — re-exports all stable and research symbols |
| `dna.py` | `AgentDNA` — embedded constitutional co-processor (443 ns/check); `constitutional_dna` context manager; `DNADisabledError` |
| `capability.py` | `Capability`, `CapabilityRegistry` — typed agent capability declarations |
| `contract.py` | `TaskContract`, `ContractStatus` — pre-execution task contracts |
| `artifact.py` | `Artifact`, `ArtifactStore` — in-memory content-addressed artifact store |
| `compiler.py` | `DAGCompiler`, `GoalSpec` — compiles goals into task DAGs |
| `swarm.py` | `SwarmExecutor`, `TaskDAG`, `TaskNode` — orchestrator-free DAG executor |
| `execution.py` | `ExecutionStatus`, `WorkReceipt` — execution outcome records |
| `mesh.py` | **`ConstitutionalMesh`** — peer-validated settlement; requires Ed25519 vote signatures (`register_local_signer`, `register_remote_agent`, `submit_vote`, `sign_vote`); `MeshProof`, `MeshResult`, `PeerAssignment`, error types |
| `debate_resolver.py` | `DebateResolver`, `DebateRecord`, `FinalVerdict`, `VerdictOutcome` — structured multi-agent debate resolution |
| `validator_set.py` | `ValidatorSet`, `CommitteeSelector`, `FaultDomainPolicy`, `SybilBoundViolation` — validator identity and committee selection |
| `quorum_certificate.py` | `QuorumCertificate`, `SignedVote`, `build_certificate`, `verify_certificate`, `detect_conflict` — aggregated vote certificates |
| `remote_vote_transport.py` | `RemoteVoteClient`, `RemoteVoteServer`, `LocalRemotePeer`, `RemoteVoteResponse` — transport for cross-node voting |
| `gossip_protocol.py` | WebSocket gossip transport for MerkleCRDT (requires extra `transport`) |
| `settlement_store.py` | `SettlementStore`, `JSONLSettlementStore`, `SQLiteSettlementStore`, `SettlementRecord`, `DuplicateSettlementError` — durable settlement persistence |
| `manifold.py` | `GovernanceManifold` + `sinkhorn_knopp` — Birkhoff/Sinkhorn baseline. **Do not "fix" collapse** — it is retained as empirical control |
| `spectral_sphere.py` | `SpectralSphereManifold`, `spectral_sphere_project` — production-direction trust manifold replacing Birkhoff; fixes uniformity collapse |
| `swarm_ode.py` | Projected RK4 continuous-time trust dynamics |
| `merkle_crdt.py` | `MerkleCRDT`, `DAGNode` — content-addressed DAG artifact store (SHA-256 CIDs, set-union merge) |
| `evolution_log.py` | **`EvolutionLog`** — SQLite-backed, append-only; enforces strict monotonicity + acceleration at write time; `DashboardRow`, `GapRecord`, `RegressionRecord`, `DecelerationRecord`, and matching error types |
| `epoch_reconfig.py` | `ConstitutionVersion`, `AmendmentProposal`, `TransitionCertificate`, `DriftBudget`, `compute_version_digest`, `evaluate_drift`, `verify_transition` |
| `latent_dna.py` | BODES hook + `LatentDNAWrapper.generate_governed()` — LLM residual steering (research extra; 53 known pre-existing RUF002/RUF003 errors for Greek characters) |
| `violation_subspace.py` | `ViolationSubspace`, `RiskAdaptiveSteering`, `fit_subspace`, `fit_leace`, `adversarial_score` — LEACE-based steering utilities |
| `private_vote.py` | Commit/reveal private ballots — `PrivateBallotBox`, `BallotChoice`, `build_commit`, `build_reveal`, `compute_nullifier`, `tally` |
| `privacy_accountant.py` | `PrivacyAccountant`, `PrivacyBudgetExhausted` — differential privacy budget tracking |
| `federated_bridge.py` | `FederatedConstitutionBridge`, `AgentCredential`, `FederationDecision` — cross-constitution federation |
| `mac_acgs_loop.py` | `MacAcgsLoop`, `MacAcgsConfig`, `MacAcgsCycleResult` — MAC-ACGS control loop |
| `bench.py` | `SwarmBenchmark`, `BenchmarkResult` — in-package benchmarking harness |
| `constants.py` | Shared numerical constants |
| `constitutional_swarm.py` / `constitution_sync.py` | (If present) top-level façade & constitution sync client |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `bittensor/` | Bittensor subnet integration — validator, miner, CAME coordinator, precedent store, tier manager, Arweave audit log (see `bittensor/AGENTS.md`) |
| `swe_bench/` | SWE-Bench evaluation scaffold — `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator` (see `swe_bench/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Any new public symbol **must** be added to `__init__.py`'s imports and `__all__` list (alphabetized).
- Vote submission paths require signatures: when modifying `mesh.py`, preserve the `register_local_signer` / `register_remote_agent` / `sign_vote` contract and raise `InvalidVoteSignatureError` on mismatch.
- `EvolutionLog` writes must remain strictly monotonic with non-negative acceleration; new write paths should raise `NonIncreasingValueError` / `DecelerationBlockedError` rather than silently dropping records.
- `manifold.py` is the **research control**, not a bug. Changes that "fix" its collapse must be sent through `spectral_sphere.py` instead.
- `latent_dna.py` carries 53 pre-existing ruff errors (Greek characters trigger RUF002/RUF003); do not mass-rewrite them — suppress targeted rules if lint-clean is required.

### Testing Requirements
- Each module has a matching `tests/test_<module>.py`. Keep parity when adding new modules.
- Research extras: `pip install -e ".[research]"` before running latent DNA, swarm ODE, or spectral sphere tests that need torch.
- Transport tests: `pip install -e ".[transport]"` for `test_gossip_protocol.py` / `test_remote_vote_transport.py`.
- Bittensor tests skip cleanly if the extra is absent.

### Common Patterns
- Errors are domain-specific exception classes (see `__init__.py`'s `__all__` — over a dozen error types). Prefer raising one of these over `ValueError`.
- Data classes (`@dataclass(frozen=True)` where possible) for records crossing module boundaries (`SettlementRecord`, `MeshProof`, `TransitionCertificate`, etc.).
- SQLite-backed stores (`EvolutionLog`, `SQLiteSettlementStore`) use WAL-safe append-only writes.
- CRDT and Merkle modules use SHA-256 CIDs for content addressing.

## Dependencies

### Internal
- Relies on `acgs-lite` for base constitutional action governance.

### External
- `cryptography` — Ed25519 signing for mesh votes and quorum certificates
- `numpy` — manifold/ODE/spectral math
- Optional: `torch`, `transformers`, `websockets`, `bittensor`

<!-- MANUAL: -->
