<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# bittensor

## Purpose
Optional Bittensor subnet integration. Wires the constitutional-swarm governance primitives (validators, precedent store, tier manager, compliance certificates, Arweave audit trail) into Bittensor's axon/dendrite networking model. Gated behind the `bittensor` install extra — the core package must import without this subdir's heavy dependencies.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Public API surface for the subnet package |
| `validator.py` | Subnet validator — scores miners, signs precedent votes |
| `miner.py` | Subnet miner — responds to governance/evaluation synapses |
| `subnet_owner.py` | Owner-side hooks (registration, parameter updates) |
| `axon_server.py` | Axon serving layer for governance synapses |
| `dendrite_client.py` | Dendrite client for querying subnet peers |
| `synapses.py` / `synapse_adapter.py` / `protocol.py` | Synapse definitions and adapter glue |
| `came_coordinator.py` | CAME (Constitutional Agent-Miner Evaluation) coordinator |
| `governance_coordinator.py` | High-level governance orchestration across validators |
| `precedent_store.py` | Thread-safe (via `threading.Lock`) precedent cache — 3/5 super-majority quorum |
| `tier_manager.py` | Thread-safe (via `threading.Lock`) miner tier assignments |
| `threshold_updater.py` | Dynamic threshold tuning for miner scoring |
| `emission_calculator.py` | Reward emission distribution across miners |
| `rule_codifier.py` | Converts accepted precedents into codified rules |
| `constitution_sync.py` | Syncs the active constitution from the subnet owner |
| `compliance_certificate.py` | Generates and verifies miner compliance certificates |
| `authenticity_detector.py` | Detects inauthentic / replayed submissions |
| `chain_anchor.py` | Anchors state roots on-chain for tamper evidence |
| `arweave_audit_log.py` | **Two-phase commit audit log** — cache Phase 1 in `_retry_state`, clear only after Phase 2 success |
| `nmc_protocol.py` | Neural Merkle Commitment protocol |
| `cascade.py` | Cascade update propagation across tiers |
| `island_evolution.py` / `map_elites.py` | Evolutionary search over miner populations |

## For AI Agents

### Working In This Directory
- **Never break the thread-safety contract:** `PrecedentStore` and `TierManager` both guard state with `threading.Lock`. New mutators must acquire the lock.
- **Preserve the two-phase commit in `arweave_audit_log.py`:** Phase 1 result is cached in `_retry_state` and must only be cleared after Phase 2 confirms. Retries on failure read from the cache.
- Precedent quorum is `min_total_validators=5, min_votes_for_precedent=3` — do not change these defaults without coordinated spec + test updates.
- Keep imports of `bittensor`, heavy ML libs, and network stacks local to this subdirectory; the top-level package must remain importable without the `bittensor` extra installed.

### Testing Requirements
- `tests/test_bittensor_*.py` — protocol, e2e, compliance, chain anchor, arweave, precedent store, tier manager, emission calculator, governance coordinator, threshold updater, authenticity detector, rule codifier, synapse adapter, nmc protocol.
- Tests skip cleanly when `bittensor` extra is missing.

### Common Patterns
- Synapse request/response objects are pydantic-style dataclasses.
- All on-chain writes go through `chain_anchor.py` — do not write directly elsewhere.
- Audit events always flow through `arweave_audit_log.py`.

## Dependencies

### Internal
- `constitutional_swarm.mesh` — vote signatures, settlement
- `constitutional_swarm.evolution_log` — monotonicity enforcement
- `constitutional_swarm.quorum_certificate` — aggregated validator signatures

### External
- `bittensor` SDK (extra: `bittensor`)
- Arweave client library (via `arweave_audit_log.py`)

<!-- MANUAL: -->
