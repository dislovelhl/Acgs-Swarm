<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# tests

## Purpose
Pytest suite covering every module in `src/constitutional_swarm`. Current baseline: **1603 passed, 1 skipped, 2 xfailed** (xfails expected — Birkhoff uniformity collapse, which is the research control result). Tests are organized one-to-one with source modules plus a few cross-cutting integration suites.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Makes `tests/` a package for `--import-mode=importlib` discovery |
| `test_constitutional_swarm.py` | Top-level smoke + public-API coverage |
| `test_mesh.py` | `ConstitutionalMesh` — peer validation, vote signatures, settlement |
| `test_manifold.py` | Birkhoff/Sinkhorn baseline — includes the 2 expected xfails |
| `test_spectral_sphere_retention.py` | `SpectralSphereManifold` — verifies collapse is fixed |
| `test_manifold_degeneration.py` | Regression guard for uniformity collapse |
| `test_evolution_log.py` | Strict monotonicity + acceleration write-time enforcement |
| `test_merkle_crdt.py` | Content-addressed DAG artifact store |
| `test_swarm_ode.py`, `test_swarm_ode_crdt_bridge.py` | Continuous-time trust dynamics |
| `test_gossip_protocol.py` | WebSocket gossip (requires `.[transport]` extra) |
| `test_remote_vote_transport.py` | Remote vote client/server roundtrip |
| `test_latent_dna.py`, `test_bodes_subspace_hook.py`, `test_bodes_subspace_leace_hook.py` | Latent DNA + BODES residual steering |
| `test_violation_subspace.py` | LEACE / subspace fitting |
| `test_private_vote.py`, `test_private_vote_v2.py` | Commit/reveal private ballots |
| `test_quorum_certificate.py`, `test_projector_certificate.py` | Aggregate signature certificates |
| `test_epoch_reconfig.py` | Constitution amendment and drift budget |
| `test_compiler.py`, `test_bench.py` | DAG compiler and benchmarking harness |
| `test_kill_switch.py`, `test_state_continuity.py` | Safety / continuity invariants |
| `test_cross_package_contracts.py`, `test_integration_acgs_lite.py` | Cross-package interaction with `acgs-lite` |
| `test_import_boundaries.py`, `test_import_boundaries_acgs_lite.py` | Enforces that core imports don't pull optional extras |
| `test_full_stack_integration.py`, `test_dag_coordinator_deep.py` | End-to-end integration scenarios |
| `test_trust_manifold_decision.py` | Manifold peer selection in `mesh.py:_select_peers()` |
| `test_rule_consistency.py`, `test_rule_codifier.py` | Rule codification invariants |
| `test_bittensor_*.py` | Bittensor subnet integration (skip without `.[bittensor]`) |
| `test_swe_bench_agent.py`, `test_swarm_coordinator.py` | SWE-Bench evaluation scaffold |
| `test_breakthrough_modules.py`, `test_evolutionary_systems.py` | Aggregate smoke over research modules |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `security/` | Security regression tests for specific CVE-style findings (see `security/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Run with `--import-mode=importlib` (required; `pyproject.toml` sets `pythonpath = ["src"]`).
- **Do not "fix" the two xfails in `test_manifold.py`** — they document the Birkhoff uniformity collapse and are expected to fail indefinitely.
- When adding a source module, add the matching `test_<module>.py` in this directory in the same change.
- Keep extras gating consistent: tests that need `transport`, `research`, or `bittensor` extras should import lazily or use `pytest.importorskip` so a minimal install still collects cleanly.
- Vote-related tests must exercise the Ed25519 signature path (`register_local_signer`/`sign_vote`) — unsigned votes should raise `InvalidVoteSignatureError`.

### Testing Requirements
```bash
python -m pytest tests/ --import-mode=importlib -q
# or, from the monorepo root:
python -m pytest packages/constitutional_swarm/tests/ --import-mode=importlib
```
Single module: `python -m pytest tests/test_mesh.py -v`.

### Common Patterns
- Fixtures are local to each test module (no shared `conftest.py` at the time of writing).
- Settlement and evolution-log tests use `tmp_path` for SQLite DB files.
- Cryptography tests generate ephemeral Ed25519 keypairs in-test.

## Dependencies

### Internal
- Imports `constitutional_swarm.*` via `pythonpath = ["src"]`.

### External
- `pytest`, `pytest-benchmark` (for `.benchmarks/` output)
- `cryptography` — key generation in signature tests

<!-- MANUAL: -->
