<!-- Parent: ../AGENTS.md -->

# constitutional_swarm

## Purpose
Top-level Python package implementing the four breakthrough patterns described in the package paper: (A) embedded Agent DNA constitutional validation, (B) stigmergic DAG-compiled swarm execution, (C) Byzantine-tolerant Constitutional Mesh with peer validation, and (D) manifold-constrained trust propagation (Sinkhorn/Birkhoff baseline and the production-direction Spectral Sphere replacement). Also hosts MCFS research modules — latent DNA residual steering, continuous-time swarm ODE, Merkle-CRDT artifact store, violation subspace / LEACE steering, federated/private voting, epoch reconfiguration, and evaluation scaffolds.

Full module inventory: see `README.md` at the repo root.

## Agent-Critical Files
| File | Why agents must know about it |
|------|-------------------------------|
| `manifold.py` | **Research control — do not "fix" its collapse.** Birkhoff/Sinkhorn baseline; uniformity collapse is retained as empirical proof. `spectral_sphere.py` is the production replacement. |
| `mesh/` | `ConstitutionalMesh` package. Requires Ed25519 vote signatures (`register_local_signer`, `register_remote_agent`, `sign_vote`); raise `InvalidVoteSignatureError` on mismatch. |
| `evolution_log.py` | Writes must remain strictly monotonic with non-negative acceleration; raise `NonIncreasingValueError` / `DecelerationBlockedError`, never silently drop records. |
| `latent_dna.py` | 53 pre-existing RUF002/RUF003 ruff errors (Greek characters). Do not mass-rewrite — suppress targeted rules if lint-clean is required. |
| `mac_acgs_loop.py` | Known import-boundary violation — see MANUAL section below for details. |
| `__init__.py` | Re-exports all stable symbols. Any new public symbol must be added here and to `__all__` (alphabetized). |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `bittensor/` | Bittensor subnet integration — validator, miner, CAME coordinator, precedent store, tier manager, Arweave audit log (see `bittensor/AGENTS.md`) |
| `swe_bench/` | SWE-Bench evaluation scaffold — `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator` (see `swe_bench/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Any new public symbol **must** be added to `__init__.py`'s imports and `__all__` list (alphabetized).
- Vote submission paths require signatures: when modifying `mesh/`, preserve the `register_local_signer` / `register_remote_agent` / `sign_vote` contract and raise `InvalidVoteSignatureError` on mismatch.
- `EvolutionLog` writes must remain strictly monotonic with non-negative acceleration; new write paths should raise `NonIncreasingValueError` / `DecelerationBlockedError` rather than silently dropping records.
- `manifold.py` is the **research control**, not a bug. Changes that "fix" its collapse must be sent through `spectral_sphere.py` instead.
- `latent_dna.py` carries 53 pre-existing ruff errors (Greek characters trigger RUF002/RUF003); do not mass-rewrite them — suppress targeted rules if lint-clean is required.
- Keep imports of `bittensor`, heavy ML libs, and network stacks gated behind their optional extras; the top-level package must remain importable without them.

### Testing Requirements
- Each module has a matching `tests/test_<module>.py`. Keep parity when adding new modules.
- Research extras: `pip install -e ".[research]"` before running latent DNA, swarm ODE, or spectral sphere tests that need torch.
- Transport tests: `pip install -e ".[transport]"` for `test_gossip_protocol.py` / `test_remote_vote_transport.py`.
- Bittensor tests skip cleanly if the extra is absent.

### Common Patterns
- Errors are domain-specific exception classes (see `__init__.py`'s `__all__`). Prefer raising one of these over `ValueError`.
- `@dataclass(frozen=True)` for records crossing module boundaries (`SettlementRecord`, `MeshProof`, `TransitionCertificate`, etc.).
- SQLite-backed stores (`EvolutionLog`, `SQLiteSettlementStore`) use WAL-safe append-only writes.
- CRDT and Merkle modules use SHA-256 CIDs for content addressing.

<!-- MANUAL: -->

### Known Issue: mac_acgs_loop.py bittensor import leak

`mac_acgs_loop.py` line 43 unconditionally imports `bittensor.came_coordinator`:

```python
from constitutional_swarm.bittensor.came_coordinator import (...)
```

This loads the entire bittensor subpackage (~458ms, measured 2026-04-24) on every
`import constitutional_swarm`, even when bittensor is not in use. Bittensor is an
optional extra; this violates the "keep core import-free of optional extras" rule.

**Fix:** move the import inside the method that constructs `CAMECoordinator`:

```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator

def _build_came_coordinator(self, ...) -> "CAMECoordinator":
    from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
    return CAMECoordinator(...)
```

Tracked in: `docs/RUNTIME_OPTIMIZATION_REPORT.md` (bottleneck B1).
