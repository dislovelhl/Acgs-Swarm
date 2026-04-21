<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# swe_bench

## Purpose
Evaluation scaffold for running constitutional-swarm against the SWE-Bench software-engineering benchmark. Provides a governed agent, a benchmark harness, and a swarm coordinator that drives multi-agent task execution under constitutional validation.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Public exports: `CodexSWEBenchAgent`, `SWEBenchAgent`, `SWEBenchHarness`, `SWEPatch` |
| `agent.py` | `SWEBenchAgent` — governed single-agent wrapper that executes SWE-Bench instances under `AgentDNA` + mesh settlement |
| `harness.py` | `SWEBenchHarness` — orchestrates instance loading, agent invocation, and result scoring |
| `swarm_coordinator.py` | `SwarmCoordinator` — distributes SWE-Bench instances across a mesh of agents via `SwarmExecutor` |

## For AI Agents

### Working In This Directory
- Treat this as an evaluation (non-production) surface — changes here must not leak into the stable core API.
- When adding new metrics or scoring rules, update `test_swe_bench_agent.py` and `test_swarm_coordinator.py` in the same change.
- Keep SWE-Bench dataset access behind explicit loader functions; do not hard-code paths.

### Testing Requirements
- `tests/test_swe_bench_agent.py`, `tests/test_swarm_coordinator.py`.

## Dependencies

### Internal
- `constitutional_swarm.dna` — embedded constitutional validation
- `constitutional_swarm.swarm` — DAG execution
- `constitutional_swarm.mesh` — peer settlement

### External
- SWE-Bench dataset / harness utilities (loaded lazily)

<!-- MANUAL: -->
