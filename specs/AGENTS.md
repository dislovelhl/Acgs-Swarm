<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# specs

## Purpose
TLA+ formal specifications and TLC model-checker configurations for the protocols implemented in `src/constitutional_swarm/`. Covers the `ConstitutionalMesh` and the constitution reconfiguration (epoch) protocol. TLA+ is the source of truth for protocol behavior; Python implementations must conform.

## Key Files
| File | Description |
|------|-------------|
| `mesh.tla` | TLA+ spec of the `ConstitutionalMesh` peer-validation + settlement protocol |
| `MeshMC.tla` | Model-checking harness instantiating `mesh.tla` with bounded parameters for TLC |
| `MeshMC.cfg` | TLC configuration: constants, invariants, temporal properties to check for `MeshMC.tla` |
| `constitution_reconfig.tla` | TLA+ spec of epoch reconfiguration / amendment protocol — matches `src/constitutional_swarm/epoch_reconfig.py` |
| `constitution_reconfig.cfg` | TLC configuration for `constitution_reconfig.tla` |
| `README.md` | How to run TLC against these specs |

## For AI Agents

### Working In This Directory
- The `.tla` files are the **protocol source of truth**. If Python and TLA+ disagree, fix the Python side (or amend the TLA+ with justification).
- When changing the protocol, update both the `.tla` file and any existing Python implementation in the same change. Re-run TLC before merging.
- TLC is invoked manually; there is no CI integration. See `specs/README.md` for exact commands.
- Keep `.cfg` files bounded enough that TLC finishes in reasonable time for a local run.

### Common Patterns
- Invariants captured in `.cfg` files should have matching assertions or tests in `tests/`.
- Temporal properties (liveness) use standard TLA+ fairness constructs.

## Dependencies

### Internal
- `src/constitutional_swarm/mesh.py` — must conform to `mesh.tla`
- `src/constitutional_swarm/epoch_reconfig.py` — must conform to `constitution_reconfig.tla`

### External
- TLA+ toolchain (TLC model checker), run locally — not installed by `pyproject.toml`

<!-- MANUAL: -->
