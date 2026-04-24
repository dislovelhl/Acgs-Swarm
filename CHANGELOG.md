# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [1.0.0] - 2026-04-23

### Added
- Signed envelope for remote votes: nonce + timestamp + Ed25519 signature; replay window enforced server-side (task sec-wss-envelope)
- Startup settlement reconciliation: `ConstitutionalMesh.reconcile_pending_settlements()` returns a `ReconciliationReport`; optional `auto_reconcile` kwarg on mesh construction (task sec-startup-reconcile)
- `RemoteVoteReplayError`, `RecoveredAssignmentError` exceptions exposed via top-level import
- `SettlementRecord.schema_version` (default 1) and `is_recovered` flag persisted in JSONL + SQLite stores (idempotent ALTER on load) (tasks sec-schema-version-prep, sec-settle-replay)
- `GoalStep` dataclass with Mapping compatibility; unknown keys preserved in `GoalStep.extra` (task refactor-goalspec)
- Shadow spectral invariant test (`tests/test_shadow_spectral_invariant.py`, N=100 zero-divergence) (task cov-e2e-remote)

### Changed
- Remote vote transport: tri-state `transport_security: Literal["plaintext", "tls", "auto"]`; `auto` resolves to `tls` unless host is loopback; passing both `ssl_context` and `transport_security` raises `ValueError` (task sec-wss-envelope)
- Envelope requirement: remote vote requests missing nonce/timestamp are rejected; no legacy compat path
- Public API narrowed: top-level `__all__` now = `["AgentDNA", "ConstitutionalMesh", "GovernanceManifold", "SwarmExecutor", "TaskDAG"]`. Advanced names remain importable from submodules (e.g. `from constitutional_swarm.remote_vote_transport import RemoteVoteClient`) (task api-narrow-final)
- `mesh.py` split into `mesh/` package: `core`, `voting`, `settlement`, `peers`, `exceptions` (backward-compat facade in `__init__.py`) (task refactor-mesh-split)
- `remote_vote_transport.py` split into `remote_vote_transport/` package: `protocol`, `transport`, `peer` (backward-compat facade) (task refactor-transport-split)

### Removed
- Legacy envelope compat path for unsigned remote vote requests

### Migration
- See `MIGRATION.md` for the 0.3 -> 1.0 upgrade guide (transport_security, schema_version, register_agent)


## [0.3.0] - 2026-04-23

### Breaking Changes

`register_agent()` has been **removed** (not just deprecated). Calling it now raises
`AttributeError`. See [MIGRATION.md](MIGRATION.md) for the upgrade guide.

**Before (0.2.x):**
```python
# public-key-only peer
mesh.register_agent("agent-1", vote_public_key=pub_key)
```

**After (0.3.0):**
```python
# public-key-only peer (signing happens outside this process)
mesh.register_remote_agent("agent-1", vote_public_key=pub_key)

# local signer (this process holds and uses the private key)
mesh.register_local_signer("agent-1", vote_private_key=priv_key)
```

### Added
- Added `MIGRATION.md` with a mapping table and before/after examples for the
  `register_agent()` → `register_local_signer()` / `register_remote_agent()` migration.
- Added two new `collect_remote_votes()` tests: missing-route `KeyError` and
  wrong-`assignment_id` response handling.

### Changed
- `register_agent()` now raises `AttributeError` (removed; was `DeprecationWarning` in 0.2.x).
- `collect_remote_votes()` KeyError message now names the missing peer ID and
  shows the expected `peer_routes` key syntax.
- `HarnessResult.resolved` and `LocalSWEBenchHarness.evaluate()` docstrings now
  document the `evaluation_mode="local_dockerless"` distinction so downstream
  consumers can distinguish local results from official SWE-bench leaderboard scores.

## [0.2.0] - 2026-04-16

### Added
- Added `EvolutionLog`, a SQLite-backed append-only governance metric log whose SQLite triggers reject regressions, gaps, and deceleration at write time for capability-curve entries.
- Added remote vote transport primitives so public-key-only peers can validate and sign mesh votes outside the producer process.
- Added remote vote transport tests and evolution log tests, bringing the package test inventory from 38 to 40 files.
- Added self-contained paper build assets so the ICLR 2027 and NDSS 2027 manuscripts compile directly from the repo.

### Changed
- Mesh peers now register explicitly with `register_local_signer(...)` and `register_remote_agent(...)`, and the public docs and examples now match that split.
- Remote vote verification now requires detached signatures, and malformed remote vote responses fail closed instead of coercing types.
- Deterministic DAG node IDs now use explicit collision detection during compiler and DAG node creation.
- The constitutional mesh settlement path now rejects duplicate JSONL settlement appends and avoids persisting raw content in settled records.
- Package guidance, README examples, and paper text now document the new governance and transport behavior.

### Fixed
- Fixed the paper sources so both submissions build cleanly with local vendored template assets and warning-free LaTeX logs.
- Removed tracked Python bytecode caches from the repository and ignored local Codex/OMX session artifacts and generated paper PDFs.

### Removed
- Removed the obsolete `HANDOFF_FORGECODE.md` handoff document.

### Breaking Changes

`register_agent()` has been split into two explicit methods. Code using the old API will receive a `DeprecationWarning` and will break in v0.3.0.

**Before (0.1.x):**
```python
mesh.register_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)
```

**After (0.2.x):**
```python
# For peers whose keys live outside this process:
mesh.register_remote_agent(
    agent_id="agent-1",
    domain="safety",
    vote_public_key=my_pub_key,
)

# For peers whose private key lives in this process:
mesh.register_local_signer(
    agent_id="agent-1",
    domain="safety",
    vote_private_key=my_priv_key,
)
```
