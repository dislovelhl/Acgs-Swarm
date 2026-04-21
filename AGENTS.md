<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# constitutional-swarm

## Purpose
Orchestrator-free constitutional governance runtime for multi-agent systems. Built on `acgs-lite`, it embeds governance per agent, supports DAG-compiled execution without a central orchestrator, provides peer-validated settlement via `ConstitutionalMesh`, and ships research modules for the MCFS (Manifold-Constrained Federated Swarm) stack — latent DNA steering, spectral-sphere trust dynamics, Merkle-CRDT artifact stores, and SWE-Bench evaluation scaffolds. This package is a **git submodule** of the ACGS monorepo; always run `git add`/`git commit` from inside this directory, not the parent repo.

## Key Files
| File | Description |
|------|-------------|
| `pyproject.toml` | Package metadata, optional extras (`transport`, `research`, `bittensor`), ruff config, pytest config (`pythonpath = ["src"]`) |
| `uv.lock` | Locked dependency graph for `uv` |
| `README.md` | User-facing overview, install paths, maturity tiers, public API examples |
| `CHANGELOG.md` | Release notes for shipped package behavior |
| `CLAUDE.md` | Claude Code working notes (submodule rules, test commands, module map, invariants) |
| `HANDOFF_CODEX.md` | Historical implementation handoff for Codex/OMX agents |
| `SECURITY.md` | Security contact and disclosure policy |
| `CODEOWNERS` | Review routing for protected paths |
| `references.bib` | Shared BibTeX entries for papers/ drafts |
| `security-audit-report.md` | Snapshot of latest security audit findings |
| `delivery-hygiene-report.md` | Tracker for release hygiene items |
| `style-improvement-report.md` | Lint/style debt tracker (e.g., the 53 pre-existing RUF002/RUF003 in `latent_dna.py`) |
| `test-coverage-report.md` | Coverage summary, including the 2 expected xfails (Birkhoff collapse) |
| `SYSTEMIC_IMPROVEMENT.md` | Cross-cutting architectural improvement notes |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/` | Python package source for `constitutional_swarm` (see `src/AGENTS.md`) |
| `tests/` | Pytest suite — 1019 passing + 2 expected xfails (see `tests/AGENTS.md`) |
| `docs/` | Long-form design docs, including MACI DP protocol draft (see `docs/AGENTS.md`) |
| `examples/` | Minimal runnable artifacts (e.g., sample constitution YAML) (see `examples/AGENTS.md`) |
| `scripts/` | Operational scripts: testnet deploy, citation verification, security reporting (see `scripts/AGENTS.md`) |
| `specs/` | TLA+ formal specifications and model-checker configs (see `specs/AGENTS.md`) |
| `paper/` | Package paper draft (Markdown, long-form) (see `paper/AGENTS.md`) |
| `papers/` | Conference paper drafts: ICLR 2027, NDSS 2027 (see `papers/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **This is a git submodule.** Always run `git add` / `git commit` from inside `packages/constitutional_swarm/`, not the monorepo root. Stage only `.py` files explicitly — never `git add -A`.
- Base branch: `main`. Parent repo integration branch: `fix/p0-security-hardening`.
- Do not "fix" `src/constitutional_swarm/manifold.py` (Birkhoff/Sinkhorn baseline) — its uniformity collapse is the empirical proof kept as a research control. `spectral_sphere.py` is the production-direction replacement.
- Feature branches live in `.worktrees/` (gitignored); create with `git worktree add .worktrees/<name> -b <name>`.
- Repository memories persist in CLAUDE.md and `.claude/rules/`; Codex/OMX read this `AGENTS.md`.

### Testing Requirements
```bash
# From inside this submodule
python -m pytest tests/ --import-mode=importlib -q     # 1019 passed, 2 xfailed
python -m ruff check src/                              # 53 known pre-existing errors in latent_dna.py
python -m ruff format src/
```
WebSocket gossip tests require `pip install -e ".[transport]"`.

### Common Patterns
- Optional extras gate heavy dependencies: `transport` (websockets), `research` (torch + latent DNA), `bittensor` (subnet integration). Keep core import-free of these.
- Vote signatures are **mandatory** on `ConstitutionalMesh.submit_vote` (Ed25519 via `register_local_signer` / `sign_vote` / `register_remote_agent`).
- Two-phase commit pattern in `bittensor/arweave_audit_log.py`: cache Phase 1 in `_retry_state`, clear only on Phase 2 success.
- `TierManager` and `PrecedentStore` are thread-safe via `threading.Lock`.

## Key Invariants
- Constitutional hash: `608508a9bd224290`
- Precedent quorum: 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`)
- `EvolutionLog` enforces strict monotonicity + acceleration at write time (declarative, SQLite-backed, append-only)
- Manifold peer selection is wired in `mesh.py:_select_peers()` (trust-weighted sampling + one exploration slot)

## Dependencies

### External (core)
- `acgs-lite` — base constitutional action governance
- `cryptography` — Ed25519 signatures
- Python 3.11+

### External (optional)
- `websockets` (extra: `transport`) — gossip protocol
- `torch`, `transformers` (extra: `research`) — latent DNA steering
- `bittensor` (extra: `bittensor`) — subnet integration

<!-- MANUAL: Notes added below this line are preserved on regeneration. -->
