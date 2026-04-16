# constitutional_swarm — Claude Notes

For repo-wide rules, see `/CLAUDE.md` and `.claude/rules/` (Claude Code auto-loads these). AGENTS.md serves Codex/OMX.

## Submodule operations

This is a git submodule. Always run `git add` / `git commit` from inside
`packages/constitutional_swarm/`, not the repo root.

- Base branch: `main`
- Parent repo integration branch: `fix/p0-security-hardening`
- Stage only `.py` files explicitly — never `git add -A`

## Testing

```bash
# From repo root
python -m pytest packages/constitutional_swarm/tests/ --import-mode=importlib

# From inside the submodule
python -m pytest tests/ --import-mode=importlib
```

## Commands

```bash
# Lint (53 pre-existing errors in latent_dna.py — suppress RUF002/RUF003 for Greek chars)
python -m ruff check src/

# Format
python -m ruff format src/

# Test (1018 tests, 2 xfailed — Birkhoff collapse, expected)
python -m pytest tests/ --import-mode=importlib -q

# Test WebSocket transport (requires extra)
pip install -e ".[transport]" && python -m pytest tests/test_gossip_protocol.py -v
```

## Module map (MCFS research stack)

| Module | Purpose |
|--------|---------|
| `evolution_log.py` | Declarative evolution log — SQLite-backed, append-only, enforces strict monotonicity + acceleration at write time |
| `latent_dna.py` | BODES hook + `LatentDNAWrapper.generate_governed()` — LLM residual steering |
| `spectral_sphere.py` | SpectralSphereManifold — replaces Birkhoff, fixes uniformity collapse |
| `merkle_crdt.py` | Content-addressed DAG artifact store (SHA-256 CIDs, set-union merge) |
| `swarm_ode.py` | Projected RK4 continuous-time trust dynamics |
| `gossip_protocol.py` | WebSocket gossip transport for MerkleCRDT (`pip install .[transport]`) |
| `swe_bench/` | Evaluation scaffold — `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator` |
| `manifold.py` | Birkhoff/Sinkhorn baseline — **do not fix**, collapse is the empirical proof |
| `mesh.py` | Full swarm mesh + settlement store |
| `bittensor/` | Bittensor subnet integration (`pip install .[bittensor]`) |

## Worktree workflow

Feature branches live in `.worktrees/` (gitignored). Create with:

```bash
git worktree add .worktrees/<branch-name> -b <branch-name>
cd .worktrees/<branch-name>
# pytest needs pythonpath = ["src"] in pyproject.toml (already present in worktree copy)
```

## Key invariants

- Constitutional hash: `608508a9bd224290`
- Precedent quorum: 3/5 super-majority (`min_total_validators=5, min_votes_for_precedent=3`)
- ArweaveAuditLogger: two-phase commit — cache Phase 1 result in `_retry_state`, clear only on success
- TierManager and PrecedentStore are thread-safe via `threading.Lock`
- Manifold peer selection is wired in `mesh.py:_select_peers()` — trust-weighted sampling with one exploration slot

## Supporting docs

- `README.md` — package overview, install paths, and public API examples
- `CHANGELOG.md` — release notes for shipped package behavior
- `paper/README.md` — entry point for the package paper draft and manuscript assets
- `paper/constitutional_swarm_paper.md` — long-form Markdown paper draft for package claims and theory
- `docs/maci_dp_protocol.md` — MCFS privacy and MACI protocol draft
- `HANDOFF_CODEX.md` — historical implementation handoff for Codex/OMX
- `security-audit-report.md` — focused security findings for remote voting and persistence
- `test-coverage-report.md` — regression-gap analysis and targeted test coverage notes
- `style-improvement-report.md` — API-surface and maintainability review
- `delivery-hygiene-report.md` — release-shape and commit-structure audit
- `SYSTEMIC_IMPROVEMENT.md` — cross-cutting improvement log for the current package line

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming -> invoke office-hours
- Bugs, errors, "why is this broken", 500 errors -> invoke investigate
- Ship, deploy, push, create PR -> invoke ship
- QA, test the site, find bugs -> invoke qa
- Code review, check my diff -> invoke review
- Update docs after shipping -> invoke document-release
- Weekly retro -> invoke retro
- Design system, brand -> invoke design-consultation
- Visual audit, design polish -> invoke design-review
- Architecture review -> invoke plan-eng-review
- Save progress, checkpoint, resume -> invoke checkpoint
- Code quality, health check -> invoke health
