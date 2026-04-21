<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# scripts

## Purpose
Operational one-off scripts: testnet deployment, citation verification for the paper drafts, and automated security-report generation. These are *not* part of the published Python package — they live outside the `src/` layout and are invoked directly with `python scripts/<name>.py`.

## Key Files
| File | Description |
|------|-------------|
| `testnet_deploy.py` | Deploys a constitutional-swarm testnet; consumes `examples/constitution.yaml` via the `--constitution` flag |
| `verify_citations.py` | Validates that every `\cite{...}` in `papers/**/*.tex` resolves to an entry in `references.bib` |
| `generate_security_report.py` | Produces `security-audit-report.md` from source scans and the `tests/security/` results |

## For AI Agents

### Working In This Directory
- Scripts here must be runnable with `python scripts/<name>.py --help` and use `argparse` for their CLI.
- Do not import from `tests/`; share helpers via `src/constitutional_swarm/` instead.
- Keep scripts idempotent where possible (safe to re-run).
- `__pycache__` appears here because the scripts are run directly — it is gitignored and not committed.

### Testing Requirements
- Scripts do not have dedicated tests, but `verify_citations.py` should be run as part of paper-preparation workflows.

## Dependencies

### Internal
- `constitutional_swarm` package (via installed `pip install -e .`)
- `examples/constitution.yaml` (for `testnet_deploy.py`)
- `references.bib` and `papers/` (for `verify_citations.py`)

<!-- MANUAL: -->
