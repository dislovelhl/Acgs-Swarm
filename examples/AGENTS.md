<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# examples

## Purpose
Minimal, runnable sample artifacts used both as user onboarding material and as inputs consumed by scripts and tests. Keep each example small enough that a reader can understand it at a glance.

## Key Files
| File | Description |
|------|-------------|
| `constitution.yaml` | Minimal sample constitution — 4 principles, 3 domains, quorum=0.6. Required by `scripts/testnet_deploy.py --constitution` |

## For AI Agents

### Working In This Directory
- Keep examples minimal — a user must be able to read them in under a minute.
- If you change `constitution.yaml`'s schema, update `scripts/testnet_deploy.py` and any tests that load it in the same change.
- Do not add generated / transient output here; examples are hand-authored inputs only.

## Dependencies

### Internal
- Consumed by `scripts/testnet_deploy.py` and documented in `README.md`.

<!-- MANUAL: -->
