<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# src

## Purpose
Python source root. Contains the single package `constitutional_swarm`. `pyproject.toml` sets `pythonpath = ["src"]` so tests and imports resolve `constitutional_swarm.*` directly from here.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `constitutional_swarm/` | Top-level package — mesh, DAG execution, manifold trust, evolution log, research modules (see `constitutional_swarm/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Do not add sibling packages here; keep this a single-package source root.
- New modules go under `constitutional_swarm/` and must be re-exported from `constitutional_swarm/__init__.py` if they are part of the public API.

<!-- MANUAL: -->
