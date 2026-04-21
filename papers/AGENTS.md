<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# papers

## Purpose
Formal LaTeX conference paper drafts. Each subdirectory is self-contained (own `.sty`, `.bst`, `references.bib`, and `sections/`) so it can be built in isolation and submitted to its target venue.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `iclr2027/` | ICLR 2027 submission draft — focused on the trust-manifold contribution (see `iclr2027/AGENTS.md`) |
| `ndss2027/` | NDSS 2027 submission draft — focused on the security/protocol contribution (see `ndss2027/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Keep per-venue style files local to each subdirectory — do not promote them up to `papers/`.
- Every `\cite{...}` in any venue draft must resolve in that draft's local `references.bib`; `scripts/verify_citations.py` enforces this.
- Do not commit build artifacts other than the final `main.pdf` per venue; no `.aux`, `.log`, `.out`, etc.
- Markdown package paper lives under `paper/` (singular), not here.

## Dependencies

### Internal
- Shares claims with `paper/constitutional_swarm_paper.md`; keep numerical results consistent across all drafts.
- Verified by `scripts/verify_citations.py`.

<!-- MANUAL: -->
