<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# paper

## Purpose
Long-form Markdown paper draft for the constitutional-swarm package itself — the "packaged research" writeup that accompanies the deployable library. Distinct from the formal LaTeX conference drafts in `papers/`, this is the authoritative narrative for the package's claims.

## Key Files
| File | Description |
|------|-------------|
| `README.md` | Entry point for the paper draft and manuscript assets |
| `constitutional_swarm_paper.md` | Long-form Markdown paper draft covering the four breakthrough patterns, theory, and empirical results |

## For AI Agents

### Working In This Directory
- Keep the Markdown paper in sync with the code: empirical numbers (e.g., 443 ns/check, 1019 tests, 3/5 quorum) should match the current implementation.
- Cross-reference modules with `src/constitutional_swarm/<name>.py` paths so readers can jump to the code.
- Do not commit rendered PDFs here — those belong in `papers/<venue>/`.

## Dependencies

### Internal
- Theory references the Birkhoff baseline (`manifold.py`) and its Spectral Sphere replacement (`spectral_sphere.py`).
- Cites shared BibTeX at the repo-root `references.bib`.

<!-- MANUAL: -->
