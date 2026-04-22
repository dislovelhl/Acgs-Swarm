<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# iclr2027

## Purpose
ICLR 2027 submission draft. Uses the official ICLR 2025 style files (reused) and focuses on the trust-manifold contribution — contrasting the Birkhoff/Sinkhorn baseline's uniformity collapse against the Spectral Sphere replacement.

## Key Files
| File | Description |
|------|-------------|
| `main.tex` | Top-level LaTeX document |
| `main.pdf` | Latest built PDF of the draft |
| `references.bib` | BibTeX entries scoped to this paper |
| `iclr2025_conference.cls` | ICLR class file (reused for 2027 draft) |
| `iclr2025_conference.sty` | ICLR style file |
| `iclr2025_conference.bst` | ICLR bibliography style |
| `natbib.sty`, `fancyhdr.sty`, `algorithm2e.sty` | Vendored LaTeX packages |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `sections/` | Per-section `.tex` files: `abstract.tex`, `introduction.tex`, `related_work.tex`, `method.tex`, `experiments.tex`, `conclusion.tex` |
| `figures/` | TikZ figure sources: `birkhoff_collapse.tex`, `variance_comparison.tex` |

## For AI Agents

### Working In This Directory
- Edit per-section files in `sections/` rather than `main.tex` when modifying prose.
- Regenerate `main.pdf` before committing textual changes.
- Every `\cite{...}` must exist in this directory's `references.bib`; run `python scripts/verify_citations.py` from the repo root.
- Figures are TikZ-native `.tex` files — do not replace with raster images.

## Dependencies

### Internal
- Empirical numbers sourced from `tests/test_manifold.py` (Birkhoff collapse xfails) and `tests/test_spectral_sphere_retention.py`.

<!-- MANUAL: -->
