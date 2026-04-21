<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# ndss2027

## Purpose
NDSS 2027 submission draft. Focuses on the security/protocol contribution: `ConstitutionalMesh` peer validation, Ed25519-signed votes, private voting (commit/reveal + MACI-DP), and the two-phase Arweave audit log.

## Key Files
| File | Description |
|------|-------------|
| `main.tex` | Top-level LaTeX document |
| `main.pdf` | Latest built PDF of the draft |
| `references.bib` | BibTeX entries scoped to this paper |
| `algorithm2e.sty` | Vendored LaTeX package |
| `TUptm.fd` | Font definition file |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `sections/` | Per-section `.tex` files: `abstract.tex`, `introduction.tex`, `protocol.tex`, `security_analysis.tex`, `evaluation.tex`, `conclusion.tex` |

## For AI Agents

### Working In This Directory
- Edit per-section files in `sections/` rather than `main.tex` when modifying prose.
- Security claims must map to concrete tests under `tests/security/` and to the TLA+ specs in `specs/`.
- Every `\cite{...}` must exist in this directory's `references.bib`; run `python scripts/verify_citations.py`.
- Regenerate `main.pdf` before committing textual changes.

## Dependencies

### Internal
- `specs/mesh.tla` and `specs/constitution_reconfig.tla` — formal protocol specs backing the security analysis.
- `tests/security/test_finding_001_unauth_ws.py` — regression coverage.

<!-- MANUAL: -->
