# Papers Figure Reproducibility Audit

Generated: 2026-04-23

Scope: `papers/iclr2027/**/*.tex` and `papers/ndss2027/**/*.tex`, plus image assets and potential figure-generation sources under `scripts/`, `papers/*/figures/`, and paper-local `README*` / `AGENTS.md`.

## Inventory

### `\includegraphics` References

No active `\includegraphics{...}` references were found in either paper tree.

### Figure Inputs

| Paper | Referencing TeX | Figure source |
| --- | --- | --- |
| ICLR 2027 | `papers/iclr2027/sections/introduction.tex` | `papers/iclr2027/figures/birkhoff_collapse.tex` |
| ICLR 2027 | `papers/iclr2027/sections/experiments.tex` | `papers/iclr2027/figures/variance_comparison.tex` |

NDSS 2027 has no active `figures/...` inputs.

### Image/PDF Files Present

| Paper | Asset |
| --- | --- |
| ICLR 2027 | `papers/iclr2027/main.pdf` |
| NDSS 2027 | `papers/ndss2027/main.pdf` |

`main.pdf` is the rendered paper output for each venue, not a standalone figure asset.

## Generator Search

Checked surfaces:

- `scripts/`
- `papers/iclr2027/figures/`
- `papers/ndss2027/figures/` (not present)
- paper-local `README*` files (none present)
- `papers/AGENTS.md`, `papers/iclr2027/AGENTS.md`, `papers/ndss2027/AGENTS.md`

No checked-in `.py`, `.R`, `.ipynb`, or Makefile target was found that writes or regenerates either ICLR figure. The ICLR figure files are TikZ/PGFPlots source with hard-coded coordinate data; they can be rendered by LaTeX as part of `main.pdf`, but there is no seeded code or data pipeline that recomputes the plotted values and emits the figure source or an image artifact.

No generator was run, because no qualifying generator script or Makefile target was found.

## Figure Classification

| Paper | Figure path | Status | Generator path or none | Reproducibility |
| --- | --- | --- | --- | --- |
| ICLR 2027 | `papers/iclr2027/figures/birkhoff_collapse.tex` | `data_only_no_generator` | none | TikZ/PGFPlots source is checked in, but plotted coordinates are manually embedded. No seeded generator was found, so byte-for-byte regeneration from checked-in data or seeded code is not verifiable. |
| ICLR 2027 | `papers/iclr2027/figures/variance_comparison.tex` | `data_only_no_generator` | none | TikZ/PGFPlots source is checked in, but plotted coordinates are manually embedded. No seeded generator was found, so byte-for-byte regeneration from checked-in data or seeded code is not verifiable. |

## Count Breakdown

| Paper | `generator_found` | `data_only_no_generator` | `no_source_found` | Notes |
| --- | ---: | ---: | ---: | --- |
| ICLR 2027 | 0 | 2 | 0 | Two TikZ figure sources are referenced by the paper. |
| NDSS 2027 | 0 | 0 | 0 | No figure inputs or `\includegraphics` references found. |

## Remediation

- Add `scripts/figure_birkhoff_collapse.py` that accepts a fixed seed, recomputes the Birkhoff/Sinkhorn and SpectralSphere variance-retention series, and emits `papers/iclr2027/figures/birkhoff_collapse.tex` or a documented generated asset.
- Add `scripts/figure_variance_comparison.py` that accepts a fixed seed, recomputes the cycle-10 comparison values, and emits `papers/iclr2027/figures/variance_comparison.tex` or a documented generated asset.
- Add a Makefile target or documented command that runs all figure generators and compares generated output against the checked-in figure sources/assets.
- Store any non-code input data under a checked-in data path and reference it from the generator, rather than embedding unexplained coordinates directly in TikZ.

## Evidence Commands

```bash
rg -n -F '\\includegraphics' papers/iclr2027 papers/ndss2027
find papers/iclr2027 papers/ndss2027 -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.pdf' -o -iname '*.svg' -o -iname '*.eps' -o -iname '*.tikz' \) -print | sort
find papers/iclr2027 papers/ndss2027 scripts -type f \( -iname '*.py' -o -iname '*.R' -o -iname '*.ipynb' -o -iname 'Makefile' -o -iname 'README*' -o -iname 'AGENTS.md' \) -print | sort
rg -n 'argparse|--seed|random|np\.random|torch\.manual_seed|savefig|figures|\.png|\.pdf|\.svg|tikz|pgfplots' scripts papers/iclr2027 papers/ndss2027 -g '!*.sty' -g '!*.cls' -g '!*.bst'
```
