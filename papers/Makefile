# Papers Makefile
# Builds LaTeX papers for ICLR 2027 and NDSS 2027 submissions.
#
# Targets:
#   paper-iclr   — build ICLR 2027 paper (3-pass pdflatex + bibtex)
#   paper-ndss   — build NDSS 2027 paper (3-pass pdflatex + bibtex)
#   paper-both   — build both papers
#   paper-clean  — remove LaTeX auxiliary files

ICLR_DIR := iclr2027
NDSS_DIR := ndss2027

.PHONY: paper-iclr paper-ndss paper-both paper-clean

paper-iclr:
	cd $(ICLR_DIR) && \
	  pdflatex -interaction=nonstopmode main.tex && \
	  bibtex main && \
	  pdflatex -interaction=nonstopmode main.tex && \
	  pdflatex -interaction=nonstopmode main.tex
	@echo "ICLR 2027 paper built: $(ICLR_DIR)/main.pdf"

paper-ndss:
	cd $(NDSS_DIR) && \
	  pdflatex -interaction=nonstopmode main.tex && \
	  bibtex main && \
	  pdflatex -interaction=nonstopmode main.tex && \
	  pdflatex -interaction=nonstopmode main.tex
	@echo "NDSS 2027 paper built: $(NDSS_DIR)/main.pdf"

paper-both: paper-iclr paper-ndss

paper-clean:
	rm -f */*.aux */*.bbl */*.blg */*.log */*.out */*.toc
	rm -f */*.fls */*.fdb_latexmk */*.synctex.gz
	@echo "LaTeX auxiliary files removed."
