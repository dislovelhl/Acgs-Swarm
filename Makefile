# constitutional-swarm — agent-operable entrypoints
#
# Every supported workflow has a one-command target here. Agents (and humans)
# should never need to inspect source to learn how to run the project.
#
# Runner: this repo is uv-managed (see uv.lock). All targets shell out through
# `uv run` against a project virtualenv. The system interpreter is python3;
# there is no bare `python`, `pip`, `ruff`, or `pytest` on PATH — use these
# targets (or `uv run <tool>`), not global tools.
#
# Standalone vs monorepo: pyproject pins `acgs-lite = { workspace = true }`
# for in-monorepo development. A standalone checkout has no workspace, so
# `make setup` passes `--no-sources` to resolve acgs-lite from PyPI instead.
# See BLOCKERS.md (B1).

UV ?= uv
# Extras installed by `make setup`. Override: `make setup EXTRAS="dev transport research"`
EXTRAS ?= dev transport
SYNC_FLAGS ?= --no-sources $(addprefix --extra ,$(EXTRAS))
# Test selection: skip slow/network/research/bittensor by default (matches CI).
TEST_MARKERS ?= not slow and not benchmark and not e2e and not research and not bittensor
# Live PostgreSQL contracts run in CI job test-postgres (requires APCC_POSTGRES_DSN
# + [postgres]). Default verify must not import psycopg via that frozen suite.
TEST_IGNORE ?= --ignore=tests/test_apcc_postgres.py
PYTEST = $(UV) run --no-sync pytest tests/ --import-mode=importlib $(TEST_IGNORE)
TLA2TOOLS_JAR ?=
TLC_TIMEOUT ?= 180
TLC_LOG ?= tlc-gcb-witness.log

.DEFAULT_GOAL := help
.PHONY: help setup dev test test-all lint format typecheck typecheck-coverage smoke verify verify-wheel agent-check agent-self-evolve tla-gcb-coverage clean

help: ## Show this help
	@echo "constitutional-swarm — make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install the package + dev extras (one-time onboarding)
	@command -v $(UV) >/dev/null 2>&1 || { \
	  echo "ERROR: 'uv' not found. Install it: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
	$(UV) sync $(SYNC_FLAGS)
	@echo "OK: environment ready. Next: 'make smoke' then 'make test'."

dev: setup smoke ## Prepare a development environment and confirm it imports

test: ## Run the default test suite (skips slow/network/research/bittensor)
	$(PYTEST) -m "$(TEST_MARKERS)" -q

test-all: ## Run the full test suite including research markers
	$(PYTEST) -m "not slow and not benchmark and not e2e" -q

lint: ## Lint the package with ruff (CI gate)
	$(UV) run --no-sync ruff check src/constitutional_swarm/

format: ## Auto-format with ruff
	$(UV) run --no-sync ruff format src/ scripts/

typecheck: ## Static type-check with mypy (config + adoption baseline in pyproject.toml [tool.mypy]).
	$(UV) run --no-sync mypy

smoke: ## Fast import + CLI sanity check (no network, no API keys)
	$(UV) run --no-sync python -c "import constitutional_swarm; print('import constitutional_swarm OK')"
	$(UV) run --no-sync acgs-swarm --help >/dev/null && echo "acgs-swarm CLI OK"
	$(UV) run --no-sync acgs-verify-receipts --help >/dev/null && echo "acgs-verify-receipts CLI OK"
	$(UV) run --no-sync acgs-agent-self-evolve --help >/dev/null && echo "acgs-agent-self-evolve CLI OK"

agent-check: ## Validate agent/tool registries + doc completeness (no install required)
	$(UV) run --no-sync python scripts/agent_check.py

typecheck-coverage: ## Assert every optional extra is type-checked or excepted (no install required)
	$(UV) run --no-sync python scripts/check_typecheck_coverage.py

agent-self-evolve: ## Build offline self-evolution harnesses for every repo agent
	$(UV) run --no-sync acgs-agent-self-evolve --json --write-report .omx/state/agent-self-evolve-report.json --fail-under 1.0

tla-gcb-coverage: ## Prove the exact GCB non-vacuity witness with pinned TLC v1.7.4
	@test -n "$(TLA2TOOLS_JAR)" || { echo "ERROR: set TLA2TOOLS_JAR to the pinned TLC v1.7.4 jar"; exit 2; }
	$(UV) run --no-sync python scripts/run_tlc_expected_witness.py \
		--tlc-jar "$(TLA2TOOLS_JAR)" --timeout "$(TLC_TIMEOUT)" --log "$(TLC_LOG)"

verify: lint typecheck agent-check typecheck-coverage smoke test ## Full local gate: lint -> typecheck -> registry/doc + coverage check -> smoke -> tests
	@echo "OK: verify passed."

verify-wheel: ## Build the wheel and install it into a blank venv (not the project .venv)
	$(UV) run --no-sync python scripts/verify_isolated_wheel.py

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .benchmarks dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
