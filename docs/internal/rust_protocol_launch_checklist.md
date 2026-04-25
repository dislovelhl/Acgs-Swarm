# Rust Protocol Gate Launch Checklist

Scope: release-readiness notes for the pre-Rust protocol canonicalization gate,
deterministic fixture corpus, and paper-claim closure work completed on
2026-04-25.

This is not a production service deployment. The launch unit is a repository
change set that should be merged only after the gates below remain green.

## Launch Unit

- Canonical protocol layer: `src/constitutional_swarm/protocol.py`
- Fixture generator: `scripts/generate_rust_protocol_fixtures.py`
- Rust protocol fixtures: `tests/fixtures/rust_protocol/`
- Protocol regression tests: `tests/test_protocol_canonicalization.py`
- Architecture decision record: `docs/internal/rust_core_protocol_adr.md`
- Remaining paper-claim reproducer: `scripts/reproduce_paper_claims.py`
- Paper reproducibility tests: `tests/test_paper_reproducibility.py`
- Claims map update: `docs/internal/claims_map.md`

## Explicit Non-Launch Items

- No Cargo workspace.
- No Rust crates.
- No PyO3 bridge.
- No network transport changes.
- No Bittensor, SWE-Bench, latent DNA, or ODE research runtime changes.
- No SQLite or JSONL Rust adapters.
- No change to Python top-level compatibility imports.

## Pre-Launch Gates

| gate | command | required result |
|---|---|---|
| Protocol tests | `python -m pytest tests/test_protocol_canonicalization.py --import-mode=importlib -q` | All tests pass. |
| Paper reproducer tests | `python -m pytest tests/test_paper_reproducibility.py --import-mode=importlib -q` | All tests pass. |
| Paper claim harness | `python scripts/reproduce_paper_claims.py` | `24` passed, `0` failed. |
| Citation verification | `python scripts/verify_citations.py --root .` | `29` verified, `0` failed. |
| New-code lint | `env RUFF_CACHE_DIR=/tmp/constitutional_swarm_ruff_cache python -m ruff check src/constitutional_swarm/protocol.py scripts/generate_rust_protocol_fixtures.py scripts/reproduce_paper_claims.py tests/test_protocol_canonicalization.py tests/test_paper_reproducibility.py` | All checks pass. |

Do not treat the repo-wide `python -m ruff check src/` result as a launch
blocker for this change unless the pre-existing `latent_dna.py` violations are
separately in scope.

## Launch Evidence

Collected on 2026-04-25:

| gate | result |
|---|---|
| Protocol tests | `7 passed in 0.63s` |
| Paper reproducer tests | `3 passed in 0.14s` |
| Paper claim harness | `24` passed, `0` failed |
| Citation verification | `29 citations scanned`; `29 verified, 0 failed` |
| New-code lint | `All checks passed!` |

## Rollout Plan

1. Merge with Rust gate documentation and fixtures only.
2. Keep Rust implementation blocked until the ADR and fixture manifest are
   reviewed.
3. Run fixture generation in CI or release validation and compare
   `tests/fixtures/rust_protocol/manifest.json` against regenerated output.
4. Start Rust v0.1 only after the validation-engine ownership decision is
   recorded in a follow-up ADR.

## Monitoring

For this repository launch, monitor CI and review signals instead of runtime
dashboards:

- Protocol fixture manifest digest changes.
- Failures in `tests/test_protocol_canonicalization.py`.
- Failures in `tests/test_paper_reproducibility.py`.
- Citation verifier regressions.
- Any accidental Cargo/Rust file additions before the gate is accepted.
- Any changes to Python import compatibility caused by protocol exports.

## Rollback Plan

If the launch regresses compatibility or produces unstable fixtures:

1. Revert the merge commit that introduced this launch unit.
2. Restore the prior `docs/internal/claims_map.md` state if paper-claim closure
   needs to be separated from the protocol gate.
3. Delete the checked-in `tests/fixtures/rust_protocol/` corpus only as part of
   the same revert.
4. Re-run the protocol and paper tests listed above to confirm the rollback.

Expected rollback time: less than 5 minutes for a git revert plus focused test
run. No database, network, or user-data rollback is required.

## Known Risks

- `ICLR-15` is mapped to DP table consistency, not proof that the published
  table's absolute sigma values follow the stated `delta=1e-5` Gaussian formula.
  The paper should resolve that mismatch before publication.
- The canonical protocol layer freezes a v1 contract before Rust exists. Any
  future encoder change must update the ADR, regenerate fixtures, and explain
  compatibility impact.
- Networked citation verification depends on external arXiv and DOI endpoints;
  `--skip-network` remains the offline fallback for CI environments without
  outbound DNS.
