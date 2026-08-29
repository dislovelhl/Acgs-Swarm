# APCC-1 qualification-live protocol v1

Frozen `2026-08-29T16:00:00Z` **before** qualification-live execution.
Protocol ID: `apcc-1.qualification-live.v1`.
This is newly introduced methodology. It does **not** revise
`apcc-1.matrix.v1` / `docs/internal/APCC-1-Experiment-Plan.md`.

## Why this protocol exists

The frozen experiment plan requires 102,416 planner identities, including
28,800 measured 30-second performance runs and 2,400,000 storage commits.
There is no in-tree live runner for that matrix. `B6AuthorityAdapter` is inert
on the public `execute` path.

Executing a reduced live set under the frozen matrix SHA and labeling it
complete would be a protocol violation. This document freezes a **qualification
subset** with thresholds chosen before outcomes.

## Non-claims (precommitted)

- Not a close of `apcc-1.matrix.v1` cells.
- Contract tests, schema validators, and catalog-construction tests are not
  live measurements.
- ScenarioRunner `BLOCKED` on `B6AuthorityAdapter` is not a live APCC-store
  measurement.
- TLC witness exit 12 is not a safety success.
- PostgreSQL `shared_buffers=128MB` is not the frozen-plan 4GB setting.
- Host swap was exhausted at reconcile (15 GiB used). Latency/throughput from
  this host are confounded. No superiority claim is allowed.
- Frozen-pair P2s remain unresolved.

## Novelty rubric (precommitted; from Prior-Art + this gate)

Evaluate separately. Do not promote one axis because another is strong.

| Axis | GO | CONDITIONAL | NO-GO | UNDETERMINED |
| --- | --- | --- | --- | --- |
| Mechanism novelty | Claim chart shows exact APCC conjunction absent from qualifying art **and** live B0–B6 frozen cells complete | Not used for mechanism | Prior art subsumes the claimed primitive | Required live frozen campaign or claim-chart archive missing |
| Systems-architecture | Distinct integration profile demonstrated against named baselines with live artifacts | Integration profile shown on qualification-live subset only | Profile is packaging of named prior systems with no residual | Incomplete |
| Implementation assurance | All required stores/verifiers/formal gates bound to campaign SHA, P0=P1=0 | SHA-bound gates pass with documented P2 | Open P0/P1 or SHA mismatch | Gate not re-run |
| Empirical utility | Frozen B0–B6 live cells meet precommitted security threshold; performance reported with CI | Qualification-live subset only | Invalid B6 authoritative commit in planned trials | Incomplete |
| Operational applicability | Production-like durability, multi-host, operator runbook | Explicitly not claimed | Contradicted | Default |

Overall novelty for this qualification: **UNDETERMINED** unless every required
frozen-plan live gate completes. A large passing unit-test count does not move
mechanism novelty off `INSUFFICIENT EVIDENCE` (`docs/internal/APCC-1-Prior-Art.md`).

Allowed overall labels after complete required gates: `GO` | `CONDITIONAL` |
`NO-GO`. Incomplete required gates: retain `UNDETERMINED`.

`PRODUCTION READINESS NOT CLAIMED` in every case.

## Security / performance thresholds (precommitted)

Copied from the frozen experiment plan; not tuned after results.

- Security: zero invalid authoritative B6 commits in planned live B6-store
  trials. Unexpected acceptance of stale/substituted/malformed/mismatched/
  unauthorized evidence is at least P1 until independently disproven.
- Performance: no pass/fail superiority. Report overhead. Flag, do not hide,
  overhead above 25% p95 latency, 25% throughput loss, or 4 KiB median
  certificate size relative to B5 **when both sides completed the same cell**.
  Relative difference is omitted if a side is blocked, incomplete, or has
  n<10 measured runs.

## B0–B6 readiness (canonical names; not renamed)

| ID | Mechanism | Live adapter | Classification |
| --- | --- | --- | --- |
| B0 | Direct completion | `ExperimentalSQLiteAdapter` | LIVE_READY (SQLite experiment adapter) |
| B1 | Commit then post-hoc audit | same | LIVE_READY |
| B2 | Pre-execution policy gate | same | LIVE_READY |
| B3 | Signed result log | same | LIVE_READY |
| B4 | Verify proof, then separate write | same | LIVE_READY |
| B5 | Existing GCB-1 SQLite | `HistoricalGCBAdapter` at `6e65db3` | LIVE_READY if snapshot/env provision succeeds; else BLOCKED_MISSING_DEPENDENCY |
| B6 empirical adapter | APCC-1 | `B6AuthorityAdapter.execute` | BLOCKED_MISSING_DEPENDENCY (trusted supervisor / empty capabilities) |
| B6 SQLite store | APCC-1 | `SQLiteAuthorityStore` via test request builder | LIVE_READY for qualification-live independent first-commits and a fixed negative set |
| B6 PostgreSQL store | APCC-1 | in-tree rate-generator | BLOCKED_MISSING_DEPENDENCY for live performance; live conformance is the PostgreSQL pytest file at campaign SHA |
| Ablation empirical adapters | remove one B6 element | none in-tree | BLOCKED_MISSING_DEPENDENCY |
| TLA+ safety/witness/ablation | `scripts/run_apcc_tlc.py` | pinned JAR | LIVE_READY as formal evidence; not implementation ablation |
| Frozen matrix 102416 cells | experiment plan | no runner | CONTRACT_ONLY / PENDING_MEASUREMENT |

## Qualification-live cells (precommitted)

Seeds used: `104729` only. Frozen five-seed schedule is **not** executed.

### A. Scenario catalog (adversarial labels, 1 trial each)

- Catalog: `default_scenario_catalog()` (39 variants, 32 `ATTACK_IDS`).
- Baselines: B0–B6 via `create_baseline_adapter` / `B6AuthorityAdapter`.
- Store: SQLite files under the run directory. Fresh DB per (baseline, variant)
  except B6 public adapter (no DB).
- Control then attack via `ScenarioRunner`.
- Success criterion: observed outcome equals catalog `expected[baseline]`,
  or a recorded harness exception. Mismatch is a finding, not retuned.

This is live for B0–B5 adapters. B6 public adapter is expected `blocked`.
It does **not** satisfy frozen 30-trials-per-cell cardinality.

### B. B6 SQLite store negatives (fixed list; no post-hoc adds)

Against one provisioned `SQLiteAuthorityStore`:

1. `valid-first-commit`
2. `exact-replay`
3. `commit-id-equivocation` (same `commit_id`, different payload)
4. `invalid-commit-request` (tampered producer signature bytes if constructible;
   otherwise record construction failure and skip without substituting a mock)

Expected: (1) accepted; (2) exact replay, no second authority; (3) conflict /
denied, no second authority; (4) fail-closed.

### C. Performance

- Payload: 1024 input / 4096 output bytes.
- Target: open-loop attempt rate 10 /s for 30 s measured.
- Warm-up: 3 unreported 30 s runs, then 10 measured 30 s runs.
- Incomplete if completed operations < 10,000 in a measured run: retain, set
  `incomplete_run=true`.
- B0–B4: adapter `execute(control)` loop (independent inserts).
- B5: same if adapter init succeeds; one adapter reused within a run, fresh
  adapter per run (documented cost). If a single B5 init exceeds 180 s, remaining
  B5 performance cells are `BLOCKED_TIMEOUT`.
- B6 SQLite: independent first-commits on pre-provisioned nodes (not frozen W1
  single-node predecessor chain). Label `QL-INDEP-NODE`. Provision 400 nodes.
  Node exhaustion => `incomplete_run`.
- B6 PostgreSQL performance: not executed (blocked above).
- Stats: per-run count, duration, ops/s, p50/p95/p99 of per-op ns; median across
  measured runs. No bootstrap 10,000 resamples in v1 (record as protocol gap vs
  frozen plan). Warm-up excluded from measured stats.

### D. Ablations

- Implementation empirical ablations: not executed (`BLOCKED_MISSING_DEPENDENCY`).
- TLA+ witness/ablation: optional re-run of `scripts/run_apcc_tlc.py` at campaign
  SHA; classified separately from empirical ablations.

### E. Cross-store / verifier

- Python/Go differential: `tests/test_apcc_go_verifier.py` + `go test`/`gofmt`/`go vet`
  at campaign SHA.
- Cross-store equivalence: requires the same canonical vectors on SQLite and
  PostgreSQL with identical externally visible dispositions. Independent green
  suites are **not** that claim. Qualification-live will attempt a small shared
  negative vector on SQLite (section B). PostgreSQL shared vector is blocked
  unless the PG pytest file is used as store-specific conformance only.

## Artifact rules

- Root: `experiments/apcc-1/qualification-live/runs/<run_id>/`
- Files: `protocol_id`, `git_sha`, timestamps, exit, JSONL observations,
  SHA-256 of curated files. Mode 0600/0700 where the writer can.
- No DSN passwords, tokens, or unredacted env dumps.
- Do not write frozen-matrix `raw.jsonl` unless every record is a real frozen
  planner identity executed to spec.

## Campaign SHA rule

If this protocol/harness is committed, measure on **that** SHA, not `e2e87f9`.
Phase 0 remains the pre-harness identity.
