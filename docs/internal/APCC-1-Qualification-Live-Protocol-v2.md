# APCC-1 qualification-live protocol v2

Frozen `2026-08-29T17:55:00Z` **before** v2 execution.
Protocol ID: `apcc-1.qualification-live.v2`.
Does **not** revise `apcc-1.matrix.v1` or reinterpret v1 rows at SHA `9c37e34`.

## Why v2 exists

Reviewer A P0: v1 `_measure_loop` capped `time.sleep` at 1 ms, so B0–B4
exceeded the written 10/s open-loop cell while records still said
`target_rate_per_second: 10`. Those v1 performance rows stay INCONCLUSIVE.

v2 sleeps until `next_beat` (no 1 ms cap). Catch-up if more than 1 s behind
is unchanged. Wall time is measured, not hardcoded 30.

## Non-claims (same as v1)

- Not a close of `apcc-1.matrix.v1`.
- Host swap exhaustion and PG `shared_buffers=128MB` (not 4GB) remain
  confounders. v2 does **not** claim the frozen-plan performance cell.
- B6 public `execute` remains BLOCKED unless a supervisor handle exists
  in-tree without changing the frozen pair (it does not on the public path).
- Empirical ablations remain BLOCKED_MISSING_DEPENDENCY (IDs exist; no runner).
- Novelty overall remains UNDETERMINED while frozen-plan live gates are incomplete.

## v2 cells (precommitted)

- Performance only: same 3 warmup + 10 measured × 30 s, seed `104729`,
  target 10/s, `MIN_OPS=10000` (so paced 10/s × 30 s remains `incomplete_run`).
- B0–B6 SQLite workloads unchanged (`QL-INDEP-NODE` for B6).
- B6 PostgreSQL performance still BLOCKED_MISSING_DEPENDENCY (no rate-generator).
- B6 PostgreSQL **store negatives**: the same four case IDs as v1 SQLite
  (`valid-first-commit`, `exact-replay`, `commit-id-equivocation`,
  `invalid-commit-request`). This is the precommitted v1 list on the other
  store, not a post-hoc expansion.
- Do not mix v1 `9c37e34` performance JSONL with v2 rows.

## Thresholds

Unchanged from v1. Relative 25% flags omitted if `incomplete_run` or n<10.
Security: zero invalid authoritative commits in the planned four store trials
per store.
