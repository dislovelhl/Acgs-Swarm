# Reviewer A — empirical methodology (campaign SHA `9c37e34`)

Independent review. Prompt did not request a positive result.
Reviewer id: `8743b6ee-265b-49a8-9876-4d725d08062b`. Date: 2026-08-29.

## Recommendation

```
APCC-1 QUALIFICATION PARTIAL
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```

Mechanism novelty GO is not recommended from this subset.

## P0 (1)

1. Performance JSONL/summary records `target_rate_per_second: 10` and
   `status: LIVE_MEASURED`, but `_measure_loop` caps sleep at 1 ms.
   Observed B0–B4 medians 27.7–43.6 ops/s. These cells are not the
   precommitted open-loop 10/s experiment. Do not use them for 10/s,
   relative-25%, or baseline-overhead claims.

## P1 (8)

1. PostgreSQL 366-test file overlapped the performance window (host not isolated;
   swap not recaptured on the performance artifact).
2. Seed `104729` is a label; payloads use `os.urandom` at import.
3. B6 scenario catalog is capability preflight; `execute` not called (39/39 blocked).
4. Race-named catalog cells are sequential; `B4InterleavingBarrier` unused.
5. B0–B4 / B5 / B6 `QL-INDEP-NODE` are different performance experiments;
   B6 PostgreSQL performance blocked; PG `shared_buffers=128MB` ≠ frozen 4GB.
6. All 70 measured runs `incomplete_run=true`; 25% relative flags cannot fire.
7. Verifier gate PARTIAL (no IETF RFC 8785 appendix corpus).
8. Empirical ablations not executed; independent PG/SQLite suites are not
   cross-store equivalence; postgres `-m security` collects 0 tests.

## P2 (selected)

- `duration_seconds` hardcoded 30; B0–B4 adapters not closed; first `go test` cached;
  remaining 269-test file list omitted from gate log; frozen SQLite pragmas not
  fully applied on experimental adapters; auto `MANIFEST.sha256` hashes gitignored
  trees; frozen-pair P2s unchanged.

## B0–B6 (reviewer classification)

| ID | scenarios | performance | frozen matrix |
| --- | --- | --- | --- |
| B0–B5 | LIVE_MEASURED with n=1 and preflight skips | INCONCLUSIVE | CONTRACT_ONLY |
| B6 public adapter | BLOCKED | — | CONTRACT_ONLY |
| B6 SQLite store | 4 negatives LIVE_MEASURED | QL-INDEP-NODE INCONCLUSIVE | CONTRACT_ONLY |
| B6 PostgreSQL | — | BLOCKED | CONTRACT_ONLY |
