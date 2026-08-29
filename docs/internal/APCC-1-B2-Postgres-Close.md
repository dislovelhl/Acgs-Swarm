# APCC-1 B2 PostgreSQL close record

Status:

```text
APCC-1 QUALIFICATION PARTIAL
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```

This file records the B2 frozen-pair close after a Codex `usage_limit_exceeded`
interruption. It is not an APCC-1 acceptance, novelty, storage-independence,
distributed, or production-readiness verdict.

## Interrupted prior attempt

```text
INTERRUPTED_USAGE_LIMIT_NO_TEST_VERDICT
```

Codex thread `01a04493-dd65-77f2-a53f-69f00c178bf4` stopped at
2026-08-29T09:52:42.513Z with `usage_limit_exceeded`. That attempt produced no
authoritative full-file pytest summary. Its partial progress is not merged with
the restarted run below.

## Frozen pair

| File | SHA-256 |
| --- | --- |
| `src/constitutional_swarm/apcc/postgres_store.py` | `576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a` |
| `tests/test_apcc_postgres.py` | `dff15b7f8b0aa6ebe3fad19305ea829faf05f71836b1ea91daa5d55c8dfb9a22` |

HEAD at recording: `df30286be482ece23536abf689f328472a565e69`
(`apcc-1-atomic-proof-carrying-commit`).

## Phase 1 — restarted full PostgreSQL file

Exact command:

```bash
export APCC_POSTGRES_DSN='postgresql://apcc@127.0.0.1:55434/apcc_test'
.venv/bin/python -m pytest tests/test_apcc_postgres.py --import-mode=importlib -q --tb=line
```

Working directory: this worktree.

| Field | Value |
| --- | --- |
| Start | 2026-08-29T12:18:24.231Z |
| End | 2026-08-29T12:55:29.512Z |
| Exit code | 0 |
| Summary | `366 passed in 2224.68s (0:37:04)` |
| Failures | 0 |
| Errors | 0 |
| Skips | 0 |
| Deselections | 0 |
| Elapsed | 2224.68s / 2225281 ms |
| Service | PostgreSQL 17.10 (Debian 17.10-1.pgdg12+1) |
| Endpoint | `127.0.0.1:55434` (`apcc_test` / user `apcc`) |
| `max_connections` | 200 |

### Fixture teardown / resource leak

After the completed run:

- leftover schemas matching `apcc_test_%`: none
- leftover roles matching `apcc_test_%`: two orphaned roles
  `apcc_test_aca927aa96486a240e433636_owner` and
  `apcc_test_aca927aa96486a240e433636_runtime`
- no matching schema or observer role for that token
- comments: `apcc-test-owner:aca927aa96486a240e433636`

Classification: residue from the interrupted Codex attempt (create/teardown
killed after owner+runtime and before observer, or after observer/schema drop).
Not attributed to the completed 366-test run, which exited 0 with unique
per-test prefixes.

## Independent static close

Reviewers: security-review subagent and protocol code-reviewer, plus a local
spot-check of cited lines. Frozen pair was not modified during review.

Verdict: `APPROVE-WITH-P2`

P0: none
P1: none

P2 (unresolved, non-blocking for this checkpoint):

1. Reader/observation/`_validate_mutation_checkpoint` always verify
   `_POSTGRES_SCHEMA_FINGERPRINT`; GCB writers are mutation-gated, so this
   fails closed rather than silently accepting a weaker contract.
2. No postgres-native test that pins `commit_output_refs` binding and
   post-commit candidate immutability (shared-core + truncate-dirty coverage
   exists).
3. Schema-manifest smoke test omits some immutability trigger names.
4. After `23505`/ambiguous classification `mismatch`, the follow-up
   `super()._commit()` is outside the retry loop.
5. `FOR UPDATE` ignores a missing workflow/certificate row; advisory locks
   remain.
6. Outbox claim/deliver/finalize is three transactions (at-least-once).
7. `pg_advisory_lock(hashtextextended(...))` can collide; unique constraints
   are the backstop.
8. Shared-suite extras unique to SQLite are not all wired on Postgres.
9. `test_postgres_matrix_is_explicit_and_non_mocked` is partly self-referential.

## What this checkpoint is not

Not APCC-1 acceptance. Not a novelty verdict. Not production readiness.
Go verifier, TLA+, B0–B6, ablations, benchmarks, and remaining-store
equivalence remain pending.
