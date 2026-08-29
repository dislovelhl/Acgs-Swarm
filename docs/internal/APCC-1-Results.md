# APCC-1 qualification results

Recorded `2026-08-29T19:45:00Z`. This file is not a production acceptance,
not a close of `apcc-1.matrix.v1`, and not a mechanism-novelty GO.

Measurement SHAs (do not mix rows):

| Kind | SHA |
| --- | --- |
| v1 catalog / PG 366 / SQLite 383 / TLC / empirical contract | `9c37e34a9a1971057d304dab1bc4b893dafc17a6` |
| v2 performance only | `3d4d9dd4bf8b6f6071fd823e17fb96110c11ccd1` |
| v2 PG/SQLite four-case negatives, Go RFC, Python/Go 66 | `4ef82a21af884e749cee31e79b9ee6360ad3cfa8` |
| Results/evidence checkpoint (this write) | HEAD at commit time |

## 1. Verdict banner

```
APCC-1 QUALIFICATION PARTIAL
CANDIDATE VERDICT UNDETERMINED
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```

PARTIAL because mandatory frozen-plan cells remain unrun or blocked
(`apcc-1.matrix.v1`, B6 public execute, empirical ablations, B6 PostgreSQL
performance, RFC 8785 appendix / independent JCS). Executable remaining
gates from the continue order were run or captured as hard blockers.
That is not a candidate pass.

## 2. Scope and claim discipline

- `apcc-1.qualification-live.v1` at `9c37e34` does **not** close
  `apcc-1.matrix.v1` (102,416 planner IDs).
- `apcc-1.qualification-live.v2` at `3d4d9dd` supersedes **performance
  methodology only**. v1 performance rows stay INCONCLUSIVE.
- Contract tests, catalog-construction tests, schema validators, and the
  formal pytest wrapper are not live measurements.
- ScenarioRunner `blocked` on `B6AuthorityAdapter` is not a live APCC-store
  measurement.
- TLC witness/ablation exit 12 is harness-PASS of intended named invariant
  violations, not ordinary safety success.
- Runner `summary.json` writes `status: LIVE_MEASURED`.
  `_measure_loop` hardcodes `target_rate_enforced: True`. Those labels are
  not copied onto the frozen-plan W1 cell.
- Relative 25% p95 / 25% throughput / 4 KiB certificate flags vs B5 are
  omitted because every measured run is `incomplete_run=true`.
- Words “material”, “significant”, and “better” are not used as findings.
- Interrupted Codex run remains `INTERRUPTED_USAGE_LIMIT_NO_TEST_VERDICT`.
  Its partial output is not merged.
- Same four case IDs on SQLite and PostgreSQL with matching **dispositions**
  are not identical certificates and are not storage-independence of the
  full suites.

## 3. Candidate identity

| Field | Value |
| --- | --- |
| Worktree | `/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit` |
| Branch | `apcc-1-atomic-proof-carrying-commit` |
| Implementation base | `df30286be482ece23536abf689f328472a565e69` |
| GCB-1 snapshot used by B5 | `6e65db3e478fa315119038b616d78f4f171422db` |
| v1 protocol ID | `apcc-1.qualification-live.v1` |
| v2 protocol ID | `apcc-1.qualification-live.v2` |
| Frozen matrix ID (unclosed) | `apcc-1.matrix.v1` |
| Upstream / push | none; no fetch; no push |

## 4. Starting and ending repository state

Continue Phase 0 (`2026-08-29T18:03:58Z`): HEAD `4ef82a2`, clean tracked
tree, no upstream. Untracked preserved: `ql-smoke-b6{,b,c}/` and campaign
run dirs. Local commits after `df30286` include `9c37e34`, `c5be1d4`,
`86baaf2`, `3d4d9dd`, `4ef82a2`.

Frozen pair **not** staged in harness commits. `git diff --check` on those
commits: no whitespace errors recorded.

## 5. Frozen-pair integrity

| Tree | `postgres_store.py` | `test_apcc_postgres.py` |
| --- | --- | --- |
| HEAD / `8bea7c4` / campaign SHAs | `576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a` | `dff15b7f8b0aa6ebe3fad19305ea829faf05f71836b1ea91daa5d55c8dfb9a22` |
| git blobs at `4ef82a2` | `da5071e6608d42c6ace296bff6d022afffc708c1` | `ed9e04f28dfeb1621c0a26a49cf5a79a5df3c319` |
| `df30286` | `fc1c1345fbe8d7486089e6025a46a0a6a861c241b44041e18dccbc686dd78749` | `ad77a7ecd39de434ee455ab5155def1842b925c9ac1c275c22ea91ff5e494f2c` |

Pair was **not** repaired. Required hashes **match**. Independent static
verdict `APPROVE-WITH-P2` applies to pair **content** `576c0449` /
`dff15b7f`. P2s remain visible (§17).

## 6. Environment and dependency versions

| Item | Value |
| --- | --- |
| Python | 3.13.13 |
| psycopg | 3.3.4 |
| Go | go1.26.7-X:nodwarf5 linux/amd64 |
| PostgreSQL | 17.10 at `127.0.0.1:55434` |
| `shared_buffers` | **128MB** (frozen plan wanted 4GB) |
| `max_connections` | 200 |
| SwapTotal / SwapFree at 18:04Z | 16777212 / 221940 kB |
| SwapFree after v2 perf | 215436 kB |
| Leftover PG roles | `apcc_test_aca927aa96486a240e433636_{owner,runtime}` |
| Leftover `apcc_test_%` schemas | none after PG negatives |
| TLC JAR | `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| DSN (redacted) | `postgresql://REDACTED@127.0.0.1:55434/apcc_test` |

Confounders for latency/throughput: swap nearly exhausted; `shared_buffers`
128MB; shared host. Frozen-plan W1 environment was not matched.

## 7. Experimental protocol

v1 frozen `2026-08-29T16:00:00Z` before measurements at `9c37e34`.
v2 frozen `2026-08-29T17:55:00Z` in `3d4d9dd` **before** v2 performance.

v2 change: `time.sleep(next_beat - now)` (no 1 ms cap). Wall time measured.
Seed: `104729` only. Warm-up 3 × 30 s unreported. Measured 10 × 30 s.
`MIN_OPS=10000` ⇒ paced 10/s × 30 s remains `incomplete_run`.
Payloads: `os.urandom(1024/4096)` at import (not derived from seed 104729).

Novelty rubric unchanged: incomplete frozen-plan live gates ⇒ overall
**UNDETERMINED**.

## 8. B0–B6 definition matrix

Canonical names from `docs/internal/APCC-1-Experiment-Plan.md`. Not renamed.

| ID | Mechanism | Live path used here | Readiness |
| --- | --- | --- | --- |
| B0 | Direct completion | `ExperimentalSQLiteAdapter` | LIVE_READY (SQLite experiment adapter) |
| B1 | Commit then post-hoc audit | same | LIVE_READY |
| B2 | Pre-execution policy gate | same | LIVE_READY |
| B3 | Signed result log | same | LIVE_READY |
| B4 | Verify proof, then separate write | same | LIVE_READY |
| B5 | Existing GCB-1 SQLite | `HistoricalGCBAdapter` @ `6e65db3` | LIVE_READY (init succeeded) |
| B6 public `execute` | APCC-1 | `B6AuthorityAdapter` | BLOCKED_MISSING_DEPENDENCY (empty capabilities / trusted supervisor). Reconfirmed at `4ef82a2`. No in-tree catalog supervisor. |
| B6 SQLite store | APCC-1 | `SQLiteAuthorityStore` | LIVE_READY for 4 planned negatives + `QL-INDEP-NODE` first-commits |
| B6 PostgreSQL store negatives | APCC-1 | `postgres_environment` unwrapped | LIVE_READY for the same 4 case IDs |
| B6 PostgreSQL performance | APCC-1 | in-tree rate-generator | BLOCKED_MISSING_DEPENDENCY |
| Empirical ablations | one-at-a-time B6 element removal | none in-tree | BLOCKED_MISSING_DEPENDENCY (`contract.ABLATION_IDS` present; modules `adapters,artifacts,contract,historical_gcb,scenarios`) |
| Frozen 102416 cells | experiment plan | no runner | CONTRACT_ONLY / PENDING_MEASUREMENT |

## 9. B0–B6 live results

Labels: CONTRACT TESTED / LIVE MEASURED / BLOCKED / THRESHOLD MET /
THRESHOLD NOT MET / INCONCLUSIVE.

### 9a. Catalog and v1 performance (`9c37e34`)

Unchanged. 273/273 catalog-match; B6 public 39/39 `blocked`.
v1 performance INCONCLUSIVE (`TARGET_RATE_NOT_ENFORCED`). See prior
`86baaf2` text for the v1 ops/s table. Do not reuse as the 10/s cell.

### 9b. v2 performance (`3d4d9dd`, `campaign-3d4d9dd-perf`)

91 rows (21 warmup + 70 measured). Failures 0. `incomplete_run` 91/91.
Pacer `sleep-until-next-beat`. Driver exit 0.
`17:56:14Z`–`18:42:10Z`. `performance.jsonl` SHA-256
`8f1882ab7a7cc2a1aa05337e5b302502cfd9cb73360f5944d40e32684f481f70`.

`target_rate_enforced` is hardcoded `True` in `_measure_loop`.

| ID | median ops/s | min–max ops/s | pstdev | median p50 ms | median p95 ms | median p99 ms | completed sum (10×30s) | error rate |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 | 10.0262 | 10.0224–10.0263 | 0.00114 | 21.204 | 24.628 | 33.541 | 3010 | 0 |
| B1 | 10.0262 | 10.0244–10.0263 | 0.00058 | 21.176 | 26.641 | 34.045 | 3010 | 0 |
| B2 | 10.0262 | 10.0238–10.0263 | 0.00075 | 21.206 | 27.690 | 33.858 | 3010 | 0 |
| B3 | 10.0262 | 10.0205–10.0262 | 0.00188 | 21.319 | 29.829 | 35.715 | 3010 | 0 |
| B4 | 10.0225 | 10.0209–10.0233 | 0.00076 | 30.578 | 39.230 | 49.125 | 3010 | 0 |
| B5 | 8.8518 | 8.3329–9.2578 | 0.404 | 108.110 | 145.425 | 163.581 | 2655 | 0 |
| B6 SQLite `QL-INDEP-NODE` | 6.6722 | 6.3824–9.2936 | 0.805 | 147.791 | 172.163 | 209.612 | 2077 | 0 |

B6 `nodes_used` measured: 279, 206, 203, 200, 201, 200, 195, 202, 192, 199.

Classification (do not copy runner `LIVE_MEASURED`):

- B0–B4: **PACED_CEILING** on the v2 written 10/s open-loop (ops/s in
  [10.0205, 10.0263]; 301 ops / ~30.02 s is a fencepost, not surplus
  capacity). Not frozen-plan W1.
- B5 and B6: **RATE_MISS** + `INCOMPLETE_RUN` (all measured ops/s < 10).
- Frozen-plan W1 10/s cell: **NOT RUN / NOT CLAIMED** (host swap / 128MB
  buffers / single seed / `MIN_OPS` / not the frozen planner identity /
  SQLite-only / B6=`QL-INDEP-NODE`).
- B6-postgresql performance: BLOCKED_MISSING_DEPENDENCY.
- `target_rate_enforced: true` is hardcoded; ignore it on B5/B6.

No relative difference vs B5 is reported (protocol: omit if incomplete).

## 10. Adversarial results

Catalog at `9c37e34` unchanged (273/273; B6 public blocked).

B6 store negatives at `4ef82a2` (same four IDs; SQLite and PostgreSQL):

| case_id | SQLite outcome | PostgreSQL outcome |
| --- | --- | --- |
| valid-first-commit | COMMITTED / authoritative / OK / 4960 B / digest `aXN5Yfm9AHVPBHKoB-4BpkRW_I_hBVqmq_Qk0DnSqdE` | COMMITTED / authoritative / OK / 4968 B / digest `l3-FmZzWYqUZJJM-pBngYhQzO_7d9cgGFopAX_iz-9k` |
| exact-replay | COMMITTED; `same_envelope_bytes=true`; `second_authority=false` | same dispositions |
| commit-id-equivocation | CONFLICTED / `COMMIT_ID_EQUIVOCATION`; not authoritative | same |
| invalid-commit-request | DENIED / `INVALID_PRODUCER_SIGNATURE`; not authoritative | same |

Both stores: `invalid_authoritative_commits=0`.
Certificates are **not** identical (different payload urandom; different
digests/byte lengths). This is disposition agreement on four planned
cases, not full-suite storage independence.

Failed harness attempts preserved (not silent-repaired into the pair):

| Attempt | Exit | Evidence |
| --- | --- | --- |
| Fixture called directly | 1 | `docs/internal/apcc-1-evidence/b6-postgres-fixture-call-fail.txt` |
| `inspect` missing after unwrap edit | 1 | `…/b6-postgres-unwrap-nameerror.txt` |
| `relative_to(ROOT)` on pytest tmp | 1 (pytest); cases had already run | `…/b6-postgres-relative-to-fail.txt` |

B6 public `execute` at `4ef82a2`: `ScenarioExecutionError: B6 execution
requires trusted supervisor preflight`; capabilities `[]`.
`execute_trusted` still requires `_SwarmExecutionHandle`. No in-tree
catalog supervisor. Remains BLOCKED_MISSING_DEPENDENCY.

Postgres `-m security` at `9c37e34`: 366 deselected, exit 5. Historical
100/266 **not reproduced**.

This is **not** frozen-plan 30-trial / 100-trial security acceptance.

## 11. Ablation results

| Kind | Status |
| --- | --- |
| Implementation empirical ablations | BLOCKED_MISSING_DEPENDENCY — command `ls experiments/apcc-1 scripts \| rg -i ablat` found no runner; IDs exist in `contract.py` |
| TLA+ witness/ablation | LIVE at `9c37e34`; formal only; see §15 |
| Passing intact system without degrading ablation | does not establish causation |

## 12. Performance results

See §9b. Additional:

- CPU, memory, DB connections, outbox backlog, recovery time, txn retry,
  lock wait: **not instrumented** (not reported as zero).
- Bootstrap 10,000 resamples: protocol gap (`bootstrap_resamples: 0`).
- B6 PostgreSQL performance: BLOCKED_MISSING_DEPENDENCY.
- v1 `9c37e34` rows: INCONCLUSIVE; do not mix.
- P2 confounders: swap exhaustion; `shared_buffers=128MB`.

## 13. PostgreSQL/SQLite cross-store equivalence

| Gate | Result | Claim allowed |
| --- | --- | --- |
| SQLite APCC file | 383 passed in 34.03s at `9c37e34` | SQLite suite conformance |
| PostgreSQL APCC file | 366 passed in 2385.52s at `9c37e34` | PostgreSQL suite conformance |
| Shared four planned negatives | LIVE at `4ef82a2`; dispositions match; certificates differ | four-case disposition agreement only |

Wording used: two implementations conform to their store-specific test
contracts; four planned negatives have the same external outcomes.
“Storage independent” is **not** claimed.

## 14. Python/Go verifier agreement

| Check | SHA | Result |
| --- | --- | --- |
| `go test -count=1 ./...` + `gofmt -l` empty + `go vet` | `4ef82a2` | exit 0 (`campaign-4ef82a2-go-rfc.log`) |
| `tests/test_apcc_go_verifier.py` + `tests/test_apcc_verifier.py` | `4ef82a2` | 66 passed in 1.48s |
| RFC 8785 official text | retrieved | SHA-256 `63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240` |
| Appendix B numbers vs APCC-CJ1 | `3d4d9dd`/`4ef82a2` | `go test` expects `WRONG_JSON_TYPE` — documents the plan gap |
| Store linearization by offline verifier | — | cannot |

**Verifier qualification gate: PARTIAL.** In-tree vectors agree. The
plan’s RFC-vector / independent JCS criterion is unmet. Appendix B is
number serialization; CJ1 admits objects/strings only.

## 15. TLA+ safety and non-vacuity evidence

Unchanged from `9c37e34`: 32/32 harness PASS; 4 safety/liveness exit 0;
28 witness/ablation exit 12. Specs unchanged. Formal wrapper 6 passed —
**not TLC**.

## 16. Static-review findings

Independent static close of frozen pair content `576c0449` / `dff15b7f`:
`APPROVE-WITH-P2`; P0=0; P1=0. Pair unchanged.

v1 Reviewer A (methodology): P0=1 (1 ms pacer / 10/s mislabel).
v1 Reviewer B (novelty): P0=3 (claim charts, frozen campaign, hashed
archives).

v2/continue independent lanes (inspect actual artifacts; not asked for GO):

| Lane | Agent | Lane verdict | Candidate (lane) |
| --- | --- | --- | --- |
| Correctness / transactional | [Review](b1152987-8880-496e-9ce0-41bafaaa5ede) | REJECT transactional close; P0=0 P1=3 | UNDETERMINED |
| Security / adversarial / fail-closed | [Review](056bf644-a655-447b-a4df-bc306b394cee) | REJECT frozen-plan security close; P0=0 live fail-open in 4 cases; P1=4 | UNDETERMINED |
| Evidence / claim-discipline | [Review](fb6a2296-38c5-40fd-bcab-b429ba87e012) | REQUEST CHANGES; COMPLETE forbidden; frozen 10/s = NO | HOLD / UNDETERMINED |
| Novelty / prior-art | [Review](e3375311-1807-4f8e-b30f-2f9e1158ebec) | UNDETERMINED; ceiling INSUFFICIENT EVIDENCE | n/a |

P1 themes kept visible: `LIVE_MEASURED` is a stamp; four cases are
return-value-only; four cases ≠ transactional suite or 30/100-trial
security; `target_rate_enforced` hardcoded; B6 catalog tautological.
No silent pair repair.

## 17. Known P2 limitations (frozen pair; remain visible)

1. GCB fingerprint is not threaded through all reader and observation paths.
2. PostgreSQL does not have a native `commit_output_refs` pin.
3. SQLSTATE 23505 mismatch handling sits outside the retry loop.
4. Outbox delivery is at-least-once.
5. `hashtextextended` advisory-lock collisions are theoretically possible.

## 18. Resource-leak and teardown findings

- After PG four-case negatives at `4ef82a2`: no leftover `apcc_test_%`
  schemas; same two orphan roles as Phase 0.
- v2 performance: gitignored `perf-db/` remains on disk.
- Auto `MANIFEST.sha256` under run dirs is **not** committed.

## 19. Artifact inventory and SHA-256 values

v2 continue curated files:

```
8f1882ab7a7cc2a1aa05337e5b302502cfd9cb73360f5944d40e32684f481f70  experiments/apcc-1/qualification-live/runs/campaign-3d4d9dd-perf/performance.jsonl
1c8f6b7999359617764ec61f3614da5a87cb584a46c9309be6892cac9c549a40  experiments/apcc-1/qualification-live/runs/campaign-3d4d9dd-perf/summary.json
c30b8b240f767e02a3472cc0441c955782b5a50258ef7cf04767fd51aefcec27  experiments/apcc-1/qualification-live/runs/campaign-3d4d9dd-perf-driver.log
43185d5913a881669f754c24689aa0f48c91d0e03ea83599cf4ea95e0195d9f5  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-pgneg/b6-postgres-negatives.jsonl
aed5601aa7e1f05ec19e52b0965e358578846f0c12dfa1f088fe26ea9289fa64  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-pgneg/summary.json
eaf0b2160211322a6ff8508a917898fd400183b1d2181f181eb71d9d68835a8f  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-pgneg-driver.log
f96e7a1c458ebbf905c8a7386c232a6fb2b2b7135984a980314e74071df360a7  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-pgneg-pytest.log
dd2b1bf73f7ec3005d0eead586039079bf0760b12d97bc9b3c98ac9981ab7a8f  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-sqlite-neg/b6-sqlite-negatives.jsonl
8320eff8b5d8683a1930b170da80b70928e63a9cbbfbdf9a961bf9386d7557bc  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-sqlite-neg/summary.json
3416cf5e7ca219c2558b6a24cc524cbb2aee57d20c72d0f1fe68d34c6ccba076  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-sqlite-neg-driver.log
0bb1c7cbb6819b7f45218d0213043d21faa2137315bfe2a0b3fd48954f73a62c  experiments/apcc-1/qualification-live/runs/campaign-4ef82a2-go-rfc.log
```

v1 curated hashes remain in
`experiments/apcc-1/qualification-live/runs/campaign-9c37e34/CURATED-MANIFEST.sha256`.

Do not commit: auto `MANIFEST.sha256`, `*.db`, `perf-db/`, `scenario-db/`,
`ql-smoke-b6{,b,c}/`.

## 20. Reproduction commands

Pin `git -C` to the worktree. Use the SHA that produced the artifact.

```bash
WT=/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit
export APCC_POSTGRES_DSN='postgresql://apcc@127.0.0.1:55434/apcc_test'
# v2 performance (SHA 3d4d9dd)
git -C "$WT" rev-parse HEAD   # was 3d4d9dd when campaign-3d4d9dd-perf ran
"$WT/.venv/bin/python" "$WT/experiments/apcc-1/run_qualification_live.py" --performance --run-id reproduce-v2-perf
# four-case PG + SQLite (SHA 4ef82a2)
"$WT/.venv/bin/python" "$WT/experiments/apcc-1/run_qualification_live.py" --b6-postgres --run-id reproduce-pgneg
"$WT/.venv/bin/python" "$WT/experiments/apcc-1/run_qualification_live.py" --b6-sqlite --run-id reproduce-sqlite-neg
"$WT/.venv/bin/python" -m pytest tests/test_apcc_ql_b6_store_negatives.py --import-mode=importlib -q
```

Re-running uses new urandom payloads; dispositions—not certificate
digests—are the comparable field.

## 21. Prior-art comparison

Unchanged: `docs/internal/APCC-1-Prior-Art.md` (cut-off 2026-08-28):
mechanism novelty **INSUFFICIENT EVIDENCE**; ceiling **SYSTEMS ABSTRACTION**.
No local hashed archives. No claim charts. v2 measurements do not change
that record.

## 22. Novelty analysis

Overall **UNDETERMINED**. Passing store tests and a held 10/s pacer on
B0–B4 experiment adapters do not move mechanism novelty off INSUFFICIENT
EVIDENCE.

| Axis | Verdict | Basis |
| --- | --- | --- |
| Mechanism novelty | UNDETERMINED | charts + frozen live cells missing |
| Systems-architecture | CONDITIONAL | qualification-live subset only |
| Implementation assurance | CONDITIONAL | SHA-bound stores; RFC appendix unmet; P2s open |
| Empirical utility | CONDITIONAL | 4+4 negatives held planned counter; frozen cells incomplete |
| Operational applicability | not claimed | rubric default |

## 23. Unsupported or rejected claims

- Frozen `apcc-1.matrix.v1` complete or closed
- B6 catalog 39/39 match as live APCC-store adversarial measurement
- Empirical pytest 209 as live B0–B6
- Formal wrapper 6 as TLC
- Independent green SQLite 383 + PG 366 as storage independence
- Four-case disposition match as full storage independence
- Historical postgres `-m security` 100/266 at `9c37e34`
- v1 performance as the written 10/s cell
- v2 performance as the frozen-plan W1 cell
- `target_rate_enforced: true` as proof B5/B6 achieved 10/s
- Throughput/latency superiority vs B5
- Mechanism novelty GO
- Production readiness
- TLC exit 12 as ordinary safety success
- RFC 8785 appendix / independent JCS conformance
- Empirical ablation non-vacuity
- CANDIDATE PASS of the frozen-plan APCC-1 qualification

## 24. Final qualification table

| Gate | SHA | Status |
| --- | --- | --- |
| Frozen pair integrity | content `576c0449`/`dff15b7f` | intact; P2s open |
| PostgreSQL 366 | `9c37e34` | 366 passed in 2385.52s, exit 0 |
| Postgres `-m security` | `9c37e34` | 366 deselected, exit 5 |
| SQLite APCC 383 | `9c37e34` | 383 passed in 34.03s, exit 0 |
| Empirical contract 209 | `9c37e34` | CONTRACT ONLY |
| TLC harness | `9c37e34` | 32/32 PASS; 28 witness exit 12 |
| v1 scenarios | `9c37e34` | 273/273 catalog-match; B6 public BLOCKED |
| v1 performance 10/s | `9c37e34` | INCONCLUSIVE |
| v2 performance B0–B4 10/s | `3d4d9dd` | PACED_CEILING (v2 subset); not frozen W1 |
| v2 performance B5/B6 | `3d4d9dd` | RATE_MISS + INCOMPLETE_RUN |
| Frozen-plan W1 cell | — | NOT CLAIMED |
| B6 SQLite 4 negatives | `4ef82a2` | LIVE; planned counter 0 |
| B6 PostgreSQL 4 negatives | `4ef82a2` | LIVE; planned counter 0; dispositions match SQLite |
| B6 public execute | `4ef82a2` | BLOCKED_MISSING_DEPENDENCY |
| B6 PG performance | — | BLOCKED_MISSING_DEPENDENCY |
| Empirical ablations | — | BLOCKED_MISSING_DEPENDENCY |
| Verifier RFC appendix | `4ef82a2` | PARTIAL |
| Python/Go 66 | `4ef82a2` | 66 passed in 1.48s |
| Frozen matrix | — | PENDING / CONTRACT_ONLY |
| Novelty | — | UNDETERMINED |
| Candidate | — | VERDICT UNDETERMINED |
| Production readiness | — | NOT CLAIMED |

## 25. Commit and push status

v2 pacer: `3d4d9dd4bf8b6f6071fd823e17fb96110c11ccd1`.
PG unwrap + pytest: `4ef82a21af884e749cee31e79b9ee6360ad3cfa8`.
Results checkpoint: this commit after reviews.
**Push not performed**; no upstream; no fetch.

## 26. Production-readiness statement

**PRODUCTION READINESS NOT CLAIMED.**

No operator runbook, multi-host durability campaign, or production-like
`shared_buffers`/swap-free host was used. Known P2s remain. B6 public
execute path is inert.

## Compact evidence table (new this continue)

| Command | SHA | Start UTC | End UTC | Exit | Summary |
| --- | --- | --- | --- | --- | --- |
| `run_qualification_live.py --performance --run-id campaign-3d4d9dd-perf` | `3d4d9dd` | 2026-08-29T17:56:14Z | 2026-08-29T18:42:11Z | 0 | 91 rows; B0–B4 ~10.02/s; B5/B6 <10; all incomplete |
| `pytest tests/test_apcc_ql_b6_store_negatives.py` | `4ef82a2` | 2026-08-29T18:02:06Z | 2026-08-29T18:02:24Z | 0 | 2 passed in 17.98s |
| `run_qualification_live.py --b6-postgres --run-id campaign-4ef82a2-pgneg` | `4ef82a2` | 2026-08-29T18:02:24Z | 2026-08-29T18:02:43Z | 0 | 4 cases; invalid_authoritative_commits=0 |
| `run_qualification_live.py --b6-sqlite --run-id campaign-4ef82a2-sqlite-neg` | `4ef82a2` | 2026-08-29T18:04:06Z | 2026-08-29T18:04:07Z | 0 | 4 cases; dispositions match PG |
| `go test -count=1 ./...` + gofmt + vet | `4ef82a2` | 2026-08-29T18:04:07Z | 2026-08-29T18:04:07Z | 0 | packages ok; RFC B expects WRONG_JSON_TYPE |
| `pytest tests/test_apcc_go_verifier.py tests/test_apcc_verifier.py` | `4ef82a2` | 2026-08-29T18:04:41Z | 2026-08-29T18:04:43Z | 0 | 66 passed in 1.48s |
| `--b6-postgres` fixture-direct | `3d4d9dd` | 2026-08-29T17:56:15Z | 2026-08-29T17:56:15Z | 1 | preserved |
| PG 366 (kept) | `9c37e34` | 2026-08-29T16:08:32Z | 2026-08-29T16:48:17Z | 0 | 366 passed in 2385.52s |

## Next action if incomplete

1. Do not relabel qualification-live as `apcc-1.matrix.v1`.
2. Do not claim frozen-plan W1 from v2 B0–B4 10/s.
3. Required for a stronger novelty or candidate pass: claim-chart archive;
   frozen live B0–B6 cells or a newly frozen smaller matrix **before**
   measurement; live B6 adapter; empirical ablation runner; RFC 8785
   independent JCS; five-seed / 30-trial cardinalities; host matching the
   frozen environment.
4. Do not push from this worktree unless a human requests it.
