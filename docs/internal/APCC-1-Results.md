# APCC-1 qualification results

Recorded `2026-08-29T17:25:12Z`. Campaign measurements bound to git SHA
`9c37e34a9a1971057d304dab1bc4b893dafc17a6`. This file is not a production
acceptance, not a close of `apcc-1.matrix.v1`, and not a mechanism-novelty GO.

## 1. Verdict banner

```
APCC-1 QUALIFICATION PARTIAL
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```

## 2. Scope and claim discipline

- Qualification-live protocol `apcc-1.qualification-live.v1` was frozen and
  committed **before** campaign execution (`9c37e34`). It does **not** close
  frozen `apcc-1.matrix.v1` (102,416 planner IDs).
- Contract tests, catalog-construction tests, schema validators, and the
  formal pytest wrapper are not live measurements.
- ScenarioRunner `blocked` on `B6AuthorityAdapter` is not a live APCC-store
  measurement.
- TLC witness/ablation exit 12 is harness-PASS of intended named invariant
  violations, not ordinary safety success.
- `summary.json` writes `status: LIVE_MEASURED` on performance cells. Reviewer A
  P0: those cells are **not** the precommitted open-loop 10/s experiment
  (`TARGET_RATE_NOT_ENFORCED`). This document classifies them INCONCLUSIVE.
- Relative 25% p95 / 25% throughput / 4 KiB certificate flags vs B5 are omitted
  because every measured run is `incomplete_run=true`.
- Words “material”, “significant”, and “better” are not used as findings.
- Interrupted Codex run remains `INTERRUPTED_USAGE_LIMIT_NO_TEST_VERDICT`.
  Its partial output is not merged.

## 3. Candidate identity

| Field | Value |
| --- | --- |
| Worktree | `/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit` |
| Branch | `apcc-1-atomic-proof-carrying-commit` |
| Phase 0 HEAD | `e2e87f9891adf3cea6af6d8a9375e4f40dae11e9` |
| Protocol/harness commit (campaign SHA) | `9c37e34a9a1971057d304dab1bc4b893dafc17a6` |
| Implementation base | `df30286be482ece23536abf689f328472a565e69` |
| GCB-1 snapshot used by B5 | `6e65db3e478fa315119038b616d78f4f171422db` |
| Protocol ID | `apcc-1.qualification-live.v1` |
| Frozen matrix ID (unclosed) | `apcc-1.matrix.v1` |
| Upstream / push | none; no fetch; no push |

## 4. Starting and ending repository state

Phase 0 (`2026-08-29T15:51:09Z`): clean tree, HEAD `e2e87f9`, six local commits
after `df30286`, no upstream.

After protocol checkpoint `9c37e34` (21 files, +1251): campaign executed on that
SHA. Evidence checkpoint `c5be1d49eea7b779378182fd2db4df2255c65df1` records
curated JSONL/logs (does not change measurement SHA). Results/novelty commit
follows this file. Smoke run directories `ql-smoke-b6{,b,c}/` remain untracked
(pre-campaign harness smokes; not mixed into campaign artifacts).

`git diff --check` and `git diff --check df30286..HEAD`: no whitespace errors
at Phase 0 and at results-write (no tracked mutations after `9c37e34` except
untracked evidence).

## 5. Frozen-pair integrity

| Tree | `postgres_store.py` | `test_apcc_postgres.py` |
| --- | --- | --- |
| Campaign SHA / HEAD / `8bea7c4` | `576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a` | `dff15b7f8b0aa6ebe3fad19305ea829faf05f71836b1ea91daa5d55c8dfb9a22` |
| `df30286` | `fc1c1345fbe8d7486089e6025a46a0a6a861c241b44041e18dccbc686dd78749` | `ad77a7ecd39de434ee455ab5155def1842b925c9ac1c275c22ea91ff5e494f2c` |

Pair was **not** repaired. Independent static verdict `APPROVE-WITH-P2`
applies to pair **content** `576c0449` / `dff15b7f`, not to `df30286` blobs.
`docs/internal/APCC-1-B2-Postgres-Close.md` lists the HEAD hashes but attributes
them to HEAD `df30286` — that attribution is false.

Pre-checkpoint PG `366 passed in 2224.68s` is bound to `df30286` only.
This campaign re-ran the file at `9c37e34`.

## 6. Environment and dependency versions

From Phase 0 plus live-window checks. Redacted: no DSN passwords observed
(`postgresql://apcc@127.0.0.1:55434/apcc_test`).

| Item | Value |
| --- | --- |
| OS | Fedora 44, Linux `7.1.9-200.fc44.x86_64`, x86_64 |
| CPU | AMD Ryzen 7 7800X3D, 8 cores / 16 threads |
| RAM | 125 GiB |
| Swap | 15 GiB; **0 B free** at Phase 0; **56 KiB free** at `2026-08-29T17:05Z` |
| Python | CPython 3.13.13 (worktree `.venv`) |
| SQLite | 3.53.1 |
| cryptography | 47.0.0 |
| psycopg | 3.3.4 |
| Go | `go1.26.7-X:nodwarf5 linux/amd64` |
| Java | OpenJDK 25.0.4.1 |
| `uv.lock` SHA-256 | `6c26c7df94b53529f4a37fb1417241f3ec163b1238a012a3c563aaf6a149cfd5` |
| TLC JAR | `/home/martin/.cache/acgs-tlc/tla2tools-v1.7.4.jar` SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| PostgreSQL | 17.10 (Debian 17.10-1.pgdg12+1) `127.0.0.1:55434` |
| PG durability | `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `max_connections=200` |
| PG `shared_buffers` | **128MB** (frozen plan wanted 4GB) |
| Leftover PG roles | `apcc_test_aca927aa96486a240e433636_owner`, `…_runtime`; namespaces: `public` only after 366 at `9c37e34` |

Confounders for latency/throughput: swap exhaustion; concurrent PG 366 during
the live performance window; `shared_buffers=128MB`.

## 7. Experimental protocol

Newly introduced methodology, frozen `2026-08-29T16:00:00Z` before campaign:

- `docs/internal/APCC-1-Qualification-Live-Protocol.md`
- `experiments/apcc-1/qualification-live.v1.json`
- `experiments/apcc-1/run_qualification_live.py`

Seed: `104729` only (frozen five-seed schedule not executed).
Warm-up: 3 × 30 s unreported. Measured: 10 × 30 s. Target written: 10/s.
`MIN_OPS=10000` ⇒ any paced 10/s × 30 s run is `incomplete_run` even if paced.
Harness defect (committed, not repaired mid-campaign):
`time.sleep(min(next_beat - now, 0.001))` — 10/s open-loop not enforced.
Payloads: `os.urandom(1024/4096)` at import (not derived from seed 104729).

Novelty rubric: incomplete frozen-plan live gates ⇒ overall **UNDETERMINED**.

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
| B6 public `execute` | APCC-1 | `B6AuthorityAdapter` | BLOCKED_MISSING_DEPENDENCY (empty capabilities / trusted supervisor) |
| B6 SQLite store | APCC-1 | `SQLiteAuthorityStore` via test request builder | LIVE_READY for 4 planned negatives + `QL-INDEP-NODE` first-commits |
| B6 PostgreSQL performance | APCC-1 | in-tree rate-generator | BLOCKED_MISSING_DEPENDENCY |
| Empirical ablations | one-at-a-time B6 element removal | none in-tree | BLOCKED_MISSING_DEPENDENCY |
| Frozen 102416 cells | experiment plan | no runner | CONTRACT_ONLY / PENDING_MEASUREMENT |

## 9. B0–B6 live results

Labels used: CONTRACT TESTED / LIVE MEASURED / BLOCKED / THRESHOLD MET /
THRESHOLD NOT MET / INCONCLUSIVE.

| ID | Frozen matrix | Empirical pytest (209) | Scenarios (n=1, seed 104729) | Performance (written 10/s cell) | Security threshold (planned B6-store trials) |
| --- | --- | --- | --- | --- | --- |
| B0 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (23 executed, 16 capability-BLOCKED; 39/39 catalog-match) | INCONCLUSIVE (`TARGET_RATE_NOT_ENFORCED`; 10/10 incomplete) | n/a |
| B1 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (same split) | INCONCLUSIVE | n/a |
| B2 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (21 compromised, 2 fail-closed, 16 blocked) | INCONCLUSIVE | n/a |
| B3 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (same as B0/B1) | INCONCLUSIVE | n/a |
| B4 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (22 fail-closed, 16 blocked, 1 compromised=`concurrent-double-commit:default` catalog-expected; sequential, not a live race) | INCONCLUSIVE | n/a |
| B5 | CONTRACT_ONLY / PENDING | CONTRACT TESTED | LIVE MEASURED (21 fail-closed, 11 not-applicable, 5 recovered, 2 blocked) | INCONCLUSIVE (below written 10/s; incomplete) | n/a |
| B6 public adapter | CONTRACT_ONLY / PENDING | CONTRACT TESTED | BLOCKED (39/39 `observed=blocked`; `execute` not called) | — | not a store trial |
| B6 SQLite store | CONTRACT_ONLY / PENDING | CONTRACT TESTED | 4 negatives LIVE MEASURED (see §10) | INCONCLUSIVE (`QL-INDEP-NODE`, not frozen W1; incomplete) | THRESHOLD MET **for those 4 cases only** (`invalid_authoritative_commits=0`) |
| B6 PostgreSQL | CONTRACT_ONLY / PENDING | — | — | BLOCKED_MISSING_DEPENDENCY | PG file is store-specific conformance, not this threshold |

Scenario counts: attempted 273, matched_expected 273, mismatched 0, errors 0,
b6_blocked 39. Observed overall: blocked 121, compromised 91, fail-closed 45,
not-applicable 11, recovered 5.

Performance measured medians (ops/s, p50/p95/p99 ms; n=10; failures=0;
incomplete=10/10). These are **not** 10/s open-loop cells.

| ID | median ops/s | min–max ops/s | median p50 ms | median p95 ms | median p99 ms | completed sum (10×30s) |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| B0 | 43.6167 | 42.6000–44.3667 | 20.878 | 27.558 | 35.881 | 13049 |
| B1 | 29.1500 | 27.8000–30.4000 | 30.853 | 48.662 | 58.961 | 8727 |
| B2 | 28.9167 | 28.3667–30.3667 | 30.509 | 50.579 | 59.918 | 8750 |
| B3 | 29.6500 | 28.8667–30.6000 | 30.998 | 45.062 | 57.960 | 8903 |
| B4 | 27.7333 | 25.9000–28.6667 | 31.638 | 56.590 | 61.637 | 8266 |
| B5 | 8.3833 | 7.8333–8.7000 | 117.763 | 159.759 | 183.513 | 2507 |
| B6 SQLite `QL-INDEP-NODE` | 6.4833 | 6.1667–6.7000 | 151.536 | 183.451 | 213.443 | 1927 (nodes_used 185–201 / 400) |

No relative difference vs B5 is reported (protocol: omit if incomplete).

## 10. Adversarial results

Catalog: `default_scenario_catalog()` — 32 `ATTACK_IDS`, 39 variants, 1 trial
each, B0–B6. Canonical names only.

B0–B5: live adapter path. Many operational variants (revocation, crash, outbox,
recovery, status) are capability-BLOCKED on B0–B4 rather than exercised.
B6 catalog: tautological blocked (empty capabilities; expected hardcoded
`blocked`).

B6 SQLite store negatives (planned list; no post-hoc adds):

| case_id | outcome | notes |
| --- | --- | --- |
| valid-first-commit | COMMITTED | 4960-byte certificate; digest `NVAO_SrMuCcypLvlx7UofVBcDoNidkIQONqXUSSzh6Y` |
| exact-replay | COMMITTED | `same_envelope_bytes=true`; `second_authority=false` |
| commit-id-equivocation | CONFLICTED | `COMMIT_ID_EQUIVOCATION`; `second_authority=false` |
| invalid-commit-request | DENIED | tampered producer signature; `INVALID_PRODUCER_SIGNATURE` |

Runner counter `invalid_authoritative_commits=0` (exact-replay COMMITTED with
no second authority is not counted invalid). This is **not** frozen-plan
30-trial / 100-trial security acceptance.

Mapping of user-requested categories to catalog names (no duplicate names
invented). Disposition is catalog-match unless noted:

| Requested category | Canonical coverage in this campaign | Live B6 store? |
| --- | --- | --- |
| stale proof | `stale-cache:*` | no (catalog only; B6 blocked) |
| substituted proof | `output-substitution`, `input-substitution`, `identity-substitution` | no |
| payload/proof mismatch | `certificate-truncation:*`, substitutions | no |
| canonicalization drift | `canonicalization-ambiguity:default` | no |
| digest mismatch | `certificate-truncation:payload-digest` / `envelope-digest` | no |
| replay | `cross-node-replay`, `cross-workflow-replay`, `cross-attempt-replay` | exact-replay on SQLite store only |
| duplicate submission | `response-loss-and-retry:default` (mostly capability-BLOCKED) | exact-replay |
| idempotent retry | same / B6 exact-replay | yes (4-case set) |
| concurrent writers | `concurrent-double-commit:default` | sequential catalog; **not** a live race (Reviewer A P1) |
| conflicting writers | `commit-id-equivocation:default` | yes (SQLite store) |
| crash before authority commit | `validator-crash:*` (capability-BLOCKED on B0–B4) | no |
| crash after commit before ack | `response-loss-and-retry:default` | no |
| outbox replay | `outbox-failure:default` | no |
| cross-workflow visibility | `cross-workflow-replay:default` | no |
| unauthorized observation | no dedicated catalog variant | no |
| storage divergence | not in qualification-live | no |
| malformed certificate | truncation / unknown-version / oversized | no |
| verifier disagreement | Python/Go pytest, not scenario catalog | see §14 |
| unsupported algorithm/version | `unknown-protocol-version:default` | no |
| partial/corrupt artifact | truncation | no |
| timeout / dependency failure | `authority-store-transaction-failure:default` | no |

Unexpected acceptance of stale/substituted/malformed/mismatched/unauthorized
evidence on a **live B6 store path** was not observed in the 4 planned
negatives. Catalog B0–B3 `compromised` on missing-proof / substitutions is
expected for those baselines, not a B6 fail-open.

## 11. Ablation results

| Kind | Status |
| --- | --- |
| Implementation empirical ablations (frozen plan: remove one B6 element) | BLOCKED_MISSING_DEPENDENCY — not executed |
| TLA+ witness/ablation | LIVE at campaign SHA; formal only; see §15 |
| Passing intact system without degrading ablation | does not establish causation; empirical ablations absent |

## 12. Performance results

See §9 table. Additional:

- CPU, memory, DB connections, outbox backlog, recovery time, txn retry, lock
  wait: **not instrumented** (not reported as zero).
- Bootstrap 10,000 resamples: protocol gap (`bootstrap_resamples: 0`).
- B6 PostgreSQL performance: BLOCKED_MISSING_DEPENDENCY (no in-tree rate-generator).
- Reviewer A P0: do not interpret these runs as the written 10/s cell.
- Reviewer A P1: PG 366 overlapped this window (`16:08:32Z`–`16:48:17Z` vs
  performance `16:09:54Z`–`16:55:50Z`).

## 13. PostgreSQL/SQLite cross-store equivalence

| Gate | Result | Claim allowed |
| --- | --- | --- |
| SQLite APCC file | 383 passed in 34.03s at `9c37e34` | SQLite suite conformance |
| PostgreSQL APCC file | 366 passed in 2385.52s at `9c37e34` | PostgreSQL suite conformance |
| Shared canonical vectors, identical external dispositions | **not executed** | **not claimed** |

Wording used: two implementations conform to their store-specific test
contracts. “Storage independent” is **not** claimed.

## 14. Python/Go verifier agreement

Repository closure (`tasks/apcc-1-plan.md`): standalone Go verifier without
Python reuse; Go unit / **RFC vector** / APCC vector / formatting / vet /
static checks; Python/Go agreement on every valid and invalid checked-in vector.

| Check at `9c37e34` | Result |
| --- | --- |
| `go test ./...` (cached, then `-count=1`) | exit 0; packages `apcc`, `cj1`, `cli` ok; `cmd/apcc-verify` no tests |
| `gofmt -l` | empty / exit 0 |
| `go vet ./...` | exit 0 |
| `tests/test_apcc_go_verifier.py` + `tests/test_apcc_verifier.py` | 66 passed in 1.38s |
| IETF RFC 8785 appendix corpus | **missing** — `internal/cj1` is APCC-CJ1 malleability, not RFC appendix |
| Store linearization by offline verifier | **cannot** (`verifiers/apcc-go/README.md`) |

**Verifier qualification gate: PARTIAL.** Tests at this SHA are green; the
plan’s RFC-vector criterion is unmet. Historical note that tests alone do not
automatically close the gate stands.

## 15. TLA+ safety and non-vacuity evidence

Command: `.venv/bin/python scripts/run_apcc_tlc.py --tlc-jar /home/martin/.cache/acgs-tlc/tla2tools-v1.7.4.jar --timeout 360`
SHA: `9c37e34`. Specs unchanged vs `e2e87f9`. JAR pin matched.

| Field | Value |
| --- | --- |
| Start | `2026-08-29T17:05:10Z` |
| End | `2026-08-29T17:09:48Z` |
| Wall | 278.111 s |
| Runner exit | 0 |
| Harness | **32/32 PASS** (this SHA’s `DEFAULT_CONFIGS` has 32 entries; historical “31/31” is not reused) |
| Safety/liveness `exit=0` | `apcc_safety.cfg`, `apcc_liveness.cfg`, `apcc_causal_safety.cfg`, `apcc_multitenant_safety.cfg` |
| Witness/ablation `exit=12` | 28 configs; harness-PASS of intended named invariant violations |

Formal pytest wrapper `tests/test_apcc_formal.py`: 6 passed in 0.02s — **not TLC**.

## 16. Static-review findings

Independent static close of frozen pair content `576c0449` / `dff15b7f`:
`APPROVE-WITH-P2`; P0=0; P1=0. Pair unchanged at campaign SHA; close remains
associated with that **content**, not with `df30286`.

Reviewer A (methodology): P0=1, P1=8 (performance labeling / fairness /
undersampling / B6 preflight).
Reviewer B (novelty): P0=3 (claim charts, frozen campaign, hashed archives).

No new frozen-pair code P0/P1. No silent pair repair.

## 17. Known P2 limitations (frozen pair; remain visible)

1. GCB fingerprint is not threaded through all reader and observation paths
   (`_POSTGRES_SCHEMA_FINGERPRINT` on readers; GCB writers mutation-gated).
2. PostgreSQL does not have a native `commit_output_refs` pin.
3. SQLSTATE 23505 mismatch handling sits outside the retry loop.
4. Outbox delivery is at-least-once (claim/deliver/finalize are three transactions).
5. `hashtextextended` advisory-lock collisions are theoretically possible
   (unique constraints are the backstop).

Additional documented P2s in the B2 close record (schema-manifest trigger names,
`FOR UPDATE` missing-row, SQLite-only extras, self-referential matrix test)
remain unresolved.

## 18. Resource-leak and teardown findings

- After PG 366 at `9c37e34`: no leftover `apcc_test_%` schemas; same two orphan
  roles as Phase 0 (`aca927aa96486a240e433636` owner/runtime). Not attributed
  as new leakage from the completed 366.
- Live campaign: SQLite DBs, B5 provisioned venvs under `perf-db/`, WAL files
  remain on disk; gitignored; no host-wide cleanup.
- Reviewer A P2: B0–B4 performance adapters are not `close()`d.
- Auto `MANIFEST.sha256` (7,688,585 bytes) hashes gitignored B5 trees — **not
  committed**.

## 19. Artifact inventory and SHA-256 values

Curated bindable files (`experiments/apcc-1/qualification-live/runs/campaign-9c37e34/CURATED-MANIFEST.sha256`):

```
2cc9dfa57122646dcf085623900de73df0934fb88bce329a3079118d66147f5c  experiments/apcc-1/qualification-live/runs/campaign-9c37e34-live/summary.json
969ef867320f2d15a56e61cdbe06c4cef472a5c09b9d40a56ebef8fb730d98a9  experiments/apcc-1/qualification-live/runs/campaign-9c37e34-live/scenarios.jsonl
3393f752f3a9193ad301ac6cab25d7863c0373d7758dd979292499fefd1f5340  experiments/apcc-1/qualification-live/runs/campaign-9c37e34-live/b6-sqlite-negatives.jsonl
1a8d7fabb8131802b45466fbbbbaebfc4929254ed364a820e1e266db20e43e40  experiments/apcc-1/qualification-live/runs/campaign-9c37e34-live/performance.jsonl
6b58237bd27cc933ff0e5b3ea4e23a7c38fc084cb70289112cd5317cd28cbea8  experiments/apcc-1/qualification-live/runs/campaign-9c37e34-live-driver.log
78cece2beefa8a7a61a8013790269b4156fd0fe6fb8cca933b4b9d566bbcf48d  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/apcc-unit-empirical-formal.log
f244c5219e206e476e5c49842d112d8db5f158b5e486bfe06552975ff0079240  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/postgres-full.log
eeadc67c8675ea9c7879ce1a52c3da3c8e06aaed83d63d9f7d3b19a77154540e  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/postgres-security-marker.log
9242d2783fc5be98c91eb9e37becaaf38ff8a57b36fa0ed94a228e496b46c2dd  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/sqlite-full.log
54908de7d68e44fd55b3919f3ec52aacfb08315dca608c70a77b6d07d5116c5a  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/tlc.log
126644ede811f12989474d788ac391ec71d00de0684fc26f49d124c95c000bed  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/verifier-go-count1.log
cd48d1c72c4d5f39f62ab0534f9a5c67a5a8751d579120ce2fbe80f2e65fbc93  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/gates/verifier.log
079037d4c99220a6ba71837101704a07a310e9b4bfdfac6d139b2b2a0114083a  experiments/apcc-1/qualification-live/runs/campaign-9c37e34/identity.txt
```

Do not commit: `MANIFEST.sha256`, `*.db`, `perf-db/`, `scenario-db/`,
`perf-b6-sqlite/`, `b6-sqlite/`.

## 20. Reproduction commands

Pin `git -C` to the worktree. Campaign SHA must be `9c37e34` to reproduce
these artifacts (later evidence commits do not re-run measurements).

```bash
WT=/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit
git -C "$WT" rev-parse HEAD   # measurements were taken at 9c37e34
export APCC_POSTGRES_DSN='postgresql://apcc@127.0.0.1:55434/apcc_test'
"$WT/.venv/bin/python" -m pytest tests/test_apcc_postgres.py --import-mode=importlib -q --tb=line
"$WT/.venv/bin/python" -m pytest tests/test_apcc_sqlite.py --import-mode=importlib -q --tb=line
"$WT/.venv/bin/python" -m pytest tests/test_apcc_empirical_adapters.py tests/test_apcc_empirical_artifacts.py tests/test_apcc_empirical_contract.py tests/test_apcc_empirical_historical_gcb.py tests/test_apcc_empirical_scenarios.py --import-mode=importlib -q
"$WT/.venv/bin/python" -m pytest tests/test_apcc_formal.py --import-mode=importlib -q
"$WT/.venv/bin/python" -m pytest tests/test_apcc_model.py tests/test_apcc_codec.py tests/test_apcc_service.py tests/test_apcc_observation.py tests/test_apcc_observation_semantics.py tests/test_apcc_architecture.py tests/test_apcc_authority_backend.py tests/test_apcc_authority_service.py tests/test_apcc_gcb_projection_contract.py --import-mode=importlib -q
( cd "$WT/verifiers/apcc-go" && go test -count=1 ./... && test -z "$(gofmt -l .)" && go vet ./... )
"$WT/.venv/bin/python" -m pytest tests/test_apcc_go_verifier.py tests/test_apcc_verifier.py --import-mode=importlib -q
"$WT/.venv/bin/python" "$WT/scripts/run_apcc_tlc.py" --tlc-jar /home/martin/.cache/acgs-tlc/tla2tools-v1.7.4.jar --timeout 360
"$WT/.venv/bin/python" "$WT/experiments/apcc-1/run_qualification_live.py" --run-id reproduce-check
```

Re-running qualification-live will **not** reproduce payload bytes (urandom)
or 10/s pacing (1 ms sleep cap still in `9c37e34` harness).

## 21. Prior-art comparison

`docs/internal/APCC-1-Prior-Art.md` (cut-off 2026-08-28): mechanism novelty
**INSUFFICIENT EVIDENCE**; ceiling **SYSTEMS ABSTRACTION**. No local hashed
archives. No claim charts for CCF/IA-CCF, Corda, Fabric, TCT, Authenticated
Workflows, PoE, CommitGuard. Qualification-live does not change that record.
Reviewer B: prior art is not shown to subsume the four-part conjunction and
not shown to be absent. Strongest adverse reading remains predictable
composition.

## 22. Novelty analysis

Rubric precommitted in `APCC-1-Qualification-Live-Protocol.md` **before**
outcomes. Overall GO/CONDITIONAL/NO-GO only after required **frozen-plan** live
gates. Those gates are incomplete ⇒ overall **UNDETERMINED**.

| Axis | Verdict | Basis |
| --- | --- | --- |
| Mechanism novelty | UNDETERMINED | charts + frozen live cells missing; not NO-GO (subsumption unproven); not GO |
| Systems-architecture | CONDITIONAL | qualification-live subset only; do not raise SYSTEMS ABSTRACTION ceiling |
| Implementation assurance | CONDITIONAL | SHA-bound stores/formal/unit gates; RFC 8785 appendix missing; P2s open |
| Empirical utility | CONDITIONAL | subset only; 4 B6 SQLite negatives held planned counter; frozen cells incomplete |
| Operational applicability | not claimed | rubric default |

A large passing unit-test count does not move mechanism novelty off
INSUFFICIENT EVIDENCE.

## 23. Unsupported or rejected claims

- Frozen `apcc-1.matrix.v1` complete or closed
- B6 catalog 39/39 match as live APCC-store adversarial measurement
- Empirical pytest 209 as live B0–B6
- Formal wrapper 6 as TLC
- Independent green SQLite 383 + PG 366 as storage independence
- Historical postgres `-m security` 100 passed / 266 deselected at this SHA
  (actual: 366 deselected, exit 5)
- Target rate 10/s enforced; performance `LIVE_MEASURED` as the §C cell
- Throughput/latency superiority or 25% overhead vs B5
- Mechanism novelty GO / primitive novelty
- Production readiness
- TLC exit 12 as ordinary safety success
- RFC 8785 appendix conformance
- Empirical ablation non-vacuity

## 24. Final qualification table

| Gate | SHA | Status |
| --- | --- | --- |
| Frozen pair integrity | `9c37e34` content `576c0449`/`dff15b7f` | intact; P2s open |
| Independent static B2 | pair content | APPROVE-WITH-P2; not re-run (pair unchanged) |
| PostgreSQL 366 | `9c37e34` | 366 passed in 2385.52s, exit 0 |
| Postgres `-m security` | `9c37e34` | 366 deselected, exit 5; historical 100/266 **not reproduced** |
| SQLite APCC 383 | `9c37e34` | 383 passed in 34.03s, exit 0 |
| Empirical contract 209 | `9c37e34` | 209 passed in 84.79s — CONTRACT ONLY |
| Remaining 9 APCC files | `9c37e34` | 269 passed in 64.07s (not historical 331; different selection) |
| Formal wrapper | `9c37e34` | 6 passed in 0.02s — not TLC |
| TLC harness | `9c37e34` | 32/32 PASS; 4 safety exit 0; 28 witness/ablation exit 12 |
| Go + Python agreement | `9c37e34` | tests green; RFC appendix **missing** ⇒ verifier PARTIAL |
| Cross-store shared vectors | — | not executed |
| B0–B6 frozen matrix | — | PENDING / CONTRACT_ONLY |
| B0–B6 qualification-live scenarios | `9c37e34` | 273/273 catalog-match; B6 public BLOCKED |
| B6 SQLite 4 negatives | `9c37e34` | LIVE; planned counter 0 |
| B0–B6 performance 10/s cell | `9c37e34` | INCONCLUSIVE (P0 labeling / rate) |
| Empirical ablations | — | BLOCKED_MISSING_DEPENDENCY |
| Independent reviews | this file | A + B complete; both refuse mechanism GO |
| Novelty | — | UNDETERMINED |
| Production readiness | — | NOT CLAIMED |

## 25. Commit and push status

Campaign SHA (measurements): `9c37e34a9a1971057d304dab1bc4b893dafc17a6`.
Evidence checkpoint: `c5be1d49eea7b779378182fd2db4df2255c65df1`.
Results/novelty checkpoint: this commit (see `git log -1`).
**Push not performed**; no upstream; no fetch.

## 26. Production-readiness statement

**PRODUCTION READINESS NOT CLAIMED.**

No operator runbook, multi-host durability campaign, or production-like
`shared_buffers`/swap-free host was used. Known P2s remain. B6 public execute
path is inert.

## Compact evidence table (commands)

| Command | SHA | Start UTC | End UTC | Exit | Summary | Artifact | SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pytest tests/test_apcc_postgres.py -q --tb=line` | `9c37e34` | 2026-08-29T16:08:32Z | 2026-08-29T16:48:17Z | 0 | 366 passed in 2385.52s | `…/gates/postgres-full.log` | `f244c5219e206e476e5c49842d112d8db5f158b5e486bfe06552975ff0079240` |
| `pytest tests/test_apcc_postgres.py -m security` | `9c37e34` | 2026-08-29T17:05:25Z | 2026-08-29T17:05:25Z | 5 | 366 deselected | `…/gates/postgres-security-marker.log` | `eeadc67c8675ea9c7879ce1a52c3da3c8e06aaed83d63d9f7d3b19a77154540e` |
| `pytest tests/test_apcc_sqlite.py -q` | `9c37e34` | 2026-08-29T16:08:36Z | 2026-08-29T16:09:11Z | 0 | 383 passed in 34.03s | `…/gates/sqlite-full.log` | `9242d2783fc5be98c91eb9e37becaaf38ff8a57b36fa0ed94a228e496b46c2dd` |
| empirical 5 files | `9c37e34` | 2026-08-29T16:08:46Z | (in combined log) | 0 | 209 passed in 84.79s | `…/gates/apcc-unit-empirical-formal.log` | `78cece2beefa8a7a61a8013790269b4156fd0fe6fb8cca933b4b9d566bbcf48d` |
| remaining 9 files | `9c37e34` | same log | 2026-08-29T16:11:15Z | 0 | 269 passed in 64.07s | same | same |
| `test_apcc_formal.py` | `9c37e34` | same log | same | 0 | 6 passed in 0.02s | same | same |
| `go test`/`gofmt`/`go vet` + 66 pytest | `9c37e34` | 2026-08-29T16:08:42Z | 2026-08-29T16:08:45Z | 0 | 66 passed in 1.38s; go cached | `…/gates/verifier.log` | `cd48d1c72c4d5f39f62ab0534f9a5c67a5a8751d579120ce2fbe80f2e65fbc93` |
| `go test -count=1 ./...` | `9c37e34` | 2026-08-29T16:16:44Z | 2026-08-29T16:16:44Z | 0 | apcc 0.022s, cj1 0.002s, cli 0.109s | `…/gates/verifier-go-count1.log` | `126644ede811f12989474d788ac391ec71d00de0684fc26f49d124c95c000bed` |
| `run_apcc_tlc.py` 32 configs | `9c37e34` | 2026-08-29T17:05:10Z | 2026-08-29T17:09:48Z | 0 | 32/32 harness PASS | `…/gates/tlc.log` | `54908de7d68e44fd55b3919f3ec52aacfb08315dca608c70a77b6d07d5116c5a` |
| `run_qualification_live.py --run-id campaign-9c37e34-live` | `9c37e34` | 2026-08-29T16:08:46Z | 2026-08-29T16:55:55Z | 0 | 273/273; 4 B6 negatives; perf INCONCLUSIVE | driver + jsonl | driver `6b58237bd27cc933ff0e5b3ea4e23a7c38fc084cb70289112cd5317cd28cbea8` |

## Next action if incomplete

1. Do not relabel qualification-live as `apcc-1.matrix.v1`.
2. Optional: fix 1 ms sleep cap in a **new** protocol checkpoint; rerun
   **performance only** on the new SHA; do not mix with `9c37e34` rows.
3. Required for a stronger novelty verdict: claim-chart archive; frozen live
   B0–B6 cells or a newly frozen smaller matrix **before** measurement; live
   B6 adapter; empirical ablations; shared SQLite/PG vectors; RFC 8785 appendix
   corpus; five-seed / 30-trial cardinalities.
4. Do not push from this worktree unless a human requests it.
