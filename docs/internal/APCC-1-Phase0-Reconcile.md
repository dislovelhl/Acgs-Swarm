# APCC-1 Phase 0 reconcile

Captured `2026-08-29T15:51:09Z` (identity) and `2026-08-29T15:59:08Z` (host extras).
No fetch. No mutation of tracked files before this record. Evidence files under
`docs/internal/apcc-1-evidence/` were created after the clean-tree check.

## Identity

| Field | Value |
| --- | --- |
| Worktree | `/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit` |
| `git rev-parse --show-toplevel` | same as worktree |
| Branch | `apcc-1-atomic-proof-carrying-commit` |
| HEAD | `e2e87f9891adf3cea6af6d8a9375e4f40dae11e9` |
| Expected starting HEAD | `e2e87f9891adf3cea6af6d8a9375e4f40dae11e9` (match) |
| `df30286` | `df30286be482ece23536abf689f328472a565e69` |
| Commits `df30286..HEAD` | 6 |
| Upstream | none (`fatal: no upstream configured`) |
| Remotes | `origin https://github.com/dislovelhl/Acgs-Swarm.git` (not fetched) |
| Push | not performed; branch has no tracking ref |
| Stash | empty |
| Working tree at 15:51:09Z | clean (`## apcc-1-atomic-proof-carrying-commit` only) |

Local commits after `df30286`:

```
e2e87f9 feat(runtime): isolate APCC authority process roles
99b9081 feat(storage): add GCB projection contract for APCC commits
8bea7c4 feat(storage): harden PostgreSQL APCC catalog admission
6497a57 feat(storage): share APCC authority-store core with PostgreSQL
b1ab1cd feat(protocol): add APCC authority observation records
65921c7 docs(research): record APCC B2 PostgreSQL close evidence
```

`git diff --stat df30286..HEAD`: 22 files, 19045 insertions, 1241 deletions.
`git diff --check` and `git diff --check df30286..HEAD`: no whitespace errors.

## Frozen pair

| Tree | `postgres_store.py` SHA-256 | `test_apcc_postgres.py` SHA-256 |
| --- | --- | --- |
| HEAD / 8bea7c4 | `576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a` | `dff15b7f8b0aa6ebe3fad19305ea829faf05f71836b1ea91daa5d55c8dfb9a22` |
| `df30286` | `fc1c1345fbe8d7486089e6025a46a0a6a861c241b44041e18dccbc686dd78749` | `ad77a7ecd39de434ee455ab5155def1842b925c9ac1c275c22ea91ff5e494f2c` |

HEAD pair matches the qualification prompt. Pair **changed** in `8bea7c4`.
`docs/internal/APCC-1-B2-Postgres-Close.md` lists the HEAD hashes but attributes
them to HEAD `df30286`. That attribution is false: those hashes are not the
`df30286` blobs.

Consequence:

- Independent static verdict `APPROVE-WITH-P2` applies to pair content
  `576c0449` / `dff15b7f` (HEAD), not to the `df30286` blobs.
- Pre-checkpoint PostgreSQL `366 passed in 2224.68s` was recorded against
  `df30286` and **cannot** be re-associated with HEAD.
- Post-checkpoint PostgreSQL runs are not bound to a SHA in-repo. They are
  historical until re-run at the campaign SHA.
- Known P2 list remains visible. Pair was not repaired.

## Environment (redacted)

| Item | Value |
| --- | --- |
| Host | fedora, Linux 7.1.9-200.fc44.x86_64, x86_64 |
| CPU | AMD Ryzen 7 7800X3D, 8 cores / 16 threads |
| RAM | 125 GiB; ~70 GiB used, ~55 GiB available at capture |
| Swap | 15 GiB total, **0 B free** (confounder for latency/throughput) |
| Disk | `/dev/nvme0n1p3` btrfs, `/home` 1.9T, 1.1T free; tmpfs `/tmp` 63G |
| Python | CPython 3.13.13 via worktree `.venv` |
| SQLite | 3.53.1 |
| cryptography | 47.0.0 |
| psycopg | 3.3.4 |
| Go | go1.26.7-X:nodwarf5 linux/amd64 |
| Java | OpenJDK 25.0.4.1 |
| `uv.lock` SHA-256 | `6c26c7df94b53529f4a37fb1417241f3ec163b1238a012a3c563aaf6a149cfd5` |
| TLC JAR | `/home/martin/.cache/acgs-tlc/tla2tools-v1.7.4.jar` SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` (matches contract pin) |
| PostgreSQL | 17.10 (Debian 17.10-1.pgdg12+1) at `127.0.0.1:55434`, db `apcc_test`, user `apcc` |
| PG settings | `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `max_connections=200`, **`shared_buffers=128MB`** |
| Frozen-plan PG `shared_buffers` | 4GB. Live endpoint does not match that freeze. |
| Leftover PG roles | `apcc_test_aca927aa96486a240e433636_owner`, `apcc_test_aca927aa96486a240e433636_runtime` (no leftover `apcc_test_%` schemas) |
| GCB-1 worktree | `6e65db3e478fa315119038b616d78f4f171422db` |

DSN password: none observed. No secrets recorded.

## Frozen empirical campaign size (not executed)

From `planning_cardinalities` on `experiments/apcc-1/matrix.v1.json`
(SHA-256 `f919446ca5fae99d2297161959e0017250c402e542275a369b55b8281d158721`):

| Cell family | Count |
| --- | --- |
| functional_attack | 7680 |
| race_recovery | 9600 |
| parser | 50126 |
| timing | 720 |
| performance_warmup | 4320 |
| performance_measured | 28800 |
| ablation | 360 |
| ablation_performance_warmup | 180 |
| ablation_performance_measured | 600 |
| storage_runs | 24 (2,400,000 commits) |
| formal | 6 |
| total planner IDs | 102416 |

No in-tree live campaign runner existed at HEAD. `B6AuthorityAdapter.execute`
raises `B6 execution requires trusted supervisor preflight`. Capabilities empty.

## Verifier gate (repository-defined, not closed by this file)

`tasks/apcc-1-plan.md` requires: standalone Go verifier without Python reuse;
Go unit / RFC vector / APCC vector / formatting / vet / static checks; Python/Go
agreement on every valid and invalid checked-in vector.

Existing historical note: Go package tests + gofmt + go vet + Python/Go
agreement tests passed, but those tests alone were not declared to close the
gate. Missing criterion until re-run at campaign SHA: explicit RFC-8785 corpus
gate, `gofmt`/`go vet`/`go test` at this SHA, and differential over the
checked-in fixture manifest. Offline verifier cannot prove store linearization
(`verifiers/apcc-go/README.md`).

## Historical gates — SHA binding

| Gate | Historical summary | Bindable to HEAD `e2e87f9`? |
| --- | --- | --- |
| PG 366 at `df30286` | 366 passed / 2224.68s | No (pair blobs differ) |
| PG tenth-cycle / post-checkpoint 366 | 100 passed + 266 deselected; 366 passed / 2178.63s | No SHA in-repo |
| Interrupted Codex run | `INTERRUPTED_USAGE_LIMIT_NO_TEST_VERDICT` | Not a test verdict |
| Static B2 | `APPROVE-WITH-P2` on pair `576c0449`/`dff15b7f` | Pair content matches HEAD |
| Empirical B0–B6 pytest | 209 passed / 79.63s | Contract coverage only; re-run at campaign SHA |
| SQLite APCC / formal wrapper / remaining unit / TLC 31/31 | historical counts | Re-run or keep unbound |

Status after Phase 0, before live campaign:

```
APCC-1 QUALIFICATION PARTIAL
NOVELTY UNDETERMINED
PRODUCTION READINESS NOT CLAIMED
```
