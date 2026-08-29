# Phase 0 continue — 2026-08-29T18:03:58Z

Worktree:
`/home/martin/Documents/Codex/2026-08-26/acgs-swarm-multi-agent-systems-distributed/work/Acgs-Swarm-public-main/.worktrees/apcc-1-atomic-proof-carrying-commit`

| Field | Value |
| --- | --- |
| Branch | `apcc-1-atomic-proof-carrying-commit` |
| HEAD | `4ef82a21af884e749cee31e79b9ee6360ad3cfa8` |
| Upstream | none (no fetch) |
| Staged | empty |
| Unstaged tracked | empty |
| Frozen pair SHA-256 | `576c0449a55a86b6d35499f3b7acd86fdca95603fe416385264705f386aaec6a` / `dff15b7f8b0aa6ebe3fad19305ea829faf05f71836b1ea91daa5d55c8dfb9a22` |
| vs required hashes | **match** |
| git blobs at HEAD | `da5071e6608d42c6ace296bff6d022afffc708c1` / `ed9e04f28dfeb1621c0a26a49cf5a79a5df3c319` |
| `df30286` pair blobs | differ (not this content) |

Untracked preserved: `ql-smoke-b6{,b,c}/`, v2 performance and PG-neg run dirs, failed-attempt logs.

| Env | Value |
| --- | --- |
| Python | 3.13.13 |
| psycopg | 3.3.4 |
| Go | go1.26.7-X:nodwarf5 linux/amd64 |
| PostgreSQL | 17.10 (Debian 17.10-1.pgdg12+1) at `127.0.0.1:55434` |
| `shared_buffers` | 128MB (frozen plan wanted 4GB) |
| `max_connections` | 200 |
| `apcc_test_%` schemas | none |
| leftover roles | `apcc_test_aca927aa96486a240e433636_{owner,runtime}` |
| SwapTotal / SwapFree | 16777212 / 221940 kB |
| TLC JAR SHA-256 | `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| DSN | `postgresql://REDACTED@127.0.0.1:55434/apcc_test` |

Local commits after `df30286`: 11 (includes `3d4d9dd` pacer v2, `4ef82a2` PG unwrap).
Nothing pushed.
