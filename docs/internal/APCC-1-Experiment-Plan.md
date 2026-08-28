# APCC-1 Frozen Experiment Plan

## Status and freeze rule

This plan is frozen before final measurements for `APCC-1.0-draft`.
`BASELINE_REMOTE_EVIDENCE_INCOMPLETE` applies. Results are unmeasured and MUST
remain labeled `PENDING_MEASUREMENT` until raw artifacts, environment records,
and hashes exist. Any change to protocol, workload, seeds, settings, repetitions,
or analysis after the first measured run increments the plan revision and
requires a complete rerun of B0–B6 for every affected cell.

## Frozen environment

| Dimension | Frozen value or capture requirement |
|---|---|
| Host | Fedora Linux 44, kernel `7.1.9-200.fc44.x86_64`, x86_64 |
| CPU/RAM | AMD Ryzen 7 7800X3D, 8 cores/16 threads, 125 GiB RAM |
| Repository baseline | `6e65db3e478fa315119038b616d78f4f171422db` |
| Python | Repository environment: CPython 3.13.13 via `uv --no-sources`; record exact lock hash |
| SQLite | Durable file; `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`, `page_size=4096`, `wal_autocheckpoint=1000` |
| PostgreSQL | PostgreSQL 17.x; `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `max_connections=200`, `shared_buffers=4GB`; ordered admission locks and full semantic attestation within one `REPEATABLE READ` snapshot |
| Go | `go1.26.7` linux/amd64; standalone verifier |
| Formal tool | TLC 1.7.4; record JAR SHA-256 and JVM flags |
| Storage | Record filesystem, mount, free space, sync settings, database sizes, and cache state per run |
| Isolation | One benchmark group at a time; no parallel TLC in one model directory; record host load/thermal state |

The final artifact records exact `uname`, CPU topology, memory, tool versions,
dependency lock hash, git SHA/status, database configuration, seeds, start/end
times, and raw-result hashes. Credentials and DSNs are redacted.

## Baselines, expected guarantees, and fairness

`Y` is an intended guarantee; `N` is intentionally absent; `N/A` means the
baseline does not expose that protocol object and is not scored as a defect for
its absence.

| Baseline | Mechanism | Pre-commit policy | Producer signature | Atomic proof/context/state | Predecessor certificate | Portable certificate | Current status | Independent verifier |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| B0 | Direct completion | N | N | N | N/A | N/A | N/A | N/A |
| B1 | Commit then post-hoc audit | N | N | N | N/A | N/A | N/A | N/A |
| B2 | Pre-execution policy gate | Y | N | N | N/A | N/A | N/A | N/A |
| B3 | Signed result log | N | Y | N | N | N | N/A | N/A |
| B4 | Verify proof, then separate write | Y | Y | N | Y | N | N/A | N/A |
| B5 | Existing GCB-1 SQLite | Y | Y | Y | Y | N | N | N |
| B6 | APCC-1 | Y | Y | Y | Y | Y | Y | Y |

All baselines use identical input/output sizes, DAGs, workloads, seeds, database
durability, host allocation, warm-up, measurement duration, and client load.
No baseline is intentionally delayed or deprived of indexes/batching it would
normally use. B5 and B6 report SQLite separately; B6 additionally reports
PostgreSQL. Security differences remain explicit rather than normalized away.

## Seeds, repetitions, and statistics

- Frozen seeds: `104729`, `130363`, `155921`, `196613`, `262147`.
- Functional attacks: exactly 30 trials per baseline/store/attack, six per seed;
  deterministic parser vectors run exactly once per build and 10,000 generated
  parser cases per seed.
- Race/recovery attacks: exactly 100 trials per condition, 20 per seed.
- Latency/throughput cells: exactly 3 unreported warm-up runs followed by 10
  measured runs. Each run lasts exactly 30 seconds after reaching target load;
  a run with fewer than 10,000 completed operations is retained and flagged.
- Restart/revocation/outbox timing: exactly 30 repetitions, six per seed.
- Storage growth: exactly 100,000 successful commits on 3 fresh databases per
  baseline/store.
- Report every run, median across repetitions, p50/p95/p99 from raw operations,
  bootstrap 95% confidence intervals with 10,000 resamples, failure counts, and
  effect sizes. Never discard an outlier without a predeclared infrastructure
  failure and retained raw record.

Security acceptance uses zero invalid authoritative commits in all planned
trials and zero Python/Go verdict/code disagreement. This empirical threshold
does not prove absence of attacks. Performance has no pass/fail superiority
threshold; report overhead with confidence intervals. Flag, but do not hide,
overhead above 25% p95 latency, 25% throughput loss, or 4 KiB median certificate
size relative to B5.

## Frozen workload matrix

Payload sizes are decoded input/output bytes before hashing. Target rates use an
open-loop generator at 10, 100, and 500 proposals/s; any unsustainable rate is
retained as overload evidence. `1,000 logical Agents` means identities on one
host, not distributed execution.

| ID | DAG and payload | Agents / executor concurrency | Mutation/retry schedule |
|---|---|---|---|
| W1 | 1 node; 1 KiB input, 4 KiB output | 1 / 1 | none |
| W2 | 100-node linear DAG; 1 KiB / 4 KiB | 100 / 16 | none |
| W3 | 1 root plus 100 children (fan-out 100); 1 KiB / 4 KiB | 101 / 100 | none |
| W4 | 100 roots plus 1 child (fan-in 100); 1 KiB / 4 KiB | 101 / 100 | none |
| W5 | 1 node/version with 100 competing attempts; 1 KiB / 4 KiB | 100 / 100 | all contend simultaneously |
| W6 | 10,000 independent nodes; 1,000 logical Agents round-robin; 1 KiB / 4 KiB | 1,000 / 100 | none |
| W7 | W2 with policy epoch update every 100 proposals | 100 / 16 | exact rate 1% updates |
| W8 | W3 with actor revocation every 100 proposals and workflow revocation every 1,000 | 101 / 100 | exact rates 1% / 0.1% |
| W9 | W1 independent nodes; 1 KiB / 4 KiB | 100 / 100 | exact replay ratio 50%; conflicting replay ratio 1% |
| W10 | W1 shape with 0 B / 0 B, 1 KiB / 4 KiB, and 64 KiB / 256 KiB payload pairs | 1 / 1 | none |

Run W1–W10 at all three target rates where the DAG permits repeated instances.
W5 runs one contention cohort per operation slot. W6 executes exactly 10,000
commits rather than a 30-second duration.

Cold cells use a fresh database, restarted benchmark/store processes, and no
pre-run queries; OS page cache is not claimed cold. Warm cells execute the three
warm-up runs against the same populated database before measurement. Baseline
order is seed-shuffled and recorded; store order alternates by seed.

Measure p50/p95/p99 commit latency, commits/s, verifier CPU time, encoding time,
certificate size, database writes/bytes per commit, outbox delay, restart
recovery, revocation propagation, contention conflicts/retries, and projected
and measured storage growth per 100,000 commits.

Each record binds baseline, store, workload, seed, concurrency, payload/DAG
shape, repetition, warm/cold state, success/failure code, authoritative outcome,
timings, byte counts, tool versions, git SHA, and environment ID.

## Attack matrix

Run every B0–B6 baseline against:

```text
missing proof; invalid signature; unknown key; output/input/identity substitution;
cross-node/workflow/attempt replay; commit_id equivocation; policy and authority
update race; actor and workflow revocation race; predecessor replacement;
concurrent double commit; response loss/retry; verifier crash; store transaction
failure; outbox failure; recovery import; legacy promotion; malicious scheduler,
executor, and retry caller; stale cache; certificate truncation; duplicate,
case-mismatched, Unicode, trailing-byte, and canonicalization ambiguity; unknown
version; oversized/deep certificate; duplicate/reordered predecessor; stale,
rolled-back, equivocal, or incomplete `AuthorityStatus`
```

The matrix also runs atomic supersession before/after each write and response,
two concurrent supersessions of one old digest, exact supersession replay,
committed-child nonretroactivity, pending-child predecessor replacement,
multi-level effective-revocation closure, and pre-revocation status use at one
millisecond before and after its effective expiry. Attempt cases separately
exercise internally inconsistent fields (`ATTEMPT_MISMATCH`) and a coherent but
inactive guarded attempt (`CROSS_ATTEMPT_REPLAY`) and assert admission precedence.
Supersession replay is issued after the old certificate is already
`SUPERSEDED` and must still return the original envelope bytes, edge, decision,
and outbox identity. Every commit/replay cell compares persisted
`certificate_payload_bytes`, returned `certificate_envelope_bytes`,
`get_certificate` bytes, predecessor/status target digest, and Python/Go digest.

Record baseline, attack, authoritative compromise, incorrect-current-consumption
event, detection, fail-open/closed result, recovery, latency, and raw artifact.
The primary metric is invalid authority, not logging.

## Ablations

For B6 remove one element at a time: atomic validation/commit, policy epoch,
authority epoch, revocation generation, attempt binding, predecessor certificate
binding, stable `commit_id`, nonce fence, independent verification, staging
invisibility, downstream certificate/current-status requirement, and
transactional outbox. Rerun the targeted attacks and matched performance cell.
Record the newly possible attack, failed invariant, detection, cost saved, and
whether evidence supports essential, defense-in-depth, or redundant status.

## Recovery and formal experiments

Inject faults before and after verification, seal generation, each authoritative
write, transaction commit, response delivery, outbox dispatch, revocation fence,
and propagation. After restart, compare state, exact certificate bytes,
decisions, nonces, conflicts, and outbox identities.

Run the APCC TLA+ safety configuration and five separate fail-closed witness
configurations: valid chain, exact replay, stale-attempt denial, revocation
blocks consumption, and recovery without authority manufacture. Record model,
config/JAR hashes, command, exit status, generated/distinct states, depth,
duration, witness markers, and failures. TLA runs use isolated model directories.
The safety model includes candidate lifecycle, logical-node current pointer,
certificate disposition, supersession edge/replay/crash/conflict behavior,
committed versus pending children, guarded transitive effective revocation, and
bounded pre-revocation status validity.

## Artifacts and stopping rules

Retain the frozen plan, vector corpus, environment JSON, raw JSONL/CSV, logs,
database-size snapshots, formal outputs, analysis script, figures/tables,
manifest, and SHA-256 for every artifact. Negative and failed runs remain in the
bundle. The planned reproduction command is not documented until its script
exists and is executed successfully.

Stop and classify the milestone `BLOCKED` for any open P0/P1, any invalid B6
authoritative commit, Python/Go disagreement, store semantic divergence, formal
safety failure, missing non-vacuity witness, unfair baseline, or missing raw
artifact. Novelty remains unclassified until prior art, all measurements,
ablations, and four independent reviews complete.
