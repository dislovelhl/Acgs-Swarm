# APCC-1 — Atomic Proof-Carrying Commit Protocol

## Objective

Extract the essential security and consistency properties of GCB-1 into a
storage-independent, runtime-independent protocol whose authoritative commits
are represented by portable, commit-authority-signed certificates. Prove the
protocol with independent implementations, two real transactional stores,
formal models, adversarial evaluation, fair baselines, and reproducible
artifacts. Issue only the strongest novelty classification supported by the
resulting evidence.

## Locked baseline and truth boundary

- Baseline commit: `6e65db3e478fa315119038b616d78f4f171422db`.
- Baseline merge-base: `259892f1369b9855c367958b02c05fbfbdd31bef`.
- APCC branch: `apcc-1-atomic-proof-carrying-commit`.
- The exact baseline has fresh local verification but no hosted branch, check
  suite, or workflow run. All APCC reports must carry
  `BASELINE_REMOTE_EVIDENCE_INCOMPLETE` until contrary evidence exists.
- GCB-1 is the behavior-preserving SQLite integration baseline. APCC must become
  its only authority-producing commit path; a parallel path is a P0 defect.
- Local commits are authorized. Pushes, pull requests, releases, deployment,
  and publication are out of scope.

## Fixed protocol choices

- Wire format: a strict, separately namespaced APCC canonical JSON profile with
  canonical inner payload bytes and a canonical detached-signature envelope.
  UTF-8, exact ASCII field names, duplicate/unknown/case-variant key rejection,
  NFC input, no lone surrogates, no numbers/bools/nulls, canonical decimal-string
  counters, unpadded base64url, explicit ordering, limits, protocol versions,
  domains, and algorithms are fail-closed requirements. Neither existing GCB
  nor `protocol.py` canonicalization is reused.
- Cryptography: SHA-256 digests and ordinary Ed25519 signatures over explicit
  domain-separated application preimages. The producer, policy/authority
  attestations, and final commit-authority seal have distinct typed roles even
  when a deployment co-locates their keys.
- Stores: the current SQLite realization and PostgreSQL 17+ through synchronous
  Psycopg 3. PostgreSQL admission locks one workflow authority guard before any
  freshness-dependent reads; every commit/control/revocation/recovery mutation
  follows the same guard order. APCC v1 forbids cross-workflow predecessors.
  State, certificate, decision, and outbox intent commit in one transaction.
- Independent verifier: a standalone Go 1.26 program using Go's Ed25519
  implementation and an independently implemented/pinned RFC 8785 canonicalizer.
  It cannot import, invoke, embed, or shell out to the Python producer.
- Current consumability is a certificate-plus-fresh-authority-status judgment.
  A static certificate proves the historical commit; it cannot by itself prove
  that a later revocation has not occurred. APCC v1 therefore requires a
  nonce-bound, per-certificate online status response signed by the status
  authority and bound to store/workflow identity, the certificate digest,
  current epochs/generations, the request nonce, and a short validity interval.
  Snapshot/checkpoint status is deferred until a later version can specify its
  authenticated proof and rollback semantics.

## Required protocol boundary

The public protocol model may depend only on stable typed values, canonical
bytes, cryptographic operations, and abstract authority-store interfaces. It
must not expose SQLite/PostgreSQL row types, scheduler/DAG classes, Python
callbacks, filesystem paths, or repository-specific artifact types.

The atomic commit linearization point jointly covers evidence verification,
policy/authority/revocation/predecessor freshness, state-version fencing,
idempotency and equivocation checks, authoritative state transition, immutable
certificate persistence, and durable outbox intent. Identical replay returns
the original certificate byte-for-byte; conflicting reuse is permanently
recorded and never commits authority.

The final certificate embeds the exact canonical producer, policy, and
authority statement bodies beside their detached signatures and body digests.
The `commit_id` namespace is authority-store-global. Node lifecycle state is
separate from immutable proposal outcomes such as denial or equivocation.

## Dependency-ordered slices

1. Freeze the protocol, threat model, named properties, architecture decisions,
   wire schema, role ownership, state machine, and experiment plan.
2. Capture RED model/codec/verification/state-transition tests, including
   duplicate-key, noncanonical, oversized, unknown-version, tamper, replay, and
   equivocation vectors.
3. Implement immutable storage-independent protocol types, strict codec,
   cryptography, certificate verification, and abstract store/service contracts.
4. Extract the SQLite authority-store realization and route GCB/SwarmExecutor
   through the single APCC commit service without weakening existing semantics.
5. Run the shared conformance suite against real SQLite transactions, including
   multiprocess contention, response loss, crash recovery, revocation, staged
   visibility, predecessor replacement, and outbox replay.
6. Implement the PostgreSQL adapter, schema, serialization/locking rules, and
   bounded retry behavior; run the identical conformance suite against a real
   PostgreSQL service.
7. Generate deterministic positive and negative cross-language vectors, then
   implement the standalone Go verifier and require identical bytes, digests,
   signatures, verdicts, and failure codes.
8. Add the APCC TLA+ safety model, conditional-liveness configuration, and five
   fail-closed non-vacuity witnesses with implementation refinement mappings.
9. Implement fair B0–B6 baselines, adversarial/recovery scenarios, ablations,
   and a frozen benchmark plan before the final measurements.
10. Run attacks, ablations, and benchmarks; retain negative results and bind raw
    results to the recorded environment, seeds, schema, and hashes.
11. Complete primary-source prior-art comparison, seven required reports,
    reproduction tooling, and the artifact manifest.
12. Run four independent review lanes—protocol minimality, formal correctness,
    crypto/conformance, and novelty/experimental validity—then remediate and
    re-review every P0/P1.
13. Run full repository, APCC, both-store, Go, TLA+, attack, recovery, benchmark,
    lint, format, typing, architecture, packaging, and diff checks.
14. Create scoped local commits only after each slice's checks pass. Issue the
    final evidence-bounded classification; do not infer novelty from complexity.

## Required evidence matrix

- Protocol: schemas, state/operation tables, linearization point, failure codes,
  trust roles, extension/version rules, and independently verifiable certificate.
- Stores: one conformance suite and literal real-store executions for SQLite and
  PostgreSQL; no in-memory substitute for critical protocol claims.
- Cross-language: deterministic generator, checked-in positive/negative vectors,
  Python producer/verifier agreement, and standalone Go agreement.
- Formal: safety invariants, conditional-liveness assumptions, bounded state
  counts, five exact witness traces, and Python refinement anchors.
- Empirical: B0–B6 guarantees, fair seeds/workloads, attacks, recovery,
  ablations, latency/throughput/contention/storage metrics, and raw artifacts.
- Research: dated primary sources, closest-system comparison, strongest
  counterargument, invalidating evidence, and an overturning experiment.

## Stop and approval gate

APCC-1 is complete only when all requested deliverables exist, all critical
tests use real authority stores, both implementations agree on every vector,
TLC safety and non-vacuity gates pass, all four independent reviews have no open
P0/P1, and the full local verification matrix passes. The final novelty verdict
must use exactly one allowed classification and may remain `INSUFFICIENT
EVIDENCE` or a systems/protocol contribution if the higher novelty gates fail.
