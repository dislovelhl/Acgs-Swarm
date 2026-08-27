# GCB-1 — Governed Commit Boundary

## Objective

Establish one SQLite-backed, fail-closed, linearizable authority boundary for the
core `SwarmExecutor` DAG so that no node becomes authoritative, no result becomes
normally visible, and no dependent becomes runnable without a strictly verified,
context-bound GCB v1 receipt.

## Fixed scope and assumptions

- Scope is the core Python DAG runtime. Existing Mesh, JSONL settlement, and
  LangGraph checkpoints remain non-authoritative unless explicitly projected from
  a GCB commit.
- SQLite is the only GCB-1 authority backend. In-memory and JSONL stores are
  projections or audit exports.
- GCB owns policy, authority, agent-revocation, predecessor, and workflow epochs
  at the linearization point until a separately designed cross-system fencing
  protocol exists.
- The legacy `submit(node_id, artifact)` and `TaskDAG.complete_node()` authority
  semantics may break. Missing governed evidence must deny, never emulate the old
  completion behavior.
- Python module privacy and AST gates are engineering controls, not protection
  from an attacker with OS-level access to the SQLite database.
- No dynamic trust, weighted consensus, 1,000-agent scaling, push, PR, or release
  is part of GCB-1.

## Threat model

Attackers may be unregistered, revoked, compromised, stale, replaying, or
colluding agents; race concurrent executors; tamper with receipts, digests,
identity, predecessor roots, epochs, and state versions; invoke public legacy,
retry, recovery, import, compensation, or administrator paths; trigger validator
timeouts/exceptions; crash between persistence steps; or inject stale checkpoints.

GCB-1 must protect authority state against these callers and failures within a
single-host, multi-threaded runtime and process-restart model. It does not claim
protection against a principal able to replace package code or directly modify
the database file outside the process security boundary.

## Implementation slices

1. Capture RED security, visibility, receipt, concurrency, crash, migration, and
   architecture regressions for the known bypass paths.
2. Introduce explicit non-authoritative and authoritative node states plus staged
   artifacts whose public projection remains invisible before commit.
3. Add a GCB v1 canonical Ed25519 receipt profile with full workflow, node,
   attempt, actor, input/output, predecessor, epoch, state-version, and nonce
   binding. Unsigned/report-mode/unknown profiles cannot authorize commits.
4. Add an opaque SQLite governed state store with WAL, `BEGIN IMMEDIATE`, foreign
   keys, busy timeout, immutable decisions, commit journal, and transactional
   outbox. Legacy snapshots cannot import authoritative states.
5. Implement the single public commit command. Within one transaction it jointly
   fences state version, policy, authority, revocation, workflow generation, and
   predecessor bindings; validates the receipt and result; records a stable
   idempotent decision; commits authority state; and queues publication/unlock.
6. Wire `SwarmExecutor` so production creates only staged results before GCB,
   claims verify authority/capability/revocation, and downstream readiness depends
   only on governed-committed predecessors with valid bindings.
7. Route retry, recovery, compensation, manual approval, revocation, and outbox
   replay through governed commands. A revocation fence is immediately effective
   even if descendant materialization is asynchronous.
8. Add AST/static architecture gates proving direct authority writes and direct
   authoritative artifact publication are absent outside the boundary.
9. Add `governed_commit.tla` plus a bounded model covering double commit, response
   loss, validator failure, stale policy/authority/revocation/predecessor epochs,
   propagation crashes, replay, and downstream visibility.
10. Run targeted tests, complete security suite, `make verify`, `make test-all`,
    TLC, then separate bypass-closure and atomicity/protocol reviews.

## Required invariants

- `GovernedCommitted(v)` implies receipt, policy, authority, predecessor, result,
  identity, epoch, state-version, and context validation all succeeded.
- Only the governed commit service can write authoritative node state, committed
  result pointers, and downstream-enablement outbox events.
- Validation and authority commit have one SQLite transaction linearization point.
- Validator timeout, exception, missing configuration, unknown schema/key, and
  persistence error fail closed.
- Identical `commit_id` plus identical canonical request returns the original
  decision; the same id with different context denies as an idempotency conflict.
- Two commit ids racing for one node/state version yield at most one commit.
- Staged or recovered-unverified results are invisible to ordinary reads,
  watchers, and downstream nodes.
- Recovery replays only durable journal/outbox state and never promotes staging.
- Revocation fences future descendant commits according to one serial order.

## Approval gate

GCB-1 is APPROVED only if every requested criterion passes, all P0/P1 findings
are closed, TLC finds no invariant violation, and two independent reviewers
separately confirm bypass closure and transaction/protocol atomicity. Otherwise
the final status is BLOCKED, with runtime integrity remaining RED or YELLOW as
the evidence requires. Algorithmic breakthrough status remains NO-GO in either
case.
