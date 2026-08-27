# APCC-1 Authority Store Refinement Profiles

## Status

This document is nonnormative. The protocol's normative boundary is the
implementation-neutral atomic authority-linearization primitive in
`APCC-1-Protocol-Spec.md`. The mechanisms below are backend refinements and do
not alter failure precedence, namespace scope, or the single-authority claim.

## SQLite refinement

A SQLite implementation may realize the primitive with one `BEGIN IMMEDIATE`
transaction covering the workflow guard, guarded reads, store-global
`commit_id` and nonce reservations, validation, conditional node transition,
certificate and decision persistence, audit records, and outbox intent. Unique
indexes may enforce global reservations, but constraint timing must preserve
the normative exact-replay/equivocation precedence. The transaction commit is
the durable linearization point. WAL configuration, busy timeouts, connection
ownership, and retry policy are implementation choices that require crash,
response-loss, concurrent-writer, and multiprocess tests.

## PostgreSQL refinement

A PostgreSQL implementation realizes this profile at `READ COMMITTED` with a
locked workflow-authority row (`SELECT ... FOR UPDATE`) and explicit
conditional writes inside one transaction. `SERIALIZABLE` is not an alternate
APCC-1 PostgreSQL profile. Store-global `commit_id` and nonce constraints are
coordinated with that guard without acquiring a second workflow guard, using a
stable lock and reservation order for cross-workflow races. Transaction commit
is the durable linearization point.

An aborted transaction whose server result is known may be retried on SQLSTATE
`40001` (serialization failure) or `40P01` (deadlock detected), within the
documented finite retry bound. SQLSTATE `23505` is not a generic retry signal:
the transaction is rolled back, then the implementation performs an
authoritative reread and classifies the persisted reservation as exact replay,
equivocation, or no durable winner according to protocol precedence.

SQLSTATE `40003` (statement completion unknown), `08007` (transaction
resolution unknown), connection loss with no SQLSTATE, and any other outcome
where commit completion is ambiguous MUST NOT repeat the mutation blindly. The
implementation opens a fresh connection and invokes recovery using the exact
`authority_store_id`, `commit_id`, and `request_digest`. Recovery returns the
persisted immutable result when present; only an authoritative absence permits
a new bounded attempt under the normal guard and reservation order.

## Required refinement evidence

Each backend must demonstrate the same observable contract: at most one node
version winner; authority-store-global commit ID and nonce namespaces; exact
replay and equivocation precedence; workflow-scoped actor revocation; atomic
certificate/decision/audit/outbox writes; failpoint behavior before and after
the linearization point; and response-loss recovery returning the original
bytes and identities. Backend-specific tables, locks, indexes, or SQL text are
not protocol requirements.
