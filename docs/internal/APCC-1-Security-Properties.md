# APCC-1 Security Properties

## Status and notation

These are the named `APCC-1.0-draft` proof obligations. Formal and
implementation evidence is pending; existing GCB tests are regression anchors,
not APCC proof. `BASELINE_REMOTE_EVIDENCE_INCOMPLETE` applies.

Let `Auth(n,v,c)` mean node `n` version `v` is authoritative under certificate
`c`; `Valid(c)` mean static certificate validity; `Current(c,s,t)` mean fresh
authenticated trust status `s` authorizes consumption at time `t`; and
`Lin(op)` denote the store transaction's durable commit.
`CurrentPtr(n)` is the logical node's current certificate digest,
`Disposition(c)` is `CURRENT`, `SUPERSEDED`, or `REVOKED`, and
`EffectiveRevoked(c)` is the guarded transitive revocation closure over
canonical certificate/predecessor and revocation tables.

## Safety

| Property | Obligation |
|---|---|
| `NoUnauthorizedCommit` | `Auth(n,v,c) => Valid(c)` and all signed actor/policy/authority roles match locked state. |
| `NoInvalidReceiptCommit` | Any invalid producer, policy, registry, or commit signature implies no authority transition. |
| `NoStalePolicyCommit` | Certificate policy epoch/version equals the guarded current policy context at `Lin`. |
| `NoStaleAuthorityCommit` | Authority root/epoch and keys equal guarded current authority at `Lin`. |
| `NoRevokedActorCommit` | Actor generation in the request equals guarded current generation and is not revoked at `Lin`. |
| `NoStaleWorkflowCommit` | Workflow epoch and revocation generation are current at `Lin`. |
| `NoInvalidPredecessorCommit` | Every bound predecessor is valid, same-workflow, exact, and currently consumable at `Lin`. |
| `NoCrossAttemptReplay` | A coherent proposal naming an attempt other than the active guarded attempt fails `CROSS_ATTEMPT_REPLAY`; internally inconsistent attempt fields fail earlier as `ATTEMPT_MISMATCH`. |
| `NoCrossWorkflowReplay` | Workflow mismatch, including predecessor import, cannot authorize a transition. |
| `NoCrossNodeReplay` | Node mismatch cannot authorize a transition. |
| `NoAuthorityFromRecovery` | Recovery only returns/retries persisted operations. |
| `NoAuthorityFromStaging` | Staged data alone never satisfies `Auth`. |
| `NoAuthorityFromOutbox` | Publication or delivery state never satisfies `Auth`. |
| `NoAuthorityFromLegacyStatus` | Legacy completion markers never satisfy `Auth`. |

## Consistency and idempotency

| Property | Obligation |
|---|---|
| `AtMostOneAuthoritativeCommitPerNodeVersion` | Competing requests for one `(workflow,node,expected_version)` have at most one successful `Lin`. |
| `CommitIdUniqueness` | One store-global `commit_id` maps to one canonical request digest and immutable decision across all workflows. |
| `CommitIdEquivocationDetection` | Different-digest reuse, including a cross-workflow race, appends the conflict ledger and never mutates authority. |
| `PredecessorCausalConsistency` | A committed child binds the exact committed predecessor set observed under the guard. |
| `CertificateStateConsistency` | Persisted state version, output digest, decision, and certificate agree atomically. |
| `RevocationMonotonicity` | Actor/workflow revocation generations and trust sequences never decrease. |
| `EffectiveRevocationClosure` | Under the workflow guard, direct certificate, actor, or workflow revocation and revoked predecessors imply `EffectiveRevoked`; caches cannot weaken the canonical closure. |
| `DownstreamAuthorityConsistency` | Ordinary consumption requires `Valid(c)` and a nonce/certificate-bound, unexpired, non-rollback v1 `AuthorityStatus`. |
| `ExactReplayPreservesState` | Exact replay causes no state/version change. |
| `ExactReplayPreservesCertificate` | Exact replay returns the original `certificate_envelope_bytes` without reserialization or resigning. |
| `ExactReplayDoesNotDuplicateSideEffects` | Exact replay creates no additional outbox identity or authority event. |
| `ConflictingReplayDoesNotMutateAuthority` | Equivocation records conflict only. |
| `CurrentPointerConsistency` | `CurrentPtr(n)=c` implies `Disposition(c)=CURRENT`, certificate node/version agreement, and no other `CURRENT` certificate for that node. |
| `DispositionMonotonicity` | Each certificate begins `CURRENT` and has at most one terminal `SUPERSEDED` or `REVOKED` event; certificate bytes never change. |
| `AtomicSupersession` | A successful supersession atomically advances `v` to `v+1`, creates the new certificate, old-to-new edge, old/new dispositions, current pointer, decision, nonce, and one outbox intent. |
| `SupersessionReplayPrecedence` | Under the workflow guard, exact replay/equivocation resolves before old-pointer/disposition/version checks, so post-success replay returns the original envelope despite the old certificate no longer being current. |
| `SupersessionNonretroactivity` | Supersession does not invalidate already committed children bound to the old certificate; a pending stale binding fails `PREDECESSOR_REPLACED`. |

## Visibility and recovery

| Property | Obligation |
|---|---|
| `NoStagedResultVisibleToOrdinaryConsumers` | Ordinary APIs return no staged payload or staged-derived authority. |
| `NoDownstreamReadBeforeAuthoritativeCommit` | Consumers cannot read a result before successful `Lin`. |
| `NoRevokedAncestorResultConsumed` | `EffectiveRevoked(c)` is computed from canonical tables under the guard; a certificate or descendant in the closure cannot receive current status. |
| `CrashDoesNotCreateAuthority` | A crash before `Lin` leaves no authoritative transition. |
| `RecoveryDoesNotPromoteUnverifiedState` | Recovery revalidates or returns an existing immutable decision. |
| `OutboxReplayDoesNotDuplicateAuthority` | At-least-once publication may duplicate delivery attempts, never authority identity. |
| `RevocationPropagationIsRecoverable` | Immediate guarded generation fence survives propagation failure; recovery eventually materializes projections. |
| `IssuedStatusHasBoundedResidualValidity` | Status issued before revocation can remain acceptable only until the smaller of signed `next_update_ms` and configured maximum staleness. |

## Conditional liveness

| Property | Assumptions and obligation |
|---|---|
| `ValidStableProposalEventuallyCommits` | With eventual store/key availability, fair scheduling, stable contexts, valid unexpired evidence, no competing winner, and bounded retry, a proposal that remains valid eventually reaches a `COMMITTED` linearization point. |
| `AdmittedProposalEventuallyTerminates` | With eventual store availability, fair request scheduling, terminating validation/key operations, and a finite serialization-retry bound, any admitted request eventually returns exactly `COMMITTED`, `DENIED`, or `CONFLICTED`. It does not assume stable governance or proposal validity and does not imply commit. |
| `IdempotentRetryEventuallyReturnsDecision` | With a persisted decision and eventual store availability, exact retry returns it byte-for-byte. |
| `RevocationEventuallyPropagates` | With fair recovery/outbox service, an immediate generation fence is eventually reflected in derived projections/status. |
| `CommittedCertificateEventuallyBecomesReadable` | With durable commit and eventual read availability, the exact certificate becomes readable. |

No liveness claim holds under continuous reconfiguration, permanent store/key
failure, expired evidence, invalidated predecessors, or an unfair scheduler.

## Formal state and required scenarios

The APCC TLA+ model must include candidate lifecycle, logical-node version and
current pointer, immutable certificate dispositions, exact replacement edges,
and transitive `EffectiveRevoked`, plus two Agents, two attempts, two policy epochs,
two authority epochs, predecessor replacement, revocation before/after
prevalidation, crash before/after commit, response-loss replay, conflicting
`commit_id` reuse, supersession replay/crash/conflict, an already committed
child versus a stale pending child, staging, outbox, status validity windows,
and consumption. It must check every named safety/consistency/visibility/
recovery invariant.

Fail-closed non-vacuity witnesses must show: a valid chain commits; exact replay
returns the same decision; a stale attempt is rejected; revocation blocks later
consumption; and recovery completes without manufacturing authority. TLA+
establishes state-machine properties only, not cryptographic security.

## Implementation refinement map

| Formal boundary | Required implementation evidence | Status |
|---|---|---|
| Guard precedes freshness reads | SQLite `BEGIN IMMEDIATE`; PostgreSQL workflow-row lock; source/static assertion | `PENDING_IMPLEMENTATION` |
| `Lin` atomicity | Faults before/after state, certificate, decision, and outbox writes on real stores | `PENDING_EMPIRICAL` |
| Certificate validity | Embedded exact bodies/digests/signatures and strict Python/Go tamper vectors | `PENDING_IMPLEMENTATION` |
| Replay/equivocation | Both-store concurrent and response-loss tests | GCB baseline only; APCC pending |
| Revocation/current status | Guarded transitive-closure tests plus `AuthorityStatus` nonce, certificate, expiry, generation, and rollback tests | `PENDING_IMPLEMENTATION` |
| Supersession | Both-store atomic edge/pointer/disposition/outbox, replay, response-loss, crash, and conflict tests | `PENDING_IMPLEMENTATION` |
| Portable bytes | Persisted payload/envelope byte comparison, `get_certificate`, exact replay, predecessor/status digest targeting, and Python/Go agreement | `PENDING_IMPLEMENTATION` |
| Causal consistency | Committed-child nonretroactivity and pending-child `PREDECESSOR_REPLACED` tests plus exact witness | GCB baseline only; APCC pending |
| Attempt precedence | Internal mismatch and coherent stale-attempt vectors asserting deterministic failure codes | `PENDING_IMPLEMENTATION` |
| No parallel authority path | Architecture/static scan plus `SwarmExecutor` integration test | `PENDING_IMPLEMENTATION`; any failure is P0 |

Denial and conflict are request outcomes, not node states. They preserve the
prior node state and persist immutable decisions; exact replay returns the same
decision, while corrected evidence uses a new nonce and uses a new global
`commit_id` after equivocation.

`NoInvalidReceiptCommit` includes reconstruction of all embedded producer,
policy, and authority APCC-CJ1 bodies; body-digest equality; issued/expiry
bounds; typed domain separation; and detached-signature validation. Verifying a
projection with fewer fields does not satisfy the property.

Acceptance requires TLC safety, all five witnesses, real-store conformance,
Python/Go agreement, attack/ablation evidence, and no open P0/P1 finding.
