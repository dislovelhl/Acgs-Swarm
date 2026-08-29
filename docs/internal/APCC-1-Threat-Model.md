# APCC-1 Threat Model

## Status and protected asset

This threat model applies to `APCC-1.0-draft` and carries
`BASELINE_REMOTE_EVIDENCE_INCOMPLETE`. Implementation and attack evidence are
pending. The protected asset is authoritative Agent-DAG state: a result becomes
authoritative only through a valid atomic APCC commit and becomes consumable
only with valid current trust status.

## Trust boundary

| Category | Assumption or guarantee |
|---|---|
| Protocol | Complete evidence, bindings, freshness, transition, certificate, decision, and outbox intent are one linearizable commit. |
| Storage | One honest linearizable store; durable transactions, uniqueness/CAS, monotonic counters, and workflow guard. |
| Host | Store process, memory, trusted clock, and commit-authority operation are isolated from untrusted runtime components. |
| Cryptography | SHA-256 collision/preimage resistance and Ed25519 EUF-CMA security; private keys remain secret. |
| Operational | Eventual store availability, bounded clock error, current trust-status delivery, retained audit material, and protected backups. |
| Out of scope | Byzantine agreement among stores, compromised host/kernel/DB admin, cryptographic breaks, denial of service, side channels, key ceremony design, malicious application semantics in correctly hashed bytes. |

The trusted computing base is the APCC-CJ1 parser/canonicalizer, cryptographic
verification, commit verifier, commit-authority key use, authority-store
transaction/guard, trust-status signer and rollback state, trusted clock, and
host boundary containing them. SQLite and PostgreSQL engines are in the storage
TCB. The standalone Go verifier is a separate audit TCB, not part of commit
availability.

## Untrusted components

Planner, scheduler, executor, proposer, evidence transport, message broker,
retry handler, result cache, staging store, outbox relay, recovery caller, and
ordinary downstream consumers may be malicious, stale, duplicated, reordered,
or crash arbitrarily. Safety must survive their compromise. They may suppress
progress, so liveness remains conditional.

## Role compromise analysis

| Role compromised | Attacker capability | Required containment and audit evidence |
|---|---|---|
| Proposer/executor | Substitute input/output/identity, replay, equivocate, omit evidence. | Producer signature and store bindings; denial/conflict record. |
| Evidence Producer | Drop/reorder/replace statements. | Strict digest/signature/canonical checks; bundle digest. |
| Policy Authority | Authorize proposals under its active policy scope. | Distinct policy epoch/key, store freshness, signed attestation log. Compromise can authorize policy decisions until revoked. |
| Authority Registry | Authorize keys/actors in its active scope. | Distinct authority epoch/root, revocation, signed registry log. Compromise can mint actor authority until revoked. |
| Revocation Authority | Revoke availability or fail to revoke. | Authenticated monotonic control version and audit log. Compromise affects current trust and liveness. |
| Commit Verifier | Accept invalid evidence. | TCB compromise: safety lost for affected commits; independent verifier can detect but not prevent. |
| Authority Store/host/DB admin | Rewrite, reorder, fork, or fabricate state/certificates. | TCB compromise: APCC guarantees do not hold. External transparency/replication is out of scope. |
| Commit Authority key | Forge historical-looking seals. | TCB compromise until key removal; sequence/log and current status bound exposure but do not undo forgery. |
| Consumer | Attempt staging/legacy reads or ignore revocation. | Authority-read API and certificate/status requirement; a bypassing consumer is outside its own safety boundary. |
| Recovery/outbox caller | Duplicate or forge recovery/publication. | Persisted identities, immutable decisions, idempotent delivery; cannot create authority. |
| External auditor | Misreport verification. | Does not alter authority; reproducible Go/Python conformance provides detection. |

Co-located roles do not erase these effects. Reusing one key across statement
domains is forbidden even when services share a process.

## Adversary actions

The evaluation must cover missing proof, invalid/unknown signatures, input,
output, and identity substitution; cross-node/workflow/attempt replay;
`commit_id` equivocation; policy/authority/actor/workflow revocation races;
predecessor replacement; concurrent double commit; response loss; verifier
crash; transaction/outbox failure; recovery import; legacy promotion; malicious
scheduler/executor/retry caller; stale cache; truncation; duplicate/case/Unicode
and canonicalization ambiguity; unknown version; oversize/depth; duplicate or
reordered predecessors; stale, rolled-back, or incomplete trust status.

The primary failure event is an invalid result becoming authoritative, not
merely absence of a log message. A second failure event is a non-current result
being reported as consumable.

## Security boundaries by phase

- Before the database linearization point, signatures and staging are evidence
  only and create no authority.
- At commit, the workflow guard precedes every freshness read and all state,
  certificate, decision, nonce, and outbox writes commit together.
- After commit, immutable certificate verification establishes history only.
- Current consumption needs the sole v1 freshness object: nonce-bound,
  per-certificate `AuthorityStatus`, checked with a trusted clock, configured
  maximum staleness, and persistent trust-log sequence/head rollback detection.
- Recovery may return an existing decision or retry a transaction. It cannot
  construct missing proof, promote staging, or infer authority from legacy
  status or outbox delivery.

## Availability and liveness assumptions

`ValidStableProposalEventuallyCommits` assumes eventual store availability,
fair transaction scheduling, bounded retry, stable node/policy/authority/
workflow epochs, unexpired evidence, non-revoked principals, available signing
keys, and no permanent predecessor invalidation. Revocation propagation and
certificate readability assume fair recovery/outbox processing. APCC makes no
unconditional liveness claim under a malicious scheduler, unavailable store,
or continuously changing governance context.

## Evidence map

| Threat claim | Evidence required | Status |
|---|---|---|
| Untrusted runtime cannot create authority | B0–B6 attack matrix on real stores | `PENDING_EMPIRICAL` |
| Races are fenced at one linearization point | TLA+ plus SQLite/PostgreSQL contention | `PENDING_FORMAL_AND_EMPIRICAL` |
| Parser ambiguity fails closed | Positive/negative Python/Go vectors | `PENDING_IMPLEMENTATION` |
| Recovery/outbox cannot create authority | Crash injection and non-vacuity trace | GCB baseline only; APCC pending |
| Current status resists stale replay/rollback | `AuthorityStatus` nonce/certificate/expiry/log-head attack tests | `PENDING_IMPLEMENTATION` |

## Signed-statement and global-identity threats

Certificates embed complete canonical producer, policy, and authority bodies,
their body digests, issued/expiry times, and detached signatures. The verifier
reconstructs each exact preimage. Digest-only references, alternate
projections, or omitted fields fail closed. `actor_authority` is
proposer-requested, registry-attested, and store-derived under the guard.

`commit_id` is store-global. A global unique index and append-only conflict
ledger serialize concurrent reuse across workflows without acquiring two
workflow guards. Workflow partitioning therefore cannot conceal equivocation.
Denial/conflict is a request outcome and cannot be mistaken for a node state or
used by recovery to promote authority.

No current evidence extends guarantees beyond the declared host/store TCB, and
no threat-model statement supports an algorithmic-breakthrough claim.
