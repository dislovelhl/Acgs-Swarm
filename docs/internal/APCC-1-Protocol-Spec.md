# APCC-1 Atomic Proof-Carrying Commit Protocol

## Status

- Protocol: `APCC-1.0-draft`
- Encoding: `APCC-CJ1`
- Baseline: `6e65db3e478fa315119038b616d78f4f171422db`
- Baseline status: `BASELINE_REMOTE_EVIDENCE_INCOMPLETE`
- Implementation, conformance, formal, and measured evidence: pending

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** use their RFC
2119 meanings. APCC assumes one linearizable authority store; it does not define
multi-store consensus, planner policy, reputation, or key ceremonies.

```text
Authoritative(result) => ValidHistoricalCommitCertificate(result)
Consumable(result, now) =>
  ValidHistoricalCommitCertificate(result) and FreshTrustStatus(result, now)
```

A certificate proves a historical commit. APCC v1 current consumption requires
one nonce-bound, per-certificate `AuthorityStatus`. Snapshot status is reserved
for a future version and is rejected by v1.

## Roles

| Role | Responsibility | Forbidden authority |
|---|---|---|
| Proposer | Names workflow, node, attempt, result, nonce, and stable `commit_id`. | Cannot commit state. |
| Executor | Produces result bytes for one attempt. | Cannot approve its result. |
| Evidence Producer | Assembles signed evidence and predecessor certificates. | Assembly is non-authoritative. |
| Policy Authority | Signs a policy decision and epoch for the proposal digest. | Cannot write node state. |
| Authority Registry | Signs Agent/key authorization and authority context. | Cannot commit a result. |
| Revocation Authority | Advances monotonic actor/workflow generations. | Cannot rewrite history. |
| Commit Verifier | Checks evidence and locked current state. | An out-of-transaction precheck is advisory. |
| Authority Store | Serializes and atomically persists the authoritative transition. | Sole persistence authority. |
| Commit Authority | Seals the final canonical payload. | A pre-commit seal is not authority. |
| Consumer | Verifies result, certificate, and current trust status. | Cannot read staging as authority. |
| Recovery Processor | Replays persisted work and outbox intents. | Cannot manufacture evidence or authority. |
| External Auditor | Verifies historical certificates independently. | Cannot assert freshness without current status. |

## APCC-CJ1 encoding

APCC-CJ1 is a restricted RFC 8785-style profile containing only objects,
arrays, and strings. Numbers, booleans, and `null` are forbidden. Counters and
Unix-millisecond timestamps are decimal strings: `0` or
`[1-9][0-9]{0,15}`, with value at most `9007199254740991`.

Identifiers are 1–128 ASCII bytes matching
`[A-Za-z0-9][A-Za-z0-9._:/-]*`. SHA-256 digests are 43-character unpadded
base64url; Ed25519 signatures are 86 characters; nonces are 16 bytes encoded as
22 characters. Decoded payloads are at most 1 MiB, nesting depth is at most 8,
predecessors at most 4,096.

Strict parsers MUST reject BOMs, invalid UTF-8, lone surrogates, trailing bytes,
non-NFC strings, duplicate/unknown/missing/case-mismatched keys, wrong JSON
types, over-limit input, padded or noncanonical base64url, duplicate set
members, and any value whose canonical re-encoding differs byte-for-byte.
Duplicate names are rejected during tokenization. Existing GCB encoders are not
APCC encoders and MUST NOT be reused.

Objects use RFC 8785 property ordering and string escaping, no whitespace, BOM,
or trailing newline. Semantic sets are sorted by unsigned lexicographic order
of member canonical bytes; other arrays retain schema order. The only
certificate semantic set in v1 is `bindings.predecessors`.

## Cryptography and envelope

SHA-256 hashes exact canonical bytes. Ordinary Ed25519 signs these exact
preimages; Ed25519ph is not used:

```text
ASCII("APCC-PROPOSAL-V1")       || 0x00 || canonical_proposal
ASCII("APCC-POLICY-V1")         || 0x00 || canonical_policy_body
ASCII("APCC-AUTHORITY-V1")      || 0x00 || canonical_authority_body
ASCII("APCC-COMMIT-V1")         || 0x00 || canonical_certificate_payload
ASCII("APCC-AUTHORITY-STATUS-V1") || 0x00 || canonical_authority_status
```

The outer envelope is itself strict APCC-CJ1:

```json
{"envelope_type":"apcc.detached-certificate-envelope","payload_b64u":"<canonical inner bytes>","payload_sha256":"<digest>","seal":{"algorithm":"Ed25519","key_id":"<key>","signature_b64u":"<signature>"}}
```

Verification canonically re-encodes the outer envelope, decodes under the size
limit, canonically re-encodes the inner payload, recomputes the digest, checks
the key binding, and verifies the commit preimage.

`certificate_payload_bytes` are the exact APCC-CJ1 bytes of the seven-object
inner payload. `certificate_digest` is
`B64URL(SHA256(certificate_payload_bytes))`; it equals envelope
`payload_sha256`, is used by predecessor bindings and `AuthorityStatus`, and is
the logical-node pointer value. `certificate_envelope_bytes` are the exact
APCC-CJ1 bytes of the detached outer envelope. They are the portable artifact
returned by `get_certificate` and by commit/replay responses.

The authority store MUST persist both byte strings, or persist the envelope and
make the payload bytes deterministically available by strict base64url decode
without reserialization. Exact replay identity and byte-preservation refer to
`certificate_envelope_bytes`; replay returns those original bytes, not a newly
serialized or newly signed envelope.

## Certificate schema and ownership

The inner payload has exactly seven objects:

| Object | Required fields | Owner |
|---|---|---|
| `header` | `protocol_version`, `certificate_type`, `encoding_profile`, `digest_algorithm`, `signature_algorithm`, `authority_store_id`, `commit_authority_key_id`, `certificate_sequence` | Protocol/store |
| `subject` | `workflow_id`, `node_id`, `attempt_id`, `agent_id`, `actor_authority`, `input_digest`, `output_digest` | Proposer requests; registry attests; store derives/checks |
| `context` | `policy_id`, `policy_version`, `policy_epoch`, `authority_root`, `authority_epoch`, `agent_revocation_generation`, `workflow_revocation_generation`, `workflow_epoch` | Policy/registry/store |
| `evidence` | `producer_statement`, `producer_statement_digest`, `policy_statement`, `policy_statement_digest`, `authority_statement`, `authority_statement_digest` | Signed roles; verifier reconstructs exact bytes |
| `decision` | `outcome`, `reason`, `commit_id`, `nonce`, `committed_at_ms` | Store/commit authority |
| `bindings` | `expected_node_version`, `committed_node_version`, `predecessor_root`, `predecessors` | Proposer/store |
| `signatures` | `producer`, `policy_authority`, `authority_registry` | Typed signing roles |

`header` literals are `APCC-1.0-draft`, `apcc.commit-certificate`, `APCC-CJ1`,
`SHA-256`, and `Ed25519`. Certificate `decision.outcome` is the lowercase wire
literal `committed`; denials are decision records, not certificates. The public
request outcome remains uppercase `COMMITTED`. `committed_node_version` equals
`expected_node_version + 1` numerically.

`actor_authority` has grammar `authority:<namespace>:<capability>`, where each
segment matches `[A-Za-z0-9][A-Za-z0-9._/-]{0,63}`. The proposer requests it,
the registry attests it for the Agent/key and authority epoch, and the store
derives the current registered value under the guard and requires equality.

The certificate embeds every exact signed body beside its detached signature.
Every field below is required and unknown fields fail closed:

| Body | Exact fields |
|---|---|
| `producer_statement` | `protocol_version`, `statement_type`, `producer_key_id`, `workflow_id`, `node_id`, `attempt_id`, `agent_id`, `actor_authority`, `input_digest`, `output_digest`, `predecessor_root`, `expected_node_version`, `commit_id`, `nonce`, `issued_at_ms`, `expires_at_ms` |
| `policy_statement` | `protocol_version`, `statement_type`, `policy_key_id`, `proposal_digest`, `decision`, `policy_id`, `policy_version`, `policy_epoch`, `workflow_id`, `node_id`, `attempt_id`, `issued_at_ms`, `expires_at_ms` |
| `authority_statement` | `protocol_version`, `statement_type`, `authority_key_id`, `proposal_digest`, `agent_id`, `producer_key_id`, `actor_authority`, `authority_root`, `authority_epoch`, `agent_revocation_generation`, `workflow_revocation_generation`, `workflow_epoch`, `workflow_id`, `node_id`, `attempt_id`, `issued_at_ms`, `expires_at_ms` |

Statement types are `apcc.producer-statement`, `apcc.policy-statement`, and
`apcc.authority-statement`; the policy decision is `allow`.
`producer_statement_digest` is SHA-256 of the exact APCC-CJ1 producer body, and
both `proposal_digest` values equal it. The policy and authority body digests
are SHA-256 of their exact APCC-CJ1 bodies. `issued_at_ms < expires_at_ms`.

Each signature object contains exactly `algorithm`, `key_id`, and
`signature_b64u`; its key ID equals its body's key ID. The verifier reconstructs
each embedded body, checks its stored digest, constructs the normative domain
preimage, and verifies the signature. Digest-only references, projections,
omitted fields, and alternative signed schemas are non-conformant.

Each predecessor contains `workflow_id`, `node_id`,
`committed_node_version`, `commit_id`, `certificate_digest`, and
`output_digest`. APCC v1 forbids cross-workflow predecessors and duplicate node
IDs, digests, or canonical members. Database identifiers, paths, runtime
objects, scheduler status, payload bytes, and unsigned annotations are
forbidden. V1 rejects every extension or unknown field.

The predecessor root is exactly:

```text
predecessor_root = B64URL(SHA256(APCC-CJ1(bindings.predecessors)))
```

## Candidate lifecycle, logical-node authority, and certificate disposition

These are three distinct state dimensions.

The non-authoritative candidate lifecycle is:

```text
UNSEEN -> ELIGIBLE -> EXECUTING -> RESULT_STAGED
RESULT_STAGED -> EVIDENCE_ASSEMBLED -> COMMIT_PENDING
any nonterminal candidate -> QUARANTINED on integrity failure
```

The result of processing `COMMIT_PENDING` is orthogonal to this lifecycle. A
successful request consumes the candidate as evidence for the logical-node
authoritative transition and immutable certificate. `DENIED` and `CONFLICTED`
are request outcomes, not candidate or logical-node states. They preserve the
candidate evidence, logical node, and pointer. Exact replay returns the
immutable decision. Corrected evidence creates a new candidate with a new nonce
and, after equivocation, a new store-global `commit_id`.

Each logical node stores `current_node_version` and an optional
`current_certificate_digest`. Initially the version is `0` and the pointer is
absent. A successful first commit or supersession atomically advances `v` to
`v+1` and sets the pointer to the new certificate. Staging, legacy status,
outbox, recovery, denial, and conflict never set or advance this pointer.

Certificate bytes are immutable. A separate append-only disposition log gives
each committed certificate initial disposition `CURRENT` and permits exactly
one terminal disposition event, `SUPERSEDED` or `REVOKED`. Terminal disposition
never returns to `CURRENT`. The effective disposition is derived from this log;
historical bytes and the original commit decision are never rewritten.

### Atomic SupersedeCommit

`SupersedeCommit(old_certificate_digest, new_proposal)` is the only replacement
operation. It uses the same workflow guard and commit algorithm as `Commit`.
Under that guard it MUST verify that:

1. the new proposal's store-global `commit_id` is resolved first. Exact replay
   immediately returns the original `certificate_envelope_bytes`, replacement
   edge, `COMMITTED` decision, and outbox identity without evaluating the old
   pointer, disposition, or version; different request bytes return
   `COMMIT_ID_EQUIVOCATION`;
2. `old_certificate_digest` equals the logical node's current pointer;
3. the old certificate has disposition `CURRENT` and version `v`; and
4. `new_proposal.expected_node_version` equals `v` and passes every ordinary
   APCC evidence, attempt, governance, revocation, and predecessor check.

One transaction then creates a new certificate for version `v+1`, appends the
exact replacement edge `old_certificate_digest -> new_certificate_digest`,
appends terminal `SUPERSEDED` disposition for the old certificate, creates
`CURRENT` disposition for the new certificate, changes the logical-node pointer
and version, persists the request/decision/nonce, and writes one supersession
outbox intent. The transaction commit is the linearization point.

Exact replay returns the same new certificate, edge, decision, and outbox
identity without mutation. A crash before commit leaves the old pointer and
disposition unchanged; a crash after commit is exact-replay recoverable. If the
old digest is not current, its disposition is terminal, the version changed, or
another supersession wins, a non-current old digest returns
`PREDECESSOR_REPLACED`, while an expected-version race returns
`NODE_VERSION_CONFLICT`; neither mutates authority. Different use of the same
`commit_id` remains `COMMIT_ID_EQUIVOCATION`.

Replacement is nonretroactive: a child committed before the supersession keeps
its valid historical binding to the old certificate and is not retroactively
denied or revoked. A pending child whose proposal binds the old certificate
fails `PREDECESSOR_REPLACED` after the pointer changes and must be reproposed
against the new current predecessor.

### Effective revocation

Under the workflow guard, the store computes the authoritative transitive
predicate `EffectiveRevoked(c)` from canonical authority tables only:

```text
EffectiveRevoked(c) =
  DirectCertificateRevoked(c)
  or ActorRevoked(c.agent_id, c.agent_revocation_generation)
  or WorkflowRevoked(c.workflow_id, c.workflow_revocation_generation)
  or exists p in CertificatePredecessorEdges[c]: EffectiveRevoked(p)
```

The canonical inputs are the immutable certificate table, canonical
certificate-predecessor edge table, monotonic actor-revocation table,
workflow-revocation table, and append-only certificate-disposition log. Caches
and projections are non-authoritative. Commit, supersession, and status issuance
evaluate the closure while holding the same workflow guard; cycles or missing
edges quarantine the affected workflow. `SUPERSEDED` alone is not revocation.

An `AuthorityStatus` issued before a revocation may remain usable only through
its signed `next_update_ms` and the consumer's smaller configured maximum
staleness. Revocation does not retroactively alter an already issued signed
status, so the bounded validity interval is an explicit residual-risk window.

## Operations and linearization

`StageResult`, `AssembleEvidence`, `ProposeCommit`, `VerifyProposal`, `Commit`,
`ReplayCommit`, `RejectCommit`, `RevokeAuthority`, `RevokeWorkflowRoot`,
`SupersedeCommit`, `VerifyCertificate`, `RecoverPendingCommit`, `RecoverOutbox`,
and `ConsumeAuthoritativeResult` return typed outcomes and audit event IDs.

Every authority/control mutation MUST:

1. perform only side-effect-free size, UTF-8, canonical schema parsing needed
   to reject malformed wire input and locate `workflow_id` and `commit_id`;
2. begin a write transaction and acquire the workflow authority guard before
   replay resolution or any normative cryptographic, binding, or freshness
   validation (`BEGIN
   IMMEDIATE` for SQLite; workflow-row `SELECT ... FOR UPDATE` for PostgreSQL
   17+);
3. reserve/resolve the store-global `commit_id` through its unique index and
   conflict ledger, then short-circuit exact replay or equivocation;
4. read all state, policy, authority, revocation, predecessor, nonce, staging,
   trust-log, and control versions while holding the guard;
5. perform every normative digest, signature, internal binding, active-state,
   freshness, causality, and transition check under the guard; any advisory
   prevalidation MUST be repeated here;
6. construct and seal the final canonical payload;
7. conditionally advance the node and persist exact certificate bytes, request
   digest, decision, nonce use, evidence references, and one outbox intent; and
8. commit.

The database commit in step 8 is the single successful linearization point. A
crash before it creates no authority; response loss after it is recovered by
exact replay. All PostgreSQL authority and control mutations acquire the same
workflow guard first; validation before the guard is non-conformant.

### Deterministic admission and attempt failures

`ATTEMPT_MISMATCH` means the submitted certificate/proposal objects are
internally inconsistent: two or more embedded subject, producer, policy, or
authority fields name different attempt IDs. `CROSS_ATTEMPT_REPLAY` means all
submitted objects coherently name one attempt, but that attempt is not the
active attempt read from authoritative state under the workflow guard.

Admission reports the first failure in this exact precedence order:

1. side-effect-free wire size, UTF-8, canonical schema, and version parsing;
2. store availability, transaction start, and workflow-guard acquisition;
3. store-global exact replay or `COMMIT_ID_EQUIVOCATION`;
4. static proof validation and cross-object internal binding equality,
   including `ATTEMPT_MISMATCH`;
5. active attempt, node, version, and current predecessor binding, including
   `CROSS_ATTEMPT_REPLAY` and `PREDECESSOR_REPLACED`;
6. policy, authority, workflow, and effective-revocation freshness; and
7. conditional write conflicts.

Implementations MAY record all observed diagnostics internally, but the
wire-visible code is the first code in this order.

`commit_id` is store-global, not workflow-scoped. A global unique index maps it
to one request digest and immutable decision. Same ID/digest returns original
bytes without resigning or duplicate side effects. Different digest appends a
conflict-ledger row containing ID, original/conflicting digests, both claimed
workflows, observation sequence, and audit identity; it returns
`COMMIT_ID_EQUIVOCATION`. Cross-workflow races serialize at the global index and
never acquire two workflow guards. Reused nonce is `NONCE_REPLAY`. Competing
node-version transitions have at most one winner.

## Stable failure codes

| Category | Complete v1 codes |
|---|---|
| Encoding | `MALFORMED_JSON`, `DUPLICATE_FIELD`, `UNKNOWN_FIELD`, `MISSING_FIELD`, `CASE_MISMATCHED_FIELD`, `WRONG_JSON_TYPE`, `INVALID_DECIMAL_STRING`, `TRAILING_BYTES`, `NONCANONICAL_ENCODING`, `INVALID_UNICODE`, `INVALID_BASE64URL`, `SIZE_LIMIT_EXCEEDED`, `DEPTH_LIMIT_EXCEEDED`, `DUPLICATE_SET_MEMBER` |
| Version | `UNKNOWN_PROTOCOL_VERSION`, `UNSUPPORTED_CERTIFICATE_TYPE`, `UNSUPPORTED_ENCODING`, `UNSUPPORTED_DIGEST_ALGORITHM`, `UNSUPPORTED_SIGNATURE_ALGORITHM`, `UNSUPPORTED_STATEMENT_TYPE` |
| Evidence | `STATEMENT_DIGEST_MISMATCH`, `PROPOSAL_DIGEST_MISMATCH`, `INVALID_PRODUCER_SIGNATURE`, `INVALID_POLICY_SIGNATURE`, `INVALID_AUTHORITY_SIGNATURE`, `INVALID_COMMIT_SEAL`, `UNKNOWN_KEY`, `KEY_ID_MISMATCH`, `ATTESTATION_EXPIRED`, `ATTESTATION_NOT_YET_VALID` |
| Binding | `SUBJECT_MISMATCH`, `ACTOR_AUTHORITY_MISMATCH`, `INPUT_DIGEST_MISMATCH`, `OUTPUT_DIGEST_MISMATCH`, `ATTEMPT_MISMATCH`, `CROSS_WORKFLOW_REPLAY`, `CROSS_NODE_REPLAY`, `CROSS_ATTEMPT_REPLAY`, `STALE_POLICY_EPOCH`, `STALE_AUTHORITY_EPOCH`, `STALE_WORKFLOW_EPOCH`, `ACTOR_REVOKED`, `WORKFLOW_REVOKED` |
| Causality/state | `INVALID_PREDECESSOR`, `PREDECESSOR_ROOT_MISMATCH`, `PREDECESSOR_REPLACED`, `CROSS_WORKFLOW_PREDECESSOR`, `NODE_VERSION_CONFLICT`, `ILLEGAL_NODE_STATE`, `RESULT_NOT_STAGED`, `STAGED_RESULT_CONFLICT`, `QUARANTINED` |
| Replay/authority | `NONCE_REPLAY`, `COMMIT_ID_EQUIVOCATION`, `AUTHORITY_FROM_STAGING_DENIED`, `AUTHORITY_FROM_RECOVERY_DENIED`, `AUTHORITY_FROM_OUTBOX_DENIED`, `LEGACY_STATUS_NOT_AUTHORITATIVE` |
| Store/recovery | `STORE_UNAVAILABLE`, `TRANSACTION_ABORTED`, `SERIALIZATION_RETRY_EXHAUSTED`, `OUTBOX_DELIVERY_PENDING` |
| Status | `AUTHORITY_STATUS_REQUIRED`, `AUTHORITY_STATUS_NONCE_MISMATCH`, `AUTHORITY_STATUS_CERTIFICATE_MISMATCH`, `AUTHORITY_STATUS_EXPIRED`, `AUTHORITY_STATUS_INVALID_SIGNATURE`, `AUTHORITY_STATUS_REVOKED`, `AUTHORITY_STATUS_SUPERSEDED`, `AUTHORITY_STATUS_ROLLBACK` |

Every non-transient failure is fail-closed. New wire-visible codes require a
protocol-version revision.

The only public commit-request outcomes are the exact uppercase strings
`COMMITTED`, `DENIED`, and `CONFLICTED`. Exact replay returns the originally
persisted outcome; it is not a fourth outcome. Diagnostic failure codes refine
`DENIED` or `CONFLICTED` without changing these spellings.

## V1 AuthorityStatus

Current consumption requires a nonce-bound per-certificate `AuthorityStatus`.
Its signed APCC-CJ1 body has exactly `protocol_version`, `statement_type`,
`authority_store_id`, `status_key_id`, `request_nonce`, `certificate_digest`,
`certificate_sequence`, `trust_log_sequence`, `trust_log_head`, `status`,
`actor_revocation_generation`, `workflow_revocation_generation`, `superseded`,
`this_update_ms`, and `next_update_ms`. All are strings;
`statement_type=apcc.authority-status`, `status` is `current` or `revoked`, and
`superseded` is `yes` or `no`. The detached signature uses the
`APCC-AUTHORITY-STATUS-V1` preimage.

The consumer supplies an unpredictable 16-byte nonce and requires exact nonce
and certificate-digest equality, trusted status key, `status=current`,
`superseded=no`, matching revocation generations, trusted-clock validity within
`this_update_ms..next_update_ms`, configured maximum staleness, and a trust-log
sequence/head not below the highest previously accepted value. Rollback or
equivocation fails closed. A signature alone is not freshness. TrustSnapshot
objects are forbidden in v1.

Without current status, a verifier may return
`VALID_HISTORICAL_CERTIFICATE` but never `CURRENTLY_CONSUMABLE`.

## Extraction and evidence gate

`src/constitutional_swarm/governed_commit.py` and `specs/governed_commit.tla`
are GCB behavior/refinement baselines, not APCC conformance evidence. APCC must
become the only authority-producing path for GCB and `SwarmExecutor`; a parallel
path is P0. The Go 1.26 verifier is standalone, shares no Python implementation,
and is unrelated to the repository's Rust protocol ADR.

Python/Go vectors, real SQLite/PostgreSQL conformance, APCC TLA+ safety and
non-vacuity, attacks, recovery, and all four reviews remain
`PENDING_IMPLEMENTATION` or `PENDING_EMPIRICAL`. The draft version cannot be
promoted while any such gate or P0/P1 finding remains open. This specification
does not establish novelty.
