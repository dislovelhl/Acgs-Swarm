# APCC-1 Prior-Art Reconnaissance

**Status:** internal research record. **Research cut-off:** 2026-08-27.
This is not a novelty, validity, infringement, freedom-to-operate, or patentability
opinion. It records adverse as well as differentiating evidence about the frozen
`APCC-1.0-draft` protocol.

## Scope, critical date, and evidence convention

The APCC conjunction examined here is: (1) independently reconstructible,
role-bound proposal/policy/authority statements and signatures; (2) an exact,
version-bound workflow/DAG history; (3) replay-safe *current* authority status
(challenge nonce, signed freshness, revocation generation, and monotone trust-log
head); and (4) one authority transaction that atomically durably records the
decision, immutable certificate payload/envelope, logical pointer, replay identity,
and outbox intent.

“Missing” means that the reviewed source does not itself establish that complete
conjunction. It does not mean that the source cannot be combined with another
source. “Composition” means assembly of known mechanisms; “mechanism” means a
different primitive, trust boundary, or invariant. Evidence grade: **N** =
standards-track standard; **F** = official standards-body document that is not
standards-track (its category is stated); **P** = peer-reviewed publication;
**T** = institution-hosted technical report; **I** = maintained project
specification; **R** = public preprint or archive record without a verified
refereed venue; **S** = supplemental maintainer-authored implementation-pattern
material.

The applicable legal critical date, claim language, jurisdiction, and qualifying
public-availability rules have not been supplied. Dates below are source publication
or release dates, not findings about legal prior-art status. In particular, a
post-critical-date source cannot by itself anticipate an earlier claim, and a
search result is not proof of an earlier public disclosure.

## Primary-source comparison matrix

| Source, date, grade | Precise supplied property | Missing from the APCC conjunction; difference assessment |
|---|---|---|
| [Proof-carrying code (PCC)](https://doi.org/10.1145/263699.263712) (1997, **P**) and [proof-carrying data (PCD)](https://projects.csail.mit.edu/pcd/) (project publication, 2010, **P**) | PCC has an untrusted producer supply code plus a safety proof, which a host checks before execution. PCD attaches proofs to distributed-computation messages so a verifier can check a specified predicate over that message’s data **and arbitrary computation history**. | Neither supplies a multi-role mutable-workflow certificate, online status/revocation, or an atomic state/certificate/outbox authority transaction. The checkable-proof element is **composition**, not a new APCC mechanism. |
| [Proof-carrying authentication (PCA)](https://doi.org/10.1145/319709.319718) (ACM CCS 1999, **P**) and [PCA implementation report](https://www.cs.princeton.edu/techreports/2001/638.pdf) (2001 Princeton technical report, **T**) | PCA implements distributed authentication in higher-order logic: requester-supplied proofs are simply checked. The implementation uses server challenges, allowing the browser/client to construct proofs responsive to a challenged authorization request. | No frozen role-body wire schema, predecessor root, authority-sealed state change, or APCC status protocol. This is a close authorization antecedent; its challenge/proof flow is adverse evidence against broad “nonce-bound authorization” characterizations. Difference: principally **composition**. |
| [Proof-carrying file system (PCFS)](https://doi.org/10.1109/SP.2010.28) (IEEE S&amp;P 2010, **P**) | PCFS extends proof-carrying authorization with conditional capabilities and policies whose consequences can vary with time and system state. | It is material prior art for conditional, time/state-sensitive authorization, but does not prescribe APCC’s exact certificate/replay/status/store profile. Difference: mostly **composition**. |
| [SPKI/SDSI](https://www.rfc-editor.org/rfc/rfc2693) (RFC 2693 Experimental, 1999, **F**), [X.509](https://www.rfc-editor.org/rfc/rfc5280) (RFC 5280 Standards Track, 2008, **N**), and [Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/) (2014, **P**) | Signed/delegable certificates, chain/path constraints, and attenuable bearer credentials with contextual caveats. | They do not specify producer/policy/authority attempt binding, a workflow predecessor root, or one authority write set. Strong adverse evidence for any claim reduced to revocable signed authorization; remaining profile is **composition**. |
| [in-toto specifications](https://in-toto.io/docs/specs/) (current project specification, retrieved 2026-08-27, **I**) and [SLSA v1.2](https://slsa.dev/spec/v1.2/) (approved 2025-11-24, **I**) | in-toto binds signed supply-chain step metadata, materials/products, and threshold policy. Current SLSA v1.2 defines supply-chain tracks/levels and recommended provenance attestations. | No nonce-bound current authority status or an authority transaction which both changes application workflow state and persists APCC proof/replay/outbox artifacts. Provenance/DAG content is largely **composition**. (Older SLSA v1.0 citations are historical, not current.) |
| [SCITT Architecture, RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) (IETF Standards Track, 2026-06, **N**) and [COSE Receipts, RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) (IETF Standards Track, 2026-06, **N**) | RFC 9943 defines single-issuer signed-statement transparency: a transparency service applies registration policy and returns a receipt; relying parties/auditors can verify registered statements and VDS consistency. RFC 9942 standardizes COSE receipt carriage and VDS-proof parameters. | A transparency receipt proves registration/inclusion, not a private workflow CAS or current per-certificate authorization. These are strong direct antecedents for signed statement/receipt/log constructions, with an APCC difference in application authority semantics and atomic write set—principally **composition**. |
| [RATS Architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) (Informational RFC, 2023-01, **F**) and [EAT, RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) (Standards Track RFC, 2025-04, **N**) | RATS defines attester/verifier/relying-party evidence and appraisal roles, explicitly describing nonce-, timestamp-, and epoch-based freshness and bounded acceptance. EAT requires every use to provide replay protection and names a nonce claim as one option. | These are direct antecedents for challenge freshness, expiry/bounded use, signed appraisal/status, and anti-replay checks. They do not define the APCC workflow graph or atomic business-state authority commit. Difference: a different attested object/trust boundary, not a broad freshness novelty. |
| [Certificate Transparency v2, RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) (2021, **N**) and [Authenticated Append-only Skip Lists](https://arxiv.org/abs/cs/0302010) (2003 CoRR/arXiv record, **R**) | CT provides Merkle inclusion/consistency proofs; AASL commits to sequence contents and order and supports succinct membership/advancement proofs. | Neither supplies decision meaning, private workflow CAS, revocation generation, or atomic business write/outbox. They strongly anticipate transparency/log-head techniques; the APCC use is **composition**. |
| [Git object model](https://git-scm.com/docs/gitcore-tutorial) (maintained documentation, **I**), [CID specification](https://github.com/multiformats/cid) (maintained specification, **I**), and [Merkle-CRDTs](https://arxiv.org/abs/2004.00107) (2020 arXiv record; no refereed venue verified, **R**) | Content digests, immutable Merkle DAGs, and causal/mergeable replicated history. | No authority-selected policy decision, revocation/status check, or all-or-nothing certificate/state/outbox write. APCC predecessor/digest structure is mostly **composition**; its single-authority fence is a different deployment model. |
| [Linearizability](https://doi.org/10.1145/78969.78972) (1990, **P**), [PostgreSQL 17 transaction isolation](https://www.postgresql.org/docs/17/transaction-iso.html) (2024 documentation, **I**), and [Paxos Commit](https://doi.org/10.1145/1073814.1073817) (2005, **P**) | Linearizability is a real-time correctness condition for concurrent objects. PostgreSQL’s Serializable isolation is transactional serializability/conflict control; it is not, merely by that label, a proof of a globally linearizable protocol. Paxos Commit supplies fault-tolerant atomic commit. | None supplies APCC role-proof construction/verification or status semantics. Atomicity and ordering use established **mechanisms**; “transactional commit” alone cannot carry novelty. |
| [PBFT](https://pmg.csail.mit.edu/papers/osdi99.pdf) (OSDI 1999, **P**) and [HotStuff](https://doi.org/10.1145/3293611.3331591) (PODC 2019, **P**) | Byzantine replicated-state-machine safety and chained quorum certificates. | APCC does not itself claim Byzantine replicas/quorum certificates. A future quorum-backed version would be a **composition** with very strong adverse ordering/commit-certificate art. |
| [OCSP, RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) (2013, **N**) | OCSP defines certificate-status requests and issuer-authorized, signed OCSP responses; it has time/status semantics and an optional nonce extension. | Relevant signed revocation/status antecedent, but no workflow/certificate transaction. Do not collapse it into OAuth: OCSP responses are signed status objects. |
| [OAuth 2.0 Token Introspection, RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) (2015, **N**) | A protected TLS endpoint returns authorization-server metadata about whether a token is active. The RFC does not make this a signed, independently portable status receipt. | Relevant online current-status/introspection antecedent, distinct from signed OCSP. No APCC DAG/atomic authority coupling. |
| [Open Policy Agent policy language](https://www.openpolicyagent.org/docs/latest/policy-language/) (maintained documentation, **I**) and [UCONABC](https://doi.org/10.1145/984334.984339) (2003, **P**) | Declarative policy evaluation; UCON models pre-, ongoing-, and post-authorization with obligations/conditions and mutable attributes. | No immutable multi-role proof envelope, independent status receipt, or state/outbox atomicity. Ongoing usage control is adverse evidence against broad “revocation during use” claims; remaining integration is **composition**. |
| [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) (Recommendation, 2013, **N**) | A formal provenance model for entities, activities, agents, and derivations. | No authority decision or atomic durability semantics. APCC causal terminology is **composition**. |
| [Transactional Outbox](https://microservices.io/patterns/data/transactional-outbox.html) (maintainer-authored pattern catalog, retrieved 2026-08-27, **S**) | Store the event/message in the same database transaction as business data and relay later; ordering/duplicate delivery are explicit concerns. | This is useful implementation-pattern evidence, not a normative standard or peer-reviewed primary result. It supplies neither certificate semantics nor independent cryptographic verification; APCC’s outbox coupling is **composition**. |
| [Proof of Execution (PoE)](https://arxiv.org/abs/2607.05397) (public arXiv preprint, 2026, **R**) | PoE presents a content-addressed contract registry; a signed causal execution event stream/DAG; canonical or monotone commit sequencing; precommit sealing; replay context; a revocation log; and execution-authorization context (EAC) states including active, revoked, and suspended. Its validator-checkable execution object binds contract, causal events, and replay context. | This directly overlaps APCC’s governed action/history/replay/revocation side. The reviewed record does not establish the frozen APCC exact statement schema and full durable certificate/state/replay/outbox tuple. The difference remains an unresolved integration-profile question, not an asserted absence or established mechanism novelty. |
| [Temporary Authority, Permanent Effects: Commit-Time Authorization for LLM Agents (CommitGuard)](https://arxiv.org/abs/2607.10487) (submitted 2026-07-11, public arXiv preprint, **R**) | A direct closest mechanism: CommitGuard is a fail-closed boundary monitor which refreshes and checks witness freshness, causal priority, effect binding, and commit eligibility, then couples the final check to the durable effect via `atomic_commit`/conditional write, lease, ETag, capability, or transaction. | It substantially anticipates atomic final authorization checking plus durable effect/conditional write. It does not, on the reviewed preprint description, disclose the complete APCC exact multi-statement certificate, predecessor-root, online status, and replay/outbox profile. The remaining distinction is an unresolved **conjunction**, not a safely asserted new primitive. |
| [CAVA: Canonical Action Verification and Attestation](https://arxiv.org/abs/2607.13716) (public arXiv preprint, 2026-07-15, **R**) | CAVA canonicalizes heterogeneous runtime actions, derives a deterministic canonical-action fingerprint, and binds approvals/receipts to that action identity; it positions itself as an action-semantics layer below PCAA. | Strong adverse evidence for canonical action identity and approval binding. It does not by itself establish APCC’s current-status or atomic authority-store profile. Difference: **composition**/integration. |
| [Proof-Carrying Agent Actions (PCAA)](https://arxiv.org/abs/2606.04104) (public arXiv preprint, 2026-06, **R**) | PCAA describes model-agnostic runtime governance built around portable action certificates, route/review/prove controls, approval receipts, and replay-ready evidence. | Strong direct application-domain antecedent for proof-carrying action receipts. It does not establish the full APCC signed status plus all-or-nothing authority transaction on the available preprint description. Difference: unresolved integration profile. |
| [Open Agent Passport](https://arxiv.org/abs/2603.20953) (public arXiv preprint, 2026-03, **R**) | Pre-action authorization with declarative policy and signed audit records. | It does not establish APCC causal DAG, replay-safe current status, or atomic certificate/state/outbox commitment. It remains a source-specific adverse **composition** reference. |
| [Position: AI Agents Need Authenticated Delegation](https://proceedings.mlr.press/v267/south25a.html) (ICML 2025, **P**) | Authenticated delegation is a recognized agent-security requirement. | It does not prescribe APCC mechanics; it is contextual rather than a complete anticipation, but reinforces that delegation/authentication goals are not new. |

## Strongest adverse theory: PoE plus CommitGuard

The strongest counterargument is not that APCC uses signatures, a DAG, or a database
transaction. **PoE** is a direct source for a content-addressed contract registry, signed
causal execution events, canonical or monotone sequencing, precommit sealing, replay
context, a revocation log, and active/revoked/suspended EAC state. **CommitGuard** is a direct source for a final, fail-closed
authorization check atomically coupled to a durable effect or conditional write. Adding
known signed-status and transactional-outbox constructions can produce a system closely
approaching the four APCC dimensions. The remaining conjunction is unresolved, not
absent from those sources.

That theory is substantial adverse evidence: broad novelty for proof-carrying governed
agent action, causal history, freshness, or atomic authorized effects is unsupported by
this record. The currently visible distinction is only the exact integration profile—such
as fixed reconstructible role bodies, the specified predecessor-root and
subject/context/version/attempt binding, an online status acceptance rule, and a single
persisted certificate/replay/outbox tuple. It is not safe to describe that distinction as
a proven new mechanism. A source-specific claim chart, including the complete PoE and
CommitGuard disclosures rather than abstracts/search snippets, is required before any
narrow conclusion.

## Inference discipline and search limits

The sources disclose the broad component families: proof-carrying code/data and
authorization; conditional/time/state authorization; signed provenance and supply-chain
attestations; online and signed status; nonce freshness and bounded use; authenticated
append-only logs; causal Merkle histories; atomic/conditional commits; and transactional
outbox delivery. Thus this record supports **no broad novelty claim**. It leaves only the
exact APCC conjunction unresolved, pending claim-by-claim comparison to a supplied
critical date and the full disclosures.

This was a targeted public, principally English-language source review. It does not
establish coverage of patents or patent applications, commercial/closed systems,
non-English publications, unpublished products, mailing lists, working-group archives,
theses, or paywalled material. It also does not establish an exhaustive version history
for the 2026 preprints. Terminology is a material risk: *certificate*, *receipt*,
*permit*, *attestation*, *proof of execution*, *commit-time authorization*,
*authorization ledger*, and *transparency service* can describe overlapping systems.
Absence from this record is not evidence of absence.

## Reusable takeaway

Treat APCC as a claim-charting target. Existing work strongly anticipates its broad
ingredients, and PoE plus CommitGuard is the closest adverse integration theory located
here. The remaining question is whether any qualifying source discloses the frozen exact
conjunction—not whether APCC introduced proof, causal history, freshness, or atomic
authorized commitment as general mechanisms.
