# APCC-1 Prior-Art Evidence Record

> **Current novelty verdict: INSUFFICIENT EVIDENCE**
>
> **Maximum supportable classification ceiling: SYSTEMS ABSTRACTION**
>
> **Research cut-off and source retrieval date: 2026-08-28**

This record does not support a mechanism-level novelty claim for
`APCC-1.0-draft`. At most, the evidence supports evaluating APCC as a systems
abstraction: a particular integration and interface profile assembled from
established authorization, proof, causal-history, status, transaction, and
outbox mechanisms. That ceiling is not itself a positive novelty finding.

This is targeted technical novelty reconnaissance, not a patent search,
freedom-to-operate search, validity opinion, infringement analysis, or legal
patentability opinion. No claim language, jurisdiction, or legally operative
critical date was supplied. Sources published in 2026, especially preprints,
must be date-qualified before they can be treated as prior art for a specific
claim.

## Scope and evidence convention

The frozen APCC conjunction examined here is:

1. independently reconstructible, role-bound proposal, policy, and authority
   statements and signatures;
2. an exact, version-bound workflow/DAG history with predecessor causality;
3. replay-safe *current* authority status, including challenge freshness,
   revocation generation, and a monotone trust-log head; and
4. one authority transaction that durably records the decision, immutable
   certificate, logical pointer, replay identity, and outbox intent as one
   atomic write set.

The comparison uses three controlled terms:

- **Supplied**: the cited source expressly supplies the capability for its own
  protected object and trust model.
- **Partial**: the source supplies a close mechanism, but not APCC's complete
  semantics or trust boundary.
- **Not established**: the reviewed source does not establish the capability.
  This is not a claim that the capability is absent from every implementation
  or could not be added by composition.

Evidence grades are: **N** standards-track standard; **F** official
non-standards-track document; **P** peer-reviewed publication; **T**
institution-hosted technical report; **I** maintained project specification;
**R** public preprint without a verified refereed venue; and **S** official
implementation-pattern documentation.

## Capability matrix

Cells use **S** = supplied, **P** = partial, and **N/E** = not established under
the cited source's stated object and trust model.

| Source/version/grade | Protected object | Commit semantics | Proof/certificate | Policy binding | Authority binding | Predecessor causality | Current status/revocation | Atomicity/linearization | Independent verification | Recovery/replay/outbox | Threat/trust model | Direct APCC overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [CCF, MSR-TR-2019-16](https://www.microsoft.com/en-us/research/publication/ccf-a-framework-for-building-confidential-verifiable-replicated-services/) (**T**) and [IA-CCF, NSDI 2022](https://www.usenix.org/conference/nsdi22/presentation/shamis) (**P**) | Replicated service transaction and ledger state (**S**) | Consensus-committed transaction execution (**S**) | Universally verifiable Merkle receipt and accountability evidence (**S**) | Programmable governance/transaction logic (**P**) | Consortium, service identity, signing keys, governance sub-ledger (**S**) | Ledger order and receipt commitment (**S**) | Governance/key evolution (**P**); APCC challenge status **N/E** | Replicated atomic state-machine execution (**S**) | Offline receipt verification and audit (**S**) | Ledger recovery/audit (**P**); APCC replay/outbox tuple **N/E** | Consortium plus TEEs for CCF; BFT/accountability assumptions for IA-CCF | **Very high**: atomic application state plus committed receipts and governance history |
| [Corda technical whitepaper v0.5](https://corda.net/content/corda-technical-whitepaper.pdf) (**I/T**) | Signed UTXO states and transactions (**S**) | Notary rejects double-spends; one notary per transaction (**S**) | Transaction signatures and contract verification (**S**) | Contract code over input/output states (**S**) | Required signers and notary (**S**) | Input-state transaction dependencies (**S**) | State consumption (**P**); online status receipt **N/E** | Atomic state consumption within a notary domain (**S**) | Parties verify transaction/dependency chain (**S**) | Dependency resolution/flow recovery (**P**); outbox **N/E** | Mutually distrusting parties; deployment-specific notary model | **Very high**: signed causal state transition with commit authority |
| [Hyperledger Fabric, EuroSys 2018](https://doi.org/10.1145/3190508.3190538) (**P**) and [Fabric 2.4 transaction flow](https://hyperledger-fabric.readthedocs.io/en/release-2.4/txflow.html) (**I**) | Endorsed transaction read/write set and channel ledger (**S**) | Execute-order-validate; valid write sets commit (**S**) | Endorser signatures and ledger evidence (**S**) | Endorsement policy (**S**) | Membership service and endorsing peers (**S**) | MVCC read-set versions (**P**) | Membership/configuration evolution (**P**); APCC status **N/E** | Ordered validation and ledger commit (**S**) | Peers validate endorsements/versions (**S**) | Replicated ledger/event delivery (**P**); outbox **N/E** | Permissioned membership and pluggable consensus | **Very high**: policy-endorsed state transition with ordered commit; no APCC current-status certificate/outbox tuple |
| [Theorem-Carrying Transaction 2023](https://arxiv.org/abs/2304.08655v1) and [TCT 2024 v1](https://arxiv.org/abs/2408.06478v1) (**R**) | Smart-contract transaction/safety property (**S**) | Runtime admission before execution (**S**); durable commit supplied by the host blockchain, not TCT (**N/E**) | Transaction-carried theorem (**S**) | Contract/interface safety specification (**S**) | Blockchain/runtime verifier (**P**) | Invoked-contract context (**P**) | **N/E** | Host blockchain transaction semantics only (**P**); TCT-specific atomic durable tuple **N/E** | Runtime proof checking (**S**) | Theorem reuse (**P**) | Blockchain runtime and proof-system assumptions | **High**: proof-carrying admission/runtime verification, not a supplied durable commit mechanism |
| [Proof-Carrying Code](https://doi.org/10.1145/263699.263712) (**P**) and [Proof-Carrying Authorization, TR-638-01](https://www.cs.princeton.edu/techreports/2001/638.pdf) (**T**) | Native-code safety policy or distributed authorization goal (**S**) | Verification before admission/authorization; business commit **N/E** | Machine-checkable safety proof or authorization proof (**S**) | Consumer-defined safety policy or authorization policy/goal (**S**) | PCC consumer and PCA authorization server/policy modules (**S**) | PCA sessions iteratively discharge subgoals (**P**) | Session/challenge state (**P**); APCC current revocation status **N/E** | **N/E** | PCC verification-condition generator and proof validator, or PCA server, verifies supplied proof (**S**) | PCA proof-session continuation (**P**); durable replay/outbox **N/E** | PCC trusts the consumer-defined safety policy, verification-condition generator, proof validator, and execution substrate; the code/proof producer is untrusted. PCA trusts the server and authenticated policy modules, while clients/provers may be untrusted | **High at proof/admission level**; neither supplies APCC's atomic certificate/status/state mutation |
| [Proof-Carrying Data and Hearsay Arguments from Signature Cards](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) (**P**) | Distributed-computation messages and accumulated computation history (**S**) | Recipient verifies each proof-carrying message; durable commit **N/E** | Succinct recursively aggregated proof on every message (**S**); §1.3 also gives a certificate-carrying-key variant (**P**) | Compliance predicate over message data and history (**S**) | Mutually untrusting parties rely on signature cards, or certified per-card verification keys under a trusted CA (**S**) | Proof aggregates the transitive message history (**S**) | Certificate validity is assumed; online revocation/current status **N/E** | **N/E** | Each receiving party verifies the attached proof (**S**) | History is proof-carried (**S**); recovery/outbox **N/E** | Mutually untrusting parties with black-box signature-card functionality; certificate variant additionally trusts a CA | **High for certificate/proof-carrying messages and causal history**; no APCC durable commit or current-status object |
| [Authenticated Workflows, arXiv:2602.10465v1](https://arxiv.org/abs/2602.10465) (2026 preprint, **R**) | Prompt, tool, data, and context crossings (**S**) | Boundary enforcement; durable commit coupling **N/E** | Cryptographic invocation/completion attestations (**S**) | MAPL policy binding (**S**) | Cryptographic identities and PEP/service signatures (**S**) | Authenticated workflow dependencies/context (**S**) | Dynamic context (**P**); APCC revocation generation **N/E** | **N/E** | PEP/downstream verification (**S**) | Context propagation (**P**); replay/outbox tuple **N/E** | Instrumented adapters and protected trust layer | **High**: policy-bound, authenticated workflow attestations |
| [Proof of Execution, arXiv:2607.05397v1](https://arxiv.org/abs/2607.05397) (2026 preprint, **R**) | Governed execution `(contract, trace, replay context)` (**S**) | Precommit sealing/validity predicate (**P**) | Execution Attestation Certificate (**S**) | Contract/authorization context (**S**) | Separated authority planes and signatures (**S**) | Signed causal event stream/DAG (**S**) | Revocation log/EAC state (**S**) | Durable state consensus/transaction **N/E** | Validator-checkable invariants (**S**) | Deterministic replay context (**S**); outbox **N/E** | Cryptography plus exclusive-effector/deployment assumptions | **Very high**: governed action, causal history, replay, revocation, certificate |
| [CommitGuard, arXiv:2607.10487v1](https://arxiv.org/abs/2607.10487) (2026 preprint, **R**) | Durable effect and authority witness (**S**) | Fail-closed check at durability boundary (**S**) | Witness/dependency/binding/eligibility signals (**P**) | Eligibility/effect binding (**S**) | Witness refreshed at commit (**S**) | Causal priority (**S**) | Witness freshness/invalidation (**S**) | **Partial**: only when integrated with a protected transaction, conditional write, lease, ETag, or capability | Monitor-verifiable signals (**P**) | Replan/refuse (**P**); APCC tuple **N/E** | Runtime must emit signals and mediate commit surface | **Very high**: final authorization conditionally coupled to durable effect |
| [SLSA Build Track v1.2](https://slsa.dev/spec/v1.2/) (**I**) | Build artifact and provenance subject (**S**) | Provenance verification before artifact acceptance; application commit **N/E** | Authenticated provenance attestation (**S**) | Build definition, external/internal parameters, dependencies (**S**) | Consumer trusts declared builder identity and accepted signer-builder mapping (**S**) | Resolved dependencies and build inputs (**S**) | Provenance freshness/revocation is verifier policy-dependent (**P**) | **N/E** | Downstream consumer verifies provenance and builder identity (**S**) | Reproducibility/verification aids (**P**); application replay/outbox **N/E** | Trusted build platform is the transitive closure represented by `builder.id`; external parameters remain untrusted inputs | **High for signed subject/provenance/policy binding**; no runtime authority status or atomic business commit |
| [The UCONABC Usage Control Model](https://doi.org/10.1145/984334.984339) (**P**) and [Dennis–Van Horn capabilities](https://publications.csail.mit.edu/lcs/pubs/pdf/MIT-LCS-TR-023.pdf) (**P/T**) | Ongoing use of objects, or protected named objects reached by capabilities (**S**) | UCON permits pre-, ongoing-, and post-use decisions; capabilities authorize operations; business commit **N/E** | Cryptographic proof/certificate **N/E** | Authorizations, obligations, conditions, and capability rights (**S**) | UCON policy decision/enforcement infrastructure; capabilities rely on supervisor/hardware-enforced unforgeability (**S**) | Usage/session evolution (**P**) | UCON continuity and mutable attributes (**S**); APCC signed current-status proof **N/E** | **N/E** | Enforcement is within the trusted reference monitor/supervisor, not an independent portable verifier (**N/E**) | Ongoing-use update (**P**); replay/outbox **N/E** | Trusted UCON enforcement mediates use; classic capability systems trust supervisor/hardware protection and possession of unforgeable references | **High for continuing authorization and delegated object authority**; no APCC proof envelope or atomic record tuple |
| [KeyNote v2](https://www.rfc-editor.org/rfc/rfc2704.html), [CCA](https://www.microsoft.com/en-us/research/publication/code-carrying-authorization/), [WAVE](https://www.usenix.org/conference/usenixsecurity19/presentation/andersen), [Biscuit 3.x](https://doc.biscuitsec.org/reference/specifications), [Zanzibar](https://www.usenix.org/conference/atc19/presentation/pang), [Cedar](https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization) (**F/P/I**) | Authorization request, credential, delegation, relation tuple (**S**) | Authorization decision; business commit **N/E** | Signed credential/proof/token in several systems (**S**) | Expressive policy/request binding (**S**) | Principals, delegation, relations (**S**) | Delegation/causal ACL ordering (**P**) | Ambient revocation/current ACL data (**P**) | Zanzibar external consistency (**P**); application commit **N/E** | Proof/token/policy evaluation (**S**) | APCC tuple **N/E** | Centralized policy through decentralized delegation, source-specific | **High at component level**: role, credential, delegation, policy binding are established |
| [TUF](https://theupdateframework.io/papers/survivable-key-compromise-ccs2010.pdf), [RATS](https://www.rfc-editor.org/rfc/rfc9334.html), [EAT](https://www.rfc-editor.org/rfc/rfc9711.html), [OCSP](https://www.rfc-editor.org/rfc/rfc6960.html) (**P/F/N**) | Update metadata, attestation evidence/result, certificate status (**S**) | Acceptance/update, not business commit (**P**) | Signed metadata/evidence/status (**S**) | Role/threshold/appraisal/status policy (**S**) | Delegated roles, attester/verifier, responder (**S**) | Metadata versions/epochs (**P**) | Revocation, nonce, timestamp, epoch freshness (**S**) | Business write set **N/E** | Client/relying-party verification (**S**) | Rollback/freeze/replay protection (**S**); outbox **N/E** | Explicit key-compromise or attestation/status roles | **High at component level**: current authority/recovery are established |
| [SCITT](https://www.rfc-editor.org/rfc/rfc9943.html), [PeerReview](https://www.sigops.org/s/conferences/sosp/2007/papers/sosp118-haeberlen.pdf), [SUNDR](https://www.usenix.org/conference/osdi-04/secure-untrusted-data-repository-sundr), [in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) (**N/P**) | Signed statements, protocol/file histories, supply-chain steps (**S**) | Registration/log/step acceptance; application commit **N/E** | Receipts, signed logs/histories/link metadata (**S**) | Registration/supply-chain policy (**S/P**) | SCITT issuer and transparency service are separable; source-specific actors (**S**) | Ordered statement/protocol/file/step history (**S**) | New statements/key evolution (**P**); APCC status **N/E** | Log consistency (**P**); business atomicity **N/E** | Relying-party/auditor/client verification (**S**) | Audit/replay/history (**S**); outbox **N/E** | Untrusted log/server or compromised step, source-specific | **High at component level**: verifiable history receipts are established |
| [Event Sourcing](https://martinfowler.com/eaaDev/EventSourcing.html) (**F**, author-source draft) | Application-state changes represented as an ordered event sequence (**S**) | Every state change is captured and persisted as an event; application state is materialized from that log (**S**) | Cryptographic proof/authentication **N/E** | Domain event/application semantics (**P**) | Trusted application and event store (**P**); no cryptographic authority binding | Event application order (**S**) | Corrections may be replayed, but cryptographic revocation/current authority **N/E** | Consistent persistence is an implementation requirement; atomic APCC tuple **N/E** | Independent cryptographic verification **N/E** | Complete rebuild, temporal query, snapshots, crash recovery, and event replay (**S**); outbox **N/E** | Application/event-store operators and stored event sequence are trusted; hostile log tampering is outside the pattern | **High for event-sourced state/materialization/replay**; no cryptographic authenticity or APCC authority certificate |
| [Cryptographic Support for Secure Logs on Untrusted Machines](https://www.schneier.com/wp-content/uploads/2016/02/paper-secure-logs.pdf) (**P**) | Audit-log entries on a compromise-prone machine (**S**) | Append and later tamper detection; event-sourced application-state materialization **N/E** | Ordinary log entries use key-evolving MACs (**S**); per-entry digital signatures **N/E**; §3.2 initialization/authenticated-channel establishment uses U/T signatures and U's certificate (`SIGN_SKU(X0)`, validated certificate/signature, `SIGN_SKT(X1)`) (**S**) | Log-entry types and verification protocol (**P**) | Untrusted logger `U`, trusted machine `T`, and optionally verifier `V` (**S**) | Chained entry state/order (**S**) | Protects entries created before compromise (**S**); APCC authority revocation **N/E** | Append order/checkpoint integrity (**P**); application atomicity **N/E** | Trusted verifier detects alteration/deletion (**S**) | Crash/restart protocol and log verification (**P**); event-sourced state rebuild/outbox **N/E** | Logger may later be compromised; trusted machine/checkpoints and MAC/key-evolution assumptions remain trusted | **High for tamper-evident authenticated audit history**; no event-sourcing commit/materialization semantics or APCC current authority |
| [Linearizability](https://doi.org/10.1145/78969.78972), [C4](https://doi.org/10.1145/3527324), [Raft](https://www.usenix.org/conference/atc14/technical-sessions/presentation/ongaro), [Tendermint](https://arxiv.org/abs/1807.04938) (**P/R**) | Concurrent/transactional object or replicated log (**S**) | Linearization, serialization, consensus (**S**) | Consensus votes/log evidence in some systems (**P**) | **N/E** | Replicas/clients (**P**) | Real-time/history/log order (**S**) | Membership change (**P**) | Atomicity/linearization foundations (**S**) | C4 mechanized proof; protocol verification varies (**S/P**) | Log recovery in implementations (**P**) | Crash/Byzantine assumptions, source-specific | **High at foundation level**: atomicity/order are not new primitives |
| [Weighted Voting for Replicated Data](https://doi.org/10.1145/800215.806583) and [Byzantine Quorum Systems](https://doi.org/10.1007/s004460050050) (**P**) | Replicated data object or Byzantine-replicated service (**S**) | Intersecting read/write quorums or Byzantine quorum operations (**S**) | Votes/authentication are protocol-specific (**P**) | **N/E** | Weighted replicas, or servers with bounded Byzantine faults (**S**) | Version/order and quorum intersection (**S**) | Failure/reconfiguration assumptions (**P**); APCC role revocation **N/E** | Quorum intersection supplies consistency/availability conditions (**S**) | Clients verify quorum responses under the protocol assumptions (**P**) | Replica recovery protocol-dependent (**P**); outbox **N/E** | Gifford assumes inaccessible/crash-prone copies; Malkhi–Reiter additionally tolerates bounded arbitrary Byzantine servers under quorum intersection/availability assumptions | **High for weighted and Byzantine quorum authority/linearization**; no APCC role certificate, policy proof, or atomic outbox tuple |
| [Pinocchio](https://www.microsoft.com/en-us/research/publication/pinocchio-nearly-practical-verifiable-computation/), [authenticated data structures](https://doi.org/10.1007/978-3-540-39658-1_2), [runtime verification](https://fsl.cs.illinois.edu/publications/havelund-rosu-2001-ase.pdf) (**P**) | Computation result, query answer, execution trace (**S**) | Verification before acceptance (**S/P**) | Succinct/authentication proof or monitor verdict (**S**) | Predicate/specification binding (**S**) | Key/source/verifier binding (**P**) | Authenticated path/finite trace (**P**) | **N/E** | Application transaction **N/E** | Independent proof/monitor checking (**S**) | Trace monitoring (**P**); durable replay/outbox **N/E** | Untrusted worker/responder or monitored implementation | **High at proof level**: independent verification is established |
| [Debezium stable Outbox Event Router](https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html) (**S**) | Database row and emitted event (**S**) | Outbox row written with application state (**S/P**) | Event identifier, not cryptographic certificate (**N/E**) | Routing configuration (**P**) | Database/connector trust (**P**) | Deployment-dependent ordering (**P**) | **N/E** | Application transaction supplies state/outbox atomicity (**S**) | Consumer deduplication identifier (**P**) | CDC relay/duplicate handling (**S**) | Trusted database transaction plus connector/transport | **High at implementation level**: transactional outbox is established composition |
| [Before the Tool Call, arXiv:2603.20953v1](https://arxiv.org/abs/2603.20953) (2026 preprint, **R**) | Agent tool call (**S**) | Synchronous pre-action gate; durable coupling **N/E** | Signed audit record (**S**) | Declarative policy (**S**) | OAP identity/specification (**P**) | **N/E** | Policy/current context (**P**) | **N/E** | Audit verification (**P**) | Audit record (**P**); replay/outbox **N/E** | Intercepted tool-call boundary | **High at application level**: OAP is the introduced specification, not the paper title |

## Strongest adverse systems

### CCF and IA-CCF

CCF is not merely an append-only audit log. The 2019 Microsoft report describes
a highly available application data store, replicated execution, programmable
governance, and a universally verifiable ledger. IA-CCF adds succinct,
universally verifiable transaction-execution receipts, signed BFT evidence,
governance-key history, and post-compromise accountability. This is strong
adverse evidence against characterizing “atomic durable state plus independently
verifiable commit receipt” as an APCC primitive. APCC's different certificate,
online-status, and outbox/replay profile is an integration distinction here.

### Corda

Corda v0.5 represents facts as signed states consumed and created by
transactions. Contract code checks the input/output transition; required
parties sign; a notary signs only if input states are unconsumed. Transaction
dependencies form a causal graph that recipients resolve and verify. Corda does
not establish APCC's online status object or exact role certificate, but it is
direct adverse evidence for a signed, policy-checked, causally linked state
transition committed under a designated authority.

### Hyperledger Fabric

Fabric's execute-order-validate path binds proposal execution to signed
endorsements, an application-specific endorsement policy, an ordered ledger,
and MVCC read-version validation before state commitment. Peers independently
validate the policy and versions. Fabric does not establish APCC's portable
certificate/status envelope or transactional outbox, but it directly anticipates
the separation of proposal, policy endorsement, ordering, and final commit.

### Theorem-Carrying Transactions

The 2023 proposal and the pinned 2024 v1 runtime-certification version require a
transaction to carry a theorem proving conformance to contract/interface safety
properties; the runtime checks it before execution and can reuse a proved
theorem. This is an admission/runtime-verification mechanism. Durable commit is
provided, if at all, by the host blockchain and is not a TCT-supplied mechanism.
TCT has a different protected object and no APCC revocation/outbox semantics. It
still defeats any broad claim to introducing a proof-carrying transaction
admitted by an independent runtime verifier.

### Authenticated Workflows

The February 2026 preprint authenticates prompts, tools, data, and context at
workflow boundaries; binds invocations to policies and cryptographic identities;
and produces completion attestations for downstream authenticated context. It
does not establish one atomic application-state/certificate/outbox transaction.
It is direct adverse evidence against broad novelty in cryptographically
authenticated, policy-bound, dependency-aware agent workflows. No legal
prior-art inference follows without a critical-date analysis.

## Other component antecedents and corrections

- **Authorization and delegation:** KeyNote binds signed credentials to action
  attributes; Necula's PCC binds untrusted code to a machine-checkable safety
  proof; Princeton PCA uses client-generated proofs and server challenges over
  distributed policy modules (TR-638-01, pp. 1–6, §§1–3), rather than the later
  Code-Carrying Authorization calculus. PCD places recursively aggregated
  proofs on messages and, in §1.3 (paper p. 314), describes a certificate-based
  variant for per-card verification keys. Code-Carrying Authorization checks
  untrusted authorization code; WAVE supplies cryptographic transitive
  delegation; Biscuit supplies offline attenuation and decentralized
  verification; Zanzibar supplies causally ordered, externally consistent
  authorization checks; Cedar supplies an analyzable authorization language.
  UCON supplies continuing usage decisions and mutable attributes, while
  Dennis–Van Horn capabilities establish supervisor-protected delegated object
  references. None of these sources supplies APCC's complete atomic durable
  certificate/status/outbox tuple.
- **Supply-chain provenance:** SLSA Build Track v1.2 binds an artifact subject
  to authenticated build provenance, builder identity, parameters, and resolved
  dependencies. Its consumer trusts the declared builder platform and accepted
  signing identity; it does not supply APCC runtime authority status or business
  commit atomicity.
- **Revocation and freshness:** TUF supplies delegated roles, versioned metadata,
  rollback/freeze defenses, and survivable key-compromise design. OCSP supplies
  signed certificate status and an optional nonce. RATS and EAT describe
  nonce-, timestamp-, and epoch-based freshness and replay protection.
- **Transparency and accountability:** SCITT separates the statement **Issuer**
  from the **Transparency Service**; the registering client need not be the
  issuer, and a signed statement may be registered with multiple services.
  “Single-issuer signed statement transparency” does not mean the issuer and
  service are one actor. PeerReview, SUNDR, and in-toto supply independently
  checkable signed histories under different trust models. The in-toto source
  used here is the peer-reviewed USENIX Security 2019 paper. Fowler's
  author-source Event Sourcing pattern defines application-state changes as a
  persisted event sequence and identifies complete rebuild, temporal query,
  snapshots, crash recovery, and event replay. It assumes the application and
  event store rather than supplying cryptographic authenticity. Separately,
  Schneier and Kelsey's §§1–4 give the primary tamper-evident secure-log model:
  an untrusted logging machine, trusted checkpoint machine, optional verifier,
  and key-evolving MAC-authenticated records. It does not supply event-sourced
  application-state materialization or commit semantics. **INCOMPLETE — no
  single qualifying primary source located** that supplies both event-sourced
  application-state/commit semantics and cryptographic log authenticity.
- **Verification and consistency:** Pinocchio and authenticated data structures
  establish proof-carrying answers from untrusted computation/storage.
  Havelund-Roșu establishes finite-execution-trace monitoring. Herlihy-Wing
  linearizability and mechanized C4 supply atomicity/serialization foundations;
  Gifford supplies weighted intersecting read/write quorums under inaccessible
  or crash-prone-copy assumptions, while Malkhi–Reiter supplies Byzantine quorum
  systems under bounded arbitrary faults. Raft and Tendermint supply replicated
  ordering under their stated fault assumptions. None binds quorum agreement to
  APCC's exact role/policy/status certificate.
- **Agent systems:** The OAP paper is titled *Before the Tool Call:
  Deterministic Pre-Action Authorization for Autonomous AI Agents*; OAP is its
  introduced specification. PoE binds contract, causal trace, replay, revocation
  state, and certificate. CommitGuard's atomic mechanisms are conditional
  integration choices—transaction, ETag, lease, capability, or conditional
  write—not a universal atomicity guarantee independent of its host.

## Adverse combination matrix

“Residual” identifies a claim-chart question; it is not a finding that the
residual is inventive.

| Combination | Capabilities supplied | Residual APCC-specific question | Adverse assessment |
|---|---|---|---|
| Corda + OCSP/RATS + outbox | Signed causal transaction, notary commit, fresh signed status, atomic event intent | Exact role reconstruction and portable APCC envelope | Strong; predictable systems composition |
| Fabric + CCF receipts + status + outbox | Endorsement policy, MVCC/ordered commit, verifiable receipt, freshness, event relay | Exact authority/status/certificate wire contract | Strong; packaging alone is not inventive |
| TCT + Corda/Fabric | Transaction-carried theorem plus policy-validated durable transition | Role division, challenge status, replay/outbox tuple | Strong proof-carrying-commit theory |
| Authenticated Workflows + CommitGuard | Signed policy dependency chain plus refreshed commit authorization | Portable certificate, queryable status, atomic record tuple | Strong 2026 theory; date qualification mandatory |
| SCITT/CCF + authorization/status/outbox | Signed receipts, auditable history, current authorization, event intent | Private workflow CAS and exact multi-role schema | Strong composition; issuer/service separation preserved |
| PoE + CommitGuard + status + outbox | Causal execution certificate, replay, final refresh, durable publication | Frozen APCC statement/store schema | Closest agent-domain theory; 2026 dates require analysis |
| in-toto + RATS/EAT + database/outbox | Signed workflow steps, freshness/appraisal, atomic state/event persistence | Mutable workflow authority semantics and APCC envelope | Strong cross-domain combination |

## Strongest counterargument

**APCC may be a predictable application composition atop CCF, Corda, or
Hyperledger Fabric, combined with PoE or CommitGuard and established TUF,
SCITT, RATS/EAT, OCSP, and transactional-outbox mechanisms. Packaging those
mechanisms behind one certificate and authority-store API is not, by itself,
inventive.**

The systems-level adverse case is broader than PoE plus CommitGuard. CCF/IA-CCF
couples application execution, replicated state, governance history, and
verifiable receipts. Corda couples signed causal state transitions to a notary
commit. Fabric separates endorsed execution, ordering, policy validation, and
commit. TCT adds a theorem carried by the transaction. PoE and CommitGuard add
agent-specific causal evidence, replay, and a fresh check at durability. The
status, lifecycle, transparency, and publication mechanisms are established.

The only visible APCC distinction is its frozen exact conjunction:
reconstructible role bodies; subject/context/version/attempt bindings;
predecessor root; online status acceptance; and one persisted
certificate/pointer/replay/outbox tuple. No claim chart yet shows this is absent
from all qualifying art, non-obvious to a skilled systems practitioner, or
synergistic rather than expected integration. The verdict is **INSUFFICIENT
EVIDENCE**, with **SYSTEMS ABSTRACTION** as the maximum classification ceiling.

## Search limits and stop condition

This targeted, public, principally English-language review used primary papers,
standards, and official maintained specifications. It did not search patents or
applications, prosecution histories, commercial/closed systems, non-English
material, theses, working-group history, unpublished products, or paywalled
literature. It did not establish an exhaustive history for any 2026 preprint.

Keep the verdict at **INSUFFICIENT EVIDENCE** until there is a critical date,
proposed claim language, archived and hashed sources, full-text claim charts for
CCF/IA-CCF, Corda, Fabric, TCT, Authenticated Workflows, PoE, and CommitGuard,
and a documented non-predictable technical effect from the exact conjunction.

## Appendix A: evidence ledger

All entries were retrieved on **2026-08-28**. No external source artifact was
found in this repository. Unless stated otherwise, the evidence-preservation
field therefore reads **INCOMPLETE — not locally archived / hash not recorded**.
Maintained, unpinned sources additionally say **moving target**. In this ledger,
**INCOMPLETE** covers either evidence-preservation gaps (archive/hash/version)
or claim-location gaps; a topic label without a pinned page or section says
**INCOMPLETE — exact claim location not pinned**. An arXiv DataCite DOI does not
establish peer review.

| ID | Exact title and author/issuer | Grade and identifier | Publication date/version | Relevant pages or sections | Local filename / SHA-256 / archive status |
|---|---|---|---|---|---|
| E01 | *CCF: A Framework for Building Confidential Verifiable Replicated Services* — Mark Russinovich, Edward Ashton, Christine Avanessians, Miguel Castro, Amaury Chamayou, Sylvan Clebsch, Manuel Costa, Cédric Fournet, Matthew Kerner, Sid Krishna, Julien Maffre, Thomas Moscibroda, Kartik Nayak, Olga Ohrimenko, Felix Schuster, Roy Schuster, Alex Shamis, Olga Vrousgou, Christoph M. Wintersteiger | **T**; MSR-TR-2019-16; DOI not recorded | 2019-04 | Ledger, governance, receipts, recovery — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E02 | *IA-CCF: Individual Accountability for Permissioned Ledgers* — Alex Shamis, Peter Pietzuch, Burcu Canakci, Miguel Castro, Cédric Fournet, Edward Ashton, Amaury Chamayou, Sylvan Clebsch, Antoine Delignat-Lavaud, Matthew Kerner, Julien Maffre, Olga Vrousgou, Christoph M. Wintersteiger, Manuel Costa, Mark Russinovich | **P**; NSDI 2022; ISBN 978-1-939133-27-4 | 2022-04 | pp. 467–491; §§1, 3–6 | INCOMPLETE — not locally archived / hash not recorded |
| E03 | *Corda: A distributed ledger* — Mike Hearn | **I/T**; DOI not recorded | 2016-11-29, v0.5 | §§2, 7; transaction, notary, dependency resolution | INCOMPLETE — not locally archived / hash not recorded |
| E04 | *Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains* — Elli Androulaki, Artem Barger, Vita Bortnikov, Christian Cachin, Konstantinos Christidis, Angelo De Caro, David Enyeart, Christopher Ferris, Gennady Laventman, Yacov Manevich, Srinivasan Muralidharan, Chet Murthy, Binh Nguyen, Manish Sethi, Gari Singh, Keith Smith, Alessandro Sorniotti, Chrysoula Stathakopoulou, Marko Vukolić, Sharon Weed Cocco, Jason Yellick | **P**; EuroSys 2018; DOI 10.1145/3190508.3190538 | 2018-04-23 | Article 30, pp. 1–15; §§2–4, execute-order-validate and ledger architecture | INCOMPLETE — not locally archived / hash not recorded |
| E05 | *Transaction Flow* — Hyperledger Fabric project/Linux Foundation | **I**; release 2.4 docs; no DOI | release 2.4, retrieved 2026-08-28 | Steps 1–6, validation and commit | INCOMPLETE — not locally archived / hash not recorded |
| E06 | *An Ethereum-compatible blockchain that explicates and ensures design-level safety properties for smart contracts* — Nikolaj Bjørner, Shuo Chen, Yang Chen, Zhongxin Guo, Peng Liu, Nanqing Luo | **R**; arXiv:2304.08655; DOI 10.48550/arXiv.2304.08655 | 2023-04-17, v1 | Abstract and protocol design — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E07 | *Theorem-Carrying-Transaction: Runtime Certification to Ensure Safety for Smart Contract Transactions* — Nikolaj S. Bjørner, Ashley J. Chen, Shuo Chen, Yang Chen, Zhongxin Guo, Tzu-Han Hsu, Peng Liu, Nanqing Luo | **R**; arXiv:2408.06478v1; DOI 10.48550/arXiv.2408.06478 | 2024-08-12, v1 | pp. 1–2, §1; §4 protocol; runtime proof check before execution and theorem reuse, not durable commit | INCOMPLETE — not locally archived / hash not recorded |
| E08 | *Authenticated Workflows: A Systems Approach to Protecting Agentic AI* — Mohan Rajagopalan, Vinay Rao | **R**; arXiv:2602.10465; DOI 10.48550/arXiv.2602.10465 | 2026-02-11, v1; date-qualified preprint | Protocol, MAPL, attestation, formal results — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E09 | *The KeyNote Trust-Management System Version 2* — Matt Blaze, Joan Feigenbaum, John Ioannidis, Angelos D. Keromytis | **F**; RFC 2704; DOI 10.17487/RFC2704 | 1999-09, Version 2 | §§1, 4–5, 7–8 | INCOMPLETE — not locally archived / hash not recorded |
| E10 | *Code-Carrying Authorization* — Sergio Maffeis, Martín Abadi, Cédric Fournet, Andy Gordon | **P**; ESORICS 2008; DOI not recorded in this review | 2008-10 | Calculus and type-system sections — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E11 | *WAVE: A Decentralized Authorization Framework with Transitive Delegation* — Michael P. Andersen, Sam Kumar, Moustafa AbdelBaky, Gabe Fierro, John Kolb, Hyung-Sin Kim, David E. Culler, Raluca Ada Popa | **P**; USENIX Security 2019; ISBN 978-1-939133-06-9 | 2019-08 | pp. 1375–1392; §§1–4 | INCOMPLETE — not locally archived / hash not recorded |
| E12 | *Biscuit, a bearer token with offline attenuation and decentralized verification* — Eclipse Biscuit project | **I**; format 3.x; no DOI | maintained spec retrieved 2026-08-28 | Semantics, revocation identifiers, cryptography — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded / moving target |
| E13 | *Zanzibar: Google's Consistent, Global Authorization System* — Ruoming Pang, Ramón Cáceres, Mike Burrows, Zhifeng Chen, Pratik Dave, Nathan Germer, Alexander Golynski, Kevin Graney, Nina Kang, Lea Kissner, Jeffrey L. Korn, Abhishek Parmar, Christina D. Richards, Mengzhi Wang | **P**; USENIX ATC 2019; DOI not recorded | 2019-07 | pp. 33–46; consistency and API | INCOMPLETE — not locally archived / hash not recorded |
| E14 | *Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization* — Joseph Cutler, Craig Disselkoen, Aaron Eline, Shaobo He, Kyle Headley, Mike Hicks, Kesha Hietala, Eleftherios Ioannidis, John Kastner, Anwar Mamat, Darin McAdams, Matt McCutchen, Neha Rungta, Emina Torlak, Andrew Wells | **P**; OOPSLA 2024; extended arXiv:2403.04651 | 2024 | Policy semantics, validation, analysis, Lean model — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E15 | *Survivable Key Compromise in Software Update Systems* — Justin Samuel, Nick Mathewson, Justin Cappos, Roger Dingledine | **P**; ACM CCS 2010; proceedings identifier 978-1-4503-0244-9/10/10 | 2010-10 | Trust, delegation, revocation, rollback/freeze — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E16 | *Remote ATtestation procedureS (RATS) Architecture* — Henk Birkholz, Dave Thaler, Michael Richardson, Ned Smith, Wei Pan | **F**; RFC 9334; DOI 10.17487/RFC9334 | 2023-01; Informational | §§3–5, 7–10; freshness | INCOMPLETE — not locally archived / hash not recorded |
| E17 | *The Entity Attestation Token (EAT)* — Laurence Lundblade, Giridhar Mandyam, Jeremy O'Donoghue, Carl Wallace | **N**; RFC 9711; DOI 10.17487/RFC9711 | 2025-04; Proposed Standard | Replay protection, nonce/epoch claims, security considerations — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E18 | *X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP* — Stefan Santesson, Michael Myers, Rich Ankney, Ambarish Malpani, Slava Galperin, Carlisle Adams | **N**; RFC 6960; DOI 10.17487/RFC6960 | 2013-06; Proposed Standard; updated by RFCs 8954 and 9654 | §§2–4 and nonce extension references | INCOMPLETE — not locally archived / hash not recorded |
| E19 | *PeerReview: Practical Accountability for Distributed Systems* — Andreas Haeberlen, Petr Kouznetsov, Peter Druschel | **P**; SOSP 2007; DOI not recorded in this review | 2007-10 | pp. 175–188; signed message histories, auditing, fault evidence | INCOMPLETE — not locally archived / hash not recorded |
| E20 | *Secure Untrusted Data Repository (SUNDR)* — Jinyuan Li, Maxwell Krohn, David Mazières, Dennis Shasha | **P**; OSDI 2004; DOI not recorded | 2004-12 | Protocol, fork consistency, signed operations — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E21 | *In Search of an Understandable Consensus Algorithm* — Diego Ongaro, John Ousterhout | **P**; USENIX ATC 2014; ISBN 978-1-931971-10-2 | 2014-06 | pp. 305–319; §§2, 5–7 | INCOMPLETE — not locally archived / hash not recorded |
| E22 | *The latest gossip on BFT consensus* — Ethan Buchman, Jae Kwon, Zarko Milosevic | **R**; arXiv:1807.04938; DOI 10.48550/arXiv.1807.04938 | 2018-07-13, v1; 2019-11-22, v3 | Tendermint ordering, safety, liveness, fault assumptions — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E23 | *Linearizability: A Correctness Condition for Concurrent Objects* — Maurice Herlihy, Jeannette M. Wing | **P**; ACM TOPLAS 12(3); DOI 10.1145/78969.78972 | 1990-07 | pp. 463–492; histories, sequential specifications, locality | INCOMPLETE — not locally archived / hash not recorded |
| E24 | *C4: Verified Transactional Objects* — Mohsen Lesani, Li-yao Xia, Anders Kaseorg, Christian J. Bell, Adam Chlipala, Benjamin C. Pierce, Steve Zdancewic | **P**; PACMPL 6(OOPSLA1), article 80; DOI 10.1145/3527324 | 2022-04-29 | pp. 1–31; linearizability, serializability, Coq development | INCOMPLETE — not locally archived / hash not recorded |
| E25 | *Pinocchio: Nearly Practical Verifiable Computation* — Bryan Parno, Jon Howell, Craig Gentry, Mariana Raykova | **P**; IEEE Symposium on Security and Privacy 2013; DOI 10.1109/SP.2013.47 | 2013-05 | pp. 238–252; public verifiable computation and toolchain | INCOMPLETE — not locally archived / hash not recorded |
| E26 | *Authenticated Data Structures* — Roberto Tamassia | **P**; ESA 2003, LNCS 2832; DOI 10.1007/978-3-540-39658-1_2 | 2003 | pp. 2–5; source/responder/user model and query proofs | INCOMPLETE — not locally archived / hash not recorded |
| E27 | *Monitoring Programs using Rewriting* — Klaus Havelund, Grigore Roșu | **P**; ASE 2001; DOI not recorded in this review | 2001-05 source record | pp. 135–143; finite-trace LTL monitoring | INCOMPLETE — not locally archived / hash not recorded |
| E28 | *An Architecture for Trustworthy and Transparent Digital Supply Chains* — Henk Birkholz, Antoine Delignat-Lavaud, Cédric Fournet, Yogesh Deshpande, Steve Lasker | **N**; RFC 9943; DOI 10.17487/RFC9943 | 2026-06; Proposed Standard; date-qualified | §§1, 3–6; issuer, registration, transparency service, receipt, relying party | INCOMPLETE — not locally archived / hash not recorded |
| E29 | *Outbox Event Router* — Debezium project | **S**; stable official documentation; no DOI | moving stable documentation retrieved 2026-08-28; example reports 3.6.1.Final | Basic outbox table, event identifier, routing, duplicate removal — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded / moving target |
| E30 | *Proof of Execution: Runtime Verification for Governed AI Agent Actions* — James Rhodes, George Kang | **R**; arXiv:2607.05397; DOI 10.48550/arXiv.2607.05397 | 2026-04-26, v1; date-qualified preprint | pp. 1–14; ECES, replay context, validity predicate, EAC | INCOMPLETE — not locally archived / hash not recorded |
| E31 | *Temporary Authority, Permanent Effects: Commit-Time Authorization for LLM Agents* — Igor Santos-Grueiro | **R**; arXiv:2607.10487; DOI 10.48550/arXiv.2607.10487 | 2026-07-11, v1; date-qualified preprint | pp. 1–20; commit-time authorization and CommitGuard | INCOMPLETE — not locally archived / hash not recorded |
| E32 | *Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents* — Uchi Uchibeke | **R**; arXiv:2603.20953; DOI 10.48550/arXiv.2603.20953; introduced OAP specification DOI 10.5281/zenodo.18901596 | 2026-03-21, v1; date-qualified preprint | Pre-action interception, declarative policy, signed audit record — INCOMPLETE — exact claim location not pinned | INCOMPLETE — not locally archived / hash not recorded |
| E33 | *in-toto: Providing farm-to-table guarantees for bits and bytes* — Santiago Torres-Arias, Hammad Afzali, Trishank Karthik Kuppusamy, Reza Curtmola, Justin Cappos | **P**; USENIX Security 2019; ISBN 978-1-939133-06-9 | 2019-08 | pp. 1393–1410; layout, link metadata, verification, threat model | INCOMPLETE — not locally archived / hash not recorded |
| E34 | *Proof-Carrying Code* — George C. Necula | **P**; POPL 1997; DOI 10.1145/263699.263712 | 1997-01 | pp. 106–119; §§1–4, producer proof and consumer checker | INCOMPLETE — not locally archived / hash not recorded |
| E35 | *A Proof-Carrying Authorization System* — Michael A. Schneider, Edward W. Felten, Lujo Bauer | **T**; Princeton CS-TR-638-01; no DOI | 2001-04 | 16 pp.; pp. 1–6, §§1–3, goals, sessions, distributed policy modules, client proofs/server challenges | INCOMPLETE — not locally archived / hash not recorded |
| E36 | *Proof-Carrying Data and Hearsay Arguments from Signature Cards* — Alessandro Chiesa, Eran Tromer | **P**; ICS 2010; DOI not recorded in this review | 2010-01 | pp. 310–331; §1.1 proof on every message, §1.3 certificate-based key variant, §§2 and 4 formal model | INCOMPLETE — not locally archived / hash not recorded |
| E37 | *Supply-chain Levels for Software Artifacts, Build Track v1.2* — OpenSSF SLSA project | **I**; immutable specification v1.2; no DOI | v1.2, retrieved 2026-08-28 | Build model, Build provenance, `builder.id`, external/internal parameters and resolved dependencies | INCOMPLETE — not locally archived / hash not recorded |
| E38 | *The UCONABC Usage Control Model* — Jaehong Park, Ravi Sandhu | **P**; ACM TISSEC 7(1); DOI 10.1145/984334.984339 | 2004-02 | pp. 128–174; §§2–4, authorizations, obligations, conditions, continuity, mutability | INCOMPLETE — not locally archived / hash not recorded |
| E39 | *Programming Semantics for Multiprogrammed Computations* — Jack B. Dennis, Earl C. Van Horn | **P/T**; MIT MAC-TR-23 and CACM 9(3); DOI 10.1145/365230.365252 | 1966-03 | CACM pp. 143–155; capability/object and supervisor-protection model | INCOMPLETE — not locally archived / hash not recorded |
| E40 | *Cryptographic Support for Secure Logs on Untrusted Machines* — Bruce Schneier, John Kelsey | **P**; 7th USENIX Security Symposium; no DOI recorded | 1998-01 | §§1–4, untrusted machine `U`, trusted machine `T`, verifier `V`, forward-integrity/checkpoint protocol | INCOMPLETE — not locally archived / hash not recorded |
| E41 | *Weighted Voting for Replicated Data* — David K. Gifford | **P**; SOSP 1979; DOI 10.1145/800215.806583 | 1979-12 | pp. 150–162; §§1–4, read/write quorum intersection and version numbers | INCOMPLETE — not locally archived / hash not recorded |
| E42 | *Byzantine Quorum Systems* — Dahlia Malkhi, Michael Reiter | **P**; Distributed Computing 11(4); DOI 10.1007/s004460050050 | 1998-10 | pp. 203–213; §§1–3, Byzantine quorum intersection and availability | INCOMPLETE — not locally archived / hash not recorded |
| E43 | *Event Sourcing* — Martin Fowler | **F**, author-source pattern draft; no DOI | 2005-12-12; maintained author page retrieved 2026-08-28 | Intent; “How it Works”; Complete Rebuild, Temporal Query, Event Replay, snapshots and official system-of-record discussion | INCOMPLETE — not locally archived / hash not recorded / moving target |

## Appendix B: source-status cautions

- Corda v0.5 is an intended-design whitepaper. It explicitly discusses design
  choices that were not necessarily implemented at publication; a claim chart
  must separate the paper's disclosure from deployed-version evidence.
- The Fabric architecture grade is based on the peer-reviewed EuroSys 2018
  paper (DOI 10.1145/3190508.3190538); the project's release 2.4 transaction
  flow remains implementation documentation graded **I**. Neither artifact is
  locally archived or hashed in this repository.
- Biscuit 3.x, Debezium `stable`, and other maintained specifications are moving
  targets. Any later claim chart must pin an immutable version, save the source
  artifact, record its retrieval URL and date, and calculate a local SHA-256.
- Authenticated Workflows, PoE, CommitGuard, and OAP are 2026 v1 preprints in
  this review. Their claims are author claims unless independently reproduced,
  and their legal relevance depends on the critical date and applicable law.
- SCITT RFC 9943 is a 2026 standards-track source. Its statement issuer,
  registering client, and transparency service are separable roles; registration
  proves policy-checked inclusion at registration time, not current APCC
  authority or atomic application-state mutation.
- Every ledger entry currently says **not locally archived / hash not recorded**.
  That is an evidence-preservation gap, not proof that the public source is
  unavailable or inaccurate.
- This record supports technical novelty research only. Patent and
  freedom-to-operate searches require separate claims, dates, jurisdictions,
  classification and citation searching, family/prosecution review, and legal
  analysis.
