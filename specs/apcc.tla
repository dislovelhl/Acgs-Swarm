------------------------------ MODULE apcc ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC
CONSTANT Ablation
Safe == "SAFE"
Nodes == {"n1", "n2", "n3"}
Agents == {"agent1", "agent2"}
\* Bounded scope: three logical nodes, two actors, two attempts, and two epochs.
\* This module has one guarded workflow. apcc_multitenant models authority-store-global
\* commit nonces and actor revocation keyed by (workflow_id, agent_id).
\* Signatures, hashes, and collision resistance are symbolic rather than cryptographic.
Attempts == {"attempt1", "attempt2"}
Candidates == {"p1", "p2", "p3", "p1r", "stale", "denied", "equivocation"}
None == "none"
MaxStaleness == 2
MaxTime == 4
CandidateLifecycle == {"EXECUTING", "RESULT_STAGED",
 "EVIDENCE_ASSEMBLED", "COMMIT_PENDING", "QUARANTINED"}
CandidatePhases == {"UNSEEN", "ELIGIBLE"} \cup CandidateLifecycle
RequestOutcomes == {"NONE", "COMMITTED", "DENIED", "CONFLICTED"}

CandidateNode(c) == CASE c \in {"p1", "p1r"} -> "n1"
 [] c \in {"p2", "denied", "equivocation"} -> "n2"
 [] OTHER -> "n3"
CandidateAgent(c) == IF c \in {"p1", "p1r", "denied"} THEN "agent1" ELSE "agent2"
Attempt(c) == IF c \in {"p1r", "denied"} THEN "attempt2" ELSE "attempt1"
ExpectedVersion(c) == CASE c \in {"p1", "p2", "p3"} -> 0
 [] c = "p1r" -> 1
 [] OTHER -> 1
Pred(c) == CASE c = "p2" -> "p1"
 [] c = "p3" -> "p2"
 [] c \in {"p1r", "stale"} -> "p1"
 [] OTHER -> None
PolicyEpoch(c) == 1
AuthorityEpoch(c) == 1
ActorGeneration(c) == 0
WorkflowEpoch(c) == 1
WorkflowGeneration(c) == 0
Workflow(c) == IF c = "equivocation" THEN "workflow2" ELSE "workflow1"
EvidenceWorkflow(c) == IF c = "equivocation" THEN "workflow1" ELSE Workflow(c)
RequestedNonce(c) == "status-nonce-" \o c
CommitId(c) == IF c \in {"p1", "equivocation"} THEN "shared-commit" ELSE c
Envelope(c) == "envelope-" \o c
OutputDigest(c) == "output-" \o c
DecisionRecord(c, version) == [candidate |-> c, outcome |-> "COMMITTED",
 version |-> version, envelope |-> Envelope(c)]
CertificateRecord(c, version) == [candidate |-> c, node |-> CandidateNode(c),
 version |-> version, decision |-> DecisionRecord(c, version),
 outputDigest |-> OutputDigest(c), workflow |-> Workflow(c)]
SupIds == {"sup-id"}
SupRequest(old, new, id) == [oldDigest |-> old, newRequest |-> new, operationId |-> id]
CanonicalSupRequest == SupRequest("p1", "p1r", "sup-id")
ConflictingSupRequest == SupRequest("p1", "p2", "sup-id")
NoSupRequest == SupRequest(None, None, None)
Parent1(c) == Pred(c)
Parent2(c) == IF Parent1(c) \in Candidates THEN Pred(Parent1(c)) ELSE None
Ancestors(c) == (IF Parent1(c) = None THEN {} ELSE {Parent1(c)}) \cup
 (IF Parent2(c) = None THEN {} ELSE {Parent2(c)})

VARIABLE s
vars == <<s>>
Init == s = [
 life |-> [c \in Candidates |-> "UNSEEN"], outcome |-> [c \in Candidates |-> "NONE"],
 attempt |-> [n \in Nodes |-> "attempt1"], policy |-> 1, authority |-> 1,
 version |-> [n \in Nodes |-> 0], ptr |-> [n \in Nodes |-> None],
 disp |-> [c \in Candidates |-> "ABSENT"], certver |-> [c \in Candidates |-> 0],
 certpred |-> [c \in Candidates |-> None], certPolicy |-> [c \in Candidates |-> 0],
 certAuthority |-> [c \in Candidates |-> 0], certActorGen |-> [c \in Candidates |-> 0],
 certWorkflowGen |-> [c \in Candidates |-> 0],
 certWorkflow |-> [c \in Candidates |-> None], certOutput |-> [c \in Candidates |-> None],
 certificateSequence |-> [c \in Candidates |-> 0],
 decisionRecord |-> [c \in Candidates |-> None],
 certificateRecord |-> [c \in Candidates |-> None],
 owner |-> [id \in {CommitId(c) : c \in Candidates} |-> None],
 commitNonceOwner |-> [nonce \in {RequestedNonce(c) : c \in Candidates} |-> None],
 pre |-> [c \in Candidates |-> None], linHistory |-> {}, replayHistory |-> {},
 conflictHistory |-> {}, conflicts |-> {}, staged |-> {}, outbox |-> {}, delivered |-> {},
 events |-> 0, readable |-> {}, SupersessionEdge |-> {}, dispHistory |-> {},
 supOwner |-> [id \in SupIds |-> NoSupRequest], supDecision |-> [id \in SupIds |-> None],
 supReplay |-> {}, supConflicts |-> {}, supConflictHistory |-> {}, supHistory |-> {},
 directRevoked |-> {}, actorRevoked |-> {}, workflowRevoked |-> FALSE,
 actorGen |-> [a \in Agents |-> 0], workflowGen |-> 0, trustSeq |-> 0,
 revocationHistory |-> {}, propagationPending |-> {}, propagationDone |-> {},
 recoveryHistory |-> {}, rejectReason |-> [c \in Candidates |-> None], now |-> 0,
 authorizationValid |-> [c \in Candidates |-> TRUE],
 receiptValid |-> [c \in Candidates |-> TRUE],
 certAuthorized |-> [c \in Candidates |-> FALSE],
 certReceiptValid |-> [c \in Candidates |-> FALSE], staleHistory |-> <<>>,
 status |-> {}, statusIssued |-> [c \in Candidates |-> 0],
 statusNext |-> [c \in Candidates |-> 0], nonceBound |-> {}, consumed |-> {}, blocked |-> FALSE,
 statusCertificate |-> [c \in Candidates |-> None],
 statusCertificateSequence |-> [c \in Candidates |-> 0],
 statusNonce |-> [c \in Candidates |-> None],
 statusActorGeneration |-> [c \in Candidates |-> 0],
 statusWorkflowGeneration |-> [c \in Candidates |-> 0],
 statusTrustSeq |-> [c \in Candidates |-> 0],
 statusTrustHead |-> [c \in Candidates |-> None],
 statusTrustGeneration |-> [c \in Candidates |-> 0],
 statusSignerRole |-> [c \in Candidates |-> None],
 statusSignerTrusted |-> [c \in Candidates |-> FALSE],
 statusChecks |-> {}, blockedStatus |-> {}, consumptionHistory |-> {},
 observedTrustSeq |-> 0, observedTrustHead |-> "head-0", observedTrustGeneration |-> 0,
 legacyCompletion |-> {}, legacyStatus |-> {}, legacyAuth |-> {},
 legacyConsumed |-> {}, legacyHistory |-> {},
 crashedBefore |-> {}, crashedAfter |-> {}, responseLost |-> {}, recovered |-> {}]

Terminal(c) == s.outcome[c] # "NONE" \/ s.life[c] = "QUARANTINED"
Settled(c) == Terminal(c) /\
 (s.outcome[c] # "COMMITTED" \/ (c \in s.readable /\ c \in s.delivered))
AdmissionAllowed(c) == CASE c = "p1" -> TRUE
 [] c = "p2" -> Settled("p1") /\
      (s.outcome["p1"] # "COMMITTED" \/ s.replayHistory # {})
 [] c = "p3" -> Settled("p2")
 [] c = "stale" -> Settled("p3")
 [] c = "p1r" -> Settled("p3") /\
      s.life["stale"] \in {"COMMIT_PENDING", "QUARANTINED"}
 [] c = "denied" -> Settled("p1r") /\
      (s.outcome["p1r"] # "COMMITTED" \/
       ("p1r" \in s.recovered /\ s.supReplay # {} /\ s.supConflicts # {}))
 [] c = "equivocation" -> Settled("denied")
AllTerminal == \A c \in Candidates : Terminal(c)
Admit(c) == /\ AdmissionAllowed(c) /\ s.life[c] = "UNSEEN"
 /\ s' = [s EXCEPT !.life[c] = "ELIGIBLE"]
Begin(c) == /\ s.life[c] = "ELIGIBLE" /\ s' = [s EXCEPT !.life[c] = "EXECUTING"]
Stage(c) == /\ s.life[c] = "EXECUTING"
 /\ s' = [s EXCEPT !.life[c] = "RESULT_STAGED", !.staged = @ \cup {c}]
Assemble(c) == /\ s.life[c] = "RESULT_STAGED"
 /\ s' = [s EXCEPT !.life[c] = "EVIDENCE_ASSEMBLED"]

PredCurrent(c) == IF Pred(c) = None THEN TRUE ELSE s.disp[Pred(c)] = "CURRENT"
DirectOrAncestorRevoked(c) == ({c} \cup Ancestors(c)) \cap s.directRevoked # {}
ActorOrAncestorRevoked(c) == \E x \in ({c} \cup Ancestors(c)) : CandidateAgent(x) \in s.actorRevoked
EffectiveRevoked(c) == DirectOrAncestorRevoked(c) \/ ActorOrAncestorRevoked(c) \/ s.workflowRevoked
ContextExceptAttempt(c) ==
 /\ PolicyEpoch(c) = s.policy /\ AuthorityEpoch(c) = s.authority
 /\ ExpectedVersion(c) = s.version[CandidateNode(c)] /\ PredCurrent(c)
 /\ ~EffectiveRevoked(c) /\ Workflow(c) = EvidenceWorkflow(c)
 /\ ActorGeneration(c) = s.actorGen[CandidateAgent(c)]
 /\ WorkflowEpoch(c) = 1 /\ WorkflowGeneration(c) = s.workflowGen
CurrentContextValid(c) ==
 /\ (Ablation = "ATTEMPT_GUARD" \/ Attempt(c) = s.attempt[CandidateNode(c)])
 /\ ContextExceptAttempt(c)
 /\ (Ablation = "AUTHORIZATION_EVIDENCE" \/ s.authorizationValid[c])
 /\ (Ablation = "RECEIPT_EVIDENCE" \/ s.receiptValid[c])
Snapshot(c) == [attempt |-> s.attempt[CandidateNode(c)], policy |-> s.policy,
 authority |-> s.authority, version |-> s.version[CandidateNode(c)],
 predecessor |-> Pred(c), predecessorCurrent |-> PredCurrent(c),
 actorGen |-> s.actorGen[CandidateAgent(c)], workflowGen |-> s.workflowGen,
 trustSeq |-> s.trustSeq, capturedAt |-> s.now]
Prepare(c) == /\ s.life[c] = "EVIDENCE_ASSEMBLED"
 /\ (c # "stale" \/ (s.outcome["p3"] = "COMMITTED" /\ PredCurrent(c)))
 /\ s' = [s EXCEPT !.life[c] = "COMMIT_PENDING", !.pre[c] = Snapshot(c),
      !.staleHistory = IF c = "stale"
       THEN Append(@, "PREVALIDATED_CURRENT") ELSE @]
InvalidateAuthorization(c) == /\ c = "p2" /\ s.life[c] = "COMMIT_PENDING"
 /\ s.outcome[c] = "NONE"
 /\ s.authorizationValid[c]
 /\ s' = [s EXCEPT !.authorizationValid[c] = FALSE]
InvalidateReceipt(c) == /\ c = "p2" /\ s.life[c] = "COMMIT_PENDING"
 /\ s.outcome[c] = "NONE"
 /\ s.receiptValid[c]
 /\ s' = [s EXCEPT !.receiptValid[c] = FALSE]
Quarantine(c) == /\ (~s.authorizationValid[c] \/ ~s.receiptValid[c] \/
                     (c = "stale" /\
                      (s.outcome["p3"] # "COMMITTED" \/ ~PredCurrent(c) \/
                       (Terminal("p1r") /\ s.outcome["p1r"] # "COMMITTED"))))
 /\ s.life[c] \in {"ELIGIBLE", "EXECUTING", "RESULT_STAGED", "EVIDENCE_ASSEMBLED", "COMMIT_PENDING"}
 /\ s.outcome[c] = "NONE"
 /\ s' = [s EXCEPT !.life[c] = "QUARANTINED"]
PreSnapshotValid(c) == s.pre[c].attempt = Attempt(c) /\
 s.pre[c].policy = PolicyEpoch(c) /\ s.pre[c].authority = AuthorityEpoch(c) /\
 s.pre[c].version = ExpectedVersion(c) /\ s.pre[c].predecessorCurrent
CommitContextValid(c) == IF Ablation = "GUARD_REREAD"
 THEN PreSnapshotValid(c) /\ s.authorizationValid[c] /\ s.receiptValid[c] /\
      Workflow(c) = EvidenceWorkflow(c)
 ELSE CurrentContextValid(c)

LinRecord(c) == <<c, s.version[CandidateNode(c)], s.policy, s.authority,
 s.actorGen[CandidateAgent(c)], s.workflowGen, s.trustSeq, Pred(c),
 (IF Pred(c) = None THEN None ELSE s.disp[Pred(c)]),
 Attempt(c), s.attempt[CandidateNode(c)]>>
AtomicCommit(c) == LET n == CandidateNode(c) IN
 /\ c # "p1r" /\ s.life[c] = "COMMIT_PENDING" /\ s.outcome[c] = "NONE"
 /\ CommitContextValid(c)
 /\ s.owner[CommitId(c)] = None /\ s.commitNonceOwner[RequestedNonce(c)] = None
 /\ c \notin s.crashedBefore
 /\ s' = [s EXCEPT !.outcome[c] = "COMMITTED",
  !.version[n] = @ + 1, !.attempt[n] = (IF c = "p1" THEN "attempt2" ELSE @),
  !.disp[c] = "CURRENT", !.dispHistory = @ \cup {<<c, "ABSENT", "CURRENT">>},
  !.certver[c] = s.version[n] + 1, !.certpred[c] = Pred(c),
  !.certPolicy[c] = s.policy, !.certAuthority[c] = s.authority,
  !.certActorGen[c] = s.actorGen[CandidateAgent(c)], !.certWorkflowGen[c] = s.workflowGen,
  !.certWorkflow[c] = Workflow(c), !.certOutput[c] = OutputDigest(c),
  !.certificateSequence[c] = s.events + 1,
  !.decisionRecord[c] = DecisionRecord(c, s.version[n] + 1),
  !.certificateRecord[c] = CertificateRecord(c, s.version[n] + 1),
  !.certAuthorized[c] = s.authorizationValid[c],
  !.certReceiptValid[c] = s.receiptValid[c],
  !.owner[CommitId(c)] = c, !.ptr[n] = c, !.linHistory = @ \cup {LinRecord(c)},
  !.commitNonceOwner[RequestedNonce(c)] = c,
  !.outbox = @ \cup {c}, !.events = @ + 1]
RejectReason(c) == IF ~PredCurrent(c) THEN "PREDECESSOR_REPLACED"
 ELSE IF Attempt(c) # s.attempt[CandidateNode(c)] THEN "CROSS_ATTEMPT_REPLAY"
 ELSE IF ~s.authorizationValid[c] THEN "UNAUTHORIZED"
 ELSE IF ~s.receiptValid[c] THEN "INVALID_RECEIPT"
 ELSE IF PolicyEpoch(c) # s.policy THEN "STALE_POLICY"
 ELSE IF AuthorityEpoch(c) # s.authority THEN "STALE_AUTHORITY"
 ELSE IF EffectiveRevoked(c) THEN "REVOKED"
 ELSE "INVALID_CONTEXT"
Reject(c) == /\ s.life[c] = "COMMIT_PENDING" /\ s.outcome[c] = "NONE"
 /\ ~CommitContextValid(c)
 /\ s' = [s EXCEPT !.outcome[c] = "DENIED",
  !.rejectReason[c] = RejectReason(c),
  !.staleHistory = IF c = "stale" /\ RejectReason(c) = "PREDECESSOR_REPLACED"
   THEN Append(@, "GUARDED_REJECT_PREDECESSOR_REPLACED") ELSE @]
ExactReplay(c) == /\ c = "p1" /\ s.owner[CommitId(c)] = c
 /\ s' = [s EXCEPT !.replayHistory = @ \cup
  {<<c, s.version[CandidateNode(c)], s.version[CandidateNode(c)],
     s.ptr[CandidateNode(c)], s.ptr[CandidateNode(c)], s.events, s.events,
     s.outbox, s.outbox, Envelope(c)>>}, !.readable = @ \cup {c}]
Equivocation(c) == /\ s.life[c] = "COMMIT_PENDING"
 /\ s.outcome[c] = "NONE"
 /\ s.owner[CommitId(c)] \notin {None, c}
 /\ s' = [s EXCEPT !.outcome[c] = "CONFLICTED",
  !.conflicts = @ \cup {c}, !.conflictHistory = @ \cup
   {<<c, s.version, s.version, s.ptr, s.ptr, s.events, s.events, s.outbox, s.outbox>>}]
AuthorityGuard(c) == IF s.owner[CommitId(c)] = c THEN ExactReplay(c)
 ELSE IF s.owner[CommitId(c)] # None THEN Equivocation(c)
 ELSE IF s.life[c] = "COMMIT_PENDING" /\ ~CommitContextValid(c) THEN Reject(c)
 ELSE AtomicCommit(c)

SupExactReplay(request) == /\ s.supOwner[request.operationId] = request
 /\ s' = [s EXCEPT !.supReplay = @ \cup
  {<<request, s.version, s.version, s.ptr, s.ptr, s.events, s.events,
     s.outbox, s.outbox, Envelope(request.newRequest)>>},
  !.readable = @ \cup {request.newRequest}]
SupEquivocation(request) == /\ s.supOwner[request.operationId] \notin {NoSupRequest, request}
 /\ s' = [s EXCEPT !.supConflicts = @ \cup {request},
  !.supConflictHistory = @ \cup
   {<<request, s.version, s.version, s.ptr, s.ptr, s.events, s.events, s.outbox, s.outbox>>}]
AtomicSupersede(request) == LET old == request.oldDigest IN LET new == request.newRequest IN
 LET n == CandidateNode(new) IN
 /\ request = CanonicalSupRequest /\ s.life[new] = "COMMIT_PENDING" /\ s.outcome[new] = "NONE"
 /\ s.ptr[n] = old /\ s.disp[old] = "CURRENT" /\ CommitContextValid(new)
 /\ s.commitNonceOwner[RequestedNonce(new)] = None
 /\ new \notin s.crashedBefore
 /\ s' = [s EXCEPT !.outcome[new] = "COMMITTED",
  !.version[n] = @ + 1,
  !.disp = [@ EXCEPT ![new] = "CURRENT", ![old] = "SUPERSEDED"],
  !.dispHistory = @ \cup {<<old, "CURRENT", "SUPERSEDED">>, <<new, "ABSENT", "CURRENT">>},
  !.certver[new] = s.version[n] + 1, !.certpred[new] = Pred(new),
  !.certpred["p3"] = (IF Ablation = "SUPERSESSION_RETROACTIVE" THEN new ELSE @),
  !.certPolicy[new] = s.policy, !.certAuthority[new] = s.authority,
  !.certActorGen[new] = s.actorGen[CandidateAgent(new)], !.certWorkflowGen[new] = s.workflowGen,
  !.certWorkflow[new] = Workflow(new), !.certOutput[new] = OutputDigest(new),
  !.certificateSequence[new] = s.events + 1,
  !.decisionRecord[new] = DecisionRecord(new, s.version[n] + 1),
  !.certificateRecord[new] = CertificateRecord(new, s.version[n] + 1),
  !.certAuthorized[new] = s.authorizationValid[new],
  !.certReceiptValid[new] = s.receiptValid[new],
  !.owner[CommitId(new)] = new, !.ptr[n] = new,
  !.commitNonceOwner[RequestedNonce(new)] = new,
  !.linHistory = @ \cup {LinRecord(new)}, !.outbox = @ \cup {new}, !.events = @ + 1,
  !.SupersessionEdge = (IF Ablation = "SUPERSESSION_EDGE" THEN @ ELSE @ \cup {<<old, new>>}),
  !.supOwner[request.operationId] = request, !.supDecision[request.operationId] = Envelope(new),
  !.staleHistory = IF s.life["stale"] = "COMMIT_PENDING" /\
      s.pre["stale"].predecessor = old /\ s.pre["stale"].predecessorCurrent
    THEN Append(@, "PREDECESSOR_SUPERSEDED") ELSE @,
  !.supHistory = @ \cup {[
    request |-> request, node |-> n,
    versionBefore |-> s.version[n], versionAfter |-> s.version[n] + 1,
    ptrBefore |-> s.ptr[n], ptrAfter |-> new,
    old |-> old, new |-> new,
    oldDispBefore |-> s.disp[old], oldDispAfter |-> "SUPERSEDED",
    newDispBefore |-> s.disp[new], newDispAfter |-> "CURRENT",
    ownerBefore |-> s.owner[CommitId(new)], ownerAfter |-> new,
    nonce |-> RequestedNonce(new),
    nonceOwnerBefore |-> s.commitNonceOwner[RequestedNonce(new)],
    nonceOwnerAfter |-> new,
    decisionAfter |-> Envelope(new),
    outboxBefore |-> s.outbox, outboxAfter |-> s.outbox \cup {new},
    edgeBefore |-> s.SupersessionEdge,
    edgeAfter |-> (IF Ablation = "SUPERSESSION_EDGE" THEN s.SupersessionEdge
                  ELSE s.SupersessionEdge \cup {<<old, new>>}),
    eventsBefore |-> s.events, eventsAfter |-> s.events + 1,
    committedChildren |-> {c \in Candidates : s.outcome[c] = "COMMITTED" /\ old \in Ancestors(c)},
    certpredBefore |-> s.certpred]}]
SupersessionGuard(request) == IF s.supOwner[request.operationId] = request
 THEN SupExactReplay(request)
 ELSE IF s.supOwner[request.operationId] # NoSupRequest THEN SupEquivocation(request)
 ELSE IF request = CanonicalSupRequest /\ s.life[request.newRequest] = "COMMIT_PENDING" /\
  ~(s.ptr[CandidateNode(request.newRequest)] = request.oldDigest /\
    s.disp[request.oldDigest] = "CURRENT" /\ CommitContextValid(request.newRequest))
 THEN Reject(request.newRequest)
 ELSE AtomicSupersede(request)
ConflictingSupersession == SupEquivocation(ConflictingSupRequest)

CrashBefore(c) == /\ c \in {"p1", "p1r"} /\ s.life[c] = "COMMIT_PENDING"
 /\ s.outcome[c] = "NONE"
 /\ s' = [s EXCEPT !.crashedBefore = @ \cup {c}]
RecoverBefore(c) == /\ c \in s.crashedBefore /\ s' = [s EXCEPT !.crashedBefore = @ \ {c}]
LoseResponse(c) == /\ c = "p1r" /\ s.outcome[c] = "COMMITTED" /\ c \notin s.responseLost
 /\ s' = [s EXCEPT !.crashedAfter = @ \cup {c}, !.responseLost = @ \cup {c}]
RecoverLostResponse(c) == /\ c \in s.responseLost /\ c \notin s.recovered
 /\ s' = [s EXCEPT !.recovered = @ \cup {c}, !.readable = @ \cup {c},
  !.version = (IF Ablation = "RECOVERY_AUTHORITY"
              THEN [s.version EXCEPT !["n1"] = @ + 1] ELSE @),
  !.events = (IF Ablation = "RECOVERY_AUTHORITY" THEN @ + 1 ELSE @),
  !.recoveryHistory = @ \cup
   {<<c, s.version,
      (IF Ablation = "RECOVERY_AUTHORITY" THEN [s.version EXCEPT !["n1"] = @ + 1]
       ELSE s.version),
      s.ptr, s.ptr, s.events,
      (IF Ablation = "RECOVERY_AUTHORITY" THEN s.events + 1 ELSE s.events),
      s.outbox, s.outbox>>},
  !.supReplay = @ \cup {<<CanonicalSupRequest, s.version, s.version, s.ptr, s.ptr,
    s.events, s.events, s.outbox, s.outbox, Envelope(c)>>}]
MakeReadable(c) == /\ c \in {x \in Candidates : s.outcome[x] = "COMMITTED"} /\ c \notin s.readable
 /\ s' = [s EXCEPT !.readable = @ \cup {c}]
DeliverOutbox(c) == /\ c \in s.outbox /\ c \notin s.delivered
 /\ s' = [s EXCEPT !.delivered = @ \cup {c}]

AffectedByDirect(root) == {c \in Candidates : c = root \/ root \in Ancestors(c)}
AffectedByActor(a) == {c \in Candidates : CandidateAgent(c) = a \/
 (\E x \in Ancestors(c) : CandidateAgent(x) = a)}
RevokeDirect(c) == /\ c = "p1" /\ c \in {x \in Candidates : s.outcome[x] = "COMMITTED"}
 /\ c \notin s.directRevoked /\ "p3" \in s.status /\ "p1r" \in s.recovered
 /\ s.outcome["stale"] = "DENIED"
 /\ s' = [s EXCEPT !.directRevoked = @ \cup {c}, !.trustSeq = @ + 1,
  !.disp[c] = (IF @ = "CURRENT" THEN "REVOKED" ELSE @),
  !.ptr[CandidateNode(c)] = (IF @ = c THEN None ELSE @),
  !.status = @ \ AffectedByDirect(c), !.consumed = @ \ AffectedByDirect(c),
  !.revocationHistory = @ \cup
   {<<"direct", c, (IF Ablation = "REVOCATION_CLOSURE" THEN {c} ELSE AffectedByDirect(c))>>},
  !.propagationPending = (IF Ablation = "PROPAGATION_FENCE" THEN @ ELSE @ \cup {c})]
RevokeActor(a) == /\ a \notin s.actorRevoked
 /\ s.life["p1"] = "COMMIT_PENDING" /\ s.outcome["p1"] = "NONE"
 /\ s' = [s EXCEPT !.actorRevoked = @ \cup {a}, !.actorGen[a] = @ + 1,
  !.trustSeq = @ + 1, !.status = @ \ AffectedByActor(a),
  !.consumed = @ \ AffectedByActor(a),
  !.revocationHistory = @ \cup {<<"actor", a, AffectedByActor(a)>>},
  !.propagationPending = @ \cup {a}]
RevokeWorkflow == /\ ~s.workflowRevoked /\ s.life["p1"] = "COMMIT_PENDING" /\ s.outcome["p1"] = "NONE"
 /\ s' = [s EXCEPT !.workflowRevoked = TRUE, !.workflowGen = @ + 1,
  !.trustSeq = @ + 1, !.status = {}, !.consumed = {},
  !.revocationHistory = @ \cup {<<"workflow", "workflow1", Candidates>>},
  !.propagationPending = @ \cup {"workflow1"}]
Propagate(x) == /\ x \in s.propagationPending
 /\ s' = [s EXCEPT !.propagationPending = @ \ {x}, !.propagationDone = @ \cup {x}]
ReconfigurePolicy == /\ s.policy = 1 /\ s.life["p1"] = "COMMIT_PENDING" /\ s.outcome["p1"] = "NONE"
 /\ s' = [s EXCEPT !.policy = 2]
ReconfigureAuthority == /\ s.authority = 1 /\ s.life["p1"] = "COMMIT_PENDING" /\ s.outcome["p1"] = "NONE"
 /\ s' = [s EXCEPT !.authority = 2]

StatusExpiry(c) == IF s.statusNext[c] < s.statusIssued[c] + MaxStaleness
 THEN s.statusNext[c] ELSE s.statusIssued[c] + MaxStaleness
StatusFaults == {"STALE", "DIGEST", "CERT_SEQUENCE", "NONCE", "ACTOR_GENERATION",
 "WORKFLOW_GENERATION", "ROLLBACK", "HEAD", "TRUST_GENERATION", "SIGNER", "ROLE"}
StatusFaultOrder == <<"STALE", "DIGEST", "CERT_SEQUENCE", "NONCE", "ACTOR_GENERATION",
 "WORKFLOW_GENERATION", "ROLLBACK", "HEAD", "TRUST_GENERATION", "SIGNER", "ROLE">>
StatusView(c, fault) == [
 certificate |-> IF fault = "DIGEST" THEN "tampered" ELSE s.statusCertificate[c],
 certificateSequence |-> IF fault = "CERT_SEQUENCE" THEN 0 ELSE s.statusCertificateSequence[c],
 nonce |-> IF fault = "NONCE" THEN "wrong-nonce" ELSE s.statusNonce[c],
 actorGeneration |-> IF fault = "ACTOR_GENERATION"
                    THEN s.statusActorGeneration[c] + 1 ELSE s.statusActorGeneration[c],
 workflowGeneration |-> IF fault = "WORKFLOW_GENERATION"
                       THEN s.statusWorkflowGeneration[c] + 1 ELSE s.statusWorkflowGeneration[c],
 sequence |-> IF fault = "ROLLBACK" THEN 0 ELSE s.statusTrustSeq[c],
 head |-> IF fault \in {"HEAD", "ROLLBACK"} THEN "tampered-head" ELSE s.statusTrustHead[c],
 trustGeneration |-> IF fault = "TRUST_GENERATION"
                    THEN s.statusTrustGeneration[c] + 1 ELSE s.statusTrustGeneration[c],
 signerRole |-> IF fault = "ROLE" THEN "COMMIT" ELSE s.statusSignerRole[c],
 signerTrusted |-> IF fault = "SIGNER" THEN FALSE ELSE s.statusSignerTrusted[c],
 checkedAt |-> IF fault = "STALE" THEN StatusExpiry(c) + 1 ELSE s.now]
StatusAccepts(c, fault) == LET v == StatusView(c, fault) IN
 c \in s.status /\ c \in s.nonceBound /\
 v.certificate = c /\ v.certificateSequence = s.certificateSequence[c] /\
 v.nonce = RequestedNonce(c) /\
 v.actorGeneration = s.certActorGen[c] /\
 v.workflowGeneration = s.certWorkflowGen[c] /\
 v.trustGeneration = s.observedTrustGeneration /\
 v.signerRole = "STATUS" /\ v.signerTrusted /\
 v.sequence >= s.observedTrustSeq /\
 (v.sequence # s.observedTrustSeq \/ v.head = s.observedTrustHead) /\
 v.checkedAt <= StatusExpiry(c) /\ s.disp[c] = "CURRENT" /\ ~EffectiveRevoked(c)
CurrentlyConsumable(c) == StatusAccepts(c, "GOOD")
IssueStatus(c) == /\ c = "p3" /\ s.outcome[c] = "COMMITTED" /\ s.disp[c] = "CURRENT"
 /\ ~EffectiveRevoked(c) /\ c \notin s.status /\ s.now <= MaxTime - MaxStaleness
 /\ s' = [s EXCEPT !.status = @ \cup {c}, !.nonceBound = @ \cup {c},
  !.statusIssued[c] = s.now,
  !.statusNext[c] = (IF Ablation = "STATUS_WINDOW" THEN s.now + MaxStaleness + 1
                    ELSE s.now + MaxStaleness),
  !.statusCertificate[c] = c, !.statusNonce[c] = RequestedNonce(c),
  !.statusCertificateSequence[c] = s.certificateSequence[c],
  !.statusActorGeneration[c] = s.certActorGen[c],
  !.statusWorkflowGeneration[c] = s.certWorkflowGen[c],
  !.statusTrustSeq[c] = s.trustSeq,
  !.statusTrustHead[c] = "head-" \o ToString(s.trustSeq),
  !.statusTrustGeneration[c] = s.trustSeq, !.statusSignerRole[c] = "STATUS",
  !.statusSignerTrusted[c] = TRUE,
  !.observedTrustSeq = s.trustSeq,
  !.observedTrustHead = "head-" \o ToString(s.trustSeq),
  !.observedTrustGeneration = s.trustSeq]
CheckStatus(c, fault) == /\ c = "p3" /\ s.outcome[c] = "COMMITTED"
 /\ fault \in StatusFaults \cup {"GOOD"} /\ <<c, fault>> \notin s.statusChecks
 /\ (fault = "GOOD" \/
      (s.outcome["stale"] = "DENIED" /\ Terminal("equivocation") /\ "p1r" \in s.recovered))
 /\ (IF fault \in StatusFaults
      THEN LET checked == Cardinality({r \in s.statusChecks : r[2] \in StatusFaults}) IN
           IF checked < Len(StatusFaultOrder)
           THEN fault = StatusFaultOrder[checked + 1] ELSE FALSE
      ELSE TRUE)
 /\ LET accepted == (StatusAccepts(c, fault) \/
          (Ablation = "STATUS_BINDING" /\ fault = "DIGEST")) IN
    s' = [s EXCEPT !.statusChecks = @ \cup {<<c, fault>>},
      !.consumed = IF accepted THEN @ \cup {c} ELSE @,
      !.consumptionHistory = IF accepted THEN @ \cup {<<c, fault>>} ELSE @,
      !.blockedStatus = IF accepted THEN @ ELSE @ \cup {fault},
      !.blocked = IF accepted THEN @ ELSE TRUE]
Consume(c) == CheckStatus(c, "GOOD")
Tick == /\ s.status # {} /\ s.now < MaxTime
 /\ s' = [s EXCEPT !.now = @ + 1,
  !.status = {c \in @ : s.now + 1 <= StatusExpiry(c)},
  !.consumed = {c \in @ : s.now + 1 <= StatusExpiry(c)}]

\* Legacy completion/status is observable migration input, never an Auth source.
AttemptLegacyAuthority(c) == /\ c = "p3" /\ s.outcome[c] = "COMMITTED"
 /\ c \notin s.legacyCompletion
 /\ StatusFaults \subseteq s.blockedStatus
 /\ LET promotes == Ablation = "LEGACY_AUTHORITY" IN
    s' = [s EXCEPT !.legacyCompletion = @ \cup {c}, !.legacyStatus = @ \cup {c},
      !.legacyAuth = IF promotes THEN @ \cup {c} ELSE @,
      !.legacyConsumed = IF promotes THEN @ \cup {c} ELSE @,
      !.legacyHistory = @ \cup {[candidate |-> c,
        authBefore |-> (c \in s.legacyAuth), authAfter |-> promotes,
        consumedBefore |-> (c \in s.legacyConsumed), consumedAfter |-> promotes]}]

Idle == /\ AllTerminal /\ s.propagationPending = {} /\ s.outbox \subseteq s.delivered
 /\ s.responseLost \subseteq s.recovered
 /\ {c \in Candidates : s.outcome[c] = "COMMITTED"} \subseteq s.readable /\ s' = s

Next == \/ (\E c \in Candidates : Admit(c))
 \/ (\E c \in Candidates : Begin(c))
 \/ (\E c \in Candidates : Stage(c))
 \/ (\E c \in Candidates : Assemble(c))
 \/ (\E c \in Candidates : Prepare(c))
 \/ InvalidateAuthorization("p2") \/ InvalidateReceipt("p2")
 \/ (\E c \in Candidates : Quarantine(c))
 \/ (\E c \in Candidates \ {"p1r", "stale"} : AuthorityGuard(c))
 \/ (s.supDecision["sup-id"] # None /\ AuthorityGuard("stale"))
 \/ SupersessionGuard(CanonicalSupRequest) \/ ConflictingSupersession
 \/ (\E c \in Candidates : CrashBefore(c))
 \/ (\E c \in Candidates : RecoverBefore(c))
 \/ (\E c \in Candidates : LoseResponse(c))
 \/ (\E c \in Candidates : RecoverLostResponse(c))
 \/ (\E c \in Candidates : MakeReadable(c))
 \/ (\E c \in Candidates : DeliverOutbox(c))
 \/ (\E a \in Agents : RevokeActor(a)) \/ RevokeWorkflow
 \/ ReconfigurePolicy \/ ReconfigureAuthority
 \/ (\E c \in Candidates : IssueStatus(c))
 \/ (\E c \in Candidates : Consume(c))
 \/ (\E fault \in StatusFaults : CheckStatus("p3", fault))
 \/ AttemptLegacyAuthority("p3")
 \/ (\E c \in Candidates : RevokeDirect(c))
 \/ (\E x \in (Candidates \cup Agents \cup {"workflow1"}) : Propagate(x))
 \/ Tick \/ Idle
Spec == Init /\ [][Next]_vars

Committed == {c \in Candidates : s.outcome[c] = "COMMITTED"}
Current == {c \in Candidates : s.disp[c] = "CURRENT"}
LinFor(c) == {r \in s.linHistory : r[1] = c}
NoUnauthorizedCommit == \A c \in Committed : s.certAuthorized[c] /\
 s.certWorkflow[c] = Workflow(c) /\ LinFor(c) # {}
NoInvalidReceiptCommit == \A c \in Committed : s.certReceiptValid[c]
NoStalePolicyCommit == \A c \in Committed : s.certPolicy[c] = PolicyEpoch(c)
NoStaleAuthorityCommit == \A c \in Committed : s.certAuthority[c] = AuthorityEpoch(c)
NoRevokedActorCommit == \A c \in Committed : s.certActorGen[c] = ActorGeneration(c)
NoStaleWorkflowCommit == \A c \in Committed : s.certWorkflowGen[c] = WorkflowGeneration(c)
NoInvalidPredecessorCommit ==
 /\ \A c \in Committed : Ancestors(c) \subseteq Committed /\ s.certpred[c] = Pred(c)
 /\ (s.outcome["stale"] = "DENIED" =>
      s.rejectReason["stale"] = "PREDECESSOR_REPLACED" /\
      Attempt("stale") = s.attempt[CandidateNode("stale")] /\
      PolicyEpoch("stale") = s.policy /\ AuthorityEpoch("stale") = s.authority /\
      ExpectedVersion("stale") = s.version[CandidateNode("stale")] /\
      s.authorizationValid["stale"] /\ s.receiptValid["stale"] /\
      s.staleHistory = <<"PREVALIDATED_CURRENT", "PREDECESSOR_SUPERSEDED",
                         "GUARDED_REJECT_PREDECESSOR_REPLACED">>)
NoCrossAttemptReplay == \A r \in s.linHistory : r[10] = r[11]
NoCrossWorkflowReplay == \A c \in Committed : s.certWorkflow[c] = EvidenceWorkflow(c)
NoCrossNodeReplay == \A n \in Nodes : s.ptr[n] = None \/ CandidateNode(s.ptr[n]) = n
NoAuthorityFromRecovery == \A r \in s.recoveryHistory :
 r[2] = r[3] /\ r[4] = r[5] /\ r[6] = r[7] /\ r[8] = r[9]
NoAuthorityFromStaging == LET stagedOnly == s.staged \ Committed IN
 stagedOnly \cap (s.outbox \cup s.readable \cup s.status \cup s.consumed \cup
  ({s.ptr[n] : n \in Nodes} \ {None})) = {}
NoAuthorityFromOutbox == s.outbox = Committed
NoAuthorityFromLegacyStatus ==
 /\ s.legacyAuth = {} /\ s.legacyConsumed = {}
 /\ \A r \in s.legacyHistory : ~r.authBefore /\ ~r.authAfter /\
      ~r.consumedBefore /\ ~r.consumedAfter
AtMostOneAuthoritativeCommitPerNodeVersion == \A x, y \in Committed :
 CandidateNode(x) = CandidateNode(y) /\ s.certver[x] = s.certver[y] => x = y
CommitIdUniqueness == \A c \in Committed : s.owner[CommitId(c)] = c
CommitIdEquivocationDetection == s.conflicts = {c \in Candidates : s.outcome[c] = "CONFLICTED"}
PredecessorCausalConsistency == \A c \in Committed : Ancestors(c) \subseteq Committed
CertificateStateConsistency == \A c \in Candidates :
 IF c \in Committed THEN
  /\ c \in s.outbox /\ s.disp[c] # "ABSENT"
  /\ s.decisionRecord[c] = DecisionRecord(c, s.certver[c])
  /\ s.certificateRecord[c] = CertificateRecord(c, s.certver[c])
  /\ s.certificateRecord[c].decision = s.decisionRecord[c]
  /\ s.certificateRecord[c].version = s.certver[c]
  /\ s.certificateRecord[c].outputDigest = OutputDigest(c)
  /\ s.certOutput[c] = OutputDigest(c)
 ELSE /\ s.decisionRecord[c] = None /\ s.certificateRecord[c] = None
      /\ s.certOutput[c] = None /\ s.disp[c] = "ABSENT"
RevocationMonotonicity ==
 /\ \A a \in Agents : s.actorGen[a] = (IF a \in s.actorRevoked THEN 1 ELSE 0)
 /\ s.workflowGen = (IF s.workflowRevoked THEN 1 ELSE 0)
 /\ s.trustSeq = Cardinality(s.actorRevoked) + s.workflowGen + Cardinality(s.directRevoked)
ExpectedRevocationSet(r) == CASE r[1] = "direct" -> AffectedByDirect(r[2])
 [] r[1] = "actor" -> AffectedByActor(r[2])
 [] OTHER -> Candidates
EffectiveRevocationClosure == \A r \in s.revocationHistory :
 r[3] = ExpectedRevocationSet(r) /\ r[3] \cap (s.status \cup s.consumed) = {}
DownstreamAuthorityConsistency == \A r \in s.consumptionHistory : r[2] = "GOOD"
ExactReplayPreservesState == \A r \in s.replayHistory : r[2] = r[3] /\ r[4] = r[5]
ExactReplayPreservesCertificate == \A r \in s.replayHistory : r[10] = Envelope(r[1])
ExactReplayDoesNotDuplicateSideEffects == \A r \in s.replayHistory : r[6] = r[7] /\ r[8] = r[9]
ConflictingReplayDoesNotMutateAuthority ==
 /\ \A r \in s.conflictHistory :
      r[2] = r[3] /\ r[4] = r[5] /\ r[6] = r[7] /\ r[8] = r[9]
 /\ \A r \in s.supConflictHistory :
      r[2] = r[3] /\ r[4] = r[5] /\ r[6] = r[7] /\ r[8] = r[9]
CurrentPointerConsistency == \A n \in Nodes : s.ptr[n] = None \/
 (s.ptr[n] \in Current /\ CandidateNode(s.ptr[n]) = n /\ s.certver[s.ptr[n]] = s.version[n] /\
  (\A c \in Current : CandidateNode(c) = n => c = s.ptr[n]))
DispositionMonotonicity ==
 /\ \A <<c, from, to>> \in s.dispHistory :
      <<from, to>> \in {<<"ABSENT", "CURRENT">>, <<"CURRENT", "SUPERSEDED">>, <<"CURRENT", "REVOKED">>}
 /\ \A c \in Candidates :
      Cardinality({e \in s.dispHistory : e[1] = c /\ e[3] \in {"SUPERSEDED", "REVOKED"}}) <= 1
AtomicSupersession == \A r \in s.supHistory :
 /\ r.versionAfter = r.versionBefore + 1
 /\ r.ptrBefore = r.old /\ r.ptrAfter = r.new
 /\ r.oldDispBefore = "CURRENT" /\ r.oldDispAfter = "SUPERSEDED"
 /\ r.newDispBefore = "ABSENT" /\ r.newDispAfter = "CURRENT"
 /\ r.ownerBefore = None /\ r.ownerAfter = r.new
 /\ r.nonceOwnerBefore = None /\ r.nonceOwnerAfter = r.new
 /\ r.nonce = RequestedNonce(r.new)
 /\ r.decisionAfter = Envelope(r.new)
 /\ r.outboxAfter = r.outboxBefore \cup {r.new}
 /\ r.edgeAfter = r.edgeBefore \cup {<<r.old, r.new>>}
 /\ r.eventsAfter = r.eventsBefore + 1
SupersessionReplayPrecedence == \A r \in s.supReplay :
 r[3] = r[2] /\ r[5] = r[4] /\ r[7] = r[6] /\ r[9] = r[8]
SupersessionNonretroactivity == \A r \in s.supHistory : \A c \in r.committedChildren :
 s.outcome[c] = "COMMITTED" /\ r.old \in Ancestors(c) /\ s.certpred[c] = r.certpredBefore[c]
NoStagedResultVisibleToOrdinaryConsumers == s.consumed \cap (s.staged \ Committed) = {}
NoDownstreamReadBeforeAuthoritativeCommit == s.readable \subseteq Committed
NoRevokedAncestorResultConsumed == \A c \in s.consumed : ~EffectiveRevoked(c)
CrashDoesNotCreateAuthority == s.crashedBefore \cap Committed = {}
RecoveryDoesNotPromoteUnverifiedState ==
 /\ s.recovered \subseteq Committed
 /\ s.recovered \subseteq s.readable
 /\ \A c \in s.recovered : s.supDecision["sup-id"] = Envelope(c)
OutboxReplayDoesNotDuplicateAuthority == s.delivered \subseteq s.outbox /\ s.events = Cardinality(Committed)
RevocationPropagationIsRecoverable ==
 /\ s.propagationDone \cap s.propagationPending = {}
 /\ \A r \in s.revocationHistory : r[2] \in s.propagationPending \cup s.propagationDone
IssuedStatusHasBoundedResidualValidity == \A c \in s.status :
 s.statusNext[c] <= s.statusIssued[c] + MaxStaleness /\ s.now <= StatusExpiry(c)
Invariant == NoUnauthorizedCommit /\ NoInvalidReceiptCommit /\ NoStalePolicyCommit /\
 NoStaleAuthorityCommit /\ NoRevokedActorCommit /\ NoStaleWorkflowCommit /\
 NoInvalidPredecessorCommit /\ NoCrossAttemptReplay /\ NoCrossWorkflowReplay /\ NoCrossNodeReplay /\
 NoAuthorityFromRecovery /\ NoAuthorityFromStaging /\ NoAuthorityFromOutbox /\ NoAuthorityFromLegacyStatus /\
 AtMostOneAuthoritativeCommitPerNodeVersion /\ CommitIdUniqueness /\ CommitIdEquivocationDetection /\
 PredecessorCausalConsistency /\ CertificateStateConsistency /\ RevocationMonotonicity /\
 EffectiveRevocationClosure /\ DownstreamAuthorityConsistency /\ ExactReplayPreservesState /\
 ExactReplayPreservesCertificate /\ ExactReplayDoesNotDuplicateSideEffects /\
 ConflictingReplayDoesNotMutateAuthority /\ CurrentPointerConsistency /\ DispositionMonotonicity /\
 AtomicSupersession /\ SupersessionReplayPrecedence /\ SupersessionNonretroactivity /\
 NoStagedResultVisibleToOrdinaryConsumers /\ NoDownstreamReadBeforeAuthoritativeCommit /\
 NoRevokedAncestorResultConsumed /\ CrashDoesNotCreateAuthority /\ RecoveryDoesNotPromoteUnverifiedState /\
 OutboxReplayDoesNotDuplicateAuthority /\ RevocationPropagationIsRecoverable /\
 IssuedStatusHasBoundedResidualValidity

LiveNext == \/ (\E c \in Candidates : Admit(c)) \/ (\E c \in Candidates : Begin(c))
 \/ (\E c \in Candidates : Stage(c)) \/ (\E c \in Candidates : Assemble(c))
 \/ (\E c \in Candidates : Prepare(c))
 \/ (\E c \in Candidates \ {"p1r", "stale"} : AuthorityGuard(c))
 \/ (s.supDecision["sup-id"] # None /\ AuthorityGuard("stale"))
 \/ SupersessionGuard(CanonicalSupRequest) \/ ConflictingSupersession
 \/ (\E c \in Candidates : MakeReadable(c)) \/ (\E c \in Candidates : DeliverOutbox(c))
 \/ IssueStatus("p3") \/ RevokeDirect("p1") \/ Propagate("p1")
 \/ LoseResponse("p1r") \/ RecoverLostResponse("p1r") \/ Idle
LivenessSpec == Init /\ [][LiveNext]_vars
 /\ (\A c \in Candidates : WF_vars(Admit(c)) /\ WF_vars(Begin(c)) /\ WF_vars(Stage(c)) /\
      WF_vars(Assemble(c)) /\ WF_vars(Prepare(c)))
 /\ (\A c \in Candidates \ {"p1r", "stale"} : WF_vars(AuthorityGuard(c)))
 /\ WF_vars(s.supDecision["sup-id"] # None /\ AuthorityGuard("stale"))
 /\ WF_vars(SupersessionGuard(CanonicalSupRequest)) /\ WF_vars(ConflictingSupersession)
 /\ (\A c \in Candidates : WF_vars(MakeReadable(c)) /\ WF_vars(DeliverOutbox(c)))
 /\ WF_vars(IssueStatus("p3")) /\ WF_vars(RevokeDirect("p1")) /\ WF_vars(Propagate("p1"))
 /\ WF_vars(LoseResponse("p1r")) /\ WF_vars(RecoverLostResponse("p1r"))
StableProposal(c) == s.life[c] = "COMMIT_PENDING" /\ CurrentContextValid(c) /\
 s.owner[CommitId(c)] = None /\ c \notin s.crashedBefore
DenialReady(c) == s.life[c] = "COMMIT_PENDING" /\ ~CommitContextValid(c) /\
 s.owner[CommitId(c)] = None
ConflictReady(c) == s.life[c] = "COMMIT_PENDING" /\
 s.owner[CommitId(c)] \notin {None, c}
ValidStableProposalEventuallyCommits == \A c \in {"p1", "p2", "p3"} :
 StableProposal(c) ~> (s.outcome[c] = "COMMITTED")
AdmittedProposalEventuallyTerminates == \A c \in Candidates : (s.life[c] # "UNSEEN") ~> Terminal(c)
DeniedProposalEventuallyReturnsDenial == \A c \in Candidates :
 DenialReady(c) ~> (s.outcome[c] = "DENIED")
ConflictingProposalEventuallyReturnsConflict ==
 /\ \A c \in Candidates : ConflictReady(c) ~> (s.outcome[c] = "CONFLICTED")
 /\ (s.supOwner["sup-id"] = CanonicalSupRequest) ~>
    (ConflictingSupRequest \in s.supConflicts)
IdempotentRetryEventuallyReturnsDecision ==
 /\ (s.owner[CommitId("p1")] = "p1") ~> (s.replayHistory # {})
 /\ (s.supDecision["sup-id"] = Envelope("p1r")) ~> (s.supReplay # {})
RevocationEventuallyPropagates == \A x \in Candidates \cup Agents \cup {"workflow1"} :
 (x \in s.propagationPending) ~> (x \in s.propagationDone)
CommittedCertificateEventuallyBecomesReadable == \A c \in Candidates : (c \in Committed) ~> (c \in s.readable)
OutboxIntentEventuallyDelivered == \A c \in Candidates : (c \in s.outbox) ~> (c \in s.delivered)
ResponseLossEventuallyRecovers == \A c \in Candidates :
 (c \in s.responseLost) ~> (c \in s.recovered)
WitnessValidChainNotReached == ~("p1" \in Committed /\ "p2" \in Committed /\ "p3" \in Committed)
WitnessExactReplayNotReached == s.replayHistory = {} \/ s.supReplay = {}
WitnessStaleRejectionNotReached == s.outcome["stale"] # "DENIED"
WitnessRevocationBlockedNotReached == ~s.blocked
WitnessRecoveryNotReached == s.recovered = {}
WitnessInvalidAuthorizationRejectedNotReached == ~(
 ~s.authorizationValid["p2"] /\ s.outcome["p2"] = "DENIED" /\
 s.rejectReason["p2"] = "UNAUTHORIZED")
WitnessInvalidReceiptRejectedNotReached == ~(
 ~s.receiptValid["p2"] /\ s.outcome["p2"] = "DENIED" /\
 s.rejectReason["p2"] = "INVALID_RECEIPT")
WitnessStatusBindingNotReached == ~(StatusFaults \subseteq s.blockedStatus)
WitnessLegacyStatusBlockedNotReached == s.legacyHistory = {} \/
 s.legacyAuth # {} \/ s.legacyConsumed # {}
=============================================================================
