---------------------- MODULE governed_commit ----------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Workflows, W1, W2, Nodes, Root, Child, Leaf,
          Executors, E1, E2, Attempts, A1, A2,
          CommitIds, C1, C2, C3, C4, C5, C6, ValidReceipts,
          NoCommit, NoAttempt, NoExecutor

VARIABLES status, staged, visible, decisions, accepted, nodeCommit,
          nodeAttempt, nodeExecutor, nodeReceiptDigest, nodeResultDigest,
          stateVersion, outbox,
          revokedRoots, propagationPending, propagationCrashed,
          equivocations, replayDenied, revocationDenied, policyEpoch, authorityEpoch,
          agentRevocationEpoch, rootRevocationEpoch, workflowGeneration,
          nodeVersion, executorEligible, validatorAvailable, responseLost

vars == <<status, staged, visible, decisions, accepted, nodeCommit,
          nodeAttempt, nodeExecutor, nodeReceiptDigest, nodeResultDigest,
          stateVersion, outbox,
          revokedRoots, propagationPending, propagationCrashed,
          equivocations, replayDenied, revocationDenied, policyEpoch, authorityEpoch,
          agentRevocationEpoch, rootRevocationEpoch, workflowGeneration,
          nodeVersion, executorEligible, validatorAvailable, responseLost>>

fenceVars == <<policyEpoch, authorityEpoch, agentRevocationEpoch,
               rootRevocationEpoch, workflowGeneration, nodeVersion,
               executorEligible, validatorAvailable, responseLost>>
coreVars == <<status, staged, visible, decisions, accepted, nodeCommit,
              nodeAttempt, nodeExecutor, nodeReceiptDigest, nodeResultDigest,
              stateVersion, outbox, revokedRoots,
              propagationPending, propagationCrashed, equivocations, replayDenied,
              revocationDenied>>

Statuses == {"blocked", "ready", "claimed", "result_produced",
             "governed_committed", "revoked", "superseded"}
DecisionValues == {"none", "committed", "denied"}

Pred(n) == IF n = Root THEN {} ELSE IF n = Child THEN {Root} ELSE {Child}
ReceiptWorkflow(c) == IF c = C5 THEN W2 ELSE W1
ReceiptNode(c) == IF c = C3 THEN Child ELSE IF c = C4 THEN Leaf ELSE Root
ReceiptAttempt(c) == IF c = C4 THEN A2 ELSE A1
ReceiptExecutor(c) == IF c = C2 \/ c = C3 \/ c = C5 THEN E2 ELSE E1
ActiveWorkflow(c) == IF c = C5 \/ c = C6 THEN W2 ELSE W1
ActiveAttempt(c) == IF c = C6 THEN A2 ELSE ReceiptAttempt(c)
Descends(n, r) == (n = r) \/ (r = Root) \/ (r = Child /\ n = Leaf)
RevokedClosure(w, n) ==
    \E pair \in revokedRoots : pair[1] = w /\ Descends(n, pair[2])
DepsCommittedAfter(w, n, target) ==
    \A p \in Pred(n) : status[w][p] = "governed_committed" \/ p = target
ContextMatches(c) ==
    /\ ReceiptWorkflow(c) = ActiveWorkflow(c)
    /\ ReceiptAttempt(c) = ActiveAttempt(c)
ReceiptPolicyEpoch(c) == IF c = C2 THEN 1 ELSE 0
ReceiptAuthorityEpoch(c) == 0
ReceiptAgentRevocationEpoch(c) == 0
ReceiptRootRevocationEpoch(c) == 0
ReceiptWorkflowGeneration(c) == IF c = C5 THEN 1 ELSE 0
ReceiptNodeVersion(c) == IF c = C6 THEN 1 ELSE 0
CertificateNode(c, p) == p
CertificateVersion(c, p) == 1
CertificateCommit(c, p) ==
    IF c = C3 /\ p = Root THEN C1
    ELSE IF c = C4 /\ p = Child THEN C3 ELSE NoCommit
CertificateReceiptDigest(c, p) == CertificateCommit(c, p)
CertificateResultDigest(c, p) == CertificateCommit(c, p)
CertificateRoot(c) == IF c = C3 THEN C1 ELSE IF c = C4 THEN C3 ELSE NoCommit
PredecessorCertificateValid(c, w, n) ==
    /\ \A p \in Pred(n) :
        /\ CertificateNode(c, p) = p
        /\ CertificateVersion(c, p) = nodeVersion[w][p]
        /\ CertificateCommit(c, p) = nodeCommit[w][p]
        /\ CertificateReceiptDigest(c, p) = nodeReceiptDigest[w][p]
        /\ CertificateResultDigest(c, p) = nodeResultDigest[w][p]
    /\ CertificateRoot(c) =
        IF n = Root THEN NoCommit
        ELSE IF n = Child THEN nodeCommit[w][Root]
        ELSE nodeCommit[w][Child]
SignedNodeVersionValid(c, w, n) == ReceiptNodeVersion(c) = nodeVersion[w][n]
EpochsMatch(c, w) ==
    /\ ReceiptPolicyEpoch(c) = policyEpoch[w]
    /\ ReceiptAuthorityEpoch(c) = authorityEpoch[w]
    /\ ReceiptAgentRevocationEpoch(c) = agentRevocationEpoch[w][ReceiptExecutor(c)]
    /\ ReceiptRootRevocationEpoch(c) = rootRevocationEpoch[w]
    /\ ReceiptWorkflowGeneration(c) = workflowGeneration[w]

TypeOK ==
    /\ status \in [Workflows -> [Nodes -> Statuses]]
    /\ staged \in [Workflows -> [Nodes -> BOOLEAN]]
    /\ visible \in [Workflows -> [Nodes -> BOOLEAN]]
    /\ decisions \in [CommitIds -> DecisionValues]
    /\ accepted \subseteq CommitIds
    /\ nodeCommit \in [Workflows -> [Nodes -> CommitIds \cup {NoCommit}]]
    /\ nodeAttempt \in [Workflows -> [Nodes -> Attempts \cup {NoAttempt}]]
    /\ nodeExecutor \in [Workflows -> [Nodes -> Executors \cup {NoExecutor}]]
    /\ nodeReceiptDigest \in [Workflows -> [Nodes -> CommitIds \cup {NoCommit}]]
    /\ nodeResultDigest \in [Workflows -> [Nodes -> CommitIds \cup {NoCommit}]]
    /\ stateVersion \in [Workflows -> Nat]
    /\ outbox \subseteq Workflows \X Nodes
    /\ revokedRoots \subseteq Workflows \X Nodes
    /\ propagationPending \subseteq Workflows \X Nodes
    /\ propagationCrashed \in BOOLEAN
    /\ equivocations \subseteq CommitIds
    /\ replayDenied \subseteq CommitIds
    /\ revocationDenied \subseteq CommitIds
    /\ policyEpoch \in [Workflows -> 0..1]
    /\ authorityEpoch \in [Workflows -> 0..1]
    /\ agentRevocationEpoch \in [Workflows -> [Executors -> 0..1]]
    /\ rootRevocationEpoch \in [Workflows -> 0..1]
    /\ workflowGeneration \in [Workflows -> 0..1]
    /\ nodeVersion \in [Workflows -> [Nodes -> 0..2]]
    /\ executorEligible \in [Workflows -> [Executors -> BOOLEAN]]
    /\ validatorAvailable \in BOOLEAN
    /\ responseLost \in BOOLEAN

Init ==
    /\ status = [w \in Workflows |-> [n \in Nodes |->
         IF n = Root THEN "ready" ELSE "blocked"]]
    /\ staged = [w \in Workflows |-> [n \in Nodes |-> FALSE]]
    /\ visible = [w \in Workflows |-> [n \in Nodes |-> FALSE]]
    /\ decisions = [c \in CommitIds |-> "none"]
    /\ accepted = {}
    /\ nodeCommit = [w \in Workflows |-> [n \in Nodes |-> NoCommit]]
    /\ nodeAttempt = [w \in Workflows |-> [n \in Nodes |-> NoAttempt]]
    /\ nodeExecutor = [w \in Workflows |-> [n \in Nodes |-> NoExecutor]]
    /\ nodeReceiptDigest = [w \in Workflows |-> [n \in Nodes |-> NoCommit]]
    /\ nodeResultDigest = [w \in Workflows |-> [n \in Nodes |-> NoCommit]]
    /\ stateVersion = [w \in Workflows |-> 0]
    /\ outbox = {}
    /\ revokedRoots = {}
    /\ propagationPending = {}
    /\ propagationCrashed = FALSE
    /\ equivocations = {}
    /\ replayDenied = {}
    /\ revocationDenied = {}
    /\ policyEpoch = [w \in Workflows |-> 0]
    /\ authorityEpoch = [w \in Workflows |-> 0]
    /\ agentRevocationEpoch = [w \in Workflows |-> [e \in Executors |-> 0]]
    /\ rootRevocationEpoch = [w \in Workflows |-> 0]
    /\ workflowGeneration = [w \in Workflows |-> 0]
    /\ nodeVersion = [w \in Workflows |-> [n \in Nodes |-> 0]]
    /\ executorEligible = [w \in Workflows |-> [e \in Executors |-> TRUE]]
    /\ validatorAvailable = TRUE
    /\ responseLost = FALSE

Claim(c) ==
    LET w == ActiveWorkflow(c) IN
    LET n == ReceiptNode(c) IN
    /\ c \in CommitIds
    /\ ContextMatches(c)
    /\ status[w][n] = "ready"
    /\ executorEligible[w][ReceiptExecutor(c)]
    /\ ~RevokedClosure(w, n)
    /\ status' = [status EXCEPT ![w][n] = "claimed"]
    /\ nodeAttempt' = [nodeAttempt EXCEPT ![w][n] = ActiveAttempt(c)]
    /\ nodeExecutor' = [nodeExecutor EXCEPT ![w][n] = ReceiptExecutor(c)]
    /\ UNCHANGED <<staged, visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    stateVersion, outbox, revokedRoots, propagationPending,
                    propagationCrashed, equivocations, replayDenied,
                    revocationDenied>>
    /\ UNCHANGED fenceVars

ProduceResult(c) ==
    LET w == ActiveWorkflow(c) IN
    LET n == ReceiptNode(c) IN
    /\ c \in CommitIds
    /\ status[w][n] = "claimed"
    /\ nodeAttempt[w][n] = ActiveAttempt(c)
    /\ nodeExecutor[w][n] = ReceiptExecutor(c)
    /\ executorEligible[w][ReceiptExecutor(c)]
    /\ status' = [status EXCEPT ![w][n] = "result_produced"]
    /\ staged' = [staged EXCEPT ![w][n] = TRUE]
    /\ UNCHANGED <<visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest, nodeAttempt,
                    nodeExecutor, stateVersion, outbox, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

TryCommit(c) ==
    LET w == ActiveWorkflow(c) IN
    LET n == ReceiptNode(c) IN
    /\ c \in CommitIds
    /\ decisions[c] = "none"
    /\ status[w][n] = "result_produced"
    /\ staged[w][n]
    /\ nodeAttempt[w][n] = ReceiptAttempt(c)
    /\ nodeExecutor[w][n] = ReceiptExecutor(c)
    /\ ContextMatches(c)
    /\ c \in ValidReceipts
    /\ validatorAvailable
    /\ EpochsMatch(c, w)
    /\ SignedNodeVersionValid(c, w, n)
    /\ executorEligible[w][ReceiptExecutor(c)]
    /\ PredecessorCertificateValid(c, w, n)
    /\ ~RevokedClosure(w, n)
    /\ \A p \in Pred(n) : status[w][p] = "governed_committed"
    /\ status' = [status EXCEPT ![w] = [x \in Nodes |->
                 IF x = n THEN "governed_committed"
                 ELSE IF status[w][x] = "blocked" /\ DepsCommittedAfter(w, x, n)
                      THEN "ready" ELSE status[w][x]]]
    /\ decisions' = [decisions EXCEPT ![c] = "committed"]
    /\ accepted' = accepted \cup {c}
    /\ nodeCommit' = [nodeCommit EXCEPT ![w][n] = c]
    /\ nodeReceiptDigest' = [nodeReceiptDigest EXCEPT ![w][n] = c]
    /\ nodeResultDigest' = [nodeResultDigest EXCEPT ![w][n] = c]
    /\ stateVersion' = [stateVersion EXCEPT ![w] = @ + 1]
    /\ outbox' = outbox \cup {<<w, n>>}
    /\ nodeVersion' = [nodeVersion EXCEPT ![w][n] = @ + 1]
    /\ UNCHANGED <<staged, visible, nodeAttempt, nodeExecutor, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, workflowGeneration,
                    executorEligible, validatorAvailable, responseLost>>

RejectConflict(c) ==
    LET w == ActiveWorkflow(c) IN LET n == ReceiptNode(c) IN
    /\ c \in CommitIds
    /\ decisions[c] = "none"
    /\ status[w][n] = "governed_committed"
    /\ decisions' = [decisions EXCEPT ![c] = "denied"]
    /\ UNCHANGED <<status, staged, visible, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest, nodeAttempt,
                    nodeExecutor, stateVersion, outbox, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

RejectCrossContext(c) ==
    /\ c \in CommitIds
    /\ decisions[c] = "none"
    /\ ~ContextMatches(c)
    /\ decisions' = [decisions EXCEPT ![c] = "denied"]
    /\ replayDenied' = replayDenied \cup {c}
    /\ UNCHANGED <<status, staged, visible, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest, nodeAttempt,
                    nodeExecutor, stateVersion, outbox, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    revocationDenied>>
    /\ UNCHANGED fenceVars

RejectRevokedAttempt(c) ==
    LET w == ActiveWorkflow(c) IN
    /\ c = C2
    /\ decisions[c] = "none"
    /\ ContextMatches(c)
    /\ ~executorEligible[w][ReceiptExecutor(c)]
    /\ ReceiptAgentRevocationEpoch(c) <
       agentRevocationEpoch[w][ReceiptExecutor(c)]
    /\ decisions' = [decisions EXCEPT ![c] = "denied"]
    /\ revocationDenied' = revocationDenied \cup {c}
    /\ UNCHANGED <<status, staged, visible, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest, nodeAttempt,
                    nodeExecutor, stateVersion, outbox, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    replayDenied>>
    /\ UNCHANGED fenceVars

ExactReplay(c) ==
    /\ c \in CommitIds
    /\ decisions[c] # "none"
    /\ UNCHANGED vars

Equivocation(c) ==
    /\ c \in accepted
    /\ c = C1
    /\ c \notin equivocations
    /\ equivocations' = equivocations \cup {c}
    /\ UNCHANGED <<status, staged, visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, outbox,
                    revokedRoots, propagationPending, propagationCrashed,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

RevokeRoot(w, r) ==
    /\ w \in Workflows
    /\ r \in Nodes
    /\ r = Root
    /\ status[w][r] = "governed_committed"
    /\ rootRevocationEpoch[w] = 0
    /\ <<w, r>> \notin revokedRoots
    /\ revokedRoots' = revokedRoots \cup {<<w, r>>}
    /\ rootRevocationEpoch' = [rootRevocationEpoch EXCEPT ![w] = @ + 1]
    /\ propagationPending' = propagationPending \cup {<<w, r>>}
    /\ visible' = [visible EXCEPT ![w] = [n \in Nodes |->
                       IF Descends(n, r) THEN FALSE ELSE visible[w][n]]]
    /\ UNCHANGED <<status, staged, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, outbox,
                    propagationCrashed, equivocations, replayDenied,
                    revocationDenied>>
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    workflowGeneration, nodeVersion, executorEligible, validatorAvailable,
                    responseLost>>

PropagationCrash ==
    /\ propagationPending # {}
    /\ ~propagationCrashed
    /\ propagationCrashed' = TRUE
    /\ UNCHANGED <<status, staged, visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, outbox,
                    revokedRoots, propagationPending, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

RecoverPropagation ==
    /\ propagationCrashed
    /\ propagationCrashed' = FALSE
    /\ UNCHANGED <<status, staged, visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, outbox,
                    revokedRoots, propagationPending, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

Propagate(pair) ==
    LET w == pair[1] IN LET r == pair[2] IN
    /\ pair \in propagationPending
    /\ ~propagationCrashed
    /\ status' = [status EXCEPT ![w] = [n \in Nodes |->
         IF n = r THEN "revoked"
         ELSE IF Descends(n, r)
              THEN IF status[w][n] = "governed_committed"
                   THEN "superseded" ELSE "blocked"
              ELSE status[w][n]]]
    /\ propagationPending' = propagationPending \ {pair}
    /\ nodeVersion' = [nodeVersion EXCEPT ![w] = [n \in Nodes |->
         IF Descends(n, r) THEN nodeVersion[w][n] + 1
         ELSE nodeVersion[w][n]]]
    /\ UNCHANGED <<staged, visible, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, outbox,
                    revokedRoots, propagationCrashed, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, workflowGeneration,
                    executorEligible, validatorAvailable, responseLost>>

Dispatch(pair) ==
    LET w == pair[1] IN LET n == pair[2] IN
    /\ pair \in outbox
    /\ ~RevokedClosure(w, n)
    /\ status[w][n] = "governed_committed"
    /\ visible' = [visible EXCEPT ![w][n] = TRUE]
    /\ outbox' = outbox \ {pair}
    /\ UNCHANGED <<status, staged, decisions, accepted, nodeCommit,
                    nodeReceiptDigest, nodeResultDigest,
                    nodeAttempt, nodeExecutor, stateVersion, revokedRoots,
                    propagationPending, propagationCrashed, equivocations,
                    replayDenied, revocationDenied>>
    /\ UNCHANGED fenceVars

ReconfigurePolicy(w) ==
    /\ w \in Workflows
    /\ policyEpoch[w] = 0
    /\ policyEpoch' = [policyEpoch EXCEPT ![w] = 1]
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<authorityEpoch, agentRevocationEpoch, rootRevocationEpoch,
                    workflowGeneration, nodeVersion, executorEligible, validatorAvailable,
                    responseLost>>

RevokeExecutor(w, e) ==
    /\ w \in Workflows
    /\ e \in Executors
    /\ authorityEpoch[w] = 0
    /\ agentRevocationEpoch[w][e] = 0
    /\ authorityEpoch' = [authorityEpoch EXCEPT ![w] = 1]
    /\ agentRevocationEpoch' = [agentRevocationEpoch EXCEPT ![w][e] = 1]
    /\ executorEligible' = [executorEligible EXCEPT ![w][e] = FALSE]
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<policyEpoch, rootRevocationEpoch, workflowGeneration,
                    nodeVersion, validatorAvailable, responseLost>>

FenceWorkflowGeneration(w) ==
    /\ w \in Workflows
    /\ workflowGeneration[w] = 0
    /\ workflowGeneration' = [workflowGeneration EXCEPT ![w] = 1]
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, nodeVersion, executorEligible, validatorAvailable,
                    responseLost>>

ValidatorFailure ==
    /\ validatorAvailable
    /\ validatorAvailable' = FALSE
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, workflowGeneration, nodeVersion,
                    executorEligible, responseLost>>

RecoverValidator ==
    /\ ~validatorAvailable
    /\ validatorAvailable' = TRUE
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, workflowGeneration, nodeVersion,
                    executorEligible, responseLost>>

ResponseLoss(c) ==
    /\ c \in accepted
    /\ ~responseLost
    /\ responseLost' = TRUE
    /\ UNCHANGED coreVars
    /\ UNCHANGED <<policyEpoch, authorityEpoch, agentRevocationEpoch,
                    rootRevocationEpoch, workflowGeneration, nodeVersion,
                    executorEligible, validatorAvailable>>

CrashRecover == UNCHANGED vars

Next ==
    \/ \E c \in CommitIds : Claim(c)
    \/ \E c \in CommitIds : ProduceResult(c)
    \/ \E c \in CommitIds : TryCommit(c)
    \/ \E c \in CommitIds : RejectConflict(c)
    \/ \E c \in CommitIds : RejectCrossContext(c)
    \/ \E c \in CommitIds : RejectRevokedAttempt(c)
    \/ \E c \in CommitIds : ExactReplay(c)
    \/ \E c \in CommitIds : Equivocation(c)
    \/ \E w \in Workflows, r \in Nodes : RevokeRoot(w, r)
    \/ PropagationCrash
    \/ RecoverPropagation
    \/ \E pair \in propagationPending : Propagate(pair)
    \/ \E pair \in outbox : Dispatch(pair)
    \/ \E w \in Workflows : ReconfigurePolicy(w)
    \/ \E w \in Workflows, e \in Executors : RevokeExecutor(w, e)
    \/ \E w \in Workflows : FenceWorkflowGeneration(w)
    \/ ValidatorFailure
    \/ RecoverValidator
    \/ \E c \in CommitIds : ResponseLoss(c)
    \/ CrashRecover

Spec == Init /\ [][Next]_vars

AuthorityRequiresProof ==
    \A w \in Workflows, n \in Nodes : status[w][n] = "governed_committed" =>
        \E c \in accepted : nodeCommit[w][n] = c /\ decisions[c] = "committed"
StagingInvisible ==
    \A w \in Workflows, n \in Nodes : visible[w][n] =>
        status[w][n] = "governed_committed" /\ ~RevokedClosure(w, n)
AtMostOneCommit ==
    \A w \in Workflows, n \in Nodes :
        Cardinality({c \in accepted : ActiveWorkflow(c) = w /\ ReceiptNode(c) = n}) <= 1
DownstreamSafety ==
    \A w \in Workflows, n \in Nodes : status[w][n] = "ready"
        /\ ~RevokedClosure(w, n) /\ n # Root =>
        \A p \in Pred(n) : status[w][p] = "governed_committed" /\ ~RevokedClosure(w, p)
OutboxAtomicity ==
    \A c \in accepted : <<ActiveWorkflow(c), ReceiptNode(c)>> \in outbox
                       \/ visible[ActiveWorkflow(c)][ReceiptNode(c)]
                       \/ RevokedClosure(ActiveWorkflow(c), ReceiptNode(c))
ReplaySafety == replayDenied \cap accepted = {}
RevocationFence ==
    \A w \in Workflows, n \in Nodes : RevokedClosure(w, n) => ~visible[w][n]
EquivocationDetected == equivocations \subseteq accepted
ConcretePredecessorFence ==
    \A c \in accepted :
        ~RevokedClosure(ActiveWorkflow(c), ReceiptNode(c)) =>
            PredecessorCertificateValid(
                c, ActiveWorkflow(c), ReceiptNode(c))
PostRevocationExecutorFence ==
    \A c \in accepted :
        executorEligible[ActiveWorkflow(c)][ReceiptExecutor(c)]
        \/ ReceiptAgentRevocationEpoch(c) <
           agentRevocationEpoch[ActiveWorkflow(c)][ReceiptExecutor(c)]

CommittedChildLeafWithCertificates ==
    /\ Pred(Child) # {}
    /\ Pred(Leaf) # {}
    /\ decisions[C3] = "committed"
    /\ decisions[C4] = "committed"
    /\ PredecessorCertificateValid(C3, W1, Child)
    /\ PredecessorCertificateValid(C4, W1, Leaf)

ObservedPostRevocationDenial ==
    /\ decisions[C2] = "denied"
    /\ C2 \in revocationDenied
    /\ ~executorEligible[W1][E2]
    /\ agentRevocationEpoch[W1][E2] = 1

CoverageGoalReached ==
    CommittedChildLeafWithCertificates /\ ObservedPostRevocationDenial

\* The coverage config deliberately checks this false invariant. Its exact
\* counterexample is the executable witness that both non-vacuity goals are
\* reachable in one bounded trace; the main safety config never enables it.
CoverageGoalNotReached == ~CoverageGoalReached

Invariant == TypeOK /\ AuthorityRequiresProof /\ StagingInvisible
             /\ AtMostOneCommit /\ DownstreamSafety /\ OutboxAtomicity
             /\ ReplaySafety /\ RevocationFence /\ EquivocationDetected
             /\ ConcretePredecessorFence /\ PostRevocationExecutorFence
=============================================================================
