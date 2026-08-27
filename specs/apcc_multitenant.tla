------------------------- MODULE apcc_multitenant -------------------------
EXTENDS FiniteSets, Naturals

CONSTANT Ablation
Safe == "SAFE"
\* Bounded scope: two workflows share one actor identifier and one commit nonce.
\* The nonce namespace is authority-store-global; actor revocation is keyed by
\* (workflow_id, agent_id). One colliding raw target exercises all three typed
\* certificate/actor/workflow revocation namespaces.
Workflows == {"shared-id", "workflow2"}
Actors == {"shared-id"}
Nonces == {"shared-nonce"}
WorkflowActorPairs == Workflows \X Actors
ActorOf(w) == "shared-id"
NonceOf(w) == "shared-nonce"

VARIABLE committed, denied, globalNonceOwner, actorRevoked, consumed,
         actorIsolationObserved, certificateRevoked, workflowRevoked,
         revocationTargetHistory
vars == <<committed, denied, globalNonceOwner, actorRevoked, consumed,
          actorIsolationObserved, certificateRevoked, workflowRevoked,
          revocationTargetHistory>>
Init == /\ committed = {} /\ denied = {}
 /\ globalNonceOwner = [n \in Nonces |-> "none"]
 /\ actorRevoked = {} /\ consumed = {} /\ actorIsolationObserved = FALSE
 /\ certificateRevoked = {} /\ workflowRevoked = {}
 /\ revocationTargetHistory = {}

Commit(w) == /\ w \notin committed \cup denied
 /\ IF globalNonceOwner[NonceOf(w)] = "none" \/ Ablation = "GLOBAL_NONCE"
       THEN /\ committed' = committed \cup {w}
            /\ globalNonceOwner' = [globalNonceOwner EXCEPT ![NonceOf(w)] = w]
            /\ UNCHANGED <<denied, actorRevoked, consumed, actorIsolationObserved,
                            certificateRevoked, workflowRevoked, revocationTargetHistory>>
       ELSE /\ denied' = denied \cup {w}
            /\ UNCHANGED <<committed, globalNonceOwner, actorRevoked, consumed,
                            actorIsolationObserved, certificateRevoked,
                            workflowRevoked, revocationTargetHistory>>
RevokeActor(w) == /\ <<w, ActorOf(w)>> \notin actorRevoked
 /\ actorRevoked' = actorRevoked \cup {<<w, ActorOf(w)>>}
 /\ UNCHANGED <<committed, denied, globalNonceOwner, consumed,
                 actorIsolationObserved, certificateRevoked, workflowRevoked,
                 revocationTargetHistory>>
ActorRevokedFor(w) == IF Ablation = "ACTOR_SCOPE"
 THEN \E pair \in actorRevoked : pair[2] = ActorOf(w)
 ELSE <<w, ActorOf(w)>> \in actorRevoked
Consume(w) == /\ w \notin consumed /\ ~ActorRevokedFor(w)
 /\ consumed' = consumed \cup {w}
 /\ actorIsolationObserved' = (actorIsolationObserved \/
      (w = "workflow2" /\ <<"shared-id", ActorOf(w)>> \in actorRevoked))
 /\ UNCHANGED <<committed, denied, globalNonceOwner, actorRevoked,
                 certificateRevoked, workflowRevoked, revocationTargetHistory>>
RevocationScopes == {"CERTIFICATE", "ACTOR", "WORKFLOW"}
RevokeTyped(scope) == /\ scope \in RevocationScopes
 /\ <<scope, "shared-id">> \notin revocationTargetHistory
 /\ certificateRevoked' =
      (IF scope = "CERTIFICATE" THEN certificateRevoked \cup {"shared-id"}
       ELSE certificateRevoked)
 /\ actorRevoked' =
      (IF scope = "ACTOR" \/ (Ablation = "TARGET_NAMESPACE" /\ scope = "CERTIFICATE")
       THEN actorRevoked \cup {<<"shared-id", "shared-id">>} ELSE actorRevoked)
 /\ workflowRevoked' =
      (IF scope = "WORKFLOW" THEN workflowRevoked \cup {"shared-id"}
       ELSE workflowRevoked)
 /\ revocationTargetHistory' = revocationTargetHistory \cup {<<scope, "shared-id">>}
 /\ UNCHANGED <<committed, denied, globalNonceOwner, consumed,
                 actorIsolationObserved>>
AllObserved == "shared-id" \in committed /\ "workflow2" \in denied /\
 <<"shared-id", "shared-id">> \in actorRevoked /\ "workflow2" \in consumed /\
 {r[1] : r \in revocationTargetHistory} = RevocationScopes
Settled == /\ Workflows \subseteq committed \cup denied
 /\ {r[1] : r \in revocationTargetHistory} = RevocationScopes
 /\ ("workflow2" \in consumed \/ ActorRevokedFor("workflow2"))
Idle == /\ Settled /\ UNCHANGED vars
Next == (\E w \in Workflows : Commit(w)) \/
        (\E scope \in RevocationScopes : RevokeTyped(scope)) \/
        Consume("workflow2") \/ Idle
Spec == Init /\ [][Next]_vars

NonceUniqueness == Cardinality(committed) <= 1
ActorRevocationWorkflowScope ==
 <<"shared-id", "shared-id">> \in actorRevoked =>
 ~ActorRevokedFor("workflow2")
RevocationTargetSeparation ==
 /\ ("shared-id" \in certificateRevoked) =
      (<<"CERTIFICATE", "shared-id">> \in revocationTargetHistory)
 /\ (<<"shared-id", "shared-id">> \in actorRevoked) =
      (<<"ACTOR", "shared-id">> \in revocationTargetHistory)
 /\ ("shared-id" \in workflowRevoked) =
      (<<"WORKFLOW", "shared-id">> \in revocationTargetHistory)
Invariant == NonceUniqueness /\ ActorRevocationWorkflowScope /\ RevocationTargetSeparation
WitnessMultitenantIsolationNotReached == ~AllObserved
WitnessRevocationTargetsNotReached == ~(
 {r[1] : r \in revocationTargetHistory} = RevocationScopes /\
 "shared-id" \in certificateRevoked /\
 <<"shared-id", "shared-id">> \in actorRevoked /\
 "shared-id" \in workflowRevoked)
=============================================================================
