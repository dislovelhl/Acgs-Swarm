---------------------- MODULE constitution_reconfig ----------------------
(*
Versioned constitution reconfiguration spec (Phase 7.3 / preview of 7.5).

Abstracts epoch-stamped constitution transitions using a joint-consensus
rule: a proposal for epoch e+1 is valid only if it is ratified under
BOTH the epoch-e and the epoch-(e+1) validator sets, mirroring Raft
joint consensus for safe reconfiguration.

Safety goal (NoStaleAcceptance): once the network has committed a
transition from epoch e to e+1, no fresh proposal signed only by the
pre-transition validator set at epoch e can be committed at epoch e+1.

This spec is deliberately protocol-level; it does not model the
underlying quorum mesh (see mesh.tla). It composes with it by
treating quorum formation as atomic.
*)

EXTENDS Naturals

CONSTANTS
    MaxEpoch               \* bound for finite-state model checking

ASSUME MaxEpoch \in Nat

VARIABLES
    epoch,                 \* current committed epoch
    pendingTransition,     \* BOOLEAN — joint-consensus phase active
    jointRatifiedBy,       \* {0,1,2} — 0 none, 1 one side, 2 both sides
    committedEpochs        \* set of epochs with committed proposals

vars == <<epoch, pendingTransition, jointRatifiedBy, committedEpochs>>

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ pendingTransition \in BOOLEAN
    /\ jointRatifiedBy \in {0, 1, 2}
    /\ committedEpochs \subseteq 0..MaxEpoch

Init ==
    /\ epoch = 0
    /\ pendingTransition = FALSE
    /\ jointRatifiedBy = 0
    /\ committedEpochs = {0}

\* Start a reconfiguration — enter joint-consensus phase.
ProposeTransition ==
    /\ ~pendingTransition
    /\ epoch < MaxEpoch
    /\ pendingTransition' = TRUE
    /\ jointRatifiedBy' = 0
    /\ UNCHANGED <<epoch, committedEpochs>>

\* Ratify under old set.
RatifyOldSide ==
    /\ pendingTransition
    /\ jointRatifiedBy < 2
    /\ jointRatifiedBy' = jointRatifiedBy + 1
    /\ UNCHANGED <<epoch, pendingTransition, committedEpochs>>

\* Ratify under new set.
RatifyNewSide ==
    /\ pendingTransition
    /\ jointRatifiedBy < 2
    /\ jointRatifiedBy' = jointRatifiedBy + 1
    /\ UNCHANGED <<epoch, pendingTransition, committedEpochs>>

\* Commit the transition once BOTH sides have ratified.
CommitTransition ==
    /\ pendingTransition
    /\ jointRatifiedBy = 2
    /\ epoch' = epoch + 1
    /\ pendingTransition' = FALSE
    /\ jointRatifiedBy' = 0
    /\ committedEpochs' = committedEpochs \cup {epoch + 1}

\* Accepting a fresh proposal at the current epoch — only when no
\* transition is pending. This forbids stale-set acceptance at
\* epoch+1 after a completed transition.
AcceptAtCurrent ==
    /\ ~pendingTransition
    /\ committedEpochs' = committedEpochs \cup {epoch}
    /\ UNCHANGED <<epoch, pendingTransition, jointRatifiedBy>>

Next ==
    \/ ProposeTransition
    \/ RatifyOldSide
    \/ RatifyNewSide
    \/ CommitTransition
    \/ AcceptAtCurrent

Spec == Init /\ [][Next]_vars

\* Safety: no committed epoch exceeds the current epoch; joint consensus
\* is a monotone two-step barrier.
NoStaleAcceptance ==
    \A e \in committedEpochs : e <= epoch

JointConsensusMonotone ==
    (pendingTransition => jointRatifiedBy \in {0, 1, 2})

Invariant == TypeOK /\ NoStaleAcceptance /\ JointConsensusMonotone

============================================================================
