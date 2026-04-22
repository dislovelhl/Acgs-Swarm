---------------------------- MODULE mesh ----------------------------
(*
Accountable-quorum mesh spec (Phase 7.3).

Abstracts the mesh down to: a set of validators with stake weights, a
per-proposal quorum collector, and a slashing rule for signatures on
two conflicting proposals in the same epoch.

Safety goal (QuorumAgreement): two valid QCs at the same epoch that
certify conflicting proposals imply that a set of validators whose
aggregate stake ≥ (2f+1) has cast signatures on BOTH proposals. Under
the honest-stake assumption (≥ 2f+1 stake is honest) this is a
contradiction, so two conflicting QCs cannot both be valid without
slashable evidence of ≥ f+1 stake equivocating.

This is a safety-only spec; liveness (quorum eventually formed) is out
of scope for this file and covered by progress assumptions in the
implementation.
*)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Validators,        \* finite set of validator ids
    Proposals,         \* finite set of proposal ids (at the same epoch)
    Stake,             \* [Validators -> Nat \ {0}]
    F                  \* byzantine budget in stake units

ASSUME Stake \in [Validators -> (Nat \ {0})]
ASSUME F \in Nat

TotalStake == LET Sum[s \in SUBSET Validators] ==
                IF s = {} THEN 0
                ELSE LET v == CHOOSE v \in s : TRUE
                     IN Stake[v] + Sum[s \ {v}]
              IN Sum[Validators]

QuorumThreshold == 2 * F + 1   \* classic BFT threshold in stake units

VARIABLES
    signed             \* [Validators -> SUBSET Proposals] — who signed what

vars == <<signed>>

TypeOK ==
    signed \in [Validators -> SUBSET Proposals]

Init ==
    signed = [v \in Validators |-> {}]

\* A validator may sign any proposal at most once per epoch, but is free
\* to sign multiple proposals (equivocate). Equivocation is the trace
\* that slashing must detect.
Sign(v, p) ==
    /\ p \in Proposals
    /\ signed' = [signed EXCEPT ![v] = signed[v] \cup {p}]

Next == \E v \in Validators, p \in Proposals : Sign(v, p)

Spec == Init /\ [][Next]_vars

\* Aggregate stake of validators that signed proposal p.
Supporters(p) == { v \in Validators : p \in signed[v] }
SupportStake(p) ==
    LET Sum[s \in SUBSET Validators] ==
          IF s = {} THEN 0
          ELSE LET v == CHOOSE v \in s : TRUE
               IN Stake[v] + Sum[s \ {v}]
    IN Sum[Supporters(p)]

\* A QC exists for p iff its support stake crosses the BFT threshold.
HasQC(p) == SupportStake(p) >= QuorumThreshold

\* Validators that equivocated across any two distinct proposals.
Equivocators ==
    { v \in Validators :
        \E p1, p2 \in Proposals :
            p1 # p2 /\ p1 \in signed[v] /\ p2 \in signed[v] }

EquivocationStake ==
    LET Sum[s \in SUBSET Validators] ==
          IF s = {} THEN 0
          ELSE LET v == CHOOSE v \in s : TRUE
               IN Stake[v] + Sum[s \ {v}]
    IN Sum[Equivocators]

\* Core safety: two conflicting QCs ⇒ ≥ F+1 stake is slashable.
QuorumAgreement ==
    \A p1, p2 \in Proposals :
        (p1 # p2 /\ HasQC(p1) /\ HasQC(p2)) =>
            EquivocationStake >= F + 1

\* Type invariant + safety.
Invariant == TypeOK /\ QuorumAgreement

============================================================================
