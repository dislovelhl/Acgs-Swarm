---- MODULE MeshMC ----
(* Model-checking wrapper for mesh.tla. TLC's .cfg syntax cannot express
   function literals for CONSTANT Stake, so we declare concrete validator
   model values here and define Stake concretely. *)

EXTENDS mesh

CONSTANTS v1, v2, v3

StakeDef ==
    [v \in Validators |->
        IF v = v1 THEN 2
        ELSE IF v = v2 THEN 1
        ELSE 1]

====
