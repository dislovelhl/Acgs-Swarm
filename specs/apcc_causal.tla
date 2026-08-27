--------------------------- MODULE apcc_causal ---------------------------
EXTENDS FiniteSets, Naturals, Sequences

CONSTANT Ablation
Safe == "SAFE"
\* Bounded scope: a root, parent, and grandparent form a depth-two chain.
\* Root and parent both reference grandparent, exercising shared-ancestor checks.
ValidResolver == "VALID_RESOLVER"
MalformedResolver == "MALFORMED_RESOLVER"
ResolverMissing == "RESOLVER_MISSING"
ResolverError == "RESOLVER_ERROR"
InvalidReturnedValue == "INVALID_RETURNED_VALUE"
EdgeFieldMismatch == "EDGE_FIELD_MISMATCH"
DigestMismatch == "DIGEST_MISMATCH"
CycleOrAlias == "CYCLE_OR_ALIAS"
DepthExceeded == "DEPTH_EXCEEDED"
CountExceeded == "COUNT_EXCEEDED"
BytesExceeded == "BYTES_EXCEEDED"
CaseOrder == <<ValidResolver, MalformedResolver, ResolverMissing, ResolverError,
 EdgeFieldMismatch, DigestMismatch, CycleOrAlias, DepthExceeded, CountExceeded,
 BytesExceeded, InvalidReturnedValue>>
Cases == {CaseOrder[i] : i \in 1..Len(CaseOrder)}
Digests == {"root", "parent", "grandparent"}
MaxDepth == 2
MaxCertificates == 3
MaxBytes == 30

Ref(d) == [workflow_id |-> "workflow1", node_id |-> "node-" \o d,
 committed_node_version |-> 1, commit_id |-> "commit-" \o d,
 certificate_digest |-> d, output_digest |-> "output-" \o d]
BadRef(d) == [Ref(d) EXCEPT !.output_digest = "wrong-output"]
Children(d, x) == CASE d = "root" /\ x = CycleOrAlias -> <<Ref("parent")>>
 [] d = "root" ->
   <<IF x = EdgeFieldMismatch THEN BadRef("parent") ELSE Ref("parent"),
     Ref("grandparent")>>
 [] d = "parent" -> <<Ref("grandparent")>>
 [] d = "grandparent" /\ x = CycleOrAlias -> <<Ref("parent")>>
 [] OTHER -> <<>>
Certificate(d, x) == [workflow_id |-> "workflow1", node_id |-> "node-" \o d,
 committed_node_version |-> 1, commit_id |-> "commit-" \o d,
 certificate_digest |-> d, output_digest |-> "output-" \o d,
 predecessors |-> Children(d, x)]
Envelope(d, x) == [resolvedEnvelope |-> TRUE, payload_digest |-> d,
 certificate |-> Certificate(d, x), byteLength |-> 10]
ResolverKind(x, d) ==
 IF d # "parent" THEN "FOUND"
 ELSE CASE x = ResolverMissing -> "MISSING"
       [] x = ResolverError -> "ERROR"
       [] x \in {MalformedResolver, InvalidReturnedValue} -> "INVALID"
       [] OTHER -> "FOUND"
Resolve(x, d) == IF x = DigestMismatch /\ d = "parent"
 THEN Envelope("grandparent", x) ELSE Envelope(d, x)
DepthLimit(x) == IF x = DepthExceeded THEN 1 ELSE MaxDepth
CountLimit(x) == IF x = CountExceeded THEN 2 ELSE MaxCertificates
ByteLimit(x) == IF x = BytesExceeded THEN 20 ELSE MaxBytes
Frame(ref, depth, path) == [digest |-> ref.certificate_digest,
 expected |-> ref, depth |-> depth, activePath |-> path]
Frames(refs, depth, path) == [i \in 1..Len(refs) |-> Frame(refs[i], depth, path)]
SixFields(c) == [workflow_id |-> c.workflow_id, node_id |-> c.node_id,
 committed_node_version |-> c.committed_node_version, commit_id |-> c.commit_id,
 certificate_digest |-> c.certificate_digest, output_digest |-> c.output_digest]
sixFieldsMatch(c, ref) == SixFields(c) = ref
InitialWork(x) == Frames(Children("root", x), 1, {"root"})
InitialHistory == {[digest |-> "root", wellFormed |-> TRUE, digestOK |-> TRUE,
 edgeOK |-> TRUE, cycleFree |-> TRUE, charged |-> TRUE]}

VARIABLE caseIndex, worklist, visited, history, depthUsed,
 certificateCount, totalBytes, result, evidence
vars == <<caseIndex, worklist, visited, history, depthUsed,
 certificateCount, totalBytes, result, evidence>>

Init == /\ caseIndex = 1
 /\ worklist = InitialWork(CaseOrder[1])
 /\ visited = {"root"} /\ history = InitialHistory /\ depthUsed = 0
 /\ certificateCount = 1 /\ totalBytes = 10
 /\ result = [x \in Cases |-> "PENDING"]
 /\ evidence = [x \in Cases |-> [visited |-> {}, history |-> {}, depthUsed |-> 0,
      certificateCount |-> 0, totalBytes |-> 0]]

FinishWithHistory(x, code, finalHistory) ==
 /\ result' = [result EXCEPT ![x] = code]
 /\ evidence' = [evidence EXCEPT ![x] = [visited |-> visited, history |-> finalHistory,
      depthUsed |-> depthUsed, certificateCount |-> certificateCount,
      totalBytes |-> totalBytes]]
 /\ caseIndex' = caseIndex + 1
 /\ IF caseIndex < Len(CaseOrder)
       THEN /\ worklist' = InitialWork(CaseOrder[caseIndex + 1])
            /\ visited' = {"root"} /\ history' = InitialHistory /\ depthUsed' = 0
            /\ certificateCount' = 1 /\ totalBytes' = 10
       ELSE UNCHANGED <<worklist, visited, history, depthUsed,
                         certificateCount, totalBytes>>

Record(frame, wellFormed, digestOK, edgeOK, cycleFree, charged) ==
 [digest |-> frame.digest, wellFormed |-> wellFormed, digestOK |-> digestOK,
  edgeOK |-> edgeOK, cycleFree |-> cycleFree, charged |-> charged]

ResolveHead == LET x == CaseOrder[caseIndex] IN LET frame == Head(worklist) IN
 LET kind == ResolverKind(x, frame.digest) IN
 IF frame.digest \in frame.activePath
 THEN FinishWithHistory(x, "INVALID_PREDECESSOR",
        history \cup {Record(frame, TRUE, TRUE, TRUE, FALSE, FALSE)})
 ELSE IF frame.depth > DepthLimit(x)
 THEN FinishWithHistory(x, "DEPTH_LIMIT_EXCEEDED", history)
 ELSE IF kind \in {"MISSING", "ERROR", "INVALID"}
      THEN FinishWithHistory(x, "INVALID_PREDECESSOR",
             history \cup {Record(frame, FALSE, FALSE, FALSE, TRUE, FALSE)})
 ELSE LET env == Resolve(x, frame.digest) IN
      LET wellFormed == env.resolvedEnvelope = TRUE IN
      LET digestOK == env.payload_digest = frame.digest /\
                       env.certificate.certificate_digest = frame.digest IN
      LET edgeOK == sixFieldsMatch(env.certificate, frame.expected) IN
      LET cycleFree == frame.digest \notin frame.activePath IN
      LET bypass == Ablation = "CAUSAL_EDGE" /\ x = EdgeFieldMismatch IN
      IF ~(wellFormed /\ digestOK /\ (edgeOK \/ bypass) /\ cycleFree)
       THEN FinishWithHistory(x, "INVALID_PREDECESSOR",
              history \cup {Record(frame, wellFormed, digestOK, edgeOK, cycleFree, FALSE)})
      ELSE IF frame.digest \in visited
       THEN /\ worklist' = Tail(worklist)
            /\ history' = history \cup
                   {Record(frame, wellFormed, digestOK, edgeOK, cycleFree, FALSE)}
            /\ UNCHANGED <<caseIndex, visited, depthUsed, certificateCount,
                            totalBytes, result, evidence>>
      ELSE IF certificateCount + 1 > CountLimit(x) \/
              totalBytes + env.byteLength > ByteLimit(x)
       THEN FinishWithHistory(x, "SIZE_LIMIT_EXCEEDED",
              history \cup {Record(frame, wellFormed, digestOK, edgeOK, cycleFree, FALSE)})
      ELSE /\ worklist' = Tail(worklist) \o
                  Frames(env.certificate.predecessors, frame.depth + 1,
                         frame.activePath \cup {frame.digest})
           /\ visited' = visited \cup {frame.digest}
           /\ history' = history \cup
                  {Record(frame, wellFormed, digestOK, edgeOK, cycleFree, TRUE)}
           /\ depthUsed' = IF frame.depth > depthUsed THEN frame.depth ELSE depthUsed
           /\ certificateCount' = certificateCount + 1
           /\ totalBytes' = totalBytes + env.byteLength
           /\ UNCHANGED <<caseIndex, result, evidence>>

CompleteCase == LET x == CaseOrder[caseIndex] IN
 /\ worklist = <<>> /\ FinishWithHistory(x, "ACCEPT", history)
AllChecked == caseIndex = Len(CaseOrder) + 1
Idle == /\ AllChecked /\ UNCHANGED vars
Next == IF AllChecked THEN Idle ELSE IF worklist = <<>> THEN CompleteCase ELSE ResolveHead
Spec == Init /\ [][Next]_vars

GoodHistory(h) == \A r \in h : r.wellFormed /\ r.digestOK /\ r.edgeOK /\ r.cycleFree
BoundedIndependentCausalVerification == \A x \in Cases :
 result[x] = "ACCEPT" =>
  /\ evidence[x].visited = Digests
  /\ GoodHistory(evidence[x].history)
  /\ evidence[x].depthUsed <= DepthLimit(x)
  /\ evidence[x].certificateCount <= CountLimit(x)
  /\ evidence[x].totalBytes <= ByteLimit(x)
FailClosedResult == \A x \in Cases : result[x] = "ACCEPT" \/
 result[x] \in {"PENDING", "INVALID_PREDECESSOR", "DEPTH_LIMIT_EXCEEDED",
                "SIZE_LIMIT_EXCEEDED"}
SharedAncestorChargedOnce == result[ValidResolver] = "ACCEPT" =>
 evidence[ValidResolver].certificateCount = Cardinality(Digests)
Invariant == BoundedIndependentCausalVerification /\ FailClosedResult /\
 SharedAncestorChargedOnce
WitnessCausalCoverageNotReached == ~(
 result[ValidResolver] = "ACCEPT" /\
 result[DepthExceeded] = "DEPTH_LIMIT_EXCEEDED" /\
 result[CountExceeded] = "SIZE_LIMIT_EXCEEDED" /\
 result[BytesExceeded] = "SIZE_LIMIT_EXCEEDED" /\
 \A x \in Cases \ {ValidResolver, DepthExceeded, CountExceeded, BytesExceeded} :
      result[x] = "INVALID_PREDECESSOR")
=============================================================================
