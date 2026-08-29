# Harness smoke on HEAD e2e87f9 (not a campaign run)

These runs used an uncommitted harness. They are not qualification-live
campaign evidence. Campaign measurements start only after the protocol/harness
checkpoint SHA.

| Run | Result |
| --- | --- |
| ql-smoke-b6 | `atomic_commit` without stage/assemble/propose: `DENIED` `RESULT_NOT_STAGED` |
| ql-smoke-b6b | stage of 4096-byte payload onto bootstrap `attempt-1` subject: `STAGED_RESULT_CONFLICT` |
| ql-smoke-b6c | unique `attempt-ql-*` + stage/assemble/propose: `COMMITTED` valid; exact replay same envelope; equivocation `COMMIT_ID_EQUIVOCATION`; tampered producer `INVALID_PRODUCER_SIGNATURE` |

B5 adapter init on this host: 0.83 s; one missing-proof trial 0.013 s, observed `fail-closed`.
