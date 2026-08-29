# Independent review — correctness / transactional (v2 continue)

Agent: [Transactional](b1152987-8880-496e-9ce0-41bafaaa5ede)
HEAD: `4ef82a2`. Pair hashes match. Not asked for a close.

**Lane:** REJECT transactional-correctness close of APCC-1.
**CANDIDATE (this lane):** VERDICT UNDETERMINED
P0=0. P1=3. Pair P2s remain visible.

P1:
1. Runner always stamps `LIVE_MEASURED` and `main()` returns 0 even if
   `invalid_authoritative_commits > 0`. Pytest checks the metric; the
   campaign CLI that wrote `campaign-4ef82a2-pgneg` does not.
2. `authoritative` / `second_authority` are return-value-only; no post
   reread / certificate-row count.
3. Four cases are not a transactional suite (no crash, 23505, outbox).

Four-case dispositions matched; `invalid_authoritative_commits=0`. That
is a narrow v2 cell, not a close.
