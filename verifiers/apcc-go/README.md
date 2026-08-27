# Independent APCC-1 Go verifier

This module verifies APCC-1 detached certificates without importing, invoking,
or generating code from the Python implementation. It has two modes:

```bash
go run ./cmd/apcc-verify historical --certificate envelope.json --trust trust.json
go run ./cmd/apcc-verify current --certificate envelope.json --trust trust.json \
  --authority-status status.json --request-nonce NONCE --now-ms UNIX_MS \
  --highest-trust-log-sequence SEQUENCE --highest-trust-log-head DIGEST \
  --maximum-staleness-ms BOUND
```

Every invocation writes exactly one compact JSON object. Verification success
exits `0`, protocol rejection exits `1`, and CLI/I/O misuse exits `2`.

The historical mode proves canonical bytes, certificate and statement digests,
role-scoped signatures, internal bindings, predecessor-root consistency, and
attestation validity at commit time. Current mode additionally proves one
nonce-bound signed status relative to caller-supplied time, staleness, and
trust-log high-water values.

An offline verifier cannot prove database linearization, current logical-node
pointers, predecessor currency, or complete transitive revocation state. Those
claims require the authority store. A valid historical certificate proves only
history; current consumption requires a fresh status from that store.
