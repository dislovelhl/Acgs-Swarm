# Migrating to constitutional_swarm v0.3.0

## Breaking: `register_agent()` removed

`register_agent()` is gone. Calling it raises `AttributeError`.

### Why

The old API accepted either a public key or a private key in a single method,
creating ambiguity about where signing happened. The replacement forces you to
declare intent explicitly:

- `register_local_signer()` — this process holds the private key and signs on
  behalf of the agent.
- `register_remote_agent()` — only the public key is known here; the remote
  peer signs its own votes externally.

### Migration table

| Old parameter        | New method                                    |
|----------------------|-----------------------------------------------|
| `vote_private_key=`  | `register_local_signer(..., vote_private_key=...)` |
| `vote_public_key=`   | `register_remote_agent(..., vote_public_key=...)` |
| neither key          | `register_local_signer(...)` (auto-generates key) |

### Before (v0.2.x)

```python
# Public-key-only peer
mesh.register_agent("agent-1", domain="safety", vote_public_key=pub_key)

# Local signer (was rejected in 0.2.x — private key not accepted)
mesh.register_agent("agent-2", domain="safety")
```

### After (v0.3.0)

```python
# Public-key-only peer (signing happens outside this process)
mesh.register_remote_agent("agent-1", domain="safety", vote_public_key=pub_key)

# Local signer (this process holds and uses the private key)
mesh.register_local_signer("agent-2", domain="safety")

# Local signer with an existing key
mesh.register_local_signer("agent-3", domain="safety", vote_private_key=priv_key)
```

### Key persistence note

`register_local_signer()` without `vote_private_key=` auto-generates a new Ed25519
key **per process**. The key is held in memory only — it does not persist across
restarts. If your agents need a stable identity across process restarts, generate the
key yourself and pass it explicitly:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Generate once and persist (e.g. to a secrets manager or env var)
priv_key = Ed25519PrivateKey.generate()
mesh.register_local_signer("agent-2", domain="safety", vote_private_key=priv_key)
```

### `unregister_agent()` is unchanged

`unregister_agent(agent_id)` still exists and removes whichever registration is
present (local signer or remote peer). There is no separate `unregister_local_signer()`
or `unregister_remote_agent()` — `unregister_agent()` covers both cases.

## 0.3 -> 1.0

### `transport_security`

The old `ssl_context: SSLContext | None = None` parameter is now derived from
`transport_security: "plaintext" | "tls" | "auto"`.

- Passing both `ssl_context` and `transport_security` now raises `ValueError`.
- Non-localhost plaintext binds are no longer silently allowed.
- Use `transport_security="auto"` (default) to select `tls` for non-loopback
  hosts and plaintext only for loopback, or set `transport_security="tls"`
  explicitly when you need a strict encrypted transport.

### Settlement `schema_version`

Records without `schema_version` are read as v1, and current writers emit v1.
Persisted JSONL and SQLite settlement journals are auto-migrated via
idempotent `ALTER` on load, so no operator action is required.

### Public API narrowing

Advanced names such as `RemoteVoteClient`, `SettlementStore`, and `MeshProof`
remain importable, but they should now be imported from their submodule paths
instead of the top-level package.

Examples:

```python
from constitutional_swarm.remote_vote_transport import RemoteVoteClient
from constitutional_swarm.settlement_store import SettlementStore
```
