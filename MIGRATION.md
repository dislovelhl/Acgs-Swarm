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
