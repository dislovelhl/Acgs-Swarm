<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->

# security

## Purpose
Regression tests for specific security findings. Each file corresponds to a tracked finding (numbered) to ensure the fix stays in place. Referenced by `security-audit-report.md` at the repo root.

## Key Files
| File | Description |
|------|-------------|
| `test_finding_001_unauth_ws.py` | Regression for Finding 001 — unauthenticated WebSocket gossip endpoint must reject peers without a valid Ed25519 handshake |

## For AI Agents

### Working In This Directory
- **Never delete** a `test_finding_*.py` file — these are permanent regression guards. If a finding is superseded, add a new numbered file and document the deprecation in `security-audit-report.md`.
- Name new files `test_finding_<NNN>_<short_slug>.py` with a zero-padded numeric id.
- Each test should clearly reproduce the original vulnerable condition and assert that current code raises/refuses as expected.

### Testing Requirements
- Collected automatically by the main `pytest tests/` run (recursion into `security/`).
- WebSocket finding tests require `.[transport]` extra.

## Dependencies

### Internal
- `constitutional_swarm.gossip_protocol` (Finding 001)
- `constitutional_swarm.mesh` (auth paths)

<!-- MANUAL: -->
