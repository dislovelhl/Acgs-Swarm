# Runtime Optimization Report

**Date:** 2026-04-24
**Branch:** `improve/test_coverage` — merged to `main` via PR #20 (2026-04-24T10:07:52Z)
**Method:** `python -X importtime`, `python -m pytest`, source inspection

---

## Baseline

| Metric | Value |
|--------|-------|
| Test suite | 1603 passed, 1 skipped, 2 xfailed in 15.39s |
| Cold-start import (`import constitutional_swarm`) | **4,204,261 µs ≈ 4.2s** |
| Import measured with | `python -X importtime -c "import constitutional_swarm"` |

The 4.2s cold start is dominated by the bittensor dependency chain loaded unconditionally through `mac_acgs_loop.py`. The mesh and transport packages import efficiently once bittensor is excluded.

---

## Files Inspected

- `src/constitutional_swarm/__init__.py`
- `src/constitutional_swarm/mac_acgs_loop.py`
- `src/constitutional_swarm/mesh/__init__.py` and `mesh/core.py`
- `src/constitutional_swarm/remote_vote_transport/__init__.py`
- `src/constitutional_swarm/violation_subspace.py`
- `src/constitutional_swarm/manifold.py`
- `src/constitutional_swarm/mesh.py` (untracked)
- `src/constitutional_swarm/remote_vote_transport.py` (untracked)

---

## Bottlenecks Found

### B1 — `mac_acgs_loop.py:43`: Unconditional bittensor import (HIGH)

```
import time:       599 |     457,472 |   constitutional_swarm.mac_acgs_loop
                                      └─ constitutional_swarm.bittensor.came_coordinator (full chain)
import time:     3,428 |     337,912 |         constitutional_swarm.bittensor.synapse_adapter
import time:    82,985 |      82,985 |         constitutional_swarm.bittensor.compliance_certificate
```

`mac_acgs_loop.py` line 43:
```python
from constitutional_swarm.bittensor.came_coordinator import (
    CAMECoordinator, ...
)
```

This unconditionally pulls the entire `bittensor/` subpackage into every `import constitutional_swarm`, including `synapse_adapter` (337ms cumulative) and `compliance_certificate` (83ms self-time). Bittensor is an **optional extra** (`pip install constitutional-swarm[bittensor]`).

**Stated convention** (root AGENTS.md): *"Keep core import-free of [optional extras]."*

This import violates that convention. When bittensor is installed, it adds ~458ms (≈11%) to cold start even for non-bittensor workloads.

**Recommended fix** — lazy import inside the method that uses `CAMECoordinator`:

```python
# mac_acgs_loop.py — replace top-level import with:
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator

# Inside the method that constructs/uses it:
def _build_came_coordinator(self, ...) -> "CAMECoordinator":
    from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
    return CAMECoordinator(...)
```

Expected impact: removes ~458ms from every cold start for non-bittensor users. Bittensor users pay the same cost, but only when the CAME path is exercised.

---

### B2 — `remote_vote_transport/__init__.py`: Private symbols in `__all__` (LOW)

The package `__init__.py` exports 9 private (`_*`) symbols via `__all__`:

```python
"_LOOPBACK_HOSTS", "_build_ssl_context", "_format_uri_host",
"_is_loopback_host", "_parse_ws_endpoint", "_resolve_transport_security",
"build_remote_vote_request_payload", "decode_remote_vote_request", ...
```

Private symbols in `__all__` break the public/private contract: tools like `from module import *` and documentation generators will surface them as public API. This does not affect runtime performance but creates API surface confusion.

Additionally, a **duplicate entry** (`"_format_uri_host"` appeared twice) was fixed in this pass.

**Recommended fix:** Remove `_*` entries from `__all__`. Keep them importable but not advertised.

---

### B3 — Shadowed flat module files (INFORMATIONAL)

Two untracked files exist alongside their package directories:

| Flat file | Package | Resolution |
|-----------|---------|------------|
| `src/constitutional_swarm/mesh.py` (1771 lines, untracked) | `src/constitutional_swarm/mesh/` | Package wins — `mesh.py` is **never loaded** |
| `src/constitutional_swarm/remote_vote_transport.py` (293 lines, untracked) | `src/constitutional_swarm/remote_vote_transport/` | Package wins — `.py` file is **never loaded** |

Verified empirically:
```
>>> import constitutional_swarm.mesh
>>> constitutional_swarm.mesh.__file__
'.../constitutional_swarm/mesh/__init__.py'   # package, not flat file
```

These files are on branch `improve/test_coverage` as untracked work in progress. No runtime impact — Python's FileFinder always prefers a package directory over a same-named module file. Document as pending integration, not dead code.

---

### B4 — Eager `__init__.py` imports (LOW, known trade-off)

`__init__.py` imports all ~20 top-level modules unconditionally. This is intentional (single-import public API) and the comment explains it:

```python
# Keep broad top-level imports for compatibility with existing tests and callers,
# but advertise only the stable 1.0 surface via __all__.
```

No action recommended. If startup latency becomes a constraint for non-bittensor users, a lazy `__getattr__`-based `__init__.py` would be the right mechanism — but the bittensor fix (B1) should be implemented first since it is the dominant cost.

---

## Changes Made in This Pass

| Change | File | Risk |
|--------|------|------|
| Removed duplicate `"_format_uri_host"` from `__all__` | `remote_vote_transport/__init__.py` | None — duplicate entry, no behavior change |

---

## Tests Run After Changes

```
python -m pytest tests/ --import-mode=importlib -q
→  1603 passed, 1 skipped, 2 xfailed in 13.02s  ✓ (no regression)
```

---

## Before / After

| Metric | Before | After |
|--------|--------|-------|
| Duplicate `__all__` entry | `"_format_uri_host"` listed twice | Fixed |
| Test suite (full run) | 1603/1 skip/2xfail, 15.39s | 1603/1 skip/2xfail, 13.02s ✓ |
| Cold-start (bittensor import leak) | ~458ms overhead | **Not fixed yet** — see B1 recommendation |

---

## Remaining Performance Risks

1. **B1 (HIGH):** `mac_acgs_loop.py` bittensor import — 458ms overhead on every cold start when bittensor is installed. Fix is low-risk (lazy import) but touches a non-trivial module; recommended for a follow-up PR.

2. **`bittensor/compliance_certificate.py`** (83ms self-time) is the single heaviest module in the bittensor chain. If bittensor startup is still slow after the B1 fix, this file is the next profiling target.

3. **`mesh/core.py` size** (71k bytes): The mesh package split is architecturally sound and imports cleanly (12ms). Size is not a runtime concern, but the untracked `mesh.py` flat file (1771 lines) may indicate a pending consolidation effort. Resolve before the next release cut.

---

## Next Recommended Optimizations

1. **Fix B1** — lazy-import `bittensor.came_coordinator` in `mac_acgs_loop.py`. Estimated impact: -458ms cold start for non-bittensor users.
2. **Clean up B2** — remove `_*` symbols from `remote_vote_transport/__init__.py.__all__`. Zero performance impact; API hygiene.
3. **Resolve untracked flat files (B3)** — decide whether `mesh.py` and `remote_vote_transport.py` are (a) meant to replace the packages, (b) scratch work to discard, or (c) compatibility stubs to commit alongside the packages. Currently they have no effect.
4. **Profile test suite** — 15.4s for 1603 tests is reasonable but not fast. The `slow` marker exists; verify it's being applied to the scale tests so `-m "not slow"` gives sub-5s feedback loops.
