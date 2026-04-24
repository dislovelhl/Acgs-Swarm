# Agent Instruction Hierarchy Audit

**Date:** 2026-04-24
**Branch:** `improve/test_coverage`
**Scope:** All agent/LLM instruction files in this package. No `skills/`, `prompts/`, or `.claude/commands/` directories exist here — those live in the parent monorepo. This audit covers the AGENTS.md hierarchy and CLAUDE.md only.

---

## Instruction Files Audited

| File | Lines | Status |
|------|-------|--------|
| `AGENTS.md` (root) | 81 → 57 | **Trimmed** |
| `src/constitutional_swarm/AGENTS.md` | 80 → 54 | **Trimmed** |
| `tests/AGENTS.md` | 75 | Kept as-is |
| `scripts/AGENTS.md` | 34 | Kept as-is |
| `docs/AGENTS.md` | 23 | Kept as-is |
| `examples/AGENTS.md` | 19 | Kept as-is |
| `src/constitutional_swarm/bittensor/AGENTS.md` | 64 | Kept as-is |
| `src/constitutional_swarm/swe_bench/AGENTS.md` | 38 | Kept as-is |
| `src/constitutional_swarm/bittensor/AGENTS.md` | 64 | Kept as-is |
| `src/constitutional_swarm/swe_bench/AGENTS.md` | 38 | Kept as-is |
| `specs/AGENTS.md` | 38 | Kept as-is |
| `paper/AGENTS.md` | 24 | Kept as-is |
| `papers/AGENTS.md` | 26 | Kept as-is |
| `CLAUDE.md` | 88 | Kept as-is (Claude Code only; Codex reads AGENTS.md) |
| `.codex` | 1 | Empty placeholder — no action needed |

---

## Findings and Decisions

### Kept (no change)

**`tests/AGENTS.md`**
- Trigger: agents modifying or adding test files
- Content: per-file test table, xfail documentation, extras-gating guidance
- Decision: kept — the per-file table is a legitimate index for a 60-file test suite. The behavioral notes (xfails are permanent research controls, extras gating) are non-obvious and save agents from mistakes.

**`scripts/AGENTS.md`**
- Trigger: agents adding or modifying operational scripts
- Decision: kept — concise, non-redundant, correct.

**`docs/AGENTS.md`**
- Trigger: agents adding protocol documentation
- Decision: kept — 23 lines, focused.

**`examples/AGENTS.md`**
- Trigger: agents touching sample constitution or examples
- Decision: kept — 19 lines, focused.

**`bittensor/AGENTS.md`**
- Trigger: agents working in the bittensor subpackage
- Content: thread-safety invariants, two-phase commit pattern, quorum constants
- Decision: kept — encodes critical constraints that are non-obvious from code alone (lock acquisition protocol, arweave retry state machine).

**`swe_bench/AGENTS.md`**
- Trigger: agents modifying the SWE-Bench evaluation scaffold
- Decision: kept — appropriately scoped.

**`CLAUDE.md`**
- Consumed by Claude Code only. Contains the module map, key invariants, and test commands. No overlap with AGENTS.md content that would confuse Codex agents. Kept as-is.

---

### Trimmed

**`AGENTS.md` (root) — 81 → 57 lines**

Removed:
1. `<!-- Generated: ... | Updated: ... -->` HTML comment — noise with no agent value.
2. Six gitignored session-artifact entries from the Key Files table:
   - `security-audit-report.md` (matches `.gitignore: *-report.md`)
   - `delivery-hygiene-report.md` (same)
   - `style-improvement-report.md` (same)
   - `test-coverage-report.md` (same)
   - `SYSTEMIC_IMPROVEMENT.md` (explicitly gitignored)
   - `HANDOFF_CODEX.md` (matches `.gitignore: HANDOFF_*.md`)
   - These files are not tracked in git; advertising them in AGENTS.md implies they are permanent repo fixtures.
3. `README.md`, `CHANGELOG.md` entries — self-evident from file names; no behavioral guidance added.
4. Entire "Dependencies" section — pyproject.toml is authoritative; the AGENTS.md copy was already out of sync.

Fixed:
- Test count: "1019 passed, 2 xfailed" → "1603 passed, 1 skipped, 2 xfailed" (verified against actual run).

**`src/constitutional_swarm/AGENTS.md` — 80 → 54 lines**

Removed:
- 30-row Key Files table replaced with 6-row "Agent-Critical Files" table. The full module inventory is in `README.md`; the AGENTS.md version was a stale duplicate. Kept only entries with behavioral guidance that an agent cannot infer from reading the code (research control, import boundary violation, Greek-character ruff suppression, monotonicity invariant).
- "Dependencies" section — same rationale as root AGENTS.md.

Added:
- Explicit note on `mac_acgs_loop.py` bittensor import boundary violation (line 43) — this is an active performance bug agents should know about before modifying that file. See `docs/RUNTIME_OPTIMIZATION_REPORT.md` for measurement.

---

## Redundancy Map

The following content exists in multiple places. The table shows where each is authoritative and where it was removed:

| Content | Authoritative source | Removed from |
|---------|---------------------|--------------|
| Package dependencies | `pyproject.toml` | Root and src AGENTS.md |
| Module inventory | `README.md` | `src/constitutional_swarm/AGENTS.md` |
| Test commands | `CLAUDE.md` (testing section) | Not duplicated further |
| Constitutional hash | `constants.py` + all AGENTS.md files | Not changed — hash appears in multiple places intentionally as a quick-reference invariant |

---

## Remaining Risks

1. **OMX regeneration risk (investigated and mitigated):** The `<!-- Generated: 2026-04-20 | Updated: 2026-04-20 -->` headers were written by **OMX** (oh-my-codex, `.omx/`) in a single scaffolding run on 2026-04-20. Each original file ended with a `<!-- MANUAL: ... -->` marker — the OMX generator preserves content *below* that line and overwrites content *above* it. Our trimmed files had dropped the marker; it has been restored to both `AGENTS.md` (root) and `src/constitutional_swarm/AGENTS.md`. **Caveat:** our trimmed content (table reductions, test count fix, mac_acgs_loop warning) sits *above* the MANUAL line — in the auto-generated zone — so a full OMX regeneration would overwrite it. To make these changes permanent: either update the OMX generator template before re-running, or move critical notes (especially the mac_acgs_loop warning) to the section below `<!-- MANUAL: -->`. The OMX sessions in `.omx/state/sessions/` read the AGENTS.md files as input context; they do not automatically overwrite them.

2. **`tests/AGENTS.md` test count**: The file says "1019 passed, 2 xfailed" (same stale number as root). Not changed here — the root AGENTS.md is the canonical count reference; subdirectory files should be considered downstream. Update if the subdirectory files are read independently.

3. **`bittensor/AGENTS.md` thread-safety quorum note**: The quorum constants (`min_total_validators=5, min_votes_for_precedent=3`) are stated in the AGENTS.md but live in code. If the defaults change, the AGENTS.md will silently lag. Consider a test that asserts these defaults to make the divergence detectable.

---

## No-Op Items (not skill files)

The following were in scope per the audit request but do not exist in this package:
- `skills/` directory: absent
- `prompts/` directory: absent
- `.claude/commands/`: absent (lives in parent monorepo)
- `.codex`: present but empty (1 byte placeholder); no content to audit
