# APCC-1 task tracker

## Baseline and planning

- [x] Resolve the exact GCB-1 worktree, branch, commit, merge-base, and origin.
- [x] Read root and directory-local source/test/security/docs/spec/script rules.
- [x] Run fresh unmodified `make verify` and `make test-all` baselines.
- [x] Run the pre-existing Mesh, constitution-reconfiguration, GCB safety, and
  GCB non-vacuity TLC gates.
- [x] Check hosted branch/check/workflow evidence for the exact baseline SHA.
- [x] Record `BASELINE_REMOTE_EVIDENCE_INCOMPLETE`.
- [x] Complete a read-only extraction and implementation planning lane.
- [x] Complete current official-source research for PostgreSQL, Psycopg, JCS,
  Go JSON, Ed25519, and the independent-verifier boundary.
- [ ] Complete and approve the architecture lane's protocol/state/store matrix.

## Specification freeze

- [ ] Write `APCC-1-Protocol-Spec.md`.
- [ ] Write `APCC-1-Threat-Model.md`.
- [ ] Write `APCC-1-Security-Properties.md`.
- [ ] Freeze canonical schema, limits, domain separation, and failure codes.
- [ ] Freeze canonical outer envelope and exact byte-level signature preimages.
- [ ] Freeze roles, state machine, operations, and atomic linearization point.
- [ ] Freeze nonce-bound online current-status semantics; defer snapshots.
- [ ] Embed exact reconstructible producer/policy/authority signed bodies.
- [ ] Freeze store-global `commit_id` and cross-workflow conflict handling.
- [ ] Freeze the fair experiment/benchmark plan before final measurements.
- [ ] Run independent protocol-minimality pre-implementation review.

## Core and SQLite realization

- [ ] Capture RED protocol model and import-boundary tests.
- [ ] Implement storage-independent model, interfaces, errors, and operations.
- [ ] Capture RED strict-codec/canonicalization tests and negative vectors.
- [ ] Implement canonical codec and deterministic vector generator.
- [ ] Capture RED signature, binding, tamper, replay, and equivocation tests.
- [ ] Implement producer verification and commit-certificate verification.
- [ ] Implement protocol service and state transitions.
- [ ] Extract the SQLite authority-store adapter.
- [ ] Route GCB and SwarmExecutor through the single APCC commit path.
- [ ] Run SQLite conformance, contention, crash, recovery, revocation, visibility,
  predecessor, response-loss, and outbox tests.

## PostgreSQL and independent verifier

- [ ] Implement PostgreSQL schema and adapter without weakening APCC semantics.
- [ ] Run the shared conformance suite against a real PostgreSQL 17+ service.
- [ ] Add PostgreSQL CI service/gate configuration.
- [ ] Generate positive and negative cross-language conformance vectors.
- [ ] Implement the standalone Go verifier without Python reuse.
- [ ] Run Go unit, RFC vector, APCC vector, formatting, vet, and static checks.
- [ ] Prove Python/Go agreement on every valid and invalid vector.

## Formal, adversarial, and empirical evidence

- [ ] Implement APCC TLA+ safety model and normal configuration.
- [ ] Implement explicit conditional-liveness assumptions/configuration.
- [ ] Implement five exact non-vacuity witnesses and fail-closed runner.
- [ ] Map every formal invariant/action to implementation tests/anchors.
- [ ] Implement fair B0–B6 baselines.
- [ ] Implement the required attack and recovery matrix.
- [ ] Implement the required ablations.
- [ ] Implement and smoke-test the frozen benchmark harness.
- [ ] Run final attacks, recovery scenarios, ablations, and benchmarks.
- [ ] Validate raw result schemas, counts, seeds, environment, and hashes.

## Research, artifacts, reviews, and handoff

- [ ] Write `APCC-1-Prior-Art.md` from current primary sources.
- [ ] Write `APCC-1-Experiment-Plan.md`.
- [ ] Write `APCC-1-Results.md`.
- [ ] Write `APCC-1-Novelty-Verdict.md`.
- [ ] Add one-command reproduction tooling and artifact manifest.
- [ ] Reviewer A: protocol minimality.
- [ ] Reviewer B: formal correctness and non-vacuity.
- [ ] Reviewer C: cryptographic/canonical/cross-language conformance.
- [ ] Reviewer D: novelty and experimental validity.
- [ ] Remediate and re-review every P0/P1 finding.
- [ ] Run the complete repository/APCC verification matrix.
- [ ] Inspect explicit status, diff stat, diff check, and generated/sealed files.
- [ ] Create scoped local commits; confirm no push, PR, release, or deployment.
- [ ] Issue exactly one evidence-bounded novelty classification and final handoff.
