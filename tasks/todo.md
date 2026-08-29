# GCB-1 task tracker

- [x] Lock repository, branch, starting HEAD, origin, and clean baseline.
- [x] Read root/source/test/security/spec instruction files.
- [x] Run unmodified `make verify` baseline.
- [x] Run unmodified targeted DAG/Mesh/receipt/recovery baseline.
- [x] Run unmodified security-marker baseline.
- [x] Run existing Mesh and constitution-reconfiguration TLC models.
- [x] Inventory all authority-producing and bypass paths.
- [x] Produce directory-local implementation and test plans.
- [x] Add RED bypass and staging-visibility regressions.
- [x] Add explicit governed state model and staged artifact projection.
- [x] Add strict canonical GCB v1 signed receipts.
- [x] Add SQLite governed state schema, migrations, and opaque mutator.
- [x] Add linearizable commit command, joint fencing, and idempotency.
- [x] Integrate executor, claim validation, and governed readiness.
- [x] Add recovery, retry, revocation, compensation, and outbox replay.
- [x] Add architecture gates and migrate affected legacy tests.
- [x] Add GCB TLA+ spec, model, config, CI matrix entry, and mapping tests.
- [x] Run targeted GCB/security/concurrency/crash/recovery tests.
- [x] Run full `make verify` and `make test-all`.
- [x] Run TLC for GCB and all pre-existing models.
- [x] Independent reviewer A: bypass closure.
- [x] Independent reviewer B: atomicity and protocol semantics.
- [x] Resolve all P0/P1 findings.
- [x] Create a local commit only if every approval criterion passes.
- [x] Confirm no push, PR, or release occurred.

## GCB-1.1 TLC non-vacuity CI gate

- [x] Accept file scope, fixed TLC v1.7.4 URL/SHA-256, and no-runtime/model guard.
- [x] Capture RED wrapper/parser/workflow regressions.
- [x] Implement strict expected-witness parser and fail-closed runner.
- [x] Add local Make parity target and formal-evidence documentation.
- [x] Split and harden formal CI with checksum verification and retained logs.
- [x] Run unit/static tests and real pinned-TLC integration.
- [x] Run Mesh, constitution-reconfiguration, GCB safety, and GCB witness gates.
- [x] Run `make verify`, format/type/static/diff checks.
- [x] Confirm no generated TLC state, commit, push, PR, or release.
- [x] Capture Reviewer A RED regressions for structured trace and runner failures.
- [x] Close Reviewer A P1/P2 findings and rerun targeted gates.
- [x] Independent Reviewer A re-review passes.
- [x] Independent Reviewer B re-review passes.
