# TLA+ specifications

Safety specs for the constitutional swarm, exhaustively checked by TLC
in CI (`.github/workflows/tla-check.yml`).

## Specs

- **`mesh.tla`** — accountable-quorum mesh. Invariant `QuorumAgreement`:
  two conflicting QCs at the same epoch imply ≥ F+1 equivocating stake
  (slashable evidence). Model-checked via the wrapper module
  `MeshMC.tla` / `MeshMC.cfg` because TLC's config syntax cannot
  express function literals for the `Stake` constant directly.
- **`constitution_reconfig.tla`** — versioned constitution reconfig with
  joint-consensus barrier. Invariant `NoStaleAcceptance`: no committed
  epoch exceeds the current epoch, and joint-consensus ratification is
  monotone.
- **`governed_commit.tla`** — GCB-1 atomic proof-carrying commit model. Its
  bounded configuration checks single-winner commit, immutable retry decisions,
  fail-closed stale fences, staging invisibility, atomic outbox creation, and
  downstream readiness only after a governed commit. In the SQLite refinement,
  `BEGIN IMMEDIATE` acquires the write fence and successful `COMMIT` is the
  authority linearization point.

## Running TLC locally

```bash
# One-time: fetch tla2tools.jar (~4MB)
curl -fsSL -o /tmp/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
echo '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88  /tmp/tla2tools.jar' \
  | sha256sum -c -

# Mesh (via MC wrapper)
cd specs
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config MeshMC.cfg MeshMC

# Constitution reconfig
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config constitution_reconfig.cfg constitution_reconfig

# Governed commit boundary
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config governed_commit.cfg governed_commit

# GCB reachability witness (same fail-closed wrapper used by CI)
cd ..
make tla-gcb-coverage TLA2TOOLS_JAR=/tmp/tla2tools.jar
```

The mesh and constitution-reconfiguration checks should complete quickly;
the bounded governed-commit safety model explores roughly 4.7 million distinct
states with the pinned TLC v1.7.4 toolchain and may take several minutes. `-deadlock`
*disables* deadlock checking (TLC convention; both specs have stable
infinite-enabling `Next` transitions where "deadlock" is not a bug).

The governed-commit safety and reachability obligations are deliberately
separate. `governed_commit.cfg` must finish with TLC exit code 0 and proves the
bounded safety invariants. `governed_commit_coverage.cfg` intentionally
challenges `CoverageGoalNotReached`; its sole expected violation yields a
counterexample demonstrating that Root, Child, and Leaf commits can precede an
executor revocation and denial of the stale attempt. The repository wrapper
accepts only TLC exit 12 with that one named violation, a complete v1.7.4
counterexample envelope, and the ordered semantic milestones. Any safety
violation, additional violation, malformed output, timeout, or runtime failure
remains fatal.

## Parameter sizing notes

For `mesh.tla` the BFT overlap bound `overlap ≥ F+1` requires
`Total ≤ 3F+1`. The default model uses `Total=4, F=1` (stake `{2,1,1}`).
Increasing total stake beyond 3F+1 makes `QuorumAgreement` fail — that
is a correct counterexample to the *model*, not the spec.

For `constitution_reconfig.tla` the `MaxEpoch` bound controls state-
space size. `MaxEpoch=3` covers two completed transitions and is
enough to exercise all `AcceptAtCurrent` / joint-consensus
interleavings.

## Adding a new spec

1. Write the `.tla` module under `specs/`.
2. Add a matching `.cfg` (or MC wrapper if constants use function
   literals).
3. Extend the matrix in `.github/workflows/tla-check.yml`.
4. Run TLC locally first, then push.
