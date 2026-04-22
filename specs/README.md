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

## Running TLC locally

```bash
# One-time: fetch tla2tools.jar (~4MB)
curl -fsSL -o /tmp/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar

# Mesh (via MC wrapper)
cd specs
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config MeshMC.cfg MeshMC

# Constitution reconfig
java -cp /tmp/tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config constitution_reconfig.cfg constitution_reconfig
```

Both checks should complete in well under a second. `-deadlock`
*disables* deadlock checking (TLC convention; both specs have stable
infinite-enabling `Next` transitions where "deadlock" is not a bug).

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
