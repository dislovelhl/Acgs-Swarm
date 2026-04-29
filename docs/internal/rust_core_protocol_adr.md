# ADR: Rust Core Protocol Gate

## Status

Accepted for pre-Rust implementation. No Cargo workspace is allowed until this
contract and its deterministic fixtures are stable.

## Context

The current Python mesh exposes useful behavior through broad compatibility
imports and internal dictionaries. Several byte formats are implementation
details rather than durable protocol contracts:

- `ConstitutionalMesh.build_vote_payload()` signs colon-joined UTF-8 fields.
- `ConstitutionalMesh.build_remote_vote_request_payload()` signs another
  colon-joined field list where content can itself contain colons.
- `ValidationVote.vote_hash`, `MeshProof.root_hash`, and content hashes use
  truncated SHA-256 hex prefixes.
- `SettlementRecord` stores assignment/result snapshots as `dict[str, Any]`
  with `schema_version=1` and recovered-state compatibility.
- Python top-level imports intentionally remain broad for caller compatibility.

Blindly mirroring these shapes in Rust would turn accidental Python internals
into a cross-language ABI. The Rust effort needs a protocol gate first.

## Decision

Add a Python canonical protocol layer in `src/constitutional_swarm/protocol.py`
before creating Rust files. It defines versioned, domain-separated encoders for:

- content hashes
- vote payloads
- remote vote request signing payloads and complete signed envelopes
- `MeshProof`
- settlement records
- SpectralSphere snapshots

The module also exposes legacy encoders for the current Python formats. Legacy
fixtures are compatibility evidence only; Rust must target the canonical v1
encoders unless a later ADR explicitly adopts a legacy format.

Generate and check in a deterministic fixture corpus under
`tests/fixtures/rust_protocol/` with `scripts/generate_rust_protocol_fixtures.py`.
The manifest records a SHA-256 digest for every artifact and must reproduce
identically across two runs.

## Rust Scope

The future Rust core should be standalone and layered:

- `core-model`: typed constitution/rule/result models, `AgentDna`, task and
  artifact primitives.
- `protocol`: canonical v1 encoders/decoders and compatibility fixture verifier.
- `mesh-engine`: assignment, vote verification, quorum, and proof verification.
- `settlement-journal`: typed append-only pending/finalized/recovered events.
- `trust`: deterministic trust math, including SpectralSphere parity.
- `python-bridge`: optional later adapter, not part of v0.1.

The Rust design must not inherit Python's broad top-level façade. Compatibility
stays in Python until the bridge phase.

## Validation Engine Boundary

`acgs-lite` remains the source of truth for constitutional validation semantics
in Phase 0 and Phase 1. Rust v0.1 may proceed only after one of these options is
chosen in a follow-up ADR:

- Rust owns a documented schema subset and fixture parity for that subset.
- Rust consumes Python-generated validation fixtures but does not claim semantic
  ownership.
- Rust waits for an upstream Rust validation engine.

Until then, fixture validation results are evidence snapshots, not a declaration
that Rust owns the full `acgs-lite` policy semantics.

## Determinism Requirements

The Rust parity gate requires injectable clock, RNG, ID generator, key provider,
and hash policy. Fixtures pin:

- assignment IDs
- timestamps
- Ed25519 keys and signatures
- nonce replay rejection
- proof roots and vote hashes
- settlement JSONL/SQLite row payloads
- SpectralSphere projection snapshots

## Settlement Model

Rust settlement must be a typed append-only journal, not a nested dictionary
store. It must preserve Python compatibility for `schema_version=1`, including
the existing invariant that missing `schema_version` reads as v1. The typed
event model should cover pending, finalized, recovered, and reconciliation
report events.

## Non-Goals

Phase 0 and Phase 1 do not add Cargo, PyO3, network transport, Bittensor,
SQLite/JSONL Rust adapters, SWE-Bench, latent DNA, ODE research modules, or a
Rust `acgs-lite` replacement.

## Verification

- `tests/test_protocol_canonicalization.py` checks legacy payload parity with
  the current Python mesh and domain separation for canonical encoders.
- The fixture generator is run twice in temporary directories and byte-compared.
- Checked-in fixtures are compared against freshly generated fixtures.
- Python top-level import compatibility remains untouched.
