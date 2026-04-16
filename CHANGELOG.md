# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [0.2.0] - 2026-04-16

### Added
- Added `EvolutionLog`, a SQLite-backed append-only governance metric log whose SQLite triggers reject regressions, gaps, and deceleration at write time for capability-curve entries.
- Added remote vote transport primitives so public-key-only peers can validate and sign mesh votes outside the producer process.
- Added remote vote transport tests and evolution log tests, bringing the package test inventory from 38 to 40 files.
- Added self-contained paper build assets so the ICLR 2027 and NDSS 2027 manuscripts compile directly from the repo.

### Changed
- Mesh peers now register explicitly with `register_local_signer(...)` and `register_remote_agent(...)`, and the public docs and examples now match that split.
- Remote vote verification now requires detached signatures, and malformed remote vote responses fail closed instead of coercing types.
- Deterministic DAG node IDs now use explicit collision detection during compiler and DAG node creation.
- The constitutional mesh settlement path now rejects duplicate JSONL settlement appends and avoids persisting raw content in settled records.
- Package guidance, README examples, and paper text now document the new governance and transport behavior.

### Fixed
- Fixed the paper sources so both submissions build cleanly with local vendored template assets and warning-free LaTeX logs.
- Removed tracked Python bytecode caches from the repository and ignored local Codex/OMX session artifacts and generated paper PDFs.

### Removed
- Removed the obsolete `HANDOFF_FORGECODE.md` handoff document.
