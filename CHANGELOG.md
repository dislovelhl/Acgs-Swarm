# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [0.2.0] - 2026-04-16

### Added
- Added `EvolutionLog`, a SQLite-backed append-only governance metric log that rejects regressions, gaps, and deceleration at write time.
- Added remote vote transport primitives so public-key-only peers can validate and sign mesh votes outside the producer process.
- Added remote vote transport tests and evolution log tests, bringing the package test inventory from 38 to 40 files.
- Added self-contained paper build assets for the ICLR 2027 and NDSS 2027 manuscripts so both documents compile directly from the repo.

### Changed
- Switched mesh peer registration to explicit signer modes with `register_local_signer(...)` and `register_remote_agent(...)`, and updated the public docs and examples to match.
- Hardened mesh vote verification so detached vote signatures are required and malformed remote vote responses fail closed instead of coercing types.
- Expanded deterministic DAG node IDs and added explicit collision detection for compiler and DAG node creation.
- Updated the constitutional mesh settlement path to reject duplicate JSONL settlement appends and to avoid persisting raw content in settled records.
- Refreshed package guidance, README examples, and paper text to document the new governance and transport behavior.

### Fixed
- Fixed the paper sources so both submissions build cleanly with local vendored template assets and warning-free LaTeX logs.
- Removed tracked Python bytecode caches from the repository and ignored local Codex/OMX session artifacts and generated paper PDFs.

### Removed
- Removed the obsolete `HANDOFF_FORGECODE.md` handoff document.
