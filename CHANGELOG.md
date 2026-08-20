# Changelog

All notable changes to ContinuityForge are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use semantic versioning.

## [Unreleased]

### Added

- Pure-domain SourceSnapshot impact analysis with frozen reports and deterministic outcomes: `SAME_POSITION`, `EXACT_MOVED_UNIQUE`, `EXACT_MOVED_AMBIGUOUS`, `NO_EXACT_MATCH`, and `INVALID_EVIDENCE`.
- Stable candidate ordering and linear-time exact line-sequence matching, including overlapping multi-line matches.
- Strict built-in-integer evidence coordinates; booleans, numeric strings, `IntEnum`, and integer subclasses are rejected.
- Bounded source-ingestion policy with decoding, file/line limits, duplicate-JSON-key rejection, and NUL, ANSI, bidirectional-control, and invalid-Unicode checks.
- Governance authority-chain verification before an `AUTHORIZED` claim is eligible for compilation.
- Narrative-event creation/evidence audit replay and pinned-snapshot Memory Pack compilation.
- Strict, bounded RFC-compatible JSON for operator event details across CLI, Python API, migration, and inspection.
- Strict schema fingerprinting and a write-free `migration-check` preflight for existing databases.
- Backup-gated, transactional v0.1/v0.2 to v0.3 migration through the unreleased `migrate` command.
- Explicit v0.1 quarantine mode that preserves each malformed row in legacy storage without creating an active domain row; malformed v0.2 data still blocks migration.
- A URI/read-barrier-based `ReadOnlyProject` and storage-aware `InspectionService` for source/continuity-safe claim and event impact reports, versioned as `continuityforge.source-impact/v0.3` with both snapshot hashes and no source body/quote fields.
- Bounded endpoint-only impact inspection with snapshot hash/line-count verification, global ledger, affected-claim authority, and affected-event creation-audit replay, batched exact matching, and metadata injection controls.
- Unreleased `source-impact`, `migration-check`, and `migrate` CLI commands with metadata-first JSON reports and formal v0.3 machine contracts.
- Explicit create-capable, write-existing, read-existing, and explicit-migrate CLI lifecycles, with stable missing-database and migration-required errors.
- Alpha package metadata plus coverage-gated Linux/Windows/macOS CI, Python 3.10-3.14 coverage, wheel/sdist inspection, clean-wheel installation, an unpacked-sdist North Pier smoke test, and a deterministic `SHA256SUMS` release manifest.
- v0.3 architecture, threat-model, migration, backup/restore, data-model, security-testing, and demo-license documentation.
- Original North Pier v1/v2 revision-impact fixtures.

### Changed

- Ordinary read, validation, compile, list, ledger, governance, and event commands no longer initialize or migrate a database as a side effect; legacy upgrades require the explicit `migrate` path.
- `NO_EXACT_MATCH` documentation now states only that the old continuous exact quote is absent. It does not label the cause as editing, deletion, truncation, or line restructuring.
- Source distributions now include the core documentation set, license notices, formal schemas, the release coverage checker, and executable North Pier fixtures while excluding tests and database/credential-like artifacts.

### Fixed

- Source-impact now replays the same complete event audit used by compiler and validator, in one bounded batch inside the pinned read transaction; divergent affected events fail with `EVENT_AUDIT_INVALID`.
- Existing-database commands now return `DATABASE_NOT_FOUND` for a missing target without creating the database, parent directory, or SQLite sidecars.
- Read-only CLI, Storage, and migration-preflight paths now reject an incomplete WAL/SHM sidecar set before SQLite can create a missing SHM file; caller-supplied SQLite URIs are rejected by `Storage.open_readonly`.
- Migration backups are bound to the locked source through a streamed logical-database digest, and temporary-file identity is rechecked before any backup page is written.

### Pre-release limitations

- v0.3.0a3 has not been released; its formal v0.3 command/report schemas are
  frozen and distributed with the source archive.
- Restore and deployment activation remain operator workflows; there is no restore CLI.
- HTTP, MCP, provider adapters, semantic impact, and automatic governance changes remain deferred.

### Security

- Documented the trusted operating-system/SQLite-owner boundary.
- Defined metadata-first administrative reports that omit complete source bodies by default.
- Preserved the operator-only `NarrativeEvent` boundary and report-only impact behavior.
- Hardened migration backups with unpredictable same-directory temporary files, identity/type verification, POSIX `0600`, collision-safe no-replace publication, and symbolic-link rejection.
- Enforced 80% combined coverage, 75% global branch coverage, 80% trusted-module branch coverage, explicit critical-branch/file gates, and both direct `ResourceWarning` and pytest unraisable-warning failures across the CI matrix.

## [0.2.0] - 2026-08-19

### Added

- Immutable, ordered `SourceSnapshot` versions for logical sources.
- Evidence quote and SHA-256 validation using 1-based inclusive line spans.
- LLM-proposes-only `ClaimProposal` workflow.
- Explicit `AUTHORIZED`, `REJECTED`, and `DISPUTED` governance decisions.
- Source-backed `NarrativeEvent` values for human/operator workflows.
- Database-wide append-only EventLedger hash chain and verification.
- Persona-, continuity-, access-, valid-time-, and knowledge-time-aware Memory Pack compilation.
- SQLite migration support for the frozen v0.1 schema.
- Alpha/Beta isolation and future-knowledge demo.

### Compatibility

- Retained the v0.1 `ingest -> claim-add -> validate -> compile` loop and Memory Pack compatibility fields.
- Added a byte-locked v0.1 contract regression gate.

## [0.1.0] - 2026-08-19

### Added

- TXT, Markdown, JSON, and SRT source ingestion.
- Content-addressed snapshots and line-level source spans.
- Claim persona/continuity isolation, knowledge cutoff, access policy, SQLite persistence, validation, and JSON compilation.
