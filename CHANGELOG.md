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
- A URI/read-barrier-based `ReadOnlyProject` and storage-aware `InspectionService` for source/continuity-safe claim and event impact reports, versioned as `continuityforge.source-impact/v0.3-alpha` with both snapshot hashes and no source body/quote fields.
- Bounded endpoint-only impact inspection with snapshot hash/line-count verification, global ledger and affected-claim authority replay, batched exact matching, and metadata injection controls.
- Unreleased `source-impact`, `migration-check`, and `migrate` alpha CLI commands with metadata-first JSON reports.
- Alpha package metadata plus coverage-gated Linux/Windows/macOS CI, Python 3.10–3.14 coverage, distribution inspection, clean-wheel installation, and demo smoke tests.
- v0.3 architecture, threat-model, migration, backup/restore, data-model, security-testing, and demo-license documentation.
- Original North Pier v1/v2 revision-impact fixtures.

### Pre-release limitations

- v0.3.0a1 has not been released and new command/report schemas may change.
- Restore and deployment activation remain operator workflows; there is no restore CLI.
- HTTP, MCP, provider adapters, semantic impact, and automatic governance changes remain deferred.

### Security

- Documented the trusted operating-system/SQLite-owner boundary.
- Defined metadata-first administrative reports that omit complete source bodies by default.
- Preserved the operator-only `NarrativeEvent` boundary and report-only impact behavior.

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
