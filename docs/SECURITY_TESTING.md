# Security Testing

This document turns the [threat model](THREAT_MODEL.md) into repeatable tests. It covers the released v0.1/v0.2 contracts and the unreleased v0.3.0a4 implementation. A passing test suite supports the stated boundaries; it does not extend them to a hostile operating-system or database owner.

## Test layers

| Layer | Purpose | Representative location |
|---|---|---|
| Frozen baseline | Preserve v0.1 observable behavior and locked fixture bytes | `tests/baseline/` |
| v0.2 regression | Protect versioning, evidence, governance, ledger, compiler, CLI, and migration behavior | `tests/` |
| Strict evidence | Reject non-built-in integers and malformed spans | `tests/v03/evidence/` |
| Authority/event integrity | Detect missing, contradictory, or evidence-divergent audit history | `tests/v03/governance/` |
| Audit Material v2 | Bind all persisted Claim/Event/Evidence fields, canonical payloads, and complete evidence sets | `tests/v03/security/test_audit_material_a4.py`, `tests/v03/security/test_material_binding_a4.py` |
| Trusted-surface parity | Require compiler, validator, and inspection to reject the same forged event audit | `tests/v03/security/test_event_audit_surface_parity.py` |
| Snapshot impact | Prove deterministic classification, stable ordering, and invalid-input handling | `tests/v03/impact/unit/` |
| Input limits | Bound source size, line length, JSON shape, and unsafe control characters | `tests/v03/security/input_limits/` |
| Schema migration | Exercise read-only preflight, strict conversion, quarantine, backup gate, explicit material attestation, and rollback | `tests/v03/migration/`, `tests/v03/schema/` |
| Read-only inspection | Prove no database mutation and metadata-first output | `tests/v03/readonly/`, `tests/v03/impact/integration/` |
| Alpha CLI/contracts | Verify explicit database lifecycles, no implicit migration, stable error envelopes, and alpha command behavior | `tests/v03/cli/`, `tests/v03/contracts/` |
| Distribution | Verify clean wheel/sdist metadata and require core docs, licenses, and the North Pier demo in the sdist | `tests/v03/packaging/` |

Run all available tests from the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m compileall -q src tests scripts
```

CI runs the coverage-gated suite on Linux with Python 3.10-3.14 and on Windows/macOS at the 3.10 and 3.14 endpoints. A separate job builds both distributions, inspects their contents/metadata, installs the wheel in a clean environment, exercises the alpha CLI, runs North Pier from the unpacked sdist rather than the checkout, and publishes a wheel-first/sdist-second `SHA256SUMS` manifest.

### Coverage and resource-warning gates

Release CI treats both direct `ResourceWarning` and pytest's `PytestUnraisableExceptionWarning` wrapper as errors, so a destructor-time leak cannot pass with exit code zero. CI also writes Coverage.py JSON for a second deterministic gate. The required thresholds are:

- at least 80% combined statement-and-branch coverage;
- at least 75% global branch coverage;
- at least 80% branch coverage across trusted modules;
- 100% for each configured critical branch and critical file.

`scripts/check_coverage.py` enforces the latter three policies from `coverage.json`; CI also asks pytest-cov to fail below the 80% combined threshold. The checker accepts only canonical direct `src/continuityforge/*.py` paths, rejects absolute/dot/empty/nested aliases and duplicate normalized paths, requires Coverage.py JSON format 3, and verifies per-file totals against the global totals. `audit_material.py` is part of the trusted-module gate. The checker is included in the source distribution so an unpacked release can reproduce the policy.

The v0.1 baseline meta-gate hashes canonical LF bytes and separately admits only the exact CRLF transport form. Mixed line endings and lone carriage returns fail rather than being normalized into an apparently valid baseline.

## Threat-to-test matrix

| Threat | Required assertion |
|---|---|
| Cross-continuity evidence | Evidence validation fails closed with a stable mismatch code. |
| Forged quote or quote hash | The reference is invalid and cannot authorize or compile a claim. |
| `bool`, `IntEnum`, or `int` subclass coordinates | The coordinate is rejected; only `type(value) is int` passes. |
| Oversized or pathological source input | Ingest stops before unbounded work or persistence. |
| Duplicate JSON keys | Ingest rejects ambiguous structure rather than choosing one value. |
| Disallowed control characters | Ingest rejects them with deterministic diagnostics. |
| Missing authority history | An `AUTHORIZED` row without a valid decision chain is excluded or reported invalid. |
| Persisted Claim/Event/Evidence field changed outside trusted storage | Audit Material v2 replay rejects the aggregate on validator/compiler/inspection surfaces. |
| Incomplete reserved digest or extra-key material attestation | The final SQLite material guard rejects the insert before it enters the ledger. |
| Event row without matching creation audit | Compiler, validator, and source-impact inspection reject the same audit divergence; inspection emits `EVENT_AUDIT_INVALID`. |
| Concurrent review during compilation | The Memory Pack uses one pinned SQLite snapshot and never mixes old authority with new evidence. |
| Ledger reorder, update, or deletion | Chain verification fails. |
| Repeated target text | Impact returns every exact candidate once, in source order. |
| Invalid or non-UTF-8-encodable evidence quote | Impact returns `INVALID_EVIDENCE`, never an encoding traceback. |
| Old exact quote absent from target | Impact returns `NO_EXACT_MATCH`; it does not infer whether the cause was editing, deletion, truncation, or restructuring. |
| Impact analysis | No claim status, decision, snapshot, evidence, or ledger row changes. |
| Malformed legacy row | Preflight blocks migration or quarantines it without increasing authority/access. |
| Legacy partial creation payload or empty v0.2 Claim/Event stream without current consent | Preflight emits `MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED`, creates no backup, and writes nothing. |
| Pre-existing legacy material attestation | Migration rejects it; stored material events never substitute for the current invocation's opt-in. |
| Accepted material write with backup disabled | Migration fails with `MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP`; no backfill or attestation is written. |
| Migration failure | The transaction rolls back and the verified pre-migration backup remains restorable. |
| Missing database for an existing-database command | `DATABASE_NOT_FOUND`; no database, parent directory, journal, WAL, SHM, or backup is created. |
| Legacy database passed to an ordinary command | The command requires explicit migration and does not invoke a writable migration path. |
| Existing or symbolic-link backup destination | Existing regular backups remain untouched; symbolic-link candidates and target identity changes fail closed. |
| Administrative report | Full source bodies and unrestricted quotes are absent unless explicitly requested by an authorized operator. |

## Snapshot Impact cases

The pure-domain suite should include:

- unchanged anchors at the same span, including a duplicate elsewhere;
- one exact moved candidate;
- multiple exact moved candidates, including overlapping matches;
- no exact candidate when the old quote is absent; the engine does not infer why;
- CRLF/LF normalization without other whitespace normalization;
- multiline quotes and blank lines;
- stable candidate sorting and frozen result objects;
- strict built-in-integer coordinates and versions;
- unpaired Unicode surrogate input;
- a large target input that exercises the linear-time line-sequence matcher.

See the original [North Pier fixtures](../examples/north_pier/README.md) for human-readable examples.

## Migration and restore scenarios

Every supported starting schema needs at least these cases:

1. eligible database migrates and produces the expected schema fingerprint;
2. malformed time, access, status, evidence, or chain data fails closed;
3. injected failure at each write phase leaves the original database usable;
4. backup manifest hashes detect modified database or sidecar files;
5. restore occurs in staging, passes integrity/schema/ledger/authority checks, then activates atomically;
6. a restored v0.1/v0.2 fixture still passes its observable compatibility suite;
7. preflight and inspection leave the main database, WAL, schema, and logical row counts unchanged; SQLite may update coordination bytes in an already-existing `-shm` file.
8. backup publication preserves existing regular artifacts, rejects symbolic-link targets, verifies file identity/type, and retains POSIX mode `0600`.
9. every read-only entry point rejects symbolic links, broken links, directories, non-regular WAL/SHM sidecars, sidecar link counts other than one, and reused non-zero database/sidecar file identities before SQLite opens the database; a WAL without SHM is rejected without creating SHM;
10. admitted legacy partial creation material and empty v0.2 Claim/Event streams fail before backup by default; with explicit opt-in, actual backfills/attestations occur only after verified backup and inside the migration transaction;
11. pre-existing attestations, wrong creation-entry bindings, wrong migration source kinds, and non-canonical six-key payloads block migration;
12. v0.1 creation backfills carry Material v2 directly without opt-in; eligible empty v0.2 backfills require explicit opt-in and a verified backup, carry Material v2 directly, create no attestation entry, and leave report attestation counts at zero;
13. `migration-check` with explicit material acceptance may be ready without a backup, while a library write with backup disabled fails with `MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP`.

`migration-check` is implemented but unreleased. Its CLI path sets
`create_backup=False`; tests must assert no database, missing sidecar, backup,
schema, or logical row creation/mutation. With the explicit material flag it
may report a ready plan, but this does not relax the actual write backup gate.
When inspecting a live WAL database,
SQLite may update coordination bytes in an already-existing `-shm` file;
callers that require byte-for-byte filesystem immutability must inspect a
private consistent copy. Its JSON shape and stream/exit semantics are frozen
by the [v0.3 CLI contract](CLI_CONTRACT.md).

CLI lifecycle tests cover all commands, not only the three preview commands.
Only `ingest` and `demo` are create-capable; governance/event writes require an
existing schema-v3 database, ordinary reads require an existing database
without migrating it, and `migrate` is the sole explicit upgrade route.

## Redaction assertions

Tests for impact, inspection, migration, and backup reports seed unique canary strings in source/quote fields and assert that the canaries are absent from default output. Migration issues serialize sensitive values as type/length/SHA-256 descriptors rather than bodies. Reports may expose identifiers, versions, hashes, spans, statuses, counts, and stable error codes.

Evidence views and Memory Packs intentionally can include cited quote spans. Test them as separate, explicit disclosure surfaces. Database files and backups contain full source content and require filesystem protection.

## Safe fixtures

- Use synthetic, repository-owned text only.
- Do not place real credentials, personal records, copyrighted corpora, or production databases in tests.
- Keep malicious samples minimal and inert.
- Document the license and origin of every new demo corpus in [Demo Licenses](DEMO_LICENSES.md).

## Release gate

A v0.3 release candidate is blocked until:

- the full supported CI matrix passes;
- the v0.1 baseline canonical LF hash and exact CRLF transport hash remain accepted, while mixed/lone-CR variants remain rejected;
- v0.2 regression tests pass without weakening assertions;
- migration rollback and staged restore tests pass;
- default administrative-report redaction tests pass;
- all v0.3 alpha CLI behavior is implemented, tested, documented, and clearly marked unreleased;
- wheel and sdist inspection passes, and North Pier runs from an unpacked sdist against the clean-installed wheel;
- `SHA256SUMS` contains exactly the wheel and sdist in stable order and both hashes verify;
- security-relevant changes receive review against [Threat Model](THREAT_MODEL.md).
