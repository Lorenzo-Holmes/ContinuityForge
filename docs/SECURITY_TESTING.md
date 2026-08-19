# Security Testing

This document turns the [threat model](THREAT_MODEL.md) into repeatable tests. It covers the released v0.1/v0.2 contracts and the unreleased v0.3.0a1 implementation. A passing test suite supports the stated boundaries; it does not extend them to a hostile operating-system or database owner.

## Test layers

| Layer | Purpose | Representative location |
|---|---|---|
| Frozen baseline | Preserve v0.1 observable behavior and locked fixture bytes | `tests/baseline/` |
| v0.2 regression | Protect versioning, evidence, governance, ledger, compiler, CLI, and migration behavior | `tests/` |
| Strict evidence | Reject non-built-in integers and malformed spans | `tests/v03/evidence/` |
| Authority/event integrity | Detect missing, contradictory, or evidence-divergent audit history | `tests/v03/governance/` |
| Snapshot impact | Prove deterministic classification, stable ordering, and invalid-input handling | `tests/v03/impact/unit/` |
| Input limits | Bound source size, line length, JSON shape, and unsafe control characters | `tests/v03/security/input_limits/` |
| Schema migration | Exercise read-only preflight, strict conversion, quarantine, backup gate, and rollback | `tests/v03/migration/`, `tests/v03/schema/` |
| Read-only inspection | Prove no database mutation and metadata-first output | `tests/v03/readonly/`, `tests/v03/impact/integration/` |
| Alpha CLI | Verify `source-impact`, `migration-check`, and `migrate` routing, output, and failure behavior | `tests/v03/cli/` |

Run all available tests from the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m compileall -q src tests
```

CI runs the coverage-gated suite on Linux with Python 3.10–3.14 and on Windows/macOS at the 3.10 and 3.14 endpoints. A separate job builds both distributions, inspects their contents/metadata, installs the wheel in a clean environment, exercises the alpha CLI, and runs both demos.

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
| Event row without matching creation audit | Compilation excludes it and project validation reports an error. |
| Concurrent review during compilation | The Memory Pack uses one pinned SQLite snapshot and never mixes old authority with new evidence. |
| Ledger reorder, update, or deletion | Chain verification fails. |
| Repeated target text | Impact returns every exact candidate once, in source order. |
| Invalid or non-UTF-8-encodable evidence quote | Impact returns `INVALID_EVIDENCE`, never an encoding traceback. |
| Changed source text | Impact returns `NO_EXACT_MATCH`; it does not use fuzzy inference. |
| Impact analysis | No claim status, decision, snapshot, evidence, or ledger row changes. |
| Malformed legacy row | Preflight blocks migration or quarantines it without increasing authority/access. |
| Migration failure | The transaction rolls back and the verified pre-migration backup remains restorable. |
| Administrative report | Full source bodies and unrestricted quotes are absent unless explicitly requested by an authorized operator. |

## Snapshot Impact cases

The pure-domain suite should include:

- unchanged anchors at the same span, including a duplicate elsewhere;
- one exact moved candidate;
- multiple exact moved candidates, including overlapping matches;
- no exact candidate after an edit;
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

`migration-check` is implemented but unreleased. Its CLI path sets `create_backup=False`; tests must assert no database, missing sidecar, backup, schema, or logical row creation/mutation. When inspecting a live WAL database, SQLite may update coordination bytes in an already-existing `-shm` file; callers that require byte-for-byte filesystem immutability must inspect a private consistent copy. Its report schema is not frozen.

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
- the v0.1 baseline hashes and observable contract remain unchanged;
- v0.2 regression tests pass without weakening assertions;
- migration rollback and staged restore tests pass;
- default administrative-report redaction tests pass;
- all v0.3 alpha CLI behavior is implemented, tested, documented, and clearly marked unreleased;
- security-relevant changes receive review against [Threat Model](THREAT_MODEL.md).
