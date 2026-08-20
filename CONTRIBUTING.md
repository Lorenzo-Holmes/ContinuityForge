# Contributing to ContinuityForge

ContinuityForge welcomes focused bug fixes, tests, documentation, source adapters, and deterministic governance tooling.

## Before opening a change

1. Search existing issues and pull requests.
2. For a substantial feature or schema change, open a design issue first.
3. For a vulnerability, follow [SECURITY.md](SECURITY.md) rather than opening a public exploit report.
4. Keep changes inside one reviewable concern.

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
```

Python 3.10 or newer is required. ContinuityForge has no third-party runtime dependencies.

Run a focused test while iterating, then the complete suite before opening a pull request:

```bash
python -m pytest tests/v03/impact/unit
python -m pytest
continuityforge demo --output-dir demo-output --reset
```

## Compatibility rules

The v0.1 observable contract is frozen. `docs/V0_1_BASELINE.md`, the legacy schema fixture, and the semantic contract are byte-locked.

- Never update a baseline hash merely to make CI green.
- Do not edit frozen files as part of an unrelated feature.
- An intentional compatibility change requires a versioned migration, updated contract, release note, tests, and explicit maintainer review.
- Keep repository text in LF form; `.gitattributes` enforces this across platforms.

## Design rules

### Deterministic core

Trusted validation, governance, migration, impact, and compilation decisions must be deterministic and testable without a model or network connection.

- LLM output starts as `PROPOSED`.
- Model confidence is metadata, not authority.
- `NarrativeEvent` remains human/operator-only.
- Snapshot impact is report-only.
- Exact impact matching does not silently become semantic matching.
- Missing or malformed security-relevant fields fail closed.

Read [Deterministic vs LLM](docs/DETERMINISTIC_VS_LLM.md) and [Architecture](docs/ARCHITECTURE.md) before changing a trust boundary.

### Data and reports

- Preserve immutable snapshot and evidence coordinates.
- Keep persona and continuity identifiers exact and opaque.
- Use half-open time intervals `[from, to)`.
- Administrative reports should expose IDs, hashes, spans, counts, and codes by default—not complete source bodies.
- Do not place real user content, credentials, private databases, or provider tokens in tests or examples.

### Python style

- Prefer the standard library.
- Use type annotations and small domain values.
- Keep storage, CLI, and provider concerns out of pure-domain modules.
- Use frozen dataclasses and tuples for immutable reports.
- Validate integers with the same strictness as the owning domain contract.
- Add stable machine-readable error codes for expected failures.

## Tests

Every behavior change needs a regression test. Include boundary cases where relevant:

- CRLF/LF and trailing-newline behavior;
- empty and multi-line evidence;
- repeated and overlapping text;
- booleans, numeric strings, enums, and integer subclasses;
- malformed Unicode and control characters;
- continuity/persona leakage;
- governance/ledger inconsistency;
- migration rollback and restore verification;
- default report redaction.

See [Security Testing](docs/SECURITY_TESTING.md).

## Documentation and changelog

- Update README or the relevant architecture document when behavior or boundaries change.
- Put user-visible changes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
- Clearly label v0.3 alpha commands and schemas as alpha pre-release interfaces.
- Do not present a pre-release command or JSON shape as a stable release contract.

## Pull requests

Complete the pull-request template, including:

- behavioral summary;
- trust-boundary impact;
- tests run;
- migration/rollback impact;
- documentation and changelog updates;
- confirmation that frozen baseline bytes remain unchanged.

By contributing, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and license your contribution under the repository's MIT License unless a file carries a different explicit notice.
