# ContinuityForge v0.3 machine-output contract

This document freezes the command-line machine contract for v0.3. The JSON
Schemas in [`schemas/`](../schemas/) are normative. Examples and human-readable
messages are explanatory and do not override those schemas.

## Normative schema markers

| Output | Marker | Normative schema |
| --- | --- | --- |
| Source-impact success report | `continuityforge.source-impact/v0.3` | `schemas/source-impact-v0.3.schema.json` |
| Runtime error envelope | `continuityforge.error/v0.3` | `schemas/error-v0.3.schema.json` |
| Migration report | `continuityforge.migration-report/v0.3` | `schemas/migration-report-v0.3.schema.json` |

Every schema uses JSON Schema Draft 2020-12. Contract objects are closed with
`additionalProperties: false` wherever the field set is owned by that schema.
The `actual` diagnostic value in a migration issue and command-specific nested
error reports are intentionally opaque JSON values; consumers must make
decisions from stable codes and fields instead of their prose or internal
shape.

## Serialization

CLI JSON is UTF-8, contains one complete JSON document, and ends with one line
feed. Serialization has these stable properties:

- object keys are sorted lexicographically;
- non-ASCII characters are emitted directly rather than escaped;
- `NaN`, positive infinity, and negative infinity are rejected;
- arrays retain their domain-defined order.

The following prose fields are diagnostic and may be clarified without a
schema-version change: `message`, `reason`, and migration-issue `message`.
Consumers must branch on `schema`, `code`, `outcome`, `reason_code`, `status`,
and other enumerated fields instead of matching prose.

## Streams and exit codes

| Situation | Exit | stdout | stderr |
| --- | ---: | --- | --- |
| Successful command | `0` | JSON result | empty |
| Argument-parser usage error | `2` | empty | argparse text |
| Validation or input failure | `3` | empty | `continuityforge.error/v0.3` JSON |
| Governance failure | `4` | empty | `continuityforge.error/v0.3` JSON |
| Ledger-integrity failure | `5` | empty | `continuityforge.error/v0.3` JSON |
| Schema, migration, or read-only safety failure | `6` | empty | `continuityforge.error/v0.3` JSON |
| `migration-check` completed but is not ready | `6` | migration-report JSON | empty |

Argument parsing happens before the runtime error envelope exists. Missing or
unknown arguments therefore retain argparse's text usage output on stderr and
exit `2`; they are not JSON errors. A not-ready `migration-check` is a valid
inspection result rather than an exception, so its report remains on stdout
even though the command exits `6`.

## Command lifecycle

The lifecycle class determines whether a command may create, write, read, or
explicitly migrate a project database.

| Lifecycle | Commands |
| --- | --- |
| `create-capable` | `ingest`, `demo` |
| `write-existing` | `claim-propose`, `claim-add`, `claim-review`, `event-add` |
| `read-existing` | `source-list`, `claim-list`, `validate`, `compile`, `ledger-verify`, `ledger-show`, `source-impact`, `migration-check` |
| `explicit-migrate` | `migrate` |

New commands must choose a lifecycle explicitly. They do not inherit database
creation or write permission from another command.

## Source-impact report

Source impact is report-only and contains no snapshot body or evidence quote.
It has exactly five outcomes, in this compatibility order:

1. `SAME_POSITION`
2. `EXACT_MOVED_UNIQUE`
3. `EXACT_MOVED_AMBIGUOUS`
4. `NO_EXACT_MATCH`
5. `INVALID_EVIDENCE`

`classification` is a compatibility alias and must equal `outcome`. The stable
explanation is `reason_code`; `reason` is diagnostic prose.

Affected evidence is ordered by this tuple:

```text
(aggregate_type, aggregate_id, original_start_line-or-0,
 original_end_line-or-0, evidence_id)
```

Candidate spans are ordered by `(start_line, end_line)`. Summary outcome keys
are exhaustive and include zero counts. The service also enforces a report-wide
candidate limit that JSON Schema cannot express as a sum across nested arrays.

The source selector accepts either `--source-key` or `--source-id`. The target
revision accepts the equivalent spellings `--target-version` and
`--to-version`.

## Migration report

`migration-check` and successful explicit migration use the same formal report
marker. `status`, `is_ready`, `succeeded`, and `changed` are separate fields;
clients must not infer one solely from another. A preflight report with
`is_ready: false` is the normal not-ready result described in the stream table.

Migration issue `code` and `severity` are machine fields. `message` and
`actual` are diagnostics. Sensitive or unsafe values may appear only as
bounded redacted descriptors. Filesystem paths must not be used as stable
identifiers.

## Compatibility changes

Changing a marker, required field, closed-object property set, enum member,
array ordering rule, stream, or exit-code meaning requires an explicitly
versioned contract change and new golden fixtures. Diagnostic prose changes do
not require a new marker when the corresponding machine code keeps its meaning.

The canonical fixtures live in `tests/v03/contracts/golden/`. Schema tests must
validate success, runtime-error, migrated, and migration-not-ready documents,
and must also prove that unknown properties and inconsistent outcome aliases are
rejected.

## Distribution requirement

Before publishing v0.3, all three `schemas/*-v0.3.schema.json` files **must** be
included in the source distribution. `MANIFEST.in` must include root schema
JSON files, and the distribution test must inspect the built sdist and assert
the exact three paths are present. Schema validation tests require
`jsonschema>=4,<5` in the development/test dependency set. Release automation
must not publish an sdist that fails either assertion.

The sdist also includes `scripts/check_coverage.py`, allowing the release
coverage policy to be reproduced from a Coverage.py JSON report. CI publishes
exactly the wheel, sdist, and `SHA256SUMS`; checksum rows are deterministic and
ordered wheel first, sdist second.
