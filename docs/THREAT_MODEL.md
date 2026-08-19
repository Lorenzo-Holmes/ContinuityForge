# ContinuityForge Threat Model

## Scope

This model covers local source ingestion, SQLite persistence, evidence/governance workflows, Memory Pack compilation, v0.3 impact inspection, migration, backup, restore, and administrative reports.

## Trust assumptions

### Trusted

- the operating-system account running ContinuityForge;
- the owner of the SQLite database and backup files;
- the Python runtime and local filesystem after ordinary platform controls;
- an explicit human/operator governance decision.

### Untrusted

- imported source files and encodings;
- model-generated text, coordinates, confidence, and rationale;
- integration-provided IDs, timestamps, access policies, and JSON;
- legacy database rows until migration preflight succeeds;
- copied reports and Memory Packs once they leave the local boundary.

An attacker able to replace the entire database and its internal ledger is out of scope. An external signed checkpoint is required to detect that replacement.

## Assets

| Asset | Security property |
|---|---|
| Source bodies | Confidentiality and immutable provenance |
| Snapshot/evidence hashes | Integrity and reproducibility |
| Persona/continuity scope | Isolation |
| Governance decisions | Authenticity and auditability |
| EventLedger | Ordered integrity signal |
| Access policy | Fail-closed confidentiality boundary |
| Time intervals/cutoffs | Temporal integrity |
| Migration/backup artifacts | Recoverability and confidentiality |
| Impact reports | Deterministic correctness without mutation |

## Threat actors and failure sources

1. **Untrusted model output** attempts to authorize itself, invent evidence, cross continuity, or create operator-only events.
2. **Malformed or adversarial source input** attempts resource exhaustion, control-sequence injection, ambiguous JSON, invalid Unicode, or coordinate confusion.
3. **Integration misuse** supplies boolean/string coordinates, malformed timestamps, overly broad access, wrong target lineage, or unsafe report options.
4. **Application defects** partially commit data, desynchronize materialized status and decisions, break ledger linkage, or leak source content.
5. **Trusted owner mistake** copies a live SQLite file incorrectly, restores the wrong database, or publishes a sensitive report/backup.

## Threat and mitigation matrix

| Threat | Primary controls | Residual risk |
|---|---|---|
| Model sets `AUTHORIZED` in payload | Proposal constructor discards authority; separate review transition | A trusted reviewer can still make a poor judgment |
| Model creates `NarrativeEvent` | Operator-only event boundary | A compromised operator account is trusted |
| Missing/fabricated evidence | Snapshot lookup, strict span, quote/hash, continuity validation | Exact evidence does not prove the claim's interpretation |
| Cross-continuity leakage | Exact opaque continuity equality in validation, queries, compiler | Incorrectly labeled source data remains an operator error |
| Future-knowledge leakage | Half-open knowledge intervals and explicit cutoff | Incorrect timestamps supplied by a reviewer |
| Access widening | Explicit enum and fail-closed migration defaults | An authorized operator may intentionally widen access |
| Boolean/string coordinate coercion | `type(value) is int` gates before persistence/matching | Third-party adapters may fail before calling the gate |
| Large or hostile input | File/line/JSON/report/database limits, strict decoding, control checks, duplicate-key rejection | Configured limits still consume resources up to the boundary |
| Source revision silently invalidates memory | Deterministic report-only impact inspection | Human review is required; no automatic dispute transition |
| Duplicate text creates false relocation certainty | `EXACT_MOVED_AMBIGUOUS` with all sorted candidates | Human must choose or reject a candidate |
| Materialized status or event lacks audit backing | Claim authority and event evidence/ledger replay | Full DB replacement by trusted owner is not detected |
| Partial migration | Preflight, backup gate, one transaction, post-verification | Disk or hardware failure may require external recovery |
| Unsafe live DB copy | SQLite backup API / consistent snapshot requirement | External tools can still make unsafe copies |
| Report leaks source body | Metadata-first schemas and explicit quote/export boundaries | Error details and Memory Packs may contain cited excerpts |
| Backup disclosure | File permission guidance and external encryption | No built-in encryption |

## Ingestion attack surface

v0.3 input hardening is designed to reject:

- oversized files, excessive lines, and oversized individual lines;
- invalid or unknown encodings;
- unpaired Unicode surrogates;
- NUL, ANSI escape/control, and bidirectional-control characters under default policy;
- malformed JSON and duplicate object keys;
- non-finite JSON numbers, excessive JSON depth, and non-JSON Python values;
- control characters hidden inside decoded JSON strings.

Limits are policy, not sanitization. Accepted content is preserved rather than rewritten.

## Evidence and Impact attack surface

Evidence coordinates are strict built-in integers. Quote comparison normalizes CRLF/CR to LF but does not trim spaces, fold case, or normalize Unicode.

The pure Impact API validates whether the supplied evidence fields form a usable exact-match anchor. It cannot establish the old snapshot's historical content or source/continuity lineage by itself. The storage-aware inspection boundary must resolve and verify those facts before trusting a report.

The inspection service also recomputes both endpoint snapshot hashes and line counts, verifies the global EventLedger, replays authority for every affected claim, validates report metadata, and performs all reads in one pinned transaction. It reads only the two endpoint bodies; intermediate revisions are lineage metadata.

Impact outcomes never mutate governance. `EXACT_MOVED_UNIQUE` is not authorization; it is only one exact relocation candidate.

## Governance and ledger attack surface

- Model payload status is ignored.
- Authorization rechecks evidence and conflicts.
- Status transitions are explicit and reasoned.
- v0.3 verifies decision and ledger backing before compilation.
- v0.3 binds the authorized evidence set to proposal/evidence ledger payloads, and binds each operator event to one matching creation record.
- compilation uses one pinned read transaction so concurrent reviews cannot create a mixed-state Memory Pack.
- Ledger hashes provide internal tamper evidence, not protection against full-database replacement.

## Migration, backup, and restore attack surface

Schema-v3 migration follows these principles:

1. preflight the source database and authority chain;
2. fingerprint the input and migration plan;
3. create and verify a consistent backup;
4. migrate in one transaction;
5. fail closed on malformed legacy authority, access, time, or evidence;
6. emit a machine-readable, source-body-redacted report;
7. verify schema, ledger, counts, and fingerprints before activation;
8. retain the backup until a restoration drill succeeds.

In v0.3.0a1, explicit quarantine applies only to malformed v0.1 rows: the raw row is preserved in legacy storage and omitted from active domain mappings. Malformed v0.2 data remains blocking. Quarantine must not turn malformed time into unbounded time or missing access into `agent_accessible`.

## Disclosure boundaries

| Surface | Default disclosure |
|---|---|
| Source list | IDs, keys, continuity, timestamps |
| Impact report | snapshot IDs/versions, spans, outcomes, codes |
| Inspection report | scoped metadata and validation findings |
| Migration/backup report | fingerprints, counts, paths/status as configured |
| Evidence error | May contain expected/actual quote excerpts |
| Memory Pack | Intentionally contains selected claims and cited provenance |
| SQLite backup | Contains all stored data |

Review explicit exports before sharing them.

## Out of scope

- malicious operating-system or database owner;
- remote authentication and multi-tenant authorization;
- cryptographic identity for human reviewers;
- external timestamping or signed checkpoints;
- database/backup encryption;
- semantic truth adjudication;
- model-provider security;
- HTTP, MCP, or hosted transport attacks.

## Review triggers

Revisit this model when adding a network transport, multi-user access, provider SDK, automatic event proposal, semantic impact, encrypted storage, signed checkpoints, or a new report that can return source content.

Vulnerabilities should follow [SECURITY.md](../SECURITY.md).
