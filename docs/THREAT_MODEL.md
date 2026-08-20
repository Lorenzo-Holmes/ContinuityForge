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
| Audit Material v2 digests | Complete persisted aggregate/evidence binding |
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
| Materialized status or event lacks audit backing | Shared claim-authority/event replay across compiler, validator, and inspection | Full DB replacement by trusted owner is not detected |
| Claim/Event/Evidence field is changed while legacy payload bound only a subset, or v0.2 audit is absent | Audit Material v2 covers every persisted field; partial creation and empty v0.2 Claim/Event streams require explicit acceptance | Operator acceptance covers current material and does not prove historical truth |
| Reserved material event is malformed or forged through a normal API | Trusted event reservation plus the final exact-shape SQLite material guard | Direct replacement of a consistently rehashed database remains out of scope |
| Source key/continuity is rewritten after evidence was created | Immutable identity/no-delete triggers plus shared Source audit replay | A trusted owner can replace and consistently rehash the entire database |
| Source revision metadata is detached from audit history | Snapshot immutability, lineage triggers, exact creation-payload replay, and `updated_at == latest snapshot.created_at` | Internal hashes are not externally anchored |
| Ordinary command silently migrates or creates a target | Explicit per-command database lifecycle and existing-file checks | A trusted operator can still invoke `migrate` intentionally |
| Accepted material history changes without recovery artifact | Verified-backup gate; `MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP` | A trusted operator remains responsible for retaining/restoring the artifact |
| Partial migration | Preflight, backup gate, one transaction, post-verification | Disk or hardware failure may require external recovery |
| Unsafe live DB copy | SQLite backup API / consistent snapshot requirement | External tools can still make unsafe copies |
| Backup path replacement or disclosure | Unpredictable private temp, identity/type checks, POSIX `0600`, no-replace publication, symlink rejection | No built-in encryption; containing directory/Windows ACL remain operator controls |
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

The inspection service also recomputes both endpoint snapshot hashes and line counts, verifies the global EventLedger, replays authority for every affected claim and the complete creation audit for every affected event, validates report metadata, and performs all reads in one pinned transaction. Event divergence fails closed with `EVENT_AUDIT_INVALID`. It reads only the two endpoint bodies; intermediate revisions are lineage metadata.

The same inspection boundary replays the selected Source and every revision against `source.created` and `source_snapshot.created`. Validator and Memory compiler use the same pure replay. A Source identity/payload, timestamp, lineage, or `updated_at` mismatch fails closed; compilation excludes every aggregate citing that Source.

Impact outcomes never mutate governance. `EXACT_MOVED_UNIQUE` is not authorization; it is only one exact relocation candidate.

## Governance and ledger attack surface

- Model payload status is ignored.
- Authorization rechecks evidence and conflicts.
- Status transitions are explicit and reasoned.
- v0.3 verifies decision and ledger backing before compilation.
- Audit Material v2 binds every persisted Claim/Event/Evidence field through canonical aggregate and complete evidence-set digests.
- Claim evidence changes carry complete v2 checkpoints; each operator event is bound to one matching creation record.
- The final material guard requires typed version/digest fields on creation and evidence checkpoints, plus exact six-key migration attestations, before ledger insertion.
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

The exact `v0.3-alpha2` structural fingerprint has a same-version hardening edge to final v0.3. Preflight rejects missing or divergent Source audit before publishing a backup. The exact `v0.3-alpha3` shape is also recognized, but its partial Claim/Event creation payloads require explicit current-invocation material acceptance.

Canonical v0.1 conversion deterministically generates Material-v2 creation records and needs no consent. Partial legacy creation material and empty v0.2 Claim/Event streams fail closed by default. With `--attest-current-legacy-material`, read-only `migration-check` may report the plan ready without creating a backup. The actual migration must verify a backup first and then, inside `BEGIN IMMEDIATE`, generate v2 creation records for accepted empty v0.2 streams and append bound attestations for partial creation records before installing the final guard. A write configured without backup fails with `MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP`.

Empty v0.2 backfills create no attestation event, so their report attestation counts remain zero. Any pre-existing legacy material-attestation event is invalid and blocks migration; it cannot substitute for current consent. An appended attestation proves only which complete current material was accepted during migration, not which values were historically true at creation time.

The implementation writes to an unpredictable same-directory temporary regular file, tracks its identity, enforces POSIX mode `0600`, verifies identity before writing, compares a streamed logical digest with the locked source connection, flushes the artifact, then publishes without replacing an existing destination. Existing regular backups are preserved through numbered names; symbolic-link candidates fail closed. These controls prevent accidental overwrite and common path-substitution mistakes inside the stated trusted-owner boundary, but they are not encryption or a defense against a malicious operating-system account.

Every read-only SQLite entry point inspects both `-wal` and `-shm` names with
`lstat` before opening the database. Symbolic links, broken links, directories,
other non-regular sidecars, sidecars with a link count other than one, and
reused non-zero file identities fail closed; a WAL without an existing SHM also
fails closed so SQLite cannot create the missing file. This is a preflight, not
an operating-system lock: the `lstat`-to-open interval remains inside the
trusted local owner/directory boundary. SQLite may update coordination bytes in
an already-existing single-link regular SHM while leaving the main database,
WAL, schema, and domain state unchanged. Inspect a private consistent copy when
byte-for-byte filesystem immutability is required.

In v0.3.0a4, explicit quarantine applies only to malformed v0.1 rows: the raw row is preserved in legacy storage and omitted from active domain mappings. Malformed v0.2 data remains blocking. Quarantine must not turn malformed time into unbounded time or missing access into `agent_accessible`.

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
