# Backup and Restore

## Status

The unreleased v0.3.0a1 `migrate` command implements a mandatory, consistent, verified pre-migration backup. `migration-check` is strictly read-only and never creates a backup. Restore, activation, retention, and external encryption remain operator workflows; there is no restore CLI.

```bash
continuityforge --db project.db migration-check --mode strict
continuityforge --db project.db migrate --mode strict
```

## Why ordinary file copying is insufficient

SQLite may use a write-ahead log. Copying only `project.db` while the database is live can omit committed WAL pages or capture an inconsistent state. ContinuityForge backup operations must use SQLite's consistent backup mechanism or operate on a verified, fully closed database set.

## Backup contract

A migration-grade backup must:

1. be created before any schema-v3 mutation;
2. represent one consistent SQLite state;
3. be written to a new artifact, never over the source database;
4. be independently openable;
5. pass SQLite integrity and foreign-key checks;
6. retain the detected schema version and database identity/fingerprint;
7. have a SHA-256 recorded after close;
8. emit metadata without embedding source bodies;
9. remain available until migration and restoration verification complete.

## Alpha backup metadata

`MigrationReport` binds the backup path and SHA-256 to the source structural fingerprint and migration checks. Current alpha output contains metadata similar to:

```json
{
  "source": {
    "kind": "v0.2",
    "digest": "STRUCTURAL_SCHEMA_SHA256",
    "user_version": 2,
    "metadata_version": 2
  },
  "checks": {
    "quick_check": "ok",
    "foreign_key_violations": 0,
    "database_bytes": 123456,
    "backup_path": "project.db.pre-v3.bak",
    "backup_sha256": "BACKUP_SHA256"
  },
  "status": "migrated"
}
```

The full JSON also contains schema object lists, capacity checks, target fingerprint, timestamps, migrated counts, issues, and quarantine records. The report schema is not frozen until v0.3 release. The backup filename is collision-safe: later runs use `.pre-v3.2.bak`, `.pre-v3.3.bak`, and so on rather than overwriting an existing artifact.

## Confidentiality

The report is metadata-first; the backup artifact is not. A backup contains source bodies, evidence quotes, claims, events, and governance history.

- store it with restrictive filesystem permissions;
- use operating-system or external encryption when required;
- do not attach it to a public issue;
- do not log its source content;
- define retention and secure deletion outside ContinuityForge.

ContinuityForge does not currently provide encryption or key management.

## Restore-before-activate workflow

Never restore directly over the only known-good database.

```mermaid
flowchart LR
    A["Backup artifact + manifest"] --> B["Verify artifact hash"]
    B --> C["Restore/copy to new staging path"]
    C --> D["Open independently"]
    D --> E["Integrity + FK + schema checks"]
    E --> F["Ledger + authority + provenance checks"]
    F --> G["Representative compile/inspection tests"]
    G --> H{"Verified?"}
    H -->|No| I["Keep active DB unchanged"]
    H -->|Yes| J["Operator-controlled activation"]
```

Activation may be an atomic rename or deployment-specific pointer switch, but it remains outside an open SQLite connection. Resolve absolute paths and retain the previous active database until the new one is verified.

## Restore verification checklist

- artifact SHA-256 matches the manifest;
- restored file opens read-only and read-write as intended;
- `PRAGMA integrity_check` succeeds;
- foreign-key checks succeed;
- detected schema matches expectation;
- source/snapshot/evidence counts match the manifest or migration report;
- snapshot and evidence hashes validate;
- EventLedger verifies;
- authority-chain verification succeeds;
- `human_only`/`hidden` access remains non-exportable by default;
- representative pre/post-cutoff Memory Packs behave as expected;
- read-only impact/inspection reports do not mutate the database;
- complete source bodies remain absent from administrative report output.

## Recovery scenarios

### Migration transaction fails

The transaction should roll back. Re-run read-only preflight against the original database and compare its fingerprint to the pre-migration report.

### Post-migration checks fail

Do not activate the candidate. Restore the verified backup to a new path and validate it independently.

### Active database is accidentally replaced

Stop writers, preserve the failed file for audit, restore to a staging path, validate, then activate. Internal EventLedger verification cannot prove identity against an attacker who replaced the entire database; compare an external backup manifest or signed checkpoint where available.

### Backup hash fails

Treat the artifact as unusable. Create a new consistent backup from a verified source database rather than ignoring or rewriting the recorded hash.

## Operational ownership

The operator is responsible for storage location, file permissions, external encryption, retention, off-site replication, restoration, and activation. The v0.3.0a1 migration path creates and verifies the backup artifact and returns machine-readable path/hash evidence, but it does not copy backups off-site or perform activation.

See [Migration v3](MIGRATION_V3.md) and [Threat Model](THREAT_MODEL.md).
