from __future__ import annotations

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3

import pytest

from continuityforge.exceptions import MigrationError, ReadOnlyStorageError
from continuityforge.migrations import migrate_to_v3, preflight_migration
from continuityforge.schema import (
    SchemaKind,
    V03_ALPHA2_SCHEMA_DIGEST,
    fingerprint_schema,
)
from continuityforge.storage import Storage


_FINAL_INPUT_LIMIT_TRIGGERS = (
    "continuityforge_claims_input_limits",
    "continuityforge_events_input_limits",
)
_FINAL_SOURCE_TRIGGERS = (
    "continuityforge_sources_identity_immutable",
    "continuityforge_sources_updated_at_guard",
    "continuityforge_sources_no_delete",
)
_FINAL_V03_TRIGGERS = _FINAL_INPUT_LIMIT_TRIGGERS + _FINAL_SOURCE_TRIGGERS


def _make_v03_alpha2(database: Path) -> tuple[str, tuple[int, str]]:
    with Storage(database) as storage:
        source, _, _ = storage.ingest_snapshot("story", "alpha", "revision one\n")
        storage.ingest_snapshot("story", "alpha", "revision two\n")
        row = storage.connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        ledger_head = (int(row["sequence"]), str(row["entry_hash"]))

    connection = sqlite3.connect(database)
    try:
        for trigger in _FINAL_V03_TRIGGERS:
            connection.execute(f'DROP TRIGGER "{trigger}"')
        connection.commit()
        fingerprint = fingerprint_schema(connection)
        assert fingerprint.kind is SchemaKind.V03_ALPHA2
        assert fingerprint.digest == V03_ALPHA2_SCHEMA_DIGEST
    finally:
        connection.close()
    return source.source_id, ledger_head


def _read_ledger_head(database: Path) -> tuple[int, str]:
    connection = sqlite3.connect(database)
    try:
        row = connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        return int(row[0]), str(row[1])
    finally:
        connection.close()


def test_v03_alpha2_to_final_v03_preserves_ledger_head(tmp_path: Path) -> None:
    database = tmp_path / "alpha2.db"
    _, ledger_head = _make_v03_alpha2(database)

    with pytest.raises(ReadOnlyStorageError):
        Storage.open_readonly(database)

    report = migrate_to_v3(database, create_backup=True)

    assert report.status == "migrated"
    assert report.source.kind is SchemaKind.V03_ALPHA2
    assert report.target is not None
    assert report.target.kind is SchemaKind.V03
    assert report.backup_path is not None
    assert _read_ledger_head(database) == ledger_head
    with closing(sqlite3.connect(report.backup_path)) as backup:
        assert fingerprint_schema(backup).kind is SchemaKind.V03_ALPHA2


def test_schema3_missing_only_source_triggers_is_not_misclassified_as_alpha2(
    tmp_path: Path,
) -> None:
    database = tmp_path / "not-alpha2.db"
    with Storage(database):
        pass
    with closing(sqlite3.connect(database)) as connection:
        for trigger in _FINAL_SOURCE_TRIGGERS:
            connection.execute(f'DROP TRIGGER "{trigger}"')
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.PARTIAL


def test_v03_alpha2_tampered_source_audit_blocks_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "tampered-alpha2.db"
    source_id, ledger_head = _make_v03_alpha2(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE sources SET source_key = ? WHERE source_id = ?",
            ("forged/story", source_id),
        )
        connection.commit()

    preflight = preflight_migration(database, create_backup=True)
    assert preflight.source.kind is SchemaKind.V03_ALPHA2
    assert preflight.is_ready is False
    assert preflight.backup_path is None
    assert "MIGRATION_SOURCE_AUDIT_INVALID" in {
        issue.code for issue in preflight.issues
    }

    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(database, create_backup=True)
    assert caught.value.report is not None
    assert caught.value.report.backup_path is None
    assert list(tmp_path.glob("*.bak")) == []
    assert _read_ledger_head(database) == ledger_head
    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA2
        assert connection.execute(
            "SELECT source_key FROM sources WHERE source_id = ?", (source_id,)
        ).fetchone()[0] == "forged/story"


def test_v03_alpha2_missing_source_audit_blocks_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing-audit-alpha2.db"
    _make_v03_alpha2(database)
    created_at = "2026-08-20T00:00:00Z"
    content = "unattested"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO sources "
            "(source_id, source_key, continuity, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("src_missing", "missing/story", "alpha", created_at, created_at),
        )
        connection.execute(
            "INSERT INTO source_snapshots "
            "(snapshot_id, source_id, version, content_hash, content, media_type, "
            "origin_path, previous_snapshot_id, line_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "snp_missing",
                "src_missing",
                1,
                sha256(content.encode("utf-8")).hexdigest(),
                content,
                "text/plain",
                None,
                None,
                1,
                created_at,
            ),
        )
        connection.commit()

    report = preflight_migration(database, create_backup=True)
    assert report.is_ready is False
    assert report.backup_path is None
    issue = next(
        item for item in report.issues if item.code == "MIGRATION_SOURCE_AUDIT_INVALID"
    )
    assert issue.record_id == "src_missing"
    assert set(issue.actual["issue_codes"]) >= {
        "SOURCE_CREATION_LEDGER_MISMATCH",
        "SOURCE_SNAPSHOT_CREATION_LEDGER_MISMATCH",
    }
    assert list(tmp_path.glob("*.bak")) == []
