from __future__ import annotations

import hashlib
import sqlite3

import pytest

from continuityforge.exceptions import MigrationError
from continuityforge.impact import MAX_EXACT_CANDIDATES, analyze_evidence_impact
from continuityforge.impact_models import ImpactTargetError
from continuityforge.ingest import (
    DEFAULT_INGEST_LIMITS,
    SourceInputError,
    ingest_content,
)
from continuityforge.migrations import preflight_migration
from continuityforge.schema import SchemaKind, classify_schema, fingerprint_schema
from continuityforge.storage import Storage


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    [
        "CREATE TABLE unexpected(value TEXT)",
        "ALTER TABLE sources ADD COLUMN unexpected TEXT",
        "CREATE VIEW unexpected_view AS SELECT source_id FROM sources",
        "CREATE TRIGGER unexpected_trigger AFTER INSERT ON sources BEGIN SELECT 1; END",
    ],
)
def test_current_schema_with_unknown_objects_fails_closed(tmp_path, mutation: str) -> None:
    database = tmp_path / "modified.db"
    with Storage(database):
        pass
    connection = sqlite3.connect(database)
    connection.execute(mutation)
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()
    before = _digest(database)

    with pytest.raises(MigrationError):
        Storage(database)

    assert _digest(database) == before


def test_same_name_noop_trigger_does_not_masquerade_as_v3(tmp_path) -> None:
    database = tmp_path / "weak-trigger.db"
    with Storage(database):
        pass
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        DROP TRIGGER continuityforge_evidence_no_update;
        CREATE TRIGGER continuityforge_evidence_no_update
        BEFORE UPDATE ON evidence_refs BEGIN SELECT 1; END;
        """
    )
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()


def test_same_columns_without_canonical_constraints_fail_closed(tmp_path) -> None:
    database = tmp_path / "weak-table.db"
    with Storage(database):
        pass
    connection = sqlite3.connect(database)
    original = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sources'"
    ).fetchone()[0]
    weakened = str(original).replace("created_at TEXT NOT NULL", "created_at TEXT")
    assert weakened != original
    connection.execute("PRAGMA writable_schema = ON")
    connection.execute(
        "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = 'sources'",
        (weakened,),
    )
    connection.execute("PRAGMA writable_schema = OFF")
    connection.commit()
    connection.close()

    reopened = sqlite3.connect(database)
    assert classify_schema(reopened) is SchemaKind.PARTIAL
    reopened.close()


@pytest.mark.parametrize(
    "script",
    [
        "CREATE UNIQUE INDEX hostile_unique ON source_snapshots(content_hash);",
        "DROP INDEX idx_evidence_snapshot;",
        (
            "DROP INDEX idx_evidence_snapshot;"
            "CREATE UNIQUE INDEX idx_evidence_snapshot "
            "ON evidence_refs(lower(snapshot_id));"
        ),
    ],
)
def test_missing_extra_or_semantically_changed_indexes_are_partial(
    tmp_path, script: str
) -> None:
    database = tmp_path / "weak-index.db"
    with Storage(database):
        pass
    connection = sqlite3.connect(database)
    connection.executescript(script)
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()


def test_impact_refuses_to_truncate_an_excessive_candidate_set() -> None:
    target = {
        "snapshot_id": "target",
        "version": 2,
        "content": "\n".join("repeat" for _ in range(MAX_EXACT_CANDIDATES + 1)),
    }
    evidence = {
        "snapshot_id": "old",
        "start_line": 1,
        "end_line": 1,
        "quote": "repeat",
    }

    with pytest.raises(ImpactTargetError) as caught:
        analyze_evidence_impact(evidence, target)

    assert caught.value.code == "TOO_MANY_EXACT_MATCHES"


def test_impact_rejects_target_before_unbounded_line_allocation() -> None:
    target = {
        "snapshot_id": "target",
        "version": 2,
        "content": "\n" * (DEFAULT_INGEST_LIMITS.max_lines + 1),
    }
    evidence = {
        "snapshot_id": "old",
        "start_line": 1,
        "end_line": 1,
        "quote": "",
    }

    with pytest.raises(ImpactTargetError) as caught:
        analyze_evidence_impact(evidence, target)

    assert caught.value.code == "TARGET_SNAPSHOT_LINES_LIMIT"


class _NoWriteStorage:
    def ingest_snapshot(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("malformed JSON must not reach storage")


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_json_rejects_nonstandard_nonfinite_numbers(constant: str) -> None:
    with pytest.raises(SourceInputError) as caught:
        ingest_content(
            _NoWriteStorage(),  # type: ignore[arg-type]
            '{"number":' + constant + "}",
            "source",
            "alpha",
            media_type="application/json",
        )
    assert caught.value.code == "NONFINITE_JSON_NUMBER"


def test_json_excessive_nesting_has_stable_error() -> None:
    content = "[" * 2_000 + "0" + "]" * 2_000
    with pytest.raises(SourceInputError) as caught:
        ingest_content(
            _NoWriteStorage(),  # type: ignore[arg-type]
            content,
            "source",
            "alpha",
            media_type="application/json",
        )
    assert caught.value.code == "JSON_NESTING_LIMIT"


def test_reports_redact_hostile_schema_object_names(tmp_path) -> None:
    database = tmp_path / "hostile-name.db"
    canary = "SECRET_BODY\u202e\nC:\\private\\source.txt"
    connection = sqlite3.connect(database)
    connection.execute('CREATE TABLE "' + canary.replace('"', '""') + '" (value TEXT)')
    connection.commit()
    encoded_fingerprint = fingerprint_schema(connection).to_json()
    connection.close()
    encoded_report = preflight_migration(database, create_backup=False).to_json()
    assert "SECRET_BODY" not in encoded_fingerprint
    assert "SECRET_BODY" not in encoded_report
    assert '"redacted": true' in encoded_fingerprint


@pytest.mark.parametrize("value", ["safe\x00hidden", "safe\x9bansi", "safe\u202eflip"])
def test_write_api_rejects_unsafe_metadata_controls(tmp_path, value: str) -> None:
    with Storage(tmp_path / "metadata.db") as storage:
        with pytest.raises(ValueError):
            storage.ingest_snapshot(value, "alpha", "content")


def test_v01_unvalidated_active_mapping_table_is_partial(tmp_path, project_root) -> None:
    database = tmp_path / "v01-extra.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.execute("CREATE TABLE claim_proposals (claim_id TEXT)")
    connection.execute("INSERT INTO claim_proposals VALUES ('hostile')")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()
    with pytest.raises(MigrationError):
        Storage(database)


def test_v01_alias_columns_and_weakened_constraints_are_partial(tmp_path, project_root) -> None:
    alias_db = tmp_path / "v01-alias.db"
    connection = sqlite3.connect(alias_db)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.execute("ALTER TABLE claims ADD COLUMN valid_start TEXT")
    connection.execute("ALTER TABLE claims ADD COLUMN raw_text TEXT")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()

    weak_db = tmp_path / "v01-weak.db"
    connection = sqlite3.connect(weak_db)
    connection.executescript(
        "CREATE TABLE source_snapshots (id TEXT, path TEXT, sha256 TEXT, continuity TEXT, content TEXT, created_at TEXT);"
        "CREATE TABLE claims (id TEXT, persona_id TEXT, continuity TEXT, claim TEXT, subject TEXT, predicate TEXT, object_value TEXT, source_snapshot_id TEXT, start_line INTEGER, end_line INTEGER, valid_from TEXT, valid_until TEXT, knowledge_from TEXT, knowledge_until TEXT, access_policy TEXT, confidence REAL, created_at TEXT);"
    )
    connection.commit()
    assert classify_schema(connection) is SchemaKind.PARTIAL
    connection.close()
