from __future__ import annotations

import hashlib
import sqlite3

import pytest

from continuityforge.constants import SCHEMA_VERSION as CONSTANT_SCHEMA_VERSION
from continuityforge.exceptions import MigrationError, ReadOnlyStorageError
from continuityforge.schema import (
    SCHEMA_VERSION,
    SchemaKind,
    classify_schema,
    fingerprint_schema,
    validate_schema,
)
from continuityforge.storage import SCHEMA_VERSION as STORAGE_SCHEMA_VERSION, Storage


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_schema_version_has_one_value_and_new_database_is_v3(tmp_path):
    database = tmp_path / "project.db"
    with Storage(database) as storage:
        assert SCHEMA_VERSION == CONSTANT_SCHEMA_VERSION == STORAGE_SCHEMA_VERSION == 3
        assert classify_schema(storage.connection) is SchemaKind.V03
        assert validate_schema(storage.connection).kind is SchemaKind.V03


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE unrelated (value TEXT)",
        "CREATE TABLE sources (source_id TEXT)",
    ],
)
def test_unknown_and_partial_databases_fail_closed_byte_for_byte(tmp_path, ddl):
    database = tmp_path / "untrusted.db"
    connection = sqlite3.connect(database)
    connection.execute(ddl)
    connection.commit()
    connection.close()
    before = _digest(database)

    with pytest.raises(MigrationError) as caught:
        Storage(database)

    assert caught.value.report.source.kind in {SchemaKind.UNKNOWN, SchemaKind.PARTIAL}
    assert _digest(database) == before


def test_opening_current_database_for_ordinary_reads_runs_no_ddl(tmp_path):
    database = tmp_path / "current.db"
    with Storage(database):
        pass
    before = _digest(database)
    with Storage(database) as storage:
        assert storage.migration_report is not None
        assert storage.migration_report.status == "already-current"
        fingerprint = fingerprint_schema(storage.connection)
    assert _digest(database) == before
    assert fingerprint.kind is SchemaKind.V03


def test_mode_ro_entry_never_creates_or_mutates(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        Storage.open_readonly(missing)
    assert not missing.exists()

    database = tmp_path / "current.db"
    with Storage(database):
        pass
    before = _digest(database)
    with Storage.open_readonly(database) as storage:
        assert storage.connection.execute("PRAGMA query_only").fetchone() is not None
        with pytest.raises(ReadOnlyStorageError):
            with storage.transaction():
                pass
    assert _digest(database) == before
