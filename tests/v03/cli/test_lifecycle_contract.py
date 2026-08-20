from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from continuityforge.cli import build_parser, main
from continuityforge.constants import CLI_COMMAND_LIFECYCLE
from continuityforge.exceptions import ReadOnlyStorageError
from continuityforge.schema import (
    SchemaKind,
    V02_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    classify_schema,
)
from continuityforge.storage import Storage


EXISTING_ONLY_ARGUMENTS = {
    "source-list": [],
    "claim-propose": [
        "--persona",
        "mira",
        "--continuity",
        "alpha",
        "--claim",
        "fact",
    ],
    "claim-add": [
        "--persona",
        "mira",
        "--continuity",
        "alpha",
        "--claim",
        "fact",
    ],
    "claim-review": [
        "claim",
        "--status",
        "authorized",
        "--reviewer",
        "reviewer",
        "--reason",
        "verified",
    ],
    "claim-list": [],
    "event-add": [
        "--persona",
        "mira",
        "--continuity",
        "alpha",
        "--title",
        "Event",
        "--summary",
        "Summary",
    ],
    "validate": ["--json"],
    "compile": [
        "--persona",
        "mira",
        "--continuity",
        "alpha",
        "--cutoff",
        "2026-01-01T00:00:00Z",
    ],
    "ledger-verify": [],
    "ledger-show": [],
    "source-impact": [
        "--source-key",
        "story",
        "--continuity",
        "alpha",
    ],
    "migration-check": [],
    "migrate": [],
}

CURRENT_ONLY_COMMANDS = tuple(
    command
    for command in EXISTING_ONLY_ARGUMENTS
    if command not in {"source-impact", "migration-check", "migrate"}
)


def _json_error(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().err)


def _create_v01(database: Path, project_root: Path) -> None:
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript(
            (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.commit()


def _create_v02(database: Path) -> None:
    with Storage(database):
        pass
    with closing(sqlite3.connect(database)) as connection:
        for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
            connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
        connection.execute("UPDATE schema_metadata SET schema_version = 2")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
        assert classify_schema(connection) is SchemaKind.V02


def _digest(database: Path) -> str:
    return sha256(database.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("command", "arguments"),
    tuple(EXISTING_ONLY_ARGUMENTS.items()),
    ids=tuple(EXISTING_ONLY_ARGUMENTS),
)
def test_existing_only_commands_reject_missing_db_without_filesystem_side_effects(
    tmp_path: Path,
    capsys,
    command: str,
    arguments: list[str],
) -> None:
    database = tmp_path / command / "missing.db"

    result = main(["--db", str(database), command, *arguments])

    assert result == 6
    assert _json_error(capsys) == {
        "schema": "continuityforge.error/v0.3",
        "code": "DATABASE_NOT_FOUND",
        "error": "DatabaseNotFoundError",
        "message": "project database not found",
    }
    assert not database.exists()
    assert not database.parent.exists()


@pytest.mark.parametrize("command", CURRENT_ONLY_COMMANDS)
@pytest.mark.parametrize("legacy_version", (1, 2))
def test_ordinary_commands_never_implicitly_migrate_legacy_databases(
    tmp_path: Path,
    project_root: Path,
    capsys,
    command: str,
    legacy_version: int,
) -> None:
    database = tmp_path / f"legacy-v{legacy_version}-{command}.db"
    if legacy_version == 1:
        _create_v01(database, project_root)
    else:
        _create_v02(database)
    before = _digest(database)

    result = main(
        ["--db", str(database), command, *EXISTING_ONLY_ARGUMENTS[command]]
    )

    assert result == 6
    error = _json_error(capsys)
    assert error["code"] == "MIGRATION_REQUIRED"
    assert error["error"] == "ExplicitMigrationRequiredError"
    assert _digest(database) == before
    assert not list(tmp_path.glob(f"{database.name}.pre-v3*.bak"))
    with closing(sqlite3.connect(database)) as connection:
        assert classify_schema(connection) is (
            SchemaKind.V01 if legacy_version == 1 else SchemaKind.V02
        )


def test_ingest_is_create_capable_but_write_commands_are_not(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "story.txt"
    source.write_text("fact\n", encoding="utf-8")
    database = tmp_path / "new" / "forge.db"

    assert (
        main(
            [
                "--db",
                str(database),
                "ingest",
                str(source),
                "--continuity",
                "alpha",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["ingested"][0]["version"] == 1
    assert database.is_file()


def test_create_capable_commands_do_not_migrate_an_existing_legacy_db(
    tmp_path: Path, project_root: Path, capsys
) -> None:
    source = tmp_path / "story.txt"
    source.write_text("fact\n", encoding="utf-8")
    ingest_database = tmp_path / "legacy-ingest.db"
    _create_v01(ingest_database, project_root)
    ingest_before = _digest(ingest_database)

    assert (
        main(
            [
                "--db",
                str(ingest_database),
                "ingest",
                str(source),
                "--continuity",
                "alpha",
            ]
        )
        == 6
    )
    assert _json_error(capsys)["code"] == "MIGRATION_REQUIRED"
    assert _digest(ingest_database) == ingest_before

    output_dir = tmp_path / "demo"
    output_dir.mkdir()
    demo_database = output_dir / "continuityforge-demo.db"
    _create_v01(demo_database, project_root)
    demo_before = _digest(demo_database)

    assert main(["demo", "--output-dir", str(output_dir)]) == 6
    assert _json_error(capsys)["code"] == "MIGRATION_REQUIRED"
    assert _digest(demo_database) == demo_before
    assert not list(tmp_path.rglob("*.pre-v3*.bak"))


def test_demo_is_create_capable(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "new-demo"

    assert main(["demo", "--output-dir", str(output_dir)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["pass"] is True
    assert all(result["checks"].values())
    assert (output_dir / "continuityforge-demo.db").is_file()


def test_every_parser_command_has_the_frozen_lifecycle() -> None:
    parser = build_parser()
    samples = {
        "ingest": ["story.txt", "--continuity", "alpha"],
        "demo": [],
        **EXISTING_ONLY_ARGUMENTS,
    }
    for command, arguments in samples.items():
        namespace = parser.parse_args([command, *arguments])
        assert namespace.lifecycle == CLI_COMMAND_LIFECYCLE[command]


@pytest.mark.parametrize(
    ("command", "arguments"),
    (("source-list", []), ("validate", ["--json"])),
)
def test_read_commands_do_not_create_a_missing_wal_shm_sidecar(
    tmp_path: Path,
    capsys,
    command: str,
    arguments: list[str],
) -> None:
    source = tmp_path / "source.db"
    with Storage(source):
        pass
    writer = sqlite3.connect(source, isolation_level=None)
    try:
        writer.execute("PRAGMA journal_mode = WAL")
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE schema_metadata SET migration_notes = ? WHERE singleton = 1",
            ("sidecar_probe",),
        )
        writer.execute("COMMIT")
        source_wal = source.with_name(source.name + "-wal")
        assert source_wal.exists()

        copied = tmp_path / f"copied-{command}.db"
        copied_wal = copied.with_name(copied.name + "-wal")
        copied_shm = copied.with_name(copied.name + "-shm")
        shutil.copyfile(source, copied)
        shutil.copyfile(source_wal, copied_wal)
        assert not copied_shm.exists()

        result = main(["--db", str(copied), command, *arguments])

        assert result == 6
        error = _json_error(capsys)
        assert error["code"] == "READ_ONLY_STORAGE_ERROR"
        assert "-shm" in str(error["message"])
        assert not copied_shm.exists()
        with pytest.raises(ReadOnlyStorageError, match="-shm"):
            Storage.open_readonly(copied)
        assert not copied_shm.exists()
        with pytest.raises(ReadOnlyStorageError, match="filesystem path"):
            Storage.open_readonly(copied.resolve().as_uri() + "?mode=ro")
        assert not copied_shm.exists()
    finally:
        writer.close()
