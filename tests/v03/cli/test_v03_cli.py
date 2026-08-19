from __future__ import annotations

from hashlib import sha256
import json
import sqlite3

from continuityforge.cli import main
from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_content
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.storage import Storage


def _captured_json(capsys, *, stderr: bool = False):
    captured = capsys.readouterr()
    return json.loads(captured.err if stderr else captured.out)


def _digest(path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _revision_project(path) -> None:
    with Storage(path) as storage:
        _, old, _ = ingest_content(
            storage,
            "Mira entered the observatory.\nThe bell rang.\n",
            "north-pier",
            "alpha",
        )
        claim_ref = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        ClaimGovernance(storage).add_authorized_human_claim(
            ClaimProposal(
                persona_id="mira",
                continuity="alpha",
                text="Mira entered the observatory.",
                knowledge_from="2026-01-01T00:00:00Z",
            ),
            [claim_ref],
        )
        event_ref = build_evidence_ref(storage, old.snapshot_id, 2, 2)
        storage.create_narrative_event(
            NarrativeEvent(
                persona_id="mira",
                continuity="alpha",
                title="The bell rang",
                summary="The bell rang.",
                knowledge_from="2026-01-01T00:00:00Z",
            ),
            [event_ref],
        )
        ingest_content(
            storage,
            "A storm arrived.\nMira entered the observatory.\nThe bell rang.\n",
            "north-pier",
            "alpha",
        )


def test_source_impact_cli_is_read_only_metadata_only_and_report_only(
    tmp_path, capsys
):
    database = tmp_path / "forge.db"
    _revision_project(database)
    before = _digest(database)

    exit_code = main(
        [
            "--db",
            str(database),
            "source-impact",
            "--source-key",
            "north-pier",
            "--continuity",
            "alpha",
        ]
    )

    assert exit_code == 0
    report = _captured_json(capsys)
    assert report["report_only"] is True
    assert report["from_snapshot"]["version"] == 1
    assert report["to_snapshot"]["version"] == 2
    assert report["summary"]["claims"] == 1
    assert report["summary"]["events"] == 1
    assert report["summary"]["outcomes"]["EXACT_MOVED_UNIQUE"] == 2
    encoded = json.dumps(report, ensure_ascii=False)
    assert "Mira entered" not in encoded
    assert "The bell rang" not in encoded
    assert _digest(database) == before
    assert not database.with_name(database.name + "-wal").exists()
    assert not database.with_name(database.name + "-shm").exists()


def test_source_impact_cli_uses_stable_metadata_injection_error(tmp_path, capsys):
    database = tmp_path / "unsafe-metadata.db"
    _revision_project(database)
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT source_id FROM sources").fetchone()
        assert row is not None
        source_id = str(row[0])
        connection.execute(
            "UPDATE sources SET source_key = ? WHERE source_id = ?",
            ("\x1b[31mCANARY", source_id),
        )
    before = _digest(database)

    assert (
        main(
            [
                "--db",
                str(database),
                "source-impact",
                "--source-id",
                source_id,
                "--continuity",
                "alpha",
            ]
        )
        == 3
    )
    error = _captured_json(capsys, stderr=True)
    assert error["schema"] == "continuityforge.error/v0.3"
    assert error["code"] == "REPORT_METADATA_CONTROL_CHARACTER"
    assert "CANARY" not in json.dumps(error, ensure_ascii=False)
    assert _digest(database) == before


def test_migration_check_accepts_current_v3_without_modifying_file(tmp_path, capsys):
    database = tmp_path / "forge.db"
    _revision_project(database)
    before = _digest(database)

    assert main(["--db", str(database), "migration-check"]) == 0

    report = _captured_json(capsys)
    assert report["source"]["kind"] == "v0.3"
    assert report["is_ready"] is True
    assert report["checks"]["backup_path"] is None
    assert _digest(database) == before


def test_migration_check_fails_closed_for_unknown_database(tmp_path, capsys):
    database = tmp_path / "foreign.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('preserve me')")
    before = database.read_bytes()

    assert main(["--db", str(database), "migration-check"]) == 6

    report = _captured_json(capsys)
    assert report["source"]["kind"] == "unknown"
    assert report["is_ready"] is False
    assert {item["code"] for item in report["issues"]} == {
        "MIGRATION_SCHEMA_UNRECOGNIZED"
    }
    assert database.read_bytes() == before


def test_read_only_commands_do_not_create_a_missing_database_or_leak_path(
    tmp_path, capsys
):
    database = tmp_path / "private" / "missing.db"

    assert (
        main(
            [
                "--db",
                str(database),
                "source-impact",
                "--source-key",
                "story",
                "--continuity",
                "alpha",
            ]
        )
        != 0
    )

    error = _captured_json(capsys, stderr=True)
    assert error["schema"] == "continuityforge.error/v0.3"
    assert error["code"] == "NOT_FOUND"
    assert str(database) not in error["message"]
    assert "<DB>" in error["message"]
    assert not database.exists()
    assert not database.parent.exists()


def test_migrate_requires_an_existing_database(tmp_path, capsys):
    database = tmp_path / "missing.db"

    assert main(["--db", str(database), "migrate"]) != 0

    error = _captured_json(capsys, stderr=True)
    assert error["code"] == "NOT_FOUND"
    assert not database.exists()


def _event_with_details_args(database, details: str) -> list[str]:
    return [
        "--db",
        str(database),
        "event-add",
        "--persona",
        "mira",
        "--continuity",
        "alpha",
        "--title",
        "Invalid details",
        "--summary",
        "This row must never be stored.",
        "--details",
        details,
    ]


def test_event_details_reject_nonfinite_json_numbers(tmp_path, capsys):
    database = tmp_path / "forge.db"

    exit_code = main(_event_with_details_args(database, '{"score": NaN}'))

    assert exit_code != 0
    error = _captured_json(capsys, stderr=True)
    assert error["code"] == "NONFINITE_JSON_NUMBER"
    with Storage(database) as storage:
        assert storage.list_narrative_events() == []


def test_event_details_reject_duplicate_keys_and_excessive_depth(tmp_path, capsys):
    for index, (details, expected_code) in enumerate(
        (
            ('{"role": "operator", "role": "model"}', "DUPLICATE_JSON_KEY"),
            ('{"nested":' + "[" * 300 + "0" + "]" * 300 + "}", "JSON_NESTING_LIMIT"),
        )
    ):
        database = tmp_path / f"forge-{index}.db"
        assert main(_event_with_details_args(database, details)) != 0
        error = _captured_json(capsys, stderr=True)
        assert error["code"] == expected_code
        with Storage(database) as storage:
            assert storage.list_narrative_events() == []


def test_cli_preflight_then_backup_gated_v01_migration(
    tmp_path, project_root, capsys
):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
                encoding="utf-8"
            )
        )
    before = _digest(database)

    assert main(["--db", str(database), "migration-check"]) == 0
    preflight = _captured_json(capsys)
    assert preflight["source"]["kind"] == "v0.1"
    assert preflight["is_ready"] is True
    assert preflight["checks"]["backup_path"] is None
    assert _digest(database) == before

    assert main(["--db", str(database), "migrate"]) == 0
    migrated = _captured_json(capsys)
    assert migrated["status"] == "migrated"
    assert migrated["succeeded"] is True
    assert migrated["target"]["kind"] == "v0.3"
    backup = migrated["checks"]["backup_path"]
    assert backup is not None
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    with Storage(database) as storage:
        assert storage.get_schema_version() == 3
        assert storage.verify_ledger()
