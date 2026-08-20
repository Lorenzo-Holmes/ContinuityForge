from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3

from continuityforge.cli import main
from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.models import ClaimProposal
from continuityforge.schema import (
    SchemaKind,
    V03_ALPHA3_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    fingerprint_schema,
)
from continuityforge.storage import Storage


_MATERIAL_FIELDS = {
    "material_version",
    "aggregate_sha256",
    "evidence_set_sha256",
}


def _rehash_ledger(connection: sqlite3.Connection) -> None:
    previous_hash = "0" * 64
    for row in connection.execute(
        "SELECT * FROM event_ledger ORDER BY sequence"
    ).fetchall():
        entry_hash = Storage._ledger_digest(
            sequence=int(row["sequence"]),
            entry_id=str(row["entry_id"]),
            event_type=str(row["event_type"]),
            aggregate_type=str(row["aggregate_type"]),
            aggregate_id=str(row["aggregate_id"]),
            payload_json=str(row["payload_json"]),
            previous_hash=previous_hash,
            created_at=str(row["created_at"]),
        )
        connection.execute(
            "UPDATE event_ledger SET previous_hash = ?, entry_hash = ? "
            "WHERE sequence = ?",
            (previous_hash, entry_hash, int(row["sequence"])),
        )
        previous_hash = entry_hash


def _make_alpha3(database: Path) -> None:
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot(
            "cli/material", "alpha", "legacy material\n"
        )
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        ClaimGovernance(storage).propose(
            ClaimProposal(
                claim_id="clm_cli_material",
                persona_id="persona",
                continuity="alpha",
                text="legacy material",
                rationale="operator must accept this current row",
            ),
            (evidence,),
        )

    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        trigger_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        trigger_sql = {str(row["name"]): str(row["sql"]) for row in trigger_rows}
        for name in V03_REQUIRED_TRIGGERS - V03_ALPHA3_REQUIRED_TRIGGERS:
            connection.execute(f'DROP TRIGGER "{name}"')
        for name in (
            "continuityforge_ledger_no_update",
            "continuityforge_ledger_no_delete",
        ):
            connection.execute(f'DROP TRIGGER "{name}"')
        rows = connection.execute(
            "SELECT sequence, payload_json FROM event_ledger "
            "WHERE event_type = 'claim.proposed'"
        ).fetchall()
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            for field in _MATERIAL_FIELDS:
                payload.pop(field, None)
            connection.execute(
                "UPDATE event_ledger SET payload_json = ? WHERE sequence = ?",
                (
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    int(row["sequence"]),
                ),
            )
        _rehash_ledger(connection)
        for name in (
            "continuityforge_ledger_no_update",
            "continuityforge_ledger_no_delete",
        ):
            connection.execute(trigger_sql[name])
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3


def test_cli_requires_explicit_material_attestation_and_then_migrates(
    tmp_path: Path, capsys
) -> None:
    database = tmp_path / "alpha3.db"
    _make_alpha3(database)

    assert main(["--db", str(database), "migration-check"]) == 6
    check = json.loads(capsys.readouterr().out)
    assert check["is_ready"] is False
    assert {item["code"] for item in check["issues"]} >= {
        "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED"
    }
    assert check["checks"]["backup_path"] is None

    assert main(["--db", str(database), "migrate"]) == 6
    error = json.loads(capsys.readouterr().err)
    assert error["schema"] == "continuityforge.error/v0.3"
    assert error["code"] == "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED"
    assert not list(tmp_path.glob("*.bak"))
    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3

    assert (
        main(
            [
                "--db",
                str(database),
                "migration-check",
                "--attest-current-legacy-material",
            ]
        )
        == 0
    )
    accepted_check = json.loads(capsys.readouterr().out)
    assert accepted_check["is_ready"] is True
    assert accepted_check["checks"]["backup_path"] is None

    assert (
        main(
            [
                "--db",
                str(database),
                "migrate",
                "--attest-current-legacy-material",
            ]
        )
        == 0
    )
    migrated = json.loads(capsys.readouterr().out)
    assert migrated["succeeded"] is True
    assert migrated["source"]["kind"] == "v0.3-alpha3"
    assert migrated["target"]["kind"] == "v0.3"
    assert migrated["attestations"] == {
        "material_version": 2,
        "claims": 1,
        "events": 0,
    }


def test_ordinary_cli_commands_classify_alpha3_as_migration_required(
    tmp_path: Path, capsys
) -> None:
    database = tmp_path / "alpha3-current-gate.db"
    _make_alpha3(database)

    assert main(["--db", str(database), "source-list"]) == 6

    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "MIGRATION_REQUIRED"
    assert error["error"] == "ExplicitMigrationRequiredError"
