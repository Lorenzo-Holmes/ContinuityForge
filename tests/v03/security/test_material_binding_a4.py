from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

import pytest

from continuityforge.exceptions import MigrationError
from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.migrations import migrate_to_v3, preflight_migration
from continuityforge.models import ClaimProposal, MemoryCutoff, NarrativeEvent
from continuityforge.schema import (
    SchemaKind,
    V02_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    classify_schema,
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
            "UPDATE event_ledger SET previous_hash = ?, entry_hash = ? WHERE sequence = ?",
            (previous_hash, entry_hash, int(row["sequence"])),
        )
        previous_hash = entry_hash


def _database_sha256(database: Path) -> str:
    return sha256(database.read_bytes()).hexdigest()


def _downgrade_to_v02(database: Path) -> None:
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        trigger_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        trigger_sql = {str(row["name"]): str(row["sql"]) for row in trigger_rows}
        for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
            connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
        for name in (
            "continuityforge_ledger_no_update",
            "continuityforge_ledger_no_delete",
        ):
            connection.execute(f'DROP TRIGGER "{name}"')
        rows = connection.execute(
            "SELECT sequence, payload_json FROM event_ledger "
            "WHERE event_type IN "
            "('claim.proposed', 'claim.evidence_added', 'narrative_event.created')"
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
        connection.execute("UPDATE schema_metadata SET schema_version = 2")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
        assert classify_schema(connection) is SchemaKind.V02


def _make_tampered_v02(database: Path) -> None:
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot(
            "story", "alpha", "attested anchor\n"
        )
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        ClaimGovernance(storage).add_authorized_human_claim(
            ClaimProposal(
                claim_id="future-claim",
                persona_id="persona",
                continuity="alpha",
                text="future-only claim",
                knowledge_from="2099-01-01T00:00:00Z",
            ),
            (evidence,),
            reviewer="reviewer",
            reason="source supports the claim, but it is not yet known",
        )
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="expired-event",
                persona_id="persona",
                continuity="alpha",
                title="Expired event",
                summary="This event left memory before the cutoff.",
                knowledge_from="2020-01-01T00:00:00Z",
                knowledge_to="2021-01-01T00:00:00Z",
            ),
            (evidence,),
        )

    _downgrade_to_v02(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE claim_proposals SET knowledge_from = ? WHERE claim_id = ?",
            ("2020-01-01T00:00:00Z", "future-claim"),
        )
        connection.execute(
            "UPDATE narrative_events SET knowledge_to = NULL WHERE event_id = ?",
            ("expired-event",),
        )
        connection.commit()


def test_v02_omitted_material_requires_opt_in_before_backup_or_mutation(
    tmp_path: Path,
) -> None:
    """Canonical v0.2 omitted fields have no recoverable historical value."""

    database = tmp_path / "v02-unbound-visibility.db"
    _make_tampered_v02(database)
    before = _database_sha256(database)

    preflight = preflight_migration(database, create_backup=True)
    assert preflight.source.kind is SchemaKind.V02
    assert preflight.is_ready is False
    assert preflight.backup_path is None
    assert "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED" in {
        issue.code for issue in preflight.issues
    }
    assert _database_sha256(database) == before
    assert list(tmp_path.glob("*.bak")) == []

    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(database, create_backup=True)
    assert caught.value.report is not None
    assert caught.value.report.backup_path is None
    assert _database_sha256(database) == before
    assert list(tmp_path.glob("*.bak")) == []


def test_v02_explicit_operator_attestation_accepts_current_material(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v02-explicit-baseline.db"
    _make_tampered_v02(database)

    report = migrate_to_v3(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )
    assert report.succeeded

    with Storage(database) as storage:
        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("persona", "alpha", "2026-01-01T00:00:00Z")
        )
    assert [item["id"] for item in pack["claims"]] == ["future-claim"]
    assert [item["id"] for item in pack["events"]] == ["expired-event"]
