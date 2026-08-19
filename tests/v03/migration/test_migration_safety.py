from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.exceptions import MigrationError
from continuityforge.governance_integrity import validate_claim_authority
from continuityforge.models import MemoryCutoff
from continuityforge.migrations import MigrationMode
from continuityforge.schema import (
    SchemaKind,
    V02_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    classify_schema,
)
from continuityforge.storage import Storage


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_v01(database: Path, project_root: Path) -> None:
    connection = sqlite3.connect(database)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.close()


def _downgrade_migrated_fixture_to_old_v2(database: Path, project_root: Path) -> None:
    _create_v01(database, project_root)
    with Storage(database):
        pass
    connection = sqlite3.connect(database)
    for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
        connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
    # Restore the two v0.2 ledger immutability triggers after clearing the
    # complete v0.3 authority stream.  This reproduces the old v0.1 migrator,
    # which created decision rows but no claim ledger entries.
    connection.execute("DROP TRIGGER IF EXISTS continuityforge_ledger_no_update")
    connection.execute("DROP TRIGGER IF EXISTS continuityforge_ledger_no_delete")
    connection.execute("DELETE FROM event_ledger")
    connection.executescript(
        """
        CREATE TRIGGER continuityforge_ledger_no_update
        BEFORE UPDATE ON event_ledger BEGIN
            SELECT RAISE(ABORT, 'EventLedger is append-only');
        END;
        CREATE TRIGGER continuityforge_ledger_no_delete
        BEFORE DELETE ON event_ledger BEGIN
            SELECT RAISE(ABORT, 'EventLedger is append-only');
        END;
        """
    )
    connection.execute("UPDATE schema_metadata SET schema_version = 2")
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()


def test_canonical_v01_migrates_with_replayable_authority_and_backup(
    tmp_path, project_root
):
    database = tmp_path / "legacy.db"
    _create_v01(database, project_root)

    with Storage(database) as storage:
        report = storage.migration_report
        assert report is not None and report.succeeded
        assert report.backup_path is not None
        counts = dict(report.migrated_counts)
        assert counts
        expected_tables = {
            "sources": "sources",
            "snapshots": "source_snapshots",
            "claims": "claim_proposals",
            "evidence": "evidence_refs",
            "events": "narrative_events",
            "event_evidence": "event_evidence_refs",
            "decisions": "governance_decisions",
            "ledger": "event_ledger",
            "legacy_records": "legacy_records",
        }
        assert counts == {
            label: storage.connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]
            for label, table in expected_tables.items()
        }
        claim = storage.get_claim_proposal("legacy-claim-alpha")
        authority = validate_claim_authority(storage, claim)
        assert authority.is_authorized
        entries = storage.list_ledger_entries(
            aggregate_type="claim", aggregate_id=claim.claim_id
        )
        assert [entry.event_type for entry in entries] == [
            "claim.proposed",
            "claim.governance_decided",
        ]
        decision = storage.list_governance_decisions(claim_id=claim.claim_id)[0]
        assert entries[1].payload == {
            "decision_id": decision.decision_id,
            "from_status": decision.from_status.value,
            "to_status": decision.to_status.value,
            "reviewer": decision.reviewer,
            "reason": decision.reason,
        }

    backup = sqlite3.connect(report.backup_path)
    try:
        assert classify_schema(backup) is SchemaKind.V01
    finally:
        backup.close()


def test_old_v2_authority_omission_is_backfilled_before_compile(
    tmp_path, project_root
):
    database = tmp_path / "old-v2.db"
    _downgrade_migrated_fixture_to_old_v2(database, project_root)

    with Storage(database) as storage:
        assert storage.get_schema_version() == 3
        claim = storage.get_claim_proposal("legacy-claim-alpha")
        assert validate_claim_authority(storage, claim).is_authorized
        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("alice", "alpha", "2026-01-04T00:00:00Z")
        )
        assert [item["id"] for item in pack["claims"]] == [claim.claim_id]


def test_strict_bad_legacy_hash_aborts_before_mutation(tmp_path, project_root):
    database = tmp_path / "bad-hash.db"
    _create_v01(database, project_root)
    connection = sqlite3.connect(database)
    connection.execute("UPDATE source_snapshots SET sha256 = ?", ("0" * 64,))
    connection.commit()
    connection.close()
    before = _digest(database)

    with pytest.raises(MigrationError) as caught:
        Storage(database)

    assert "MIGRATION_SNAPSHOT_HASH_MISMATCH" in {
        issue.code for issue in caught.value.report.issues
    }
    assert _digest(database) == before
    assert not list(tmp_path.glob("bad-hash.db.pre-v3*.bak"))


def test_explicit_quarantine_retains_bad_claim_only_as_legacy_record(
    tmp_path, project_root
):
    database = tmp_path / "quarantine-claim.db"
    _create_v01(database, project_root)
    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE claims SET access_policy = ?, knowledge_from = ?",
        ("mystery", "not-a-time"),
    )
    connection.commit()
    connection.close()

    with Storage(database, migration_mode=MigrationMode.QUARANTINE) as storage:
        report = storage.migration_report
        assert report is not None and report.succeeded
        assert ("claims", "legacy-claim-alpha") in report.quarantined
        assert storage.list_claim_proposals() == []
        retained = storage.list_legacy_records(original_table="claims")
        assert len(retained) == 1
        assert retained[0]["migrated_entity_id"] is None
        assert retained[0]["payload"]["access_policy"] == "mystery"
        assert retained[0]["payload"]["knowledge_from"] == "not-a-time"


def test_quarantined_snapshot_also_quarantines_dependent_claim(
    tmp_path, project_root
):
    database = tmp_path / "quarantine-snapshot.db"
    _create_v01(database, project_root)
    connection = sqlite3.connect(database)
    connection.execute("UPDATE source_snapshots SET sha256 = ?", ("0" * 64,))
    connection.commit()
    connection.close()

    with Storage(database, migration_mode="quarantine") as storage:
        report = storage.migration_report
        assert report is not None
        assert ("source_snapshots", "legacy-snapshot-alpha") in report.quarantined
        assert ("claims", "legacy-claim-alpha") in report.quarantined
        assert storage.list_snapshots() == []
        assert storage.list_claim_proposals() == []
        assert {
            item["original_table"] for item in storage.list_legacy_records()
        } >= {"source_snapshots", "claims"}
