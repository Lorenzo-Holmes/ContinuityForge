from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.exceptions import MigrationError
from continuityforge.governance_integrity import validate_claim_authority
from continuityforge.models import MemoryCutoff
from continuityforge.migrations import MigrationMode, preflight_migration
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
        assert entries[0].payload["material_version"] == 2
        assert len(entries[0].payload["aggregate_sha256"]) == 64
        assert len(entries[0].payload["evidence_set_sha256"]) == 64
        assert not storage.list_ledger_entries(
            event_type="claim.material_attested",
            aggregate_type="claim",
            aggregate_id=claim.claim_id,
        )
        event_creations = storage.list_ledger_entries(
            event_type="narrative_event.created",
            aggregate_type="narrative_event",
        )
        assert all(entry.payload["material_version"] == 2 for entry in event_creations)
        assert not storage.list_ledger_entries(
            event_type="narrative_event.material_attested",
            aggregate_type="narrative_event",
        )
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
    before = _digest(database)
    backups_before = set(tmp_path.glob("old-v2.db.pre-v3*.bak"))

    with pytest.raises(MigrationError) as caught:
        Storage(database)
    assert caught.value.report is not None
    assert "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED" in {
        issue.code for issue in caught.value.report.issues
    }
    assert caught.value.report.backup_path is None
    assert _digest(database) == before
    assert set(tmp_path.glob("old-v2.db.pre-v3*.bak")) == backups_before

    with Storage(database, attest_current_legacy_material=True) as storage:
        assert storage.get_schema_version() == 3
        assert storage.migration_report is not None
        assert storage.migration_report.backup_path is not None
        assert dict(storage.migration_report.attestation_counts) == {
            "claims": 0,
            "events": 0,
        }
        claim = storage.get_claim_proposal("legacy-claim-alpha")
        assert validate_claim_authority(storage, claim).is_authorized
        creation = storage.list_ledger_entries(
            event_type="claim.proposed",
            aggregate_type="claim",
            aggregate_id=claim.claim_id,
        )
        assert len(creation) == 1
        assert creation[0].payload["material_version"] == 2
        assert not storage.list_ledger_entries(
            event_type="claim.material_attested",
            aggregate_type="claim",
            aggregate_id=claim.claim_id,
        )
        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("alice", "alpha", "2026-01-04T00:00:00Z")
        )
        assert [item["id"] for item in pack["claims"]] == [claim.claim_id]


def test_old_v2_empty_authorized_claim_stream_still_requires_evidence_pre_backup(
    tmp_path, project_root
):
    database = tmp_path / "old-v2-no-claim-evidence.db"
    _downgrade_migrated_fixture_to_old_v2(database, project_root)
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        DROP TRIGGER continuityforge_evidence_no_delete;
        DELETE FROM evidence_refs;
        CREATE TRIGGER continuityforge_evidence_no_delete
        BEFORE DELETE ON evidence_refs BEGIN
            SELECT RAISE(ABORT, 'EvidenceRef rows are immutable');
        END;
        """
    )
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()
    backups_before = set(tmp_path.glob("old-v2-no-claim-evidence.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_EVIDENCE_REQUIRED" in {issue.code for issue in report.issues}
    assert (
        set(tmp_path.glob("old-v2-no-claim-evidence.db.pre-v3*.bak"))
        == backups_before
    )


def test_early_v2_without_event_evidence_table_fails_pre_backup(
    tmp_path, project_root
):
    database = tmp_path / "early-v2-no-event-evidence.db"
    _downgrade_migrated_fixture_to_old_v2(database, project_root)
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO narrative_events "
        "(event_id, persona_id, continuity, event_type, title, summary, details_json, "
        "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evt_early_v2",
            "alice",
            "alpha",
            "legacy.event",
            "Legacy event",
            "No Event Evidence table exists.",
            "{}",
            None,
            None,
            None,
            None,
            "agent_accessible",
            "2026-01-01T00:00:00Z",
        ),
    )
    connection.execute("DROP TABLE event_evidence_refs")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()
    backups_before = set(tmp_path.glob("early-v2-no-event-evidence.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_EVENT_EVIDENCE_REQUIRED" in {
        issue.code for issue in report.issues
    }
    assert (
        set(tmp_path.glob("early-v2-no-event-evidence.db.pre-v3*.bak"))
        == backups_before
    )


def test_old_v2_source_cache_and_partial_audit_fail_before_backup(
    tmp_path, project_root
):
    cache_database = tmp_path / "old-v2-source-cache.db"
    _downgrade_migrated_fixture_to_old_v2(cache_database, project_root)
    connection = sqlite3.connect(cache_database)
    connection.execute(
        "UPDATE sources SET updated_at = ?",
        ("2029-01-01T00:00:00Z",),
    )
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()
    cache_backups = set(tmp_path.glob("old-v2-source-cache.db.pre-v3*.bak"))

    cache_report = preflight_migration(
        cache_database,
        create_backup=True,
        attest_current_legacy_material=True,
    )
    assert not cache_report.is_ready
    assert cache_report.backup_path is None
    assert "MIGRATION_SOURCE_AUDIT_INVALID" in {
        issue.code for issue in cache_report.issues
    }
    assert set(tmp_path.glob("old-v2-source-cache.db.pre-v3*.bak")) == cache_backups

    partial_database = tmp_path / "old-v2-source-partial.db"
    _downgrade_migrated_fixture_to_old_v2(partial_database, project_root)
    connection = sqlite3.connect(partial_database)
    connection.row_factory = sqlite3.Row
    source = connection.execute("SELECT * FROM sources LIMIT 1").fetchone()
    assert source is not None
    payload_json = json.dumps(
        {
            "source_key": str(source["source_key"]),
            "continuity": str(source["continuity"]),
            "audit_backfill": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    entry_hash = Storage._ledger_digest(
        sequence=1,
        entry_id="led_partial_source",
        event_type="source.created",
        aggregate_type="source",
        aggregate_id=str(source["source_id"]),
        payload_json=payload_json,
        previous_hash="0" * 64,
        created_at=str(source["created_at"]),
    )
    connection.execute(
        "INSERT INTO event_ledger "
        "(sequence, entry_id, event_type, aggregate_type, aggregate_id, payload_json, "
        "previous_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1,
            "led_partial_source",
            "source.created",
            "source",
            str(source["source_id"]),
            payload_json,
            "0" * 64,
            entry_hash,
            str(source["created_at"]),
        ),
    )
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()
    partial_backups = set(tmp_path.glob("old-v2-source-partial.db.pre-v3*.bak"))

    partial_report = preflight_migration(
        partial_database,
        create_backup=True,
        attest_current_legacy_material=True,
    )
    assert not partial_report.is_ready
    assert partial_report.backup_path is None
    assert "MIGRATION_SOURCE_AUDIT_INVALID" in {
        issue.code for issue in partial_report.issues
    }
    assert (
        set(tmp_path.glob("old-v2-source-partial.db.pre-v3*.bak"))
        == partial_backups
    )


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
