from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

import continuityforge.migrations as migrations
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import MigrationError, SchemaError
from continuityforge.migrations import MigrationIssue, MigrationMode, MigrationReport
from continuityforge.models import ClaimProposal, GovernanceStatus
from continuityforge.schema import (
    SchemaKind,
    V02_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    classify_schema,
    fingerprint_schema,
)
from continuityforge.storage import GENESIS_HASH, Storage


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


def _recompute_ledger(connection: sqlite3.Connection) -> None:
    connection.row_factory = sqlite3.Row
    previous = GENESIS_HASH
    for row in connection.execute("SELECT * FROM event_ledger ORDER BY sequence"):
        digest = Storage._ledger_digest(
            sequence=int(row["sequence"]),
            entry_id=str(row["entry_id"]),
            event_type=str(row["event_type"]),
            aggregate_type=str(row["aggregate_type"]),
            aggregate_id=str(row["aggregate_id"]),
            payload_json=str(row["payload_json"]),
            previous_hash=previous,
            created_at=str(row["created_at"]),
        )
        connection.execute(
            "UPDATE event_ledger SET previous_hash = ?, entry_hash = ? WHERE sequence = ?",
            (previous, digest, int(row["sequence"])),
        )
        previous = digest


def _create_semantically_corrupt_v02(database: Path) -> None:
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot("story", "alpha", "fact")
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        claim = storage.create_claim_proposal(
            ClaimProposal(
                claim_id="claim",
                persona_id="persona",
                continuity="alpha",
                text="fact",
            ),
            (evidence,),
        )
        storage.record_governance_decision(
            claim.claim_id,
            GovernanceStatus.AUTHORIZED,
            reviewer="reviewer",
            reason="verified",
        )

    connection = sqlite3.connect(database)
    for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
        connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
    connection.execute("DROP TRIGGER continuityforge_ledger_no_update")
    row = connection.execute(
        "SELECT sequence, payload_json FROM event_ledger "
        "WHERE event_type = 'claim.governance_decided'"
    ).fetchone()
    assert row is not None
    payload = json.loads(str(row[1]))
    payload["decision_id"] = "dec_orphan"
    connection.execute(
        "UPDATE event_ledger SET payload_json = ? WHERE sequence = ?",
        (json.dumps(payload, sort_keys=True, separators=(",", ":")), int(row[0])),
    )
    _recompute_ledger(connection)
    connection.executescript(
        """
        CREATE TRIGGER continuityforge_ledger_no_update
        BEFORE UPDATE ON event_ledger BEGIN
            SELECT RAISE(ABORT, 'EventLedger is append-only');
        END;
        """
    )
    connection.execute("UPDATE schema_metadata SET schema_version = 2")
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()


def _create_v02_with_unledgered_evidence(database: Path) -> None:
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot("story", "alpha", "fact")
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        claim = storage.create_claim_proposal(
            ClaimProposal(
                claim_id="claim",
                persona_id="persona",
                continuity="alpha",
                text="fact",
            ),
            (evidence,),
        )
        storage.record_governance_decision(
            claim.claim_id,
            GovernanceStatus.AUTHORIZED,
            reviewer="reviewer",
            reason="verified",
        )
        existing = storage.get_claim_evidence(claim.claim_id)[0]

    connection = sqlite3.connect(database)
    for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
        connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
    connection.execute(
        "INSERT INTO evidence_refs "
        "(evidence_id, claim_id, snapshot_id, start_line, end_line, quote, "
        "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evr_unledgered",
            claim.claim_id,
            existing.snapshot_id,
            existing.start_line,
            existing.end_line,
            existing.quote,
            existing.content_hash,
            "2026-08-19T00:00:00Z",
        ),
    )
    connection.execute("UPDATE schema_metadata SET schema_version = 2")
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    assert classify_schema(connection) is SchemaKind.V02
    connection.close()


def test_v02_exact_authority_correspondence_is_a_preflight_gate(tmp_path: Path) -> None:
    database = tmp_path / "bad-authority.db"
    _create_semantically_corrupt_v02(database)
    before = _digest(database)

    with pytest.raises(MigrationError) as caught:
        Storage(database)

    codes = {issue.code for issue in caught.value.report.issues}
    assert "MIGRATION_AUTHORITY_LEDGER_CORRESPONDENCE_INVALID" in codes
    assert "MIGRATION_AUTHORITY_LEDGER_ORPHAN" in codes
    assert _digest(database) == before
    assert not list(tmp_path.glob("bad-authority.db.pre-v3*.bak"))


def test_v02_unledgered_evidence_is_rejected_before_backup(tmp_path: Path) -> None:
    database = tmp_path / "unledgered-evidence.db"
    _create_v02_with_unledgered_evidence(database)
    before = _digest(database)

    with pytest.raises(MigrationError) as caught:
        Storage(database)

    assert "MIGRATION_EVIDENCE_SET_LEDGER_MISMATCH" in {
        issue.code for issue in caught.value.report.issues
    }
    assert _digest(database) == before
    assert not list(tmp_path.glob("unledgered-evidence.db.pre-v3*.bak"))


def test_failed_backup_verification_removes_partial_artifact(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "legacy.db"
    _create_v01(database, project_root)
    before = _digest(database)
    connection = sqlite3.connect(database)

    def fail_digest(path: Path) -> str:
        raise OSError("injected backup read failure")

    monkeypatch.setattr(migrations, "_file_sha256", fail_digest)
    report = migrations.preflight_migration(connection, create_backup=True)
    connection.close()

    assert "MIGRATION_BACKUP_VERIFICATION_FAILED" in {
        issue.code for issue in report.issues
    }
    assert not report.is_ready
    assert report.backup_path is None
    assert not list(tmp_path.glob("legacy.db.pre-v3*.bak"))
    assert _digest(database) == before


def test_migration_report_redacts_sensitive_values_and_absolute_paths() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        fingerprint = fingerprint_schema(connection)
    report = MigrationReport(
        mode=MigrationMode.STRICT,
        source=fingerprint,
        issues=(
            MigrationIssue(
                "MIGRATION_EVIDENCE_QUOTE_MISMATCH",
                "quote mismatch",
                field="quote",
                actual="SECRET EVIDENCE QUOTE",
            ),
            MigrationIssue(
                "MIGRATION_EVENT_DETAILS_INVALID",
                "details invalid",
                field="details_json",
                actual='{"secret":"SECRET EVENT BODY"}',
            ),
            MigrationIssue(
                "MIGRATION_PATH_INVALID",
                "path invalid",
                field="origin_path",
                actual=str(Path.cwd().resolve() / "secret.txt"),
            ),
            MigrationIssue(
                "MIGRATION_ID_INVALID",
                "id invalid",
                record_id="SECRET\nC:\\private\\body.txt",
            ),
        ),
        quarantined=(("claims", "SECRET\nC:\\private\\body.txt"),),
    )

    encoded = report.to_json()
    assert "SECRET EVIDENCE QUOTE" not in encoded
    assert "SECRET EVENT BODY" not in encoded
    assert str(Path.cwd().resolve()) not in encoded
    assert "SECRET" not in encoded
    assert encoded.count('"redacted": true') >= 3


def test_target_validation_failure_rolls_back_before_commit(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "atomic.db"
    _create_v01(database, project_root)
    before = _digest(database)

    def reject_target(_connection: sqlite3.Connection):
        raise SchemaError("injected target validation failure")

    monkeypatch.setattr("continuityforge.storage.validate_schema", reject_target)
    with pytest.raises(SchemaError):
        Storage(database)

    assert _digest(database) == before
    connection = sqlite3.connect(database)
    try:
        assert classify_schema(connection) is SchemaKind.V01
        assert connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 1
    finally:
        connection.close()


def test_v01_null_primary_key_alias_cannot_create_authority(
    tmp_path: Path, project_root: Path
) -> None:
    database = tmp_path / "null-id.db"
    _create_v01(database, project_root)
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO source_snapshots VALUES (NULL, 'null.txt', ?, 'alpha', 'x', ?)",
        (hashlib.sha256(b"x").hexdigest(), "2026-08-19T00:00:00Z"),
    )
    connection.execute(
        "INSERT INTO claims VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, NULL, NULL, NULL, NULL, ?, 1.0, ?)",
        (
            "claim-null-ref", "persona", "alpha", "x", "s", "p", "o", "None",
            "agent_accessible", "2026-08-19T00:00:00Z",
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(MigrationError) as caught:
        Storage(database)
    codes = {issue.code for issue in caught.value.report.issues}
    assert "MIGRATION_ID_INVALID" in codes
    assert "MIGRATION_EVIDENCE_SNAPSHOT_MISSING" in codes


def test_resource_gate_runs_before_row_materialization(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "bounded.db"
    _create_v01(database, project_root)
    monkeypatch.setattr(migrations, "MAX_MIGRATION_DATABASE_BYTES", 1)

    def forbidden_rows(*_args, **_kwargs):
        raise AssertionError("untrusted rows were materialized")

    monkeypatch.setattr(migrations, "_rows", forbidden_rows)
    report = migrations.preflight_migration(database, create_backup=False)
    assert "MIGRATION_RESOURCE_LIMIT" in {issue.code for issue in report.issues}
    assert report.quick_check == "not-run"


def test_table_row_limit_fails_closed(tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = tmp_path / "row-limit.db"
    _create_v01(database, project_root)
    monkeypatch.setattr(migrations, "MAX_MIGRATION_ROWS_PER_TABLE", 0)
    report = migrations.preflight_migration(database, create_backup=False)
    assert "MIGRATION_RESOURCE_LIMIT" in {issue.code for issue in report.issues}
    assert not report.is_ready
