from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3

import pytest

import continuityforge.storage as storage_module
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import MigrationError
from continuityforge.migrations import MigrationMode, migrate_to_v3, preflight_migration
from continuityforge.models import ClaimProposal
from continuityforge.schema import (
    SchemaKind,
    V03_ALPHA2_REQUIRED_TRIGGERS,
    V03_REQUIRED_TRIGGERS,
    fingerprint_schema,
)
from continuityforge.storage import Storage


KIB = 1024


def _utf8_text(byte_count: int) -> str:
    multibyte, remainder = divmod(byte_count, 3)
    value = "\u754c" * multibyte + "x" * remainder
    assert len(value.encode("utf-8")) == byte_count
    return value


def _make_oversize_alpha2(
    database: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, tuple[int, str]]:
    oversized = _utf8_text(256 * KIB + 1)
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot("story", "alpha", "anchor")
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)

        # Reproduce bytes that a published alpha2 database could already hold:
        # remove only the not-yet-published SQL boundary and bypass the new
        # Python boundary while constructing a coherent authority ledger.
        storage.connection.execute(
            'DROP TRIGGER "continuityforge_claims_input_limits"'
        )
        monkeypatch.setattr(storage_module, "validate_claim_fields", lambda **_: None)
        claim = storage.create_claim_proposal(
            ClaimProposal(
                claim_id="oversize-alpha2-claim",
                persona_id="persona",
                continuity="alpha",
                text=oversized,
            ),
            (evidence,),
        )
        row = storage.connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        ledger_head = (int(row["sequence"]), str(row["entry_hash"]))

    with closing(sqlite3.connect(database)) as connection:
        # The claim trigger was already removed above; remove every remaining
        # final-only trigger so the fixture is the exact published alpha2 shape.
        for trigger in V03_REQUIRED_TRIGGERS - V03_ALPHA2_REQUIRED_TRIGGERS:
            connection.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA2
    return claim.claim_id, ledger_head


def test_alpha2_oversize_claim_fails_preflight_before_backup_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "oversize-alpha2.db"
    claim_id, ledger_head = _make_oversize_alpha2(database, monkeypatch)

    report = preflight_migration(database, create_backup=True)

    assert report.source.kind is SchemaKind.V03_ALPHA2
    assert report.is_ready is False
    assert report.backup_path is None
    issue = next(item for item in report.issues if item.code == "CLAIM_TEXT_BYTES_LIMIT")
    assert issue.table == "claim_proposals"
    assert issue.record_id == claim_id
    assert issue.field == "text"
    assert issue.actual == {"bytes": 256 * KIB + 1, "limit": 256 * KIB}
    assert list(tmp_path.glob("*.bak")) == []

    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(database, create_backup=True)
    assert caught.value.report is not None
    assert caught.value.report.backup_path is None

    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA2
        stored = connection.execute(
            "SELECT text FROM claim_proposals WHERE claim_id = ?", (claim_id,)
        ).fetchone()[0]
        assert len(stored.encode("utf-8")) == 256 * KIB + 1
        head = connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert (int(head[0]), str(head[1])) == ledger_head


def test_v01_oversize_claim_is_rejected_or_quarantined_without_truncation(
    tmp_path: Path, project_root: Path
) -> None:
    database = tmp_path / "oversize-v01.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript(
            (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.execute(
            "UPDATE claims SET claim = ? WHERE id = ?",
            (_utf8_text(256 * KIB + 1), "legacy-claim-alpha"),
        )
        connection.commit()

    strict = preflight_migration(database, create_backup=True)
    assert strict.source.kind is SchemaKind.V01
    assert strict.is_ready is False
    assert strict.backup_path is None
    assert any(issue.code == "CLAIM_TEXT_BYTES_LIMIT" for issue in strict.issues)
    assert list(tmp_path.glob("*.bak")) == []

    with Storage(database, migration_mode=MigrationMode.QUARANTINE) as storage:
        report = storage.migration_report
        assert report is not None and report.succeeded
        assert ("claims", "legacy-claim-alpha") in report.quarantined
        assert storage.list_claim_proposals() == []
        retained = storage.list_legacy_records(original_table="claims")
        assert len(retained) == 1
        original = retained[0]["payload"]["claim"]
        assert len(original.encode("utf-8")) == 256 * KIB + 1
