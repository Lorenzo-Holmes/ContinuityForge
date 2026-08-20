from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import ContinuityViolation, InspectionIntegrityError
from continuityforge.governance import ClaimGovernance
from continuityforge.inspection import InspectionService
from continuityforge.models import ClaimProposal, MemoryCutoff
from continuityforge.readonly import ReadOnlyProject
from continuityforge.schema import SchemaKind, classify_schema
from continuityforge.storage import Storage
from continuityforge.validate import ProjectValidator


def _insert_unreferenced_source(storage: Storage, source_id: str = "src_raw") -> None:
    storage.connection.execute(
        "INSERT INTO sources "
        "(source_id, source_key, continuity, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            source_id,
            "raw/source",
            "alpha",
            "2026-08-20T00:00:00Z",
            "2026-08-20T00:00:00Z",
        ),
    )


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("source_id", "src_rewritten"),
        ("source_key", "rewritten/source"),
        ("continuity", "beta"),
        ("created_at", "2099-01-01T00:00:00Z"),
    ],
)
def test_source_identity_fields_reject_raw_sql_updates(
    storage: Storage,
    column: str,
    replacement: str,
) -> None:
    """A logical Source identity is immutable even before it has a snapshot."""

    _insert_unreferenced_source(storage)

    with pytest.raises(sqlite3.IntegrityError, match="Source.*immutable"):
        storage.connection.execute(
            f'UPDATE sources SET "{column}" = ? WHERE source_id = ?',
            (replacement, "src_raw"),
        )


def test_source_rows_cannot_be_deleted_even_without_snapshots(storage: Storage) -> None:
    """The Source no-delete rule must not rely only on snapshot foreign keys."""

    _insert_unreferenced_source(storage)

    with pytest.raises(sqlite3.IntegrityError, match="Source.*cannot be deleted"):
        storage.connection.execute(
            "DELETE FROM sources WHERE source_id = ?", ("src_raw",)
        )


def test_source_updated_at_follows_latest_snapshot_but_rejects_arbitrary_sql(
    storage: Storage,
) -> None:
    """updated_at may advance only to the timestamp of the latest revision."""

    source, _, _ = storage.ingest_snapshot("story", "alpha", "first revision\n")
    _, latest, created = storage.ingest_snapshot(
        "story", "alpha", "second revision\n"
    )

    assert created is True
    refreshed = storage.get_source(source.source_id)
    assert refreshed.updated_at == latest.created_at

    with pytest.raises(sqlite3.IntegrityError, match="updated_at.*latest"):
        storage.connection.execute(
            "UPDATE sources SET updated_at = ? WHERE source_id = ?",
            ("2099-01-01T00:00:00Z", source.source_id),
        )


def test_source_continuity_cannot_be_reclassified_into_another_worldline(
    storage: Storage,
) -> None:
    source, snapshot, _ = storage.ingest_snapshot(
        "worldline/source", "beta", "beta-only fact\n"
    )

    with pytest.raises(sqlite3.IntegrityError, match="Source.*immutable"):
        storage.connection.execute(
            "UPDATE sources SET continuity = ? WHERE source_id = ?",
            ("alpha", source.source_id),
        )

    assert storage.get_source(source.source_id).continuity == "beta"
    assert storage.get_snapshot(snapshot.snapshot_id).continuity == "beta"
    alpha_claim = ClaimProposal(
        persona_id="persona",
        continuity="alpha",
        text="beta-only fact",
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    with pytest.raises(ContinuityViolation):
        ClaimGovernance(storage).propose(alpha_claim, (evidence,))


def test_source_key_cannot_be_rewritten_without_changing_the_ledger(
    storage: Storage,
) -> None:
    source, _, _ = storage.ingest_snapshot("canonical/key", "alpha", "fact\n")

    with pytest.raises(sqlite3.IntegrityError, match="Source.*immutable"):
        storage.connection.execute(
            "UPDATE sources SET source_key = ? WHERE source_id = ?",
            ("forged/key", source.source_id),
        )

    assert storage.get_source(source.source_id).source_key == "canonical/key"
    creation = storage.list_ledger_entries(
        event_type="source.created",
        aggregate_type="source",
        aggregate_id=source.source_id,
    )
    assert len(creation) == 1
    assert creation[0].payload["source_key"] == "canonical/key"


def _authorized_source_project(database: Path) -> tuple[str, str]:
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot(
            "canonical/story", "alpha", "attested anchor\nsecond anchor"
        )
        storage.ingest_snapshot(
            "canonical/story", "alpha", "attested anchor moved\nsecond anchor"
        )
        evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        claim = ClaimGovernance(storage).add_authorized_human_claim(
            ClaimProposal(
                claim_id="claim-source-audit",
                persona_id="persona",
                continuity="alpha",
                text="attested anchor",
            ),
            (evidence,),
            reviewer="reviewer",
            reason="the immutable line directly supports the claim",
        )
        return source.source_id, claim.claim_id


def _rewrite_source_key_behind_canonical_triggers(
    storage: Storage,
    source_id: str,
) -> None:
    """Simulate a database owner bypass, then restore the exact schema shape."""

    rows = storage.connection.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type = 'trigger' AND tbl_name = 'sources' ORDER BY name"
    ).fetchall()
    assert rows, "the final v0.3 schema must install Source integrity triggers"
    trigger_sql = [(str(row[0]), str(row[1])) for row in rows]
    for name, _ in trigger_sql:
        escaped = name.replace('"', '""')
        storage.connection.execute(f'DROP TRIGGER "{escaped}"')
    storage.connection.execute(
        "UPDATE sources SET source_key = ? WHERE source_id = ?",
        ("forged/story", source_id),
    )
    for _, sql in trigger_sql:
        storage.connection.execute(sql)


def test_source_audit_break_is_rejected_by_all_three_trusted_surfaces(
    tmp_path: Path,
) -> None:
    """Validator, compiler, and inspection must share Source audit semantics."""

    database = tmp_path / "source-audit-parity.db"
    source_id, claim_id = _authorized_source_project(database)

    with Storage(database) as storage:
        _rewrite_source_key_behind_canonical_triggers(storage, source_id)
        assert classify_schema(storage.connection) is SchemaKind.V03
        assert storage.verify_ledger()

        validation = ProjectValidator(storage).validate()
        assert "SOURCE_LEDGER_PAYLOAD_MISMATCH" in {
            issue.code for issue in validation.issues
        }

        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("persona", "alpha", "2100-01-01T00:00:00Z")
        )
        assert all(item["id"] != claim_id for item in pack["claims"])
        diagnostic = next(
            item for item in pack["diagnostics"] if item["aggregate_id"] == claim_id
        )
        assert diagnostic["code"] == "SOURCE_AUDIT_INVALID"
        assert "SOURCE_LEDGER_PAYLOAD_MISMATCH" in {
            issue["code"] for issue in diagnostic["details"]["issues"]
        }

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )
    assert caught.value.code == "SOURCE_AUDIT_INVALID"
