from __future__ import annotations

from hashlib import sha256
import json
import sqlite3
from pathlib import Path

import pytest

import continuityforge.inspection as inspection_module
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import (
    InspectionIntegrityError,
    InspectionLimitError,
    LedgerIntegrityError,
)
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import IngestLimits
from continuityforge.inspection import InspectionService
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.readonly import ReadOnlyProject
from continuityforge.schema import V02_REQUIRED_TRIGGERS, V03_REQUIRED_TRIGGERS
from continuityforge.storage import Storage


def _project(
    database: Path,
    *,
    revisions: int = 2,
    claims: int = 1,
    event: bool = False,
) -> tuple[str, str]:
    with Storage(database) as storage:
        source, first, _ = storage.ingest_snapshot("story", "alpha", "anchor")
        for index in range(claims):
            evidence = build_evidence_ref(storage, first.snapshot_id, 1, 1)
            storage.create_claim_proposal(
                ClaimProposal(
                    claim_id=f"claim_{index}",
                    persona_id="persona",
                    continuity="alpha",
                    text=f"claim {index}",
                ),
                (evidence,),
            )
        if event:
            evidence = build_evidence_ref(storage, first.snapshot_id, 1, 1)
            storage.create_narrative_event(
                NarrativeEvent(
                    event_id="event_0",
                    persona_id="persona",
                    continuity="alpha",
                    title="event",
                    summary="event summary",
                ),
                (evidence,),
            )
        for version in range(2, revisions + 1):
            storage.ingest_snapshot("story", "alpha", f"padding {version}\nanchor")
    return source.source_id, first.snapshot_id


def _drop_trigger(connection: sqlite3.Connection, name: str) -> None:
    connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')


def _rewrite_source_key_and_rehash_ledger(
    database: Path, source_id: str, value: str
) -> None:
    """Model a database-owner rewrite while keeping every audit input coherent."""

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    _drop_trigger(connection, "continuityforge_sources_identity_immutable")
    _drop_trigger(connection, "continuityforge_ledger_no_update")
    connection.execute(
        "UPDATE sources SET source_key = ? WHERE source_id = ?", (value, source_id)
    )
    previous_hash = "0" * 64
    rows = connection.execute("SELECT * FROM event_ledger ORDER BY sequence").fetchall()
    for row in rows:
        payload = json.loads(str(row["payload_json"]))
        if (
            row["event_type"] == "source.created"
            and row["aggregate_id"] == source_id
        ) or (
            row["event_type"] == "source_snapshot.created"
            and payload.get("source_id") == source_id
        ):
            payload["source_key"] = value
        payload_json = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        entry_hash = Storage._ledger_digest(
            sequence=int(row["sequence"]),
            entry_id=str(row["entry_id"]),
            event_type=str(row["event_type"]),
            aggregate_type=str(row["aggregate_type"]),
            aggregate_id=str(row["aggregate_id"]),
            payload_json=payload_json,
            previous_hash=previous_hash,
            created_at=str(row["created_at"]),
        )
        connection.execute(
            "UPDATE event_ledger SET payload_json = ?, previous_hash = ?, "
            "entry_hash = ? WHERE sequence = ?",
            (payload_json, previous_hash, entry_hash, int(row["sequence"])),
        )
        previous_hash = entry_hash
    connection.commit()
    connection.close()


def test_lineage_uses_metadata_only_and_revision_limit_is_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "revisions.db"
    source_id, _ = _project(database, revisions=4)
    monkeypatch.setattr(inspection_module, "MAX_SOURCE_REVISIONS", 3)

    with ReadOnlyProject.open(database) as project:
        statements: list[str] = []
        project.connection.set_trace_callback(statements.append)
        report = InspectionService(project).source_impact(
            source_id, continuity="alpha", from_version=1, to_version=3
        )
        project.connection.set_trace_callback(None)
        assert report.to_version == 3
        body_queries = [sql for sql in statements if sql.startswith("SELECT ss.*")]
        assert len(body_queries) == 1
        assert "versionIN(1,3)" in body_queries[0].replace(" ", "")

        with pytest.raises(InspectionLimitError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=4
            )
        assert caught.value.code == "SOURCE_REVISION_LIMIT_EXCEEDED"


def test_affected_evidence_limit_accepts_boundary_and_rejects_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "evidence-limit.db"
    source_id, _ = _project(database, claims=3)
    with ReadOnlyProject.open(database) as project:
        monkeypatch.setattr(inspection_module, "MAX_AFFECTED_EVIDENCE", 3)
        assert (
            InspectionService(project)
            .source_impact(source_id, continuity="alpha", from_version=1, to_version=2)
            .affected_count
            == 3
        )
        monkeypatch.setattr(inspection_module, "MAX_AFFECTED_EVIDENCE", 2)
        with pytest.raises(InspectionLimitError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "AFFECTED_EVIDENCE_LIMIT_EXCEEDED"


def test_affected_evidence_material_has_a_stable_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "evidence-bytes.db"
    source_id, _ = _project(database)
    monkeypatch.setattr(inspection_module, "MAX_INSPECTION_MATERIAL_BYTES", 1)
    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionLimitError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED"


def test_aggregate_candidate_limit_accepts_boundary_and_rejects_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "candidate-limit.db"
    source_id, _ = _project(database, claims=2)
    with ReadOnlyProject.open(database) as project:
        monkeypatch.setattr(inspection_module, "MAX_REPORT_CANDIDATES", 2)
        report = InspectionService(project).source_impact(
            source_id, continuity="alpha", from_version=1, to_version=2
        )
        assert sum(len(item.impact.candidates) for item in report.affected) == 2
        monkeypatch.setattr(inspection_module, "MAX_REPORT_CANDIDATES", 1)
        with pytest.raises(InspectionLimitError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    ("sql", "params", "code"),
    [
        (
            "UPDATE source_snapshots SET content_hash = ? WHERE version = 1",
            ("0" * 64,),
            "SNAPSHOT_CONTENT_HASH_MISMATCH",
        ),
        (
            "UPDATE source_snapshots SET line_count = 2 WHERE version = 1",
            (),
            "SNAPSHOT_LINE_COUNT_MISMATCH",
        ),
        (
            "UPDATE source_snapshots SET content = 'bitrot' WHERE version = 1",
            (),
            "SNAPSHOT_CONTENT_HASH_MISMATCH",
        ),
    ],
)
def test_endpoint_hash_and_line_count_are_recomputed_in_pinned_read(
    tmp_path: Path, sql: str, params: tuple[object, ...], code: str
) -> None:
    database = tmp_path / f"{code}.db"
    source_id, _ = _project(database)
    with ReadOnlyProject.open(database) as project:
        writer = sqlite3.connect(database)
        _drop_trigger(writer, "continuityforge_snapshots_no_update")
        writer.execute(sql, params)
        writer.commit()
        writer.close()
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == code


def test_oversized_old_snapshot_is_rejected_before_body_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "large-old.db"
    source_id, _ = _project(database)
    monkeypatch.setattr(
        inspection_module,
        "DEFAULT_INGEST_LIMITS",
        IngestLimits(max_file_bytes=5, max_lines=10, max_line_bytes=5),
    )
    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionLimitError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "SNAPSHOT_BYTES_LIMIT_EXCEEDED"


def _downgrade_to_v2_without_claim_ledger(database: Path) -> None:
    connection = sqlite3.connect(database)
    for name in V03_REQUIRED_TRIGGERS - V02_REQUIRED_TRIGGERS:
        _drop_trigger(connection, name)
    _drop_trigger(connection, "continuityforge_ledger_no_update")
    _drop_trigger(connection, "continuityforge_ledger_no_delete")
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
    connection.close()


def test_v2_cached_authorized_status_without_ledger_fails_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing-authority.db"
    with Storage(database) as storage:
        source, first, _ = storage.ingest_snapshot("story", "alpha", "anchor")
        evidence = build_evidence_ref(storage, first.snapshot_id, 1, 1)
        claim = ClaimGovernance(storage).add_authorized_human_claim(
            ClaimProposal(
                claim_id="claim",
                persona_id="persona",
                continuity="alpha",
                text="claim",
            ),
            (evidence,),
        )
        storage.ingest_snapshot("story", "alpha", "padding\nanchor")
        assert claim.status.value == "AUTHORIZED"
    _downgrade_to_v2_without_claim_ledger(database)

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source.source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "CLAIM_AUTHORITY_INVALID"


def test_broken_global_ledger_fails_before_governance_is_reported(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broken-ledger.db"
    source_id, _ = _project(database)
    with ReadOnlyProject.open(database) as project:
        writer = sqlite3.connect(database)
        _drop_trigger(writer, "continuityforge_ledger_no_update")
        writer.execute(
            "UPDATE event_ledger SET entry_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        writer.commit()
        writer.close()
        with pytest.raises(LedgerIntegrityError):
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("\x1b[31mCANARY", "REPORT_METADATA_CONTROL_CHARACTER"),
        ("safe\u202eCANARY", "REPORT_METADATA_CONTROL_CHARACTER"),
        ("CANARY" * 300, "REPORT_METADATA_BYTES_LIMIT_EXCEEDED"),
    ],
)
def test_untrusted_source_metadata_never_reaches_success_report(
    tmp_path: Path, value: str, code: str
) -> None:
    database = tmp_path / "metadata.db"
    source_id, _ = _project(database)
    with ReadOnlyProject.open(database) as project:
        _rewrite_source_key_and_rehash_ledger(database, source_id, value)
        with pytest.raises((InspectionIntegrityError, InspectionLimitError)) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == code
        assert "CANARY" not in str(caught.value)


def test_untrusted_persona_metadata_fails_before_authority_output(
    tmp_path: Path,
) -> None:
    database = tmp_path / "persona.db"
    source_id, _ = _project(database)
    with ReadOnlyProject.open(database) as project:
        writer = sqlite3.connect(database)
        _drop_trigger(writer, "continuityforge_claims_fields_immutable")
        writer.execute("UPDATE claim_proposals SET persona_id = ?", ("\nCANARY",))
        writer.commit()
        writer.close()
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "REPORT_METADATA_CONTROL_CHARACTER"
        assert "CANARY" not in str(caught.value)


@pytest.mark.parametrize("details", ['{"x":NaN}', '{"x":1,"x":2}', '[]'])
def test_event_details_use_strict_bounded_json(tmp_path: Path, details: str) -> None:
    database = tmp_path / "event-details.db"
    source_id, _ = _project(database, event=True)
    with ReadOnlyProject.open(database) as project:
        writer = sqlite3.connect(database)
        _drop_trigger(writer, "continuityforge_events_no_update")
        writer.execute("UPDATE narrative_events SET details_json = ?", (details,))
        writer.commit()
        writer.close()
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id, continuity="alpha", from_version=1, to_version=2
            )
        assert caught.value.code == "EVENT_DETAILS_INVALID"
