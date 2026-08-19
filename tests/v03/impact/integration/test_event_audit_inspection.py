from __future__ import annotations

from pathlib import Path

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import InspectionLimitError
from continuityforge.inspection import InspectionService
from continuityforge.models import NarrativeEvent
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


def _audited_fixture(database: Path, *, event_count: int) -> tuple[str, str]:
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot(
            "story", "alpha", "old anchor\nsecond anchor"
        )
        for index in range(event_count):
            evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
            storage.create_narrative_event(
                NarrativeEvent(
                    event_id=f"event_{index:03d}",
                    persona_id="persona",
                    continuity="alpha",
                    event_type="fixture.event",
                ),
                (evidence,),
            )
        storage.ingest_snapshot(
            "story", "alpha", "moved\nold anchor\nsecond anchor"
        )
    return source.source_id, old.snapshot_id


def test_inspection_replays_an_affected_events_complete_evidence_set(
    tmp_path: Path,
) -> None:
    database = tmp_path / "complete-event-audit.db"
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot("story", "alpha", "old")
        _, target, _ = storage.ingest_snapshot("story", "alpha", "target")
        old_evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        target_evidence = build_evidence_ref(storage, target.snapshot_id, 1, 1)
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="event_complete_set",
                persona_id="persona",
                continuity="alpha",
            ),
            (old_evidence, target_evidence),
        )

    with ReadOnlyProject.open(database) as project:
        report = InspectionService(project).source_impact(
            source.source_id,
            continuity="alpha",
            from_version=1,
            to_version=2,
        )

    assert report.event_count == 1
    assert report.affected_count == 1
    assert report.affected[0].aggregate_id == "event_complete_set"


def test_readonly_event_audit_batch_has_record_and_byte_bounds(tmp_path: Path) -> None:
    database = tmp_path / "bounded-event-audit.db"
    _, old_snapshot_id = _audited_fixture(database, event_count=1)

    with ReadOnlyProject.open(database) as project:
        at_boundary = project.get_event_audit_for_snapshot(
            old_snapshot_id,
            max_records=2,
            max_material_bytes=1024 * 1024,
        )
        assert len(at_boundary.ledger_entries) == 1
        assert len(at_boundary.evidence) == 1

        with pytest.raises(InspectionLimitError) as record_error:
            project.get_event_audit_for_snapshot(
                old_snapshot_id,
                max_records=1,
                max_material_bytes=1024 * 1024,
            )
        assert (
            record_error.value.code
            == "INSPECTION_EVENT_AUDIT_RECORD_LIMIT_EXCEEDED"
        )

        with pytest.raises(InspectionLimitError) as byte_error:
            project.get_event_audit_for_snapshot(
                old_snapshot_id,
                max_records=100,
                max_material_bytes=1,
            )
        assert byte_error.value.code == "INSPECTION_EVENT_AUDIT_BYTES_LIMIT_EXCEEDED"


def test_inspection_ignores_an_unaffected_invalid_event_audit(tmp_path: Path) -> None:
    database = tmp_path / "scoped-event-audit.db"
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot("story", "alpha", "old anchor")
        valid_evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="event_in_scope",
                persona_id="persona",
                continuity="alpha",
            ),
            (valid_evidence,),
        )
        storage.ingest_snapshot("story", "alpha", "new anchor")

        _, unrelated, _ = storage.ingest_snapshot(
            "unrelated", "beta", "unrelated anchor"
        )
        unrelated_evidence = build_evidence_ref(
            storage, unrelated.snapshot_id, 1, 1
        )
        storage.connection.execute(
            "INSERT INTO narrative_events "
            "(event_id, persona_id, continuity, event_type, title, summary, "
            "details_json, valid_from, valid_to, knowledge_from, knowledge_to, "
            "access_policy, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
            (
                "event_out_of_scope",
                "persona",
                "beta",
                "raw.insert",
                "Raw",
                "Out of scope",
                "{}",
                "agent_accessible",
                "2026-08-20T00:00:00Z",
            ),
        )
        storage.connection.execute(
            "INSERT INTO event_evidence_refs "
            "(evidence_id, event_id, snapshot_id, start_line, end_line, quote, "
            "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evr_out_of_scope",
                "event_out_of_scope",
                unrelated.snapshot_id,
                1,
                1,
                unrelated_evidence.quote,
                unrelated_evidence.content_hash,
                "2026-08-20T00:00:00Z",
            ),
        )
        assert storage.verify_ledger()

    with ReadOnlyProject.open(database) as project:
        report = InspectionService(project).source_impact(
            source.source_id,
            continuity="alpha",
            from_version=1,
            to_version=2,
        )

    assert report.event_count == 1
    assert {item.aggregate_id for item in report.affected} == {"event_in_scope"}


def _inspection_read_counts(database: Path, source_id: str) -> tuple[int, int]:
    with ReadOnlyProject.open(database) as project:
        statements: list[str] = []
        project.connection.set_trace_callback(statements.append)
        InspectionService(project).source_impact(
            source_id,
            continuity="alpha",
            from_version=1,
            to_version=2,
        )
        project.connection.set_trace_callback(None)

    reads = [
        statement
        for statement in statements
        if statement.lstrip().upper().startswith(("SELECT", "WITH"))
    ]
    event_audit_reads = [
        statement
        for statement in reads
        if statement.lstrip().upper().startswith("WITH AFFECTED(EVENT_ID)")
    ]
    return len(reads), len(event_audit_reads)


def test_event_audit_inspection_query_count_is_not_per_event(tmp_path: Path) -> None:
    one_database = tmp_path / "one-event.db"
    many_database = tmp_path / "many-events.db"
    one_source, _ = _audited_fixture(one_database, event_count=1)
    many_source, _ = _audited_fixture(many_database, event_count=32)

    one_counts = _inspection_read_counts(one_database, one_source)
    many_counts = _inspection_read_counts(many_database, many_source)

    assert one_counts == many_counts
    assert one_counts[1] == 3
