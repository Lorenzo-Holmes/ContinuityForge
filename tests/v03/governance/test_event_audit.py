from __future__ import annotations

import json
import pytest
from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.event_integrity import replay_event_audits, validate_event_audits
from continuityforge.models import MemoryCutoff, NarrativeEvent
from continuityforge.validate import ProjectValidator


def _cutoff() -> MemoryCutoff:
    return MemoryCutoff("mira", "alpha", "2026-08-20T00:00:00Z")


def _event_fixture(storage):
    _, snapshot, _ = storage.ingest_snapshot("story", "alpha", "bell")
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    event = storage.create_narrative_event(
        NarrativeEvent(
            event_id="event_legitimate",
            persona_id="mira",
            continuity="alpha",
            event_type="bell.rang",
            title="Bell",
            summary="The bell rang.",
        ),
        (evidence,),
    )
    return event, storage.get_event_evidence(event.event_id)[0]


def test_legitimate_event_audit_replays_and_compiles(storage):
    event, _ = _event_fixture(storage)
    pack = MemoryCompiler(storage).compile(_cutoff())
    assert [item["id"] for item in pack["events"]] == [event.event_id]
    assert ProjectValidator(storage).validate().is_valid


def test_preloaded_event_audit_batch_matches_storage_backed_replay(storage):
    event, _ = _event_fixture(storage)
    storage_reports = validate_event_audits(storage, (event,))
    batch_reports = replay_event_audits(
        (event,),
        storage.list_ledger_entries(aggregate_type="narrative_event"),
        storage.list_all_event_evidence(),
    )

    assert batch_reports[event.event_id].to_dict() == storage_reports[
        event.event_id
    ].to_dict()


def test_direct_event_insert_without_ledger_is_excluded(storage):
    storage.connection.execute(
        "INSERT INTO narrative_events "
        "(event_id, persona_id, continuity, event_type, title, summary, details_json, "
        "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
        (
            "event_out_of_band",
            "mira",
            "alpha",
            "raw.insert",
            "Raw",
            "Out of band",
            "{}",
            "agent_accessible",
            "2026-08-19T00:00:00Z",
        ),
    )

    pack = MemoryCompiler(storage).compile(_cutoff())
    assert pack["events"] == []
    diagnostic = next(
        item for item in pack["diagnostics"]
        if item["aggregate_id"] == "event_out_of_band"
    )
    assert diagnostic["code"] == "EVENT_AUDIT_INVALID"
    assert "EVENT_CREATION_LEDGER_MISMATCH" in {
        issue["code"] for issue in diagnostic["details"]["issues"]
    }
    assert "EVENT_CREATION_LEDGER_MISMATCH" in {
        issue.code for issue in ProjectValidator(storage).validate().issues
    }


def test_direct_event_evidence_insert_breaks_audited_set(storage):
    event, original = _event_fixture(storage)
    storage.connection.execute(
        "INSERT INTO event_evidence_refs "
        "(evidence_id, event_id, snapshot_id, start_line, end_line, quote, "
        "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evr_out_of_band",
            event.event_id,
            original.snapshot_id,
            original.start_line,
            original.end_line,
            original.quote,
            original.content_hash,
            "2026-08-19T00:00:00Z",
        ),
    )

    pack = MemoryCompiler(storage).compile(_cutoff())
    assert pack["events"] == []
    diagnostic = next(
        item for item in pack["diagnostics"]
        if item["aggregate_id"] == event.event_id
    )
    assert "EVENT_EVIDENCE_SET_LEDGER_MISMATCH" in {
        issue["code"] for issue in diagnostic["details"]["issues"]
    }


def test_forged_event_ledger_payload_does_not_attest_raw_event(storage):
    storage.connection.execute(
        "INSERT INTO narrative_events "
        "(event_id, persona_id, continuity, event_type, title, summary, details_json, "
        "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
        (
            "event_forged",
            "mira",
            "alpha",
            "actual.type",
            "Actual",
            "Actual summary",
            "{}",
            "agent_accessible",
            "2026-08-19T00:00:00Z",
        ),
    )
    with storage.transaction() as connection:
        storage._append_ledger_in_transaction(
            connection,
            event_type="narrative_event.created",
            aggregate_type="narrative_event",
            aggregate_id="event_forged",
            payload={
                "persona_id": "someone-else",
                "continuity": "beta",
                "event_type": "forged.type",
                "valid_from": None,
                "knowledge_from": None,
                "access_policy": "hidden",
                "evidence_ids": [],
                "evidence_refs": [],
                "material_version": 2,
                "aggregate_sha256": "0" * 64,
                "evidence_set_sha256": "1" * 64,
            },
        )

    pack = MemoryCompiler(storage).compile(_cutoff())
    assert pack["events"] == []
    diagnostic = next(
        item for item in pack["diagnostics"]
        if item["aggregate_id"] == "event_forged"
    )
    codes = {issue["code"] for issue in diagnostic["details"]["issues"]}
    assert "EVENT_LEDGER_PAYLOAD_MISMATCH" in codes
    assert "EVENT_LEDGER_TIMESTAMP_MISMATCH" in codes


def test_event_details_are_strict_deterministic_json(storage):
    _, snapshot, _ = storage.ingest_snapshot("details-story", "alpha", "detail")
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    event = storage.create_narrative_event(
        NarrativeEvent(
            event_id="event_details",
            persona_id="mira",
            continuity="alpha",
            event_type="detail.recorded",
            details={"z": [1, True, None], "a": {"value": 1.5}},
        ),
        (evidence,),
    )
    pack = MemoryCompiler(storage).compile(_cutoff())
    compiled = next(item for item in pack["events"] if item["id"] == event.event_id)
    assert compiled["details"] == {"a": {"value": 1.5}, "z": [1, True, None]}
    json.dumps(pack, allow_nan=False)

    with pytest.raises(ValueError):
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="event_nan",
                persona_id="mira",
                continuity="alpha",
                details={"bad": float("nan")},
            )
        )
    with pytest.raises(TypeError):
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="event_object",
                persona_id="mira",
                continuity="alpha",
                details={"bad": object()},
            )
        )
