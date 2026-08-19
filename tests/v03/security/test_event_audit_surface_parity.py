from __future__ import annotations

from pathlib import Path

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import InspectionIntegrityError
from continuityforge.inspection import InspectionService
from continuityforge.models import MemoryCutoff, NarrativeEvent
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage
from continuityforge.validate import ProjectValidator


@pytest.mark.parametrize(
    ("corruption", "audit_code"),
    [
        ("missing_creation", "EVENT_CREATION_LEDGER_MISMATCH"),
        ("payload_mismatch", "EVENT_LEDGER_PAYLOAD_MISMATCH"),
        ("extra_evidence", "EVENT_EVIDENCE_SET_LEDGER_MISMATCH"),
    ],
)
def test_compiler_validator_and_inspection_reject_the_same_event_audit_break(
    tmp_path: Path,
    corruption: str,
    audit_code: str,
) -> None:
    database = tmp_path / f"event-audit-{corruption}.db"
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot(
            "story", "alpha", "attested anchor\nadditional anchor"
        )
        _, target, _ = storage.ingest_snapshot(
            "story", "alpha", "attested anchor moved\nadditional anchor moved"
        )
        if corruption in {"missing_creation", "payload_mismatch"}:
            event_id = "event_without_creation_audit"
            evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
            storage.connection.execute(
                "INSERT INTO narrative_events "
                "(event_id, persona_id, continuity, event_type, title, summary, "
                "details_json, valid_from, valid_to, knowledge_from, knowledge_to, "
                "access_policy, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                (
                    event_id,
                    "persona",
                    "alpha",
                    "raw.insert",
                    "Raw",
                    "Out of band",
                    "{}",
                    "agent_accessible",
                    "2026-08-20T00:00:00Z",
                ),
            )
            if corruption == "payload_mismatch":
                storage.append_ledger(
                    "narrative_event.created",
                    "narrative_event",
                    event_id,
                    {
                        "persona_id": "wrong-persona",
                        "continuity": "wrong-continuity",
                        "event_type": "wrong.type",
                        "valid_from": None,
                        "knowledge_from": None,
                        "access_policy": "hidden",
                        "evidence_ids": ["evr_without_creation_audit"],
                        "evidence_refs": [
                            {
                                "evidence_id": "evr_without_creation_audit",
                                "snapshot_id": old.snapshot_id,
                                "start_line": evidence.start_line,
                                "end_line": evidence.end_line,
                                "content_hash": evidence.content_hash,
                            }
                        ],
                    },
                )
            storage.connection.execute(
                "INSERT INTO event_evidence_refs "
                "(evidence_id, event_id, snapshot_id, start_line, end_line, quote, "
                "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "evr_without_creation_audit",
                    event_id,
                    old.snapshot_id,
                    evidence.start_line,
                    evidence.end_line,
                    evidence.quote,
                    evidence.content_hash,
                    "2026-08-20T00:00:00Z",
                ),
            )
        else:
            event_id = "event_with_extra_evidence"
            original = build_evidence_ref(storage, old.snapshot_id, 1, 1)
            event = storage.create_narrative_event(
                NarrativeEvent(
                    event_id=event_id,
                    persona_id="persona",
                    continuity="alpha",
                ),
                (original,),
            )
            # The unattested row deliberately cites the target revision.  An
            # inspection implementation that replays only old-snapshot
            # provenance would miss it; the event's complete evidence set must
            # be loaded for deterministic audit replay.
            extra = build_evidence_ref(storage, target.snapshot_id, 2, 2)
            storage.connection.execute(
                "INSERT INTO event_evidence_refs "
                "(evidence_id, event_id, snapshot_id, start_line, end_line, quote, "
                "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "evr_extra_unattested",
                    event_id,
                    target.snapshot_id,
                    extra.start_line,
                    extra.end_line,
                    extra.quote,
                    extra.content_hash,
                    event.created_at,
                ),
            )
        assert storage.verify_ledger()

        validation = ProjectValidator(storage).validate()
        assert audit_code in {issue.code for issue in validation.issues}

        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("persona", "alpha", "2100-01-01T00:00:00Z")
        )
        assert all(item["id"] != event_id for item in pack["events"])
        diagnostic = next(
            item
            for item in pack["diagnostics"]
            if item["aggregate_id"] == event_id
        )
        assert diagnostic["code"] == "EVENT_AUDIT_INVALID"
        assert audit_code in {
            issue["code"] for issue in diagnostic["details"]["issues"]
        }

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as inspection_error:
            InspectionService(project).source_impact(
                source.source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )

    assert inspection_error.value.code == "EVENT_AUDIT_INVALID"
