from __future__ import annotations

import sqlite3

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import EvidenceValidationError, InvalidTransitionError
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_content
from continuityforge.models import ClaimProposal, EvidenceRef, GovernanceStatus, NarrativeEvent


def _claim() -> ClaimProposal:
    return ClaimProposal(
        persona_id="mira",
        continuity="alpha",
        text="Mira entered the observatory.",
    )


def test_public_decision_api_routes_through_governance_evidence_gate(storage):
    pending = ClaimGovernance(storage).propose(_claim(), [])
    with pytest.raises(EvidenceValidationError):
        storage.record_governance_decision(
            pending.claim_id,
            GovernanceStatus.AUTHORIZED,
            "editor",
            "raw façade call",
        )
    assert storage.get_claim_proposal(pending.claim_id).status is GovernanceStatus.PROPOSED


@pytest.mark.parametrize(("start", "end"), [(True, 1), ("1", 1), (1, "1")])
def test_storage_rejects_coercible_evidence_coordinates(storage, start, end):
    _, snapshot, _ = ingest_content(storage, "line\n", "story", "alpha")
    evidence = EvidenceRef(snapshot.snapshot_id, start, end)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ClaimGovernance(storage).propose(_claim(), [evidence])


def test_authorized_evidence_cannot_be_appended_by_api_or_direct_sql(storage):
    _, snapshot, _ = ingest_content(storage, "first\nsecond\n", "story", "alpha")
    governance = ClaimGovernance(storage)
    claim = governance.add_authorized_human_claim(
        _claim(), [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)]
    )
    extra = build_evidence_ref(storage, snapshot.snapshot_id, 2, 2)
    with pytest.raises(InvalidTransitionError):
        storage.add_claim_evidence(claim.claim_id, extra)
    with pytest.raises(sqlite3.IntegrityError):
        storage.connection.execute(
            "INSERT INTO evidence_refs "
            "(evidence_id, claim_id, snapshot_id, start_line, end_line, quote, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "evr_direct",
                claim.claim_id,
                snapshot.snapshot_id,
                2,
                2,
                "second",
                "2026-01-01T00:00:00Z",
            ),
        )


def test_domain_rows_and_ledger_are_not_rewritable(storage):
    _, snapshot, _ = ingest_content(storage, "event\n", "story", "alpha")
    event = storage.create_narrative_event(
        NarrativeEvent(
            persona_id="mira",
            continuity="alpha",
            title="Event",
            summary="event",
        ),
        [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)],
    )
    with pytest.raises(sqlite3.IntegrityError):
        storage.connection.execute(
            "UPDATE source_snapshots SET content = 'changed' WHERE snapshot_id = ?",
            (snapshot.snapshot_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        storage.connection.execute(
            "UPDATE narrative_events SET summary = 'changed' WHERE event_id = ?",
            (event.event_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        storage.connection.execute("DELETE FROM event_ledger")
