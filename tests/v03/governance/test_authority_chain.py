from __future__ import annotations

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import LedgerIntegrityError
from continuityforge.governance import ClaimGovernance
from continuityforge.governance_integrity import validate_claim_authority
from continuityforge.ingest import ingest_content
from continuityforge.models import ClaimProposal, GovernanceStatus, MemoryCutoff
from continuityforge.validate import ProjectValidator


def _proposal() -> ClaimProposal:
    return ClaimProposal(
        persona_id="mira",
        continuity="alpha",
        text="Mira entered the observatory.",
        subject="mira",
        predicate="location",
        object_value="observatory",
        knowledge_from="2026-01-01T00:00:00Z",
    )


def _pending_with_evidence(storage):
    _, snapshot, _ = ingest_content(
        storage, "Mira entered the observatory.\n", "story", "alpha"
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    return ClaimGovernance(storage).propose(_proposal(), [evidence])


def _remove_application_status_guards(storage) -> None:
    """Simulate a trusted DB owner intentionally bypassing app triggers."""

    rows = storage.connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'trigger' AND tbl_name = 'claim_proposals'"
    ).fetchall()
    for row in rows:
        name = str(row[0]).replace('"', '""')
        storage.connection.execute(f'DROP TRIGGER "{name}"')


def test_legitimate_authority_chain_replays_and_compiles(storage):
    pending = _pending_with_evidence(storage)
    governance = ClaimGovernance(storage)
    governance.review(
        pending.claim_id,
        GovernanceStatus.AUTHORIZED,
        reviewer="editor",
        reason="the immutable line directly supports the claim",
    )

    claim = storage.get_claim_proposal(pending.claim_id)
    authority = validate_claim_authority(storage, claim)
    assert authority.is_authorized
    assert authority.issues == ()

    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    assert [item["id"] for item in pack["claims"]] == [pending.claim_id]


def test_raw_status_escalation_is_rejected_by_compiler_and_validator(storage):
    pending = _pending_with_evidence(storage)
    _remove_application_status_guards(storage)
    storage.connection.execute(
        "UPDATE claim_proposals SET status = ? WHERE claim_id = ?",
        (GovernanceStatus.AUTHORIZED.value, pending.claim_id),
    )

    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    assert pack["claims"] == []
    diagnostic = next(
        item for item in pack["diagnostics"] if item["aggregate_id"] == pending.claim_id
    )
    assert diagnostic["code"] == "AUTHORITY_CHAIN_INVALID"
    issue_codes = {
        issue["code"] for issue in diagnostic["details"]["issues"]
    }
    assert "CLAIM_STATUS_REPLAY_MISMATCH" in issue_codes

    report = ProjectValidator(storage).validate()
    assert not report.is_valid
    assert "CLAIM_STATUS_REPLAY_MISMATCH" in {issue.code for issue in report.issues}


def test_decision_without_matching_ledger_event_is_not_authoritative(storage):
    pending = _pending_with_evidence(storage)
    _remove_application_status_guards(storage)
    storage.connection.execute(
        "INSERT INTO governance_decisions "
        "(decision_id, claim_id, from_status, to_status, reviewer, reason, decided_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "dec_out_of_band",
            pending.claim_id,
            GovernanceStatus.PROPOSED.value,
            GovernanceStatus.AUTHORIZED.value,
            "raw-sql",
            "out of band mutation",
            "2026-01-01T00:00:00Z",
        ),
    )
    storage.connection.execute(
        "UPDATE claim_proposals SET status = ? WHERE claim_id = ?",
        (GovernanceStatus.AUTHORIZED.value, pending.claim_id),
    )

    claim = storage.get_claim_proposal(pending.claim_id)
    authority = validate_claim_authority(storage, claim)
    assert not authority.is_valid
    assert "DECISION_LEDGER_MISMATCH" in {
        issue.code for issue in authority.issues
    }


def test_compiler_fails_closed_when_global_ledger_chain_is_invalid(storage):
    pending = _pending_with_evidence(storage)
    ClaimGovernance(storage).review(
        pending.claim_id,
        GovernanceStatus.AUTHORIZED,
        reviewer="editor",
        reason="the immutable line directly supports the claim",
    )

    storage.connection.execute(
        "DROP TRIGGER continuityforge_ledger_no_update"
    )
    storage.connection.execute(
        "UPDATE event_ledger SET payload_json = ? WHERE sequence = 1",
        ('{"tampered":true}',),
    )
    assert storage.verify_ledger() is False

    with pytest.raises(LedgerIntegrityError, match="verification failed"):
        MemoryCompiler(storage).compile(
            MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
        )


def test_unledgered_evidence_insert_is_not_part_of_authorized_claim(storage):
    pending = _pending_with_evidence(storage)
    ClaimGovernance(storage).review(
        pending.claim_id,
        GovernanceStatus.AUTHORIZED,
        reviewer="editor",
        reason="the original evidence set was reviewed",
    )
    original = storage.get_claim_evidence(pending.claim_id)[0]
    storage.connection.execute(
        "DROP TRIGGER continuityforge_evidence_reviewable_insert"
    )
    storage.connection.execute(
        "INSERT INTO evidence_refs "
        "(evidence_id, claim_id, snapshot_id, start_line, end_line, quote, "
        "content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "evr_out_of_band",
            pending.claim_id,
            original.snapshot_id,
            original.start_line,
            original.end_line,
            original.quote,
            original.content_hash,
            "2026-08-19T00:00:00Z",
        ),
    )

    authority = validate_claim_authority(
        storage, storage.get_claim_proposal(pending.claim_id)
    )
    assert not authority.is_valid
    assert "EVIDENCE_SET_LEDGER_MISMATCH" in {
        issue.code for issue in authority.issues
    }

    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    assert pack["claims"] == []
    report = ProjectValidator(storage).validate()
    assert "EVIDENCE_SET_LEDGER_MISMATCH" in {
        issue.code for issue in report.issues
    }


def test_decision_replay_uses_ledger_sequence_when_clock_moves_backward(
    storage, monkeypatch
):
    pending = _pending_with_evidence(storage)
    timestamps = iter(
        [
            "2026-08-19T03:00:00Z",
            "2026-08-19T02:00:00Z",
            "2026-08-19T01:00:00Z",
        ]
    )
    monkeypatch.setattr("continuityforge.storage._now", lambda: next(timestamps))
    governance = ClaimGovernance(storage)
    governance.review(
        pending.claim_id,
        GovernanceStatus.AUTHORIZED,
        reviewer="editor",
        reason="authorize",
    )
    governance.review(
        pending.claim_id,
        GovernanceStatus.DISPUTED,
        reviewer="editor",
        reason="reopen",
    )
    governance.review(
        pending.claim_id,
        GovernanceStatus.AUTHORIZED,
        reviewer="editor",
        reason="reauthorize",
    )

    decisions = storage.list_governance_decisions(claim_id=pending.claim_id)
    assert [item.decided_at for item in decisions] == [
        "2026-08-19T03:00:00Z",
        "2026-08-19T02:00:00Z",
        "2026-08-19T01:00:00Z",
    ]
    authority = validate_claim_authority(
        storage, storage.get_claim_proposal(pending.claim_id)
    )
    assert authority.is_authorized
    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    assert [item["id"] for item in pack["claims"]] == [pending.claim_id]
