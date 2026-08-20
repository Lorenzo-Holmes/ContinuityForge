from __future__ import annotations

from continuityforge.audit_material import claim_material_digests
from continuityforge.governance_integrity import replay_claim_authority
from continuityforge.models import (
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
)


def _claim(status: GovernanceStatus = GovernanceStatus.AUTHORIZED) -> ClaimProposal:
    updated_at = (
        "2026-01-01T00:00:00Z"
        if status is not GovernanceStatus.PROPOSED
        else "2025-12-31T00:00:00Z"
    )
    return ClaimProposal(
        claim_id="clm_1",
        persona_id="mira",
        continuity="alpha",
        text="Supported.",
        status=status,
        created_at="2025-12-31T00:00:00Z",
        updated_at=updated_at,
    )


def _evidence(evidence_id: str) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        claim_id="clm_1",
        snapshot_id="snp_1",
        start_line=1,
        end_line=1,
        created_at="2025-12-31T00:00:00Z",
    )


def _decision(
    *,
    decision_id: str = "dec_1",
    from_status: GovernanceStatus = GovernanceStatus.PROPOSED,
    to_status: GovernanceStatus = GovernanceStatus.AUTHORIZED,
) -> GovernanceDecision:
    return GovernanceDecision(
        decision_id=decision_id,
        claim_id="clm_1",
        from_status=from_status,
        to_status=to_status,
        reviewer="editor",
        reason="verified source evidence",
        decided_at="2026-01-01T00:00:00Z",
    )


def _entry(
    sequence: int, event_type: str, payload: dict[str, object]
) -> LedgerEntry:
    if event_type == "claim.proposed":
        payload = {
            "persona_id": "mira",
            "continuity": "alpha",
            "text": "Supported.",
            "access_policy": "agent_accessible",
            "confidence": 1.0,
            **payload,
        }
    return LedgerEntry(
        sequence=sequence,
        entry_id=f"led_{sequence}",
        event_type=event_type,
        aggregate_type="claim",
        aggregate_id="clm_1",
        payload=payload,
        previous_hash="0" * 64,
        entry_hash="1" * 64,
        created_at="2026-01-01T00:00:00Z",
    )


def _decision_entry(sequence: int, decision: GovernanceDecision) -> LedgerEntry:
    return _entry(
        sequence,
        "claim.governance_decided",
        {
            "decision_id": decision.decision_id,
            "from_status": decision.from_status.value,
            "to_status": decision.to_status.value,
            "reviewer": decision.reviewer,
            "reason": decision.reason,
        },
    )


def _proposal_entry(claim: ClaimProposal, evidence: list[EvidenceRef]) -> LedgerEntry:
    return _entry(
        1,
        "claim.proposed",
        {
            "evidence_ids": [item.evidence_id for item in evidence],
            **claim_material_digests(claim, evidence).to_payload(),
        },
    )


def test_replay_accepts_exact_decision_ledger_correspondence():
    decision = _decision()
    claim = _claim()
    evidence = [_evidence("evr_1")]
    report = replay_claim_authority(
        claim,
        [decision],
        [
            _proposal_entry(claim, evidence),
            _decision_entry(2, decision),
        ],
        evidence,
    )
    assert report.is_authorized
    assert report.issues == ()


def test_replay_detects_evidence_added_after_authorization():
    decision = _decision()
    report = replay_claim_authority(
        _claim(),
        [decision],
        [
            _entry(1, "claim.proposed", {"evidence_ids": ["evr_1"]}),
            _decision_entry(2, decision),
            _entry(3, "claim.evidence_added", {"evidence_id": "evr_2"}),
        ],
    )
    assert not report.is_valid
    assert "EVIDENCE_APPENDED_WITHOUT_REVIEW_REOPEN" in {
        issue.code for issue in report.issues
    }


def test_replay_allows_evidence_after_explicit_dispute():
    authorize = _decision()
    dispute = _decision(
        decision_id="dec_2",
        from_status=GovernanceStatus.AUTHORIZED,
        to_status=GovernanceStatus.DISPUTED,
    )
    claim = _claim(GovernanceStatus.DISPUTED)
    claim.updated_at = dispute.decided_at
    evidence = [_evidence("evr_1"), _evidence("evr_2")]
    checkpoint = claim_material_digests(claim, evidence).to_payload()
    report = replay_claim_authority(
        claim,
        [authorize, dispute],
        [
            _proposal_entry(claim, evidence[:1]),
            _decision_entry(2, authorize),
            _decision_entry(3, dispute),
            _entry(
                4,
                "claim.evidence_added",
                {
                    "evidence_id": "evr_2",
                    "snapshot_id": "snp_1",
                    "start_line": 1,
                    "end_line": 1,
                    **checkpoint,
                },
            ),
        ],
        evidence,
    )
    assert report.is_valid
    assert report.replayed_status is GovernanceStatus.DISPUTED


def test_replay_detects_payload_and_order_mismatch():
    authorize = _decision()
    dispute = _decision(
        decision_id="dec_2",
        from_status=GovernanceStatus.AUTHORIZED,
        to_status=GovernanceStatus.DISPUTED,
    )
    wrong_authorize_entry = _decision_entry(3, authorize)
    wrong_payload = dict(wrong_authorize_entry.payload)
    wrong_payload["reviewer"] = "someone-else"
    report = replay_claim_authority(
        _claim(GovernanceStatus.DISPUTED),
        [authorize, dispute],
        [
            _entry(1, "claim.proposed", {}),
            _decision_entry(2, dispute),
            _entry(3, "claim.governance_decided", wrong_payload),
        ],
    )
    codes = {issue.code for issue in report.issues}
    assert "DECISION_LEDGER_PAYLOAD_MISMATCH" in codes
    assert "DECISION_CHAIN_BROKEN" in codes


def test_replay_binds_current_evidence_set_to_ledger_ids():
    decision = _decision()
    report = replay_claim_authority(
        _claim(),
        [decision],
        [
            _entry(1, "claim.proposed", {"evidence_ids": ["evr_1"]}),
            _decision_entry(2, decision),
        ],
        ["evr_1", "evr_out_of_band"],
    )
    assert not report.is_valid
    assert "EVIDENCE_SET_LEDGER_MISMATCH" in {
        issue.code for issue in report.issues
    }


def test_replay_binds_proposal_and_appended_evidence_payloads() -> None:
    dispute = _decision(to_status=GovernanceStatus.DISPUTED)
    report = replay_claim_authority(
        _claim(GovernanceStatus.DISPUTED),
        [dispute],
        [
            _entry(
                1,
                "claim.proposed",
                {"persona_id": "forged", "evidence_ids": []},
            ),
            _decision_entry(2, dispute),
            _entry(
                3,
                "claim.evidence_added",
                {
                    "evidence_id": "evr_2",
                    "snapshot_id": "wrong",
                    "start_line": 99,
                    "end_line": 99,
                },
            ),
        ],
        [
            EvidenceRef(
                evidence_id="evr_2",
                claim_id="clm_1",
                snapshot_id="snp_1",
                start_line=1,
                end_line=1,
            )
        ],
    )
    codes = {issue.code for issue in report.issues}
    assert "CLAIM_PROPOSAL_LEDGER_PAYLOAD_MISMATCH" in codes
    assert "EVIDENCE_LEDGER_PAYLOAD_MISMATCH" in codes
