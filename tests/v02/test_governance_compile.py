from __future__ import annotations

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import (
    EvidenceValidationError,
    GovernanceConflictError,
    NotFoundError,
)
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_content
from continuityforge.models import (
    AccessPolicy,
    ClaimProposal,
    GovernanceStatus,
    MemoryCutoff,
    NarrativeEvent,
)


def _proposal(
    text: str,
    *,
    continuity: str = "alpha",
    knowledge_from: str = "2026-01-01T00:00:00Z",
    access_policy: AccessPolicy = AccessPolicy.AGENT_ACCESSIBLE,
    subject: str = "mira",
    predicate: str = "location",
    object_value: str = "observatory",
) -> ClaimProposal:
    return ClaimProposal(
        persona_id="mira",
        continuity=continuity,
        text=text,
        subject=subject,
        predicate=predicate,
        object_value=object_value,
        valid_from="2026-01-01T00:00:00Z",
        knowledge_from=knowledge_from,
        access_policy=access_policy,
        confidence=0.91,
    )


def test_llm_can_only_propose_and_authorization_is_separate(storage):
    _, snapshot, _ = ingest_content(
        storage, "Mira entered the observatory.\n", "story", "alpha"
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    governance = ClaimGovernance(storage)
    pending = governance.propose_from_llm(
        {
            "persona_id": "mira",
            "continuity": "alpha",
            "text": "Mira entered the observatory.",
            "subject": "mira",
            "predicate": "location",
            "object_value": "observatory",
            "knowledge_from": "2026-01-01T00:00:00Z",
            "confidence": 0.91,
            "status": "AUTHORIZED",
        },
        [evidence],
        provider="fixture",
        model="MODEL",
    )
    assert pending.status is GovernanceStatus.PROPOSED
    assert pending.proposed_by == "llm:fixture"
    assert pending.confidence == pytest.approx(0.91)

    cutoff = MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    assert MemoryCompiler(storage).compile(cutoff)["claims"] == []

    decision = governance.review(
        pending.claim_id,
        "AUTHORIZED",
        reviewer="editor",
        reason="line 1 directly supports the atomic claim",
    )
    assert decision.to_status is GovernanceStatus.AUTHORIZED
    pack = MemoryCompiler(storage).compile(cutoff)
    assert [item["id"] for item in pack["claims"]] == [pending.claim_id]
    assert pack["claims"][0]["governance_status"] == "AUTHORIZED"
    assert pack["claims"][0]["source_span"] == {
        "start_line": 1,
        "end_line": 1,
        "start_char": None,
        "end_char": None,
    }


def test_authorization_requires_original_evidence(storage):
    governance = ClaimGovernance(storage)
    pending = governance.propose(_proposal("Unsupported claim"), [])
    with pytest.raises(EvidenceValidationError) as caught:
        governance.review(
            pending.claim_id,
            "AUTHORIZED",
            reviewer="editor",
            reason="attempted review",
        )
    assert caught.value.report.issues[0].code == "EVIDENCE_REQUIRED"
    assert storage.get_claim_proposal(pending.claim_id).status is GovernanceStatus.PROPOSED


def test_v01_human_add_rolls_back_when_authorization_fails(storage):
    governance = ClaimGovernance(storage)
    proposal = _proposal("Unsupported atomic add")
    with pytest.raises(EvidenceValidationError):
        governance.add_authorized_human_claim(proposal, [])
    with pytest.raises(NotFoundError):
        storage.get_claim_proposal(proposal.claim_id)


def test_conflict_requires_disputed_governance(storage):
    _, snapshot, _ = ingest_content(
        storage,
        "Mira is in the observatory.\nMira is in the library.\n",
        "story",
        "alpha",
    )
    governance = ClaimGovernance(storage)
    first = governance.add_authorized_human_claim(
        _proposal("Mira is in the observatory.", object_value="observatory"),
        [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)],
    )
    second = governance.propose(
        _proposal("Mira is in the library.", object_value="library"),
        [build_evidence_ref(storage, snapshot.snapshot_id, 2, 2)],
    )
    with pytest.raises(GovernanceConflictError) as caught:
        governance.review(
            second.claim_id,
            "AUTHORIZED",
            reviewer="editor",
            reason="both spans exist",
        )
    assert caught.value.conflicting_ids == [first.claim_id]
    governance.review(
        second.claim_id,
        "DISPUTED",
        reviewer="editor",
        reason="contradicts the active fact",
    )
    assert storage.get_claim_proposal(second.claim_id).status is GovernanceStatus.DISPUTED


def test_worldline_cutoff_and_access_policy_survive_v02(storage):
    _, alpha, _ = ingest_content(
        storage,
        "Mira entered Alpha.\nThe code is ORION-7.\nPrivate note.\n",
        "story",
        "alpha",
    )
    _, beta, _ = ingest_content(storage, "Mira entered Beta.\n", "story", "beta")
    governance = ClaimGovernance(storage)
    early = governance.add_authorized_human_claim(
        _proposal("Mira entered Alpha."),
        [build_evidence_ref(storage, alpha.snapshot_id, 1, 1)],
    )
    future = governance.add_authorized_human_claim(
        _proposal(
            "The code is ORION-7.",
            knowledge_from="2026-01-03T00:00:00Z",
            subject="archive",
            predicate="code",
            object_value="ORION-7",
        ),
        [build_evidence_ref(storage, alpha.snapshot_id, 2, 2)],
    )
    private = governance.add_authorized_human_claim(
        _proposal(
            "Private note.",
            access_policy=AccessPolicy.HUMAN_ONLY,
            subject="note",
            predicate="visibility",
            object_value="private",
        ),
        [build_evidence_ref(storage, alpha.snapshot_id, 3, 3)],
    )
    beta_claim = governance.add_authorized_human_claim(
        _proposal("Mira entered Beta.", continuity="beta", object_value="beta"),
        [build_evidence_ref(storage, beta.snapshot_id, 1, 1)],
    )

    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    ids = {item["id"] for item in pack["claims"]}
    assert early.claim_id in ids
    assert future.claim_id not in ids
    assert private.claim_id not in ids
    assert beta_claim.claim_id not in ids

    human_pack = MemoryCompiler(storage).compile(
        MemoryCutoff(
            "mira",
            "alpha",
            "2026-01-02T00:00:00Z",
            access_policies=(
                AccessPolicy.AGENT_ACCESSIBLE,
                AccessPolicy.HUMAN_ONLY,
            ),
        )
    )
    assert private.claim_id in {item["id"] for item in human_pack["claims"]}


def test_authorized_claim_can_be_disputed_when_new_evidence_arrives(storage):
    _, snapshot, _ = ingest_content(storage, "Initial account.\n", "story", "alpha")
    governance = ClaimGovernance(storage)
    claim = governance.add_authorized_human_claim(
        _proposal("Initial account."),
        [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)],
    )
    governance.review(
        claim.claim_id,
        GovernanceStatus.DISPUTED,
        reviewer="editor",
        reason="a later source revision challenges this account",
    )
    assert storage.get_claim_proposal(claim.claim_id).status is GovernanceStatus.DISPUTED
    assert MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )["claims"] == []


def test_narrative_event_retains_source_provenance(storage):
    _, snapshot, _ = ingest_content(
        storage, "The observatory opened at midnight.\n", "story", "alpha"
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    event = storage.create_narrative_event(
        NarrativeEvent(
            persona_id="mira",
            continuity="alpha",
            event_type="location.opened",
            title="Observatory opened",
            summary="The observatory opened at midnight.",
            valid_from="2026-01-01T00:00:00Z",
            knowledge_from="2026-01-01T00:00:00Z",
        ),
        [evidence],
    )
    pack = MemoryCompiler(storage).compile(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z")
    )
    assert [item["id"] for item in pack["events"]] == [event.event_id]
    assert pack["events"][0]["provenance"][0]["snapshot_id"] == snapshot.snapshot_id
