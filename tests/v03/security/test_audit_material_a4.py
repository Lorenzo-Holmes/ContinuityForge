from __future__ import annotations

from dataclasses import replace
import math
from pathlib import Path

import pytest

from continuityforge.audit_material import (
    CLAIM_ATTESTATION_EVENT,
    CLAIM_CREATION_EVENT,
    CLAIM_EVIDENCE_EVENT,
    EVENT_ATTESTATION_EVENT,
    EVENT_CREATION_EVENT,
    build_material_attestation_payload,
    canonical_json,
    claim_aggregate_material,
    claim_material_digests,
    event_material_digests,
    evidence_material,
    validate_material_attestation_payload,
)
from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.event_integrity import replay_event_audit
from continuityforge.exceptions import InspectionIntegrityError
from continuityforge.governance import ClaimGovernance
from continuityforge.governance_integrity import replay_claim_authority
from continuityforge.inspection import InspectionService
from continuityforge.models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
    MemoryCutoff,
    NarrativeEvent,
)
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage
from continuityforge.validate import ProjectValidator


T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-02T00:00:00Z"
T2 = "2026-01-03T00:00:00Z"


def _claim(**changes: object) -> ClaimProposal:
    values: dict[str, object] = {
        "claim_id": "clm_material",
        "persona_id": "persona",
        "continuity": "alpha",
        "text": "The anchor exists.",
        "subject": "anchor",
        "predicate": "exists",
        "object_value": "true",
        "valid_from": T0,
        "valid_to": "2030-01-01T00:00:00Z",
        "knowledge_from": T0,
        "knowledge_to": "2030-01-01T00:00:00Z",
        "access_policy": AccessPolicy.AGENT_ACCESSIBLE,
        "confidence": 0.75,
        "status": GovernanceStatus.PROPOSED,
        "proposed_by": "human",
        "proposal_model": "none",
        "rationale": "source",
        "created_at": T0,
        "updated_at": T0,
    }
    values.update(changes)
    return ClaimProposal(**values)


def _event(**changes: object) -> NarrativeEvent:
    values: dict[str, object] = {
        "event_id": "evt_material",
        "persona_id": "persona",
        "continuity": "alpha",
        "event_type": "anchor.seen",
        "title": "Anchor",
        "summary": "The anchor was seen.",
        "details": {"order": 1, "nested": {"ok": True}},
        "valid_from": T0,
        "valid_to": "2030-01-01T00:00:00Z",
        "knowledge_from": T0,
        "knowledge_to": "2030-01-01T00:00:00Z",
        "access_policy": AccessPolicy.AGENT_ACCESSIBLE,
        "created_at": T0,
    }
    values.update(changes)
    return NarrativeEvent(**values)


def _evidence(evidence_id: str = "evr_material", **changes: object) -> EvidenceRef:
    values: dict[str, object] = {
        "evidence_id": evidence_id,
        "claim_id": "clm_material",
        "event_id": None,
        "snapshot_id": "snp_material",
        "start_line": 1,
        "end_line": 2,
        "start_char": 0,
        "end_char": 8,
        "quote": "anchor",
        "content_hash": "a" * 64,
        "created_at": T0,
    }
    values.update(changes)
    return EvidenceRef(**values)


def _ledger(
    sequence: int,
    event_type: str,
    payload: dict[str, object],
    *,
    aggregate_type: str = "claim",
    aggregate_id: str = "clm_material",
    created_at: str = T0,
) -> LedgerEntry:
    return LedgerEntry(
        sequence=sequence,
        entry_id=f"led_{sequence}",
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload,
        previous_hash="0" * 64,
        entry_hash="1" * 64,
        created_at=created_at,
    )


CLAIM_MUTATIONS = {
    "claim_id": "clm_other",
    "persona_id": "other",
    "continuity": "beta",
    "text": "Changed.",
    "subject": "other-subject",
    "predicate": "changed",
    "object_value": "false",
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_to": "2031-01-01T00:00:00Z",
    "knowledge_from": "2025-01-01T00:00:00Z",
    "knowledge_to": "2031-01-01T00:00:00Z",
    "access_policy": AccessPolicy.HIDDEN,
    "confidence": 0.25,
    "proposed_by": "other-human",
    "proposal_model": "other-model",
    "rationale": "other-rationale",
    "created_at": "2025-01-01T00:00:00Z",
}


@pytest.mark.parametrize("field", sorted(CLAIM_MUTATIONS))
def test_claim_material_binds_every_creation_field(field: str) -> None:
    claim = _claim()
    original = claim_material_digests(claim, ()).aggregate_sha256
    mutated = replace(claim, **{field: CLAIM_MUTATIONS[field]})
    assert claim_material_digests(mutated, ()).aggregate_sha256 != original


EVENT_MUTATIONS = {
    "event_id": "evt_other",
    "persona_id": "other",
    "continuity": "beta",
    "event_type": "anchor.changed",
    "title": "Other",
    "summary": "Changed.",
    "details": {"order": 2},
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_to": "2031-01-01T00:00:00Z",
    "knowledge_from": "2025-01-01T00:00:00Z",
    "knowledge_to": "2031-01-01T00:00:00Z",
    "access_policy": AccessPolicy.HIDDEN,
    "created_at": "2025-01-01T00:00:00Z",
}


@pytest.mark.parametrize("field", sorted(EVENT_MUTATIONS))
def test_event_material_binds_every_persisted_field(field: str) -> None:
    event = _event()
    original = event_material_digests(event, ()).aggregate_sha256
    mutated = replace(event, **{field: EVENT_MUTATIONS[field]})
    assert event_material_digests(mutated, ()).aggregate_sha256 != original


EVIDENCE_MUTATIONS = {
    "evidence_id": "evr_other",
    "claim_id": "clm_other",
    "event_id": "evt_other",
    "snapshot_id": "snp_other",
    "start_line": 2,
    "end_line": 3,
    "start_char": 1,
    "end_char": 9,
    "quote": "changed",
    "content_hash": "b" * 64,
    "created_at": T1,
}


@pytest.mark.parametrize("field", sorted(EVIDENCE_MUTATIONS))
def test_evidence_material_binds_every_persisted_field(field: str) -> None:
    evidence = _evidence()
    original = evidence_material(evidence)
    mutated = replace(evidence, **{field: EVIDENCE_MUTATIONS[field]})
    assert evidence_material(mutated) != original
    assert (
        claim_material_digests(_claim(), (mutated,)).evidence_set_sha256
        != claim_material_digests(_claim(), (evidence,)).evidence_set_sha256
    )


def test_material_canonicalization_is_strict_order_independent_and_duplicate_aware() -> None:
    first = _evidence("evr_a")
    second = _evidence("evr_b", start_line=3, end_line=3)
    left = claim_material_digests(_claim(), (first, second))
    right = claim_material_digests(_claim(), (second, first))
    duplicate = claim_material_digests(_claim(), (first, second, first))
    assert left == right
    assert duplicate.evidence_set_sha256 != left.evidence_set_sha256
    assert canonical_json({"z": 1, "a": {"y": 2, "x": 3}}) == (
        '{"a":{"x":3,"y":2},"z":1}'
    )
    for invalid in (float("nan"), float("inf"), {1: "not-a-string-key"}, object()):
        with pytest.raises((TypeError, ValueError)):
            canonical_json(invalid)


def test_claim_creation_cache_values_are_normalized_but_current_cache_is_replayed() -> None:
    proposed = _claim()
    current = replace(
        proposed,
        status=GovernanceStatus.AUTHORIZED,
        updated_at=T2,
    )
    assert claim_aggregate_material(current)["status"] == "PROPOSED"
    assert claim_aggregate_material(current)["updated_at"] == T0
    assert claim_material_digests(current, ()) == claim_material_digests(proposed, ())


def test_negative_zero_confidence_uses_the_sqlite_round_trip_representation(storage) -> None:
    claim = storage.create_claim_proposal(
        ClaimProposal(
            claim_id="clm_negative_zero",
            persona_id="persona",
            continuity="alpha",
            text="negative zero",
            confidence=-0.0,
        )
    )
    assert math.copysign(1.0, claim.confidence) == 1.0
    stored = storage.get_claim_proposal(claim.claim_id)
    assert math.copysign(1.0, stored.confidence) == 1.0
    assert claim_material_digests(_claim(confidence=-0.0), ()) == (
        claim_material_digests(_claim(confidence=0.0), ())
    )
    assert replay_claim_authority(
        stored,
        (),
        storage.list_ledger_entries(aggregate_type="claim", aggregate_id=claim.claim_id),
        (),
    ).is_valid


@pytest.mark.parametrize("confidence", [False, True])
def test_boolean_confidence_is_not_accepted_as_a_number(
    storage, confidence: bool
) -> None:
    proposal = ClaimProposal(
        claim_id=f"clm_bool_{str(confidence).lower()}",
        persona_id="persona",
        continuity="alpha",
        text="boolean confidence",
        confidence=confidence,  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError, match="not bool"):
        ClaimGovernance(storage).propose(proposal)
    with pytest.raises(TypeError, match="not bool"):
        storage.create_claim_proposal(proposal)
    assert storage.list_claim_proposals() == []


def test_claim_updated_at_uses_last_valid_ledger_sequence_even_when_clock_rolls_back() -> None:
    evidence = [_evidence()]
    claim = _claim(status=GovernanceStatus.DISPUTED, updated_at=T1)
    creation = _ledger(
        1,
        CLAIM_CREATION_EVENT,
        {
            "persona_id": claim.persona_id,
            "continuity": claim.continuity,
            "text": claim.text,
            "access_policy": claim.access_policy.value,
            "confidence": claim.confidence,
            "evidence_ids": [evidence[0].evidence_id],
            **claim_material_digests(claim, evidence).to_payload(),
        },
    )
    authorize = GovernanceDecision(
        "dec_authorize",
        claim.claim_id,
        GovernanceStatus.PROPOSED,
        GovernanceStatus.AUTHORIZED,
        "reviewer",
        "authorized",
        T2,
    )
    dispute = GovernanceDecision(
        "dec_dispute",
        claim.claim_id,
        GovernanceStatus.AUTHORIZED,
        GovernanceStatus.DISPUTED,
        "reviewer",
        "reopened",
        T1,
    )
    entries = [creation]
    for sequence, decision in enumerate((authorize, dispute), start=2):
        entries.append(
            _ledger(
                sequence,
                "claim.governance_decided",
                {
                    "decision_id": decision.decision_id,
                    "from_status": decision.from_status.value,
                    "to_status": decision.to_status.value,
                    "reviewer": decision.reviewer,
                    "reason": decision.reason,
                },
                created_at=decision.decided_at,
            )
        )
    report = replay_claim_authority(claim, (authorize, dispute), entries, evidence)
    assert report.is_valid
    forged = replay_claim_authority(
        replace(claim, updated_at=T2), (authorize, dispute), entries, evidence
    )
    assert "CLAIM_UPDATED_AT_REPLAY_MISMATCH" in {
        issue.code for issue in forged.issues
    }

    timestamp_mismatch = list(entries)
    timestamp_mismatch[1] = replace(timestamp_mismatch[1], created_at=T0)
    mismatch = replay_claim_authority(
        claim, (authorize, dispute), timestamp_mismatch, evidence
    )
    assert "DECISION_LEDGER_TIMESTAMP_MISMATCH" in {
        issue.code for issue in mismatch.issues
    }


def test_event_details_at_storage_depth_limit_remain_auditable(storage: Storage) -> None:
    details: dict[str, object] = {}
    for _ in range(127):
        details = {"nested": details}

    source, snapshot, _ = storage.ingest_snapshot(
        "depth/material", "alpha", "depth anchor\n"
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    created = storage.create_narrative_event(
        _event(event_id="evt_depth", details=details),
        (evidence,),
    )

    assert source.continuity == "alpha"
    assert event_material_digests(
        created, storage.get_event_evidence(created.event_id)
    ).material_version == 2


def test_legacy_creation_requires_one_bound_attestation_and_v2_rejects_it() -> None:
    claim = _claim()
    evidence = [_evidence()]
    legacy = _ledger(
        1,
        CLAIM_CREATION_EVENT,
        {
            "persona_id": claim.persona_id,
            "continuity": claim.continuity,
            "text": claim.text,
            "access_policy": claim.access_policy.value,
            "confidence": claim.confidence,
            "evidence_ids": [evidence[0].evidence_id],
        },
    )
    payload = build_material_attestation_payload(
        claim_material_digests(claim, evidence),
        attested_event_type=CLAIM_CREATION_EVENT,
        attested_entry_id=legacy.entry_id,
        migration_source_kind="v0.2",
    )
    attestation = _ledger(2, CLAIM_ATTESTATION_EVENT, payload)
    assert replay_claim_authority(claim, (), (legacy, attestation), evidence).is_valid
    duplicate = _ledger(3, CLAIM_ATTESTATION_EVENT, payload)
    assert not replay_claim_authority(
        claim, (), (legacy, attestation, duplicate), evidence
    ).is_valid

    v2 = _ledger(
        1,
        CLAIM_CREATION_EVENT,
        {**legacy.payload, **claim_material_digests(claim, evidence).to_payload()},
    )
    assert not replay_claim_authority(claim, (), (v2, attestation), evidence).is_valid


def test_event_legacy_attestation_is_strictly_bound_to_creation_entry() -> None:
    event = _event()
    evidence = [replace(_evidence(), claim_id=None, event_id=event.event_id)]
    creation = _ledger(
        1,
        EVENT_CREATION_EVENT,
        {
            "persona_id": event.persona_id,
            "continuity": event.continuity,
            "event_type": event.event_type,
            "valid_from": event.valid_from,
            "knowledge_from": event.knowledge_from,
            "access_policy": event.access_policy.value,
            "evidence_ids": [evidence[0].evidence_id],
            "evidence_refs": [
                {
                    "evidence_id": evidence[0].evidence_id,
                    "snapshot_id": evidence[0].snapshot_id,
                    "start_line": evidence[0].start_line,
                    "end_line": evidence[0].end_line,
                    "content_hash": evidence[0].content_hash,
                }
            ],
        },
        aggregate_type="narrative_event",
        aggregate_id=event.event_id,
    )
    payload = build_material_attestation_payload(
        event_material_digests(event, evidence),
        attested_event_type=EVENT_CREATION_EVENT,
        attested_entry_id=creation.entry_id,
        migration_source_kind="v0.3-alpha3",
    )
    attestation = _ledger(
        2,
        EVENT_ATTESTATION_EVENT,
        payload,
        aggregate_type="narrative_event",
        aggregate_id=event.event_id,
    )
    assert replay_event_audit(event, (creation, attestation), evidence).is_valid
    bad_payload = dict(payload)
    bad_payload["attested_entry_id"] = "led_other"
    bad = replace(attestation, payload=bad_payload)
    assert not replay_event_audit(event, (creation, bad), evidence).is_valid


def test_attestation_source_kind_is_a_strict_legacy_whitelist() -> None:
    digests = claim_material_digests(_claim(), ())
    for source_kind in ("v0.2", "v0.3-alpha2", "v0.3-alpha3"):
        payload = build_material_attestation_payload(
            digests,
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id="led_1",
            migration_source_kind=source_kind,
        )
        assert validate_material_attestation_payload(
            payload,
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id="led_1",
        ) == digests
    for source_kind in ("v0.1", "v0.3", "V0.2", ""):
        with pytest.raises(ValueError):
            build_material_attestation_payload(
                digests,
                attested_event_type=CLAIM_CREATION_EVENT,
                attested_entry_id="led_1",
                migration_source_kind=source_kind,
            )


def test_claim_evidence_added_stores_a_complete_latest_material_checkpoint(storage) -> None:
    _, snapshot, _ = storage.ingest_snapshot("checkpoint", "alpha", "one\ntwo\n")
    first = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
    second = build_evidence_ref(storage, snapshot.snapshot_id, 2, 2)
    claim = storage.create_claim_proposal(
        ClaimProposal(
            claim_id="clm_checkpoint",
            persona_id="persona",
            continuity="alpha",
            text="checkpoint",
        ),
        (first,),
    )
    storage.add_claim_evidence(claim.claim_id, second)
    stored = storage.get_claim_evidence(claim.claim_id)
    report = replay_claim_authority(
        storage.get_claim_proposal(claim.claim_id),
        (),
        storage.list_ledger_entries(aggregate_type="claim", aggregate_id=claim.claim_id),
        stored,
    )
    assert report.is_valid
    checkpoint = storage.list_ledger_entries(
        event_type=CLAIM_EVIDENCE_EVENT,
        aggregate_type="claim",
        aggregate_id=claim.claim_id,
    )[-1]
    expected = claim_material_digests(claim, stored).to_payload()
    assert {key: checkpoint.payload[key] for key in expected} == expected


@pytest.mark.parametrize(
    ("aggregate", "inner_code", "compiler_code", "inspection_code"),
    [
        (
            "claim",
            "CLAIM_AGGREGATE_MATERIAL_MISMATCH",
            "AUTHORITY_CHAIN_INVALID",
            "CLAIM_AUTHORITY_INVALID",
        ),
        (
            "event",
            "EVENT_AGGREGATE_MATERIAL_MISMATCH",
            "EVENT_AUDIT_INVALID",
            "EVENT_AUDIT_INVALID",
        ),
    ],
)
def test_material_visibility_tamper_has_validator_compiler_inspection_parity(
    tmp_path: Path,
    aggregate: str,
    inner_code: str,
    compiler_code: str,
    inspection_code: str,
) -> None:
    database = tmp_path / f"material-{aggregate}.db"
    aggregate_id: str
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot("story", "alpha", "anchor\n")
        storage.ingest_snapshot("story", "alpha", "anchor changed\n")
        evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        if aggregate == "claim":
            claim = ClaimGovernance(storage).add_authorized_human_claim(
                ClaimProposal(
                    claim_id="clm_future",
                    persona_id="persona",
                    continuity="alpha",
                    text="future claim",
                    knowledge_from="2099-01-01T00:00:00Z",
                ),
                (evidence,),
                reviewer="reviewer",
                reason="verified",
            )
            aggregate_id = claim.claim_id
            trigger = "continuityforge_claims_fields_immutable"
            mutation = (
                "UPDATE claim_proposals SET knowledge_from = ? WHERE claim_id = ?",
                ("2020-01-01T00:00:00Z", aggregate_id),
            )
        else:
            event = storage.create_narrative_event(
                NarrativeEvent(
                    event_id="evt_expired",
                    persona_id="persona",
                    continuity="alpha",
                    title="Expired",
                    knowledge_from="2020-01-01T00:00:00Z",
                    knowledge_to="2021-01-01T00:00:00Z",
                ),
                (evidence,),
            )
            aggregate_id = event.event_id
            trigger = "continuityforge_events_no_update"
            mutation = (
                "UPDATE narrative_events SET knowledge_to = NULL WHERE event_id = ?",
                (aggregate_id,),
            )

        trigger_sql = storage.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger,),
        ).fetchone()[0]
        storage.connection.execute(f'DROP TRIGGER "{trigger}"')
        storage.connection.execute(*mutation)
        storage.connection.execute(trigger_sql)
        assert storage.verify_ledger()

        validation_codes = {issue.code for issue in ProjectValidator(storage).validate().issues}
        assert inner_code in validation_codes
        pack = MemoryCompiler(storage).compile(
            MemoryCutoff("persona", "alpha", "2026-01-01T00:00:00Z")
        )
        assert not any(
            item["id"] == aggregate_id
            for item in (*pack["claims"], *pack["events"])
        )
        diagnostic = next(
            item for item in pack["diagnostics"] if item["aggregate_id"] == aggregate_id
        )
        assert diagnostic["code"] == compiler_code
        assert inner_code in {
            issue["code"] for issue in diagnostic["details"]["issues"]
        }

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as exc_info:
            InspectionService(project).source_impact(
                source.source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )
    assert exc_info.value.code == inspection_code


@pytest.mark.parametrize(
    "event_type",
    [
        CLAIM_CREATION_EVENT,
        CLAIM_EVIDENCE_EVENT,
        CLAIM_ATTESTATION_EVENT,
        EVENT_CREATION_EVENT,
        EVENT_ATTESTATION_EVENT,
    ],
)
def test_public_append_ledger_rejects_reserved_material_events(
    storage, event_type: str
) -> None:
    with pytest.raises(ValueError, match="reserved audit events"):
        storage.append_ledger(event_type, "claim", "aggregate", {})
