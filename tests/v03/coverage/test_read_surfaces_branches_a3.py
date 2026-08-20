from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import continuityforge.compiler as compiler_module
import continuityforge.inspection as inspection_module
from continuityforge.compiler import CompilationDiagnostic, MemoryCompiler
from continuityforge.evidence import (
    EvidenceValidator,
    ValidationIssue,
    ValidationReport,
    build_evidence_ref,
    quote_sha256,
)
from continuityforge.event_integrity import (
    replay_event_audit,
    replay_event_audits,
    validate_event_audits,
)
from continuityforge.exceptions import (
    ContinuityViolation,
    EvidenceValidationError,
    InspectionIntegrityError,
    InspectionLimitError,
    LedgerIntegrityError,
    NotFoundError,
)
from continuityforge.governance_integrity import (
    replay_claim_authority,
    validate_claim_authorities,
    validate_claim_authority,
)
from continuityforge.impact_models import (
    ImpactCandidate,
    ImpactOutcome,
    ImpactReasonCode,
    ImpactReport,
)
from continuityforge.inspection import (
    AffectedEvidence,
    InspectionService,
    SourceImpactReport,
)
from continuityforge.models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
    MemoryCutoff,
    NarrativeEvent,
    Source,
    SourceSnapshot,
)
from continuityforge.readonly import (
    ClaimAuthorityMaterial,
    EventAuditMaterial,
    ProvenanceRecord,
    ReadOnlyProject,
)
from continuityforge.source_integrity import SourceAuditIssue, SourceAuditReport
from continuityforge.storage import Storage
from continuityforge.validate import (
    ProjectIssue,
    ProjectValidationReport,
    ProjectValidator,
    Severity,
)


NOW = "2026-08-20T00:00:00Z"


def _claim(
    claim_id: str = "claim",
    *,
    status: GovernanceStatus = GovernanceStatus.PROPOSED,
    persona_id: str = "persona",
    continuity: str = "alpha",
    text: str = "supported claim",
    **changes: Any,
) -> ClaimProposal:
    values: dict[str, Any] = {
        "claim_id": claim_id,
        "persona_id": persona_id,
        "continuity": continuity,
        "text": text,
        "status": status,
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(changes)
    return ClaimProposal(**values)


def _event(
    event_id: str = "event",
    *,
    persona_id: str = "persona",
    continuity: str = "alpha",
    **changes: Any,
) -> NarrativeEvent:
    values: dict[str, Any] = {
        "event_id": event_id,
        "persona_id": persona_id,
        "continuity": continuity,
        "event_type": "narrative",
        "title": "title",
        "summary": "summary",
        "created_at": NOW,
    }
    values.update(changes)
    return NarrativeEvent(**values)


def _evidence(
    evidence_id: str | None = "evidence",
    *,
    snapshot_id: str = "snapshot",
    claim_id: str | None = None,
    event_id: str | None = None,
    quote: Any = "anchor",
    content_hash: Any = None,
    start_line: Any = 1,
    end_line: Any = 1,
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        snapshot_id=snapshot_id,
        claim_id=claim_id,
        event_id=event_id,
        quote=quote,
        content_hash=content_hash,
        start_line=start_line,
        end_line=end_line,
        created_at=NOW,
    )


def _ledger(
    sequence: int,
    event_type: str,
    payload: dict[str, Any] | None = None,
    *,
    aggregate_type: str = "claim",
    aggregate_id: str = "claim",
    created_at: str = NOW,
) -> LedgerEntry:
    return LedgerEntry(
        sequence=sequence,
        entry_id=f"ledger-{sequence}",
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload or {},
        previous_hash="0" * 64,
        entry_hash="1" * 64,
        created_at=created_at,
    )


def _decision(
    decision_id: str = "decision",
    *,
    claim_id: str = "claim",
    from_status: GovernanceStatus = GovernanceStatus.PROPOSED,
    to_status: GovernanceStatus = GovernanceStatus.AUTHORIZED,
    reviewer: str = "reviewer",
    reason: str = "reason",
) -> GovernanceDecision:
    return GovernanceDecision(
        decision_id=decision_id,
        claim_id=claim_id,
        from_status=from_status,
        to_status=to_status,
        reviewer=reviewer,
        reason=reason,
        decided_at=NOW,
    )


def _decision_ledger(sequence: int, decision: GovernanceDecision) -> LedgerEntry:
    return _ledger(
        sequence,
        "claim.governance_decided",
        {
            "decision_id": decision.decision_id,
            "from_status": decision.from_status.value,
            "to_status": decision.to_status.value,
            "reviewer": decision.reviewer,
            "reason": decision.reason,
        },
        aggregate_id=decision.claim_id,
    )


def _proposal_ledger(
    sequence: int = 1,
    *,
    claim: ClaimProposal | None = None,
    evidence_ids: Any = (),
) -> LedgerEntry:
    claim = claim or _claim()
    return _ledger(
        sequence,
        "claim.proposed",
        {
            "persona_id": claim.persona_id,
            "continuity": claim.continuity,
            "text": claim.text,
            "access_policy": claim.access_policy.value,
            "confidence": float(claim.confidence),
            "evidence_ids": evidence_ids,
        },
        aggregate_id=claim.claim_id,
    )


def _impact(
    *,
    old_snapshot_id: str = "old",
    target_snapshot_id: str = "target",
    candidates: tuple[ImpactCandidate, ...] | None = None,
) -> ImpactReport:
    return ImpactReport(
        outcome=ImpactOutcome.SAME_POSITION,
        old_snapshot_id=old_snapshot_id,
        target_snapshot_id=target_snapshot_id,
        target_snapshot_version=2,
        original_start_line=1,
        original_end_line=1,
        candidates=candidates or (ImpactCandidate(1, 1),),
        reason_code=ImpactReasonCode.EXACT_AT_ORIGINAL_SPAN,
        reason="the exact quote remains at the original span",
    )


def _snapshot(
    snapshot_id: str = "snapshot",
    *,
    content: Any = "anchor",
    continuity: str = "alpha",
    source_id: str = "source",
    version: int = 1,
    content_hash: str | None = None,
    line_count: int | None = 1,
    previous_snapshot_id: str | None = None,
) -> SourceSnapshot:
    digest = content_hash
    if digest is None and isinstance(content, str):
        digest = sha256(content.encode("utf-8")).hexdigest()
    return SourceSnapshot(
        snapshot_id=snapshot_id,
        source_id=source_id,
        source_key="story",
        continuity=continuity,
        version=version,
        content_hash=digest or "0" * 64,
        content=content,
        previous_snapshot_id=previous_snapshot_id,
        line_count=line_count,
        created_at=NOW,
    )


def _seed_read_project(database: Path) -> dict[str, str]:
    with Storage(database) as storage:
        source, first, _ = storage.ingest_snapshot("story", "alpha", "anchor\nsecond")
        _, second, _ = storage.ingest_snapshot("story", "alpha", "moved\nanchor")
        storage.ingest_snapshot("story", "beta", "other worldline")
        evidence = build_evidence_ref(storage, first.snapshot_id, 1, 1)
        claim = storage.create_claim_proposal(
            _claim("claim-db", text="anchor"), (evidence,)
        )
        event = storage.create_narrative_event(
            _event("event-db"),
            (build_evidence_ref(storage, first.snapshot_id, 2, 2),),
        )
        claim_evidence = storage.get_claim_evidence(claim.claim_id)[0]
        event_evidence = storage.get_event_evidence(event.event_id)[0]
        assert claim_evidence.evidence_id is not None
        assert event_evidence.evidence_id is not None
        return {
            "source": source.source_id,
            "first": first.snapshot_id,
            "second": second.snapshot_id,
            "claim": claim.claim_id,
            "event": event.event_id,
            "claim_evidence": claim_evidence.evidence_id,
            "event_evidence": event_evidence.evidence_id,
        }


def test_provenance_record_rejects_mismatched_owner_material() -> None:
    claim = _claim()
    event = _event()
    claim_evidence = _evidence(claim_id=claim.claim_id)
    event_evidence = _evidence("event-evidence", event_id=event.event_id)

    with pytest.raises(ValueError, match="aggregate_type"):
        ProvenanceRecord("snapshot", "other", claim.claim_id, claim, claim_evidence)
    with pytest.raises(ValueError, match="snapshot IDs differ"):
        ProvenanceRecord("other", "claim", claim.claim_id, claim, claim_evidence)
    with pytest.raises(TypeError, match="ClaimProposal"):
        ProvenanceRecord("snapshot", "claim", event.event_id, event, event_evidence)
    with pytest.raises(ValueError, match="claim IDs differ"):
        ProvenanceRecord("snapshot", "claim", "other", claim, claim_evidence)
    with pytest.raises(TypeError, match="NarrativeEvent"):
        ProvenanceRecord("snapshot", "event", claim.claim_id, claim, claim_evidence)
    with pytest.raises(ValueError, match="event IDs differ"):
        ProvenanceRecord("snapshot", "event", "other", event, event_evidence)

    claim_record = ProvenanceRecord(
        "snapshot", "claim", claim.claim_id, claim, claim_evidence
    )
    event_record = ProvenanceRecord(
        "snapshot", "event", event.event_id, event, event_evidence
    )
    assert claim_record.claim is claim and claim_record.event is None
    assert event_record.event is event and event_record.claim is None


@pytest.mark.parametrize("payload_json", ["{", "[]", "null", '"scalar"'])
def test_readonly_ledger_mapping_fails_closed_for_invalid_payload(
    payload_json: str,
) -> None:
    row = {
        "sequence": 1,
        "entry_id": "entry",
        "event_type": "event",
        "aggregate_type": "claim",
        "aggregate_id": "claim",
        "payload_json": payload_json,
        "previous_hash": "0" * 64,
        "entry_hash": "1" * 64,
        "created_at": NOW,
    }
    with pytest.raises(InspectionIntegrityError) as caught:
        ReadOnlyProject._ledger_entry(row)  # type: ignore[arg-type]
    assert caught.value.code == "LEDGER_PAYLOAD_INVALID"


def test_readonly_lookup_and_lineage_argument_gates(tmp_path: Path) -> None:
    database = tmp_path / "read-gates.db"
    ids = _seed_read_project(database)
    with ReadOnlyProject.open(database) as project:
        with pytest.raises(TypeError, match="not both"):
            project.get_source(ids["source"], source_key="story")
        with pytest.raises(TypeError, match="required"):
            project.get_source()
        with pytest.raises(NotFoundError):
            project.get_source("missing")
        with pytest.raises(ContinuityViolation, match="more than one continuity"):
            project.get_source(source_key="story")
        with pytest.raises(ContinuityViolation, match="continuity mismatch"):
            project.get_source(ids["source"], continuity="beta")

        for version in (True, 0, -1, "1"):
            with pytest.raises(ValueError, match="positive integer"):
                project.get_snapshot_by_version(ids["source"], version)  # type: ignore[arg-type]
        with pytest.raises(NotFoundError):
            project.get_snapshot_by_version(ids["source"], 99)
        with pytest.raises(NotFoundError):
            project.get_latest_snapshot("missing")
        with pytest.raises(NotFoundError):
            project.get_latest_snapshot_metadata("missing")

        with pytest.raises(TypeError, match="built-in integers"):
            project.list_snapshot_metadata(
                ids["source"], from_version=True, to_version=2, limit=2
            )
        with pytest.raises(ValueError, match="1 <="):
            project.list_snapshot_metadata(
                ids["source"], from_version=2, to_version=1, limit=2
            )
        with pytest.raises(ValueError, match="positive built-in integer"):
            project.list_snapshot_metadata(
                ids["source"], from_version=1, to_version=2, limit=True
            )
        with pytest.raises(InspectionLimitError) as caught:
            project.list_snapshot_metadata(
                ids["source"], from_version=1, to_version=2, limit=1
            )
        assert caught.value.code == "SOURCE_REVISION_LIMIT_EXCEEDED"

        bad_endpoint_sets: tuple[tuple[Any, ...], ...] = (
            (),
            (1, 2, 3),
            (True,),
            (1, 1),
        )
        for versions in bad_endpoint_sets:
            with pytest.raises(ValueError):
                project.get_snapshots_by_versions_bounded(
                    ids["source"], versions, max_content_bytes=1_000
                )
        with pytest.raises(ValueError, match="max_content_bytes"):
            project.get_snapshots_by_versions_bounded(
                ids["source"], (1,), max_content_bytes=True
            )
        with pytest.raises(NotFoundError):
            project.get_snapshots_by_versions_bounded(
                ids["source"], (99,), max_content_bytes=1_000
            )
        with pytest.raises(InspectionLimitError) as caught:
            project.get_snapshots_by_versions_bounded(
                ids["source"], (1,), max_content_bytes=1
            )
        assert caught.value.code == "SNAPSHOT_BYTES_LIMIT_EXCEEDED"

        with pytest.raises(NotFoundError):
            project.get_claim_proposal("missing")
        with pytest.raises(NotFoundError):
            project.get_claim_evidence("missing")
        with pytest.raises(NotFoundError):
            project.get_narrative_event("missing")
        with pytest.raises(NotFoundError):
            project.get_event_evidence("missing")
        with pytest.raises(NotFoundError):
            project.get_evidence("missing")
        with pytest.raises(TypeError, match="mutually exclusive"):
            project.list_evidence(claim_id=ids["claim"], event_id=ids["event"])


def test_readonly_public_read_filters_return_typed_complete_material(
    tmp_path: Path,
) -> None:
    database = tmp_path / "read-surfaces.db"
    ids = _seed_read_project(database)
    project = ReadOnlyProject.open(database)
    assert project.schema_version == 3
    assert project.get_source(source_key="story", continuity="alpha").source_id == ids[
        "source"
    ]
    assert [item.continuity for item in project.list_sources(continuity="alpha")] == [
        "alpha"
    ]
    assert project.get_snapshot(ids["first"]).version == 1
    assert project.get_snapshot_by_version(ids["source"], 2).snapshot_id == ids[
        "second"
    ]
    assert project.get_latest_snapshot(ids["source"]).version == 2
    assert project.get_latest_snapshot_metadata(ids["source"]).version == 2
    assert [item.version for item in project.list_snapshot_metadata(
        ids["source"], from_version=1, to_version=2, limit=2
    )] == [1, 2]
    endpoints = project.get_snapshots_by_versions_bounded(
        ids["source"], (2, 1), max_content_bytes=1_000
    )
    assert tuple(endpoints) == (1, 2)
    assert [item.version for item in project.list_snapshots(ids["source"])] == [1, 2]
    assert [item.version for item in project.list_snapshots(
        source_key="story", continuity="alpha"
    )] == [1, 2]
    assert len(project.list_source_audit_snapshots()) == 3

    claims = project.list_claim_proposals(
        persona_id="persona",
        continuity="alpha",
        status="PROPOSED",
        snapshot_id=ids["first"],
    )
    assert [item.claim_id for item in claims] == [ids["claim"]]
    assert project.get_claim_proposal(ids["claim"]).text == "anchor"
    assert project.get_claim_evidence(ids["claim"])[0].evidence_id == ids[
        "claim_evidence"
    ]
    assert project.list_all_claim_evidence()[0].claim_id == ids["claim"]

    events = project.list_narrative_events(persona_id="persona", continuity="alpha")
    assert [item.event_id for item in events] == [ids["event"]]
    assert project.get_narrative_event(ids["event"]).title == "title"
    assert project.get_event_evidence(ids["event"])[0].evidence_id == ids[
        "event_evidence"
    ]
    assert project.list_all_event_evidence()[0].event_id == ids["event"]
    assert project.get_evidence(ids["claim_evidence"]).claim_id == ids["claim"]
    assert project.get_evidence(ids["event_evidence"]).event_id == ids["event"]

    assert [item.claim_id for item in project.list_evidence(claim_id=ids["claim"])] == [
        ids["claim"]
    ]
    assert [item.event_id for item in project.list_evidence(event_id=ids["event"])] == [
        ids["event"]
    ]
    by_snapshot = project.list_snapshot_evidence(ids["first"])
    assert {item.claim_id or item.event_id for item in by_snapshot} == {
        ids["claim"],
        ids["event"],
    }
    provenance = project.get_provenance_for_snapshots((ids["first"],))[
        ids["first"]
    ]
    assert {(item.aggregate_type, item.aggregate_id) for item in provenance} == {
        ("claim", ids["claim"]),
        ("event", ids["event"]),
    }
    assert project.list_provenance(ids["first"]) == provenance

    with project.read_transaction():
        with project.transaction():
            assert project.get_source(ids["source"]).source_key == "story"
    project.close()
    project.close()
    with pytest.raises(RuntimeError, match="closed"):
        _ = project.connection


def test_readonly_provenance_and_integrity_limits_are_independent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "read-limits.db"
    ids = _seed_read_project(database)
    with ReadOnlyProject.open(database) as project:
        invalid_batches: tuple[Any, ...] = (
            "one-id",
            ("",),
            tuple(f"snapshot-{index}" for index in range(901)),
        )
        for batch in invalid_batches:
            with pytest.raises((TypeError, ValueError)):
                project.get_provenance_for_snapshots(batch)
        assert dict(project.get_provenance_for_snapshots(())) == {}
        with pytest.raises(ValueError, match="max_records"):
            project.get_provenance_for_snapshots((ids["first"],), max_records=True)
        with pytest.raises(ValueError, match="max_material_bytes"):
            project.get_provenance_for_snapshots(
                (ids["first"],), max_material_bytes=True
            )
        with pytest.raises(InspectionLimitError) as caught:
            project.get_provenance_for_snapshots(
                (ids["first"],), max_records=1, max_material_bytes=10**9
            )
        assert caught.value.code == "AFFECTED_EVIDENCE_LIMIT_EXCEEDED"
        with pytest.raises(InspectionLimitError) as caught:
            project.get_provenance_for_snapshots(
                (ids["first"],), max_records=100, max_material_bytes=1
            )
        assert caught.value.code == "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED"

        with pytest.raises(InspectionLimitError) as caught:
            project.verify_ledger_bounded(
                max_entries=1,
                max_payload_bytes=10**9,
                max_single_payload_bytes=10**9,
            )
        assert caught.value.code == "INSPECTION_LEDGER_ENTRY_LIMIT_EXCEEDED"
        with pytest.raises(InspectionLimitError) as caught:
            project.verify_ledger_bounded(
                max_entries=10**6,
                max_payload_bytes=1,
                max_single_payload_bytes=10**9,
            )
        assert caught.value.code == "INSPECTION_LEDGER_PAYLOAD_LIMIT_EXCEEDED"
        for kwargs in (
            {"max_entries": True, "max_payload_bytes": 1, "max_single_payload_bytes": 1},
            {"max_entries": 1, "max_payload_bytes": 0, "max_single_payload_bytes": 1},
            {"max_entries": 1, "max_payload_bytes": 1, "max_single_payload_bytes": 0},
        ):
            with pytest.raises(ValueError, match="positive built-in integer"):
                project.verify_ledger_bounded(**kwargs)


def test_readonly_audit_material_validates_types_and_both_limits(
    tmp_path: Path,
) -> None:
    database = tmp_path / "audit-limits.db"
    ids = _seed_read_project(database)
    with ReadOnlyProject.open(database) as project:
        readers = (
            (
                project.get_source_audit_for_source,
                ids["source"],
                "INSPECTION_SOURCE_AUDIT_RECORD_LIMIT_EXCEEDED",
                "INSPECTION_SOURCE_AUDIT_BYTES_LIMIT_EXCEEDED",
            ),
            (
                project.get_claim_authority_for_snapshot,
                ids["first"],
                "INSPECTION_AUTHORITY_RECORD_LIMIT_EXCEEDED",
                "INSPECTION_AUTHORITY_BYTES_LIMIT_EXCEEDED",
            ),
            (
                project.get_event_audit_for_snapshot,
                ids["first"],
                "INSPECTION_EVENT_AUDIT_RECORD_LIMIT_EXCEEDED",
                "INSPECTION_EVENT_AUDIT_BYTES_LIMIT_EXCEEDED",
            ),
        )
        for reader, identifier, record_code, byte_code in readers:
            for bad_identifier in (None, ""):
                with pytest.raises(ValueError, match="must be non-empty"):
                    reader(
                        bad_identifier, max_records=100, max_material_bytes=10**9
                    )
            for name, bad_value in (("max_records", True), ("max_material_bytes", 0)):
                kwargs = {"max_records": 100, "max_material_bytes": 10**9}
                kwargs[name] = bad_value
                with pytest.raises(ValueError, match="positive built-in integer"):
                    reader(identifier, **kwargs)
            with pytest.raises(InspectionLimitError) as caught:
                reader(identifier, max_records=1, max_material_bytes=10**9)
            assert caught.value.code == record_code
            with pytest.raises(InspectionLimitError) as caught:
                reader(identifier, max_records=10**6, max_material_bytes=1)
            assert caught.value.code == byte_code


class _EvidenceStorage:
    def __init__(self, snapshots: dict[str, Any], sources: dict[str, Any] | None = None):
        self.snapshots = snapshots
        self.sources = sources or {}

    def get_snapshot(self, snapshot_id: str) -> Any:
        if snapshot_id not in self.snapshots:
            raise KeyError(snapshot_id)
        return self.snapshots[snapshot_id]

    def get_source(self, source_id: str) -> Any:
        if source_id not in self.sources:
            raise KeyError(source_id)
        return self.sources[source_id]


def test_evidence_validator_accumulates_hostile_material_diagnostics() -> None:
    storage = _EvidenceStorage(
        {
            "no-content": {"content": object(), "continuity": "alpha"},
            "no-continuity": {
                "content": "one",
                "continuity": None,
                "source_id": "missing-source",
                "line_count": 1,
            },
            "mismatch": {
                "content": "one\ntwo",
                "continuity": "beta",
                "line_count": 99,
            },
            "valid": {
                "content": "one\ntwo",
                "continuity": "alpha",
                "line_count": 2,
            },
        }
    )
    refs: list[Any] = [
        {},
        {"snapshot_id": "valid", "start_line": True, "end_line": 1},
        {"snapshot_id": "missing", "start_line": 1, "end_line": 1},
        {"snapshot_id": "no-content", "start_line": 1, "end_line": 1},
        {"snapshot_id": "no-continuity", "start_line": 1, "end_line": 1},
        {"snapshot_id": "mismatch", "start_line": 0, "end_line": 1},
        {"snapshot_id": "valid", "start_line": 1, "end_line": 3},
        {
            "snapshot_id": "valid",
            "start_line": 1,
            "end_line": 1,
            "quote": object(),
            "content_hash": "not-a-digest",
        },
        {
            "snapshot_id": "valid",
            "start_line": 2,
            "end_line": 2,
            "quote": "wrong",
            "content_hash": "0" * 64,
        },
    ]
    report = EvidenceValidator(storage).validate_claim(
        {"continuity": object()}, refs
    )
    codes = [issue.code for issue in report.issues]
    assert "CLAIM_CONTINUITY_MISSING" in codes
    assert "SNAPSHOT_ID_REQUIRED" in codes
    assert "INVALID_LINE_RANGE" in codes
    assert "SNAPSHOT_NOT_FOUND" in codes
    assert "SNAPSHOT_CONTENT_MISSING" in codes
    assert "SNAPSHOT_CONTINUITY_MISSING" in codes
    assert "SNAPSHOT_LINE_COUNT_MISMATCH" in codes
    assert "LINE_RANGE_OUT_OF_BOUNDS" in codes
    assert "INVALID_QUOTE" in codes
    assert "QUOTE_MISMATCH" in codes
    assert "INVALID_CONTENT_HASH" in codes
    assert "CONTENT_HASH_MISMATCH" in codes
    with pytest.raises(EvidenceValidationError) as caught:
        report.raise_for_errors()
    assert caught.value.report is report
    assert report.to_dict()["issues"][0]["actual"].startswith("<object object")


def test_evidence_continuity_fallback_and_digest_normalization() -> None:
    quote = "one"
    storage = _EvidenceStorage(
        {
            "fallback": {
                "content": quote,
                "continuity": None,
                "source_id": "source",
                "line_count": 1,
            }
        },
        {"source": {"continuity": "alpha"}},
    )
    report = EvidenceValidator(storage).validate_claim(
        {"continuity": "alpha"},
        [
            {
                "snapshot_id": "fallback",
                "line_start": 1,
                "line_end": 1,
                "quote": "one\r\n"[:-2],
                "sha256": f"SHA256:{quote_sha256(quote).upper()}",
            }
        ],
    )
    assert report.is_valid
    assert ValidationReport().to_json() == '{"is_valid": true, "issues": []}'


def test_evidence_builder_fails_closed_for_missing_content_and_bad_ranges() -> None:
    missing = _EvidenceStorage({})
    with pytest.raises(EvidenceValidationError) as caught:
        build_evidence_ref(missing, "missing", 1, 1)
    assert caught.value.report.issues[0].code == "SNAPSHOT_NOT_FOUND"

    no_content = _EvidenceStorage({"snapshot": {"content": object()}})
    with pytest.raises(EvidenceValidationError) as caught:
        build_evidence_ref(no_content, "snapshot", 1, 1)
    assert caught.value.report.issues[0].code == "SNAPSHOT_CONTENT_MISSING"

    valid = _EvidenceStorage({"snapshot": {"content": "one\ntwo"}})
    for start, end, code in ((0, 1, "INVALID_LINE_RANGE"), (1, 3, "LINE_RANGE_OUT_OF_BOUNDS")):
        with pytest.raises(EvidenceValidationError) as caught:
            build_evidence_ref(valid, "snapshot", start, end)
        assert caught.value.report.issues[0].code == code
    ref = build_evidence_ref(
        valid,
        "snapshot",
        1,
        1,
        include_quote=False,
        include_content_hash=False,
    )
    assert ref.quote is None and ref.content_hash is None


def test_event_audit_reports_all_malformed_creation_material() -> None:
    event = _event(created_at=NOW)
    wrong_owner = _evidence(event_id="other-event")
    entry = _ledger(
        1,
        "narrative_event.created",
        {
            "persona_id": "forged",
            "continuity": event.continuity,
            "event_type": event.event_type,
            "valid_from": event.valid_from,
            "knowledge_from": event.knowledge_from,
            "access_policy": event.access_policy.value,
            "evidence_ids": ["", 1],
            "evidence_refs": "not-a-list",
        },
        aggregate_type="narrative_event",
        aggregate_id=event.event_id,
        created_at="2020-01-01T00:00:00Z",
    )
    report = replay_event_audit(event, [entry], [wrong_owner])
    codes = {issue.code for issue in report.issues}
    assert codes == {
        "EVENT_EVIDENCE_OWNER_MISMATCH",
        "EVENT_LEDGER_PAYLOAD_MISMATCH",
        "EVENT_LEDGER_TIMESTAMP_MISMATCH",
        "EVENT_LEDGER_EVIDENCE_IDS_INVALID",
        "EVENT_LEDGER_EVIDENCE_REFS_INVALID",
        "EVENT_EVIDENCE_SET_LEDGER_MISMATCH",
    }
    assert report.to_dict()["is_valid"] is False


def test_event_audit_rejects_duplicate_and_reordered_evidence() -> None:
    event = _event()
    first = _evidence("first", event_id=event.event_id)
    second = _evidence("second", event_id=event.event_id)
    refs = [
        {
            "evidence_id": "second",
            "snapshot_id": "snapshot",
            "start_line": 1,
            "end_line": 1,
            "content_hash": None,
        },
        {
            "evidence_id": "first",
            "snapshot_id": "snapshot",
            "start_line": 1,
            "end_line": 1,
            "content_hash": None,
        },
    ]
    entry = _ledger(
        1,
        "narrative_event.created",
        {
            "persona_id": event.persona_id,
            "continuity": event.continuity,
            "event_type": event.event_type,
            "valid_from": event.valid_from,
            "knowledge_from": event.knowledge_from,
            "access_policy": event.access_policy.value,
            "evidence_ids": ["first", "first"],
            "evidence_refs": refs,
        },
        aggregate_type="narrative_event",
        aggregate_id=event.event_id,
    )
    codes = {issue.code for issue in replay_event_audit(event, [entry], [first, second]).issues}
    assert "EVENT_LEDGER_EVIDENCE_DUPLICATE" in codes
    assert "EVENT_LEDGER_EVIDENCE_ORDER_INVALID" in codes


def test_event_audit_bulk_surface_fails_closed_when_material_unavailable() -> None:
    event = _event()
    assert validate_event_audits(object(), []) == {}  # type: ignore[arg-type]
    report = validate_event_audits(object(), [event])[event.event_id]  # type: ignore[arg-type]
    assert {issue.code for issue in report.issues} == {"EVENT_AUDIT_DATA_UNAVAILABLE"}
    grouped = replay_event_audits(
        [event],
        [_ledger(1, "unrelated", aggregate_id=event.event_id)],
        [_evidence(event_id=None)],
    )
    assert not grouped[event.event_id].is_valid


def test_claim_authority_surfaces_missing_and_corrupt_governance_material() -> None:
    claim = _claim(status=GovernanceStatus.REJECTED)
    alien = _decision(
        claim_id="other",
        to_status=GovernanceStatus.AUTHORIZED,
        reviewer="",
        reason="",
    )
    orphan = _ledger(
        2,
        "claim.governance_decided",
        {"decision_id": "orphan"},
        aggregate_id=claim.claim_id,
    )
    missing_id = _ledger(
        3,
        "claim.governance_decided",
        {},
        aggregate_id=claim.claim_id,
    )
    early_evidence = _ledger(
        4,
        "claim.evidence_added",
        {"evidence_id": "duplicate"},
        aggregate_id=claim.claim_id,
    )
    duplicate_evidence = _ledger(
        5,
        "claim.evidence_added",
        {"evidence_id": "duplicate"},
        aggregate_id=claim.claim_id,
    )
    report = replay_claim_authority(
        claim,
        [alien],
        [orphan, missing_id, early_evidence, duplicate_evidence],
        ["duplicate", "duplicate", ""],
    )
    codes = {issue.code for issue in report.issues}
    assert {
        "CLAIM_PROPOSAL_LEDGER_MISMATCH",
        "LEDGER_DECISION_ID_MISSING",
        "DECISION_CLAIM_MISMATCH",
        "DECISION_LEDGER_MISMATCH",
        "ORPHAN_GOVERNANCE_LEDGER_ENTRY",
        "EVIDENCE_LEDGER_ORDER_INVALID",
        "DUPLICATE_EVIDENCE_LEDGER_ID",
        "STORED_EVIDENCE_ID_INVALID",
        "DUPLICATE_STORED_EVIDENCE_ID",
        "EVIDENCE_SET_LEDGER_MISMATCH",
        "CLAIM_STATUS_REPLAY_MISMATCH",
    } <= codes
    assert report.to_dict()["is_valid"] is False


def test_claim_authority_rejects_transition_attribution_and_ledger_order() -> None:
    claim = _claim(status=GovernanceStatus.PROPOSED)
    decision = _decision(
        from_status=GovernanceStatus.AUTHORIZED,
        to_status=GovernanceStatus.PROPOSED,
        reviewer=" ",
        reason=" ",
    )
    report = replay_claim_authority(
        claim,
        [decision],
        [
            _decision_ledger(1, decision),
            _proposal_ledger(2, claim=claim, evidence_ids=["", 1]),
            _ledger(
                2,
                "claim.evidence_added",
                {"evidence_id": ""},
                aggregate_id=claim.claim_id,
            ),
        ],
    )
    codes = {issue.code for issue in report.issues}
    assert {
        "DECISION_CHAIN_BROKEN",
        "DECISION_TRANSITION_INVALID",
        "DECISION_ATTRIBUTION_MISSING",
        "CLAIM_PROPOSAL_LEDGER_ORDER_INVALID",
        "PROPOSAL_EVIDENCE_LEDGER_INVALID",
        "EVIDENCE_LEDGER_ID_MISSING",
        "EVIDENCE_LEDGER_ORDER_INVALID",
    } <= codes


def test_claim_authority_validation_adapters_fail_closed_without_storage() -> None:
    claim = _claim()
    single = validate_claim_authority(object(), claim)  # type: ignore[arg-type]
    bulk = validate_claim_authorities(object(), [claim])[claim.claim_id]  # type: ignore[arg-type]
    assert {issue.code for issue in single.issues} == {"AUTHORITY_DATA_UNAVAILABLE"}
    assert {issue.code for issue in bulk.issues} == {"AUTHORITY_DATA_UNAVAILABLE"}


def test_report_metadata_and_report_models_reject_unsafe_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value, code in (
        (None, "REPORT_METADATA_INVALID"),
        ("", "REPORT_METADATA_INVALID"),
        ("\ud800", "REPORT_METADATA_INVALID_UNICODE"),
        ("\x1bunsafe", "REPORT_METADATA_CONTROL_CHARACTER"),
        ("safe\u202eunsafe", "REPORT_METADATA_CONTROL_CHARACTER"),
    ):
        with pytest.raises(InspectionIntegrityError) as caught:
            inspection_module._validate_report_metadata("field", value)
        assert caught.value.code == code
    with pytest.raises(InspectionLimitError) as caught:
        inspection_module._validate_report_metadata("field", "x" * 1025)
    assert caught.value.code == "REPORT_METADATA_BYTES_LIMIT_EXCEEDED"
    with pytest.raises(InspectionIntegrityError) as caught:
        inspection_module._validate_snapshot_digest("digest", "x" * 64)
    assert caught.value.code == "SNAPSHOT_CONTENT_HASH_INVALID"

    impact = _impact()
    with pytest.raises(ValueError, match="aggregate_type"):
        AffectedEvidence("other", "id", "evidence", "persona", None, impact)
    with pytest.raises(ValueError, match="governance_status"):
        AffectedEvidence("claim", "id", "evidence", "persona", None, impact)
    with pytest.raises(ValueError, match="do not have"):
        AffectedEvidence("event", "id", "evidence", "persona", "AUTHORIZED", impact)

    affected = AffectedEvidence(
        "claim", "claim", "evidence", "persona", "AUTHORIZED", impact
    )
    report = SourceImpactReport(
        source_id="source",
        source_key="story",
        continuity="alpha",
        from_snapshot_id="old",
        from_version=1,
        from_snapshot_sha256="A" * 64,
        to_snapshot_id="target",
        to_version=2,
        to_snapshot_sha256="B" * 64,
        affected=(affected,),
    )
    assert report.from_snapshot_sha256 == "a" * 64
    assert report.claim_count == 1 and report.event_count == 0
    assert report.outcome_counts[ImpactOutcome.SAME_POSITION.value] == 1
    assert report.to_dict()["summary"]["affected_evidence"] == 1
    assert report.to_json()

    base = dict(
        source_id="source",
        source_key="story",
        continuity="alpha",
        from_snapshot_id="old",
        from_version=1,
        from_snapshot_sha256="a" * 64,
        to_snapshot_id="target",
        to_version=2,
        to_snapshot_sha256="b" * 64,
        affected=(affected,),
    )
    with pytest.raises(ValueError, match="from_version"):
        SourceImpactReport(**{**base, "to_version": 1})
    with pytest.raises(ValueError, match="report-only"):
        SourceImpactReport(**{**base, "report_only": False})
    monkeypatch.setattr(inspection_module, "MAX_AFFECTED_EVIDENCE", 0)
    with pytest.raises(InspectionLimitError) as caught:
        SourceImpactReport(**base)
    assert caught.value.code == "AFFECTED_EVIDENCE_LIMIT_EXCEEDED"
    monkeypatch.setattr(inspection_module, "MAX_AFFECTED_EVIDENCE", 10)
    monkeypatch.setattr(inspection_module, "MAX_REPORT_CANDIDATES", 0)
    with pytest.raises(InspectionLimitError) as caught:
        SourceImpactReport(**base)
    assert caught.value.code == "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED"


def test_inspection_snapshot_integrity_enforces_each_resource_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_snapshot_integrity(_snapshot(content=object()))
    assert caught.value.code == "SNAPSHOT_CONTENT_MISSING"
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_snapshot_integrity(
            _snapshot(content="\ud800", content_hash="0" * 64)
        )
    assert caught.value.code == "SNAPSHOT_CONTENT_INVALID_UNICODE"

    monkeypatch.setattr(
        inspection_module,
        "DEFAULT_INGEST_LIMITS",
        SimpleNamespace(max_file_bytes=1, max_lines=10, max_line_bytes=10),
    )
    with pytest.raises(InspectionLimitError) as caught:
        InspectionService._validate_snapshot_integrity(_snapshot(content="two"))
    assert caught.value.code == "SNAPSHOT_BYTES_LIMIT_EXCEEDED"

    monkeypatch.setattr(
        inspection_module,
        "DEFAULT_INGEST_LIMITS",
        SimpleNamespace(max_file_bytes=100, max_lines=1, max_line_bytes=100),
    )
    with pytest.raises(InspectionLimitError) as caught:
        InspectionService._validate_snapshot_integrity(
            _snapshot(content="one\ntwo", line_count=2)
        )
    assert caught.value.code == "SNAPSHOT_LINES_LIMIT_EXCEEDED"

    monkeypatch.setattr(
        inspection_module,
        "DEFAULT_INGEST_LIMITS",
        SimpleNamespace(max_file_bytes=100, max_lines=10, max_line_bytes=1),
    )
    with pytest.raises(InspectionLimitError) as caught:
        InspectionService._validate_snapshot_integrity(_snapshot(content="two"))
    assert caught.value.code == "SNAPSHOT_LINE_BYTES_LIMIT_EXCEEDED"

    monkeypatch.setattr(
        inspection_module,
        "DEFAULT_INGEST_LIMITS",
        SimpleNamespace(max_file_bytes=100, max_lines=10, max_line_bytes=100),
    )
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_snapshot_integrity(
            _snapshot(content="one", line_count=2)
        )
    assert caught.value.code == "SNAPSHOT_LINE_COUNT_MISMATCH"
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_snapshot_integrity(
            _snapshot(content="one", content_hash="0" * 64)
        )
    assert caught.value.code == "SNAPSHOT_CONTENT_HASH_MISMATCH"
    digest, lines = InspectionService._validate_snapshot_integrity(
        _snapshot(content="one")
    )
    assert digest == sha256(b"one").hexdigest() and lines == ("one",)


def test_inspection_provenance_authority_and_event_audit_fail_closed() -> None:
    snapshot = _snapshot()
    claim = _claim()
    evidence = _evidence(claim_id=claim.claim_id)
    record = ProvenanceRecord(
        snapshot.snapshot_id, "claim", claim.claim_id, claim, evidence
    )
    bad_metadata = ProvenanceRecord(
        snapshot.snapshot_id,
        "claim",
        claim.claim_id,
        claim,
        _evidence(None, claim_id=claim.claim_id),
    )
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_provenance_metadata(bad_metadata)
    assert caught.value.code == "REPORT_METADATA_INVALID"

    inconsistent = ProvenanceRecord(
        snapshot.snapshot_id,
        "claim",
        claim.claim_id,
        _claim(text="different"),
        _evidence("other-evidence", claim_id=claim.claim_id),
    )
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_claim_authority(
            (record, inconsistent), ClaimAuthorityMaterial((), (), ())
        )
    assert caught.value.code == "CLAIM_AUTHORITY_MATERIAL_INCONSISTENT"

    out_of_scope = ClaimAuthorityMaterial(
        (), (_ledger(1, "other", aggregate_id="other"),), ()
    )
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_claim_authority((record,), out_of_scope)
    assert caught.value.code == "CLAIM_AUTHORITY_SCOPE_MISMATCH"
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_claim_authority(
            (record,), ClaimAuthorityMaterial((), (), ())
        )
    assert caught.value.code == "CLAIM_AUTHORITY_INVALID"

    event = _event()
    event_record = ProvenanceRecord(
        snapshot.snapshot_id,
        "event",
        event.event_id,
        event,
        _evidence("event-evidence", event_id=event.event_id),
    )
    inconsistent_event = ProvenanceRecord(
        snapshot.snapshot_id,
        "event",
        event.event_id,
        _event(title="different"),
        _evidence("event-evidence-2", event_id=event.event_id),
    )
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_event_audit(
            (event_record, inconsistent_event), EventAuditMaterial((), ())
        )
    assert caught.value.code == "EVENT_AUDIT_INVALID"
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_event_audit(
            (event_record,), EventAuditMaterial((), (_evidence(event_id=None),))
        )
    assert caught.value.code == "EVENT_AUDIT_INVALID"
    with pytest.raises(InspectionIntegrityError) as caught:
        InspectionService._validate_event_audit(
            (event_record,), EventAuditMaterial((), ())
        )
    assert caught.value.code == "EVENT_AUDIT_INVALID"


def test_inspection_anchor_rejects_drift_and_derives_legacy_fields() -> None:
    snapshot = _snapshot(content="anchor\nsecond", line_count=2)
    claim = _claim()

    def record(evidence: EvidenceRef, *, continuity: str = "alpha") -> ProvenanceRecord:
        aggregate = _claim(continuity=continuity)
        return ProvenanceRecord(
            snapshot.snapshot_id,
            "claim",
            aggregate.claim_id,
            aggregate,
            evidence,
        )

    with pytest.raises(EvidenceValidationError, match="continuity"):
        InspectionService._validated_anchor(
            object(),
            record(_evidence(claim_id=claim.claim_id), continuity="beta"),
            snapshot,
            ("anchor", "second"),
        )
    with pytest.raises(EvidenceValidationError, match="line range"):
        InspectionService._validated_anchor(
            object(),
            record(_evidence(claim_id=claim.claim_id, end_line=3)),
            snapshot,
            ("anchor", "second"),
        )
    with pytest.raises(EvidenceValidationError, match="quote"):
        InspectionService._validated_anchor(
            object(),
            record(_evidence(claim_id=claim.claim_id, quote="wrong")),
            snapshot,
            ("anchor", "second"),
        )
    with pytest.raises(EvidenceValidationError, match="digest is invalid"):
        InspectionService._validated_anchor(
            object(),
            record(_evidence(claim_id=claim.claim_id, content_hash=7)),
            snapshot,
            ("anchor", "second"),
        )
    with pytest.raises(EvidenceValidationError, match="digest does not match"):
        InspectionService._validated_anchor(
            object(),
            record(_evidence(claim_id=claim.claim_id, content_hash="0" * 64)),
            snapshot,
            ("anchor", "second"),
        )

    derived = InspectionService._validated_anchor(
        object(),
        record(_evidence(claim_id=claim.claim_id, quote=None, content_hash=None)),
        snapshot,
        ("anchor", "second"),
    )
    assert derived.quote == "anchor"
    assert derived.content_hash == quote_sha256("anchor")
    normalized = InspectionService._validated_anchor(
        object(),
        record(
            _evidence(
                claim_id=claim.claim_id,
                content_hash=f"SHA256:{quote_sha256('anchor').upper()}",
            )
        ),
        snapshot,
        ("anchor", "second"),
    )
    assert normalized.content_hash == quote_sha256("anchor")


def test_inspection_service_rejects_bad_repository_and_version_arguments(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="ReadOnlyProject"):
        InspectionService(object())  # type: ignore[arg-type]
    database = tmp_path / "inspection-arguments.db"
    ids = _seed_read_project(database)
    with ReadOnlyProject.open(database) as project:
        service = InspectionService(project)
        invalid_calls = (
            lambda: service.source_impact(continuity="alpha"),
            lambda: service.source_impact(
                ids["source"], source_key="story", continuity="alpha"
            ),
            lambda: service.source_impact(ids["source"], continuity=""),
            lambda: service.source_impact(
                ids["source"],
                continuity="alpha",
                to_version=2,
                target_version=3,
            ),
            lambda: service.source_impact(
                ids["source"], continuity="alpha", to_version=True
            ),
            lambda: service.source_impact(
                ids["source"], continuity="alpha", from_version=True, to_version=2
            ),
            lambda: service.source_impact(
                ids["source"], continuity="alpha", from_version=2, to_version=2
            ),
        )
        for call in invalid_calls:
            with pytest.raises((TypeError, ValueError)):
                call()


class _LedgerOnlyStorage:
    def __init__(self, verdict: Any = True, *, raises: Exception | None = None):
        self.verdict = verdict
        self.raises = raises

    def verify_ledger(self) -> Any:
        if self.raises is not None:
            raise self.raises
        return self.verdict


def test_compiler_fails_closed_before_reading_untrusted_aggregates() -> None:
    compiler = MemoryCompiler(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="persona_id"):
        compiler.compile(MemoryCutoff(" ", "alpha", NOW))
    with pytest.raises(ValueError, match="continuity"):
        compiler.compile(MemoryCutoff("persona", " ", NOW))
    with pytest.raises(LedgerIntegrityError, match="cannot verify"):
        compiler.compile(MemoryCutoff("persona", "alpha", NOW))

    for verdict in (False, (False, ["broken"]), SimpleNamespace(is_valid=False)):
        with pytest.raises(LedgerIntegrityError, match="verification failed"):
            MemoryCompiler(_LedgerOnlyStorage(verdict)).compile(  # type: ignore[arg-type]
                MemoryCutoff("persona", "alpha", NOW)
            )

    entered: list[str] = []

    class Transactional(_LedgerOnlyStorage):
        @contextmanager
        def read_transaction(self):
            entered.append("entered")
            yield self

    with pytest.raises(LedgerIntegrityError):
        MemoryCompiler(Transactional(False)).compile(  # type: ignore[arg-type]
            MemoryCutoff("persona", "alpha", NOW)
        )
    assert entered == ["entered"]


def test_compiler_claim_guards_emit_stable_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outsider = _claim(
        "outsider", status=GovernanceStatus.AUTHORIZED, persona_id="other"
    )
    unauthorized = _claim("unauthorized", status=GovernanceStatus.PROPOSED)
    invalid_evidence = _claim("invalid-evidence", status=GovernanceStatus.AUTHORIZED)

    class StorageSurface:
        def verify_ledger(self) -> bool:
            return True

        def list_claim_proposals(self, **_: Any) -> list[ClaimProposal]:
            return [outsider, unauthorized, invalid_evidence]

        def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]:
            return []

    valid_authority = SimpleNamespace(is_authorized=True, to_dict=lambda: {})
    monkeypatch.setattr(compiler_module, "validate_source_audits", lambda storage: {})
    monkeypatch.setattr(
        compiler_module,
        "validate_claim_authorities",
        lambda storage, claims: {item.claim_id: valid_authority for item in claims},
    )
    pack = MemoryCompiler(StorageSurface()).compile(  # type: ignore[arg-type]
        MemoryCutoff("persona", "alpha", NOW)
    )
    diagnostics = {item["aggregate_id"]: item["code"] for item in pack["diagnostics"]}
    assert diagnostics == {
        "outsider": "ISOLATION_GUARD",
        "unauthorized": "UNAUTHORIZED_CLAIM",
        "invalid-evidence": "EVIDENCE_INVALID",
    }


def test_compiler_rejects_invalid_authority_and_missing_source_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_authority = _claim("bad-authority", status=GovernanceStatus.AUTHORIZED)
    missing_source = _claim("missing-source", status=GovernanceStatus.AUTHORIZED)
    ref = _evidence("source-evidence", snapshot_id="snapshot", claim_id="missing-source")

    class StorageSurface:
        def verify_ledger(self) -> bool:
            return True

        def list_claim_proposals(self, **_: Any) -> list[ClaimProposal]:
            return [bad_authority, missing_source]

        def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]:
            return [] if claim_id == "bad-authority" else [ref]

        def get_snapshot(self, snapshot_id: str) -> SourceSnapshot:
            return _snapshot(snapshot_id)

    invalid_authority = SimpleNamespace(
        is_authorized=False, to_dict=lambda: {"is_authorized": False}
    )
    valid_authority = SimpleNamespace(is_authorized=True, to_dict=lambda: {})
    monkeypatch.setattr(compiler_module, "validate_source_audits", lambda storage: {})
    monkeypatch.setattr(
        compiler_module,
        "validate_claim_authorities",
        lambda storage, claims: {
            "bad-authority": invalid_authority,
            "missing-source": valid_authority,
        },
    )
    pack = MemoryCompiler(StorageSurface()).compile(  # type: ignore[arg-type]
        MemoryCutoff("persona", "alpha", NOW)
    )
    diagnostics = {item["aggregate_id"]: item["code"] for item in pack["diagnostics"]}
    assert diagnostics == {
        "bad-authority": "AUTHORITY_CHAIN_INVALID",
        "missing-source": "SOURCE_AUDIT_INVALID",
    }


def test_compiler_event_guards_skip_filtered_and_fail_closed_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        _event("outsider", persona_id="other"),
        _event("hidden", access_policy=AccessPolicy.HIDDEN),
        _event("future", knowledge_from="2100-01-01T00:00:00Z"),
        _event("bad-audit"),
        _event("missing-evidence"),
    ]

    class StorageSurface:
        def list_narrative_events(self, **_: Any) -> list[NarrativeEvent]:
            return events

        def get_event_evidence(self, event_id: str) -> list[EvidenceRef]:
            raise AttributeError("legacy storage")

    valid = SimpleNamespace(is_valid=True, to_dict=lambda: {})
    invalid = SimpleNamespace(is_valid=False, to_dict=lambda: {"is_valid": False})
    monkeypatch.setattr(
        compiler_module,
        "validate_event_audits",
        lambda storage, items: {
            item.event_id: invalid if item.event_id == "bad-audit" else valid
            for item in items
        },
    )
    compiler = MemoryCompiler(StorageSurface())  # type: ignore[arg-type]
    diagnostics: list[CompilationDiagnostic] = []
    result = compiler._compile_events(
        MemoryCutoff("persona", "alpha", NOW),
        {AccessPolicy.AGENT_ACCESSIBLE},
        diagnostics,
        {},
    )
    assert result == []
    assert {(item.aggregate_id, item.code) for item in diagnostics} == {
        ("bad-audit", "EVENT_AUDIT_INVALID"),
        ("missing-evidence", "EVIDENCE_INVALID"),
    }


def test_compiler_event_source_audit_is_required_before_evidence_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _event("event-source-audit")
    ref = _evidence("event-ref", event_id=event.event_id)

    class StorageSurface:
        def list_narrative_events(self, **_: Any) -> list[NarrativeEvent]:
            return [event]

        def get_event_evidence(self, event_id: str) -> list[EvidenceRef]:
            return [ref]

        def get_snapshot(self, snapshot_id: str) -> SourceSnapshot:
            return _snapshot(snapshot_id)

    valid = SimpleNamespace(is_valid=True, to_dict=lambda: {})
    monkeypatch.setattr(
        compiler_module,
        "validate_event_audits",
        lambda storage, items: {event.event_id: valid},
    )
    diagnostics: list[CompilationDiagnostic] = []
    result = MemoryCompiler(StorageSurface())._compile_events(  # type: ignore[arg-type]
        MemoryCutoff("persona", "alpha", NOW),
        {AccessPolicy.AGENT_ACCESSIBLE},
        diagnostics,
        {},
    )
    assert result == []
    assert [(item.aggregate_id, item.code) for item in diagnostics] == [
        (event.event_id, "SOURCE_AUDIT_INVALID")
    ]


class _ClaimValidationStorage:
    def list_governance_decisions(self, **_: Any) -> list[Any]:
        raise NotImplementedError

    def get_claim_evidence(self, claim_id: str) -> list[Any]:
        return []


def test_project_validator_claim_and_event_surfaces_report_missing_material() -> None:
    invalid_claim = _claim(
        valid_from="2026-01-02T00:00:00Z",
        valid_to="2026-01-01T00:00:00Z",
    )
    validator = ProjectValidator(_ClaimValidationStorage())  # type: ignore[arg-type]
    warnings = validator._validate_claims([invalid_claim], strict_proposals=False)
    errors = validator._validate_claims([invalid_claim], strict_proposals=True)
    assert "AUTHORITY_DATA_UNAVAILABLE" in {item.code for item in warnings}
    assert "INVALID_TEMPORAL_INTERVAL" in {item.code for item in warnings}
    assert next(item for item in warnings if item.code == "EVIDENCE_REQUIRED").severity is Severity.WARNING
    assert next(item for item in errors if item.code == "EVIDENCE_REQUIRED").severity is Severity.ERROR
    rejected = _claim(status=GovernanceStatus.REJECTED)
    rejected_issues = validator._validate_claims([rejected], strict_proposals=True)
    assert "EVIDENCE_REQUIRED" not in {item.code for item in rejected_issues}

    class EventStorage:
        def list_narrative_events(self) -> list[NarrativeEvent]:
            return [
                _event(
                    valid_from="2026-01-02T00:00:00Z",
                    valid_to="2026-01-01T00:00:00Z",
                )
            ]

    event_issues = ProjectValidator(EventStorage())._validate_events()  # type: ignore[arg-type]
    event_codes = {item.code for item in event_issues}
    assert "EVENT_AUDIT_DATA_UNAVAILABLE" in event_codes
    assert "INVALID_TEMPORAL_INTERVAL" in event_codes
    assert "EVIDENCE_REQUIRED" in event_codes

    assert ProjectValidator(object())._validate_events() == []  # type: ignore[arg-type]
    assert ProjectValidator(object())._validate_snapshots() == []  # type: ignore[arg-type]


def test_project_validator_snapshot_and_ledger_fail_closed_branches() -> None:
    source = Source("source", "story", "alpha", NOW, NOW)
    malformed = _snapshot(
        content="tampered",
        continuity="beta",
        version=2,
        content_hash="0" * 64,
        previous_snapshot_id="wrong",
    )

    class SnapshotStorage:
        def list_sources(self) -> list[Source]:
            return [source]

        def list_snapshots(self, source_id: str) -> list[SourceSnapshot]:
            return [malformed]

    issues = ProjectValidator(SnapshotStorage())._validate_snapshots()  # type: ignore[arg-type]
    codes = {item.code for item in issues}
    assert {
        "SOURCE_AUDIT_DATA_UNAVAILABLE",
        "SNAPSHOT_HASH_MISMATCH",
        "SNAPSHOT_VERSION_GAP",
        "SNAPSHOT_CHAIN_BROKEN",
        "SOURCE_CONTINUITY_MISMATCH",
    } <= codes

    verdicts = (
        _LedgerOnlyStorage(raises=RuntimeError("broken")),
        _LedgerOnlyStorage(False),
        _LedgerOnlyStorage((False, ["broken"])),
        _LedgerOnlyStorage(SimpleNamespace(is_valid=False)),
    )
    for storage in verdicts:
        ledger_issues = ProjectValidator(storage)._validate_ledger()  # type: ignore[arg-type]
        assert [item.code for item in ledger_issues] == ["EVENT_LEDGER_INVALID"]
    assert ProjectValidator(_LedgerOnlyStorage(True))._validate_ledger() == []  # type: ignore[arg-type]

    report = ProjectValidationReport(
        [
            ProjectIssue("error", Severity.ERROR, "error"),
            ProjectIssue("warning", Severity.WARNING, "warning"),
        ]
    )
    assert not report.is_valid and report.error_count == 1 and report.warning_count == 1
    assert '"error_count": 1' in report.to_json()


def test_compiler_invalid_source_audit_preserves_deterministic_details() -> None:
    class SnapshotStorage:
        def get_snapshot(self, snapshot_id: str) -> SourceSnapshot:
            return _snapshot(snapshot_id)

    compiler = MemoryCompiler(SnapshotStorage())  # type: ignore[arg-type]
    ref = _evidence(snapshot_id="snapshot")
    missing = compiler._invalid_source_audit([ref], {})
    assert missing is not None and missing.source_id == "source" and not missing.is_valid
    invalid = SourceAuditReport(
        "source",
        1,
        1,
        0,
        (SourceAuditIssue("MISSING", "missing snapshot ledger"),),
    )
    assert compiler._invalid_source_audit([ref], {"source": invalid}) is invalid
    valid = SourceAuditReport("source", 1, 1, 1)
    assert compiler._invalid_source_audit([ref], {"source": valid}) is None
