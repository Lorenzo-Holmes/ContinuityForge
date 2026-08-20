from __future__ import annotations

from pathlib import Path

import pytest

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import (
    InspectionIntegrityError,
    LedgerIntegrityError,
)
from continuityforge.governance import ClaimGovernance
from continuityforge.inspection import InspectionService
from continuityforge.models import ClaimProposal, MemoryCutoff
from continuityforge.readonly import ReadOnlyProject
from continuityforge.schema import SchemaKind, classify_schema
from continuityforge.storage import Storage
from continuityforge.validate import ProjectValidator


def _authorized_claim_project(database: Path) -> tuple[str, str, str]:
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot(
            "story", "alpha", "attested anchor\nsecond anchor"
        )
        storage.ingest_snapshot(
            "story", "alpha", "attested anchor moved\nsecond anchor"
        )
        evidence = build_evidence_ref(storage, old.snapshot_id, 1, 1)
        claim = ClaimGovernance(storage).add_authorized_human_claim(
            ClaimProposal(
                claim_id="claim-authorized",
                persona_id="persona",
                continuity="alpha",
                text="attested anchor",
            ),
            (evidence,),
            reviewer="reviewer",
            reason="the cited line supports the claim",
        )
        saved_evidence = storage.get_claim_evidence(claim.claim_id)[0]
        assert saved_evidence.evidence_id is not None
        return source.source_id, claim.claim_id, saved_evidence.evidence_id


def _compile(storage: Storage) -> dict[str, object]:
    return MemoryCompiler(storage).compile(
        MemoryCutoff("persona", "alpha", "2100-01-01T00:00:00Z")
    )


def _diagnostic(pack: dict[str, object], aggregate_id: str) -> dict[str, object]:
    return next(
        item
        for item in pack["diagnostics"]  # type: ignore[index]
        if item["aggregate_id"] == aggregate_id
    )


def test_claim_material_break_is_rejected_by_compiler_validator_and_inspection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "claim-corruption.db"
    source_id, claim_id, _ = _authorized_claim_project(database)

    with Storage(database) as storage:
        storage.connection.execute(
            "DROP TRIGGER continuityforge_claims_fields_immutable"
        )
        storage.connection.execute(
            "UPDATE claim_proposals SET text = ? WHERE claim_id = ?",
            ("forged materialized claim", claim_id),
        )
        storage.connection.executescript(
            """
            CREATE TRIGGER continuityforge_claims_fields_immutable
            BEFORE UPDATE ON claim_proposals
            WHEN OLD.claim_id IS NOT NEW.claim_id
              OR OLD.persona_id IS NOT NEW.persona_id
              OR OLD.continuity IS NOT NEW.continuity
              OR OLD.text IS NOT NEW.text
              OR OLD.subject IS NOT NEW.subject
              OR OLD.predicate IS NOT NEW.predicate
              OR OLD.object_value IS NOT NEW.object_value
              OR OLD.valid_from IS NOT NEW.valid_from
              OR OLD.valid_to IS NOT NEW.valid_to
              OR OLD.knowledge_from IS NOT NEW.knowledge_from
              OR OLD.knowledge_to IS NOT NEW.knowledge_to
              OR OLD.access_policy IS NOT NEW.access_policy
              OR OLD.confidence IS NOT NEW.confidence
              OR OLD.proposed_by IS NOT NEW.proposed_by
              OR OLD.proposal_model IS NOT NEW.proposal_model
              OR OLD.rationale IS NOT NEW.rationale
              OR OLD.created_at IS NOT NEW.created_at
            BEGIN
                SELECT RAISE(ABORT, 'ClaimProposal content is immutable');
            END;
            """
        )
        assert classify_schema(storage.connection) is SchemaKind.V03
        assert storage.verify_ledger()

        validation = ProjectValidator(storage).validate()
        assert "CLAIM_PROPOSAL_LEDGER_PAYLOAD_MISMATCH" in {
            issue.code for issue in validation.issues
        }

        pack = _compile(storage)
        assert pack["claims"] == []
        diagnostic = _diagnostic(pack, claim_id)
        assert diagnostic["code"] == "AUTHORITY_CHAIN_INVALID"
        assert "CLAIM_PROPOSAL_LEDGER_PAYLOAD_MISMATCH" in {
            issue["code"]
            for issue in diagnostic["details"]["issues"]  # type: ignore[index]
        }

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )
    assert caught.value.code == "CLAIM_AUTHORITY_INVALID"


def test_evidence_body_break_is_rejected_by_compiler_validator_and_inspection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "evidence-corruption.db"
    source_id, claim_id, evidence_id = _authorized_claim_project(database)

    with Storage(database) as storage:
        storage.connection.execute(
            "DROP TRIGGER continuityforge_evidence_no_update"
        )
        storage.connection.execute(
            "UPDATE evidence_refs SET quote = ? WHERE evidence_id = ?",
            ("forged evidence quote", evidence_id),
        )
        storage.connection.executescript(
            """
            CREATE TRIGGER continuityforge_evidence_no_update
            BEFORE UPDATE ON evidence_refs BEGIN
                SELECT RAISE(ABORT, 'EvidenceRef rows are immutable');
            END;
            """
        )
        assert classify_schema(storage.connection) is SchemaKind.V03
        assert storage.verify_ledger()

        validation = ProjectValidator(storage).validate()
        validation_codes = {issue.code for issue in validation.issues}
        assert "QUOTE_MISMATCH" in validation_codes
        assert "CLAIM_EVIDENCE_SET_MATERIAL_MISMATCH" in validation_codes

        pack = _compile(storage)
        assert pack["claims"] == []
        diagnostic = _diagnostic(pack, claim_id)
        assert diagnostic["code"] == "AUTHORITY_CHAIN_INVALID"
        assert "CLAIM_EVIDENCE_SET_MATERIAL_MISMATCH" in {
            issue["code"]
            for issue in diagnostic["details"]["issues"]  # type: ignore[index]
        }

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionIntegrityError) as caught:
            InspectionService(project).source_impact(
                source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )
    assert caught.value.code == "CLAIM_AUTHORITY_INVALID"


def test_global_ledger_break_is_rejected_by_compiler_validator_and_inspection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "ledger-corruption.db"
    source_id, _, _ = _authorized_claim_project(database)

    with Storage(database) as storage:
        storage.connection.execute(
            "DROP TRIGGER continuityforge_ledger_no_update"
        )
        storage.connection.execute(
            "UPDATE event_ledger SET payload_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
        storage.connection.executescript(
            """
            CREATE TRIGGER continuityforge_ledger_no_update
            BEFORE UPDATE ON event_ledger BEGIN
                SELECT RAISE(ABORT, 'EventLedger is append-only');
            END;
            """
        )
        assert classify_schema(storage.connection) is SchemaKind.V03
        assert not storage.verify_ledger()

        validation = ProjectValidator(storage).validate()
        assert "EVENT_LEDGER_INVALID" in {
            issue.code for issue in validation.issues
        }

        with pytest.raises(LedgerIntegrityError):
            _compile(storage)

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(LedgerIntegrityError):
            InspectionService(project).source_impact(
                source_id,
                continuity="alpha",
                from_version=1,
                to_version=2,
            )
