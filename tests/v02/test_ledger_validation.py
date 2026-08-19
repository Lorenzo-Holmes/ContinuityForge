from __future__ import annotations

import sqlite3

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_content
from continuityforge.models import ClaimProposal
from continuityforge.validate import ProjectValidator


def test_event_ledger_is_append_only_and_verifiable(storage):
    _, snapshot, _ = ingest_content(storage, "Supported.\n", "story", "alpha")
    ClaimGovernance(storage).add_authorized_human_claim(
        ClaimProposal(
            persona_id="mira", continuity="alpha", text="Supported."
        ),
        [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)],
    )
    entries = storage.list_ledger_entries()
    assert len(entries) >= 4
    assert storage.verify_ledger()

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        storage.connection.execute(
            "UPDATE event_ledger SET payload_json = '{}' WHERE sequence = 1"
        )
    assert storage.verify_ledger()

    # A database owner can intentionally remove SQLite triggers; verification
    # still detects that out-of-band tampering cryptographically.
    storage.connection.execute("DROP TRIGGER continuityforge_ledger_no_update")
    storage.connection.execute(
        "UPDATE event_ledger SET payload_json = '{}' WHERE sequence = 1"
    )
    assert storage.verify_ledger() is False


def test_project_validator_reports_proposed_missing_evidence_as_warning(storage):
    ClaimGovernance(storage).propose(
        ClaimProposal(
            persona_id="mira", continuity="alpha", text="Needs a citation."
        ),
        [],
    )
    report = ProjectValidator(storage).validate()
    assert report.is_valid
    assert report.warning_count == 1
    assert report.issues[0].code == "EVIDENCE_REQUIRED"

    strict = ProjectValidator(storage).validate(strict_proposals=True)
    assert not strict.is_valid
    assert strict.error_count == 1
