from __future__ import annotations

import pytest

from continuityforge.evidence import (
    EvidenceValidator,
    build_evidence_ref,
    validate_line_range_types,
)
from continuityforge.exceptions import EvidenceValidationError
from continuityforge.ingest import ingest_content
from continuityforge.models import ClaimProposal


@pytest.mark.parametrize(
    "start_line,end_line",
    [
        (True, 1),
        (False, 1),
        (1, True),
        ("1", 1),
        (1, "1"),
        (1.0, 1),
        (1, 1.0),
        (None, 1),
    ],
)
def test_shared_line_type_gate_rejects_coercible_non_integers(
    start_line, end_line
):
    with pytest.raises(TypeError, match="built-in integers"):
        validate_line_range_types(start_line, end_line)


def test_shared_line_type_gate_returns_exact_integers():
    assert validate_line_range_types(1, 2) == (1, 2)


@pytest.mark.parametrize("bad_coordinate", [True, False, "1", 1.0])
def test_builder_rejects_bad_coordinate_before_returning_evidence(
    storage, bad_coordinate
):
    _, snapshot, _ = ingest_content(storage, "one\ntwo\n", "source", "alpha")

    with pytest.raises(EvidenceValidationError) as caught:
        build_evidence_ref(storage, snapshot.snapshot_id, bad_coordinate, 1)

    report = caught.value.report
    assert not report.is_valid
    assert report.issues[0].code == "INVALID_LINE_RANGE"


@pytest.mark.parametrize("bad_coordinate", [True, False, "1", 1.0])
def test_validator_rejects_bad_coordinate_without_coercion(storage, bad_coordinate):
    _, snapshot, _ = ingest_content(storage, "one\ntwo\n", "source", "alpha")
    claim = ClaimProposal(persona_id="mira", continuity="alpha", text="One")
    evidence = {
        "snapshot_id": snapshot.snapshot_id,
        "start_line": bad_coordinate,
        "end_line": 1,
    }

    report = EvidenceValidator(storage).validate_claim(claim, [evidence])

    assert not report.is_valid
    assert [issue.code for issue in report.issues] == ["INVALID_LINE_RANGE"]
    # Even adversarial values must leave reports safe for CLI JSON output.
    assert '"is_valid": false' in report.to_json()
