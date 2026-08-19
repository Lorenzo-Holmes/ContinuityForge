from __future__ import annotations

from hashlib import sha256

import pytest

from continuityforge.impact import analyze_evidence_impact
from continuityforge.impact_models import (
    ImpactClassification,
    ImpactOutcome,
    ImpactReasonCode,
)


FROZEN_IMPACT_OUTCOMES = (
    "SAME_POSITION",
    "EXACT_MOVED_UNIQUE",
    "EXACT_MOVED_AMBIGUOUS",
    "NO_EXACT_MATCH",
    "INVALID_EVIDENCE",
)


def _evidence(quote: str, *, start_line: int, end_line: int) -> dict[str, object]:
    return {
        "snapshot_id": "snapshot-v1",
        "start_line": start_line,
        "end_line": end_line,
        "quote": quote,
        "content_hash": sha256(quote.encode("utf-8")).hexdigest(),
    }


def _target(content: str) -> dict[str, object]:
    return {
        "snapshot_id": "snapshot-v2",
        "version": 2,
        "content": content,
    }


def test_impact_outcome_contract_has_exactly_five_members() -> None:
    assert tuple(item.name for item in ImpactOutcome) == FROZEN_IMPACT_OUTCOMES
    assert tuple(item.value for item in ImpactOutcome) == FROZEN_IMPACT_OUTCOMES
    assert len(ImpactOutcome.__members__) == 5
    assert ImpactClassification is ImpactOutcome


@pytest.mark.parametrize(
    ("change", "evidence", "target"),
    (
        (
            "edit",
            _evidence("alpha beta", start_line=1, end_line=1),
            _target("alpha BETA"),
        ),
        (
            "delete",
            _evidence("alpha beta", start_line=1, end_line=1),
            _target(""),
        ),
        (
            "split-line",
            _evidence("alpha beta", start_line=1, end_line=1),
            _target("alpha\nbeta"),
        ),
        (
            "merge-lines",
            _evidence("alpha\nbeta", start_line=1, end_line=2),
            _target("alpha beta"),
        ),
    ),
)
def test_non_exact_edit_delete_split_and_merge_are_only_no_exact_match(
    change: str,
    evidence: dict[str, object],
    target: dict[str, object],
) -> None:
    report = analyze_evidence_impact(evidence, target)

    assert change
    assert report.outcome is ImpactOutcome.NO_EXACT_MATCH
    assert report.classification is ImpactOutcome.NO_EXACT_MATCH
    assert report.reason_code is ImpactReasonCode.EXACT_QUOTE_NOT_FOUND
    assert report.candidates == ()
    assert report.error_code is None
