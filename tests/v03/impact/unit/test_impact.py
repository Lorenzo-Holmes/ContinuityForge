from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError
from enum import IntEnum

import pytest

import continuityforge.impact as impact_module
from continuityforge.evidence import quote_sha256
from continuityforge.impact import (
    ImpactEngine,
    analyze_evidence_impact,
    analyze_impact,
    analyze_validated_evidence_batch,
    classify_evidence_impact,
    prepare_impact_target,
)
from continuityforge.impact_models import (
    ImpactCandidate,
    ImpactClassification,
    ImpactErrorCode,
    ImpactOutcome,
    ImpactReasonCode,
    ImpactReport,
    ImpactTargetError,
)
from continuityforge.models import EvidenceRef, SourceSnapshot


class _IntSubclass(int):
    pass


class _IntEnumeration(IntEnum):
    ONE = 1
    TWO = 2


def _snapshot(
    content: str,
    *,
    snapshot_id: str = "snapshot-v2",
    version: int = 2,
) -> SourceSnapshot:
    return SourceSnapshot(
        snapshot_id=snapshot_id,
        source_id="source-1",
        source_key="story",
        continuity="alpha",
        version=version,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        content=content,
    )


def _evidence(
    quote: object = "remember me",
    *,
    start_line: object = 2,
    end_line: object = 2,
    snapshot_id: object = "snapshot-v1",
    content_hash: object = None,
) -> EvidenceRef:
    # Runtime validation is intentionally owned by the impact engine; type
    # ignores let malformed legacy values exercise INVALID_EVIDENCE.
    return EvidenceRef(
        snapshot_id=snapshot_id,  # type: ignore[arg-type]
        start_line=start_line,  # type: ignore[arg-type]
        end_line=end_line,  # type: ignore[arg-type]
        quote=quote,  # type: ignore[arg-type]
        content_hash=content_hash,  # type: ignore[arg-type]
    )


def test_same_position_preserves_identity_version_span_and_reason() -> None:
    report = analyze_evidence_impact(
        _evidence("remember me", start_line=2, end_line=2),
        _snapshot("before\nremember me\nafter\n"),
    )

    assert report.outcome is ImpactOutcome.SAME_POSITION
    assert report.classification is ImpactClassification.SAME_POSITION
    assert report.old_snapshot_id == "snapshot-v1"
    assert report.evidence_snapshot_id == "snapshot-v1"
    assert report.target_snapshot_id == "snapshot-v2"
    assert report.target_snapshot_version == 2
    assert report.original_span == (2, 2)
    assert report.candidate_spans == ((2, 2),)
    assert report.reason_code == ImpactReasonCode.EXACT_AT_ORIGINAL_SPAN.value
    assert report.error_code is None


def test_same_position_wins_when_exact_text_is_duplicated_elsewhere() -> None:
    report = analyze_evidence_impact(
        _evidence("same", start_line=2, end_line=2),
        _snapshot("same\nsame\nother"),
    )

    assert report.outcome is ImpactOutcome.SAME_POSITION
    assert report.candidate_spans == ((1, 1), (2, 2))


def test_exact_moved_unique() -> None:
    report = analyze_evidence_impact(
        _evidence("kept", start_line=1, end_line=1),
        _snapshot("inserted\nkept\ntrailer"),
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_UNIQUE
    assert report.candidate_spans == ((2, 2),)
    assert report.reason_code == ImpactReasonCode.EXACT_AT_ONE_DIFFERENT_SPAN.value


def test_exact_moved_ambiguous_candidates_have_stable_source_order() -> None:
    report = analyze_evidence_impact(
        _evidence("repeat", start_line=9, end_line=9),
        _snapshot("repeat\nx\nrepeat\ny\nrepeat"),
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_AMBIGUOUS
    assert report.candidate_spans == ((1, 1), (3, 3), (5, 5))
    assert report.reason_code == (
        ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS.value
    )


def test_overlapping_multiline_matches_are_all_reported_stably() -> None:
    report = analyze_evidence_impact(
        _evidence("A\nA", start_line=8, end_line=9),
        _snapshot("A\nA\nA"),
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_AMBIGUOUS
    assert report.candidate_spans == ((1, 2), (2, 3))


def test_multiline_quote_and_crlf_lf_are_canonicalized() -> None:
    quote = "alpha\r\nbeta"
    report = analyze_evidence_impact(
        _evidence(
            quote,
            start_line=1,
            end_line=2,
            content_hash="SHA256:" + quote_sha256(quote).upper(),
        ),
        _snapshot("intro\r\nalpha\r\nbeta\r\noutro\r\n"),
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_UNIQUE
    assert report.candidate_spans == ((2, 3),)


def test_exact_matching_does_not_normalize_semantic_whitespace() -> None:
    report = analyze_evidence_impact(
        _evidence("two spaces  here", start_line=1, end_line=1),
        _snapshot("two spaces here"),
    )

    assert report.outcome is ImpactOutcome.NO_EXACT_MATCH
    assert report.candidates == ()
    assert report.reason_code == ImpactReasonCode.EXACT_QUOTE_NOT_FOUND.value


def test_blank_line_is_a_valid_one_line_quote() -> None:
    report = analyze_evidence_impact(
        _evidence("", start_line=1, end_line=1, content_hash=quote_sha256("")),
        _snapshot("heading\n\ntrailer"),
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_UNIQUE
    assert report.candidate_spans == ((2, 2),)


@pytest.mark.parametrize(
    ("evidence", "error_code"),
    [
        (None, ImpactErrorCode.EVIDENCE_REQUIRED),
        (
            _evidence("text", snapshot_id=""),
            ImpactErrorCode.SNAPSHOT_ID_REQUIRED,
        ),
        (
            _evidence("text", start_line=True, end_line=1),
            ImpactErrorCode.INVALID_LINE_RANGE,
        ),
        (
            _evidence("text", start_line=0, end_line=1),
            ImpactErrorCode.INVALID_LINE_RANGE,
        ),
        (
            _evidence(None, start_line=1, end_line=1),
            ImpactErrorCode.QUOTE_REQUIRED,
        ),
        (
            _evidence(["not", "text"], start_line=1, end_line=2),
            ImpactErrorCode.INVALID_QUOTE,
        ),
        (
            _evidence("bad\ud800", start_line=1, end_line=1),
            ImpactErrorCode.INVALID_UNICODE_QUOTE,
        ),
        (
            _evidence("one line", start_line=1, end_line=2),
            ImpactErrorCode.QUOTE_SPAN_MISMATCH,
        ),
        (
            _evidence("text", start_line=1, end_line=1, content_hash="nope"),
            ImpactErrorCode.INVALID_CONTENT_HASH,
        ),
        (
            _evidence(
                "text",
                start_line=1,
                end_line=1,
                content_hash="0" * 64,
            ),
            ImpactErrorCode.CONTENT_HASH_MISMATCH,
        ),
    ],
)
def test_invalid_old_evidence_returns_stable_frozen_report(
    evidence: object, error_code: ImpactErrorCode
) -> None:
    report = analyze_evidence_impact(evidence, _snapshot("text"))

    assert report.outcome is ImpactOutcome.INVALID_EVIDENCE
    assert report.reason_code == ImpactReasonCode.EVIDENCE_FAILED_VALIDATION.value
    assert report.error_code == error_code.value
    assert report.candidates == ()
    assert report.is_valid_evidence is False
    with pytest.raises(FrozenInstanceError):
        report.reason = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("bad_line", [True, _IntSubclass(1), _IntEnumeration.ONE])
def test_evidence_coordinates_require_exact_builtin_int(bad_line: object) -> None:
    report = analyze_evidence_impact(
        _evidence("text", start_line=bad_line, end_line=1),
        _snapshot("text"),
    )

    assert report.outcome is ImpactOutcome.INVALID_EVIDENCE
    assert report.error_code is ImpactErrorCode.INVALID_LINE_RANGE


@pytest.mark.parametrize("bad_version", [True, _IntSubclass(2), _IntEnumeration.TWO])
def test_target_version_requires_exact_builtin_int(bad_version: object) -> None:
    target = {"snapshot_id": "target", "version": bad_version, "content": "text"}
    with pytest.raises(ImpactTargetError) as caught:
        analyze_evidence_impact(
            _evidence("text", start_line=1, end_line=1),
            target,
        )
    assert caught.value.code == "TARGET_SNAPSHOT_VERSION_INVALID"


@pytest.mark.parametrize("bad_line", [True, _IntSubclass(1), _IntEnumeration.ONE])
def test_candidate_coordinates_require_exact_builtin_int(bad_line: object) -> None:
    with pytest.raises(TypeError):
        ImpactCandidate(bad_line, 1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("target", "code"),
    [
        (None, "TARGET_SNAPSHOT_REQUIRED"),
        (
            {"snapshot_id": "", "version": 2, "content": "text"},
            "TARGET_SNAPSHOT_ID_REQUIRED",
        ),
        (
            {"snapshot_id": "target", "content": "text"},
            "TARGET_SNAPSHOT_VERSION_INVALID",
        ),
        (
            {"snapshot_id": "target", "version": 2, "content": None},
            "TARGET_SNAPSHOT_CONTENT_MISSING",
        ),
        (
            {"snapshot_id": "target", "version": 2, "content": "bad\ud800"},
            "TARGET_SNAPSHOT_CONTENT_INVALID_UNICODE",
        ),
    ],
)
def test_missing_or_invalid_target_is_a_caller_error(
    target: object, code: str
) -> None:
    with pytest.raises(ImpactTargetError) as caught:
        analyze_evidence_impact(_evidence("text", start_line=1, end_line=1), target)
    assert caught.value.code == code
    assert isinstance(caught.value, ValueError)


def test_report_model_normalizes_candidate_order_and_serializes() -> None:
    report = ImpactReport(
        outcome=ImpactOutcome.EXACT_MOVED_AMBIGUOUS,
        old_snapshot_id="old",
        target_snapshot_id="new",
        target_snapshot_version=3,
        original_start_line=8,
        original_end_line=8,
        candidates=(ImpactCandidate(5, 5), ImpactCandidate(1, 1)),
        reason_code=ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS.value,
        reason="stable",
    )

    assert report.candidate_spans == ((1, 1), (5, 5))
    assert isinstance(report.candidates, tuple)
    assert report.to_dict() == {
        "outcome": "EXACT_MOVED_AMBIGUOUS",
        "classification": "EXACT_MOVED_AMBIGUOUS",
        "old_snapshot_id": "old",
        "target_snapshot_id": "new",
        "target_snapshot_version": 3,
        "original_span": {"start_line": 8, "end_line": 8},
        "candidates": [
            {"start_line": 1, "end_line": 1},
            {"start_line": 5, "end_line": 5},
        ],
        "reason_code": "EXACT_AT_MULTIPLE_DIFFERENT_SPANS",
        "reason": "stable",
        "error_code": None,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "outcome": ImpactOutcome.SAME_POSITION,
            "candidates": (ImpactCandidate(2, 2),),
            "reason_code": ImpactReasonCode.EXACT_AT_ORIGINAL_SPAN,
        },
        {
            "outcome": ImpactOutcome.EXACT_MOVED_UNIQUE,
            "candidates": (ImpactCandidate(1, 1), ImpactCandidate(3, 3)),
            "reason_code": ImpactReasonCode.EXACT_AT_ONE_DIFFERENT_SPAN,
        },
        {
            "outcome": ImpactOutcome.EXACT_MOVED_AMBIGUOUS,
            "candidates": (ImpactCandidate(1, 1), ImpactCandidate(4, 4)),
            "reason_code": ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS,
        },
        {
            "outcome": ImpactOutcome.NO_EXACT_MATCH,
            "candidates": (ImpactCandidate(1, 1),),
            "reason_code": ImpactReasonCode.EXACT_QUOTE_NOT_FOUND,
        },
        {
            "outcome": ImpactOutcome.EXACT_MOVED_UNIQUE,
            "candidates": (ImpactCandidate(1, 1),),
            "reason_code": ImpactReasonCode.EXACT_QUOTE_NOT_FOUND,
        },
        {
            "outcome": ImpactOutcome.EXACT_MOVED_AMBIGUOUS,
            "candidates": (ImpactCandidate(1, 1), ImpactCandidate(1, 1)),
            "reason_code": ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS,
        },
    ],
)
def test_report_model_rejects_semantically_inconsistent_construction(
    overrides: dict[str, object]
) -> None:
    values: dict[str, object] = {
        "outcome": ImpactOutcome.EXACT_MOVED_UNIQUE,
        "old_snapshot_id": "old",
        "target_snapshot_id": "new",
        "target_snapshot_version": 2,
        "original_start_line": 4,
        "original_end_line": 4,
        "candidates": (ImpactCandidate(1, 1),),
        "reason_code": ImpactReasonCode.EXACT_AT_ONE_DIFFERENT_SPAN,
        "reason": "stable",
    }
    values.update(overrides)
    with pytest.raises(ValueError):
        ImpactReport(**values)  # type: ignore[arg-type]


def test_engine_and_function_aliases_share_one_deterministic_path() -> None:
    evidence = _evidence("moved", start_line=9, end_line=9)
    target = _snapshot("before\nmoved")
    expected = analyze_evidence_impact(evidence, target)

    assert ImpactEngine.analyze(evidence, target) == expected
    assert ImpactEngine().classify(evidence, target) == expected
    assert classify_evidence_impact(evidence, target) == expected
    assert analyze_impact(evidence, target) == expected


def test_validated_batch_matches_single_analysis_for_overlapping_patterns() -> None:
    target = _snapshot("A\nA\nA\nB\nA\nB")
    prepared = prepare_impact_target(target)
    evidence = (
        _evidence("A\nA", start_line=8, end_line=9),
        _evidence("A\nB", start_line=4, end_line=5),
        _evidence("A", start_line=1, end_line=1),
        _evidence("missing", start_line=3, end_line=3),
    )
    batch = analyze_validated_evidence_batch(
        evidence, prepared, max_total_candidates=100
    )
    singles = tuple(ImpactEngine.analyze_prepared(item, prepared) for item in evidence)
    assert batch == singles


def test_validated_batch_counts_duplicate_anchor_candidates_toward_report_limit() -> None:
    prepared = prepare_impact_target(_snapshot("same"))
    evidence = (
        _evidence("same", start_line=2, end_line=2),
        _evidence("same", start_line=3, end_line=3),
    )
    with pytest.raises(ImpactTargetError) as caught:
        analyze_validated_evidence_batch(
            evidence, prepared, max_total_candidates=1
        )
    assert caught.value.code == "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED"


def test_validated_batch_fails_before_building_an_unbounded_pattern_trie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(impact_module, "MAX_BATCH_PATTERN_LINES", 1)
    prepared = prepare_impact_target(_snapshot("one\ntwo"))
    with pytest.raises(ImpactTargetError) as caught:
        analyze_validated_evidence_batch(
            (
                _evidence("one", start_line=1, end_line=1),
                _evidence("two", start_line=2, end_line=2),
            ),
            prepared,
            max_total_candidates=10,
        )
    assert caught.value.code == "IMPACT_PATTERN_LINES_LIMIT_EXCEEDED"


def test_mapping_inputs_retain_old_and_target_identity() -> None:
    report = analyze_evidence_impact(
        {
            "snapshot_id": "legacy-v1",
            "start_line": 4,
            "end_line": 4,
            "quote": "fact",
            "content_hash": quote_sha256("fact"),
        },
        {"snapshot_id": "legacy-v4", "version": 4, "content": "fact"},
    )

    assert report.outcome is ImpactOutcome.EXACT_MOVED_UNIQUE
    assert report.old_snapshot_id == "legacy-v1"
    assert report.target_snapshot_id == "legacy-v4"
    assert report.target_version == 4
    assert report.original_span == (4, 4)
    assert report.candidate_spans == ((1, 1),)
