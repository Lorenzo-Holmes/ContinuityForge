from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

from continuityforge.cli import main
from continuityforge.evidence import build_evidence_ref
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.serialization import json_dumps
from continuityforge.storage import Storage


OLD_CONTENT = "same\nunique\nambiguous\ngone"
TARGET_CONTENT = "same\npadding\nunique\nambiguous\npadding2\nambiguous"


def _fixed_ids(monkeypatch) -> None:
    counters: defaultdict[str, int] = defaultdict(int)

    def next_id(prefix: str) -> str:
        counters[prefix] += 1
        return f"{prefix}_{counters[prefix]:04d}"

    monkeypatch.setattr("continuityforge.storage._new_id", next_id)
    monkeypatch.setattr(
        "continuityforge.storage._now", lambda: "2026-08-20T00:00:00Z"
    )


def _create_fixed_project(database: Path, monkeypatch) -> None:
    _fixed_ids(monkeypatch)
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot(
            "story", "alpha", OLD_CONTENT
        )
        assert source.source_id == "src_0001"
        assert old.snapshot_id == "snp_0001"

        for line, claim_id, evidence_id in (
            (1, "claim-same", "evidence-claim-same"),
            (2, "claim-unique", "evidence-claim-unique"),
        ):
            evidence = replace(
                build_evidence_ref(storage, old.snapshot_id, line, line),
                evidence_id=evidence_id,
            )
            storage.create_claim_proposal(
                ClaimProposal(
                    claim_id=claim_id,
                    persona_id="persona",
                    continuity="alpha",
                    text=f"claim {line}",
                ),
                (evidence,),
            )

        for line, event_id, evidence_id in (
            (3, "event-ambiguous", "evidence-event-ambiguous"),
            (4, "event-gone", "evidence-event-gone"),
        ):
            evidence = replace(
                build_evidence_ref(storage, old.snapshot_id, line, line),
                evidence_id=evidence_id,
            )
            storage.create_narrative_event(
                NarrativeEvent(
                    event_id=event_id,
                    persona_id="persona",
                    continuity="alpha",
                    title=f"event {line}",
                    summary=f"summary {line}",
                ),
                (evidence,),
            )

        _, target, _ = storage.ingest_snapshot(
            "story", "alpha", TARGET_CONTENT
        )
        assert target.snapshot_id == "snp_0002"


def _impact(
    *,
    outcome: str,
    original_line: int,
    candidates: list[tuple[int, int]],
    reason_code: str,
    reason: str,
) -> dict[str, object]:
    return {
        "outcome": outcome,
        "classification": outcome,
        "old_snapshot_id": "snp_0001",
        "target_snapshot_id": "snp_0002",
        "target_snapshot_version": 2,
        "original_span": {
            "start_line": original_line,
            "end_line": original_line,
        },
        "candidates": [
            {"start_line": start, "end_line": end}
            for start, end in candidates
        ],
        "reason_code": reason_code,
        "reason": reason,
        "error_code": None,
    }


def _affected(
    aggregate_type: str,
    aggregate_id: str,
    evidence_id: str,
    impact: dict[str, object],
) -> dict[str, object]:
    return {
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "evidence_id": evidence_id,
        "persona_id": "persona",
        "governance_status": (
            "PROPOSED" if aggregate_type == "claim" else None
        ),
        "impact": impact,
    }


def _golden_report() -> dict[str, object]:
    return {
        "schema": "continuityforge.source-impact/v0.3",
        "report_only": True,
        "source": {
            "source_id": "src_0001",
            "source_key": "story",
            "continuity": "alpha",
        },
        "from_snapshot": {
            "snapshot_id": "snp_0001",
            "version": 1,
            "sha256": sha256(OLD_CONTENT.encode("utf-8")).hexdigest(),
        },
        "to_snapshot": {
            "snapshot_id": "snp_0002",
            "version": 2,
            "sha256": sha256(TARGET_CONTENT.encode("utf-8")).hexdigest(),
        },
        "summary": {
            "affected_evidence": 4,
            "claims": 2,
            "events": 2,
            "outcomes": {
                "SAME_POSITION": 1,
                "EXACT_MOVED_UNIQUE": 1,
                "EXACT_MOVED_AMBIGUOUS": 1,
                "NO_EXACT_MATCH": 1,
                "INVALID_EVIDENCE": 0,
            },
        },
        "affected": [
            _affected(
                "claim",
                "claim-same",
                "evidence-claim-same",
                _impact(
                    outcome="SAME_POSITION",
                    original_line=1,
                    candidates=[(1, 1)],
                    reason_code="EXACT_AT_ORIGINAL_SPAN",
                    reason="exact quote remains at the original line span",
                ),
            ),
            _affected(
                "claim",
                "claim-unique",
                "evidence-claim-unique",
                _impact(
                    outcome="EXACT_MOVED_UNIQUE",
                    original_line=2,
                    candidates=[(3, 3)],
                    reason_code="EXACT_AT_ONE_DIFFERENT_SPAN",
                    reason="exact quote occurs once at a different line span",
                ),
            ),
            _affected(
                "event",
                "event-ambiguous",
                "evidence-event-ambiguous",
                _impact(
                    outcome="EXACT_MOVED_AMBIGUOUS",
                    original_line=3,
                    candidates=[(4, 4), (6, 6)],
                    reason_code="EXACT_AT_MULTIPLE_DIFFERENT_SPANS",
                    reason="exact quote occurs at multiple different line spans",
                ),
            ),
            _affected(
                "event",
                "event-gone",
                "evidence-event-gone",
                _impact(
                    outcome="NO_EXACT_MATCH",
                    original_line=4,
                    candidates=[],
                    reason_code="EXACT_QUOTE_NOT_FOUND",
                    reason="exact quote does not occur in the target snapshot",
                ),
            ),
        ],
    }


def test_source_impact_success_json_and_order_are_golden(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    database = tmp_path / "forge.db"
    _create_fixed_project(database, monkeypatch)

    exit_code = main(
        [
            "--db",
            str(database),
            "source-impact",
            "--source-key",
            "story",
            "--continuity",
            "alpha",
            "--from-version",
            "1",
            "--target-version",
            "2",
        ]
    )

    captured = capsys.readouterr()
    golden = _golden_report()
    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == golden
    assert captured.out == json_dumps(golden) + "\n"
    assert [
        (item["aggregate_type"], item["aggregate_id"], item["evidence_id"])
        for item in golden["affected"]  # type: ignore[index]
    ] == [
        ("claim", "claim-same", "evidence-claim-same"),
        ("claim", "claim-unique", "evidence-claim-unique"),
        ("event", "event-ambiguous", "evidence-event-ambiguous"),
        ("event", "event-gone", "evidence-event-gone"),
    ]


def test_source_impact_error_envelope_and_exit_code_are_golden(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    database = tmp_path / "forge.db"
    _create_fixed_project(database, monkeypatch)

    exit_code = main(
        [
            "--db",
            str(database),
            "source-impact",
            "--source-key",
            "story",
            "--continuity",
            "alpha",
            "--from-version",
            "2",
            "--target-version",
            "2",
        ]
    )

    captured = capsys.readouterr()
    golden = {
        "schema": "continuityforge.error/v0.3",
        "code": "INVALID_ARGUMENT",
        "error": "ValueError",
        "message": "from_version must be earlier than to_version",
    }
    assert exit_code == 3
    assert captured.out == ""
    assert json.loads(captured.err) == golden
    assert captured.err == json_dumps(golden) + "\n"
