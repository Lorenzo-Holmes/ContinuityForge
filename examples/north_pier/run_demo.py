"""Build and verify the original North Pier source-impact demo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_path
from continuityforge.inspection import InspectionService
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


SOURCE_KEY = "north-pier-field-log"
CONTINUITY = "alpha"
PERSONA = "mira"
DATABASE_NAME = "north-pier-demo.db"
REPORT_NAME = "north-pier-impact-report.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify the deterministic North Pier impact demo."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("north-pier-output"),
        help="directory for the SQLite database and JSON impact report",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="replace this demo's existing database/report artifacts",
    )
    return parser


def _prepare_output(output_dir: Path, *, reset: bool) -> tuple[Path, Path]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    database = output_dir / DATABASE_NAME
    report = output_dir / REPORT_NAME
    artifacts = (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
        report,
    )
    existing = tuple(path for path in artifacts if path.exists())
    if existing and not reset:
        names = ", ".join(path.name for path in existing)
        raise FileExistsError(
            f"demo output already exists ({names}); pass --reset to replace it"
        )
    if reset:
        for path in artifacts:
            path.unlink(missing_ok=True)
    return database, report


def _authorized_claim(
    governance: ClaimGovernance,
    storage: Storage,
    snapshot_id: str,
    *,
    text: str,
    subject: str,
    predicate: str,
    object_value: str,
    start_line: int,
    end_line: int,
) -> ClaimProposal:
    evidence = build_evidence_ref(storage, snapshot_id, start_line, end_line)
    return governance.add_authorized_human_claim(
        ClaimProposal(
            persona_id=PERSONA,
            continuity=CONTINUITY,
            text=text,
            subject=subject,
            predicate=predicate,
            object_value=object_value,
            valid_from="2026-01-01T00:00:00Z",
            knowledge_from="2026-01-01T00:00:00Z",
        ),
        (evidence,),
        reviewer="demo:operator",
        reason="North Pier synthetic fixture evidence verified by operator",
    )


def run_demo(output_dir: Path, *, reset: bool = False) -> Path:
    database, report_path = _prepare_output(output_dir, reset=reset)
    fixture_dir = Path(__file__).resolve().parent

    expected_by_aggregate: dict[tuple[str, str], str] = {}
    with Storage(database) as storage:
        source, snapshot_v1, created_v1 = ingest_path(
            storage,
            fixture_dir / "north_pier_v1.txt",
            SOURCE_KEY,
            CONTINUITY,
        )
        assert created_v1 and snapshot_v1.version == 1

        governance = ClaimGovernance(storage)
        arrival = _authorized_claim(
            governance,
            storage,
            snapshot_v1.snapshot_id,
            text="Mira arrived at North Pier before dawn.",
            subject="mira",
            predicate="arrived_at",
            object_value="north-pier-before-dawn",
            start_line=2,
            end_line=2,
        )
        maintenance = _authorized_claim(
            governance,
            storage,
            snapshot_v1.snapshot_id,
            text="The north hinge requires inspection.",
            subject="north-hinge",
            predicate="maintenance_state",
            object_value="inspection-required",
            start_line=8,
            end_line=8,
        )
        knowledge = _authorized_claim(
            governance,
            storage,
            snapshot_v1.snapshot_id,
            text="Mira left without learning the locker code.",
            subject="mira",
            predicate="locker_code_knowledge",
            object_value="unknown",
            start_line=6,
            end_line=6,
        )
        custody_event = storage.create_narrative_event(
            NarrativeEvent(
                persona_id=PERSONA,
                continuity=CONTINUITY,
                event_type="custody",
                title="Compass registered and secured",
                summary="Rowan logged the compass and sealed it in Locker Seven.",
                details={"fixture": "north-pier", "operator_authored": True},
                valid_from="2026-01-01T18:00:00Z",
                knowledge_from="2026-01-01T18:00:00Z",
            ),
            (
                build_evidence_ref(
                    storage,
                    snapshot_v1.snapshot_id,
                    4,
                    5,
                ),
            ),
        )

        expected_by_aggregate.update(
            {
                ("claim", arrival.claim_id): "SAME_POSITION",
                ("claim", maintenance.claim_id): "EXACT_MOVED_AMBIGUOUS",
                ("claim", knowledge.claim_id): "NO_EXACT_MATCH",
                ("event", custody_event.event_id): "EXACT_MOVED_UNIQUE",
            }
        )

        source_v2, snapshot_v2, created_v2 = ingest_path(
            storage,
            fixture_dir / "north_pier_v2.txt",
            SOURCE_KEY,
            CONTINUITY,
        )
        assert source_v2.source_id == source.source_id
        assert created_v2 and snapshot_v2.version == 2

    with ReadOnlyProject.open(database) as repository:
        report = InspectionService(repository).source_impact(
            source_key=SOURCE_KEY,
            continuity=CONTINUITY,
            from_version=1,
            target_version=2,
        )

    observed = {
        (item.aggregate_type, item.aggregate_id): item.outcome.value
        for item in report.affected
    }
    assert observed == expected_by_aggregate
    assert report.report_only is True
    assert report.affected_count == 4
    assert report.claim_count == 3
    assert report.event_count == 1
    assert report.outcome_counts == {
        "SAME_POSITION": 1,
        "EXACT_MOVED_UNIQUE": 1,
        "EXACT_MOVED_AMBIGUOUS": 1,
        "NO_EXACT_MATCH": 1,
        "INVALID_EVIDENCE": 0,
    }

    report_path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return report_path


def main() -> int:
    args = _parser().parse_args()
    report_path = run_demo(args.output_dir, reset=args.reset)
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
