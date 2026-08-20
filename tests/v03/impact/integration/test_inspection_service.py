from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import sqlite3

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import ContinuityViolation
from continuityforge.impact_models import ImpactOutcome
from continuityforge.inspection import InspectionService
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


def _impact_fixture(database: Path) -> tuple[str, str]:
    old_content = "same\nunique\nambiguous\ngone"
    target_content = "same\npadding\nunique\nambiguous\npadding2\nambiguous"
    with Storage(database) as storage:
        source, old, _ = storage.ingest_snapshot("story", "alpha", old_content)
        for line, claim_id in ((1, "claim_same"), (2, "claim_unique")):
            evidence = build_evidence_ref(storage, old.snapshot_id, line, line)
            storage.create_claim_proposal(
                ClaimProposal(
                    claim_id=claim_id,
                    persona_id="persona",
                    continuity="alpha",
                    text=f"SECRET CLAIM BODY {line}",
                ),
                (evidence,),
            )
        for line, event_id in ((3, "event_ambiguous"), (4, "event_gone")):
            evidence = build_evidence_ref(storage, old.snapshot_id, line, line)
            storage.create_narrative_event(
                NarrativeEvent(
                    event_id=event_id,
                    persona_id="persona",
                    continuity="alpha",
                    title=f"SECRET EVENT TITLE {line}",
                    summary=f"SECRET EVENT SUMMARY {line}",
                ),
                (evidence,),
            )
        storage.ingest_snapshot("story", "alpha", target_content)
    return source.source_id, old.snapshot_id


def test_source_impact_covers_claims_events_and_four_exact_outcomes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "impact.db"
    source_id, _ = _impact_fixture(database)

    with ReadOnlyProject.open(database) as project:
        report = InspectionService(project).source_impact(
            source_id, continuity="alpha", from_version=1, to_version=2
        )
        assert report.report_only is True
        assert report.to_dict()["schema"] == "continuityforge.source-impact/v0.3-alpha"
        assert len(report.from_snapshot_sha256) == 64
        assert len(report.to_snapshot_sha256) == 64
        assert report.claim_count == 2
        assert report.event_count == 2
        assert report.affected_count == 4
        outcomes = {item.aggregate_id: item.outcome for item in report.affected}
        assert outcomes == {
            "claim_same": ImpactOutcome.SAME_POSITION,
            "claim_unique": ImpactOutcome.EXACT_MOVED_UNIQUE,
            "event_ambiguous": ImpactOutcome.EXACT_MOVED_AMBIGUOUS,
            "event_gone": ImpactOutcome.NO_EXACT_MATCH,
        }
        # The report is deterministic JSON and intentionally omits all source,
        # quote, claim-body, event-title, and event-summary text.
        encoded = report.to_json()
        assert json.loads(encoded) == report.to_dict()
        assert '"quote"' not in encoded
        assert '"content"' not in encoded
        for secret in (
            "SECRET CLAIM BODY",
            "SECRET EVENT TITLE",
            "SECRET EVENT SUMMARY",
        ):
            assert secret not in encoded

        # target_version is an alias and from_version defaults to predecessor.
        defaulted = InspectionService(project).source_impact(
            source_key="story", continuity="alpha", target_version=2
        )
        assert defaulted.to_dict() == report.to_dict()

        statements: list[str] = []
        project.connection.set_trace_callback(statements.append)
        InspectionService(project).source_impact(
            source_id, continuity="alpha", from_version=1, to_version=2
        )
        project.connection.set_trace_callback(None)
        reads = [
            sql
            for sql in statements
            if sql.lstrip().upper().startswith(("SELECT", "WITH"))
        ]
        # Endpoint bodies, metadata-only lineage, bounded provenance counts,
        # global ledger verification, claim authority, and event audit replay
        # all use a fixed query plan.  Aggregate/evidence count never creates
        # N+1 reads.
        # Source identity/revision audit adds one bounded stats read plus the
        # two complete, content-free material reads to the fixed query plan.
        assert len(reads) == 20
        assert len([sql for sql in reads if sql.startswith("SELECT ss.*")]) == 1
        assert (
            len(
                [
                    sql
                    for sql in reads
                    if sql.lstrip().upper().startswith("WITH AFFECTED(EVENT_ID)")
                ]
            )
            == 3
        )


def test_source_impact_rejects_cross_source_and_cross_continuity(
    tmp_path: Path,
) -> None:
    database = tmp_path / "lineage.db"
    with Storage(database) as storage:
        alpha, _, _ = storage.ingest_snapshot("story", "alpha", "a1")
        storage.ingest_snapshot("story", "alpha", "a2")
        storage.ingest_snapshot("story", "beta", "b1")
        storage.ingest_snapshot("story", "beta", "b2")

    with ReadOnlyProject.open(database) as project:
        service = InspectionService(project)
        with pytest.raises(ContinuityViolation, match="continuity"):
            service.source_impact(
                alpha.source_id,
                continuity="beta",
                from_version=1,
                to_version=2,
            )
        # A key shared by multiple worldlines still resolves only with the
        # explicit continuity and never merges the two logical Sources.
        report = service.source_impact(
            source_key="story",
            continuity="beta",
            from_version=1,
            to_version=2,
        )
        assert report.continuity == "beta"
        assert report.source_id != alpha.source_id


def test_source_impact_pins_one_read_snapshot_and_repository_is_reusable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "concurrent.db"
    with Storage(database) as storage:
        source, first, _ = storage.ingest_snapshot("story", "alpha", "one")
        _, second, _ = storage.ingest_snapshot("story", "alpha", "two")

    writer = sqlite3.connect(database, isolation_level=None)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("PRAGMA wal_autocheckpoint = 0")
    content = "three"
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO source_snapshots "
        "(snapshot_id, source_id, version, content_hash, content, media_type, "
        "origin_path, previous_snapshot_id, line_count, created_at) "
        "VALUES ('snp_concurrent', ?, 3, ?, ?, 'text/plain', NULL, ?, 1, ?)",
        (
            source.source_id,
            sha256(content.encode()).hexdigest(),
            content,
            second.snapshot_id,
            "2026-08-19T00:00:00Z",
        ),
    )

    class CommitAfterSourceRead(ReadOnlyProject):
        writer_connection: sqlite3.Connection | None = None

        def get_source(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            result = super().get_source(*args, **kwargs)
            if self.writer_connection is not None:
                self.writer_connection.execute("COMMIT")
                self.writer_connection = None
            return result

    CommitAfterSourceRead.writer_connection = writer
    with CommitAfterSourceRead.open(database) as project:
        report = InspectionService(project).source_impact(
            source.source_id, continuity="alpha"
        )
        # The commit occurs after get_source's SELECT.  Every later SELECT in
        # this inspection remains on that same snapshot instead of mixing v3.
        assert report.from_version == 1
        assert report.to_version == 2
        # The transaction was rolled back on exit, so the next independent
        # read sees the newly committed revision.
        assert project.get_latest_snapshot(source.source_id).version == 3

    writer.close()
