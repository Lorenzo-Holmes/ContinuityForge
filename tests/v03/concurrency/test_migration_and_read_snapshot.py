from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import sqlite3
import threading

from continuityforge.compiler import MemoryCompiler
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import MigrationError
from continuityforge.models import ClaimProposal, EvidenceRef, GovernanceStatus, MemoryCutoff
from continuityforge.readonly import ReadOnlyProject
from continuityforge.schema import SchemaKind, classify_schema
from continuityforge.storage import Storage


def _create_v01(database: Path, project_root: Path) -> None:
    connection = sqlite3.connect(database)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.close()


def test_two_migrators_never_commit_competing_schema_changes(
    tmp_path: Path, project_root: Path
) -> None:
    database = tmp_path / "race.db"
    _create_v01(database, project_root)
    barrier = threading.Barrier(2)

    def open_storage() -> str:
        barrier.wait(timeout=5)
        try:
            with Storage(database) as storage:
                assert storage.migration_report is not None
                return storage.migration_report.status
        except MigrationError:
            # A process that fingerprinted v0.1 just before the winner's
            # commit must fail and retry rather than migrate a changed input.
            return "changed-before-lock"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: open_storage(), range(2)))

    connection = sqlite3.connect(database)
    try:
        assert classify_schema(connection) is SchemaKind.V03
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()
    assert "migrated" in outcomes
    assert set(outcomes) <= {"migrated", "already-current", "changed-before-lock"}
    # Lock serialization also prevents both processes from selecting the same
    # backup name before either has created it.
    backups = list(tmp_path.glob("race.db.pre-v3*.bak"))
    assert len(backups) == 1


def test_read_snapshot_rolls_back_after_exception_and_sees_next_wal_commit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "snapshot.db"
    with Storage(database) as storage:
        source, first, _ = storage.ingest_snapshot("story", "alpha", "one")

    writer = sqlite3.connect(database, isolation_level=None)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("PRAGMA wal_autocheckpoint = 0")
    with ReadOnlyProject.open(database) as project:
        try:
            with project.read_transaction():
                assert project.get_latest_snapshot(source.source_id).version == 1
                content = "two"
                writer.execute("BEGIN IMMEDIATE")
                writer.execute(
                    "INSERT INTO source_snapshots "
                    "(snapshot_id, source_id, version, content_hash, content, media_type, "
                    "origin_path, previous_snapshot_id, line_count, created_at) "
                    "VALUES ('snp_after_error', ?, 2, ?, ?, 'text/plain', NULL, ?, 1, ?)",
                    (
                        source.source_id,
                        sha256(content.encode()).hexdigest(),
                        content,
                        first.snapshot_id,
                        "2026-08-19T00:00:00Z",
                    ),
                )
                writer.execute("COMMIT")
                # This read remains pinned even though a WAL commit exists.
                assert project.get_latest_snapshot(source.source_id).version == 1
                raise RuntimeError("injected inspection failure")
        except RuntimeError:
            pass

        # The failed outer block rolled back; the repository is immediately
        # reusable and the next transaction observes the committed revision.
        assert not project.connection.in_transaction
        assert project.get_latest_snapshot(source.source_id).version == 2
    writer.close()


def test_compiler_pins_authority_and_evidence_to_one_wal_snapshot(tmp_path: Path) -> None:
    database = tmp_path / "compile-snapshot.db"
    with Storage(database) as setup:
        _, snapshot, _ = setup.ingest_snapshot("story", "alpha", "first\nsecond")
        first = build_evidence_ref(setup, snapshot.snapshot_id, 1, 1)
        claim = setup.create_claim_proposal(
            ClaimProposal(
                claim_id="claim",
                persona_id="mira",
                continuity="alpha",
                text="first",
            ),
            (first,),
        )
        setup.record_governance_decision(
            claim.claim_id,
            GovernanceStatus.AUTHORIZED,
            reviewer="editor",
            reason="verified",
        )
        snapshot_id = snapshot.snapshot_id

    mode = sqlite3.connect(database)
    mode.execute("PRAGMA journal_mode = WAL")
    mode.close()
    reader = Storage(database)
    writer = Storage(database)
    authority_loaded = threading.Event()
    writer_done = threading.Event()
    original_bulk_evidence = reader.list_all_claim_evidence

    def hooked_bulk_evidence():
        items = original_bulk_evidence()
        authority_loaded.set()
        assert writer_done.wait(5)
        return items

    reader.list_all_claim_evidence = hooked_bulk_evidence  # type: ignore[method-assign]
    result: dict[str, object] = {}

    def compile_pack() -> None:
        result["pack"] = MemoryCompiler(reader).compile(
            MemoryCutoff("mira", "alpha", "2026-08-20T00:00:00Z")
        )

    worker = threading.Thread(target=compile_pack)
    worker.start()
    assert authority_loaded.wait(5)
    writer.record_governance_decision(
        "claim",
        GovernanceStatus.DISPUTED,
        reviewer="editor",
        reason="new evidence requires review",
    )
    writer.add_claim_evidence(
        "claim", EvidenceRef(snapshot_id=snapshot_id, start_line=2, end_line=2)
    )
    writer_done.set()
    worker.join(5)
    assert not worker.is_alive()

    pack = result["pack"]
    assert isinstance(pack, dict)
    assert len(pack["claims"]) == 1
    assert [item["source_span"]["start_line"] for item in pack["claims"][0]["provenance"]] == [1]
    assert writer.get_claim_proposal("claim").status is GovernanceStatus.DISPUTED
    assert len(writer.get_claim_evidence("claim")) == 2
    reader.close()
    writer.close()
