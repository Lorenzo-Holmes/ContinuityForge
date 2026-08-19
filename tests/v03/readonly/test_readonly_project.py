from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import NotFoundError, ReadOnlyStorageError, SchemaError
from continuityforge.models import ClaimProposal
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _create_project(path: Path) -> tuple[str, str, str]:
    with Storage(path) as storage:
        source, snapshot, _ = storage.ingest_snapshot(
            "story", "alpha", "one\ntwo"
        )
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        claim = storage.create_claim_proposal(
            ClaimProposal(persona_id="p", continuity="alpha", text="one"),
            (evidence,),
        )
    return source.source_id, snapshot.snapshot_id, claim.claim_id


def test_open_reads_models_and_sqlite_rejects_every_write(tmp_path: Path) -> None:
    database = tmp_path / "project.db"
    source_id, snapshot_id, claim_id = _create_project(database)
    before = _digest(database)
    sidecars_before = {
        suffix: (database.parent / f"{database.name}{suffix}").exists()
        for suffix in ("-wal", "-shm")
    }

    with ReadOnlyProject.open(database) as project:
        assert project.connection.execute("PRAGMA query_only").fetchone()[0] == 1
        assert project.get_source(source_id).continuity == "alpha"
        assert project.get_snapshot(snapshot_id).content == "one\ntwo"
        assert project.get_claim(claim_id).text == "one"
        assert project.get_claim_evidence(claim_id)[0].snapshot_id == snapshot_id
        records = project.list_provenance(snapshot_id)
        assert [(item.aggregate_type, item.aggregate_id) for item in records] == [
            ("claim", claim_id)
        ]
        with pytest.raises(sqlite3.OperationalError, match="readonly|read-only"):
            project.connection.execute("CREATE TABLE forbidden(value TEXT)")

    assert _digest(database) == before
    assert {
        suffix: (database.parent / f"{database.name}{suffix}").exists()
        for suffix in ("-wal", "-shm")
    } == sidecars_before


def test_missing_and_unknown_databases_fail_closed_without_creation(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing" / "project.db"
    with pytest.raises(NotFoundError):
        ReadOnlyProject.open(missing)
    assert not missing.exists()
    assert not missing.parent.exists()

    unknown = tmp_path / "unknown.db"
    connection = sqlite3.connect(unknown)
    connection.execute("CREATE TABLE unrelated(value TEXT)")
    connection.commit()
    connection.close()
    before = _digest(unknown)
    with pytest.raises(SchemaError, match="unknown"):
        ReadOnlyProject.open(unknown)
    assert _digest(unknown) == before


def test_read_only_open_sees_committed_rows_in_existing_wal(tmp_path: Path) -> None:
    """The repository participates in WAL instead of taking a stale immutable view."""

    database = tmp_path / "live.db"
    source_id, _, _ = _create_project(database)
    writer = sqlite3.connect(database, isolation_level=None)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("PRAGMA wal_autocheckpoint = 0")
    latest = writer.execute(
        "SELECT snapshot_id, version FROM source_snapshots "
        "WHERE source_id = ? ORDER BY version DESC LIMIT 1",
        (source_id,),
    ).fetchone()
    assert latest is not None
    snapshot_id = "snp_live_committed"
    content = "committed through wal"
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO source_snapshots "
        "(snapshot_id, source_id, version, content_hash, content, media_type, "
        "origin_path, previous_snapshot_id, line_count, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'text/plain', NULL, ?, 1, ?)",
        (
            snapshot_id,
            source_id,
            int(latest[1]) + 1,
            sha256(content.encode()).hexdigest(),
            content,
            str(latest[0]),
            "2026-08-19T00:00:00Z",
        ),
    )
    writer.execute("COMMIT")
    assert database.with_name(database.name + "-wal").exists()

    with ReadOnlyProject.open(database) as project:
        assert project.get_snapshot(snapshot_id).content == content

    writer.close()


def test_wal_without_shm_fails_before_sqlite_can_create_a_sidecar(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    _create_project(source)
    writer = sqlite3.connect(source, isolation_level=None)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("PRAGMA wal_autocheckpoint = 0")
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("UPDATE sources SET updated_at = updated_at")
    writer.execute("COMMIT")
    source_wal = source.with_name(source.name + "-wal")
    assert source_wal.exists()

    copied = tmp_path / "copied.db"
    shutil.copyfile(source, copied)
    shutil.copyfile(source_wal, copied.with_name(copied.name + "-wal"))
    copied_shm = copied.with_name(copied.name + "-shm")
    assert not copied_shm.exists()
    with pytest.raises(ReadOnlyStorageError, match="-shm"):
        ReadOnlyProject.open(copied)
    assert not copied_shm.exists()
    writer.close()


def test_batch_provenance_uses_constant_number_of_set_queries(tmp_path: Path) -> None:
    database = tmp_path / "batch.db"
    with Storage(database) as storage:
        _, first, _ = storage.ingest_snapshot("story", "alpha", "first")
        _, second, _ = storage.ingest_snapshot("story", "alpha", "second")
        for index, snapshot in enumerate((first, second)):
            evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
            storage.create_claim_proposal(
                ClaimProposal(
                    claim_id=f"claim_{index}",
                    persona_id="p",
                    continuity="alpha",
                    text=f"claim {index}",
                ),
                (evidence,),
            )

    with ReadOnlyProject.open(database) as project:
        statements: list[str] = []
        project.connection.set_trace_callback(statements.append)
        grouped = project.get_provenance_for_snapshots(
            (first.snapshot_id, second.snapshot_id)
        )
        project.connection.set_trace_callback(None)
        assert all(len(records) == 1 for records in grouped.values())
        selects = [sql for sql in statements if sql.lstrip().upper().startswith("SELECT")]
        # One claim query plus one event query, independent of aggregate count.
        assert len(selects) == 2
