from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from hashlib import sha256

import pytest

import continuityforge.migrations as migrations
from continuityforge.exceptions import MigrationError
from continuityforge.migrations import preflight_migration
from continuityforge.storage import Storage


def _create_v01(database: Path, project_root: Path) -> None:
    connection = sqlite3.connect(database)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
def test_migration_backup_is_owner_read_write_only(tmp_path, project_root):
    database = tmp_path / "private.db"
    _create_v01(database, project_root)
    database.chmod(0o600)

    with Storage(database) as storage:
        report = storage.migration_report

    assert report is not None and report.succeeded
    backup = Path(report.backup_path)
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_existing_backup_is_preserved_and_numbered(tmp_path, project_root):
    database = tmp_path / "project.db"
    _create_v01(database, project_root)
    existing = tmp_path / "project.db.pre-v3.bak"
    existing.write_bytes(b"operator-owned previous backup")

    with Storage(database) as storage:
        report = storage.migration_report

    assert report is not None and report.succeeded
    assert existing.read_bytes() == b"operator-owned previous backup"
    assert Path(report.backup_path).name == "project.db.pre-v3.2.bak"
    assert not list(tmp_path.glob(".project.db.pre-v3-*.tmp"))


def test_symbolic_link_backup_target_fails_closed(tmp_path, project_root):
    database = tmp_path / "linked.db"
    _create_v01(database, project_root)
    destination = tmp_path / "redirected.db"
    link = tmp_path / "linked.db.pre-v3.bak"
    try:
        link.symlink_to(destination)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are not available for this test account")

    with pytest.raises(MigrationError) as caught:
        Storage(database)

    assert "MIGRATION_BACKUP_VERIFICATION_FAILED" in {
        issue.code for issue in caught.value.report.issues
    }
    assert link.is_symlink()
    assert not destination.exists()
    assert not list(tmp_path.glob(".linked.db.pre-v3-*.tmp"))


def test_replaced_temporary_backup_never_overwrites_the_replacement(
    tmp_path, project_root, monkeypatch
):
    database = tmp_path / "source.db"
    victim = tmp_path / "victim.db"
    _create_v01(database, project_root)
    with closing(sqlite3.connect(victim)) as connection:
        connection.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sentinel VALUES ('preserve me')")
        connection.commit()

    original_connect = sqlite3.connect
    replacement: Path | None = None

    def replacing_connect(target, *args, **kwargs):
        nonlocal replacement
        candidate = Path(str(target))
        if (
            replacement is None
            and candidate.parent == tmp_path
            and candidate.name.startswith(".source.db.pre-v3-")
            and candidate.name.endswith(".tmp")
        ):
            candidate.unlink()
            try:
                os.link(victim, candidate)
            except OSError:
                pytest.skip("hard links are not available on this filesystem")
            replacement = candidate
        return original_connect(target, *args, **kwargs)

    with closing(original_connect(database)) as source:
        monkeypatch.setattr(migrations.sqlite3, "connect", replacing_connect)
        report = preflight_migration(source, create_backup=True)

    assert not report.is_ready
    assert "MIGRATION_BACKUP_VERIFICATION_FAILED" in {
        issue.code for issue in report.issues
    }
    assert replacement is not None and replacement.exists()
    assert not list(tmp_path.glob("source.db.pre-v3*.bak"))
    with closing(original_connect(victim)) as connection:
        assert connection.execute("SELECT value FROM sentinel").fetchone() == (
            "preserve me",
        )


def test_backup_is_logically_bound_to_the_open_migration_source(
    tmp_path, project_root, monkeypatch
):
    database = tmp_path / "source-a.db"
    replacement = tmp_path / "source-b.db"
    _create_v01(database, project_root)
    _create_v01(replacement, project_root)
    replacement_content = "different source contents"
    with closing(sqlite3.connect(replacement)) as connection:
        connection.execute(
            "UPDATE source_snapshots SET content = ?, sha256 = ?",
            (
                replacement_content,
                sha256(replacement_content.encode("utf-8")).hexdigest(),
            ),
        )
        connection.commit()

    original_open_readonly = migrations._open_readonly
    redirected = False

    def redirect_first_source_open(path: Path):
        nonlocal redirected
        if not redirected and Path(path).resolve() == database.resolve():
            redirected = True
            return original_open_readonly(replacement)
        return original_open_readonly(path)

    with closing(sqlite3.connect(database, isolation_level=None)) as source:
        source.execute("BEGIN IMMEDIATE")
        monkeypatch.setattr(
            migrations,
            "_open_readonly",
            redirect_first_source_open,
        )
        report = preflight_migration(source, create_backup=True)
        source.execute("ROLLBACK")

    assert redirected
    assert not report.is_ready
    assert "MIGRATION_BACKUP_VERIFICATION_FAILED" in {
        issue.code for issue in report.issues
    }
    assert not list(tmp_path.glob("source-a.db.pre-v3*.bak"))
    assert not list(tmp_path.glob(".source-a.db.pre-v3-*.tmp"))


def test_direct_preflight_does_not_create_a_missing_wal_shm_sidecar(tmp_path):
    source = tmp_path / "live.db"
    with Storage(source):
        pass
    writer = sqlite3.connect(source, isolation_level=None)
    try:
        writer.execute("PRAGMA journal_mode = WAL")
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "UPDATE schema_metadata SET migration_notes = ? WHERE singleton = 1",
            ("sidecar_probe",),
        )
        writer.execute("COMMIT")
        source_wal = source.with_name(source.name + "-wal")
        assert source_wal.exists()

        copied = tmp_path / "copied.db"
        copied_wal = copied.with_name(copied.name + "-wal")
        copied_shm = copied.with_name(copied.name + "-shm")
        shutil.copyfile(source, copied)
        shutil.copyfile(source_wal, copied_wal)
        assert not copied_shm.exists()

        with pytest.raises(MigrationError, match="-shm"):
            preflight_migration(copied, create_backup=False)
        assert not copied_shm.exists()
    finally:
        writer.close()
