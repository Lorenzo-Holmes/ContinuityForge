from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

import continuityforge.sqlite_safety as sqlite_safety
from continuityforge.cli import main
from continuityforge.exceptions import MigrationError, ReadOnlyStorageError
from continuityforge.migrations import preflight_migration
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


def test_lstat_link_mode_is_rejected_without_following_the_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sqlite_safety.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFLNK),
    )
    with pytest.raises(sqlite_safety.SQLiteSidecarError, match="symbolic link"):
        sqlite_safety.validate_readonly_sidecars(Path("project.db"))


def test_lstat_operating_system_error_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(_path: Path) -> None:
        raise PermissionError("injected")

    monkeypatch.setattr(sqlite_safety.os, "lstat", denied)
    with pytest.raises(sqlite_safety.SQLiteSidecarError, match="cannot be inspected"):
        sqlite_safety.validate_readonly_sidecars(Path("project.db"))


def _database(tmp_path: Path) -> Path:
    database = tmp_path / "project.db"
    with Storage(database) as storage:
        storage.ingest_snapshot("story", "alpha", "anchor\n")
    return database


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _unsafe_sidecar(
    database: Path, suffix: str, kind: str
) -> tuple[Path, Path | None]:
    sidecar = database.with_name(database.name + suffix)
    target: Path | None = None
    if kind == "directory":
        sidecar.mkdir()
    else:
        target = database.with_name(f"{suffix[1:]}-target")
        if kind == "symlink":
            target.write_bytes(b"SIDE-CAR-CANARY")
        try:
            os.symlink(target, sidecar)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symbolic links are unavailable: {exc}")
    return sidecar, target


def _assert_unsafe_sidecar_unchanged(
    sidecar: Path, target: Path | None, kind: str
) -> None:
    info = os.lstat(sidecar)
    if kind == "directory":
        assert stat.S_ISDIR(info.st_mode)
    else:
        assert stat.S_ISLNK(info.st_mode)
        assert target is not None
        if kind == "symlink":
            assert target.read_bytes() == b"SIDE-CAR-CANARY"
        else:
            assert not target.exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
@pytest.mark.parametrize("kind", ["symlink", "broken-link", "directory"])
@pytest.mark.parametrize(
    "entrypoint",
    ["cli", "storage", "inspection", "migration"],
)
def test_all_readonly_entrypoints_reject_unsafe_sqlite_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    suffix: str,
    kind: str,
    entrypoint: str,
) -> None:
    database = _database(tmp_path)
    before = _digest(database)
    sidecar, target = _unsafe_sidecar(database, suffix, kind)

    if entrypoint == "cli":
        assert main(["--db", str(database), "source-list"]) == 6
        error = capsys.readouterr().err
        assert "READ_ONLY_STORAGE_ERROR" in error
    elif entrypoint == "storage":
        with pytest.raises(ReadOnlyStorageError, match="sidecar"):
            Storage.open_readonly(database)
    elif entrypoint == "inspection":
        with pytest.raises(ReadOnlyStorageError, match="sidecar"):
            ReadOnlyProject.open(database)
    else:
        with pytest.raises(MigrationError, match="sidecar"):
            preflight_migration(database, create_backup=False)

    assert _digest(database) == before
    _assert_unsafe_sidecar_unchanged(sidecar, target, kind)
