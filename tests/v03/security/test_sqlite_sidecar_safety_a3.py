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
        lambda _path: SimpleNamespace(
            st_mode=stat.S_IFLNK,
            st_nlink=1,
            st_dev=1,
            st_ino=1,
        ),
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


def _hardlink(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hard links are unavailable: {exc}")


def _hardlinked_sidecars(database: Path, relation: str) -> Path:
    """Create an unsafe sidecar and return the content-bearing victim."""

    wal = database.with_name(database.name + "-wal")
    shm = database.with_name(database.name + "-shm")
    if relation == "main":
        _hardlink(database, shm)
        return database
    if relation == "sidecar":
        shm.write_bytes(b"SIDE-CAR-VICTIM")
        _hardlink(shm, wal)
        return shm

    canary = database.parent / "external-canary"
    canary.write_bytes(b"EXTERNAL-CANARY")
    _hardlink(canary, shm)
    return canary


def _tree_snapshot(
    directory: Path,
) -> dict[str, tuple[int, int, int, int, int, bytes | None]]:
    snapshot: dict[str, tuple[int, int, int, int, int, bytes | None]] = {}
    for path in sorted(directory.iterdir()):
        info = os.lstat(path)
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        snapshot[path.name] = (
            info.st_mode,
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_size,
            payload,
        )
    return snapshot


@pytest.mark.parametrize("relation", ["main", "sidecar", "external"])
@pytest.mark.parametrize("entrypoint", ["cli", "storage", "inspection", "migration"])
def test_all_readonly_entrypoints_reject_hardlinked_sqlite_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    relation: str,
    entrypoint: str,
) -> None:
    database = _database(tmp_path)
    victim = _hardlinked_sidecars(database, relation)
    before = _tree_snapshot(tmp_path)
    database_digest = _digest(database)
    victim_digest = _digest(victim)

    if entrypoint == "cli":
        assert main(["--db", str(database), "source-list"]) == 6
        assert "READ_ONLY_STORAGE_ERROR" in capsys.readouterr().err
    elif entrypoint == "storage":
        with pytest.raises(ReadOnlyStorageError, match="sidecar"):
            Storage.open_readonly(database)
    elif entrypoint == "inspection":
        with pytest.raises(ReadOnlyStorageError, match="sidecar"):
            ReadOnlyProject.open(database)
    else:
        with pytest.raises(MigrationError, match="sidecar"):
            preflight_migration(database, create_backup=False)

    assert _digest(database) == database_digest
    assert _digest(victim) == victim_digest
    assert _tree_snapshot(tmp_path) == before


def test_zero_inode_identity_is_not_compared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "missing.db"
    shm = database.with_name(database.name + "-shm")
    shm.write_bytes(b"SHM")
    original_lstat = sqlite_safety.os.lstat

    def zero_inode(path: Path) -> os.stat_result:
        info = original_lstat(path)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_dev=info.st_dev,
            st_ino=0,
        )

    monkeypatch.setattr(sqlite_safety.os, "lstat", zero_inode)
    sqlite_safety.validate_readonly_sidecars(database)


def test_zero_inode_database_identity_is_not_compared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "project.db"
    database.write_bytes(b"DB")
    database.with_name(database.name + "-shm").write_bytes(b"SHM")
    original_lstat = sqlite_safety.os.lstat

    def zero_inode(path: Path) -> SimpleNamespace:
        info = original_lstat(path)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_dev=info.st_dev,
            st_ino=0,
        )

    monkeypatch.setattr(sqlite_safety.os, "lstat", zero_inode)
    sqlite_safety.validate_readonly_sidecars(database)


def test_database_identity_inspection_error_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "project.db"
    database.write_bytes(b"DB")
    database.with_name(database.name + "-shm").write_bytes(b"SHM")
    original_lstat = sqlite_safety.os.lstat

    def denied_for_database(path: Path) -> os.stat_result:
        if Path(path) == database:
            raise PermissionError("injected")
        return original_lstat(path)

    monkeypatch.setattr(sqlite_safety.os, "lstat", denied_for_database)
    with pytest.raises(
        sqlite_safety.SQLiteSidecarError,
        match="database cannot be inspected",
    ):
        sqlite_safety.validate_readonly_sidecars(database)


def test_duplicate_nonzero_file_identity_is_rejected_even_with_single_link_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def duplicate_identity(path: Path) -> SimpleNamespace:
        name = os.fspath(path)
        if name.endswith("-wal"):
            raise FileNotFoundError(name)
        return SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_nlink=1,
            st_dev=7,
            st_ino=11,
        )

    monkeypatch.setattr(sqlite_safety.os, "lstat", duplicate_identity)
    with pytest.raises(sqlite_safety.SQLiteSidecarError, match="file identity"):
        sqlite_safety.validate_readonly_sidecars(Path("project.db"))


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
