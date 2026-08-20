"""Filesystem preflight for SQLite WAL sidecars used by read-only paths."""

from __future__ import annotations

import os
from pathlib import Path
import stat


class SQLiteSidecarError(RuntimeError):
    """A WAL sidecar set is incomplete or contains an unsafe file type."""


def _portable_file_identity(info: os.stat_result) -> tuple[int, int] | None:
    """Return a comparable identity only where the platform exposes one."""

    inode = int(getattr(info, "st_ino", 0) or 0)
    device = getattr(info, "st_dev", None)
    if inode == 0 or device is None:
        return None
    return int(device), inode


def validate_readonly_sidecars(database: str | Path) -> None:
    """Reject sidecars that could make a read-only open create/follow files.

    ``os.lstat`` is intentional: a symbolic link (including a broken link) is
    rejected rather than followed.  The check is a fail-closed preflight, not
    an operating-system lock; callers still treat the database directory and
    owning OS account as part of the local trust boundary.
    """

    path = Path(database)
    present: dict[str, bool] = {}
    sidecar_info: dict[str, os.stat_result] = {}
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        try:
            info = os.lstat(sidecar)
        except FileNotFoundError:
            present[suffix] = False
            continue
        except OSError as exc:
            raise SQLiteSidecarError(
                f"SQLite {suffix} sidecar cannot be inspected"
            ) from exc

        present[suffix] = True
        if stat.S_ISLNK(info.st_mode):
            raise SQLiteSidecarError(
                f"SQLite {suffix} sidecar must not be a symbolic link"
            )
        if not stat.S_ISREG(info.st_mode):
            raise SQLiteSidecarError(
                f"SQLite {suffix} sidecar must be a regular file"
            )
        if info.st_nlink != 1:
            raise SQLiteSidecarError(
                f"SQLite {suffix} sidecar link count must be exactly 1"
            )
        sidecar_info[suffix] = info

    if present["-wal"] and not present["-shm"]:
        raise SQLiteSidecarError(
            "SQLite read-only access requires an existing -shm sidecar when -wal exists"
        )
    if not sidecar_info:
        return

    # Link-count validation is the portable hard-link defense.  File identity
    # comparison adds defense in depth on filesystems that expose non-zero
    # inode values.  A missing main database is deliberately left for the
    # caller's read-only SQLite open so the pre-existing missing-file semantics
    # are preserved.
    identities: dict[tuple[int, int], str] = {}
    try:
        database_info = os.lstat(path)
    except FileNotFoundError:
        database_info = None
    except OSError as exc:
        raise SQLiteSidecarError(
            "SQLite database cannot be inspected for sidecar identity"
        ) from exc

    if database_info is not None:
        database_identity = _portable_file_identity(database_info)
        if database_identity is not None:
            identities[database_identity] = "database"

    for suffix, info in sidecar_info.items():
        identity = _portable_file_identity(info)
        if identity is None:
            continue
        previous = identities.get(identity)
        if previous is not None:
            raise SQLiteSidecarError(
                f"SQLite {suffix} sidecar must not share file identity with {previous}"
            )
        identities[identity] = f"{suffix} sidecar"


__all__ = ["SQLiteSidecarError", "validate_readonly_sidecars"]
