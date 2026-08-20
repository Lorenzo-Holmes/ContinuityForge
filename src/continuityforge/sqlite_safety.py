"""Filesystem preflight for SQLite WAL sidecars used by read-only paths."""

from __future__ import annotations

import os
from pathlib import Path
import stat


class SQLiteSidecarError(RuntimeError):
    """A WAL sidecar set is incomplete or contains an unsafe file type."""


def validate_readonly_sidecars(database: str | Path) -> None:
    """Reject sidecars that could make a read-only open create/follow files.

    ``os.lstat`` is intentional: a symbolic link (including a broken link) is
    rejected rather than followed.  The check is a fail-closed preflight, not
    an operating-system lock; callers still treat the database directory and
    owning OS account as part of the local trust boundary.
    """

    path = Path(database)
    present: dict[str, bool] = {}
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

    if present["-wal"] and not present["-shm"]:
        raise SQLiteSidecarError(
            "SQLite read-only access requires an existing -shm sidecar when -wal exists"
        )


__all__ = ["SQLiteSidecarError", "validate_readonly_sidecars"]
