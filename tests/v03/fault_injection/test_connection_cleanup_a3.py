from __future__ import annotations

from pathlib import Path

import pytest

import continuityforge.migrations as migrations_module
import continuityforge.readonly as readonly_module
import continuityforge.storage as storage_module
from continuityforge.migrations import preflight_migration
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


class _InjectedConfigurationFailure(RuntimeError):
    pass


class _FailingConnection:
    def __init__(self) -> None:
        self.row_factory = None
        self.closed = False
        self.in_transaction = False

    def execute(self, *_args, **_kwargs):
        raise _InjectedConfigurationFailure("injected post-connect failure")

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("surface", ["storage", "migration", "inspection"])
def test_post_connect_configuration_failure_always_closes_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    database = tmp_path / "project.db"
    database.write_bytes(b"not opened by the injected connector")
    connection = _FailingConnection()

    if surface == "storage":
        monkeypatch.setattr(
            storage_module.sqlite3, "connect", lambda *_a, **_k: connection
        )
        action = lambda: Storage(database)
    elif surface == "migration":
        monkeypatch.setattr(
            migrations_module.sqlite3, "connect", lambda *_a, **_k: connection
        )
        action = lambda: preflight_migration(database, create_backup=False)
    else:
        monkeypatch.setattr(
            readonly_module.sqlite3, "connect", lambda *_a, **_k: connection
        )
        action = lambda: ReadOnlyProject.open(database)

    with pytest.raises(_InjectedConfigurationFailure):
        action()
    assert connection.closed is True
