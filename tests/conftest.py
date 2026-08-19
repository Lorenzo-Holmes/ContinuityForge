from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def project_root() -> Path:
    return ROOT


@pytest.fixture
def storage(tmp_path):
    from continuityforge.storage import Storage

    with Storage(tmp_path / "continuityforge.db") as database:
        yield database

