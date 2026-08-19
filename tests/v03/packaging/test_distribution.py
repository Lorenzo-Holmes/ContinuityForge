"""Release artifact checks executed after ``python -m build``."""

from __future__ import annotations

import ast
import email
import os
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest


EXPECTED_VERSION = "0.3.0a1"
FORBIDDEN_SUFFIXES = {
    ".db",
    ".env",
    ".key",
    ".pem",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "htmlcov",
}
FORBIDDEN_NAMES = {
    ".coverage",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "coverage.xml",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
}


def _dist_dir() -> Path:
    configured = os.environ.get("CONTINUITYFORGE_DIST_DIR")
    if not configured:
        pytest.skip("distribution inspection runs after the build step")
    return Path(configured)


def _assert_safe_members(members: list[str]) -> None:
    assert members
    for member in members:
        path = PurePosixPath(member.replace("\\", "/"))
        assert not (set(path.parts) & FORBIDDEN_PARTS), member
        assert path.name.lower() not in FORBIDDEN_NAMES, member
        assert path.suffix.lower() not in FORBIDDEN_SUFFIXES, member
        assert "secret" not in path.name.lower(), member


def test_wheel_contents_and_metadata() -> None:
    wheels = sorted(_dist_dir().glob("*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as archive:
        members = archive.namelist()
        _assert_safe_members(members)

        metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
        entry_point_names = [
            name for name in members if name.endswith(".dist-info/entry_points.txt")
        ]
        assert len(metadata_names) == 1
        assert len(entry_point_names) == 1

        metadata = email.message_from_bytes(archive.read(metadata_names[0]))
        assert metadata["Name"] == "continuityforge"
        assert metadata["Version"] == EXPECTED_VERSION
        assert metadata["Requires-Python"] == ">=3.10"
        assert metadata["License-Expression"] == "MIT"
        assert metadata.get_all("License-File") == ["LICENSE"]
        project_urls = {
            key.strip(): value.strip()
            for item in metadata.get_all("Project-URL", [])
            for key, value in (item.split(",", 1),)
        }
        assert project_urls["Repository"] == (
            "https://github.com/Lorenzo-Holmes/ContinuityForge"
        )

        init_tree = ast.parse(
            archive.read("continuityforge/__init__.py").decode("utf-8")
        )
        runtime_versions = [
            ast.literal_eval(node.value)
            for node in init_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        ]
        assert runtime_versions == [EXPECTED_VERSION]

        entry_points = archive.read(entry_point_names[0]).decode("utf-8")
        assert "continuityforge = continuityforge.cli:main" in entry_points


def test_source_archive_is_clean_and_versioned() -> None:
    archives = sorted(_dist_dir().glob("*.tar.gz"))
    assert len(archives) == 1
    assert archives[0].name == f"continuityforge-{EXPECTED_VERSION}.tar.gz"

    with tarfile.open(archives[0], "r:gz") as archive:
        members = [member.name for member in archive.getmembers()]
    _assert_safe_members(members)
