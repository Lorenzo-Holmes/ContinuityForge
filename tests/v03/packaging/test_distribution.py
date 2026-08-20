"""Release artifact checks executed after ``python -m build``."""

from __future__ import annotations

import ast
import email
import hashlib
import os
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest


EXPECTED_VERSION = "0.3.0a3"
FORBIDDEN_SUFFIXES = {
    ".bak",
    ".backup",
    ".db",
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".venv-release",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "tests",
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
        filename = path.name.lower()
        assert not (set(path.parts) & FORBIDDEN_PARTS), member
        assert filename not in FORBIDDEN_NAMES, member
        assert not filename.startswith(".env."), member
        assert path.suffix.lower() not in FORBIDDEN_SUFFIXES, member
        assert not any(
            marker in filename
            for marker in (
                ".db-",
                ".db.",
                ".sqlite-",
                ".sqlite.",
                ".sqlite3-",
                ".sqlite3.",
            )
        ), member
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
    root = f"continuityforge-{EXPECTED_VERSION}/"
    required = {
        root + "CHANGELOG.md",
        root + "CODE_OF_CONDUCT.md",
        root + "CONTRIBUTING.md",
        root + "LICENSE",
        root + "README.md",
        root + "SECURITY.md",
        root + "LICENSES/NORTH_PIER_DEMO.md",
        root + "LICENSES/README.md",
        root + "docs/ARCHITECTURE.md",
        root + "docs/BACKUP_AND_RESTORE.md",
        root + "docs/CLI_CONTRACT.md",
        root + "docs/DATA_MODEL.md",
        root + "docs/DEMO_LICENSES.md",
        root + "docs/DETERMINISTIC_VS_LLM.md",
        root + "docs/MIGRATION_V3.md",
        root + "docs/SECURITY_TESTING.md",
        root + "docs/SNAPSHOT_IMPACT.md",
        root + "docs/THREAT_MODEL.md",
        root + "docs/V0_1_BASELINE.md",
        root + "docs/V0_2_DESIGN.md",
        root + "docs/V0_3_DECISIONS.md",
        root + "schemas/error-v0.3.schema.json",
        root + "schemas/migration-report-v0.3.schema.json",
        root + "schemas/source-impact-v0.3.schema.json",
        root + "scripts/check_coverage.py",
        root + "examples/north_pier/README.md",
        root + "examples/north_pier/impact-cases.json",
        root + "examples/north_pier/north_pier_v1.txt",
        root + "examples/north_pier/north_pier_v2.txt",
        root + "examples/north_pier/run_demo.py",
    }
    assert required <= set(members)
    schema_members = sorted(
        member for member in members if member.startswith(root + "schemas/")
    )
    assert schema_members == sorted(
        [
            root + "schemas/error-v0.3.schema.json",
            root + "schemas/migration-report-v0.3.schema.json",
            root + "schemas/source-impact-v0.3.schema.json",
        ]
    )


def test_sha256sums_is_complete_ordered_and_correct() -> None:
    dist = _dist_dir()
    checksum_path = dist / "SHA256SUMS"
    expected_names = [
        f"continuityforge-{EXPECTED_VERSION}-py3-none-any.whl",
        f"continuityforge-{EXPECTED_VERSION}.tar.gz",
    ]
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    assert len(lines) == len(expected_names)

    actual_names: list[str] = []
    for line, expected_name in zip(lines, expected_names):
        digest, filename = line.split(maxsplit=1)
        actual_names.append(filename)
        artifact = dist / filename
        assert artifact.is_file()
        assert digest == hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert filename == expected_name
    assert actual_names == expected_names
