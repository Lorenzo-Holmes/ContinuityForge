"""v0.3.0a5 full-source archive and release provenance contracts."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import zipfile
from copy import copy
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BUILD_SCRIPT = REPOSITORY_ROOT / "scripts" / "build_source_archive.py"
VERIFY_SCRIPT = REPOSITORY_ROOT / "scripts" / "verify_release_provenance.py"
VERSION = "0.3.0a5"
WHEEL_NAME = f"continuityforge-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"continuityforge-{VERSION}.tar.gz"


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment.pop("GITHUB_SHA", None)
    return environment


def _run(
    command: list[str],
    *,
    cwd: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=_git_environment(),
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _git(repo: Path, *arguments: str) -> str:
    return _run(["git", *arguments], cwd=repo).stdout.strip()


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")


def _make_repository(tmp_path: Path) -> tuple[Path, str, list[str]]:
    repo = tmp_path / "fixture-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Release Test")
    _git(repo, "config", "user.email", "release-test@example.invalid")
    _git(repo, "config", "commit.gpgSign", "false")

    tracked = {
        ".gitattributes": "* text=auto eol=lf\n",
        ".github/workflows/ci.yml": "name: fixture\n",
        "README.md": "tracked README\n",
        "bin/continuityforge-fixture": "#!/bin/sh\nprintf fixture\\n\n",
        "docs/release.txt": "full repository fixture\n",
        "pyproject.toml": (
            "[build-system]\n"
            "requires = [\"setuptools\"]\n"
            "build-backend = \"setuptools.build_meta\"\n\n"
            "[project]\n"
            "name = \"continuityforge\"\n"
            f"version = \"{VERSION}\"\n"
        ),
        "requirements/ci-build.txt": (
            "build==1.3.0 \\\n    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        ),
        "requirements/ci-test.txt": (
            "pytest==8.4.2 \\\n    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        ),
        "src/continuityforge/__init__.py": f'__version__ = "{VERSION}"\n',
        "tests/test_fixture.py": "def test_fixture():\n    assert True\n",
    }
    for relative, content in tracked.items():
        _write(repo / relative, content)
    _git(repo, "add", "--all")
    _git(repo, "update-index", "--chmod=+x", "bin/continuityforge-fixture")
    _git(repo, "commit", "--quiet", "-m", "fixture release commit")
    commit = _git(repo, "rev-parse", "HEAD")
    tracked_names = _git(repo, "ls-tree", "-r", "--name-only", commit).splitlines()

    # These changes deliberately make the worktree unsafe and inconsistent.  A
    # correct builder reads only committed objects and never sees any of them.
    _write(repo / "pyproject.toml", "[project]\nname='wrong'\nversion='9.9.9'\n")
    _write(repo / ".env", "TOKEN=worktree-only\n")
    _write(repo / "untracked.db", b"database bytes")
    _write(repo / ".pytest_cache/state", "cache\n")
    _write(repo / "untracked.txt", "worktree-only\n")

    dist = repo / "dist"
    dist.mkdir()
    _write(dist / WHEEL_NAME, b"fixture wheel\n")
    _write(dist / SDIST_NAME, b"fixture sdist\n")

    locks = []
    for relative, name, version in (
        ("requirements/ci-build.txt", "build", "1.3.0"),
        ("requirements/ci-test.txt", "pytest", "8.4.2"),
    ):
        lock_path = repo / relative
        locks.append(
            {
                "path": relative,
                "requirements": [{"name": name, "version": version}],
                "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            }
        )
    environment_report = {
        "environment": {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": "946684800",
            "TZ": "UTC",
        },
        "installed": [
            {"name": "build", "version": "1.3.0"},
            {"name": "pytest", "version": "8.4.2"},
        ],
        "locks": locks,
        "platform": {"machine": "fixture-machine", "system": "Linux"},
        "python": {"implementation": "CPython", "version": "3.12.0"},
        "schema_version": 1,
    }
    (repo.parent / "release-environment.json").write_bytes(
        _canonical_json(environment_report)
    )
    return repo, commit, tracked_names


def _build_command(repo: Path, commit: str) -> list[str]:
    return [
        sys.executable,
        str(BUILD_SCRIPT),
        "--repo",
        str(repo),
        "--commit",
        commit,
        "--expected-commit",
        commit,
        "--version",
        VERSION,
        "--dist-dir",
        "dist",
        "--wheel",
        f"dist/{WHEEL_NAME}",
        "--sdist",
        f"dist/{SDIST_NAME}",
        "--environment-report",
        str(repo.parent / "release-environment.json"),
        "--workflow-repository",
        "fixture/continuityforge",
        "--workflow-name",
        "Release fixture",
        "--workflow-run-id",
        "123456",
        "--workflow-run-attempt",
        "2",
        "--workflow-ref",
        "refs/tags/v0.3.0a5",
    ]


def _verify_command(repo: Path, commit: str) -> list[str]:
    return [
        sys.executable,
        str(VERIFY_SCRIPT),
        "--repo",
        str(repo),
        "--dist-dir",
        "dist",
        "--expected-commit",
        commit,
        "--version",
        VERSION,
    ]


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("ascii")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rebind_source_artifact(dist: Path, archive_name: str) -> None:
    """Model an attacker who can recompute all public digest metadata."""

    archive_path = dist / archive_name
    provenance_path = dist / "release-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    source_record = next(
        record for record in provenance["artifacts"] if record["role"] == "source_zip"
    )
    source_record["sha256"] = _sha256(archive_path)
    source_record["size"] = archive_path.stat().st_size
    _write_provenance_and_checksums(dist, archive_name, provenance)


def _write_provenance_and_checksums(
    dist: Path,
    archive_name: str,
    provenance: dict[str, object],
    *,
    wheel_name: str = WHEEL_NAME,
) -> None:
    provenance_path = dist / "release-provenance.json"
    provenance_path.write_bytes(_canonical_json(provenance))

    checksum_names = [
        wheel_name,
        SDIST_NAME,
        archive_name,
        provenance_path.name,
    ]
    (dist / "SHA256SUMS").write_text(
        "".join(f"{_sha256(dist / name)}  {name}\n" for name in checksum_names),
        encoding="ascii",
        newline="\n",
    )


def _insert_unreferenced_zip_bytes(raw: bytes) -> bytes:
    """Insert bytes before the central directory and retarget only the EOCD."""

    eocd_signature = b"PK\x05\x06"
    eocd_offset = raw.rfind(eocd_signature)
    assert eocd_offset >= 0
    central_offset = struct.unpack_from("<I", raw, eocd_offset + 16)[0]
    junk = b"UNREFERENCED-BY-ZIP-CENTRAL-DIRECTORY"
    mutated = bytearray(raw[:central_offset] + junk + raw[central_offset:])
    shifted_eocd = eocd_offset + len(junk)
    struct.pack_into("<I", mutated, shifted_eocd + 16, central_offset + len(junk))
    return bytes(mutated)


def test_build_is_git_exact_deterministic_and_self_verifying(tmp_path: Path) -> None:
    repo, commit, tracked_names = _make_repository(tmp_path)
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}")
    short_commit = commit[:7]
    archive_name = f"ContinuityForge-v{VERSION}-{short_commit}-source.zip"
    prefix = f"ContinuityForge-v{VERSION}-{short_commit}/"

    result = _run(_build_command(repo, commit), cwd=repo)
    report = json.loads(result.stdout)
    assert report["commit"] == commit
    assert report["tree"] == tree
    assert Path(report["source_zip"]).name == archive_name

    dist = repo / "dist"
    source_zip = dist / archive_name
    provenance_path = dist / "release-provenance.json"
    checksums_path = dist / "SHA256SUMS"
    first_bytes = {
        "source": source_zip.read_bytes(),
        "provenance": provenance_path.read_bytes(),
        "checksums": checksums_path.read_bytes(),
    }

    with zipfile.ZipFile(source_zip) as archive:
        assert archive.namelist() == [prefix + name for name in tracked_names]
        assert archive.read(prefix + "pyproject.toml").decode("utf-8").count(VERSION) == 1
        assert (archive.getinfo(prefix + "bin/continuityforge-fixture").external_attr >> 16) & 0xFFFF == 0o100755
        names = archive.namelist()
        assert prefix + ".github/workflows/ci.yml" in names
        assert prefix + "tests/test_fixture.py" in names
        assert all(".env" not in name for name in names)
        assert all("untracked" not in name for name in names)
        assert all(".pytest_cache" not in name for name in names)
        assert all("dist/" not in name.removeprefix(prefix) for name in names)

    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    assert provenance["schema"] == "continuityforge.release-provenance.v1"
    assert provenance["source"] == {
        "archive": {
            "compression": "stored",
            "format": "zip",
            "name": archive_name,
            "prefix": prefix,
            "timestamp": "1980-01-01T00:00:00Z",
        },
        "commit": commit,
        "project_name": "continuityforge",
        "short_commit": short_commit,
        "tracked_entry_count": len(tracked_names),
        "tree": tree,
        "version": VERSION,
    }
    assert provenance["workflow"]["run_id"] == "123456"
    assert provenance["workflow"]["run_attempt"] == "2"
    assert provenance["workflow"]["source_sha"] == commit
    assert provenance["toolchain"]["release_environment"]["schema_version"] == 1
    assert provenance["toolchain"]["release_environment_sha256"] == _sha256(
        repo.parent / "release-environment.json"
    )
    assert provenance["checksum_manifest"]["order"] == [
        "wheel",
        "sdist",
        "source_zip",
        "provenance",
    ]

    checksum_lines = checksums_path.read_text(encoding="ascii").splitlines()
    assert [line.split("  ", 1)[1] for line in checksum_lines] == [
        WHEEL_NAME,
        SDIST_NAME,
        archive_name,
        "release-provenance.json",
    ]
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        assert digest == _sha256(dist / name)

    verification = _run(_verify_command(repo, commit), cwd=repo)
    verified = json.loads(verification.stdout)
    assert verified == {
        "artifacts_verified": 4,
        "commit": commit,
        "source_entries_verified": len(tracked_names),
        "tree": tree,
        "verified": True,
        "version": VERSION,
    }

    # Rebuilding from the same commit and inputs produces byte-identical
    # metadata and source archive despite the dirty worktree.
    _run(_build_command(repo, commit), cwd=repo)
    assert source_zip.read_bytes() == first_bytes["source"]
    assert provenance_path.read_bytes() == first_bytes["provenance"]
    assert checksums_path.read_bytes() == first_bytes["checksums"]


def test_builder_fails_closed_when_database_artifact_is_tracked(tmp_path: Path) -> None:
    repo, _, _ = _make_repository(tmp_path)
    _write(repo / "release-cache.db", b"tracked database")
    _git(repo, "add", "release-cache.db")
    _git(repo, "commit", "--quiet", "-m", "track forbidden database")
    commit = _git(repo, "rev-parse", "HEAD")

    result = _run(_build_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert "forbidden sensitive/database artifact is tracked" in result.stderr
    assert "release-cache.db" in result.stderr


def test_builder_strictly_parses_hashes_from_committed_lock_blob(tmp_path: Path) -> None:
    repo, _, _ = _make_repository(tmp_path)
    lock_path = repo / "requirements/ci-build.txt"
    lock_path.write_text("build==1.3.0\n", encoding="ascii", newline="\n")
    _git(repo, "add", "requirements/ci-build.txt")
    _git(repo, "commit", "--quiet", "-m", "remove committed package hash")
    commit = _git(repo, "rev-parse", "HEAD")

    report_path = repo.parent / "release-environment.json"
    report = json.loads(report_path.read_text(encoding="ascii"))
    report["locks"][0]["sha256"] = _sha256(lock_path)
    report_path.write_bytes(_canonical_json(report))

    result = _run(_build_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert "invalid committed release lock requirements/ci-build.txt" in result.stderr
    assert "has no SHA-256 hashes" in result.stderr


def test_verifier_rejects_rehashed_archive_that_differs_from_git(tmp_path: Path) -> None:
    repo, commit, _ = _make_repository(tmp_path)
    _run(_build_command(repo, commit), cwd=repo)
    dist = repo / "dist"
    archive_name = f"ContinuityForge-v{VERSION}-{commit[:7]}-source.zip"
    archive_path = dist / archive_name

    with zipfile.ZipFile(archive_path, "r") as source:
        comment = source.comment
        members = [(info, source.read(info)) for info in source.infolist()]
    replacement = archive_path.with_suffix(".tampered.zip")
    with zipfile.ZipFile(replacement, "w", compression=zipfile.ZIP_STORED) as target:
        target.comment = comment
        for info, data in members:
            if info.filename.endswith("/README.md"):
                data = bytes([data[0] ^ 0x01]) + data[1:]
            target.writestr(info, data)
    os.replace(replacement, archive_path)

    _rebind_source_artifact(dist, archive_name)

    result = _run(_verify_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert "README.md does not match Git blob" in result.stderr


def test_verifier_rejects_rehashed_bytes_outside_zip_members(tmp_path: Path) -> None:
    mutators = {
        "appended": lambda raw: raw + b"BYTES-AFTER-EOCD",
        "prepended": lambda raw: b"SELF-EXTRACTOR-PREFIX" + raw,
        "unreferenced": _insert_unreferenced_zip_bytes,
    }
    for label, mutate in mutators.items():
        case_path = tmp_path / label
        case_path.mkdir()
        repo, commit, _ = _make_repository(case_path)
        _run(_build_command(repo, commit), cwd=repo)
        dist = repo / "dist"
        archive_name = f"ContinuityForge-v{VERSION}-{commit[:7]}-source.zip"
        archive_path = dist / archive_name
        archive_path.write_bytes(mutate(archive_path.read_bytes()))
        _rebind_source_artifact(dist, archive_name)

        # Standard ZIP parsing still sees the exact committed members.  The
        # canonical byte rebuild, rather than member traversal, rejects it.
        with zipfile.ZipFile(archive_path) as archive:
            assert archive.testzip() is None
        result = _run(_verify_command(repo, commit), cwd=repo, check=False)
        assert result.returncode == 2, label
        assert "source ZIP is not byte-for-byte canonical" in result.stderr, label


def test_verifier_rejects_rehashed_noncanonical_zip_metadata(tmp_path: Path) -> None:
    repo, commit, _ = _make_repository(tmp_path)
    _run(_build_command(repo, commit), cwd=repo)
    dist = repo / "dist"
    archive_name = f"ContinuityForge-v{VERSION}-{commit[:7]}-source.zip"
    archive_path = dist / archive_name

    with zipfile.ZipFile(archive_path, "r") as source:
        archive_comment = source.comment
        members = [(copy(info), source.read(info)) for info in source.infolist()]
    members[0][0].comment = b"noncanonical-member-comment"
    replacement = archive_path.with_suffix(".metadata.zip")
    with zipfile.ZipFile(replacement, "w", compression=zipfile.ZIP_STORED) as target:
        target.comment = archive_comment
        for info, data in members:
            target.writestr(info, data)
    os.replace(replacement, archive_path)
    _rebind_source_artifact(dist, archive_name)

    result = _run(_verify_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert "unexpected ZIP member metadata" in result.stderr


def test_verifier_rejects_rehashed_non_pure_wheel_tag(tmp_path: Path) -> None:
    repo, commit, _ = _make_repository(tmp_path)
    _run(_build_command(repo, commit), cwd=repo)
    dist = repo / "dist"
    archive_name = f"ContinuityForge-v{VERSION}-{commit[:7]}-source.zip"
    bad_wheel_name = f"continuityforge-{VERSION}-cp312-cp312-win_amd64.whl"
    os.replace(dist / WHEEL_NAME, dist / bad_wheel_name)

    provenance_path = dist / "release-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    wheel_record = next(
        record for record in provenance["artifacts"] if record["role"] == "wheel"
    )
    wheel_record["name"] = bad_wheel_name
    _write_provenance_and_checksums(
        dist,
        archive_name,
        provenance,
        wheel_name=bad_wheel_name,
    )

    result = _run(_verify_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert f"expected pure wheel {WHEEL_NAME}" in result.stderr


@pytest.mark.parametrize(
    ("tamper", "expected_error"),
    [
        ("lock_requirements", "lock record does not match committed lock"),
        ("installed_extra", "installed does not exactly match"),
        ("python_version", "Python version must be CPython 3.10 through 3.14"),
        ("python_implementation", "requires the CPython implementation"),
        ("platform_system", "supports Darwin, Linux, and Windows"),
        ("source_date_epoch", "must be at least 315532800"),
    ],
)
def test_verifier_rejects_forged_environment_after_all_digests_are_recomputed(
    tmp_path: Path,
    tamper: str,
    expected_error: str,
) -> None:
    repo, commit, _ = _make_repository(tmp_path)
    _run(_build_command(repo, commit), cwd=repo)
    dist = repo / "dist"
    archive_name = f"ContinuityForge-v{VERSION}-{commit[:7]}-source.zip"
    provenance_path = dist / "release-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    environment = provenance["toolchain"]["release_environment"]

    if tamper == "lock_requirements":
        environment["locks"][0]["requirements"][0]["version"] = "99.0"
    elif tamper == "installed_extra":
        environment["installed"].append({"name": "unlocked-plugin", "version": "9.9"})
    elif tamper == "python_version":
        environment["python"]["version"] = "3.99.0"
    elif tamper == "python_implementation":
        environment["python"]["implementation"] = "FictionPython"
    elif tamper == "platform_system":
        environment["platform"]["system"] = "FictionOS"
    elif tamper == "source_date_epoch":
        environment["environment"]["SOURCE_DATE_EPOCH"] = "1"
    else:  # pragma: no cover - guarded by parametrization
        raise AssertionError(tamper)

    provenance["toolchain"]["release_environment_sha256"] = hashlib.sha256(
        _canonical_json(environment)
    ).hexdigest()
    _write_provenance_and_checksums(dist, archive_name, provenance)

    result = _run(_verify_command(repo, commit), cwd=repo, check=False)
    assert result.returncode == 2
    assert expected_error in result.stderr
