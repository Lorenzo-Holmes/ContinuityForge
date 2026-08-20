#!/usr/bin/env python3
"""Build a deterministic, Git-object-backed source release bundle.

The checksum manifest order is part of the v1 release contract and is frozen as:
wheel, sdist, source ZIP, provenance.  The first two entries deliberately retain
the v0.3.0a4 order.  ``SHA256SUMS`` uses two ASCII spaces between each lowercase
SHA-256 digest and its artifact basename.

Only objects reachable from the requested commit are read.  Worktree changes,
ignored files, and untracked files therefore cannot enter the source ZIP.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

from verify_release_environment import (
    VerificationError as EnvironmentVerificationError,
    _validate_runtime,
    parse_lock_bytes,
)


PROVENANCE_SCHEMA = "continuityforge.release-provenance.v1"
ARTIFACT_ORDER = ("wheel", "sdist", "source_zip", "provenance")
ARCHIVE_LABEL = "ContinuityForge"
PROVENANCE_NAME = "release-provenance.json"
CHECKSUMS_NAME = "SHA256SUMS"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

_SAFE_RELEASE_TOKEN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+!-]*\Z")
_HEX_OBJECT_ID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TOML_SECTION = re.compile(r"(?m)^\s*\[([^]]+)]\s*(?:#.*)?$")
_TOML_STRING = re.compile(
    r"(?m)^\s*{key}\s*=\s*(?P<quote>['\"])(?P<value>[^'\"\r\n]+)"
    r"(?P=quote)\s*(?:#.*)?$"
)

_FORBIDDEN_PARTS = {
    ".cache",
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}
_FORBIDDEN_NAMES = {
    ".coverage",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "coverage.json",
    "coverage.xml",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "thumbs.db",
}
_FORBIDDEN_SUFFIXES = {
    ".bak",
    ".backup",
    ".db",
    ".duckdb",
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
_DATABASE_SIDECAR_MARKERS = (
    ".db-",
    ".db.",
    ".duckdb-",
    ".duckdb.",
    ".sqlite-",
    ".sqlite.",
    ".sqlite3-",
    ".sqlite3.",
)
_SUPPORTED_GIT_MODES = {"100644", "100755", "120000"}
_WINDOWS_RESERVED_BASENAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class ReleaseError(RuntimeError):
    """A fail-closed release bundle validation error."""


@dataclass(frozen=True)
class GitEntry:
    """One recursively listed blob from a Git tree."""

    mode: str
    object_id: str
    path: str


@dataclass(frozen=True)
class SourceIdentity:
    """Resolved identity and metadata for the source tree."""

    commit: str
    tree: str
    short_commit: str
    project_name: str
    version: str
    entries: tuple[GitEntry, ...]


def _decode_stderr(value: bytes) -> str:
    return value.decode("utf-8", errors="replace").strip()


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    # A local refs/replace namespace must never change the objects bound to a
    # published commit ID.  Optional locks also prevent read-only release
    # inspection from writing refresh data into the repository.
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def run_git(repo: Path, arguments: Sequence[str]) -> bytes:
    """Run Git without a shell and return raw stdout."""

    command = ["git", "-C", str(repo), *arguments]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:  # pragma: no cover - depends on the host installation
        raise ReleaseError(f"Git could not be executed: {exc}") from exc
    if result.returncode:
        detail = _decode_stderr(result.stderr) or "unknown Git error"
        raise ReleaseError(f"Git command failed: {detail}")
    return result.stdout


def resolve_repository(value: str | os.PathLike[str]) -> Path:
    """Resolve and validate a Git worktree or bare repository path."""

    try:
        repo = Path(value).expanduser().resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"repository does not exist: {value}") from exc
    if not repo.is_dir():
        raise ReleaseError(f"repository is not a directory: {repo}")
    inside = run_git(repo, ["rev-parse", "--is-inside-work-tree"]).strip()
    if inside != b"true":
        raise ReleaseError(f"not a Git worktree: {repo}")
    return repo


def resolve_commit(repo: Path, revision: str) -> tuple[str, str]:
    """Resolve ``revision`` to an exact commit and its root tree."""

    if not revision or "\x00" in revision or "\r" in revision or "\n" in revision:
        raise ReleaseError("commit revision must be a non-empty single line")
    commit = run_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
    ).decode("ascii").strip()
    tree = run_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}"],
    ).decode("ascii").strip()
    if not _HEX_OBJECT_ID.fullmatch(commit):
        raise ReleaseError(f"Git returned an invalid commit object ID: {commit!r}")
    if not _HEX_OBJECT_ID.fullmatch(tree):
        raise ReleaseError(f"Git returned an invalid tree object ID: {tree!r}")
    return commit, tree


def validate_tracked_path(path: str) -> None:
    """Reject unsafe, generated, sensitive, or non-portable tracked paths."""

    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ReleaseError(f"unsafe tracked path: {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ReleaseError(f"unsafe tracked path: {path!r}")

    lowered_parts = tuple(part.casefold() for part in pure.parts)
    for original_part, part in zip(pure.parts, lowered_parts):
        stem = part.split(".", 1)[0]
        if (
            any(ord(character) < 32 for character in original_part)
            or any(character in '<>:"|?*' for character in original_part)
            or original_part.endswith((" ", "."))
            or stem in _WINDOWS_RESERVED_BASENAMES
        ):
            raise ReleaseError(f"tracked path is not cross-platform safe: {path}")
        if part in _FORBIDDEN_PARTS or part.endswith(".egg-info"):
            raise ReleaseError(f"forbidden generated/cache path is tracked: {path}")

    filename = lowered_parts[-1]
    suffix = PurePosixPath(filename).suffix
    if filename in _FORBIDDEN_NAMES:
        raise ReleaseError(f"forbidden sensitive/generated file is tracked: {path}")
    if filename == ".env" or filename.startswith(".env."):
        raise ReleaseError(f"forbidden environment file is tracked: {path}")
    if suffix in _FORBIDDEN_SUFFIXES:
        raise ReleaseError(f"forbidden sensitive/database artifact is tracked: {path}")
    if any(marker in filename for marker in _DATABASE_SIDECAR_MARKERS):
        raise ReleaseError(f"forbidden database sidecar is tracked: {path}")


def list_git_entries(repo: Path, commit: str) -> tuple[GitEntry, ...]:
    """List every tracked blob in a commit without consulting the worktree."""

    raw = run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit])
    entries: list[GitEntry] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = header.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError("Git tree contains an unparseable/non-UTF-8 path") from exc

        validate_tracked_path(path)
        if path in seen:
            raise ReleaseError(f"duplicate path returned by Git: {path}")
        seen.add(path)
        if object_type != "blob" or mode not in _SUPPORTED_GIT_MODES:
            raise ReleaseError(
                f"unsupported Git entry {path!r}: mode={mode}, type={object_type}"
            )
        if not _HEX_OBJECT_ID.fullmatch(object_id):
            raise ReleaseError(f"invalid blob object ID for {path}: {object_id!r}")
        entries.append(GitEntry(mode=mode, object_id=object_id, path=path))

    if not entries:
        raise ReleaseError("the selected commit has no tracked files")
    return tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8")))


def read_git_blobs(repo: Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    """Read blobs efficiently through Git's batch object protocol."""

    unique_ids = tuple(dict.fromkeys(object_ids))
    if not unique_ids:
        return {}
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in unique_ids)
    command = ["git", "-C", str(repo), "cat-file", "--batch"]
    try:
        result = subprocess.run(
            command,
            input=request,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:  # pragma: no cover - depends on the host installation
        raise ReleaseError(f"Git could not read source blobs: {exc}") from exc
    if result.returncode:
        detail = _decode_stderr(result.stderr) or "unknown Git cat-file error"
        raise ReleaseError(f"Git could not read source blobs: {detail}")

    output = result.stdout
    cursor = 0
    blobs: dict[str, bytes] = {}
    for requested_id in unique_ids:
        line_end = output.find(b"\n", cursor)
        if line_end < 0:
            raise ReleaseError("truncated response from Git cat-file")
        header = output[cursor:line_end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":
            raise ReleaseError(
                f"Git object is missing or is not a blob: {requested_id}"
            )
        try:
            returned_id = header[0].decode("ascii")
            size = int(header[2])
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError("invalid response from Git cat-file") from exc
        data_start = line_end + 1
        data_end = data_start + size
        if data_end >= len(output) or output[data_end : data_end + 1] != b"\n":
            raise ReleaseError("truncated blob data from Git cat-file")
        if returned_id != requested_id:
            raise ReleaseError(
                f"Git returned {returned_id} while {requested_id} was requested"
            )
        blobs[requested_id] = output[data_start:data_end]
        cursor = data_end + 1
    if cursor != len(output):
        raise ReleaseError("unexpected trailing data from Git cat-file")
    return blobs


def _project_section(pyproject: str) -> str:
    matches = list(_TOML_SECTION.finditer(pyproject))
    for index, match in enumerate(matches):
        if match.group(1).strip() == "project":
            end = matches[index + 1].start() if index + 1 < len(matches) else len(pyproject)
            return pyproject[match.end() : end]
    raise ReleaseError("tracked pyproject.toml has no [project] table")


def _simple_toml_string(section: str, key: str) -> str:
    match = re.compile(_TOML_STRING.pattern.format(key=re.escape(key))).search(section)
    if not match:
        raise ReleaseError(f"tracked pyproject.toml has no static project.{key}")
    return match.group("value")


def read_project_identity(
    entries: Sequence[GitEntry], blobs: Mapping[str, bytes]
) -> tuple[str, str]:
    """Read project name/version from the committed pyproject blob."""

    pyproject_entries = [entry for entry in entries if entry.path == "pyproject.toml"]
    if len(pyproject_entries) != 1:
        raise ReleaseError("the selected commit must contain one root pyproject.toml")
    try:
        pyproject = blobs[pyproject_entries[0].object_id].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError("tracked pyproject.toml is not UTF-8") from exc
    section = _project_section(pyproject)
    project_name = _simple_toml_string(section, "name")
    version = _simple_toml_string(section, "version")
    if not _SAFE_RELEASE_TOKEN.fullmatch(project_name):
        raise ReleaseError(f"project name is unsafe for release filenames: {project_name!r}")
    if not _SAFE_RELEASE_TOKEN.fullmatch(version):
        raise ReleaseError(f"version is unsafe for release filenames: {version!r}")
    return project_name, version


def validate_symlink_targets(
    entries: Sequence[GitEntry], blobs: Mapping[str, bytes]
) -> None:
    """Reject symlinks that could escape the extracted archive root."""

    for entry in entries:
        if entry.mode != "120000":
            continue
        try:
            target = blobs[entry.object_id].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseError(f"symlink target is not UTF-8: {entry.path}") from exc
        if (
            not target
            or target.startswith("/")
            or "\\" in target
            or "\x00" in target
            or re.match(r"^[A-Za-z]:", target)
        ):
            raise ReleaseError(f"unsafe symlink target for {entry.path}: {target!r}")
        resolved_parts = list(PurePosixPath(entry.path).parent.parts)
        for part in target.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if not resolved_parts:
                    raise ReleaseError(
                        f"symlink escapes the archive root: {entry.path} -> {target}"
                    )
                resolved_parts.pop()
                continue
            resolved_parts.append(part)
        if any(part.casefold() == ".git" for part in resolved_parts):
            raise ReleaseError(f"symlink targets forbidden .git path: {entry.path}")


def load_source_identity(repo: Path, revision: str) -> tuple[SourceIdentity, dict[str, bytes]]:
    """Resolve a commit, recursively load its tree, and read its exact blobs."""

    commit, tree = resolve_commit(repo, revision)
    entries = list_git_entries(repo, commit)
    blobs = read_git_blobs(repo, (entry.object_id for entry in entries))
    validate_symlink_targets(entries, blobs)
    project_name, version = read_project_identity(entries, blobs)
    identity = SourceIdentity(
        commit=commit,
        tree=tree,
        short_commit=commit[:7],
        project_name=project_name,
        version=version,
        entries=entries,
    )
    return identity, blobs


def archive_basename(identity: SourceIdentity, label: str = ARCHIVE_LABEL) -> str:
    """Return the frozen deterministic source ZIP basename."""

    if not _SAFE_RELEASE_TOKEN.fullmatch(label):
        raise ReleaseError(f"archive label is unsafe: {label!r}")
    return f"{label}-v{identity.version}-{identity.short_commit}-source.zip"


def archive_prefix(identity: SourceIdentity, label: str = ARCHIVE_LABEL) -> str:
    """Return the single top-level directory prefix used in the ZIP."""

    if not _SAFE_RELEASE_TOKEN.fullmatch(label):
        raise ReleaseError(f"archive label is unsafe: {label!r}")
    return f"{label}-v{identity.version}-{identity.short_commit}/"


def archive_comment(identity: SourceIdentity, prefix: str) -> bytes:
    """Return an immutable ASCII binding stored in the ZIP end record."""

    return (
        f"{PROVENANCE_SCHEMA}\n"
        f"commit {identity.commit}\n"
        f"tree {identity.tree}\n"
        f"prefix {prefix}\n"
    ).encode("ascii")


def zip_mode(git_mode: str) -> int:
    """Translate a Git tree mode to a portable UNIX ZIP mode."""

    if git_mode == "100644":
        return 0o100644
    if git_mode == "100755":
        return 0o100755
    if git_mode == "120000":
        return 0o120777
    raise ReleaseError(f"unsupported Git mode: {git_mode}")


def _temporary_path(parent: Path, suffix: str) -> Path:
    handle = tempfile.NamedTemporaryFile(
        mode="wb", prefix=".continuityforge-release-", suffix=suffix, dir=parent, delete=False
    )
    path = Path(handle.name)
    handle.close()
    return path


def build_source_zip(
    destination: Path,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
    *,
    label: str = ARCHIVE_LABEL,
) -> str:
    """Atomically write a deterministic stored ZIP from committed blobs."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = archive_prefix(identity, label)
    temporary = _temporary_path(destination.parent, ".zip.tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=True,
            strict_timestamps=True,
        ) as archive:
            archive.comment = archive_comment(identity, prefix)
            for entry in identity.entries:
                info = zipfile.ZipInfo(prefix + entry.path, date_time=ZIP_TIMESTAMP)
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = zip_mode(entry.mode) << 16
                info.internal_attr = 0
                info.extra = b""
                info.comment = b""
                archive.writestr(info, blobs[entry.object_id])
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return prefix


def sha256_file(path: Path) -> str:
    """Hash a regular artifact without loading it all into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_path(value: str, dist_dir: Path, role: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.is_symlink():
        raise ReleaseError(f"{role} artifact must not be a symbolic link: {candidate}")
    try:
        candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"{role} artifact does not exist: {value}") from exc
    if candidate.parent != dist_dir:
        raise ReleaseError(f"{role} artifact must be directly inside {dist_dir}")
    if candidate.is_symlink() or not candidate.is_file():
        raise ReleaseError(f"{role} artifact is not a regular file: {candidate}")
    return candidate


def validate_distribution_names(
    identity: SourceIdentity, wheel: Path, sdist: Path
) -> None:
    """Bind supplied distribution names to the committed project metadata."""

    wheel_project = re.sub(r"[-_.]+", "_", identity.project_name).lower()
    wheel_version = identity.version.replace("-", "_")
    expected_wheel = f"{wheel_project}-{wheel_version}-py3-none-any.whl"
    if wheel.name != expected_wheel:
        raise ReleaseError(f"expected pure wheel {expected_wheel}, got {wheel.name}")
    sdist_project = re.sub(r"[-_.]+", "-", identity.project_name).lower()
    expected_sdist = f"{sdist_project}-{identity.version}.tar.gz"
    if sdist.name != expected_sdist:
        raise ReleaseError(f"expected sdist {expected_sdist}, got {sdist.name}")


def artifact_record(role: str, path: Path) -> dict[str, object]:
    """Create a deterministic artifact identity record."""

    return {
        "name": path.name,
        "role": role,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _environment_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\x00\r\n"):
        raise ReleaseError(f"{label} must be a non-empty single-line string")
    return value


def _environment_exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != expected:
        raise ReleaseError(
            f"{label} keys differ (missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)})"
        )
    return value


def validate_environment_record(
    value: object,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
) -> dict[str, object]:
    """Validate the authoritative WP-03 environment record and committed locks."""

    record = _environment_exact_keys(
        value,
        {"environment", "installed", "locks", "platform", "python", "schema_version"},
        "release environment",
    )
    if record["schema_version"] != 1:
        raise ReleaseError("release environment schema_version must be 1")

    python = _environment_exact_keys(
        record["python"], {"implementation", "version"}, "release environment.python"
    )
    implementation = _environment_text(
        python["implementation"], "release environment.python.implementation"
    )
    python_version_text = _environment_text(
        python["version"], "release environment.python.version"
    )
    if implementation != "CPython":
        raise ReleaseError("release environment requires the CPython implementation")
    version_match = re.fullmatch(
        r"3\.(?P<minor>10|11|12|13|14)\.(?P<micro>[0-9]+)",
        python_version_text,
    )
    if version_match is None:
        raise ReleaseError(
            "release environment Python version must be CPython 3.10 through 3.14"
        )
    python_version = (
        3,
        int(version_match.group("minor")),
        int(version_match.group("micro")),
    )

    platform_record = _environment_exact_keys(
        record["platform"], {"machine", "system"}, "release environment.platform"
    )
    _environment_text(platform_record["machine"], "release environment.platform.machine")
    system = _environment_text(
        platform_record["system"], "release environment.platform.system"
    )

    environment = _environment_exact_keys(
        record["environment"],
        {
            "PIP_DISABLE_PIP_VERSION_CHECK",
            "PIP_NO_INPUT",
            "PYTHONHASHSEED",
            "SOURCE_DATE_EPOCH",
            "TZ",
        },
        "release environment.environment",
    )
    for name, environment_value in environment.items():
        _environment_text(environment_value, f"release environment.environment.{name}")
    try:
        _validate_runtime(
            python_version=python_version,
            system=system,
            environ={str(name): str(value) for name, value in environment.items()},
        )
    except EnvironmentVerificationError as exc:
        raise ReleaseError(f"invalid release environment runtime: {exc}") from exc

    entries_by_path = {entry.path: entry for entry in identity.entries}
    locks = record["locks"]
    expected_lock_paths = (
        "requirements/ci-build.txt",
        "requirements/ci-test.txt",
    )
    if not isinstance(locks, list) or len(locks) != len(expected_lock_paths):
        raise ReleaseError(
            "release environment.locks must contain ci-build.txt and ci-test.txt"
        )
    expected_versions: dict[str, str] = {}
    for index, (item, expected_path) in enumerate(zip(locks, expected_lock_paths)):
        lock = _environment_exact_keys(
            item,
            {"path", "requirements", "sha256"},
            f"release environment.locks[{index}]",
        )
        path = _environment_text(lock["path"], f"release environment.locks[{index}].path")
        validate_tracked_path(path)
        if path != expected_path:
            raise ReleaseError(
                f"release environment lock {index} must be {expected_path}, got {path}"
            )
        entry = entries_by_path.get(path)
        if entry is None:
            raise ReleaseError(f"release environment lock is not tracked at the commit: {path}")
        lock_bytes = blobs[entry.object_id]
        try:
            parsed_lock = parse_lock_bytes(lock_bytes, Path(path))
        except EnvironmentVerificationError as exc:
            raise ReleaseError(f"invalid committed release lock {path}: {exc}") from exc
        expected_requirements = [
            {"name": requirement.name, "version": requirement.version}
            for requirement in parsed_lock.requirements
        ]
        expected_lock = {
            "path": path,
            "requirements": expected_requirements,
            "sha256": parsed_lock.sha256,
        }
        if dict(lock) != expected_lock:
            raise ReleaseError(
                f"release environment lock record does not match committed lock: {path}"
            )
        for requirement in parsed_lock.requirements:
            previous = expected_versions.setdefault(requirement.name, requirement.version)
            if previous != requirement.version:
                raise ReleaseError(
                    f"conflicting committed lock versions for {requirement.name}: "
                    f"{previous} and {requirement.version}"
                )

    installed = record["installed"]
    expected_installed = [
        {"name": name, "version": version}
        for name, version in sorted(expected_versions.items())
    ]
    if installed != expected_installed:
        raise ReleaseError(
            "release environment.installed does not exactly match the committed "
            "lock union"
        )
    return record


def load_environment_report(
    value: str,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
) -> tuple[dict[str, object], str]:
    """Load a canonical WP-03 report and bind it to committed lock files."""

    report_path = Path(value).expanduser()
    if not report_path.is_absolute():
        report_path = Path.cwd() / report_path
    if report_path.is_symlink() or not report_path.is_file():
        raise ReleaseError(f"environment report is missing or not a regular file: {report_path}")
    raw = report_path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ReleaseError("environment report exceeds the 1 MiB release limit")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("environment report is not valid UTF-8 JSON") from exc
    record = validate_environment_record(parsed, identity, blobs)
    if raw != canonical_json_bytes(record):
        raise ReleaseError("environment report is not canonical sorted-key/LF JSON")
    return record, hashlib.sha256(raw).hexdigest()


def toolchain_record(
    repo: Path,
    environment_report: str,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
) -> dict[str, object]:
    """Embed the authoritative WP-03 record rather than taking a second snapshot."""

    release_environment, report_digest = load_environment_report(
        environment_report, identity, blobs
    )
    git_version = run_git(repo, ["--version"]).decode("utf-8", errors="strict").strip()
    return {
        "git": git_version,
        "release_environment": release_environment,
        "release_environment_sha256": report_digest,
    }


def _required_text(value: str | None, label: str) -> str:
    if value is None or not value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ReleaseError(f"{label} must be a non-empty single line")
    return value.strip()


def workflow_record(
    *,
    repository: str | None,
    workflow: str | None,
    run_id: str | None,
    run_attempt: str | None,
    ref: str | None,
    commit: str,
) -> dict[str, str]:
    """Create the GitHub Actions run binding used by release provenance."""

    repository_value = _required_text(repository, "workflow repository")
    workflow_value = _required_text(workflow, "workflow name")
    run_id_value = _required_text(run_id, "workflow run ID")
    run_attempt_value = _required_text(run_attempt, "workflow run attempt")
    ref_value = _required_text(ref, "workflow ref")
    if not re.fullmatch(r"[1-9][0-9]*", run_id_value):
        raise ReleaseError("workflow run ID must be a positive integer")
    if not re.fullmatch(r"[1-9][0-9]*", run_attempt_value):
        raise ReleaseError("workflow run attempt must be a positive integer")
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository_value):
        raise ReleaseError("workflow repository must use owner/name form")
    return {
        "provider": "github-actions",
        "ref": ref_value,
        "repository": repository_value,
        "run_attempt": run_attempt_value,
        "run_id": run_id_value,
        "source_sha": commit,
        "workflow": workflow_value,
    }


def canonical_json_bytes(value: object) -> bytes:
    """Serialize release JSON canonically with an LF terminator."""

    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("ascii")


def atomic_write(path: Path, data: bytes) -> None:
    """Write bytes atomically in the destination directory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _temporary_path(path.parent, ".tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_release_bundle(args: argparse.Namespace) -> dict[str, str]:
    """Build the source ZIP, provenance, and frozen-order checksum manifest."""

    repo = resolve_repository(args.repo)
    dist_dir = Path(args.dist_dir).expanduser()
    if not dist_dir.is_absolute():
        dist_dir = Path.cwd() / dist_dir
    dist_dir.mkdir(parents=True, exist_ok=True)
    dist_dir = dist_dir.resolve(strict=True)

    identity, blobs = load_source_identity(repo, args.commit)
    if args.version is not None and args.version != identity.version:
        raise ReleaseError(
            f"requested version {args.version!r} does not match committed "
            f"project.version {identity.version!r}"
        )
    if args.expected_commit is not None:
        expected_commit, _ = resolve_commit(repo, args.expected_commit)
        if expected_commit != identity.commit:
            raise ReleaseError(
                f"selected commit {identity.commit} does not match expected commit "
                f"{expected_commit}"
            )

    wheel = _artifact_path(args.wheel, dist_dir, "wheel")
    sdist = _artifact_path(args.sdist, dist_dir, "sdist")
    validate_distribution_names(identity, wheel, sdist)

    # Validate all external metadata before replacing any release output.
    workflow = workflow_record(
        repository=args.workflow_repository,
        workflow=args.workflow_name,
        run_id=args.workflow_run_id,
        run_attempt=args.workflow_run_attempt,
        ref=args.workflow_ref,
        commit=identity.commit,
    )
    toolchain = toolchain_record(
        repo, args.environment_report, identity, blobs
    )

    source_zip = dist_dir / archive_basename(identity, args.archive_label)
    if source_zip in {wheel, sdist}:
        raise ReleaseError("source ZIP destination overlaps a distribution artifact")
    prefix = build_source_zip(
        source_zip, identity, blobs, label=args.archive_label
    )

    artifacts = [
        artifact_record("wheel", wheel),
        artifact_record("sdist", sdist),
        artifact_record("source_zip", source_zip),
    ]
    provenance_path = dist_dir / PROVENANCE_NAME
    checksums_path = dist_dir / CHECKSUMS_NAME
    provenance: dict[str, object] = {
        "artifacts": artifacts,
        "checksum_manifest": {
            "format": "<lowercase-sha256><two-spaces><artifact-basename><LF>",
            "name": CHECKSUMS_NAME,
            "order": list(ARTIFACT_ORDER),
            "provenance_name": PROVENANCE_NAME,
        },
        "schema": PROVENANCE_SCHEMA,
        "source": {
            "archive": {
                "compression": "stored",
                "format": "zip",
                "name": source_zip.name,
                "prefix": prefix,
                "timestamp": "1980-01-01T00:00:00Z",
            },
            "commit": identity.commit,
            "project_name": identity.project_name,
            "short_commit": identity.short_commit,
            "tracked_entry_count": len(identity.entries),
            "tree": identity.tree,
            "version": identity.version,
        },
        "toolchain": toolchain,
        "workflow": workflow,
    }
    atomic_write(provenance_path, canonical_json_bytes(provenance))

    checksum_records = [*artifacts, artifact_record("provenance", provenance_path)]
    lines = [f"{record['sha256']}  {record['name']}\n" for record in checksum_records]
    atomic_write(checksums_path, "".join(lines).encode("ascii"))

    return {
        "checksums": str(checksums_path),
        "commit": identity.commit,
        "provenance": str(provenance_path),
        "source_zip": str(source_zip),
        "tree": identity.tree,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic full-repository source ZIP from an exact Git "
            "commit, then bind it to wheel/sdist and GitHub Actions provenance. "
            "SHA256SUMS order is wheel, sdist, source ZIP, provenance."
        )
    )
    parser.add_argument("--repo", default=".", help="Git worktree (default: .)")
    parser.add_argument(
        "--commit",
        default=os.environ.get("GITHUB_SHA", "HEAD"),
        help="commit/ref to archive (default: GITHUB_SHA or HEAD)",
    )
    parser.add_argument(
        "--expected-commit",
        default=os.environ.get("GITHUB_SHA"),
        help="independent expected commit/ref binding (default: GITHUB_SHA)",
    )
    parser.add_argument("--version", help="expected committed project.version")
    parser.add_argument("--dist-dir", default="dist", help="artifact directory")
    parser.add_argument("--wheel", required=True, help="wheel path inside --dist-dir")
    parser.add_argument("--sdist", required=True, help="sdist path inside --dist-dir")
    parser.add_argument(
        "--environment-report",
        required=True,
        help="canonical report emitted by verify_release_environment.py --record",
    )
    parser.add_argument(
        "--archive-label", default=ARCHIVE_LABEL, help="safe source archive label"
    )
    parser.add_argument(
        "--workflow-repository",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="GitHub owner/name (default: GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--workflow-name",
        default=os.environ.get("GITHUB_WORKFLOW"),
        help="workflow name (default: GITHUB_WORKFLOW)",
    )
    parser.add_argument(
        "--workflow-run-id",
        default=os.environ.get("GITHUB_RUN_ID"),
        help="workflow run ID (default: GITHUB_RUN_ID)",
    )
    parser.add_argument(
        "--workflow-run-attempt",
        default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        help="workflow run attempt (default: GITHUB_RUN_ATTEMPT or 1)",
    )
    parser.add_argument(
        "--workflow-ref",
        default=os.environ.get("GITHUB_REF"),
        help="workflow ref (default: GITHUB_REF)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = build_release_bundle(args)
    except (OSError, ReleaseError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"release bundle error: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
