#!/usr/bin/env python3
"""Verify ContinuityForge release provenance against exact Git objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Mapping, Sequence

from build_source_archive import (
    ARCHIVE_LABEL,
    ARTIFACT_ORDER,
    CHECKSUMS_NAME,
    PROVENANCE_NAME,
    PROVENANCE_SCHEMA,
    ZIP_TIMESTAMP,
    GitEntry,
    ReleaseError,
    SourceIdentity,
    archive_basename,
    archive_comment,
    archive_prefix,
    build_source_zip,
    canonical_json_bytes,
    load_source_identity,
    resolve_commit,
    resolve_repository,
    sha256_file,
    validate_environment_record,
    validate_distribution_names,
    zip_mode,
)


_CHECKSUM_LINE = re.compile(
    r"\A(?P<digest>[0-9a-f]{64})  (?P<name>[A-Za-z0-9][A-Za-z0-9._+!-]*)\Z"
)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ReleaseError(f"{label} must be a JSON array")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\x00\r\n"):
        raise ReleaseError(f"{label} must be a non-empty single-line string")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReleaseError(f"{label} must be a non-negative integer")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReleaseError(f"{label} keys differ (missing={missing}, extra={extra})")


def _regular_artifact(dist_dir: Path, name: str, role: str) -> Path:
    if Path(name).name != name or "/" in name or "\\" in name:
        raise ReleaseError(f"{role} name is not an artifact basename: {name!r}")
    path = dist_dir / name
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"{role} artifact is missing or not a regular file: {name}")
    return path


def _load_provenance(path: Path) -> tuple[dict[str, object], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"provenance is missing or not a regular file: {path}")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ReleaseError("provenance exceeds the 1 MiB verification limit")
    try:
        decoded = raw.decode("ascii")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("provenance is not valid canonical ASCII JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseError("provenance root must be a JSON object")
    if raw != canonical_json_bytes(value):
        raise ReleaseError("provenance JSON is not in canonical form")
    return value, raw


def _validate_toolchain(
    value: object,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
) -> None:
    toolchain = _mapping(value, "toolchain")
    _exact_keys(
        toolchain,
        {"git", "release_environment", "release_environment_sha256"},
        "toolchain",
    )
    _text(toolchain["git"], "toolchain.git")
    release_environment = validate_environment_record(
        toolchain["release_environment"], identity, blobs
    )
    report_digest = _text(
        toolchain["release_environment_sha256"],
        "toolchain.release_environment_sha256",
    )
    expected_digest = hashlib.sha256(canonical_json_bytes(release_environment)).hexdigest()
    if report_digest != expected_digest:
        raise ReleaseError(
            "toolchain.release_environment_sha256 does not match embedded record"
        )


def _validate_workflow(value: object, commit: str) -> None:
    workflow = _mapping(value, "workflow")
    _exact_keys(
        workflow,
        {
            "provider",
            "ref",
            "repository",
            "run_attempt",
            "run_id",
            "source_sha",
            "workflow",
        },
        "workflow",
    )
    if workflow["provider"] != "github-actions":
        raise ReleaseError("workflow.provider must be github-actions")
    for key in ("ref", "repository", "run_attempt", "run_id", "source_sha", "workflow"):
        _text(workflow[key], f"workflow.{key}")
    if workflow["source_sha"] != commit:
        raise ReleaseError("workflow.source_sha does not match source.commit")
    if not str(workflow["run_id"]).isdecimal() or str(workflow["run_id"]).startswith("0"):
        raise ReleaseError("workflow.run_id must be a positive decimal integer")
    if not str(workflow["run_attempt"]).isdecimal() or str(
        workflow["run_attempt"]
    ).startswith("0"):
        raise ReleaseError("workflow.run_attempt must be a positive decimal integer")
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", str(workflow["repository"])):
        raise ReleaseError("workflow.repository must use owner/name form")


def _validate_archive(
    path: Path,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
    prefix: str,
) -> None:
    expected_names = [prefix + entry.path for entry in identity.entries]
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if names != expected_names:
                missing = sorted(set(expected_names) - set(names))
                extra = sorted(set(names) - set(expected_names))
                raise ReleaseError(
                    "source ZIP does not contain the exact tracked tree "
                    f"(missing={missing}, extra={extra}, order_or_duplicates_changed="
                    f"{not missing and not extra})"
                )
            if archive.comment != archive_comment(identity, prefix):
                raise ReleaseError("source ZIP Git identity comment does not match provenance")

            for info, entry in zip(infos, identity.entries):
                if info.is_dir():
                    raise ReleaseError(f"unexpected directory entry in source ZIP: {info.filename}")
                if info.date_time != ZIP_TIMESTAMP:
                    raise ReleaseError(f"non-deterministic ZIP timestamp: {info.filename}")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise ReleaseError(f"source ZIP member is not stored: {info.filename}")
                if info.flag_bits & 0x1:
                    raise ReleaseError(f"encrypted ZIP member is forbidden: {info.filename}")
                if info.extra or info.comment:
                    raise ReleaseError(f"unexpected ZIP member metadata: {info.filename}")
                if info.create_system != 3:
                    raise ReleaseError(f"ZIP member lacks UNIX mode metadata: {info.filename}")
                actual_mode = (info.external_attr >> 16) & 0xFFFF
                expected_mode = zip_mode(entry.mode)
                if actual_mode != expected_mode:
                    raise ReleaseError(
                        f"ZIP mode for {entry.path} is {actual_mode:o}, expected "
                        f"{expected_mode:o} from Git"
                    )
                expected = blobs[entry.object_id]
                if info.file_size != len(expected):
                    raise ReleaseError(
                        f"ZIP size for {entry.path} does not match Git blob "
                        f"{entry.object_id}"
                    )
                actual = archive.read(info)
                if actual != expected:
                    raise ReleaseError(
                        f"ZIP content for {entry.path} does not match Git blob "
                        f"{entry.object_id}"
                    )
    except zipfile.BadZipFile as exc:
        raise ReleaseError(f"source ZIP is invalid: {exc}") from exc


def _files_equal(left: Path, right: Path) -> bool:
    """Compare complete file contents without trusting ZIP reachability metadata."""

    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            left_chunk = left_stream.read(1024 * 1024)
            right_chunk = right_stream.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def _validate_canonical_archive_bytes(
    path: Path,
    identity: SourceIdentity,
    blobs: Mapping[str, bytes],
    archive_label: str,
) -> None:
    """Rebuild the canonical ZIP and compare every container byte.

    ZIP readers intentionally tolerate prepended self-extractor data, bytes not
    referenced by the central directory, and bytes after the EOCD record.  A
    tree/member-only verifier therefore cannot establish a canonical release
    artifact.  Rebuilding in an automatically cleaned temporary directory and
    comparing size, SHA-256, and the complete byte stream closes that gap.
    """

    with tempfile.TemporaryDirectory(prefix="continuityforge-verify-") as temporary:
        canonical_path = Path(temporary) / "canonical-source.zip"
        build_source_zip(
            canonical_path,
            identity,
            blobs,
            label=archive_label,
        )
        size_equal = path.stat().st_size == canonical_path.stat().st_size
        digest_equal = sha256_file(path) == sha256_file(canonical_path)
        bytes_equal = _files_equal(path, canonical_path)
        if not (size_equal and digest_equal and bytes_equal):
            raise ReleaseError(
                "source ZIP is not byte-for-byte canonical "
                f"(size_equal={size_equal}, sha256_equal={digest_equal}, "
                f"bytes_equal={bytes_equal})"
            )


def _artifact_records(value: object) -> list[Mapping[str, object]]:
    records = _list(value, "artifacts")
    if len(records) != 3:
        raise ReleaseError("artifacts must contain source_zip, wheel, and sdist")
    parsed: list[Mapping[str, object]] = []
    for index, item in enumerate(records):
        record = _mapping(item, f"artifacts[{index}]")
        _exact_keys(record, {"name", "role", "sha256", "size"}, f"artifacts[{index}]")
        _text(record["name"], f"artifacts[{index}].name")
        _text(record["role"], f"artifacts[{index}].role")
        digest = _text(record["sha256"], f"artifacts[{index}].sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseError(f"artifacts[{index}].sha256 is invalid")
        _integer(record["size"], f"artifacts[{index}].size")
        parsed.append(record)
    roles = [str(record["role"]) for record in parsed]
    if roles != list(ARTIFACT_ORDER[:3]):
        raise ReleaseError(f"artifact role order is not frozen order: {roles}")
    return parsed


def _verify_checksum_manifest(
    path: Path,
    dist_dir: Path,
    expected_names: list[str],
) -> None:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"checksum manifest is missing or not a regular file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReleaseError("SHA256SUMS must be ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise ReleaseError("SHA256SUMS must use LF lines and end with LF")
    lines = text.splitlines()
    if len(lines) != len(ARTIFACT_ORDER):
        raise ReleaseError(
            f"SHA256SUMS must contain exactly {len(ARTIFACT_ORDER)} lines"
        )

    actual_names: list[str] = []
    for index, line in enumerate(lines):
        match = _CHECKSUM_LINE.fullmatch(line)
        if not match:
            raise ReleaseError(f"invalid SHA256SUMS line {index + 1}")
        name = match.group("name")
        actual_names.append(name)
        artifact = _regular_artifact(dist_dir, name, ARTIFACT_ORDER[index])
        actual_digest = sha256_file(artifact)
        if actual_digest != match.group("digest"):
            raise ReleaseError(f"SHA-256 mismatch for {name}")
    if actual_names != expected_names:
        raise ReleaseError(
            f"SHA256SUMS artifact order/names differ: expected {expected_names}, "
            f"got {actual_names}"
        )


def verify_release(args: argparse.Namespace) -> dict[str, object]:
    """Verify metadata, checksums, and every archived Git blob/mode."""

    repo = resolve_repository(args.repo)
    dist_dir = Path(args.dist_dir).expanduser()
    if not dist_dir.is_absolute():
        dist_dir = Path.cwd() / dist_dir
    try:
        dist_dir = dist_dir.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"artifact directory does not exist: {dist_dir}") from exc
    if not dist_dir.is_dir():
        raise ReleaseError(f"artifact directory is not a directory: {dist_dir}")

    provenance_path = dist_dir / args.provenance
    checksums_path = dist_dir / args.checksums
    if provenance_path.name != args.provenance or checksums_path.name != args.checksums:
        raise ReleaseError("provenance/checksum arguments must be basenames")
    provenance, _ = _load_provenance(provenance_path)
    _exact_keys(
        provenance,
        {"artifacts", "checksum_manifest", "schema", "source", "toolchain", "workflow"},
        "provenance",
    )
    if provenance["schema"] != PROVENANCE_SCHEMA:
        raise ReleaseError(f"unsupported provenance schema: {provenance['schema']!r}")

    source = _mapping(provenance["source"], "source")
    _exact_keys(
        source,
        {
            "archive",
            "commit",
            "project_name",
            "short_commit",
            "tracked_entry_count",
            "tree",
            "version",
        },
        "source",
    )
    commit = _text(source["commit"], "source.commit")
    identity, blobs = load_source_identity(repo, commit)
    if identity.commit != commit:
        raise ReleaseError("source.commit is not a canonical full commit object ID")
    if source["tree"] != identity.tree:
        raise ReleaseError("source.tree does not match the commit's root Git tree")
    if source["short_commit"] != identity.short_commit:
        raise ReleaseError("source.short_commit is not the frozen seven-character prefix")
    if source["project_name"] != identity.project_name:
        raise ReleaseError("source.project_name does not match committed pyproject.toml")
    if source["version"] != identity.version:
        raise ReleaseError("source.version does not match committed pyproject.toml")
    if _integer(source["tracked_entry_count"], "source.tracked_entry_count") != len(
        identity.entries
    ):
        raise ReleaseError("source.tracked_entry_count does not match the Git tree")

    if args.expected_commit is not None:
        expected_commit, _ = resolve_commit(repo, args.expected_commit)
        if expected_commit != identity.commit:
            raise ReleaseError(
                f"provenance commit {identity.commit} does not match expected commit "
                f"{expected_commit}"
            )
    if args.version is not None and args.version != identity.version:
        raise ReleaseError(
            f"provenance version {identity.version!r} does not match expected "
            f"version {args.version!r}"
        )

    archive = _mapping(source["archive"], "source.archive")
    _exact_keys(
        archive,
        {"compression", "format", "name", "prefix", "timestamp"},
        "source.archive",
    )
    expected_archive_name = archive_basename(identity, args.archive_label)
    expected_prefix = archive_prefix(identity, args.archive_label)
    expected_archive_fields = {
        "compression": "stored",
        "format": "zip",
        "name": expected_archive_name,
        "prefix": expected_prefix,
        "timestamp": "1980-01-01T00:00:00Z",
    }
    if dict(archive) != expected_archive_fields:
        raise ReleaseError(
            f"source.archive differs from deterministic contract: {dict(archive)!r}"
        )

    records = _artifact_records(provenance["artifacts"])
    if records[2]["name"] != expected_archive_name:
        raise ReleaseError("source_zip artifact name does not match source.archive.name")
    artifact_paths: list[Path] = []
    for record in records:
        role = str(record["role"])
        name = str(record["name"])
        path = _regular_artifact(dist_dir, name, role)
        artifact_paths.append(path)
        if path.stat().st_size != record["size"]:
            raise ReleaseError(f"recorded size does not match {name}")
        if sha256_file(path) != record["sha256"]:
            raise ReleaseError(f"recorded SHA-256 does not match {name}")
    validate_distribution_names(identity, artifact_paths[0], artifact_paths[1])

    manifest = _mapping(provenance["checksum_manifest"], "checksum_manifest")
    _exact_keys(
        manifest,
        {"format", "name", "order", "provenance_name"},
        "checksum_manifest",
    )
    expected_manifest = {
        "format": "<lowercase-sha256><two-spaces><artifact-basename><LF>",
        "name": args.checksums,
        "order": list(ARTIFACT_ORDER),
        "provenance_name": args.provenance,
    }
    if dict(manifest) != expected_manifest:
        raise ReleaseError("checksum_manifest does not match the frozen v1 contract")

    _validate_toolchain(provenance["toolchain"], identity, blobs)
    _validate_workflow(provenance["workflow"], identity.commit)
    _verify_checksum_manifest(
        checksums_path,
        dist_dir,
        [str(record["name"]) for record in records] + [provenance_path.name],
    )
    _validate_archive(artifact_paths[2], identity, blobs, expected_prefix)
    _validate_canonical_archive_bytes(
        artifact_paths[2], identity, blobs, args.archive_label
    )

    return {
        "artifacts_verified": len(ARTIFACT_ORDER),
        "commit": identity.commit,
        "source_entries_verified": len(identity.entries),
        "tree": identity.tree,
        "verified": True,
        "version": identity.version,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify canonical release provenance, frozen-order SHA256SUMS, and "
            "the source ZIP against every path, mode, and blob in a Git commit."
        )
    )
    parser.add_argument("--repo", default=".", help="Git worktree (default: .)")
    parser.add_argument("--dist-dir", default="dist", help="artifact directory")
    parser.add_argument(
        "--provenance", default=PROVENANCE_NAME, help="provenance basename"
    )
    parser.add_argument("--checksums", default=CHECKSUMS_NAME, help="checksum basename")
    parser.add_argument(
        "--expected-commit",
        default=os.environ.get("GITHUB_SHA"),
        help="expected commit/ref (default: GITHUB_SHA; otherwise provenance commit)",
    )
    parser.add_argument("--version", help="expected committed project.version")
    parser.add_argument(
        "--archive-label", default=ARCHIVE_LABEL, help="expected source archive label"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = verify_release(args)
    except (OSError, ReleaseError) as exc:
        parser.exit(2, f"release provenance error: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
