#!/usr/bin/env python3
"""Verify and record the hash-locked ContinuityForge release environment."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import os
import platform
import re
import sys
import sysconfig
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCKS = (
    ROOT / "requirements" / "ci-build.txt",
    ROOT / "requirements" / "ci-test.txt",
)
SUPPORTED_SYSTEMS = frozenset({"Darwin", "Linux", "Windows"})
REPRODUCIBLE_ENVIRONMENT = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
}
MINIMUM_SOURCE_DATE_EPOCH = 315532800  # 1980-01-01, the ZIP timestamp floor.
NAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
PIN_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)$")
HASH_PATTERN = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")


class VerificationError(ValueError):
    """A lock, interpreter, environment, or recorded report is invalid."""


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class ParsedLock:
    path: Path
    sha256: str
    requirements: tuple[LockedRequirement, ...]


def canonicalize_name(name: str) -> str:
    """Return the PEP 503 comparison form for a distribution name."""

    if not NAME_PATTERN.fullmatch(name):
        raise VerificationError(f"invalid distribution name: {name!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(text: str, source: Path) -> tuple[str, ...]:
    logical: list[str] = []
    pending: list[str] = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if not stripped:
            raise VerificationError(
                f"{source}:{number}: blank line inside a continued requirement"
            )
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        if not fragment or fragment.startswith("#"):
            raise VerificationError(f"{source}:{number}: invalid continuation")
        pending.append(fragment)
        if not continued:
            logical.append(" ".join(pending))
            pending.clear()
    if pending:
        raise VerificationError(f"{source}: unterminated line continuation")
    return tuple(logical)


def parse_lock_bytes(raw: bytes, source: Path) -> ParsedLock:
    """Parse strict lock bytes, including committed blobs without a checkout."""

    path = Path(source)
    if b"\r" in raw:
        raise VerificationError(f"{path}: lock file must use LF line endings")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{path}: lock file must be ASCII") from exc
    if not text.endswith("\n"):
        raise VerificationError(f"{path}: lock file must end with LF")

    requirements: list[LockedRequirement] = []
    seen: set[str] = set()
    for logical_line in _logical_lines(text, path):
        tokens = logical_line.split()
        pin = PIN_PATTERN.fullmatch(tokens[0]) if tokens else None
        if pin is None:
            raise VerificationError(
                f"{path}: requirement must be an exact NAME==VERSION pin: "
                f"{logical_line!r}"
            )
        name = canonicalize_name(pin.group(1))
        if name in seen:
            raise VerificationError(f"{path}: duplicate requirement {name!r}")
        digests: list[str] = []
        for token in tokens[1:]:
            matched_hash = HASH_PATTERN.fullmatch(token)
            if matched_hash is None:
                raise VerificationError(
                    f"{path}: only SHA-256 --hash options are allowed: {token!r}"
                )
            digests.append(matched_hash.group(1))
        if not digests:
            raise VerificationError(f"{path}: {name} has no SHA-256 hashes")
        if digests != sorted(set(digests)):
            raise VerificationError(f"{path}: {name} hashes must be unique and sorted")
        seen.add(name)
        requirements.append(
            LockedRequirement(name=name, version=pin.group(2), hashes=tuple(digests))
        )

    if not requirements:
        raise VerificationError(f"{path}: lock file is empty")
    names = [requirement.name for requirement in requirements]
    if names != sorted(names):
        raise VerificationError(f"{path}: requirements must be sorted by canonical name")
    return ParsedLock(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        requirements=tuple(requirements),
    )


def parse_lock(path: Path) -> ParsedLock:
    """Parse a strict, fully pinned ``pip --require-hashes`` lock file."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read lock file {path}: {exc}") from exc
    return parse_lock_bytes(raw, path)


def _validate_runtime(
    *,
    python_version: tuple[int, int, int],
    system: str,
    environ: Mapping[str, str],
) -> None:
    major_minor = python_version[:2]
    if major_minor[0] != 3 or not 10 <= major_minor[1] <= 14:
        raise VerificationError(
            "release tooling requires Python 3.10 through 3.14; "
            f"found {python_version[0]}.{python_version[1]}.{python_version[2]}"
        )
    if system not in SUPPORTED_SYSTEMS:
        raise VerificationError(
            f"release tooling supports Darwin, Linux, and Windows; found {system!r}"
        )
    for name, expected in REPRODUCIBLE_ENVIRONMENT.items():
        actual = environ.get(name)
        if actual != expected:
            raise VerificationError(
                f"{name} must be {expected!r} for release builds; found {actual!r}"
            )
    epoch = environ.get("SOURCE_DATE_EPOCH")
    if epoch is None or not epoch.isascii() or not epoch.isdecimal():
        raise VerificationError("SOURCE_DATE_EPOCH must be an ASCII decimal integer")
    if int(epoch) < MINIMUM_SOURCE_DATE_EPOCH:
        raise VerificationError(
            f"SOURCE_DATE_EPOCH must be at least {MINIMUM_SOURCE_DATE_EPOCH}"
        )


def _validate_runtime_identity(
    *,
    python_version: tuple[int, int, int],
    python_version_text: str,
    implementation: str,
    machine: str,
) -> None:
    """Require a self-consistent, portable release runtime identity."""

    if implementation != "CPython":
        raise VerificationError(
            f"release tooling requires CPython; found {implementation!r}"
        )
    expected_version_text = ".".join(str(part) for part in python_version)
    if python_version_text != expected_version_text:
        raise VerificationError(
            "Python version text does not match the runtime tuple: "
            f"{python_version_text!r} != {expected_version_text!r}"
        )
    if (
        not isinstance(machine, str)
        or not machine
        or any(character in machine for character in "\x00\r\n")
    ):
        raise VerificationError("platform machine must be a non-empty single line")


def _lock_label(path: Path, record_root: Path) -> str:
    try:
        relative = path.resolve().relative_to(record_root.resolve())
    except ValueError as exc:
        raise VerificationError(
            f"lock file must be below the record root {record_root}: {path}"
        ) from exc
    return relative.as_posix()


def _installed_versions() -> dict[str, str]:
    installed: dict[str, str] = {}
    for distribution in metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise VerificationError("installed distribution has no Name metadata")
        name = canonicalize_name(raw_name)
        version = distribution.version
        previous = installed.setdefault(name, version)
        if previous != version:
            raise VerificationError(
                f"multiple installed versions of {name}: {previous!r} and {version!r}"
            )
    return installed


def build_report(
    lock_paths: Sequence[Path] = DEFAULT_LOCKS,
    *,
    record_root: Path = ROOT,
    environ: Mapping[str, str] | None = None,
    python_version: tuple[int, int, int] | None = None,
    python_version_text: str | None = None,
    implementation: str | None = None,
    system: str | None = None,
    machine: str | None = None,
    installed_versions: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Validate the current release environment and return its stable record."""

    active_environ = os.environ if environ is None else environ
    active_python = (
        (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
        if python_version is None
        else python_version
    )
    active_system = platform.system() if system is None else system
    active_python_version_text = (
        platform.python_version()
        if python_version_text is None
        else python_version_text
    )
    active_implementation = (
        platform.python_implementation()
        if implementation is None
        else implementation
    )
    if machine is None:
        active_machine = platform.machine() or sysconfig.get_platform()
    else:
        active_machine = machine
    _validate_runtime(
        python_version=active_python,
        system=active_system,
        environ=active_environ,
    )
    _validate_runtime_identity(
        python_version=active_python,
        python_version_text=active_python_version_text,
        implementation=active_implementation,
        machine=active_machine,
    )

    parsed_locks = tuple(parse_lock(Path(path)) for path in lock_paths)
    expected_versions: dict[str, str] = {}
    for parsed in parsed_locks:
        for requirement in parsed.requirements:
            previous = expected_versions.setdefault(requirement.name, requirement.version)
            if previous != requirement.version:
                raise VerificationError(
                    f"conflicting pins for {requirement.name}: {previous} and "
                    f"{requirement.version}"
                )

    observed_versions = (
        _installed_versions()
        if installed_versions is None
        else {
            canonicalize_name(name): version
            for name, version in installed_versions.items()
        }
    )
    missing = sorted(set(expected_versions) - set(observed_versions))
    extra = sorted(set(observed_versions) - set(expected_versions))
    if missing:
        raise VerificationError(
            "locked distributions are not installed: " + ", ".join(missing)
        )
    if extra:
        raise VerificationError(
            "installed distributions are not present in either lock: "
            + ", ".join(extra)
        )

    installed: list[dict[str, str]] = []
    for name, expected in sorted(expected_versions.items()):
        actual = observed_versions[name]
        if actual != expected:
            raise VerificationError(
                f"installed {name} version is {actual!r}; lock requires {expected!r}"
            )
        installed.append({"name": name, "version": actual})

    return {
        "environment": {
            **{
                name: active_environ[name]
                for name in sorted(REPRODUCIBLE_ENVIRONMENT)
            },
            "SOURCE_DATE_EPOCH": active_environ["SOURCE_DATE_EPOCH"],
        },
        "installed": installed,
        "locks": [
            {
                "path": _lock_label(parsed.path, record_root),
                "requirements": [
                    {"name": requirement.name, "version": requirement.version}
                    for requirement in parsed.requirements
                ],
                "sha256": parsed.sha256,
            }
            for parsed in parsed_locks
        ],
        "platform": {
            "machine": active_machine,
            "system": active_system,
        },
        "python": {
            "implementation": active_implementation,
            "version": active_python_version_text,
        },
        "schema_version": 1,
    }


def canonical_json(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    )


def write_report(path: Path, report: Mapping[str, object]) -> None:
    """Atomically write a canonical UTF-8/LF environment record."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(report)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"environment report contains duplicate key {key!r}")
        result[key] = value
    return result


def check_report(path: Path, actual: Mapping[str, object]) -> None:
    """Require ``path`` to be canonical and equal to the current environment."""

    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        expected = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read environment report {path}: {exc}") from exc
    if text != canonical_json(expected):
        raise VerificationError(f"environment report is not canonical JSON: {path}")
    if expected != actual:
        raise VerificationError(f"environment report does not match current state: {path}")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--record",
        type=Path,
        metavar="PATH",
        help="write the verified environment as canonical JSON",
    )
    output.add_argument(
        "--check",
        type=Path,
        metavar="PATH",
        help="check a canonical record against the current environment",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = build_report()
        if args.record is not None:
            write_report(args.record, report)
            digest = hashlib.sha256(args.record.read_bytes()).hexdigest()
            print(f"recorded release environment: {args.record} sha256:{digest}")
        elif args.check is not None:
            check_report(args.check, report)
            print(f"verified release environment record: {args.check}")
        else:
            print("verified release environment")
    except VerificationError as exc:
        print(f"release environment verification failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
