"""Isolated contracts for the v0.3.0a5 release environment lock."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "verify_release_environment.py"
SPEC = importlib.util.spec_from_file_location("verify_release_environment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_environment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_environment
SPEC.loader.exec_module(release_environment)

VALID_ENVIRONMENT = {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
    "PYTHONHASHSEED": "0",
    "SOURCE_DATE_EPOCH": "1767225600",
    "TZ": "UTC",
}


def _write_lock(path: Path, name: str = "demo", version: str = "1.0") -> None:
    path.write_text(
        f"{name}=={version} \\\n"
        f"    --hash=sha256:{'0' * 64} \\\n"
        f"    --hash=sha256:{'f' * 64}\n",
        encoding="ascii",
        newline="\n",
    )


def test_repository_locks_are_exact_hashed_and_cover_ci_tooling() -> None:
    build = release_environment.parse_lock(ROOT / "requirements" / "ci-build.txt")
    test = release_environment.parse_lock(ROOT / "requirements" / "ci-test.txt")
    build_versions = {item.name: item.version for item in build.requirements}
    test_versions = {item.name: item.version for item in test.requirements}

    assert build_versions["pip"] == "26.2.1"
    assert build_versions["setuptools"] == "84.0.0"
    assert build_versions["build"] == "1.5.0"
    assert build_versions["wheel"] == "0.48.0"
    assert test_versions["pytest"] == "8.4.2"
    assert test_versions["pytest-cov"] == "7.1.0"
    assert test_versions["coverage"] == "7.15.4"
    assert test_versions["jsonschema"] == "4.26.0"
    assert test_versions["rpds-py"] == "0.30.0"
    assert all(item.hashes for parsed in (build, test) for item in parsed.requirements)


@pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
@pytest.mark.parametrize("minor", range(10, 15))
def test_supported_python_and_os_matrix(system: str, minor: int) -> None:
    release_environment._validate_runtime(
        python_version=(3, minor, 0),
        system=system,
        environ=VALID_ENVIRONMENT,
    )


@pytest.mark.parametrize("python_version", [(3, 9, 18), (3, 15, 0)])
def test_unsupported_python_is_rejected(
    python_version: tuple[int, int, int],
) -> None:
    with pytest.raises(
        release_environment.VerificationError,
        match="Python 3.10 through 3.14",
    ):
        release_environment._validate_runtime(
            python_version=python_version,
            system="Linux",
            environ=VALID_ENVIRONMENT,
        )


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"implementation": "PyPy"}, "requires CPython"),
        ({"python_version_text": "3.12.9"}, "does not match the runtime tuple"),
        ({"machine": ""}, "machine must be a non-empty single line"),
    ],
)
def test_report_entry_rejects_inconsistent_runtime_identity(
    tmp_path: Path,
    override: dict[str, str],
    message: str,
) -> None:
    build_lock = tmp_path / "ci-build.txt"
    test_lock = tmp_path / "ci-test.txt"
    _write_lock(build_lock)
    _write_lock(test_lock)
    arguments: dict[str, object] = {
        "record_root": tmp_path,
        "environ": VALID_ENVIRONMENT,
        "python_version": (3, 12, 1),
        "python_version_text": "3.12.1",
        "implementation": "CPython",
        "system": "Linux",
        "machine": "x86_64",
        "installed_versions": {"demo": "1.0"},
    }
    arguments.update(override)

    with pytest.raises(release_environment.VerificationError, match=message):
        release_environment.build_report((build_lock, test_lock), **arguments)


@pytest.mark.parametrize(
    "content, message",
    [
        ("demo>=1.0 --hash=sha256:" + "0" * 64 + "\n", "exact NAME==VERSION"),
        ("demo==1.0\n", "has no SHA-256 hashes"),
        ("demo==1.0 --hash=sha512:" + "0" * 64 + "\n", "only SHA-256"),
    ],
)
def test_lock_parser_rejects_non_reproducible_entries(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    lock = tmp_path / "invalid.txt"
    lock.write_text(content, encoding="ascii", newline="\n")
    with pytest.raises(release_environment.VerificationError, match=message):
        release_environment.parse_lock(lock)


def test_record_is_canonical_and_checkable(tmp_path: Path) -> None:
    build_lock = tmp_path / "ci-build.txt"
    test_lock = tmp_path / "ci-test.txt"
    _write_lock(build_lock)
    _write_lock(test_lock)

    report = release_environment.build_report(
        (build_lock, test_lock),
        record_root=tmp_path,
        environ=VALID_ENVIRONMENT,
        python_version=(3, 14, 1),
        python_version_text="3.14.1",
        implementation="CPython",
        system="Darwin",
        machine="arm64",
        installed_versions={"demo": "1.0"},
    )
    destination = tmp_path / "release-environment.json"
    release_environment.write_report(destination, report)

    payload = destination.read_bytes()
    assert b"\r" not in payload
    assert payload.decode("utf-8") == release_environment.canonical_json(report)
    assert json.loads(payload) == report
    release_environment.check_report(destination, report)

    changed = {**report, "schema_version": 2}
    with pytest.raises(
        release_environment.VerificationError,
        match="does not match current state",
    ):
        release_environment.check_report(destination, changed)


def test_unlocked_installed_distribution_is_rejected(tmp_path: Path) -> None:
    build_lock = tmp_path / "ci-build.txt"
    test_lock = tmp_path / "ci-test.txt"
    _write_lock(build_lock)
    _write_lock(test_lock)

    with pytest.raises(
        release_environment.VerificationError,
        match="not present in either lock: unlocked-plugin",
    ):
        release_environment.build_report(
            (build_lock, test_lock),
            record_root=tmp_path,
            environ=VALID_ENVIRONMENT,
            python_version=(3, 12, 1),
            python_version_text="3.12.1",
            implementation="CPython",
            system="Linux",
            machine="x86_64",
            installed_versions={"demo": "1.0", "unlocked_plugin": "9.9"},
        )


def test_empty_platform_machine_uses_sysconfig_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_lock = tmp_path / "ci-build.txt"
    test_lock = tmp_path / "ci-test.txt"
    _write_lock(build_lock)
    _write_lock(test_lock)
    monkeypatch.setattr(release_environment.platform, "machine", lambda: "")
    monkeypatch.setattr(
        release_environment.sysconfig, "get_platform", lambda: "win-amd64"
    )

    report = release_environment.build_report(
        (build_lock, test_lock),
        record_root=tmp_path,
        environ=VALID_ENVIRONMENT,
        python_version=(3, 12, 7),
        python_version_text="3.12.7",
        implementation="CPython",
        system="Windows",
        installed_versions={"demo": "1.0"},
    )

    assert report["platform"]["machine"] == "win-amd64"
