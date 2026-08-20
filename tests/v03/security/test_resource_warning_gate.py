"""Regression contract for destructor-time resource leak handling."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_destructor_resource_warning_fails_pytest_subprocess() -> None:
    # Keep the probe on the repository's drive.  GitHub's Windows checkout is
    # on D: while its generic temp directory is on C:; crossing those drives
    # makes pytest choose an unrelated filesystem root during collection.
    with TemporaryDirectory(
        prefix=".resource-warning-",
        dir=PROJECT_ROOT,
    ) as directory:
        probe = Path(directory) / "test_resource_warning_probe.py"
        probe.write_text(
            """
import gc
import warnings


class LeakedResource:
    def __del__(self):
        warnings.warn("leaked-resource-probe", ResourceWarning)


def test_probe():
    resource = LeakedResource()
    del resource
    gc.collect()
""".lstrip(),
            encoding="utf-8",
        )

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-c",
                str(PROJECT_ROOT / "pyproject.toml"),
                str(probe),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

        output = completed.stdout + completed.stderr
        assert completed.returncode != 0, output
        assert "PytestUnraisableExceptionWarning" in output
        assert "leaked-resource-probe" in output
