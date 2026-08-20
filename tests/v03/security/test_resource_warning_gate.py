"""Regression contract for destructor-time resource leak handling."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_destructor_resource_warning_fails_pytest_subprocess(tmp_path: Path) -> None:
    probe = tmp_path / "test_resource_warning_probe.py"
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
