from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
coverage_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage_gate
SPEC.loader.exec_module(coverage_gate)

def _file(
    *,
    lines: tuple[int, int] = (80, 100),
    branches: tuple[int, int] = (80, 20),
    executed: list[list[int]] | None = None,
    missing: list[list[int]] | None = None,
) -> dict[str, object]:
    covered_lines, statements = lines
    covered_branches, missing_branches = branches
    return {
        "summary": {
            "covered_lines": covered_lines,
            "num_statements": statements,
            "covered_branches": covered_branches,
            "missing_branches": missing_branches,
        },
        "executed_branches": executed or [],
        "missing_branches": missing or [],
    }


def _payload(files: dict[str, dict[str, object]]) -> dict[str, object]:
    return {"meta": {"format": 3}, "files": files}


def test_all_release_gates_pass_with_explicit_p0_p1_branches() -> None:
    payload = _payload(
        {
            "src\\continuityforge\\storage.py": _file(
                executed=[[10, 11], [10, 12]], branches=(100, 0)
            ),
            "src/continuityforge/other.py": _file(branches=(75, 25)),
        }
    )

    report = coverage_gate.evaluate_coverage(
        payload,
        critical_branches=[
            "src/continuityforge/storage.py:10:11",
            "src/continuityforge/storage.py:10:12",
        ],
        critical_files=["src/continuityforge/storage.py"],
    )

    assert report.passed
    assert report.combined.actual == 83.75
    assert report.global_branches.actual == 87.5
    assert report.trusted_branches.actual == 100.0


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"combined_minimum": 90.0}, "combined coverage"),
        ({"global_branch_minimum": 90.0}, "global pure branch coverage"),
        ({"trusted_branch_minimum": 101.0}, "trusted pure branch coverage"),
    ],
)
def test_release_gate_reports_each_threshold_failure(
    change: dict[str, float], expected: str
) -> None:
    payload = _payload(
        {
            "src/continuityforge/storage.py": _file(branches=(80, 20)),
            "src/continuityforge/other.py": _file(branches=(80, 20)),
        }
    )
    report = coverage_gate.evaluate_coverage(payload, **change)

    failure = next(result for result in report.results if result.name == expected)
    assert not failure.passed
    assert f"FAIL {expected}" in failure.render()


def test_critical_branch_and_file_are_strict_100_percent_gates() -> None:
    payload = _payload(
        {
            "src/continuityforge/storage.py": _file(
                branches=(1, 1), executed=[[42, 43]], missing=[[42, 44]]
            ),
            "src/continuityforge/other.py": _file(branches=(100, 0)),
        }
    )

    report = coverage_gate.evaluate_coverage(
        payload,
        global_branch_minimum=0,
        trusted_branch_minimum=0,
        critical_branches=["src/continuityforge/storage.py:42:44"],
        critical_files=["src/continuityforge/storage.py"],
    )

    assert not report.passed
    assert not report.critical_branches[0].passed
    assert not report.critical_files[0].passed


def test_unknown_critical_branch_is_a_configuration_error() -> None:
    payload = _payload(
        {"src/continuityforge/storage.py": _file(executed=[[42, 43]], branches=(1, 0))}
    )

    with pytest.raises(coverage_gate.CoverageInputError, match="absent"):
        coverage_gate.evaluate_coverage(
            payload, critical_branches=["src/continuityforge/storage.py:42:99"]
        )


def test_main_returns_input_error_for_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "coverage.json"
    report.write_text("[]", encoding="utf-8")

    assert coverage_gate.main(["--json", str(report)]) == 2
    assert "COVERAGE INPUT ERROR" in capsys.readouterr().err


def test_main_renders_gate_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(_payload({"src/continuityforge/storage.py": _file(branches=(0, 100))})),
        encoding="utf-8",
    )

    assert coverage_gate.main(["--json", str(report)]) == 1
    assert "FAIL combined coverage" in capsys.readouterr().out
