from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_coverage_a5", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
coverage_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage_gate
SPEC.loader.exec_module(coverage_gate)

AUDIT_PATH = "src/continuityforge/audit_material.py"


def _file(
    *,
    lines: tuple[int, int] = (80, 100),
    branches: tuple[int, int] = (80, 20),
) -> dict[str, object]:
    covered_lines, statements = lines
    covered_branches, missing_branches = branches
    executed_branch_details = [
        [10_000 + index, 20_000 + index] for index in range(covered_branches)
    ]
    missing_branch_details = [
        [30_000 + index, 40_000 + index] for index in range(missing_branches)
    ]
    return {
        "summary": {
            "covered_lines": covered_lines,
            "num_statements": statements,
            "missing_lines": statements - covered_lines,
            "excluded_lines": 0,
            "num_branches": covered_branches + missing_branches,
            "num_partial_branches": 0,
            "covered_branches": covered_branches,
            "missing_branches": missing_branches,
        },
        "executed_lines": list(range(1, covered_lines + 1)),
        "missing_lines": list(range(covered_lines + 1, statements + 1)),
        "excluded_lines": [],
        "executed_branches": executed_branch_details,
        "missing_branches": missing_branch_details,
    }


def _payload(files: dict[str, dict[str, object]]) -> dict[str, object]:
    totals = {
        field: sum(int(entry["summary"][field]) for entry in files.values())  # type: ignore[index]
        for field in coverage_gate.SUMMARY_COUNT_FIELDS
    }
    return {"meta": {"format": 3}, "files": files, "totals": totals}


def test_critical_file_min_enforces_separate_statement_and_branch_targets() -> None:
    report = coverage_gate.evaluate_coverage(
        _payload({AUDIT_PATH: _file(lines=(96, 100), branches=(9, 1))}),
        critical_file_minimums=[f"{AUDIT_PATH}:95:90"],
    )

    assert report.passed
    statements, branches = report.critical_file_minimums
    assert statements.name == f"critical file statements {AUDIT_PATH}"
    assert statements.actual == 96.0
    assert statements.minimum == 95.0
    assert branches.name == f"critical file pure branches {AUDIT_PATH}"
    assert branches.actual == 90.0
    assert branches.minimum == 90.0


@pytest.mark.parametrize(
    ("lines", "branches", "failed_gate"),
    [
        ((94, 100), (10, 0), "critical file statements"),
        ((100, 100), (8, 2), "critical file pure branches"),
    ],
)
def test_critical_file_min_reports_each_metric_failure(
    lines: tuple[int, int], branches: tuple[int, int], failed_gate: str
) -> None:
    report = coverage_gate.evaluate_coverage(
        _payload({AUDIT_PATH: _file(lines=lines, branches=branches)}),
        critical_file_minimums=[f"{AUDIT_PATH}:95:90"],
    )

    assert not report.passed
    failure = next(
        result
        for result in report.critical_file_minimums
        if result.name.startswith(failed_gate)
    )
    assert not failure.passed


def test_two_field_critical_file_min_applies_one_threshold_to_both_metrics() -> None:
    report = coverage_gate.evaluate_coverage(
        _payload({AUDIT_PATH: _file(lines=(85, 100), branches=(85, 15))}),
        critical_file_minimums=[f"{AUDIT_PATH}:85"],
    )

    assert report.passed
    assert [result.minimum for result in report.critical_file_minimums] == [85.0, 85.0]


def test_critical_file_min_normalizes_backslashes_to_one_canonical_path() -> None:
    report = coverage_gate.evaluate_coverage(
        _payload({AUDIT_PATH: _file(lines=(95, 100), branches=(9, 1))}),
        critical_file_minimums=[r"src\continuityforge\audit_material.py:95:90"],
    )

    assert report.passed
    assert all(AUDIT_PATH in result.name for result in report.critical_file_minimums)


def test_duplicate_normalized_critical_file_min_paths_fail_closed() -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match="more than once"):
        coverage_gate.evaluate_coverage(
            _payload({AUDIT_PATH: _file()}),
            critical_file_minimums=[
                f"{AUDIT_PATH}:95:90",
                r"src\continuityforge\audit_material.py:96:91",
            ],
        )


@pytest.mark.parametrize(
    "specification",
    [
        AUDIT_PATH,
        ":95:90",
        f"{AUDIT_PATH}:0:90",
        f"{AUDIT_PATH}:95:0",
        f"{AUDIT_PATH}:101:90",
        f"{AUDIT_PATH}:95:101",
        f"{AUDIT_PATH}:nan:90",
        f"{AUDIT_PATH}:95:inf",
        f"{AUDIT_PATH}:not-a-number:90",
    ],
)
def test_malformed_or_vacuous_critical_file_minimums_fail_closed(
    specification: str,
) -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match="critical file"):
        coverage_gate.evaluate_coverage(
            _payload({AUDIT_PATH: _file()}),
            critical_file_minimums=[specification],
        )


def test_absent_critical_file_minimum_path_fails_closed() -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match="absent"):
        coverage_gate.evaluate_coverage(
            _payload({"src/continuityforge/storage.py": _file()}),
            critical_file_minimums=[f"{AUDIT_PATH}:95:90"],
        )


@pytest.mark.parametrize(
    ("critical_entry", "expected"),
    [
        (_file(lines=(0, 0), branches=(1, 0)), "no statement opportunities"),
        (_file(lines=(1, 1), branches=(0, 0)), "no branch opportunities"),
    ],
)
def test_zero_critical_file_opportunities_fail_closed(
    critical_entry: dict[str, object], expected: str
) -> None:
    payload = _payload(
        {
            AUDIT_PATH: critical_entry,
            "src/continuityforge/storage.py": _file(lines=(1, 1), branches=(1, 0)),
        }
    )

    with pytest.raises(coverage_gate.CoverageInputError, match=expected):
        coverage_gate.evaluate_coverage(
            payload,
            critical_file_minimums=[f"{AUDIT_PATH}:95:90"],
        )


def test_inconsistent_critical_file_counters_fail_before_threshold_evaluation() -> None:
    entry = _file(lines=(96, 100), branches=(9, 1))
    entry["summary"]["covered_lines"] = 95  # type: ignore[index]

    with pytest.raises(coverage_gate.CoverageInputError, match="disagrees with details"):
        coverage_gate.evaluate_coverage(
            _payload({AUDIT_PATH: entry}),
            critical_file_minimums=[f"{AUDIT_PATH}:95:90"],
        )


def test_main_accepts_critical_file_min_and_renders_both_metrics(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    coverage_json = tmp_path / "coverage.json"
    coverage_json.write_text(
        json.dumps(
            _payload({AUDIT_PATH: _file(lines=(96, 100), branches=(9, 1))})
        ),
        encoding="utf-8",
    )

    assert coverage_gate.main(
        ["--json", str(coverage_json), "--critical-file-min", f"{AUDIT_PATH}:95:90"]
    ) == 0
    output = capsys.readouterr().out
    assert f"PASS critical file statements {AUDIT_PATH}" in output
    assert f"PASS critical file pure branches {AUDIT_PATH}" in output
