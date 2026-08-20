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
    executed_branch_details = list(executed or [])
    missing_branch_details = list(missing or [])
    assert len(executed_branch_details) <= covered_branches
    assert len(missing_branch_details) <= missing_branches
    executed_branch_details.extend(
        [[10_000 + index, 20_000 + index]
         for index in range(len(executed_branch_details), covered_branches)]
    )
    missing_branch_details.extend(
        [[30_000 + index, 40_000 + index]
         for index in range(len(missing_branch_details), missing_branches)]
    )
    partial_sources = {pair[0] for pair in executed_branch_details} & {
        pair[0] for pair in missing_branch_details
    }
    return {
        "summary": {
            "covered_lines": covered_lines,
            "num_statements": statements,
            "missing_lines": statements - covered_lines,
            "excluded_lines": 0,
            "num_branches": covered_branches + missing_branches,
            "num_partial_branches": len(partial_sources),
            "covered_branches": covered_branches,
            "missing_branches": missing_branches,
        },
        "executed_lines": list(range(1, covered_lines + 1)),
        "missing_lines": list(range(covered_lines + 1, statements + 1)),
        "excluded_lines": [],
        "executed_branches": executed_branch_details,
        "missing_branches": missing_branch_details,
    }


def _payload(
    files: dict[str, dict[str, object]], *, format_version: object = 3
) -> dict[str, object]:
    totals = {
        field: sum(int(entry["summary"][field]) for entry in files.values())  # type: ignore[index]
        for field in coverage_gate.SUMMARY_COUNT_FIELDS
    }
    return {"meta": {"format": format_version}, "files": files, "totals": totals}


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


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            _payload({"src/continuityforge/storage.py": _file(lines=(0, 0), branches=(0, 0))}),
            "denominator must be positive",
        ),
        (
            _payload({"src/continuityforge/storage.py": _file(lines=(1, 1), branches=(0, 0))}),
            "denominator must be positive",
        ),
        (
            _payload(
                {
                    "src/continuityforge/storage.py": _file(lines=(1, 1), branches=(0, 0)),
                    "src/continuityforge/other.py": _file(lines=(1, 1), branches=(1, 0)),
                }
            ),
            "denominator must be positive",
        ),
    ],
)
def test_empty_release_gate_denominators_fail_closed(
    payload: dict[str, object], expected: str
) -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match=expected):
        coverage_gate.evaluate_coverage(payload)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("covered_lines", 79, "covered-lines summary disagrees"),
        ("covered_branches", 79, "covered-branches summary disagrees"),
        ("missing_branches", 19, "missing-branches summary disagrees"),
    ],
)
def test_summary_counters_must_match_coverage_details(
    field: str, value: int, expected: str
) -> None:
    entry = _file()
    entry["summary"][field] = value  # type: ignore[index]
    payload = _payload({"src/continuityforge/storage.py": entry})

    with pytest.raises(coverage_gate.CoverageInputError, match=expected):
        coverage_gate.evaluate_coverage(payload)


def test_executed_and_missing_branch_details_must_be_disjoint() -> None:
    entry = _file(branches=(1, 1), executed=[[42, 43]], missing=[[42, 44]])
    entry["missing_branches"] = [[42, 43]]
    payload = _payload({"src/continuityforge/storage.py": entry})

    with pytest.raises(coverage_gate.CoverageInputError, match="overlapping.*branches"):
        coverage_gate.evaluate_coverage(payload)


@pytest.mark.parametrize(
    "raw_path",
    [
        "",
        "/src/continuityforge/storage.py",
        r"\\server\share\src\continuityforge\storage.py",
        "C:/src/continuityforge/storage.py",
        r"C:\src\continuityforge\storage.py",
        "../src/continuityforge/storage.py",
        "src/../continuityforge/storage.py",
        "src//continuityforge/storage.py",
        "src/continuityforge/",
        "./src/continuityforge/storage.py",
        "src/./continuityforge/storage.py",
        "tests/continuityforge/storage.py",
        "src/continuityforge/nested/storage.py",
        "src/continuityforge/storage.txt",
    ],
)
def test_measured_paths_must_be_unambiguous_package_modules(raw_path: str) -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match="coverage path"):
        coverage_gate.evaluate_coverage(_payload({raw_path: _file()}))


def test_slash_variants_cannot_overwrite_the_same_normalized_path() -> None:
    payload = _payload(
        {
            r"src\continuityforge\storage.py": _file(),
            "src/continuityforge/storage.py": _file(),
        }
    )

    with pytest.raises(coverage_gate.CoverageInputError, match="duplicate normalized path"):
        coverage_gate.evaluate_coverage(payload)


@pytest.mark.parametrize("format_version", [None, True, 2, 3.0, "3"])
def test_coverage_json_format_is_exact(format_version: object) -> None:
    with pytest.raises(coverage_gate.CoverageInputError, match=r"meta\.format"):
        coverage_gate.evaluate_coverage(
            _payload(
                {"src/continuityforge/storage.py": _file()},
                format_version=format_version,
            )
        )


@pytest.mark.parametrize("section", ["meta", "totals"])
def test_required_top_level_mappings_cannot_be_omitted(section: str) -> None:
    payload = _payload({"src/continuityforge/storage.py": _file()})
    del payload[section]

    with pytest.raises(coverage_gate.CoverageInputError, match=section):
        coverage_gate.evaluate_coverage(payload)


@pytest.mark.parametrize("field", coverage_gate.SUMMARY_COUNT_FIELDS)
def test_top_level_totals_must_equal_per_file_summaries(field: str) -> None:
    payload = _payload({"src/continuityforge/storage.py": _file()})
    payload["totals"][field] += 1  # type: ignore[index,operator]

    with pytest.raises(coverage_gate.CoverageInputError, match="coverage totals"):
        coverage_gate.evaluate_coverage(payload)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("missing_lines", 19, "missing-lines summary disagrees"),
        ("excluded_lines", 1, "excluded-lines summary disagrees"),
        ("num_branches", 99, "branch summary disagrees"),
        ("num_partial_branches", 1, "partial-branches summary disagrees"),
    ],
)
def test_extended_per_file_counters_must_match_details(
    field: str, value: int, expected: str
) -> None:
    entry = _file()
    entry["summary"][field] = value  # type: ignore[index]

    with pytest.raises(coverage_gate.CoverageInputError, match=expected):
        coverage_gate.evaluate_coverage(
            _payload({"src/continuityforge/storage.py": entry})
        )


def test_exact_trusted_paths_prevent_basename_spoofing() -> None:
    payload = _payload({"src/continuityforge/not_storage.py": _file()})

    with pytest.raises(coverage_gate.CoverageInputError, match="no trusted"):
        coverage_gate.evaluate_coverage(payload)


def test_main_returns_input_error_for_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "coverage.json"
    report.write_text("[]", encoding="utf-8")

    assert coverage_gate.main(["--json", str(report)]) == 2
    assert "COVERAGE INPUT ERROR" in capsys.readouterr().err


def test_main_rejects_duplicate_raw_json_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "coverage.json"
    path = "src/continuityforge/storage.py"
    report.write_text(
        '{"meta":{"format":3},"files":{"'
        + path
        + '":{},"'
        + path
        + '":{}},"totals":{}}',
        encoding="utf-8",
    )

    assert coverage_gate.main(["--json", str(report)]) == 2
    assert "duplicate key" in capsys.readouterr().err


def test_main_renders_gate_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(_payload({"src/continuityforge/storage.py": _file(branches=(0, 100))})),
        encoding="utf-8",
    )

    assert coverage_gate.main(["--json", str(report)]) == 1
    assert "FAIL combined coverage" in capsys.readouterr().out
