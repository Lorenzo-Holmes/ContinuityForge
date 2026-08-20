#!/usr/bin/env python3
"""Enforce ContinuityForge release coverage gates from ``coverage json`` output.

The gate deliberately consumes Coverage.py's JSON report so it can enforce the
statement+branch aggregate gate and separately reason about branch-only groups.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

COMBINED_MINIMUM = 80.0
GLOBAL_BRANCH_MINIMUM = 75.0
TRUSTED_BRANCH_MINIMUM = 80.0

TRUSTED_MODULES = frozenset(
    {
        "schema.py",
        "migrations.py",
        "storage.py",
        "readonly.py",
        "inspection.py",
        "compiler.py",
        "validate.py",
        "evidence.py",
        "governance_integrity.py",
        "event_integrity.py",
        "source_integrity.py",
    }
)


class CoverageInputError(ValueError):
    """The Coverage.py JSON did not have the contract this gate needs."""


@dataclass(frozen=True)
class GateResult:
    name: str
    actual: float
    minimum: float
    numerator: int
    denominator: int
    passed: bool

    def render(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"{status} {self.name}: {self.actual:.2f}% "
            f"({self.numerator}/{self.denominator}; minimum {self.minimum:.2f}%)"
        )


@dataclass(frozen=True)
class CoverageGateReport:
    combined: GateResult
    global_branches: GateResult
    trusted_branches: GateResult
    critical_branches: tuple[GateResult, ...]
    critical_files: tuple[GateResult, ...]

    @property
    def results(self) -> tuple[GateResult, ...]:
        return (
            self.combined,
            self.global_branches,
            self.trusted_branches,
            *self.critical_branches,
            *self.critical_files,
        )

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)


def _normalise_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _summary_counts(summary: Mapping[str, Any], field: str) -> int:
    value = summary.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CoverageInputError(f"coverage summary field {field!r} must be a non-negative integer")
    return value


def _percentage(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        raise CoverageInputError("coverage gate denominator must be positive")
    return 100.0 * numerator / denominator


def _gate(name: str, numerator: int, denominator: int, minimum: float) -> GateResult:
    actual = _percentage(numerator, denominator)
    return GateResult(name, actual, minimum, numerator, denominator, actual >= minimum)


def _files_from_payload(payload: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    files = payload.get("files")
    if not isinstance(files, Mapping):
        raise CoverageInputError("coverage JSON is missing its files mapping")
    result: dict[str, Mapping[str, Any]] = {}
    for raw_path, entry in files.items():
        if not isinstance(raw_path, str) or not isinstance(entry, Mapping):
            raise CoverageInputError("coverage JSON files mapping contains an invalid entry")
        summary = entry.get("summary")
        if not isinstance(summary, Mapping):
            raise CoverageInputError(f"coverage JSON file {raw_path!r} is missing summary")
        # Validate all counters used by every gate before calculating anything.
        for field in ("covered_lines", "num_statements", "covered_branches", "missing_branches"):
            _summary_counts(summary, field)

        executed_lines = _line_numbers(entry, "executed_lines")
        missing_lines = _line_numbers(entry, "missing_lines")
        if executed_lines & missing_lines:
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} contains overlapping executed and missing lines"
            )
        if _summary_counts(summary, "covered_lines") != len(executed_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} covered-lines summary disagrees with details"
            )
        if _summary_counts(summary, "num_statements") != len(executed_lines | missing_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} statement summary disagrees with details"
            )

        executed_branches = _branch_pairs(entry, "executed_branches")
        missing_branches = _branch_pairs(entry, "missing_branches")
        if executed_branches & missing_branches:
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} contains overlapping executed and missing branches"
            )
        if _summary_counts(summary, "covered_branches") != len(executed_branches):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} covered-branches summary disagrees with details"
            )
        if _summary_counts(summary, "missing_branches") != len(missing_branches):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} missing-branches summary disagrees with details"
            )
        result[_normalise_path(raw_path)] = entry
    return result


def _branch_counts(entries: Iterable[Mapping[str, Any]]) -> tuple[int, int]:
    covered = 0
    total = 0
    for entry in entries:
        summary = entry["summary"]
        covered += _summary_counts(summary, "covered_branches")
        total += _summary_counts(summary, "covered_branches") + _summary_counts(summary, "missing_branches")
    return covered, total


def _parse_critical_branch(specification: str) -> tuple[str, tuple[int, int]]:
    try:
        raw_path, raw_source, raw_destination = specification.rsplit(":", 2)
        source = int(raw_source)
        destination = int(raw_destination)
    except (TypeError, ValueError) as error:
        raise CoverageInputError(
            "critical branch must be PATH:SOURCE_LINE:DESTINATION_LINE"
        ) from error
    if not raw_path:
        raise CoverageInputError("critical branch path must not be empty")
    return _normalise_path(raw_path), (source, destination)


def _line_numbers(entry: Mapping[str, Any], field: str) -> set[int]:
    raw_lines = entry.get(field)
    if not isinstance(raw_lines, list):
        raise CoverageInputError(f"coverage line field {field!r} must be a list")
    lines: set[int] = set()
    for value in raw_lines:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise CoverageInputError(f"coverage line field {field!r} contains an invalid line")
        if value in lines:
            raise CoverageInputError(f"coverage line field {field!r} contains a duplicate line")
        lines.add(value)
    return lines


def _branch_pairs(entry: Mapping[str, Any], field: str) -> set[tuple[int, int]]:
    raw_pairs = entry.get(field)
    if not isinstance(raw_pairs, list):
        raise CoverageInputError(f"coverage branch field {field!r} must be a list")
    pairs: set[tuple[int, int]] = set()
    for pair in raw_pairs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(value, int) and not isinstance(value, bool) for value in pair)
        ):
            raise CoverageInputError(f"coverage branch field {field!r} contains an invalid branch")
        branch = (pair[0], pair[1])
        if branch in pairs:
            raise CoverageInputError(f"coverage branch field {field!r} contains a duplicate branch")
        pairs.add(branch)
    return pairs


def evaluate_coverage(
    payload: Mapping[str, Any],
    *,
    combined_minimum: float = COMBINED_MINIMUM,
    global_branch_minimum: float = GLOBAL_BRANCH_MINIMUM,
    trusted_branch_minimum: float = TRUSTED_BRANCH_MINIMUM,
    critical_branches: Sequence[str] = (),
    critical_files: Sequence[str] = (),
) -> CoverageGateReport:
    """Evaluate release gates without invoking Coverage.py itself."""
    files = _files_from_payload(payload)
    if not files:
        raise CoverageInputError("coverage JSON contains no measured files")

    covered_lines = statements = 0
    for entry in files.values():
        summary = entry["summary"]
        covered_lines += _summary_counts(summary, "covered_lines")
        statements += _summary_counts(summary, "num_statements")
    covered_branches, total_branches = _branch_counts(files.values())
    combined = _gate(
        "combined coverage",
        covered_lines + covered_branches,
        statements + total_branches,
        combined_minimum,
    )
    global_branches = _gate(
        "global pure branch coverage",
        covered_branches,
        total_branches,
        global_branch_minimum,
    )

    trusted_entries = [
        entry for path, entry in files.items() if path.rsplit("/", 1)[-1] in TRUSTED_MODULES
    ]
    if not trusted_entries:
        raise CoverageInputError("coverage JSON contains no trusted ContinuityForge modules")
    trusted_covered, trusted_total = _branch_counts(trusted_entries)
    trusted_branches = _gate(
        "trusted pure branch coverage",
        trusted_covered,
        trusted_total,
        trusted_branch_minimum,
    )

    branch_results: list[GateResult] = []
    for specification in critical_branches:
        path, branch = _parse_critical_branch(specification)
        entry = files.get(path)
        if entry is None:
            raise CoverageInputError(f"critical branch file is absent from coverage JSON: {path}")
        executed = _branch_pairs(entry, "executed_branches")
        missing = _branch_pairs(entry, "missing_branches")
        if branch not in executed | missing:
            raise CoverageInputError(
                f"critical branch {path}:{branch[0]}:{branch[1]} is absent from coverage JSON"
            )
        branch_results.append(
            _gate(f"critical branch {path}:{branch[0]}:{branch[1]}", int(branch in executed), 1, 100.0)
        )

    file_results: list[GateResult] = []
    for raw_path in critical_files:
        path = _normalise_path(raw_path)
        entry = files.get(path)
        if entry is None:
            raise CoverageInputError(f"critical file is absent from coverage JSON: {path}")
        summary = entry["summary"]
        covered = _summary_counts(summary, "covered_branches")
        total = covered + _summary_counts(summary, "missing_branches")
        if total == 0:
            raise CoverageInputError(f"critical file has no branch opportunities: {path}")
        file_results.append(_gate(f"critical file {path}", covered, total, 100.0))

    return CoverageGateReport(
        combined=combined,
        global_branches=global_branches,
        trusted_branches=trusted_branches,
        critical_branches=tuple(branch_results),
        critical_files=tuple(file_results),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True, help="path written by `coverage json`")
    parser.add_argument("--combined-minimum", type=float, default=COMBINED_MINIMUM)
    parser.add_argument("--global-branch-minimum", type=float, default=GLOBAL_BRANCH_MINIMUM)
    parser.add_argument("--trusted-branch-minimum", type=float, default=TRUSTED_BRANCH_MINIMUM)
    parser.add_argument(
        "--critical-branch",
        action="append",
        default=[],
        metavar="PATH:SOURCE:DESTINATION",
        help="require one P0/P1 branch to be covered (repeatable)",
    )
    parser.add_argument(
        "--critical-file",
        action="append",
        default=[],
        metavar="PATH",
        help="require every branch in one P0/P1 file to be covered (repeatable)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        with args.json.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, Mapping):
            raise CoverageInputError("coverage JSON root must be an object")
        report = evaluate_coverage(
            payload,
            combined_minimum=args.combined_minimum,
            global_branch_minimum=args.global_branch_minimum,
            trusted_branch_minimum=args.trusted_branch_minimum,
            critical_branches=args.critical_branch,
            critical_files=args.critical_file,
        )
    except (CoverageInputError, OSError, json.JSONDecodeError) as error:
        print(f"COVERAGE INPUT ERROR: {error}", file=sys.stderr)
        return 2

    for result in report.results:
        print(result.render())
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
