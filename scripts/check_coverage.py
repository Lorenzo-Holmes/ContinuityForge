#!/usr/bin/env python3
"""Enforce ContinuityForge release coverage gates from ``coverage json`` output.

The gate deliberately consumes Coverage.py's JSON report so it can enforce the
statement+branch aggregate gate and separately reason about branch-only groups.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

COMBINED_MINIMUM = 80.0
GLOBAL_BRANCH_MINIMUM = 75.0
TRUSTED_BRANCH_MINIMUM = 80.0
COVERAGE_JSON_FORMAT = 3

SUMMARY_COUNT_FIELDS = (
    "covered_lines",
    "num_statements",
    "missing_lines",
    "excluded_lines",
    "num_branches",
    "num_partial_branches",
    "covered_branches",
    "missing_branches",
)

TRUSTED_MODULES = frozenset(
    {
        "src/continuityforge/audit_material.py",
        "src/continuityforge/schema.py",
        "src/continuityforge/migrations.py",
        "src/continuityforge/storage.py",
        "src/continuityforge/readonly.py",
        "src/continuityforge/inspection.py",
        "src/continuityforge/compiler.py",
        "src/continuityforge/validate.py",
        "src/continuityforge/evidence.py",
        "src/continuityforge/governance_integrity.py",
        "src/continuityforge/event_integrity.py",
        "src/continuityforge/source_integrity.py",
    }
)


class CoverageInputError(ValueError):
    """The Coverage.py JSON did not have the contract this gate needs."""


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageInputError(f"coverage JSON contains duplicate key: {key!r}")
        result[key] = value
    return result


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
    critical_file_minimums: tuple[GateResult, ...]

    @property
    def results(self) -> tuple[GateResult, ...]:
        return (
            self.combined,
            self.global_branches,
            self.trusted_branches,
            *self.critical_branches,
            *self.critical_files,
            *self.critical_file_minimums,
        )

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)


def _normalise_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise CoverageInputError("coverage path must be non-empty text")
    normalised = path.replace("\\", "/")
    if normalised.startswith("/") or (
        len(normalised) >= 2
        and normalised[0].isalpha()
        and normalised[1] == ":"
    ):
        raise CoverageInputError(f"coverage path must be repository-relative: {path!r}")
    components = normalised.split("/")
    if any(component == "" for component in components):
        raise CoverageInputError(f"coverage path contains an empty component: {path!r}")
    if any(component in {".", ".."} for component in components):
        raise CoverageInputError(f"coverage path contains a dot component: {path!r}")
    if (
        len(components) != 3
        or components[:2] != ["src", "continuityforge"]
        or not components[2].endswith(".py")
        or components[2] == ".py"
    ):
        raise CoverageInputError(
            "coverage path must match src/continuityforge/*.py: " f"{path!r}"
        )
    return "/".join(components)


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
        path = _normalise_path(raw_path)
        if path in result:
            raise CoverageInputError(
                f"coverage JSON contains duplicate normalized path: {path}"
            )
        summary = entry.get("summary")
        if not isinstance(summary, Mapping):
            raise CoverageInputError(f"coverage JSON file {raw_path!r} is missing summary")
        # Validate all counters used by every gate before calculating anything.
        for field in SUMMARY_COUNT_FIELDS:
            _summary_counts(summary, field)

        executed_lines = _line_numbers(entry, "executed_lines")
        missing_lines = _line_numbers(entry, "missing_lines")
        excluded_lines = _line_numbers(entry, "excluded_lines")
        if executed_lines & missing_lines:
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} contains overlapping executed and missing lines"
            )
        if excluded_lines & (executed_lines | missing_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} contains overlapping excluded and statement lines"
            )
        if _summary_counts(summary, "covered_lines") != len(executed_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} covered-lines summary disagrees with details"
            )
        if _summary_counts(summary, "num_statements") != len(executed_lines | missing_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} statement summary disagrees with details"
            )
        if _summary_counts(summary, "missing_lines") != len(missing_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} missing-lines summary disagrees with details"
            )
        if _summary_counts(summary, "excluded_lines") != len(excluded_lines):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} excluded-lines summary disagrees with details"
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
        if _summary_counts(summary, "num_branches") != len(
            executed_branches | missing_branches
        ):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} branch summary disagrees with details"
            )
        partial_sources = {source for source, _ in executed_branches} & {
            source for source, _ in missing_branches
        }
        if _summary_counts(summary, "num_partial_branches") != len(partial_sources):
            raise CoverageInputError(
                f"coverage JSON file {raw_path!r} partial-branches summary disagrees with details"
            )
        result[path] = entry
    return result


def _validate_metadata(payload: Mapping[str, Any]) -> None:
    meta = payload.get("meta")
    if not isinstance(meta, Mapping):
        raise CoverageInputError("coverage JSON is missing its meta mapping")
    format_version = meta.get("format")
    if type(format_version) is not int or format_version != COVERAGE_JSON_FORMAT:
        raise CoverageInputError(
            f"coverage JSON meta.format must be {COVERAGE_JSON_FORMAT}"
        )


def _validate_totals(
    payload: Mapping[str, Any], files: Mapping[str, Mapping[str, Any]]
) -> None:
    totals = payload.get("totals")
    if not isinstance(totals, Mapping):
        raise CoverageInputError("coverage JSON is missing its totals mapping")
    for field in SUMMARY_COUNT_FIELDS:
        actual = _summary_counts(totals, field)
        expected = sum(
            _summary_counts(entry["summary"], field) for entry in files.values()
        )
        if actual != expected:
            raise CoverageInputError(
                f"coverage totals field {field!r} disagrees with per-file summaries"
            )


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


def _minimum_percentage(raw_value: str, *, label: str) -> float:
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as error:
        raise CoverageInputError(f"{label} must be a percentage") from error
    if not math.isfinite(value) or value <= 0.0 or value > 100.0:
        raise CoverageInputError(f"{label} must be greater than 0 and at most 100")
    return value


def _parse_critical_file_minimum(specification: str) -> tuple[str, float, float]:
    """Parse PATH:STATEMENTS[:BRANCHES], normalizing one repository path.

    The two-field spelling applies one minimum to both metrics.  The three-field
    spelling permits a stricter statement target without pretending that
    statement and pure-branch coverage are the same measurement.
    """

    if not isinstance(specification, str):
        raise CoverageInputError(
            "critical file minimum must be PATH:STATEMENTS[:BRANCHES]"
        )
    parts = specification.rsplit(":", 2)
    if len(parts) == 2:
        raw_path, raw_statements = parts
        raw_branches = raw_statements
    elif len(parts) == 3:
        raw_path, raw_statements, raw_branches = parts
    else:
        raise CoverageInputError(
            "critical file minimum must be PATH:STATEMENTS[:BRANCHES]"
        )
    if not raw_path:
        raise CoverageInputError("critical file minimum path must not be empty")
    path = _normalise_path(raw_path)
    statements = _minimum_percentage(
        raw_statements, label="critical file statement minimum"
    )
    branches = _minimum_percentage(
        raw_branches, label="critical file branch minimum"
    )
    return path, statements, branches


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
    critical_file_minimums: Sequence[str] = (),
) -> CoverageGateReport:
    """Evaluate release gates without invoking Coverage.py itself."""
    _validate_metadata(payload)
    files = _files_from_payload(payload)
    if not files:
        raise CoverageInputError("coverage JSON contains no measured files")
    _validate_totals(payload, files)

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

    trusted_entries = [entry for path, entry in files.items() if path in TRUSTED_MODULES]
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

    file_minimum_results: list[GateResult] = []
    minimum_paths: set[str] = set()
    for specification in critical_file_minimums:
        path, statement_minimum, branch_minimum = _parse_critical_file_minimum(
            specification
        )
        if path in minimum_paths:
            raise CoverageInputError(
                f"critical file minimum path is specified more than once: {path}"
            )
        minimum_paths.add(path)
        entry = files.get(path)
        if entry is None:
            raise CoverageInputError(
                f"critical file minimum is absent from coverage JSON: {path}"
            )
        summary = entry["summary"]
        covered_lines = _summary_counts(summary, "covered_lines")
        statements = _summary_counts(summary, "num_statements")
        if statements == 0:
            raise CoverageInputError(
                f"critical file minimum has no statement opportunities: {path}"
            )
        covered_branches = _summary_counts(summary, "covered_branches")
        total_branches = covered_branches + _summary_counts(
            summary, "missing_branches"
        )
        if total_branches == 0:
            raise CoverageInputError(
                f"critical file minimum has no branch opportunities: {path}"
            )
        file_minimum_results.extend(
            (
                _gate(
                    f"critical file statements {path}",
                    covered_lines,
                    statements,
                    statement_minimum,
                ),
                _gate(
                    f"critical file pure branches {path}",
                    covered_branches,
                    total_branches,
                    branch_minimum,
                ),
            )
        )

    return CoverageGateReport(
        combined=combined,
        global_branches=global_branches,
        trusted_branches=trusted_branches,
        critical_branches=tuple(branch_results),
        critical_files=tuple(file_results),
        critical_file_minimums=tuple(file_minimum_results),
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
    parser.add_argument(
        "--critical-file-min",
        action="append",
        default=[],
        metavar="PATH:STATEMENTS[:BRANCHES]",
        help=(
            "require per-file statement and pure-branch minimums; a single "
            "percentage applies to both metrics (repeatable)"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        with args.json.open("r", encoding="utf-8") as handle:
            payload = json.load(handle, object_pairs_hook=_json_object_without_duplicates)
        if not isinstance(payload, Mapping):
            raise CoverageInputError("coverage JSON root must be an object")
        report = evaluate_coverage(
            payload,
            combined_minimum=args.combined_minimum,
            global_branch_minimum=args.global_branch_minimum,
            trusted_branch_minimum=args.trusted_branch_minimum,
            critical_branches=args.critical_branch,
            critical_files=args.critical_file,
            critical_file_minimums=args.critical_file_min,
        )
    except (CoverageInputError, OSError, json.JSONDecodeError) as error:
        print(f"COVERAGE INPUT ERROR: {error}", file=sys.stderr)
        return 2

    for result in report.results:
        print(result.render())
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
