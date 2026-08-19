"""Immutable domain models for deterministic evidence impact analysis.

This module deliberately contains no persistence, CLI, or model-provider code.
Reports are frozen value objects so callers can cache, compare, and serialize an
impact decision without its meaning changing underneath them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class ImpactOutcome(str, Enum):
    """Deterministic relationship between old evidence and a target snapshot.

    ``INVALID_EVIDENCE`` means the supplied fields cannot serve as a
    self-consistent exact-match anchor.  It is not a complete historical
    provenance verdict, which requires the old snapshot and lineage context.
    """

    SAME_POSITION = "SAME_POSITION"
    EXACT_MOVED_UNIQUE = "EXACT_MOVED_UNIQUE"
    EXACT_MOVED_AMBIGUOUS = "EXACT_MOVED_AMBIGUOUS"
    NO_EXACT_MATCH = "NO_EXACT_MATCH"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"

    def __str__(self) -> str:
        return self.value


# Public compatibility spelling agreed for clients that prefer
# ``classification`` over ``outcome``.
ImpactClassification = ImpactOutcome


class ImpactReasonCode(str, Enum):
    """Stable, machine-readable explanation for a successful classification."""

    EXACT_AT_ORIGINAL_SPAN = "EXACT_AT_ORIGINAL_SPAN"
    EXACT_AT_ONE_DIFFERENT_SPAN = "EXACT_AT_ONE_DIFFERENT_SPAN"
    EXACT_AT_MULTIPLE_DIFFERENT_SPANS = "EXACT_AT_MULTIPLE_DIFFERENT_SPANS"
    EXACT_QUOTE_NOT_FOUND = "EXACT_QUOTE_NOT_FOUND"
    EVIDENCE_FAILED_VALIDATION = "EVIDENCE_FAILED_VALIDATION"

    def __str__(self) -> str:
        return self.value


class ImpactErrorCode(str, Enum):
    """Stable invalid-evidence codes returned inside an impact report."""

    EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
    SNAPSHOT_ID_REQUIRED = "SNAPSHOT_ID_REQUIRED"
    INVALID_LINE_RANGE = "INVALID_LINE_RANGE"
    QUOTE_REQUIRED = "QUOTE_REQUIRED"
    INVALID_QUOTE = "INVALID_QUOTE"
    INVALID_UNICODE_QUOTE = "INVALID_UNICODE_QUOTE"
    QUOTE_SPAN_MISMATCH = "QUOTE_SPAN_MISMATCH"
    INVALID_CONTENT_HASH = "INVALID_CONTENT_HASH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"

    def __str__(self) -> str:
        return self.value


class ImpactTargetError(ValueError):
    """Caller error raised when the target snapshot itself is unavailable/bad.

    A missing target version is not a property of the old evidence and must not
    be collapsed into ``INVALID_EVIDENCE``.  The stable ``code`` lets callers
    distinguish lookup/input failures without parsing the message.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# Short spelling for callers that frame target lookup as a snapshot concern.
TargetSnapshotError = ImpactTargetError


@dataclass(frozen=True, order=True, slots=True)
class ImpactCandidate:
    """One exact occurrence of the old quote in the target snapshot.

    Ordering is deliberately line-position ordering.  Reports additionally
    normalize candidate iterables to this order, making output stable even when
    a caller constructs a report directly.
    """

    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if type(self.start_line) is not int:
            raise TypeError("start_line must be an integer")
        if type(self.end_line) is not int:
            raise TypeError("end_line must be an integer")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("expected 1 <= start_line <= end_line")

    @property
    def span(self) -> tuple[int, int]:
        return (self.start_line, self.end_line)

    @property
    def line_start(self) -> int:
        return self.start_line

    @property
    def line_end(self) -> int:
        return self.end_line

    @property
    def target_start_line(self) -> int:
        return self.start_line

    @property
    def target_end_line(self) -> int:
        return self.end_line

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1

    def to_dict(self) -> dict[str, int]:
        return {"start_line": self.start_line, "end_line": self.end_line}


@dataclass(frozen=True, slots=True)
class ImpactReport:
    """Frozen result of analyzing one old evidence reference.

    ``original_*`` retains the old coordinates when they are real integers,
    including coordinates that later prove invalid.  ``candidates`` is always a
    sorted tuple, never a mutable list.
    """

    outcome: ImpactOutcome
    old_snapshot_id: str | None
    target_snapshot_id: str
    target_snapshot_version: int
    original_start_line: int | None
    original_end_line: int | None
    candidates: tuple[ImpactCandidate, ...]
    reason_code: ImpactReasonCode
    reason: str
    error_code: ImpactErrorCode | None = None

    def __post_init__(self) -> None:
        outcome = ImpactOutcome(self.outcome)
        object.__setattr__(self, "outcome", outcome)
        normalized_candidates = tuple(
            sorted(tuple(self.candidates), key=lambda item: (item.start_line, item.end_line))
        )
        object.__setattr__(self, "candidates", normalized_candidates)

        if len(set(normalized_candidates)) != len(normalized_candidates):
            raise ValueError("candidates must contain unique line spans")

        if not isinstance(self.target_snapshot_id, str) or not self.target_snapshot_id:
            raise ValueError("target_snapshot_id must be non-empty")
        if (
            type(self.target_snapshot_version) is not int
            or self.target_snapshot_version < 1
        ):
            raise ValueError("target_snapshot_version must be a positive integer")
        reason_code = ImpactReasonCode(self.reason_code)
        object.__setattr__(self, "reason_code", reason_code)
        expected_reason_codes = {
            ImpactOutcome.SAME_POSITION: ImpactReasonCode.EXACT_AT_ORIGINAL_SPAN,
            ImpactOutcome.EXACT_MOVED_UNIQUE: (
                ImpactReasonCode.EXACT_AT_ONE_DIFFERENT_SPAN
            ),
            ImpactOutcome.EXACT_MOVED_AMBIGUOUS: (
                ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS
            ),
            ImpactOutcome.NO_EXACT_MATCH: ImpactReasonCode.EXACT_QUOTE_NOT_FOUND,
            ImpactOutcome.INVALID_EVIDENCE: (
                ImpactReasonCode.EVIDENCE_FAILED_VALIDATION
            ),
        }
        if reason_code is not expected_reason_codes[outcome]:
            raise ValueError(
                f"reason_code {reason_code.value} is inconsistent with {outcome.value}"
            )
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("reason must be non-empty")
        if outcome is ImpactOutcome.INVALID_EVIDENCE:
            if self.error_code is None:
                raise ValueError("invalid-evidence reports require error_code")
            object.__setattr__(self, "error_code", ImpactErrorCode(self.error_code))
            if normalized_candidates:
                raise ValueError("invalid-evidence reports cannot contain candidates")
        elif self.error_code is not None:
            raise ValueError("valid impact classifications cannot contain error_code")

        if outcome is not ImpactOutcome.INVALID_EVIDENCE:
            if not isinstance(self.old_snapshot_id, str) or not self.old_snapshot_id:
                raise ValueError("valid classifications require old_snapshot_id")
            if (
                type(self.original_start_line) is not int
                or type(self.original_end_line) is not int
                or self.original_start_line < 1
                or self.original_end_line < self.original_start_line
            ):
                raise ValueError("valid classifications require a valid original span")

            original = (self.original_start_line, self.original_end_line)
            original_width = self.original_end_line - self.original_start_line + 1
            if any(candidate.line_count != original_width for candidate in normalized_candidates):
                raise ValueError("candidate widths must equal the original evidence width")

            at_original = any(candidate.span == original for candidate in normalized_candidates)
            if outcome is ImpactOutcome.SAME_POSITION and not at_original:
                raise ValueError("SAME_POSITION requires a candidate at the original span")
            if outcome is ImpactOutcome.EXACT_MOVED_UNIQUE and (
                len(normalized_candidates) != 1 or at_original
            ):
                raise ValueError(
                    "EXACT_MOVED_UNIQUE requires one candidate away from the original span"
                )
            if outcome is ImpactOutcome.EXACT_MOVED_AMBIGUOUS and (
                len(normalized_candidates) < 2 or at_original
            ):
                raise ValueError(
                    "EXACT_MOVED_AMBIGUOUS requires multiple candidates away from "
                    "the original span"
                )
            if outcome is ImpactOutcome.NO_EXACT_MATCH and normalized_candidates:
                raise ValueError("NO_EXACT_MATCH reports cannot contain candidates")

    @property
    def classification(self) -> ImpactOutcome:
        """Compatibility alias for :attr:`outcome`."""

        return self.outcome

    @property
    def evidence_snapshot_id(self) -> str | None:
        return self.old_snapshot_id

    @property
    def source_snapshot_id(self) -> str | None:
        return self.old_snapshot_id

    @property
    def target_version(self) -> int:
        return self.target_snapshot_version

    @property
    def original_span(self) -> tuple[int, int] | None:
        if self.original_start_line is None or self.original_end_line is None:
            return None
        return (self.original_start_line, self.original_end_line)

    @property
    def candidate_spans(self) -> tuple[tuple[int, int], ...]:
        return tuple(candidate.span for candidate in self.candidates)

    @property
    def is_valid_evidence(self) -> bool:
        return self.outcome is not ImpactOutcome.INVALID_EVIDENCE

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-safe representation."""

        original_span = None
        if self.original_span is not None:
            original_span = {
                "start_line": self.original_span[0],
                "end_line": self.original_span[1],
            }
        return {
            "outcome": self.outcome.value,
            "classification": self.outcome.value,
            "old_snapshot_id": self.old_snapshot_id,
            "target_snapshot_id": self.target_snapshot_id,
            "target_snapshot_version": self.target_snapshot_version,
            "original_span": original_span,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "reason_code": self.reason_code.value,
            "reason": self.reason,
            "error_code": self.error_code.value if self.error_code is not None else None,
        }


def freeze_candidates(
    candidates: Iterable[ImpactCandidate],
) -> tuple[ImpactCandidate, ...]:
    """Return candidates in stable line order as an immutable tuple."""

    return tuple(sorted(tuple(candidates), key=lambda item: item.span))


# Additional descriptive aliases cost no behavior and make the domain intent
# clear in type annotations used by downstream packages.
EvidenceImpactCandidate = ImpactCandidate
EvidenceImpactReport = ImpactReport


__all__ = [
    "EvidenceImpactCandidate",
    "EvidenceImpactReport",
    "ImpactCandidate",
    "ImpactClassification",
    "ImpactErrorCode",
    "ImpactOutcome",
    "ImpactReasonCode",
    "ImpactReport",
    "ImpactTargetError",
    "TargetSnapshotError",
    "freeze_candidates",
]
