"""Deterministic, model-independent evidence validation.

LLMs may propose claims and evidence spans, but they do not decide whether those
spans are admissible.  This module checks snapshot identity, line boundaries,
continuity isolation, quoted text, and optional SHA-256 digests before governance
is allowed to consider a proposal.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Protocol

from .exceptions import EvidenceValidationError, NotFoundError
from .ingest import extract_line_quote, source_lines

if TYPE_CHECKING:  # pragma: no cover - imports are only for static checkers
    from .models import Claim, EvidenceRef, Source, SourceSnapshot


class EvidenceStorage(Protocol):
    """Storage operations needed by deterministic evidence validation."""

    def get_snapshot(self, snapshot_id: str) -> "SourceSnapshot": ...

    def get_source(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str | None = None,
    ) -> "Source": ...


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One machine-readable reason an evidence set is inadmissible."""

    code: str
    message: str
    evidence_index: int | None = None
    snapshot_id: str | None = None
    field: str | None = None
    expected: Any = None
    actual: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation, retaining explicit nulls."""

        return {
            "code": self.code,
            "message": self.message,
            "evidence_index": self.evidence_index,
            "snapshot_id": self.snapshot_id,
            "field": self.field,
            "expected": _json_safe(self.expected),
            "actual": _json_safe(self.actual),
        }


@dataclass(slots=True)
class ValidationReport:
    """Complete validation result for a proposed claim's evidence set."""

    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "issues": [issue.to_dict() for issue in self.issues],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def raise_for_errors(self) -> None:
        """Raise the domain exception expected by governance callers."""

        if not self.is_valid:
            raise EvidenceValidationError(
                f"evidence validation failed with {len(self.issues)} issue(s)",
                report=self,
            )


def _value(obj: object, *names: str, default: Any = None) -> Any:
    """Read the first present field from a dataclass-like object or mapping."""

    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _json_safe(value: Any) -> Any:
    """Convert hostile/malformed field values into deterministic JSON values."""

    if isinstance(value, Enum):
        return _json_safe(value.value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return repr(value)


def validate_line_range_types(
    start_line: object, end_line: object
) -> tuple[int, int]:
    """Return line coordinates only when both are built-in integers.

    SQLite and Python both coerce booleans and numeric strings to integers.  This
    shared gate is intentionally stricter and is suitable for calling immediately
    before persistence as well as from evidence construction and validation.
    """

    if type(start_line) is not int or type(end_line) is not int:
        raise TypeError(
            "start_line and end_line must be built-in integers; "
            "booleans and strings are not accepted"
        )
    return start_line, end_line


def _normalize_quote(value: str) -> str:
    """Normalize only line separators, never semantic whitespace."""

    return value.replace("\r\n", "\n").replace("\r", "\n")


def quote_sha256(quote: str) -> str:
    """Hash a canonical line quote using lowercase hexadecimal SHA-256."""

    return hashlib.sha256(_normalize_quote(quote).encode("utf-8")).hexdigest()


def _normalize_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    digest = value.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[7:]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        return None
    return digest


class EvidenceValidator:
    """Validate proposed evidence against immutable stored snapshots."""

    def __init__(self, storage: EvidenceStorage) -> None:
        self.storage = storage

    def validate_claim(
        self,
        claim: "Claim | Mapping[str, Any] | object",
        evidence_refs: Iterable["EvidenceRef | Mapping[str, Any] | object"] | None = None,
    ) -> ValidationReport:
        """Validate every evidence reference for ``claim``.

        ``evidence_refs`` may be omitted when a caller supplies an object/mapping
        with an ``evidence_refs`` or ``evidence`` field.  The result always
        contains all independently discoverable issues rather than stopping at
        the first rejected span.
        """

        if evidence_refs is None:
            evidence_refs = _value(claim, "evidence_refs", "evidence", default=None)
        refs = list(evidence_refs or [])
        if not refs:
            return ValidationReport(
                [
                    ValidationIssue(
                        code="EVIDENCE_REQUIRED",
                        message="a claim proposal must cite at least one source span",
                        field="evidence_refs",
                    )
                ]
            )

        claim_continuity = _value(claim, "continuity")
        issues: list[ValidationIssue] = []
        if not isinstance(claim_continuity, str) or not claim_continuity.strip():
            issues.append(
                ValidationIssue(
                    code="CLAIM_CONTINUITY_MISSING",
                    message="claim continuity is required for source isolation",
                    field="continuity",
                    actual=claim_continuity,
                )
            )
            normalized_claim_continuity: str | None = None
        else:
            # Continuity is an opaque worldline identifier, not display text.
            # Whitespace is therefore significant once non-emptiness is known.
            normalized_claim_continuity = claim_continuity

        for index, evidence in enumerate(refs):
            issues.extend(
                self._validate_evidence(
                    evidence,
                    index=index,
                    claim_continuity=normalized_claim_continuity,
                )
            )
        return ValidationReport(issues)

    # Short alias useful for validation pipelines.
    validate = validate_claim

    def _validate_evidence(
        self,
        evidence: "EvidenceRef | Mapping[str, Any] | object",
        *,
        index: int,
        claim_continuity: str | None,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        snapshot_id = _value(evidence, "snapshot_id")
        if not isinstance(snapshot_id, str) or not snapshot_id.strip():
            return [
                ValidationIssue(
                    code="SNAPSHOT_ID_REQUIRED",
                    message="evidence reference must name a snapshot",
                    evidence_index=index,
                    field="snapshot_id",
                    actual=snapshot_id,
                )
            ]
        snapshot_id = snapshot_id.strip()

        raw_start = _value(evidence, "start_line", "line_start")
        raw_end = _value(evidence, "end_line", "line_end")
        try:
            start_line, end_line = validate_line_range_types(raw_start, raw_end)
        except TypeError:
            return [
                ValidationIssue(
                    code="INVALID_LINE_RANGE",
                    message="start_line and end_line must be built-in integers",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="line_range",
                    expected="built-in integer line numbers",
                    actual={"start_line": raw_start, "end_line": raw_end},
                )
            ]

        try:
            snapshot = self.storage.get_snapshot(snapshot_id)
        except (NotFoundError, KeyError, LookupError):
            snapshot = None
        if snapshot is None:
            return [
                ValidationIssue(
                    code="SNAPSHOT_NOT_FOUND",
                    message=f"snapshot does not exist: {snapshot_id}",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="snapshot_id",
                    actual=snapshot_id,
                )
            ]

        content = _value(snapshot, "content", "raw_content")
        if not isinstance(content, str):
            issues.append(
                ValidationIssue(
                    code="SNAPSHOT_CONTENT_MISSING",
                    message="snapshot has no textual content",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="content",
                )
            )
            return issues

        snapshot_continuity = _value(snapshot, "continuity")
        if not isinstance(snapshot_continuity, str) or not snapshot_continuity.strip():
            source_id = _value(snapshot, "source_id")
            if isinstance(source_id, str) and source_id:
                try:
                    source = self.storage.get_source(source_id)
                except (NotFoundError, KeyError, LookupError):
                    source = None
                if source is not None:
                    snapshot_continuity = _value(source, "continuity")

        if not isinstance(snapshot_continuity, str) or not snapshot_continuity.strip():
            issues.append(
                ValidationIssue(
                    code="SNAPSHOT_CONTINUITY_MISSING",
                    message="snapshot continuity cannot be established",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="continuity",
                    actual=snapshot_continuity,
                )
            )
        elif (
            claim_continuity is not None
            and snapshot_continuity != claim_continuity
        ):
            issues.append(
                ValidationIssue(
                    code="CONTINUITY_MISMATCH",
                    message="claim and evidence snapshot belong to different continuities",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="continuity",
                    expected=claim_continuity,
                    actual=snapshot_continuity,
                )
            )

        line_count = len(source_lines(content))
        stored_line_count = _value(snapshot, "line_count")
        if isinstance(stored_line_count, int) and stored_line_count != line_count:
            issues.append(
                ValidationIssue(
                    code="SNAPSHOT_LINE_COUNT_MISMATCH",
                    message="stored snapshot line count does not match its content",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="line_count",
                    expected=line_count,
                    actual=stored_line_count,
                )
            )

        if start_line < 1 or end_line < start_line:
            issues.append(
                ValidationIssue(
                    code="INVALID_LINE_RANGE",
                    message="expected 1 <= start_line <= end_line",
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="line_range",
                    expected="1 <= start_line <= end_line",
                    actual={"start_line": start_line, "end_line": end_line},
                )
            )
            return issues
        if end_line > line_count:
            issues.append(
                ValidationIssue(
                    code="LINE_RANGE_OUT_OF_BOUNDS",
                    message=(
                        f"line span {start_line}-{end_line} exceeds snapshot line count "
                        f"{line_count}"
                    ),
                    evidence_index=index,
                    snapshot_id=snapshot_id,
                    field="line_range",
                    expected={"minimum": 1, "maximum": line_count},
                    actual={"start_line": start_line, "end_line": end_line},
                )
            )
            return issues

        expected_quote = extract_line_quote(content, start_line, end_line)
        supplied_quote = _value(evidence, "quote")
        if supplied_quote is not None:
            if not isinstance(supplied_quote, str):
                issues.append(
                    ValidationIssue(
                        code="INVALID_QUOTE",
                        message="evidence quote must be text",
                        evidence_index=index,
                        snapshot_id=snapshot_id,
                        field="quote",
                        expected=expected_quote,
                        actual=supplied_quote,
                    )
                )
            elif _normalize_quote(supplied_quote) != expected_quote:
                issues.append(
                    ValidationIssue(
                        code="QUOTE_MISMATCH",
                        message="evidence quote does not match the cited snapshot lines",
                        evidence_index=index,
                        snapshot_id=snapshot_id,
                        field="quote",
                        expected=expected_quote,
                        actual=supplied_quote,
                    )
                )

        supplied_hash = _value(
            evidence,
            "content_hash",
            "quote_sha256",
            "sha256",
            default=None,
        )
        if supplied_hash is not None:
            normalized_hash = _normalize_digest(supplied_hash)
            expected_hash = quote_sha256(expected_quote)
            if normalized_hash is None:
                issues.append(
                    ValidationIssue(
                        code="INVALID_CONTENT_HASH",
                        message="evidence content_hash must be a SHA-256 hexadecimal digest",
                        evidence_index=index,
                        snapshot_id=snapshot_id,
                        field="content_hash",
                        expected="64 hexadecimal characters",
                        actual=supplied_hash,
                    )
                )
            elif normalized_hash != expected_hash:
                issues.append(
                    ValidationIssue(
                        code="CONTENT_HASH_MISMATCH",
                        message="evidence content hash does not match the cited snapshot lines",
                        evidence_index=index,
                        snapshot_id=snapshot_id,
                        field="content_hash",
                        expected=expected_hash,
                        actual=normalized_hash,
                    )
                )

        return issues


def build_evidence_ref(
    storage: EvidenceStorage,
    snapshot_id: str,
    start_line: int,
    end_line: int,
    *,
    include_quote: bool = True,
    include_content_hash: bool = True,
) -> "EvidenceRef":
    """Build a checked evidence reference from an immutable snapshot line span."""

    try:
        parsed_start, parsed_end = validate_line_range_types(start_line, end_line)
    except TypeError as exc:
        report = ValidationReport(
            [
                ValidationIssue(
                    code="INVALID_LINE_RANGE",
                    message=str(exc),
                    snapshot_id=snapshot_id,
                    field="line_range",
                    expected="built-in integer line numbers",
                    actual={"start_line": start_line, "end_line": end_line},
                )
            ]
        )
        raise EvidenceValidationError(report.issues[0].message, report=report) from exc

    try:
        snapshot = storage.get_snapshot(snapshot_id)
    except (NotFoundError, KeyError, LookupError) as exc:
        snapshot = None
        missing_cause: Exception | None = exc
    else:
        missing_cause = None

    if snapshot is None:
        report = ValidationReport(
            [
                ValidationIssue(
                    code="SNAPSHOT_NOT_FOUND",
                    message=f"snapshot does not exist: {snapshot_id}",
                    snapshot_id=snapshot_id,
                    field="snapshot_id",
                    actual=snapshot_id,
                )
            ]
        )
        raise EvidenceValidationError(
            report.issues[0].message, report=report
        ) from missing_cause

    content = _value(snapshot, "content", "raw_content")
    if not isinstance(content, str):
        report = ValidationReport(
            [
                ValidationIssue(
                    code="SNAPSHOT_CONTENT_MISSING",
                    message="snapshot has no textual content",
                    snapshot_id=snapshot_id,
                    field="content",
                )
            ]
        )
        raise EvidenceValidationError(report.issues[0].message, report=report)

    line_count = len(source_lines(content))
    range_code: str | None = None
    range_message: str | None = None
    if parsed_start < 1 or parsed_end < parsed_start:
        range_code = "INVALID_LINE_RANGE"
        range_message = "expected 1 <= start_line <= end_line"
    elif parsed_end > line_count:
        range_code = "LINE_RANGE_OUT_OF_BOUNDS"
        range_message = (
            f"line span {parsed_start}-{parsed_end} exceeds source line count "
            f"{line_count}"
        )

    if range_code is not None:
        report = ValidationReport(
            [
                ValidationIssue(
                    code=range_code,
                    message=range_message or "invalid line range",
                    snapshot_id=snapshot_id,
                    field="line_range",
                    actual={"start_line": start_line, "end_line": end_line},
                )
            ]
        )
        raise EvidenceValidationError(report.issues[0].message, report=report)

    quote = extract_line_quote(content, parsed_start, parsed_end)

    # Delayed import keeps ingestion and validation usable by schema tooling while
    # models/storage migrations are being inspected.
    from .models import EvidenceRef

    return EvidenceRef(
        snapshot_id=snapshot_id,
        start_line=parsed_start,
        end_line=parsed_end,
        quote=quote if include_quote else None,
        content_hash=quote_sha256(quote) if include_content_hash else None,
    )


__all__ = [
    "EvidenceStorage",
    "EvidenceValidator",
    "ValidationIssue",
    "ValidationReport",
    "build_evidence_ref",
    "quote_sha256",
    "validate_line_range_types",
]
