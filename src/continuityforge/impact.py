"""Pure deterministic impact analysis for evidence across source versions.

The engine performs exact line-sequence matching only.  It deliberately has no
SQLite, CLI, network, or LLM dependency: callers resolve the target
``SourceSnapshot`` and pass it in as a complete domain value.  The two-argument
API cannot establish source/continuity lineage from ``EvidenceRef`` alone;
callers must establish that boundary with ``EvidenceValidator`` or their
higher-level inspection service before interpreting the report as trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .evidence import quote_sha256
from .impact_models import (
    ImpactCandidate,
    ImpactClassification,
    ImpactErrorCode,
    ImpactOutcome,
    ImpactReasonCode,
    ImpactReport,
    ImpactTargetError,
    TargetSnapshotError,
    freeze_candidates,
)
from .ingest import DEFAULT_INGEST_LIMITS, _bounded_utf8_size, source_lines

if TYPE_CHECKING:  # pragma: no cover - runtime stays domain-value agnostic
    from .models import EvidenceRef, SourceSnapshot


# A complete ambiguous-match report is useful only while its candidate set is
# itself bounded.  Failing instead of truncating prevents callers from
# mistaking a partial set for every exact occurrence.
MAX_EXACT_CANDIDATES = 10_000
MAX_BATCH_PATTERN_LINES = 1_000_000


@dataclass(frozen=True, slots=True)
class PreparedImpactTarget:
    """A validated target whose addressable lines are materialized once."""

    snapshot_id: str
    version: int
    lines: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ImpactTargetError(
                "TARGET_SNAPSHOT_ID_REQUIRED", "target snapshot_id must be non-empty"
            )
        if type(self.version) is not int or self.version < 1:
            raise ImpactTargetError(
                "TARGET_SNAPSHOT_VERSION_INVALID",
                "target snapshot version must be a positive integer",
            )
        if not isinstance(self.lines, tuple) or any(
            not isinstance(line, str) for line in self.lines
        ):
            raise ImpactTargetError(
                "TARGET_SNAPSHOT_CONTENT_MISSING",
                "prepared target lines must be a tuple of text",
            )
        if len(self.lines) > DEFAULT_INGEST_LIMITS.max_lines:
            raise ImpactTargetError(
                "TARGET_SNAPSHOT_LINES_LIMIT",
                "target snapshot exceeds the deterministic impact line limit",
            )
        total_bytes = max(0, len(self.lines) - 1)
        try:
            for line in self.lines:
                line_bytes = len(line.encode("utf-8"))
                if line_bytes > DEFAULT_INGEST_LIMITS.max_line_bytes:
                    raise ImpactTargetError(
                        "TARGET_SNAPSHOT_LINE_BYTES_LIMIT",
                        "target snapshot contains an overlong line",
                    )
                total_bytes += line_bytes
                if total_bytes > DEFAULT_INGEST_LIMITS.max_file_bytes:
                    raise ImpactTargetError(
                        "TARGET_SNAPSHOT_BYTES_LIMIT",
                        "target snapshot exceeds the deterministic impact byte limit",
                    )
        except UnicodeEncodeError as exc:
            raise ImpactTargetError(
                "TARGET_SNAPSHOT_CONTENT_INVALID_UNICODE",
                "target snapshot content must be encodable as UTF-8",
            ) from exc


_LINE_SEPARATORS = frozenset(
    {"\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"}
)


def _bounded_line_count(content: str, *, limit: int) -> int:
    """Count ``splitlines``-style lines without first allocating a line list."""

    if not content:
        return 0
    separators = 0
    previous_was_cr = False
    last_was_separator = False
    for character in content:
        if character == "\n" and previous_was_cr:
            previous_was_cr = False
            last_was_separator = True
            continue
        is_separator = character in _LINE_SEPARATORS
        if is_separator:
            separators += 1
            if separators > limit:
                return separators
        previous_was_cr = character == "\r"
        last_was_separator = is_separator
    return separators if last_was_separator else separators + 1


_REASONS: dict[ImpactOutcome, str] = {
    ImpactOutcome.SAME_POSITION: "exact quote remains at the original line span",
    ImpactOutcome.EXACT_MOVED_UNIQUE: (
        "exact quote occurs once at a different line span"
    ),
    ImpactOutcome.EXACT_MOVED_AMBIGUOUS: (
        "exact quote occurs at multiple different line spans"
    ),
    ImpactOutcome.NO_EXACT_MATCH: "exact quote does not occur in the target snapshot",
    ImpactOutcome.INVALID_EVIDENCE: (
        "old evidence cannot serve as a self-consistent exact-match anchor"
    ),
}


_INVALID_MESSAGES: dict[ImpactErrorCode, str] = {
    ImpactErrorCode.EVIDENCE_REQUIRED: "old evidence is required",
    ImpactErrorCode.SNAPSHOT_ID_REQUIRED: "old evidence snapshot_id is required",
    ImpactErrorCode.INVALID_LINE_RANGE: (
        "old evidence must use integer lines with 1 <= start_line <= end_line"
    ),
    ImpactErrorCode.QUOTE_REQUIRED: "old evidence quote is required for exact matching",
    ImpactErrorCode.INVALID_QUOTE: "old evidence quote must be text",
    ImpactErrorCode.INVALID_UNICODE_QUOTE: (
        "old evidence quote contains Unicode that cannot be encoded as UTF-8"
    ),
    ImpactErrorCode.QUOTE_SPAN_MISMATCH: (
        "old evidence quote line count does not match its line span"
    ),
    ImpactErrorCode.INVALID_CONTENT_HASH: (
        "old evidence content_hash must be a SHA-256 hexadecimal digest"
    ),
    ImpactErrorCode.CONTENT_HASH_MISMATCH: (
        "old evidence content_hash does not match its normalized quote"
    ),
}


def _value(obj: object, *names: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _real_int(value: object) -> int | None:
    if type(value) is not int:
        return None
    return value


def _normalize_quote(value: str) -> str:
    """Mirror v0.2 evidence semantics: normalize line separators only."""

    return value.replace("\r\n", "\n").replace("\r", "\n")


def _normalize_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    digest = value.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[7:]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        return None
    return digest


def _target_fields(target_snapshot: object) -> tuple[str, int, str]:
    """Validate caller-owned target input or raise a stable caller error."""

    if target_snapshot is None:
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_REQUIRED", "target snapshot must be resolved by the caller"
        )

    snapshot_id = _value(target_snapshot, "snapshot_id", "id")
    if not isinstance(snapshot_id, str) or not snapshot_id.strip():
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_ID_REQUIRED", "target snapshot_id must be non-empty"
        )

    version = _real_int(_value(target_snapshot, "version", "target_version"))
    if version is None or version < 1:
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_VERSION_INVALID",
            "target snapshot version must be a positive integer",
        )

    content = _value(target_snapshot, "content", "raw_content")
    if not isinstance(content, str):
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_CONTENT_MISSING",
            "target snapshot must contain resolved textual content",
        )
    try:
        encoded_size = _bounded_utf8_size(
            content, DEFAULT_INGEST_LIMITS.max_file_bytes
        )
    except UnicodeEncodeError as exc:
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_CONTENT_INVALID_UNICODE",
            "target snapshot content must be encodable as UTF-8",
        ) from exc
    if encoded_size > DEFAULT_INGEST_LIMITS.max_file_bytes:
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_BYTES_LIMIT",
            "target snapshot exceeds the deterministic impact byte limit",
        )
    if _bounded_line_count(
        content, limit=DEFAULT_INGEST_LIMITS.max_lines
    ) > DEFAULT_INGEST_LIMITS.max_lines:
        raise ImpactTargetError(
            "TARGET_SNAPSHOT_LINES_LIMIT",
            "target snapshot exceeds the deterministic impact line limit",
        )

    return snapshot_id.strip(), version, content


def prepare_impact_target(target_snapshot: object) -> PreparedImpactTarget:
    """Validate and split a target once for bounded multi-evidence analysis."""

    snapshot_id, version, content = _target_fields(target_snapshot)
    return PreparedImpactTarget(
        snapshot_id=snapshot_id,
        version=version,
        lines=tuple(source_lines(content)),
    )


def _invalid_report(
    *,
    target_snapshot_id: str,
    target_snapshot_version: int,
    old_snapshot_id: str | None,
    original_start_line: int | None,
    original_end_line: int | None,
    error_code: ImpactErrorCode,
) -> ImpactReport:
    return ImpactReport(
        outcome=ImpactOutcome.INVALID_EVIDENCE,
        old_snapshot_id=old_snapshot_id,
        target_snapshot_id=target_snapshot_id,
        target_snapshot_version=target_snapshot_version,
        original_start_line=original_start_line,
        original_end_line=original_end_line,
        candidates=(),
        reason_code=ImpactReasonCode.EVIDENCE_FAILED_VALIDATION.value,
        reason=_INVALID_MESSAGES[error_code],
        error_code=error_code.value,
    )


def _exact_candidates(
    target_lines: tuple[str, ...], quote_lines: tuple[str, ...]
) -> tuple[ImpactCandidate, ...]:
    """Find every exact line-sequence occurrence in stable source order.

    Knuth-Morris-Pratt matching keeps the pure domain API linear in the number
    of target and quote lines, while retaining overlapping occurrences.
    """

    width = len(quote_lines)
    if width < 1 or width > len(target_lines):
        return ()

    prefix = [0] * width
    matched = 0
    for index in range(1, width):
        while matched and quote_lines[index] != quote_lines[matched]:
            matched = prefix[matched - 1]
        if quote_lines[index] == quote_lines[matched]:
            matched += 1
            prefix[index] = matched

    matches: list[ImpactCandidate] = []
    matched = 0
    for target_index, target_line in enumerate(target_lines):
        while matched and target_line != quote_lines[matched]:
            matched = prefix[matched - 1]
        if target_line == quote_lines[matched]:
            matched += 1
        if matched == width:
            zero_based_start = target_index - width + 1
            start_line = zero_based_start + 1
            if len(matches) >= MAX_EXACT_CANDIDATES:
                raise ImpactTargetError(
                    "TOO_MANY_EXACT_MATCHES",
                    "target snapshot contains more than "
                    f"{MAX_EXACT_CANDIDATES} exact evidence matches",
                )
            matches.append(
                ImpactCandidate(
                    start_line=start_line,
                    end_line=start_line + width - 1,
                )
            )
            matched = prefix[matched - 1]
    return freeze_candidates(matches)


def _report_from_candidates(
    *,
    old_snapshot_id: str,
    target: PreparedImpactTarget,
    start_line: int,
    end_line: int,
    candidates: tuple[ImpactCandidate, ...],
) -> ImpactReport:
    original = (start_line, end_line)
    has_original = any(candidate.span == original for candidate in candidates)
    if has_original:
        outcome = ImpactOutcome.SAME_POSITION
        reason_code = ImpactReasonCode.EXACT_AT_ORIGINAL_SPAN
    elif len(candidates) == 1:
        outcome = ImpactOutcome.EXACT_MOVED_UNIQUE
        reason_code = ImpactReasonCode.EXACT_AT_ONE_DIFFERENT_SPAN
    elif len(candidates) > 1:
        outcome = ImpactOutcome.EXACT_MOVED_AMBIGUOUS
        reason_code = ImpactReasonCode.EXACT_AT_MULTIPLE_DIFFERENT_SPANS
    else:
        outcome = ImpactOutcome.NO_EXACT_MATCH
        reason_code = ImpactReasonCode.EXACT_QUOTE_NOT_FOUND
    return ImpactReport(
        outcome=outcome,
        old_snapshot_id=old_snapshot_id,
        target_snapshot_id=target.snapshot_id,
        target_snapshot_version=target.version,
        original_start_line=start_line,
        original_end_line=end_line,
        candidates=candidates,
        reason_code=reason_code.value,
        reason=_REASONS[outcome],
    )


def analyze_validated_evidence_batch(
    evidence_items: Iterable["EvidenceRef"],
    target: PreparedImpactTarget,
    *,
    max_total_candidates: int,
) -> tuple[ImpactReport, ...]:
    """Analyze canonical evidence anchors with one multi-pattern target scan.

    This boundary is intentionally narrower than :func:`analyze_evidence_impact`:
    callers must first validate each anchor against its old immutable snapshot.
    InspectionService does so before calling this function.  An Aho-Corasick
    trie over line tokens avoids an O(evidence * target-lines) set of KMP scans.
    """

    if not isinstance(target, PreparedImpactTarget):
        raise TypeError("target must be PreparedImpactTarget")
    if type(max_total_candidates) is not int or max_total_candidates < 1:
        raise ValueError("max_total_candidates must be a positive integer")
    items = tuple(evidence_items)
    anchors: list[tuple[str, int, int]] = []
    pattern_ids: dict[tuple[str, ...], int] = {}
    patterns: list[tuple[str, ...]] = []
    anchor_patterns: list[int] = []
    pattern_line_total = 0
    for evidence in items:
        old_id = evidence.snapshot_id
        start_line = evidence.start_line
        end_line = evidence.end_line
        quote = evidence.quote
        if (
            not isinstance(old_id, str)
            or not old_id
            or type(start_line) is not int
            or type(end_line) is not int
            or start_line < 1
            or end_line < start_line
            or not isinstance(quote, str)
        ):
            raise ValueError("batch impact requires canonical validated evidence")
        quote_lines = tuple(_normalize_quote(quote).split("\n"))
        if len(quote_lines) != end_line - start_line + 1:
            raise ValueError("batch impact evidence quote span is inconsistent")
        pattern_id = pattern_ids.get(quote_lines)
        if pattern_id is None:
            pattern_line_total += len(quote_lines)
            if pattern_line_total > MAX_BATCH_PATTERN_LINES:
                raise ImpactTargetError(
                    "IMPACT_PATTERN_LINES_LIMIT_EXCEEDED",
                    "validated evidence patterns exceed the batch line limit",
                )
            pattern_id = len(patterns)
            pattern_ids[quote_lines] = pattern_id
            patterns.append(quote_lines)
        anchors.append((old_id, start_line, end_line))
        anchor_patterns.append(pattern_id)

    # Each trie node stores line-token transitions, a failure link, and the
    # patterns ending at that node.  Pattern material is already bounded by
    # snapshot/evidence inspection limits.
    transitions: list[dict[str, int]] = [{}]
    failures: list[int] = [0]
    outputs: list[list[int]] = [[]]
    for pattern_id, pattern in enumerate(patterns):
        state = 0
        for token in pattern:
            next_state = transitions[state].get(token)
            if next_state is None:
                next_state = len(transitions)
                transitions[state][token] = next_state
                transitions.append({})
                failures.append(0)
                outputs.append([])
            state = next_state
        outputs[state].append(pattern_id)

    pending: deque[int] = deque()
    for child in transitions[0].values():
        pending.append(child)
    while pending:
        state = pending.popleft()
        for token, child in transitions[state].items():
            pending.append(child)
            fallback = failures[state]
            while fallback and token not in transitions[fallback]:
                fallback = failures[fallback]
            failures[child] = transitions[fallback].get(token, 0)
            outputs[child].extend(outputs[failures[child]])

    matches: list[list[ImpactCandidate]] = [[] for _ in patterns]
    pattern_uses = [0 for _ in patterns]
    for pattern_id in anchor_patterns:
        pattern_uses[pattern_id] += 1
    emitted_report_candidates = 0
    state = 0
    for target_index, token in enumerate(target.lines):
        while state and token not in transitions[state]:
            state = failures[state]
        state = transitions[state].get(token, 0)
        for pattern_id in outputs[state]:
            emitted_report_candidates += pattern_uses[pattern_id]
            if emitted_report_candidates > max_total_candidates:
                raise ImpactTargetError(
                    "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED",
                    "source impact candidates exceed the aggregate report limit",
                )
            pattern_width = len(patterns[pattern_id])
            start_line = target_index - pattern_width + 2
            pattern_matches = matches[pattern_id]
            if len(pattern_matches) >= MAX_EXACT_CANDIDATES:
                raise ImpactTargetError(
                    "TOO_MANY_EXACT_MATCHES",
                    "target snapshot contains more than "
                    f"{MAX_EXACT_CANDIDATES} exact evidence matches",
                )
            pattern_matches.append(
                ImpactCandidate(
                    start_line=start_line,
                    end_line=start_line + pattern_width - 1,
                )
            )

    reports: list[ImpactReport] = []
    total_candidates = 0
    for anchor, pattern_id in zip(anchors, anchor_patterns):
        old_id, start_line, end_line = anchor
        candidates = tuple(matches[pattern_id])
        total_candidates += len(candidates)
        if total_candidates > max_total_candidates:
            raise ImpactTargetError(
                "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED",
                "source impact candidates exceed the aggregate report limit",
            )
        reports.append(
            _report_from_candidates(
                old_snapshot_id=old_id,
                target=target,
                start_line=start_line,
                end_line=end_line,
                candidates=candidates,
            )
        )
    return tuple(reports)


def analyze_prepared_evidence_impact(
    evidence: "EvidenceRef | Mapping[str, Any] | object",
    target: PreparedImpactTarget,
) -> ImpactReport:
    """Classify one old evidence reference against a prepared target.

    Classification priority is intentional:

    1. an exact occurrence at the original coordinates is ``SAME_POSITION``
       even when duplicate occurrences also exist;
    2. one exact occurrence elsewhere is ``EXACT_MOVED_UNIQUE``;
    3. multiple exact occurrences elsewhere are ``EXACT_MOVED_AMBIGUOUS``;
    4. no occurrence is ``NO_EXACT_MATCH``.

    Malformed old evidence produces a frozen ``INVALID_EVIDENCE`` report.  That
    outcome means only that the supplied fields cannot form a self-consistent
    exact-match anchor; it does not revalidate historical provenance.
    Missing/malformed target snapshot input raises :class:`ImpactTargetError`
    because target resolution belongs to the caller.

    This pure two-value operation does not claim that ``target_snapshot`` is a
    later version of the evidence's logical source: ``EvidenceRef`` contains an
    old snapshot ID but no source/continuity lineage.  That check belongs to the
    caller's storage-aware validation/inspection boundary.
    """

    if not isinstance(target, PreparedImpactTarget):
        raise TypeError("target must be PreparedImpactTarget")
    target_id = target.snapshot_id
    target_version = target.version

    if evidence is None:
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=None,
            original_start_line=None,
            original_end_line=None,
            error_code=ImpactErrorCode.EVIDENCE_REQUIRED,
        )

    raw_old_snapshot_id = _value(evidence, "snapshot_id")
    if not isinstance(raw_old_snapshot_id, str) or not raw_old_snapshot_id.strip():
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=None,
            original_start_line=_real_int(_value(evidence, "start_line", "line_start")),
            original_end_line=_real_int(_value(evidence, "end_line", "line_end")),
            error_code=ImpactErrorCode.SNAPSHOT_ID_REQUIRED,
        )
    old_snapshot_id = raw_old_snapshot_id.strip()

    raw_start = _value(evidence, "start_line", "line_start")
    raw_end = _value(evidence, "end_line", "line_end")
    start_line = _real_int(raw_start)
    end_line = _real_int(raw_end)
    if (
        start_line is None
        or end_line is None
        or start_line < 1
        or end_line < start_line
    ):
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=old_snapshot_id,
            original_start_line=start_line,
            original_end_line=end_line,
            error_code=ImpactErrorCode.INVALID_LINE_RANGE,
        )

    supplied_quote = _value(evidence, "quote")
    if supplied_quote is None:
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=old_snapshot_id,
            original_start_line=start_line,
            original_end_line=end_line,
            error_code=ImpactErrorCode.QUOTE_REQUIRED,
        )
    if not isinstance(supplied_quote, str):
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=old_snapshot_id,
            original_start_line=start_line,
            original_end_line=end_line,
            error_code=ImpactErrorCode.INVALID_QUOTE,
        )

    normalized_quote = _normalize_quote(supplied_quote)
    try:
        quote_bytes = _bounded_utf8_size(
            normalized_quote, DEFAULT_INGEST_LIMITS.max_file_bytes
        )
    except UnicodeEncodeError:
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=old_snapshot_id,
            original_start_line=start_line,
            original_end_line=end_line,
            error_code=ImpactErrorCode.INVALID_UNICODE_QUOTE,
        )
    if quote_bytes > DEFAULT_INGEST_LIMITS.max_file_bytes:
        raise ImpactTargetError(
            "EVIDENCE_QUOTE_BYTES_LIMIT",
            "evidence quote exceeds the deterministic impact byte limit",
        )
    # Quote semantics use literal LF splitting so a trailing LF cites one more
    # blank line; count it without allocating the eventual tuple first.
    if normalized_quote.count("\n") + 1 > DEFAULT_INGEST_LIMITS.max_lines:
        raise ImpactTargetError(
            "EVIDENCE_QUOTE_LINES_LIMIT",
            "evidence quote exceeds the deterministic impact line limit",
        )
    # Evidence quotes are canonical LF-joined lines.  Literal splitting is
    # necessary here: ``""`` represents one cited blank line, and ``"\n"``
    # represents two cited blank lines.
    quote_lines = tuple(normalized_quote.split("\n"))
    if len(quote_lines) != end_line - start_line + 1:
        return _invalid_report(
            target_snapshot_id=target_id,
            target_snapshot_version=target_version,
            old_snapshot_id=old_snapshot_id,
            original_start_line=start_line,
            original_end_line=end_line,
            error_code=ImpactErrorCode.QUOTE_SPAN_MISMATCH,
        )

    supplied_hash = _value(
        evidence, "content_hash", "quote_sha256", "sha256", default=None
    )
    if supplied_hash is not None:
        normalized_hash = _normalize_digest(supplied_hash)
        if normalized_hash is None:
            return _invalid_report(
                target_snapshot_id=target_id,
                target_snapshot_version=target_version,
                old_snapshot_id=old_snapshot_id,
                original_start_line=start_line,
                original_end_line=end_line,
                error_code=ImpactErrorCode.INVALID_CONTENT_HASH,
            )
        if normalized_hash != quote_sha256(normalized_quote):
            return _invalid_report(
                target_snapshot_id=target_id,
                target_snapshot_version=target_version,
                old_snapshot_id=old_snapshot_id,
                original_start_line=start_line,
                original_end_line=end_line,
                error_code=ImpactErrorCode.CONTENT_HASH_MISMATCH,
            )

    candidates = _exact_candidates(target.lines, quote_lines)
    return _report_from_candidates(
        old_snapshot_id=old_snapshot_id,
        target=target,
        start_line=start_line,
        end_line=end_line,
        candidates=candidates,
    )


def analyze_evidence_impact(
    evidence: "EvidenceRef | Mapping[str, Any] | object",
    target_snapshot: "SourceSnapshot | Mapping[str, Any] | object",
) -> ImpactReport:
    """Compatibility API that prepares one target and analyzes one evidence."""

    return analyze_prepared_evidence_impact(
        evidence,
        prepare_impact_target(target_snapshot),
    )


class ImpactEngine:
    """Stateless façade for dependency-injected domain workflows."""

    __slots__ = ()

    @staticmethod
    def analyze(
        evidence: "EvidenceRef | Mapping[str, Any] | object",
        target_snapshot: "SourceSnapshot | Mapping[str, Any] | object",
    ) -> ImpactReport:
        return analyze_evidence_impact(evidence, target_snapshot)

    @staticmethod
    def prepare(target_snapshot: object) -> PreparedImpactTarget:
        return prepare_impact_target(target_snapshot)

    @staticmethod
    def analyze_prepared(
        evidence: "EvidenceRef | Mapping[str, Any] | object",
        target: PreparedImpactTarget,
    ) -> ImpactReport:
        return analyze_prepared_evidence_impact(evidence, target)

    @staticmethod
    def analyze_validated_batch(
        evidence_items: Iterable["EvidenceRef"],
        target: PreparedImpactTarget,
        *,
        max_total_candidates: int,
    ) -> tuple[ImpactReport, ...]:
        return analyze_validated_evidence_batch(
            evidence_items,
            target,
            max_total_candidates=max_total_candidates,
        )

    classify = analyze


# Straightforward aliases for call sites that use "classify" or omit the
# evidence qualifier.  All paths execute the same deterministic function.
classify_evidence_impact = analyze_evidence_impact
analyze_impact = analyze_evidence_impact


__all__ = [
    "ImpactCandidate",
    "ImpactClassification",
    "ImpactEngine",
    "ImpactErrorCode",
    "ImpactOutcome",
    "ImpactReasonCode",
    "ImpactReport",
    "ImpactTargetError",
    "MAX_BATCH_PATTERN_LINES",
    "MAX_EXACT_CANDIDATES",
    "PreparedImpactTarget",
    "TargetSnapshotError",
    "analyze_evidence_impact",
    "analyze_prepared_evidence_impact",
    "analyze_validated_evidence_batch",
    "analyze_impact",
    "classify_evidence_impact",
    "prepare_impact_target",
]
