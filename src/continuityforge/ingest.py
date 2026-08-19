"""Source ingestion for immutable, versioned snapshots.

This module deliberately keeps parsing shallow: the exact decoded source text is
stored in a :class:`SourceSnapshot`, while format-specific extraction belongs to
the claim-proposal layer.  That separation makes line-level provenance stable
even when proposal models or parsers change.
"""

from __future__ import annotations

import codecs
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - imports are only for static checkers
    from .models import Source, SourceSnapshot


MEDIA_TYPES: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".json": "application/json",
    ".srt": "application/x-subrip",
}


class SourceInputError(ValueError):
    """Base class for stable, machine-identifiable source input failures."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class SourceLimitError(SourceInputError):
    """Source input exceeded a configured resource boundary."""


class UnsafeSourceError(SourceInputError):
    """Source input contains a control character disabled by policy."""


class SourceDecodeError(SourceInputError):
    """Source bytes could not be decoded deterministically."""


@dataclass(frozen=True, slots=True)
class IngestLimits:
    """Resource and control-character policy for untrusted source material.

    Limits use bytes rather than code points so a small character count cannot
    conceal a large UTF-8 allocation.  Defaults are intentionally generous for
    books and transcripts while bounding accidental or adversarial inputs.
    """

    max_file_bytes: int = 16 * 1024 * 1024
    max_lines: int = 200_000
    max_line_bytes: int = 1024 * 1024
    max_json_depth: int = 256
    reject_nul: bool = True
    reject_ansi: bool = True
    reject_bidi_controls: bool = True

    def __post_init__(self) -> None:
        for name in (
            "max_file_bytes",
            "max_lines",
            "max_line_bytes",
            "max_json_depth",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive built-in integer")
        for name in ("reject_nul", "reject_ansi", "reject_bidi_controls"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")


DEFAULT_INGEST_LIMITS = IngestLimits()


_BIDI_CONTROLS = frozenset(
    {
        "\u061c",  # ARABIC LETTER MARK
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    }
)

_LINE_SEPARATORS = frozenset(
    {"\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"}
)


def _bounded_source_line_count(content: str, limit: int) -> int:
    """Count splitlines-style records without allocating an unbounded list."""

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


def _bounded_utf8_size(content: str, limit: int) -> int:
    """Measure UTF-8 size with bounded temporary allocations."""

    total = 0
    for offset in range(0, len(content), 64 * 1024):
        total += len(content[offset : offset + 64 * 1024].encode("utf-8"))
        if total > limit:
            return total
    return total


class SnapshotIngestStorage(Protocol):
    """The small storage surface required by :func:`ingest_path`."""

    def ingest_snapshot(
        self,
        source_key: str,
        continuity: str,
        content: str,
        media_type: str = "text/plain",
        origin_path: str | None = None,
    ) -> tuple["Source", "SourceSnapshot", bool]:
        """Create or reuse a content-addressed source snapshot."""


def source_lines(content: str) -> list[str]:
    """Return the addressable source lines used by evidence references.

    Line numbers are one-based and line endings are not part of a line's text.
    Python's ``splitlines`` handles LF, CRLF, CR, and Unicode separators while
    preserving all other whitespace.  An empty source therefore has zero
    addressable lines and a trailing newline does not manufacture an extra line.
    """

    return content.splitlines()


def extract_line_quote(content: str, start_line: int, end_line: int) -> str:
    """Extract an inclusive, one-based line span using canonical LF separators.

    ``ValueError`` is raised for malformed or out-of-bounds spans.  Canonical LF
    separators make an evidence digest independent of the source file's platform
    line-ending convention; the snapshot itself still retains the original text.
    """

    lines = source_lines(content)
    if type(start_line) is not int or type(end_line) is not int:
        raise TypeError("line numbers must be built-in integers")
    if start_line < 1 or end_line < start_line:
        raise ValueError("expected 1 <= start_line <= end_line")
    if end_line > len(lines):
        raise ValueError(
            f"line span {start_line}-{end_line} exceeds source line count {len(lines)}"
        )
    return "\n".join(lines[start_line - 1 : end_line])


def _decode_source(data: bytes, *, encoding: str | None = None) -> str:
    """Decode source bytes without normalizing their textual content."""

    if encoding is not None:
        if not isinstance(encoding, str) or not encoding.strip():
            raise SourceDecodeError(
                "source decoding failed: encoding must be a non-empty string",
                code="SOURCE_DECODE_ERROR",
            )
        try:
            codecs.lookup(encoding)
        except LookupError as exc:
            raise SourceDecodeError(
                f"source decoding failed: unknown text encoding {encoding!r}",
                code="SOURCE_DECODE_ERROR",
            ) from exc
        selected_encoding = encoding
        encoding_label = encoding
    elif data.startswith(codecs.BOM_UTF8):
        selected_encoding = "utf-8-sig"
        encoding_label = "UTF-8 BOM"
    elif data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        selected_encoding = "utf-32"
        encoding_label = "UTF-32 BOM"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        selected_encoding = "utf-16"
        encoding_label = "UTF-16 BOM"
    else:
        selected_encoding = "utf-8"
        encoding_label = "UTF-8"

    try:
        return data.decode(selected_encoding)
    except (UnicodeDecodeError, UnicodeError) as exc:
        raise SourceDecodeError(
            f"source decoding failed: invalid {encoding_label} text",
            code="SOURCE_DECODE_ERROR",
        ) from exc


def _resolve_limits(limits: IngestLimits | None) -> IngestLimits:
    if limits is None:
        return DEFAULT_INGEST_LIMITS
    if not isinstance(limits, IngestLimits):
        raise TypeError("limits must be an IngestLimits instance")
    return limits


def _unsafe_control(content: str, limits: IngestLimits) -> tuple[str, int] | None:
    """Return ``(issue_code, offset)`` for the first disabled control."""

    for offset, character in enumerate(content):
        if limits.reject_nul and character == "\x00":
            return "NUL_BYTE", offset
        if limits.reject_ansi and character in {"\x1b", "\x9b"}:
            return "ANSI_CONTROL", offset
        if limits.reject_bidi_controls and character in _BIDI_CONTROLS:
            return "BIDI_CONTROL", offset
    return None


def _check_controls(content: str, limits: IngestLimits, *, context: str) -> None:
    unsafe = _unsafe_control(content, limits)
    if unsafe is None:
        return
    code, offset = unsafe
    names = {
        "NUL_BYTE": "NUL byte",
        "ANSI_CONTROL": "ANSI escape/control",
        "BIDI_CONTROL": "bidirectional control",
    }
    raise UnsafeSourceError(
        f"unsafe source text: {names[code]} at character offset {offset} ({context})",
        code=code,
    )


def _validate_content_limits(content: str, limits: IngestLimits) -> None:
    try:
        encoded_size = _bounded_utf8_size(content, limits.max_file_bytes)
    except UnicodeEncodeError as exc:
        raise UnsafeSourceError(
            "unsafe source text: unpaired Unicode surrogate",
            code="INVALID_UNICODE",
        ) from exc
    if encoded_size > limits.max_file_bytes:
        raise SourceLimitError(
            f"source exceeds max_file_bytes: {encoded_size} > {limits.max_file_bytes}",
            code="MAX_FILE_BYTES",
        )

    line_count = _bounded_source_line_count(content, limits.max_lines)
    if line_count > limits.max_lines:
        raise SourceLimitError(
            f"source exceeds max_lines: {line_count} > {limits.max_lines}",
            code="MAX_LINES",
        )
    lines = source_lines(content)
    for line_number, line in enumerate(lines, start=1):
        line_size = _bounded_utf8_size(line, limits.max_line_bytes)
        if line_size > limits.max_line_bytes:
            raise SourceLimitError(
                "source line exceeds max_line_bytes: "
                f"line {line_number} has {line_size} bytes; "
                f"limit is {limits.max_line_bytes}",
                code="MAX_LINE_BYTES",
            )


class _DuplicateJSONKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


class _NonFiniteJSONNumberError(ValueError):
    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(key)
        result[key] = value
    return result


def _reject_nonfinite_json_number(token: str) -> None:
    """Reject the non-standard NaN/Infinity extensions accepted by stdlib JSON."""

    raise _NonFiniteJSONNumberError(token)


def _check_json_values(value: Any, limits: IngestLimits) -> None:
    """Apply control policy to decoded JSON strings, including escaped controls."""

    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > limits.max_json_depth:
            raise SourceInputError(
                "invalid JSON: nesting depth exceeds configured limit",
                code="JSON_NESTING_LIMIT",
            )
        if isinstance(item, str):
            _check_controls(item, limits, context="decoded JSON string")
        elif isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item.keys())
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def _decode_json(content: str, limits: IngestLimits) -> Any:
    """Decode one JSON value under the shared deterministic safety policy."""

    try:
        decoded = json.loads(
            content,
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_nonfinite_json_number,
        )
    except _DuplicateJSONKeyError as exc:
        raise SourceInputError(
            f"duplicate JSON object key: {exc.key!r}",
            code="DUPLICATE_JSON_KEY",
        ) from exc
    except _NonFiniteJSONNumberError as exc:
        raise SourceInputError(
            f"invalid JSON non-finite number: {exc.token}",
            code="NONFINITE_JSON_NUMBER",
        ) from exc
    except json.JSONDecodeError as exc:
        raise SourceInputError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
            code="INVALID_JSON",
        ) from exc
    except RecursionError as exc:
        raise SourceInputError(
            "invalid JSON: nesting depth exceeds parser capacity",
            code="JSON_NESTING_LIMIT",
        ) from exc
    except MemoryError as exc:
        raise SourceInputError(
            "invalid JSON: parser resource capacity exhausted",
            code="JSON_RESOURCE_EXHAUSTED",
        ) from exc
    _check_json_values(decoded, limits)
    return decoded


def parse_json_content(
    content: str, *, limits: IngestLimits | None = None
) -> Any:
    """Parse untrusted JSON with the same bounds used for source ingestion.

    This entry point is shared by structured CLI fields so they cannot bypass
    duplicate-key, non-finite-number, control-character, size, or nesting
    checks merely because they are not stored as a ``SourceSnapshot``.
    """

    if not isinstance(content, str):
        raise TypeError("JSON content must be text")
    policy = _resolve_limits(limits)
    _validate_content_limits(content, policy)
    _check_controls(content, policy, context="JSON input")
    return _decode_json(content, policy)


def _validate_format(content: str, suffix: str, limits: IngestLimits) -> None:
    """Reject malformed structured input while leaving its spelling untouched."""

    if suffix == ".json":
        _decode_json(content, limits)


def _read_source_bytes(path: Path, limits: IngestLimits) -> bytes:
    """Read no more than the configured maximum plus one sentinel byte."""

    size = path.stat().st_size
    if size > limits.max_file_bytes:
        raise SourceLimitError(
            f"source exceeds max_file_bytes: {size} > {limits.max_file_bytes}",
            code="MAX_FILE_BYTES",
        )
    with path.open("rb") as stream:
        data = stream.read(limits.max_file_bytes + 1)
    if len(data) > limits.max_file_bytes:
        raise SourceLimitError(
            "source exceeds max_file_bytes while reading: "
            f"> {limits.max_file_bytes}",
            code="MAX_FILE_BYTES",
        )
    return data


def ingest_content(
    storage: SnapshotIngestStorage,
    content: str,
    source_key: str,
    continuity: str,
    *,
    media_type: str = "text/plain",
    origin_path: str | None = None,
    limits: IngestLimits | None = None,
) -> tuple["Source", "SourceSnapshot", bool]:
    """Persist source text through the storage versioning boundary.

    ``source_key`` is a logical identifier only within ``continuity``.  Storage
    owns version allocation, deduplication, and ``previous_snapshot_id`` links so
    concurrent importers cannot create competing versions in application code.
    """

    if not isinstance(content, str):
        raise TypeError("content must be text")
    if not isinstance(source_key, str) or not source_key.strip():
        raise ValueError("source_key must be a non-empty string")
    if not isinstance(continuity, str) or not continuity.strip():
        raise ValueError("continuity must be a non-empty string")
    if not isinstance(media_type, str) or not media_type.strip():
        raise ValueError("media_type must be a non-empty string")

    policy = _resolve_limits(limits)
    _validate_content_limits(content, policy)
    _check_controls(content, policy, context="source")
    if media_type.split(";", 1)[0].strip().lower() == "application/json":
        _validate_format(content, ".json", policy)

    return storage.ingest_snapshot(
        source_key=source_key.strip(),
        continuity=continuity.strip(),
        content=content,
        media_type=media_type,
        origin_path=origin_path,
    )


def ingest_path(
    storage: SnapshotIngestStorage,
    path: str | Path,
    source_key: str,
    continuity: str,
    *,
    encoding: str | None = None,
    limits: IngestLimits | None = None,
) -> tuple["Source", "SourceSnapshot", bool]:
    """Import TXT, Markdown, JSON, or SRT as a versioned source snapshot.

    The decoded file is persisted verbatim (apart from a Unicode BOM consumed by
    its decoder).  Re-importing unchanged content is expected to return
    ``created=False``; adding changed content advances the logical source version.
    """

    source_path = Path(path)
    suffix = source_path.suffix.lower()
    try:
        media_type = MEDIA_TYPES[suffix]
    except KeyError as exc:
        supported = ", ".join(sorted(MEDIA_TYPES))
        raise ValueError(
            f"unsupported source format {suffix or '<none>'}; expected one of: {supported}"
        ) from exc

    if not source_path.is_file():
        raise FileNotFoundError(f"source file does not exist: {source_path}")

    policy = _resolve_limits(limits)
    content = _decode_source(_read_source_bytes(source_path, policy), encoding=encoding)
    return ingest_content(
        storage,
        content,
        source_key,
        continuity,
        media_type=media_type,
        origin_path=str(source_path.resolve()),
        limits=policy,
    )


__all__ = [
    "DEFAULT_INGEST_LIMITS",
    "IngestLimits",
    "MEDIA_TYPES",
    "SnapshotIngestStorage",
    "SourceDecodeError",
    "SourceInputError",
    "SourceLimitError",
    "UnsafeSourceError",
    "extract_line_quote",
    "ingest_content",
    "ingest_path",
    "parse_json_content",
    "source_lines",
]
