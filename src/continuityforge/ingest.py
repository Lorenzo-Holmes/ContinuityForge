"""Source ingestion for immutable, versioned snapshots.

This module deliberately keeps parsing shallow: the exact decoded source text is
stored in a :class:`SourceSnapshot`, while format-specific extraction belongs to
the claim-proposal layer.  That separation makes line-level provenance stable
even when proposal models or parsers change.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - imports are only for static checkers
    from .models import Source, SourceSnapshot


MEDIA_TYPES: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".json": "application/json",
    ".srt": "application/x-subrip",
}


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
    if isinstance(start_line, bool) or isinstance(end_line, bool):
        raise ValueError("line numbers must be integers")
    if not isinstance(start_line, int) or not isinstance(end_line, int):
        raise ValueError("line numbers must be integers")
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
        return data.decode(encoding)
    if data.startswith(codecs.BOM_UTF8):
        return data.decode("utf-8-sig")
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    return data.decode("utf-8")


def _validate_format(content: str, suffix: str) -> None:
    """Reject malformed structured input while leaving its spelling untouched."""

    if suffix == ".json":
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc


def ingest_content(
    storage: SnapshotIngestStorage,
    content: str,
    source_key: str,
    continuity: str,
    *,
    media_type: str = "text/plain",
    origin_path: str | None = None,
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

    content = _decode_source(source_path.read_bytes(), encoding=encoding)
    _validate_format(content, suffix)
    return ingest_content(
        storage,
        content,
        source_key,
        continuity,
        media_type=media_type,
        origin_path=str(source_path.resolve()),
    )


__all__ = [
    "MEDIA_TYPES",
    "SnapshotIngestStorage",
    "extract_line_quote",
    "ingest_content",
    "ingest_path",
    "source_lines",
]
