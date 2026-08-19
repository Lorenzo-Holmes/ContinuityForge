"""ISO-8601 helpers shared by storage, validation, and compilation."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_instant(value: str | datetime | None) -> datetime | None:
    """Parse an ISO-8601 instant and normalize it to UTC.

    Naive values are intentionally treated as UTC.  This keeps the CLI
    deterministic while still accepting the date-only values used by v0.1.
    """

    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def isoformat_utc(value: str | datetime | None) -> str | None:
    """Return a stable UTC ISO-8601 representation using a ``Z`` suffix."""

    parsed = parse_instant(value)
    if parsed is None:
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def contains_instant(
    start: str | datetime | None,
    end: str | datetime | None,
    instant: str | datetime,
) -> bool:
    """Return whether ``instant`` falls in the half-open interval [start, end)."""

    point = parse_instant(instant)
    lower = parse_instant(start)
    upper = parse_instant(end)
    assert point is not None
    return (lower is None or lower <= point) and (upper is None or point < upper)


def intervals_overlap(
    left_start: str | datetime | None,
    left_end: str | datetime | None,
    right_start: str | datetime | None,
    right_end: str | datetime | None,
) -> bool:
    """Return whether two half-open intervals overlap."""

    ls = parse_instant(left_start) or datetime.min.replace(tzinfo=timezone.utc)
    le = parse_instant(left_end) or datetime.max.replace(tzinfo=timezone.utc)
    rs = parse_instant(right_start) or datetime.min.replace(tzinfo=timezone.utc)
    re = parse_instant(right_end) or datetime.max.replace(tzinfo=timezone.utc)
    return ls < re and rs < le


def validate_interval(start: str | None, end: str | None, *, name: str) -> None:
    """Raise ``ValueError`` when a half-open interval is inverted or empty."""

    lower = parse_instant(start)
    upper = parse_instant(end)
    if lower is not None and upper is not None and lower >= upper:
        raise ValueError(f"{name}: start must be earlier than end")

