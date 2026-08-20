"""Central UTF-8 byte limits for persisted Claim and NarrativeEvent material.

The validators in this module are deliberately storage-independent.  They do
not normalize, coerce, truncate, or persist values; callers receive the same
string after an exact UTF-8 byte-count check.
"""

from __future__ import annotations

from typing import Final


KIB: Final = 1024
MIB: Final = 1024 * KIB

MAX_CLAIM_TEXT_UTF8_BYTES: Final = 256 * KIB
MAX_CLAIM_RATIONALE_UTF8_BYTES: Final = 256 * KIB
MAX_CLAIM_METADATA_UTF8_BYTES: Final = 4 * KIB
MAX_EVENT_TITLE_UTF8_BYTES: Final = 16 * KIB
MAX_EVENT_SUMMARY_UTF8_BYTES: Final = 256 * KIB
MAX_EVENT_DETAILS_JSON_BYTES: Final = MIB

CLAIM_METADATA_FIELDS: Final = (
    "subject",
    "predicate",
    "object_value",
    "proposed_by",
    "proposal_model",
)


class AggregateInputError(ValueError):
    """Persisted aggregate input is malformed or exceeds a stable limit."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def validate_utf8_field(
    value: object,
    *,
    field: str,
    max_bytes: int,
    code: str,
    optional: bool = False,
) -> str | None:
    """Return ``value`` unchanged after strict type/UTF-8/byte validation."""

    if value is None and optional:
        return None
    if not isinstance(value, str):
        expected = "text or None" if optional else "text"
        raise TypeError(f"{field} must be {expected}")
    try:
        byte_count = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise AggregateInputError(
            f"{field} contains invalid Unicode",
            code="INVALID_UNICODE",
        ) from exc
    if byte_count > max_bytes:
        raise AggregateInputError(
            f"{field} exceeds the UTF-8 byte limit",
            code=code,
        )
    return value


def validate_claim_fields(
    *,
    text: object,
    rationale: object = None,
    subject: object = None,
    predicate: object = None,
    object_value: object = None,
    proposed_by: object = None,
    proposal_model: object = None,
) -> None:
    """Validate all bounded Claim fields without changing their contents."""

    validate_utf8_field(
        text,
        field="claim.text",
        max_bytes=MAX_CLAIM_TEXT_UTF8_BYTES,
        code="CLAIM_TEXT_BYTES_LIMIT",
    )
    validate_utf8_field(
        rationale,
        field="claim.rationale",
        max_bytes=MAX_CLAIM_RATIONALE_UTF8_BYTES,
        code="CLAIM_RATIONALE_BYTES_LIMIT",
        optional=True,
    )
    metadata = {
        "subject": subject,
        "predicate": predicate,
        "object_value": object_value,
        "proposed_by": proposed_by,
        "proposal_model": proposal_model,
    }
    for name in CLAIM_METADATA_FIELDS:
        validate_utf8_field(
            metadata[name],
            field=f"claim.{name}",
            max_bytes=MAX_CLAIM_METADATA_UTF8_BYTES,
            code="CLAIM_METADATA_BYTES_LIMIT",
            optional=True,
        )


def validate_event_fields(*, title: object, summary: object) -> None:
    """Validate bounded NarrativeEvent text without changing its contents."""

    validate_utf8_field(
        title,
        field="event.title",
        max_bytes=MAX_EVENT_TITLE_UTF8_BYTES,
        code="EVENT_TITLE_BYTES_LIMIT",
    )
    validate_utf8_field(
        summary,
        field="event.summary",
        max_bytes=MAX_EVENT_SUMMARY_UTF8_BYTES,
        code="EVENT_SUMMARY_BYTES_LIMIT",
    )


__all__ = [
    "AggregateInputError",
    "CLAIM_METADATA_FIELDS",
    "MAX_CLAIM_METADATA_UTF8_BYTES",
    "MAX_CLAIM_RATIONALE_UTF8_BYTES",
    "MAX_CLAIM_TEXT_UTF8_BYTES",
    "MAX_EVENT_DETAILS_JSON_BYTES",
    "MAX_EVENT_SUMMARY_UTF8_BYTES",
    "MAX_EVENT_TITLE_UTF8_BYTES",
    "validate_claim_fields",
    "validate_event_fields",
    "validate_utf8_field",
]
