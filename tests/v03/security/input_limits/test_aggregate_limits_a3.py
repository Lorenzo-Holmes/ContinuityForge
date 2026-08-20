from __future__ import annotations

import sqlite3
from typing import Callable

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.models import ClaimProposal, NarrativeEvent


KIB = 1024
MIB = 1024 * KIB

CLAIM_FIELD_LIMITS = (
    ("text", 256 * KIB, "CLAIM_TEXT_BYTES_LIMIT"),
    ("rationale", 256 * KIB, "CLAIM_RATIONALE_BYTES_LIMIT"),
    ("subject", 4 * KIB, "CLAIM_METADATA_BYTES_LIMIT"),
    ("predicate", 4 * KIB, "CLAIM_METADATA_BYTES_LIMIT"),
    ("object_value", 4 * KIB, "CLAIM_METADATA_BYTES_LIMIT"),
    ("proposed_by", 4 * KIB, "CLAIM_METADATA_BYTES_LIMIT"),
    ("proposal_model", 4 * KIB, "CLAIM_METADATA_BYTES_LIMIT"),
)

EVENT_FIELD_LIMITS = (
    ("title", 16 * KIB, "EVENT_TITLE_BYTES_LIMIT"),
    ("summary", 256 * KIB, "EVENT_SUMMARY_BYTES_LIMIT"),
)


def _utf8_text(byte_count: int) -> str:
    """Return non-ASCII text whose UTF-8 representation is exactly byte_count."""

    multibyte, remainder = divmod(byte_count, 3)
    value = "\u754c" * multibyte + "x" * remainder
    assert len(value.encode("utf-8")) == byte_count
    return value


def _assert_limit_code(action: Callable[[], object], expected: str) -> None:
    with pytest.raises(Exception) as caught:
        action()
    assert getattr(caught.value, "code", None) == expected


def _seed_evidence(storage):
    _, snapshot, _ = storage.ingest_snapshot("story", "alpha", "anchor")
    return build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)


def _counts(storage, *tables: str) -> tuple[int, ...]:
    return tuple(
        int(storage.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in tables
    )


def _claim(field: str, value: str) -> ClaimProposal:
    values = {
        "claim_id": f"claim_{field}_{len(value)}",
        "persona_id": "persona",
        "continuity": "alpha",
        "text": "ordinary claim",
        field: value,
    }
    return ClaimProposal(**values)


def _event(field: str, value: str) -> NarrativeEvent:
    values = {
        "event_id": f"event_{field}_{len(value)}",
        "persona_id": "persona",
        "continuity": "alpha",
        "title": "ordinary title",
        "summary": "ordinary summary",
        field: value,
    }
    return NarrativeEvent(**values)


@pytest.mark.parametrize(("field", "limit", "code"), CLAIM_FIELD_LIMITS)
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_claim_fields_have_exact_utf8_byte_boundaries(
    storage, field: str, limit: int, code: str, delta: int
) -> None:
    evidence = _seed_evidence(storage)
    value = _utf8_text(limit + delta)
    before = _counts(storage, "claim_proposals", "evidence_refs", "event_ledger")

    if delta <= 0:
        persisted = storage.create_claim_proposal(
            _claim(field, value), (evidence,)
        )
        assert getattr(persisted, field) == value
        assert len(getattr(persisted, field).encode("utf-8")) == limit + delta
        return

    _assert_limit_code(
        lambda: storage.create_claim_proposal(_claim(field, value), (evidence,)),
        code,
    )
    assert _counts(
        storage, "claim_proposals", "evidence_refs", "event_ledger"
    ) == before


@pytest.mark.parametrize(("field", "limit", "code"), EVENT_FIELD_LIMITS)
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_event_fields_have_exact_utf8_byte_boundaries(
    storage, field: str, limit: int, code: str, delta: int
) -> None:
    evidence = _seed_evidence(storage)
    value = _utf8_text(limit + delta)
    before = _counts(storage, "narrative_events", "event_evidence_refs", "event_ledger")

    if delta <= 0:
        persisted = storage.create_narrative_event(
            _event(field, value), (evidence,)
        )
        assert getattr(persisted, field) == value
        assert len(getattr(persisted, field).encode("utf-8")) == limit + delta
        return

    _assert_limit_code(
        lambda: storage.create_narrative_event(_event(field, value), (evidence,)),
        code,
    )
    assert _counts(
        storage, "narrative_events", "event_evidence_refs", "event_ledger"
    ) == before


def test_claim_byte_limit_is_checked_before_compatibility_whitespace_trim(
    storage,
) -> None:
    evidence = _seed_evidence(storage)
    # The historical API trims the stored claim text.  Limit enforcement must
    # still inspect the complete caller input rather than silently dropping an
    # over-limit suffix before counting bytes.
    value = _utf8_text(256 * KIB) + " "
    before = _counts(storage, "claim_proposals", "evidence_refs", "event_ledger")

    _assert_limit_code(
        lambda: storage.create_claim_proposal(_claim("text", value), (evidence,)),
        "CLAIM_TEXT_BYTES_LIMIT",
    )
    assert _counts(
        storage, "claim_proposals", "evidence_refs", "event_ledger"
    ) == before


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_event_details_keeps_the_existing_one_mib_json_boundary(
    storage, delta: int
) -> None:
    evidence = _seed_evidence(storage)
    # Canonical JSON for {"v": VALUE} has eight structural ASCII bytes.
    value = _utf8_text(MIB - 8 + delta)
    before = _counts(storage, "narrative_events", "event_evidence_refs", "event_ledger")
    event = NarrativeEvent(
        event_id=f"event_details_{delta}",
        persona_id="persona",
        continuity="alpha",
        title="ordinary title",
        summary="ordinary summary",
        details={"v": value},
    )

    if delta <= 0:
        persisted = storage.create_narrative_event(event, (evidence,))
        assert persisted.details == {"v": value}
        stored_size = int(
            storage.connection.execute(
                "SELECT length(CAST(details_json AS BLOB)) FROM narrative_events "
                "WHERE event_id = ?",
                (persisted.event_id,),
            ).fetchone()[0]
        )
        assert stored_size == MIB + delta
        return

    with pytest.raises(ValueError, match="JSON byte limit"):
        storage.create_narrative_event(event, (evidence,))
    assert _counts(
        storage, "narrative_events", "event_evidence_refs", "event_ledger"
    ) == before


@pytest.mark.parametrize(("field", "limit", "code"), CLAIM_FIELD_LIMITS)
def test_direct_sql_cannot_bypass_claim_byte_limits(
    storage, field: str, limit: int, code: str
) -> None:
    values: dict[str, object] = {
        "claim_id": f"raw_claim_{field}",
        "persona_id": "persona",
        "continuity": "alpha",
        "text": "ordinary claim",
        "subject": None,
        "predicate": None,
        "object_value": None,
        "valid_from": None,
        "valid_to": None,
        "knowledge_from": None,
        "knowledge_to": None,
        "access_policy": "agent_accessible",
        "confidence": 1.0,
        "status": "PROPOSED",
        "proposed_by": None,
        "proposal_model": None,
        "rationale": None,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    values[field] = _utf8_text(limit + 1)
    columns = tuple(values)

    with pytest.raises(sqlite3.IntegrityError) as caught:
        storage.connection.execute(
            "INSERT INTO claim_proposals ("
            + ", ".join(columns)
            + ") VALUES ("
            + ", ".join("?" for _ in columns)
            + ")",
            tuple(values[column] for column in columns),
        )

    assert code in str(caught.value)
    assert storage.connection.execute(
        "SELECT 1 FROM claim_proposals WHERE claim_id = ?", (values["claim_id"],)
    ).fetchone() is None


@pytest.mark.parametrize(("field", "limit", "code"), EVENT_FIELD_LIMITS)
def test_direct_sql_cannot_bypass_event_byte_limits(
    storage, field: str, limit: int, code: str
) -> None:
    values: dict[str, object] = {
        "event_id": f"raw_event_{field}",
        "persona_id": "persona",
        "continuity": "alpha",
        "event_type": "narrative",
        "title": "ordinary title",
        "summary": "ordinary summary",
        "details_json": "{}",
        "valid_from": None,
        "valid_to": None,
        "knowledge_from": None,
        "knowledge_to": None,
        "access_policy": "agent_accessible",
        "created_at": "2026-01-01T00:00:00Z",
    }
    values[field] = _utf8_text(limit + 1)
    columns = tuple(values)

    with pytest.raises(sqlite3.IntegrityError) as caught:
        storage.connection.execute(
            "INSERT INTO narrative_events ("
            + ", ".join(columns)
            + ") VALUES ("
            + ", ".join("?" for _ in columns)
            + ")",
            tuple(values[column] for column in columns),
        )

    assert code in str(caught.value)
    assert storage.connection.execute(
        "SELECT 1 FROM narrative_events WHERE event_id = ?", (values["event_id"],)
    ).fetchone() is None


def test_direct_sql_cannot_bypass_event_details_json_byte_limit(storage) -> None:
    values: tuple[object, ...] = (
        "raw_event_details",
        "persona",
        "alpha",
        "narrative",
        "ordinary title",
        "ordinary summary",
        "x" * (MIB + 1),
        None,
        None,
        None,
        None,
        "agent_accessible",
        "2026-01-01T00:00:00Z",
    )
    with pytest.raises(sqlite3.IntegrityError, match="EVENT_DETAILS_INVALID"):
        storage.connection.execute(
            "INSERT INTO narrative_events "
            "(event_id, persona_id, continuity, event_type, title, summary, "
            "details_json, valid_from, valid_to, knowledge_from, knowledge_to, "
            "access_policy, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )
    assert storage.connection.execute(
        "SELECT 1 FROM narrative_events WHERE event_id = 'raw_event_details'"
    ).fetchone() is None
