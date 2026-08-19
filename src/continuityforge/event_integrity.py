"""Deterministic audit replay for operator-authored NarrativeEvents."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .models import EvidenceRef, LedgerEntry, NarrativeEvent


class EventAuditStorage(Protocol):
    def list_ledger_entries(
        self,
        *,
        after_sequence: int = 0,
        event_type: str | None = None,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        limit: int | None = None,
    ) -> list[LedgerEntry]: ...

    def list_all_event_evidence(self) -> list[EvidenceRef]: ...


@dataclass(frozen=True, slots=True)
class EventAuditIssue:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EventAuditReport:
    event_id: str
    creation_entry_count: int
    evidence_count: int
    issues: tuple[EventAuditIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues and self.creation_entry_count == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "creation_entry_count": self.creation_entry_count,
            "evidence_count": self.evidence_count,
            "is_valid": self.is_valid,
            "issues": [asdict(issue) for issue in self.issues],
        }


def _issue(
    issues: list[EventAuditIssue], code: str, message: str, **details: Any
) -> None:
    issues.append(EventAuditIssue(code, message, details))


def _evidence_material(evidence: EvidenceRef) -> dict[str, Any]:
    return {
        "evidence_id": evidence.evidence_id,
        "snapshot_id": evidence.snapshot_id,
        "start_line": evidence.start_line,
        "end_line": evidence.end_line,
        "content_hash": evidence.content_hash,
    }


def _material_key(material: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        material.get("evidence_id"),
        material.get("snapshot_id"),
        material.get("start_line"),
        material.get("end_line"),
        material.get("content_hash"),
    )


def replay_event_audit(
    event: NarrativeEvent,
    ledger_entries: Sequence[LedgerEntry],
    evidence: Sequence[EvidenceRef],
) -> EventAuditReport:
    """Bind one immutable event row and its evidence set to EventLedger."""

    issues: list[EventAuditIssue] = []
    creation_entries = [
        entry
        for entry in ledger_entries
        if entry.event_type == "narrative_event.created"
        and entry.aggregate_type == "narrative_event"
        and entry.aggregate_id == event.event_id
    ]
    if len(creation_entries) != 1:
        _issue(
            issues,
            "EVENT_CREATION_LEDGER_MISMATCH",
            "narrative event must have exactly one creation ledger entry",
            count=len(creation_entries),
        )

    actual_evidence = list(evidence)
    for item in actual_evidence:
        if item.event_id != event.event_id:
            _issue(
                issues,
                "EVENT_EVIDENCE_OWNER_MISMATCH",
                "event audit received evidence owned by another aggregate",
                evidence_id=item.evidence_id,
                evidence_event_id=item.event_id,
            )

    if len(creation_entries) == 1:
        entry = creation_entries[0]
        expected_core = {
            "persona_id": event.persona_id,
            "continuity": event.continuity,
            "event_type": event.event_type,
            "valid_from": event.valid_from,
            "knowledge_from": event.knowledge_from,
            "access_policy": event.access_policy.value,
        }
        if any(entry.payload.get(key) != value for key, value in expected_core.items()):
            _issue(
                issues,
                "EVENT_LEDGER_PAYLOAD_MISMATCH",
                "event row and creation ledger core payload differ",
                sequence=entry.sequence,
            )
        if entry.created_at != event.created_at:
            _issue(
                issues,
                "EVENT_LEDGER_TIMESTAMP_MISMATCH",
                "event row and creation ledger timestamps differ",
                sequence=entry.sequence,
            )

        payload_ids = entry.payload.get("evidence_ids")
        payload_refs = entry.payload.get("evidence_refs")
        if not isinstance(payload_ids, (list, tuple)) or any(
            not isinstance(item, str) or not item for item in payload_ids
        ):
            _issue(
                issues,
                "EVENT_LEDGER_EVIDENCE_IDS_INVALID",
                "creation ledger evidence_ids must be non-empty string IDs",
                sequence=entry.sequence,
            )
            payload_ids = []
        if len(set(payload_ids)) != len(payload_ids):
            _issue(
                issues,
                "EVENT_LEDGER_EVIDENCE_DUPLICATE",
                "creation ledger names an evidence ID more than once",
                sequence=entry.sequence,
            )

        ledger_material: list[Mapping[str, Any]] = []
        if not isinstance(payload_refs, (list, tuple)) or any(
            not isinstance(item, Mapping) for item in payload_refs
        ):
            _issue(
                issues,
                "EVENT_LEDGER_EVIDENCE_REFS_INVALID",
                "creation ledger evidence_refs must be an object list",
                sequence=entry.sequence,
            )
        else:
            ledger_material = list(payload_refs)
            ref_ids = [item.get("evidence_id") for item in ledger_material]
            if list(payload_ids) != ref_ids:
                _issue(
                    issues,
                    "EVENT_LEDGER_EVIDENCE_ORDER_INVALID",
                    "evidence_ids and evidence_refs must use the same stable order",
                    sequence=entry.sequence,
                )

        actual_material = [_evidence_material(item) for item in actual_evidence]
        actual_keys = {_material_key(item) for item in actual_material}
        ledger_keys = {_material_key(item) for item in ledger_material}
        if (
            len(actual_keys) != len(actual_material)
            or len(ledger_keys) != len(ledger_material)
            or actual_keys != ledger_keys
        ):
            _issue(
                issues,
                "EVENT_EVIDENCE_SET_LEDGER_MISMATCH",
                "stored event evidence differs from the audited evidence set",
                stored_count=len(actual_material),
                ledger_count=len(ledger_material),
            )

    return EventAuditReport(
        event_id=event.event_id,
        creation_entry_count=len(creation_entries),
        evidence_count=len(actual_evidence),
        issues=tuple(issues),
    )


def validate_event_audits(
    storage: EventAuditStorage, events: Iterable[NarrativeEvent]
) -> dict[str, EventAuditReport]:
    """Bulk-load all event audit inputs with two set queries."""

    event_items = list(events)
    if not event_items:
        return {}
    try:
        entries = storage.list_ledger_entries(aggregate_type="narrative_event")
        evidence = storage.list_all_event_evidence()
    except (AttributeError, NotImplementedError) as exc:
        return {
            event.event_id: EventAuditReport(
                event_id=event.event_id,
                creation_entry_count=0,
                evidence_count=0,
                issues=(
                    EventAuditIssue(
                        "EVENT_AUDIT_DATA_UNAVAILABLE",
                        "storage cannot provide event ledger and evidence history",
                        {"error_type": type(exc).__name__},
                    ),
                ),
            )
            for event in event_items
        }

    entries_by_event: dict[str, list[LedgerEntry]] = {}
    for entry in entries:
        entries_by_event.setdefault(entry.aggregate_id, []).append(entry)
    evidence_by_event: dict[str, list[EvidenceRef]] = {}
    for item in evidence:
        if item.event_id is not None:
            evidence_by_event.setdefault(item.event_id, []).append(item)
    return {
        event.event_id: replay_event_audit(
            event,
            entries_by_event.get(event.event_id, ()),
            evidence_by_event.get(event.event_id, ()),
        )
        for event in event_items
    }


__all__ = [
    "EventAuditIssue",
    "EventAuditReport",
    "EventAuditStorage",
    "replay_event_audit",
    "validate_event_audits",
]
