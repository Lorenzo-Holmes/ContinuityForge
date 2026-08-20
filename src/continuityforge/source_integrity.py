"""Deterministic audit replay for logical Sources and SourceSnapshots.

``sources`` stores the identity inherited by every snapshot.  Consequently a
Source row is security-relevant provenance, not mutable display metadata.  The
SQLite triggers prevent ordinary rewrites; this module independently binds the
materialized rows to their append-only EventLedger records so every trusted
read surface fails closed after a trigger-bypass or legacy corruption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .models import LedgerEntry, Source


@dataclass(frozen=True, slots=True)
class SourceAuditSnapshot:
    """Content-free snapshot material required by Source audit replay."""

    snapshot_id: str
    source_id: str
    version: int
    content_hash: str
    media_type: str
    origin_path: str | None
    previous_snapshot_id: str | None
    line_count: int
    created_at: str


class SourceAuditStorage(Protocol):
    """Bounded read surface shared by Storage and ReadOnlyProject."""

    def list_sources(self, *, continuity: str | None = None) -> list[Source]: ...

    def list_source_audit_snapshots(self) -> list[SourceAuditSnapshot]: ...

    def list_ledger_entries(
        self,
        *,
        after_sequence: int = 0,
        event_type: str | None = None,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        limit: int | None = None,
    ) -> list[LedgerEntry]: ...


@dataclass(frozen=True, slots=True)
class SourceAuditIssue:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SourceAuditReport:
    source_id: str
    snapshot_count: int
    source_creation_entry_count: int
    snapshot_creation_entry_count: int
    issues: tuple[SourceAuditIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "snapshot_count": self.snapshot_count,
            "source_creation_entry_count": self.source_creation_entry_count,
            "snapshot_creation_entry_count": self.snapshot_creation_entry_count,
            "is_valid": self.is_valid,
            "issues": [asdict(issue) for issue in self.issues],
        }


def _issue(
    issues: list[SourceAuditIssue], code: str, message: str, **details: Any
) -> None:
    issues.append(SourceAuditIssue(code, message, details))


def _snapshot_payload(snapshot: SourceAuditSnapshot, source: Source) -> dict[str, Any]:
    return {
        "source_id": source.source_id,
        "source_key": source.source_key,
        "continuity": source.continuity,
        "version": snapshot.version,
        "content_hash": snapshot.content_hash,
        "previous_snapshot_id": snapshot.previous_snapshot_id,
        "media_type": snapshot.media_type,
        "origin_path": snapshot.origin_path,
        "line_count": snapshot.line_count,
    }


def replay_source_audit(
    source: Source,
    snapshots: Sequence[SourceAuditSnapshot],
    ledger_entries: Sequence[LedgerEntry],
) -> SourceAuditReport:
    """Bind one Source, its complete revision lineage, and creation ledger."""

    issues: list[SourceAuditIssue] = []
    ordered_snapshots = sorted(snapshots, key=lambda item: (item.version, item.snapshot_id))
    snapshot_ids = {item.snapshot_id for item in ordered_snapshots}

    for snapshot in ordered_snapshots:
        if snapshot.source_id != source.source_id:
            _issue(
                issues,
                "SOURCE_SNAPSHOT_OWNER_MISMATCH",
                "source audit received a snapshot owned by another Source",
                snapshot_id=snapshot.snapshot_id,
                snapshot_source_id=snapshot.source_id,
            )

    source_entries = [
        entry
        for entry in ledger_entries
        if entry.event_type == "source.created"
        and entry.aggregate_type == "source"
        and entry.aggregate_id == source.source_id
    ]
    if len(source_entries) != 1:
        _issue(
            issues,
            "SOURCE_CREATION_LEDGER_MISMATCH",
            "Source must have exactly one source.created ledger entry",
            count=len(source_entries),
        )
    else:
        entry = source_entries[0]
        expected = {
            "source_key": source.source_key,
            "continuity": source.continuity,
        }
        if any(entry.payload.get(key) != value for key, value in expected.items()):
            _issue(
                issues,
                "SOURCE_LEDGER_PAYLOAD_MISMATCH",
                "Source identity and source.created ledger payload differ",
                sequence=entry.sequence,
            )
        if entry.created_at != source.created_at:
            _issue(
                issues,
                "SOURCE_LEDGER_TIMESTAMP_MISMATCH",
                "Source created_at and source.created ledger timestamp differ",
                sequence=entry.sequence,
            )

    if not ordered_snapshots:
        _issue(
            issues,
            "SOURCE_SNAPSHOT_REQUIRED",
            "every committed Source must own at least one SourceSnapshot",
        )

    previous: SourceAuditSnapshot | None = None
    snapshot_entries: list[LedgerEntry] = []
    entry_sequences: list[int] = []
    for expected_version, snapshot in enumerate(ordered_snapshots, start=1):
        if snapshot.version != expected_version:
            _issue(
                issues,
                "SOURCE_SNAPSHOT_VERSION_GAP",
                "SourceSnapshot versions must be contiguous",
                snapshot_id=snapshot.snapshot_id,
                expected=expected_version,
                actual=snapshot.version,
            )
        expected_previous = previous.snapshot_id if previous is not None else None
        if snapshot.previous_snapshot_id != expected_previous:
            _issue(
                issues,
                "SOURCE_SNAPSHOT_LINEAGE_MISMATCH",
                "SourceSnapshot predecessor does not match the prior revision",
                snapshot_id=snapshot.snapshot_id,
                expected=expected_previous,
                actual=snapshot.previous_snapshot_id,
            )

        matches = [
            entry
            for entry in ledger_entries
            if entry.event_type == "source_snapshot.created"
            and entry.aggregate_type == "source_snapshot"
            and entry.aggregate_id == snapshot.snapshot_id
        ]
        snapshot_entries.extend(matches)
        if len(matches) != 1:
            _issue(
                issues,
                "SOURCE_SNAPSHOT_CREATION_LEDGER_MISMATCH",
                "SourceSnapshot must have exactly one creation ledger entry",
                snapshot_id=snapshot.snapshot_id,
                count=len(matches),
            )
        else:
            entry = matches[0]
            expected_payload = _snapshot_payload(snapshot, source)
            if any(
                entry.payload.get(key) != value
                for key, value in expected_payload.items()
            ):
                _issue(
                    issues,
                    "SOURCE_SNAPSHOT_LEDGER_PAYLOAD_MISMATCH",
                    "SourceSnapshot material and creation ledger payload differ",
                    snapshot_id=snapshot.snapshot_id,
                    sequence=entry.sequence,
                )
            if entry.created_at != snapshot.created_at:
                _issue(
                    issues,
                    "SOURCE_SNAPSHOT_LEDGER_TIMESTAMP_MISMATCH",
                    "SourceSnapshot created_at and ledger timestamp differ",
                    snapshot_id=snapshot.snapshot_id,
                    sequence=entry.sequence,
                )
            entry_sequences.append(entry.sequence)
        previous = snapshot

    if ordered_snapshots and source.updated_at != ordered_snapshots[-1].created_at:
        _issue(
            issues,
            "SOURCE_UPDATED_AT_MISMATCH",
            "Source updated_at must equal its latest SourceSnapshot created_at",
            expected=ordered_snapshots[-1].created_at,
            actual=source.updated_at,
        )
    has_backfill = any(
        entry.payload.get("audit_backfill") is True
        for entry in source_entries + snapshot_entries
    )
    if len(source_entries) == 1 and entry_sequences and not has_backfill:
        if source_entries[0].sequence >= min(entry_sequences):
            _issue(
                issues,
                "SOURCE_LEDGER_ORDER_INVALID",
                "source.created must precede SourceSnapshot creation entries",
                source_sequence=source_entries[0].sequence,
            )
    if entry_sequences != sorted(entry_sequences) and not has_backfill:
        _issue(
            issues,
            "SOURCE_SNAPSHOT_LEDGER_ORDER_INVALID",
            "SourceSnapshot creation entries must follow revision order",
            sequences=entry_sequences,
        )

    relevant = [
        entry
        for entry in ledger_entries
        if entry.event_type in {"source.created", "source_snapshot.created"}
    ]
    recognized_sequences = {
        entry.sequence for entry in source_entries + snapshot_entries
    }
    for entry in relevant:
        if entry.sequence in recognized_sequences:
            continue
        if entry.aggregate_id == source.source_id or entry.aggregate_id in snapshot_ids:
            _issue(
                issues,
                "SOURCE_AUDIT_LEDGER_CORRESPONDENCE_INVALID",
                "Source audit ledger entry uses an invalid aggregate type or event owner",
                sequence=entry.sequence,
                event_type=entry.event_type,
                aggregate_type=entry.aggregate_type,
                aggregate_id=entry.aggregate_id,
            )

    return SourceAuditReport(
        source_id=source.source_id,
        snapshot_count=len(ordered_snapshots),
        source_creation_entry_count=len(source_entries),
        snapshot_creation_entry_count=len(snapshot_entries),
        issues=tuple(issues),
    )


def replay_source_audits(
    sources: Iterable[Source],
    snapshots: Iterable[SourceAuditSnapshot],
    ledger_entries: Iterable[LedgerEntry],
) -> dict[str, SourceAuditReport]:
    """Replay a caller-supplied batch and report orphan creation entries."""

    source_items = list(sources)
    snapshot_items = list(snapshots)
    entry_items = list(ledger_entries)
    snapshots_by_source: dict[str, list[SourceAuditSnapshot]] = {}
    snapshot_owner: dict[str, str] = {}
    for snapshot in snapshot_items:
        snapshots_by_source.setdefault(snapshot.source_id, []).append(snapshot)
        snapshot_owner[snapshot.snapshot_id] = snapshot.source_id

    known_sources = {source.source_id for source in source_items}
    entries_by_source: dict[str, list[LedgerEntry]] = {
        source_id: [] for source_id in known_sources
    }
    orphan_issues: dict[str, list[SourceAuditIssue]] = {}
    for entry in entry_items:
        if entry.event_type == "source.created":
            owner = (
                entry.aggregate_id
                if entry.aggregate_id in known_sources
                else snapshot_owner.get(entry.aggregate_id)
            )
        elif entry.event_type == "source_snapshot.created":
            owner = snapshot_owner.get(entry.aggregate_id)
            if owner is None and entry.aggregate_id in known_sources:
                owner = entry.aggregate_id
        else:
            continue
        if owner in known_sources:
            entries_by_source[owner].append(entry)
            continue
        orphan_key = entry.aggregate_id
        orphan_issues.setdefault(f"orphan:{orphan_key}", []).append(
            SourceAuditIssue(
                "SOURCE_AUDIT_LEDGER_ORPHAN",
                "Source creation ledger entry has no matching materialized aggregate",
                {
                    "sequence": entry.sequence,
                    "event_type": entry.event_type,
                    "aggregate_type": entry.aggregate_type,
                    "aggregate_id": entry.aggregate_id,
                },
            )
        )

    reports = {
        source.source_id: replay_source_audit(
            source,
            snapshots_by_source.get(source.source_id, ()),
            entries_by_source.get(source.source_id, ()),
        )
        for source in source_items
    }
    for snapshot in snapshot_items:
        if snapshot.source_id in known_sources:
            continue
        orphan_issues.setdefault(f"orphan:{snapshot.source_id}", []).append(
            SourceAuditIssue(
                "SOURCE_AUDIT_SNAPSHOT_ORPHAN",
                "SourceSnapshot has no matching materialized Source",
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_source_id": snapshot.source_id,
                },
            )
        )
    for source_id, issues in orphan_issues.items():
        current = reports.get(source_id)
        if current is None:
            reports[source_id] = SourceAuditReport(
                source_id=source_id,
                snapshot_count=0,
                source_creation_entry_count=0,
                snapshot_creation_entry_count=0,
                issues=tuple(issues),
            )
        else:
            reports[source_id] = SourceAuditReport(
                source_id=current.source_id,
                snapshot_count=current.snapshot_count,
                source_creation_entry_count=current.source_creation_entry_count,
                snapshot_creation_entry_count=current.snapshot_creation_entry_count,
                issues=current.issues + tuple(issues),
            )
    return reports


def validate_source_audits(
    storage: SourceAuditStorage,
) -> dict[str, SourceAuditReport]:
    """Bulk-load Source audit data with a constant number of repository reads."""

    try:
        sources = storage.list_sources()
        snapshots = storage.list_source_audit_snapshots()
        entries = storage.list_ledger_entries(event_type="source.created")
        entries.extend(
            storage.list_ledger_entries(event_type="source_snapshot.created")
        )
    except (AttributeError, NotImplementedError) as exc:
        return {
            source.source_id: SourceAuditReport(
                source_id=source.source_id,
                snapshot_count=0,
                source_creation_entry_count=0,
                snapshot_creation_entry_count=0,
                issues=(
                    SourceAuditIssue(
                        "SOURCE_AUDIT_DATA_UNAVAILABLE",
                        "storage cannot provide Source audit material",
                        {"error_type": type(exc).__name__},
                    ),
                ),
            )
            for source in locals().get("sources", ())
        }
    return replay_source_audits(sources, snapshots, entries)


__all__ = [
    "SourceAuditIssue",
    "SourceAuditReport",
    "SourceAuditSnapshot",
    "SourceAuditStorage",
    "replay_source_audit",
    "replay_source_audits",
    "validate_source_audits",
]
