"""Transactional migration gates and machine-readable preflight reports.

This module performs no schema DDL.  It identifies and validates an input,
checks SQLite integrity and backup capacity, and creates a consistent backup.
The storage backend owns the single migration transaction and uses this report
as its admission gate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import unicodedata
from typing import Any, Iterable, Mapping

from .audit_material import (
    CLAIM_ATTESTATION_EVENT,
    CLAIM_CREATION_EVENT,
    CLAIM_EVIDENCE_EVENT,
    EVENT_ATTESTATION_EVENT,
    EVENT_CREATION_EVENT,
    MATERIAL_VERSION,
    AuditMaterialDigests,
    claim_material_digests,
    event_material_digests,
    parse_material_digests,
)
from .constants import MIGRATION_REPORT_SCHEMA, SCHEMA_VERSION
from .evidence import quote_sha256
from .exceptions import MigrationError
from .ingest import SourceInputError, extract_line_quote, parse_json_content, source_lines
from .limits import (
    MAX_CLAIM_METADATA_UTF8_BYTES,
    MAX_CLAIM_RATIONALE_UTF8_BYTES,
    MAX_CLAIM_TEXT_UTF8_BYTES,
    MAX_EVENT_DETAILS_JSON_BYTES,
    MAX_EVENT_SUMMARY_UTF8_BYTES,
    MAX_EVENT_TITLE_UTF8_BYTES,
)
from .models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    LedgerEntry,
    NarrativeEvent,
    Source,
)
from .schema import (
    ALLOWED_MIGRATIONS,
    SchemaFingerprint,
    SchemaKind,
    fingerprint_schema,
)
from .source_integrity import (
    SourceAuditSnapshot,
    replay_source_audits,
)
from .sqlite_safety import SQLiteSidecarError, validate_readonly_sidecars
from .timeutil import parse_instant


GENESIS_HASH = "0" * 64
MAX_MIGRATION_DATABASE_BYTES = 1024 * 1024 * 1024
MAX_MIGRATION_ROWS_PER_TABLE = 250_000
MAX_MIGRATION_TOTAL_ROWS = 1_000_000
MAX_METADATA_UTF8_BYTES = 4096
_BIDI_CONTROL_CLASSES = frozenset({"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"})
_ACCESS = frozenset({"agent_accessible", "human_only", "hidden"})
_STATUSES = frozenset({"PROPOSED", "AUTHORIZED", "REJECTED", "DISPUTED"})
_TRANSITIONS = {
    "PROPOSED": frozenset({"AUTHORIZED", "REJECTED", "DISPUTED"}),
    "AUTHORIZED": frozenset({"DISPUTED"}),
    "REJECTED": frozenset({"DISPUTED"}),
    "DISPUTED": frozenset({"AUTHORIZED", "REJECTED"}),
}


class MigrationMode(str, Enum):
    """Legacy-data policy selected explicitly by the operator."""

    STRICT = "strict"
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class MigrationIssue:
    """One stable, machine-readable migration finding."""

    code: str
    message: str
    table: str | None = None
    record_id: str | None = None
    field: str | None = None
    actual: Any = None
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "table": _safe_report_identifier(self.table),
            "record_id": _safe_report_identifier(self.record_id),
            "field": _safe_report_identifier(self.field),
            "actual": _safe_issue_actual(self.actual, field=self.field),
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """Frozen result of preflight or migration execution."""

    mode: MigrationMode
    source: SchemaFingerprint
    target_version: int = SCHEMA_VERSION
    status: str = "preflight"
    issues: tuple[MigrationIssue, ...] = ()
    quick_check: str = "not-run"
    foreign_key_violations: int = 0
    database_bytes: int | None = None
    required_free_bytes: int | None = None
    available_free_bytes: int | None = None
    backup_path: str | None = None
    backup_sha256: str | None = None
    target: SchemaFingerprint | None = None
    started_at: str | None = None
    finished_at: str | None = None
    migrated_counts: tuple[tuple[str, int], ...] = ()
    attestation_material_version: int | None = None
    attestation_counts: tuple[tuple[str, int], ...] = ()
    quarantined: tuple[tuple[str, str], ...] = ()

    @property
    def is_ready(self) -> bool:
        return (
            not any(issue.severity == "error" for issue in self.issues)
            and self.quick_check.lower() == "ok"
            and self.foreign_key_violations == 0
            and (
                self.source.kind in {SchemaKind.EMPTY, SchemaKind.V03}
                or (self.source.kind, SchemaKind.V03) in ALLOWED_MIGRATIONS
            )
        )

    @property
    def succeeded(self) -> bool:
        return self.status in {"initialized", "migrated", "already-current"}

    @property
    def changed(self) -> bool:
        return self.status in {"initialized", "migrated"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MIGRATION_REPORT_SCHEMA,
            "mode": self.mode.value,
            "source": self.source.to_dict(),
            "target_version": self.target_version,
            "status": self.status,
            "is_ready": self.is_ready,
            "succeeded": self.succeeded,
            "changed": self.changed,
            "issues": [issue.to_dict() for issue in self.issues],
            "checks": {
                "quick_check": self.quick_check,
                "foreign_key_violations": self.foreign_key_violations,
                "database_bytes": self.database_bytes,
                "required_free_bytes": self.required_free_bytes,
                "available_free_bytes": self.available_free_bytes,
                "backup_path": self.backup_path,
                "backup_sha256": self.backup_sha256,
            },
            "target": self.target.to_dict() if self.target is not None else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "migrated_counts": dict(self.migrated_counts),
            "attestations": {
                "material_version": self.attestation_material_version,
                "claims": dict(self.attestation_counts).get("claims", 0),
                "events": dict(self.attestation_counts).get("events", 0),
            },
            "quarantine": {
                "count": len(self.quarantined),
                "records": [
                    {
                        "table": _safe_report_identifier(table),
                        "record_id": _safe_report_identifier(record_id),
                    }
                    for table, record_id in self.quarantined
                ],
            },
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent
        )


@dataclass(frozen=True, slots=True)
class MaterialAttestationTarget:
    """One legacy creation entry that needs a v2 material checkpoint."""

    aggregate_id: str
    creation_entry_id: str


@dataclass(frozen=True, slots=True)
class LegacyMaterialPlan:
    """Write-free plan for establishing v2 material checkpoints."""

    source_kind: SchemaKind
    claim_backfills: tuple[str, ...] = ()
    event_backfills: tuple[str, ...] = ()
    claim_attestations: tuple[MaterialAttestationTarget, ...] = ()
    event_attestations: tuple[MaterialAttestationTarget, ...] = ()
    issues: tuple[MigrationIssue, ...] = ()
    requires_explicit_attestation: bool = False

    @property
    def checkpoint_counts(self) -> tuple[tuple[str, int], ...]:
        return (
            ("claims", len(self.claim_attestations)),
            ("events", len(self.event_attestations)),
        )

    @property
    def acceptance_counts(self) -> tuple[tuple[str, int], ...]:
        """Rows whose current legacy material needs operator acceptance."""

        return (
            (
                "claims",
                len(self.claim_backfills) + len(self.claim_attestations),
            ),
            (
                "events",
                len(self.event_backfills) + len(self.event_attestations),
            ),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


_SENSITIVE_REPORT_FIELDS = frozenset(
    {
        "quote",
        "content",
        "text",
        "title",
        "summary",
        "details",
        "details_json",
        "origin_path",
        "path",
        "payload_json",
    }
)


def _redacted_descriptor(value: object) -> dict[str, Any]:
    """Describe sensitive diagnostics without serializing their body."""

    if isinstance(value, str):
        data = value.encode("utf-8", errors="surrogatepass")
        return {
            "redacted": True,
            "type": "str",
            "length": len(value),
            "sha256": sha256(data).hexdigest(),
        }
    if isinstance(value, bytes):
        return {
            "redacted": True,
            "type": "bytes",
            "length": len(value),
            "sha256": sha256(value).hexdigest(),
        }
    material = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda item: type(item).__name__,
    ).encode("utf-8", errors="surrogatepass")
    length = len(value) if hasattr(value, "__len__") else None
    return {
        "redacted": True,
        "type": type(value).__name__,
        "length": length,
        "sha256": sha256(material).hexdigest(),
    }


def _safe_issue_actual(value: object, *, field: str | None = None) -> object:
    """Return bounded, path-safe migration diagnostics for JSON reports."""

    if field is not None and field.lower() in _SENSITIVE_REPORT_FIELDS:
        return _redacted_descriptor(value)
    if isinstance(value, Path):
        return _redacted_descriptor(value)
    if isinstance(value, str):
        try:
            is_absolute = Path(value).is_absolute()
        except (OSError, ValueError):
            is_absolute = False
        unsafe = any(
            unicodedata.category(character) in {"Cc", "Cs"}
            or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
            for character in value
        )
        if is_absolute or len(value) > 256 or unsafe:
            return _redacted_descriptor(value)
        return value
    if isinstance(value, bytes):
        return _redacted_descriptor(value)
    if isinstance(value, Mapping):
        return {
            str(key): _safe_issue_actual(child, field=str(key))
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        if len(value) > 50:
            return _redacted_descriptor(value)
        return [_safe_issue_actual(child) for child in value]
    if isinstance(value, float) and not math.isfinite(value):
        return {
            "type": "float",
            "value": "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf"),
        }
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return {"redacted": True, "type": type(value).__name__}


def _safe_report_identifier(value: str | None) -> object:
    """Keep ordinary IDs useful while bounding attacker-controlled v0.1 keys."""

    if value is None:
        return None
    unsafe_control = any(
        unicodedata.category(character) in {"Cc", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
        for character in value
    )
    try:
        absolute = Path(value).is_absolute()
    except (OSError, ValueError):
        absolute = False
    try:
        too_many_bytes = len(value.encode("utf-8")) > 256
    except UnicodeError:
        too_many_bytes = True
    if len(value) > 128 or too_many_bytes or unsafe_control or absolute:
        return _redacted_descriptor(value)
    return value


def _issue(
    issues: list[MigrationIssue],
    code: str,
    message: str,
    *,
    table: str | None = None,
    record_id: object | None = None,
    field: str | None = None,
    actual: Any = None,
    severity: str = "error",
) -> None:
    issues.append(
        MigrationIssue(
            code=code,
            message=message,
            table=table,
            record_id=None if record_id is None else str(record_id),
            field=field,
            actual=actual,
            severity=severity,
        )
    )


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _check_aggregate_utf8_bytes(
    issues: list[MigrationIssue],
    value: object,
    *,
    table: str,
    record_id: object,
    field: str,
    max_bytes: int,
    code: str,
) -> None:
    """Fail closed when legacy aggregate text cannot fit the target schema.

    Migration never truncates or normalizes persisted material.  Non-text
    values remain the responsibility of the existing semantic validators; this
    helper only performs a strict UTF-8 encoding and exact byte count.
    """

    if value is None or not isinstance(value, str):
        return
    try:
        actual_bytes = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        _issue(
            issues,
            "INVALID_UNICODE",
            f"{field} cannot be encoded as UTF-8",
            table=table,
            record_id=record_id,
            field=field,
            actual={"type": "str"},
        )
        return
    if actual_bytes > max_bytes:
        _issue(
            issues,
            code,
            f"{field} exceeds the target UTF-8 byte limit",
            table=table,
            record_id=record_id,
            field=field,
            actual={"bytes": actual_bytes, "limit": max_bytes},
        )


def _check_time(
    issues: list[MigrationIssue],
    value: object,
    *,
    table: str,
    record_id: object,
    field: str,
    required: bool = False,
) -> None:
    if value is None or value == "":
        if required:
            _issue(
                issues,
                "MIGRATION_TIME_REQUIRED",
                f"{field} is required",
                table=table,
                record_id=record_id,
                field=field,
                actual=value,
            )
        return
    if not isinstance(value, str):
        _issue(
            issues,
            "MIGRATION_TIME_INVALID",
            f"{field} must be ISO-8601 text",
            table=table,
            record_id=record_id,
            field=field,
            actual=value,
        )
        return
    try:
        parse_instant(value)
    except (TypeError, ValueError, OverflowError):
        _issue(
            issues,
            "MIGRATION_TIME_INVALID",
            f"{field} is not a valid ISO-8601 instant",
            table=table,
            record_id=record_id,
            field=field,
            actual=value,
        )


def _check_interval(
    issues: list[MigrationIssue],
    start: object,
    end: object,
    *,
    table: str,
    record_id: object,
    name: str,
) -> None:
    if start in (None, "") or end in (None, ""):
        return
    try:
        lower = parse_instant(start)  # type: ignore[arg-type]
        upper = parse_instant(end)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return
    if lower is not None and upper is not None and lower >= upper:
        _issue(
            issues,
            "MIGRATION_INTERVAL_INVALID",
            f"{name} start must be earlier than end",
            table=table,
            record_id=record_id,
            field=name,
            actual={"start": start, "end": end},
        )


def _rows(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    escaped = '"' + table.replace('"', '""') + '"'
    return [dict(row) for row in connection.execute(f"SELECT * FROM {escaped}")]


def _claim_material_model(row: Mapping[str, Any]) -> ClaimProposal:
    return ClaimProposal(
        claim_id=str(row["claim_id"]),
        persona_id=str(row["persona_id"]),
        continuity=str(row["continuity"]),
        text=str(row["text"]),
        subject=row.get("subject"),
        predicate=row.get("predicate"),
        object_value=row.get("object_value"),
        valid_from=row.get("valid_from"),
        valid_to=row.get("valid_to"),
        knowledge_from=row.get("knowledge_from"),
        knowledge_to=row.get("knowledge_to"),
        access_policy=AccessPolicy(str(row["access_policy"])),
        confidence=float(row["confidence"]),
        proposed_by=row.get("proposed_by"),
        proposal_model=row.get("proposal_model"),
        rationale=row.get("rationale"),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _event_material_model(row: Mapping[str, Any]) -> NarrativeEvent:
    details = json.loads(str(row["details_json"]))
    if not isinstance(details, Mapping):
        raise ValueError("NarrativeEvent details_json must decode to an object")
    return NarrativeEvent(
        event_id=str(row["event_id"]),
        persona_id=str(row["persona_id"]),
        continuity=str(row["continuity"]),
        event_type=str(row["event_type"]),
        title=str(row["title"]),
        summary=str(row["summary"]),
        details=dict(details),
        valid_from=row.get("valid_from"),
        valid_to=row.get("valid_to"),
        knowledge_from=row.get("knowledge_from"),
        knowledge_to=row.get("knowledge_to"),
        access_policy=AccessPolicy(str(row["access_policy"])),
        created_at=str(row["created_at"]),
    )


def _evidence_material_model(
    row: Mapping[str, Any], *, aggregate_type: str
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=str(row["evidence_id"]),
        claim_id=(str(row["claim_id"]) if aggregate_type == "claim" else None),
        event_id=(
            str(row["event_id"])
            if aggregate_type == "narrative_event"
            else None
        ),
        snapshot_id=str(row["snapshot_id"]),
        start_line=int(row["start_line"]),
        end_line=int(row["end_line"]),
        start_char=row.get("start_char"),
        end_char=row.get("end_char"),
        quote=row.get("quote"),
        content_hash=row.get("content_hash"),
        created_at=str(row["created_at"]),
    )


def _material_issue(
    issues: list[MigrationIssue],
    code: str,
    message: str,
    *,
    aggregate_type: str,
    aggregate_id: str,
    actual: object = None,
) -> None:
    _issue(
        issues,
        code,
        message,
        table="event_ledger",
        record_id=aggregate_id,
        field="payload_json",
        actual=actual,
    )


def _parse_ledger_payload(row: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = json.loads(str(row.get("payload_json")))
    if not isinstance(payload, Mapping):
        raise ValueError("ledger payload must be a JSON object")
    return payload


def _check_material_entry(
    *,
    aggregate_type: str,
    aggregate_id: str,
    creation_event_type: str,
    creation_rows: list[dict[str, Any]],
    attestation_rows: list[dict[str, Any]],
    creation_digests: AuditMaterialDigests | None,
    attestation_digests: AuditMaterialDigests,
    source_kind: SchemaKind,
    allow_backfill: bool,
    issues: list[MigrationIssue],
) -> tuple[str, MaterialAttestationTarget | None]:
    """Return ``backfill``, ``attest``, or ``existing`` for one aggregate."""

    if len(creation_rows) != 1:
        if not creation_rows and allow_backfill and not attestation_rows:
            return "backfill", None
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_CREATION_CORRESPONDENCE_INVALID",
            "material migration requires exactly one creation ledger entry",
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            actual={
                "creation_entries": len(creation_rows),
                "attestation_entries": len(attestation_rows),
            },
        )
        return "invalid", None

    creation = creation_rows[0]
    try:
        creation_payload = _parse_ledger_payload(creation)
        stored_creation_digests = parse_material_digests(creation_payload)
    except (
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeError,
    ) as exc:
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_PAYLOAD_INVALID",
            "creation ledger material fields are malformed",
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            actual={"error_type": type(exc).__name__},
        )
        return "invalid", None

    if len(attestation_rows) > 1:
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_ATTESTATION_CORRESPONDENCE_INVALID",
            "a legacy creation entry may have at most one material attestation",
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            actual=len(attestation_rows),
        )
        return "invalid", None

    if stored_creation_digests is not None:
        if attestation_rows:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_ATTESTATION_REDUNDANT",
                "a v2 creation entry must not also have a material attestation",
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
            )
            return "invalid", None
        if creation_digests is None or stored_creation_digests != creation_digests:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_DIGEST_MISMATCH",
                "creation ledger material digest differs from persisted material",
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
            )
            return "invalid", None
        return "v2", None

    if attestation_rows:
        # Alpha2/alpha3/v0.2 did not have a protected, explicit migration
        # attestation operation.  Accepting a pre-existing lookalike would let
        # the database being migrated decide that the current operator had
        # consented.  The sole admitted attestation is appended by this
        # migration invocation after its explicit opt-in and verified backup.
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_ATTESTATION_PREEXISTING",
            "legacy schemas must not contain pre-existing material attestations",
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            actual=len(attestation_rows),
        )
        return "invalid", None

    return (
        "attest",
        MaterialAttestationTarget(
            aggregate_id=aggregate_id,
            creation_entry_id=str(creation["entry_id"]),
        ),
    )


def _validate_claim_evidence_material_checkpoints(
    *,
    claim_id: str,
    claim: ClaimProposal,
    creation_payload: Mapping[str, Any],
    current_evidence: list[EvidenceRef],
    ledger: list[dict[str, Any]],
    issues: list[MigrationIssue],
    require_material: bool = True,
) -> None:
    """Validate cumulative Evidence checkpoints before backup.

    A v2 creation requires material digests on every subsequent
    ``claim.evidence_added`` entry.  A legacy creation may omit those fields,
    but once any material field is present the complete checkpoint must be
    valid; partial or forged hybrid streams therefore fail closed.
    """

    evidence_by_id = {str(item.evidence_id): item for item in current_evidence}
    initial_ids = creation_payload.get("evidence_ids")
    if not isinstance(initial_ids, list) or any(
        not isinstance(item, str) or not item for item in initial_ids
    ):
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_EVIDENCE_SET_INVALID",
            "v2 claim creation must identify its initial Evidence set",
            aggregate_type="claim",
            aggregate_id=claim_id,
        )
        return
    if len(set(initial_ids)) != len(initial_ids) or any(
        item not in evidence_by_id for item in initial_ids
    ):
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_EVIDENCE_SET_INVALID",
            "v2 claim creation names duplicate or unknown Evidence rows",
            aggregate_type="claim",
            aggregate_id=claim_id,
        )
        return

    audited_ids = list(initial_ids)
    added_entries = [
        entry
        for entry in ledger
        if entry.get("event_type") == CLAIM_EVIDENCE_EVENT
        and entry.get("aggregate_type") == "claim"
        and entry.get("aggregate_id") == claim_id
    ]
    try:
        added_entries.sort(key=lambda entry: int(entry["sequence"]))
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_EVIDENCE_CHECKPOINT_INVALID",
            "Evidence checkpoint ordering is malformed",
            aggregate_type="claim",
            aggregate_id=claim_id,
            actual={"error_type": type(exc).__name__},
        )
        return

    for entry in added_entries:
        try:
            payload = _parse_ledger_payload(entry)
            evidence_id = payload.get("evidence_id")
            if (
                not isinstance(evidence_id, str)
                or evidence_id not in evidence_by_id
                or evidence_id in audited_ids
            ):
                raise ValueError("Evidence checkpoint names a duplicate or unknown row")
            audited_ids.append(evidence_id)
            stored = parse_material_digests(payload)
            if stored is None and require_material:
                raise ValueError("Evidence checkpoint omits v2 material digests")
            if stored is not None:
                expected = claim_material_digests(
                    claim,
                    [evidence_by_id[item] for item in audited_ids],
                )
                if stored != expected:
                    raise ValueError("Evidence checkpoint digest mismatch")
        except (
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            UnicodeError,
        ) as exc:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_EVIDENCE_CHECKPOINT_INVALID",
                "claim.evidence_added material checkpoint is invalid",
                aggregate_type="claim",
                aggregate_id=claim_id,
                actual={"error_type": type(exc).__name__},
            )

    if set(audited_ids) != set(evidence_by_id):
        _material_issue(
            issues,
            "MIGRATION_MATERIAL_EVIDENCE_SET_MISMATCH",
            "the final v2 Evidence checkpoint differs from stored Evidence rows",
            aggregate_type="claim",
            aggregate_id=claim_id,
            actual={
                "audited": len(set(audited_ids)),
                "stored": len(evidence_by_id),
            },
        )


def plan_legacy_material_checkpoints(
    connection: sqlite3.Connection,
    kind: SchemaKind,
) -> LegacyMaterialPlan:
    """Inspect legacy material binding without writing SQLite.

    v0.1 has no EventLedger and creates v2 checkpoints while converting rows.
    v0.2 may backfill an all-empty legacy stream.  Alpha2/alpha3 must already
    have exactly one creation entry and can only add a bound attestation when
    that historical payload predates material v2.
    """

    if kind is SchemaKind.V01:
        return LegacyMaterialPlan(
            source_kind=kind,
            claim_backfills=tuple(
                sorted(str(row.get("id")) for row in _rows(connection, "claims"))
            ),
            event_backfills=tuple(
                sorted(
                    str(row.get("id"))
                    for table in ("narrative_events", "events")
                    if table in {
                        str(item[0])
                        for item in connection.execute(
                            "SELECT name FROM sqlite_master WHERE type = 'table'"
                        ).fetchall()
                    }
                    for row in _rows(connection, table)
                )
            ),
        )

    if kind not in {
        SchemaKind.V02,
        SchemaKind.V03_ALPHA2,
        SchemaKind.V03_ALPHA3,
    }:
        return LegacyMaterialPlan(source_kind=kind)

    issues: list[MigrationIssue] = []
    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    ledger = _rows(connection, "event_ledger")
    claim_rows = {str(row["claim_id"]): row for row in _rows(connection, "claim_proposals")}
    event_rows = {str(row["event_id"]): row for row in _rows(connection, "narrative_events")}
    claim_evidence_rows: dict[str, list[dict[str, Any]]] = {}
    for row in _rows(connection, "evidence_refs"):
        claim_evidence_rows.setdefault(str(row["claim_id"]), []).append(row)
    event_evidence_rows: dict[str, list[dict[str, Any]]] = {}
    if "event_evidence_refs" in table_names:
        for row in _rows(connection, "event_evidence_refs"):
            event_evidence_rows.setdefault(str(row["event_id"]), []).append(row)

    material_event_scopes = {
        CLAIM_CREATION_EVENT: ("claim", set(claim_rows)),
        CLAIM_EVIDENCE_EVENT: ("claim", set(claim_rows)),
        CLAIM_ATTESTATION_EVENT: ("claim", set(claim_rows)),
        EVENT_CREATION_EVENT: ("narrative_event", set(event_rows)),
        EVENT_ATTESTATION_EVENT: ("narrative_event", set(event_rows)),
    }
    for entry in ledger:
        expected = material_event_scopes.get(str(entry.get("event_type")))
        if expected is None:
            continue
        expected_type, known_ids = expected
        aggregate_id = str(entry.get("aggregate_id"))
        if entry.get("aggregate_type") != expected_type or aggregate_id not in known_ids:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_EVENT_SCOPE_INVALID",
                "material ledger event has the wrong aggregate scope",
                aggregate_type=expected_type,
                aggregate_id=aggregate_id,
                actual={
                    "event_type": entry.get("event_type"),
                    "aggregate_type": entry.get("aggregate_type"),
                },
            )

    claim_backfills: list[str] = []
    event_backfills: list[str] = []
    claim_attestations: list[MaterialAttestationTarget] = []
    event_attestations: list[MaterialAttestationTarget] = []
    allow_backfill = kind is SchemaKind.V02

    for claim_id, row in sorted(claim_rows.items()):
        creations = [
            item
            for item in ledger
            if item.get("event_type") == CLAIM_CREATION_EVENT
            and item.get("aggregate_type") == "claim"
            and item.get("aggregate_id") == claim_id
        ]
        attestations = [
            item
            for item in ledger
            if item.get("event_type") == CLAIM_ATTESTATION_EVENT
            and item.get("aggregate_type") == "claim"
            and item.get("aggregate_id") == claim_id
        ]
        creation_payload: Mapping[str, Any] = {}
        try:
            claim = _claim_material_model(row)
            current_evidence = [
                _evidence_material_model(item, aggregate_type="claim")
                for item in claim_evidence_rows.get(claim_id, [])
            ]
            attestation_digests = claim_material_digests(claim, current_evidence)
            creation_digests: AuditMaterialDigests | None = None
            if len(creations) == 1:
                creation_payload = _parse_ledger_payload(creations[0])
                evidence_ids = creation_payload.get("evidence_ids")
                if isinstance(evidence_ids, list) and all(
                    isinstance(item, str) for item in evidence_ids
                ):
                    evidence_by_id = {
                        str(item.evidence_id): item for item in current_evidence
                    }
                    if all(item in evidence_by_id for item in evidence_ids):
                        creation_digests = claim_material_digests(
                            claim,
                            [evidence_by_id[item] for item in evidence_ids],
                        )
        except (
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            UnicodeError,
        ) as exc:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_COMPUTATION_INVALID",
                "claim material cannot be canonically hashed",
                aggregate_type="claim",
                aggregate_id=claim_id,
                actual={"error_type": type(exc).__name__},
            )
            continue
        action, target = _check_material_entry(
            aggregate_type="claim",
            aggregate_id=claim_id,
            creation_event_type=CLAIM_CREATION_EVENT,
            creation_rows=creations,
            attestation_rows=attestations,
            creation_digests=creation_digests,
            attestation_digests=attestation_digests,
            source_kind=kind,
            allow_backfill=allow_backfill,
            issues=issues,
        )
        if action == "backfill":
            claim_backfills.append(claim_id)
        elif action == "attest" and target is not None:
            claim_attestations.append(target)
            _validate_claim_evidence_material_checkpoints(
                claim_id=claim_id,
                claim=claim,
                creation_payload=creation_payload,
                current_evidence=current_evidence,
                ledger=ledger,
                issues=issues,
                require_material=False,
            )
        elif action == "v2":
            _validate_claim_evidence_material_checkpoints(
                claim_id=claim_id,
                claim=claim,
                creation_payload=creation_payload,
                current_evidence=current_evidence,
                ledger=ledger,
                issues=issues,
            )

    for event_id, row in sorted(event_rows.items()):
        creations = [
            item
            for item in ledger
            if item.get("event_type") == EVENT_CREATION_EVENT
            and item.get("aggregate_type") == "narrative_event"
            and item.get("aggregate_id") == event_id
        ]
        attestations = [
            item
            for item in ledger
            if item.get("event_type") == EVENT_ATTESTATION_EVENT
            and item.get("aggregate_type") == "narrative_event"
            and item.get("aggregate_id") == event_id
        ]
        try:
            event = _event_material_model(row)
            evidence = [
                _evidence_material_model(item, aggregate_type="narrative_event")
                for item in event_evidence_rows.get(event_id, [])
            ]
            digests = event_material_digests(event, evidence)
        except (
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            UnicodeError,
        ) as exc:
            _material_issue(
                issues,
                "MIGRATION_MATERIAL_COMPUTATION_INVALID",
                "NarrativeEvent material cannot be canonically hashed",
                aggregate_type="narrative_event",
                aggregate_id=event_id,
                actual={"error_type": type(exc).__name__},
            )
            continue
        action, target = _check_material_entry(
            aggregate_type="narrative_event",
            aggregate_id=event_id,
            creation_event_type=EVENT_CREATION_EVENT,
            creation_rows=creations,
            attestation_rows=attestations,
            creation_digests=digests,
            attestation_digests=digests,
            source_kind=kind,
            allow_backfill=allow_backfill,
            issues=issues,
        )
        if action == "backfill":
            event_backfills.append(event_id)
        elif action == "attest" and target is not None:
            event_attestations.append(target)

    requires_explicit = bool(
        claim_backfills
        or event_backfills
        or claim_attestations
        or event_attestations
    )
    return LegacyMaterialPlan(
        source_kind=kind,
        claim_backfills=tuple(claim_backfills),
        event_backfills=tuple(event_backfills),
        claim_attestations=tuple(claim_attestations),
        event_attestations=tuple(event_attestations),
        issues=tuple(issues),
        requires_explicit_attestation=requires_explicit,
    )


def _required_id(
    issues: list[MigrationIssue],
    value: object,
    *,
    table: str,
    record_id: object,
    field: str,
) -> str | None:
    if not _valid_metadata_text(value):
        _issue(
            issues,
            "MIGRATION_ID_INVALID",
            f"{field} must be a non-empty string",
            table=table,
            record_id=record_id,
            field=field,
            actual=type(value).__name__,
        )
        return None
    return value


def _valid_metadata_text(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        if len(value.encode("utf-8")) > MAX_METADATA_UTF8_BYTES:
            return False
    except UnicodeError:
        return False
    return not any(
        unicodedata.category(character) in {"Cc", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
        for character in value
    )


def _validate_v01(connection: sqlite3.Connection) -> list[MigrationIssue]:
    issues: list[MigrationIssue] = []
    snapshots = _rows(connection, "source_snapshots")
    snapshot_map: dict[str, dict[str, Any]] = {}
    for row in snapshots:
        record_id = row.get("id")
        snapshot_id = _required_id(
            issues, record_id, table="source_snapshots", record_id=record_id, field="id"
        )
        if snapshot_id is not None:
            snapshot_map[snapshot_id] = row
        _required_id(
            issues,
            row.get("path"),
            table="source_snapshots",
            record_id=record_id,
            field="path",
        )
        content = row.get("content")
        if not isinstance(content, str):
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_CONTENT_INVALID",
                "snapshot content must be text",
                table="source_snapshots",
                record_id=record_id,
                field="content",
                actual=type(content).__name__,
            )
        digest = row.get("sha256")
        if not _valid_digest(digest):
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_HASH_INVALID",
                "snapshot sha256 must be 64 hexadecimal characters",
                table="source_snapshots",
                record_id=record_id,
                field="sha256",
                actual=digest,
            )
        elif isinstance(content, str) and str(digest).lower() != sha256(
            content.encode("utf-8")
        ).hexdigest():
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_HASH_MISMATCH",
                "snapshot sha256 does not match content",
                table="source_snapshots",
                record_id=record_id,
                field="sha256",
                actual=digest,
            )
        if not _valid_metadata_text(row.get("continuity")):
            _issue(
                issues,
                "MIGRATION_CONTINUITY_REQUIRED",
                "snapshot continuity is required",
                table="source_snapshots",
                record_id=record_id,
                field="continuity",
                actual=row.get("continuity"),
            )
        _check_time(
            issues,
            row.get("created_at"),
            table="source_snapshots",
            record_id=record_id,
            field="created_at",
            required=True,
        )

    for row in _rows(connection, "claims"):
        record_id = row.get("id")
        _required_id(
            issues, record_id, table="claims", record_id=record_id, field="id"
        )
        for field in ("persona_id", "continuity", "claim"):
            valid = (
                _valid_metadata_text(row.get(field))
                if field in {"persona_id", "continuity"}
                else isinstance(row.get(field), str) and bool(row[field].strip())
            )
            if not valid:
                _issue(
                    issues,
                    "MIGRATION_REQUIRED_TEXT_MISSING",
                    f"claim {field} is required",
                    table="claims",
                    record_id=record_id,
                    field=field,
                    actual=row.get(field),
                )
        _check_aggregate_utf8_bytes(
            issues,
            row.get("claim"),
            table="claims",
            record_id=record_id,
            field="claim",
            max_bytes=MAX_CLAIM_TEXT_UTF8_BYTES,
            code="CLAIM_TEXT_BYTES_LIMIT",
        )
        for field in ("subject", "predicate", "object_value"):
            _check_aggregate_utf8_bytes(
                issues,
                row.get(field),
                table="claims",
                record_id=record_id,
                field=field,
                max_bytes=MAX_CLAIM_METADATA_UTF8_BYTES,
                code="CLAIM_METADATA_BYTES_LIMIT",
            )
        access = row.get("access_policy")
        if access not in _ACCESS:
            _issue(
                issues,
                "MIGRATION_ACCESS_INVALID",
                "legacy access policy must be explicit and recognized",
                table="claims",
                record_id=record_id,
                field="access_policy",
                actual=access,
            )
        if "status" in row or "governance_status" in row:
            raw_status = row.get("status", row.get("governance_status"))
            status_aliases = {
                "accepted",
                "approved",
                "active",
                "denied",
                "invalid",
                "pending",
                "conflicted",
            }
            if not isinstance(raw_status, str) or (
                raw_status.strip().upper() not in _STATUSES
                and raw_status.strip().lower() not in status_aliases
            ):
                _issue(
                    issues,
                    "MIGRATION_STATUS_INVALID",
                    "explicit legacy governance status is missing or unrecognized",
                    table="claims",
                    record_id=record_id,
                    field="status",
                    actual=raw_status,
                )
        confidence = row.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            _issue(
                issues,
                "MIGRATION_CONFIDENCE_INVALID",
                "claim confidence must be finite and between 0 and 1",
                table="claims",
                record_id=record_id,
                field="confidence",
                actual=confidence,
            )
        for field in (
            "valid_from",
            "valid_until",
            "knowledge_from",
            "knowledge_until",
        ):
            _check_time(
                issues,
                row.get(field),
                table="claims",
                record_id=record_id,
                field=field,
            )
        _check_time(
            issues,
            row.get("created_at"),
            table="claims",
            record_id=record_id,
            field="created_at",
            required=True,
        )
        _check_interval(
            issues,
            row.get("valid_from"),
            row.get("valid_until"),
            table="claims",
            record_id=record_id,
            name="valid_interval",
        )
        _check_interval(
            issues,
            row.get("knowledge_from"),
            row.get("knowledge_until"),
            table="claims",
            record_id=record_id,
            name="knowledge_interval",
        )

        snapshot_id = _required_id(
            issues,
            row.get("source_snapshot_id"),
            table="claims",
            record_id=record_id,
            field="source_snapshot_id",
        )
        snapshot = snapshot_map.get(snapshot_id) if snapshot_id is not None else None
        if snapshot is None:
            _issue(
                issues,
                "MIGRATION_EVIDENCE_SNAPSHOT_MISSING",
                "claim source snapshot does not exist",
                table="claims",
                record_id=record_id,
                field="source_snapshot_id",
                actual=snapshot_id,
            )
            continue
        if row.get("continuity") != snapshot.get("continuity"):
            _issue(
                issues,
                "MIGRATION_EVIDENCE_CONTINUITY_MISMATCH",
                "claim and source snapshot continuities differ",
                table="claims",
                record_id=record_id,
                field="continuity",
                actual={
                    "claim": row.get("continuity"),
                    "snapshot": snapshot.get("continuity"),
                },
            )
        start, end = row.get("start_line"), row.get("end_line")
        line_count = (
            len(source_lines(snapshot["content"]))
            if isinstance(snapshot.get("content"), str)
            else 0
        )
        if (
            type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or end > line_count
        ):
            _issue(
                issues,
                "MIGRATION_EVIDENCE_RANGE_INVALID",
                "claim evidence lines are malformed or out of bounds",
                table="claims",
                record_id=record_id,
                field="line_range",
                actual={"start_line": start, "end_line": end, "line_count": line_count},
            )

    # Some permissive v0.1 databases included operator-authored events.  They
    # are migrated only when their access and temporal bounds are explicit and
    # valid; otherwise quarantine retains the raw row without a domain event.
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for table in ("narrative_events", "events"):
        if table not in tables:
            continue
        for row in _rows(connection, table):
            record_id = row.get("event_id", row.get("id"))
            _required_id(
                issues,
                record_id,
                table=table,
                record_id=record_id,
                field="event_id" if "event_id" in row else "id",
            )
            for field in ("persona_id", "continuity"):
                if not _valid_metadata_text(row.get(field)):
                    _issue(
                        issues,
                        "MIGRATION_REQUIRED_TEXT_MISSING",
                        f"event {field} is required",
                        table=table,
                        record_id=record_id,
                        field=field,
                        actual=row.get(field),
                    )
            _check_aggregate_utf8_bytes(
                issues,
                row.get("title"),
                table=table,
                record_id=record_id,
                field="title",
                max_bytes=MAX_EVENT_TITLE_UTF8_BYTES,
                code="EVENT_TITLE_BYTES_LIMIT",
            )
            _check_aggregate_utf8_bytes(
                issues,
                row.get("summary", row.get("text")),
                table=table,
                record_id=record_id,
                field="summary",
                max_bytes=MAX_EVENT_SUMMARY_UTF8_BYTES,
                code="EVENT_SUMMARY_BYTES_LIMIT",
            )
            details_field = "details_json" if "details_json" in row else "details"
            if details_field in row:
                _check_aggregate_utf8_bytes(
                    issues,
                    row.get(details_field),
                    table=table,
                    record_id=record_id,
                    field=details_field,
                    max_bytes=MAX_EVENT_DETAILS_JSON_BYTES,
                    code="MIGRATION_EVENT_DETAILS_INVALID",
                )
            access = row.get("access_policy", row.get("access"))
            if access not in _ACCESS:
                _issue(
                    issues,
                    "MIGRATION_ACCESS_INVALID",
                    "legacy event access policy must be explicit and recognized",
                    table=table,
                    record_id=record_id,
                    field="access_policy",
                    actual=access,
                )
            for field in (
                "valid_from",
                "valid_to",
                "valid_until",
                "knowledge_from",
                "knowledge_to",
                "knowledge_until",
                "created_at",
            ):
                if field in row:
                    _check_time(
                        issues,
                        row.get(field),
                        table=table,
                        record_id=record_id,
                        field=field,
                        required=field == "created_at",
                    )
    return issues


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def _ledger_digest(row: Mapping[str, Any]) -> str:
    material = _canonical_json(
        {
            "sequence": int(row["sequence"]),
            "entry_id": str(row["entry_id"]),
            "event_type": str(row["event_type"]),
            "aggregate_type": str(row["aggregate_type"]),
            "aggregate_id": str(row["aggregate_id"]),
            "payload_json": str(row["payload_json"]),
            "previous_hash": str(row["previous_hash"]),
            "created_at": str(row["created_at"]),
        }
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _validate_v02(connection: sqlite3.Connection) -> list[MigrationIssue]:
    issues: list[MigrationIssue] = []
    sources: dict[str, dict[str, Any]] = {}
    for row in _rows(connection, "sources"):
        source_id = _required_id(
            issues, row.get("source_id"), table="sources", record_id=row.get("source_id"), field="source_id"
        )
        if source_id is not None:
            sources[source_id] = row
    snapshots: dict[str, dict[str, Any]] = {}
    for row in _rows(connection, "source_snapshots"):
        snapshot_id = _required_id(
            issues, row.get("snapshot_id"), table="source_snapshots", record_id=row.get("snapshot_id"), field="snapshot_id"
        )
        if snapshot_id is not None:
            snapshots[snapshot_id] = row
    claims: dict[str, dict[str, Any]] = {}
    for row in _rows(connection, "claim_proposals"):
        claim_id = _required_id(
            issues, row.get("claim_id"), table="claim_proposals", record_id=row.get("claim_id"), field="claim_id"
        )
        if claim_id is not None:
            claims[claim_id] = row
    stored_evidence_by_claim: dict[str, list[str]] = {}
    stored_evidence_rows_by_claim: dict[str, dict[str, dict[str, Any]]] = {}
    for row in _rows(connection, "evidence_refs"):
        evidence_id = _required_id(
            issues, row.get("evidence_id"), table="evidence_refs", record_id=row.get("evidence_id"), field="evidence_id"
        )
        claim_id = _required_id(
            issues, row.get("claim_id"), table="evidence_refs", record_id=row.get("evidence_id"), field="claim_id"
        )
        _required_id(
            issues, row.get("snapshot_id"), table="evidence_refs", record_id=row.get("evidence_id"), field="snapshot_id"
        )
        if evidence_id is not None and claim_id is not None:
            stored_evidence_by_claim.setdefault(claim_id, []).append(evidence_id)
            stored_evidence_rows_by_claim.setdefault(claim_id, {})[evidence_id] = row

    for source_id, row in sources.items():
        for field in ("source_key", "continuity"):
            if not _valid_metadata_text(row.get(field)):
                _issue(
                    issues,
                    "MIGRATION_REQUIRED_TEXT_MISSING",
                    f"source {field} is required",
                    table="sources",
                    record_id=source_id,
                    field=field,
                    actual=row.get(field),
                )
        for field in ("created_at", "updated_at"):
            _check_time(
                issues,
                row.get(field),
                table="sources",
                record_id=source_id,
                field=field,
                required=True,
            )

    for snapshot_id, row in snapshots.items():
        _required_id(
            issues,
            row.get("source_id"),
            table="source_snapshots",
            record_id=snapshot_id,
            field="source_id",
        )
        source = sources.get(str(row.get("source_id")))
        content = row.get("content")
        digest = row.get("content_hash")
        if not _valid_metadata_text(row.get("media_type")):
            _issue(
                issues,
                "MIGRATION_REQUIRED_TEXT_MISSING",
                "snapshot media_type is required and must be safe metadata",
                table="source_snapshots",
                record_id=snapshot_id,
                field="media_type",
                actual=row.get("media_type"),
            )
        if source is None:
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_SOURCE_MISSING",
                "snapshot source does not exist",
                table="source_snapshots",
                record_id=snapshot_id,
                field="source_id",
                actual=row.get("source_id"),
            )
        if not isinstance(content, str):
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_CONTENT_INVALID",
                "snapshot content must be text",
                table="source_snapshots",
                record_id=snapshot_id,
                field="content",
                actual=type(content).__name__,
            )
        if not _valid_digest(digest):
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_HASH_INVALID",
                "snapshot content_hash must be SHA-256",
                table="source_snapshots",
                record_id=snapshot_id,
                field="content_hash",
                actual=digest,
            )
        elif isinstance(content, str) and str(digest).lower() != sha256(
            content.encode("utf-8")
        ).hexdigest():
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_HASH_MISMATCH",
                "snapshot hash does not match content",
                table="source_snapshots",
                record_id=snapshot_id,
                field="content_hash",
                actual=digest,
            )
        lines = len(source_lines(content)) if isinstance(content, str) else 0
        if type(row.get("line_count")) is not int or row.get("line_count") != lines:
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_LINE_COUNT_INVALID",
                "snapshot line_count does not match content",
                table="source_snapshots",
                record_id=snapshot_id,
                field="line_count",
                actual=row.get("line_count"),
            )
        version = row.get("version")
        previous_id = row.get("previous_snapshot_id")
        if type(version) is not int or version < 1:
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_VERSION_INVALID",
                "snapshot version must be a positive integer",
                table="source_snapshots",
                record_id=snapshot_id,
                field="version",
                actual=version,
            )
        elif version == 1 and previous_id is not None:
            _issue(
                issues,
                "MIGRATION_SNAPSHOT_LINEAGE_INVALID",
                "version 1 must not name a previous snapshot",
                table="source_snapshots",
                record_id=snapshot_id,
                field="previous_snapshot_id",
                actual=previous_id,
            )
        elif version > 1:
            previous = snapshots.get(str(previous_id))
            if (
                previous is None
                or previous.get("source_id") != row.get("source_id")
                or previous.get("version") != version - 1
            ):
                _issue(
                    issues,
                    "MIGRATION_SNAPSHOT_LINEAGE_INVALID",
                    "previous snapshot must be the same source's prior version",
                    table="source_snapshots",
                    record_id=snapshot_id,
                    field="previous_snapshot_id",
                    actual=previous_id,
                )
        _check_time(
            issues,
            row.get("created_at"),
            table="source_snapshots",
            record_id=snapshot_id,
            field="created_at",
            required=True,
        )

    for claim_id, row in claims.items():
        _check_aggregate_utf8_bytes(
            issues,
            row.get("text"),
            table="claim_proposals",
            record_id=claim_id,
            field="text",
            max_bytes=MAX_CLAIM_TEXT_UTF8_BYTES,
            code="CLAIM_TEXT_BYTES_LIMIT",
        )
        _check_aggregate_utf8_bytes(
            issues,
            row.get("rationale"),
            table="claim_proposals",
            record_id=claim_id,
            field="rationale",
            max_bytes=MAX_CLAIM_RATIONALE_UTF8_BYTES,
            code="CLAIM_RATIONALE_BYTES_LIMIT",
        )
        for field in (
            "subject",
            "predicate",
            "object_value",
            "proposed_by",
            "proposal_model",
        ):
            _check_aggregate_utf8_bytes(
                issues,
                row.get(field),
                table="claim_proposals",
                record_id=claim_id,
                field=field,
                max_bytes=MAX_CLAIM_METADATA_UTF8_BYTES,
                code="CLAIM_METADATA_BYTES_LIMIT",
            )
        for field in ("persona_id", "continuity", "text"):
            valid = (
                _valid_metadata_text(row.get(field))
                if field in {"persona_id", "continuity"}
                else isinstance(row.get(field), str) and bool(row[field].strip())
            )
            if not valid:
                _issue(
                    issues,
                    "MIGRATION_REQUIRED_TEXT_MISSING",
                    f"claim {field} is required",
                    table="claim_proposals",
                    record_id=claim_id,
                    field=field,
                    actual=row.get(field),
                )
        if row.get("access_policy") not in _ACCESS:
            _issue(
                issues,
                "MIGRATION_ACCESS_INVALID",
                "claim access policy is not recognized",
                table="claim_proposals",
                record_id=claim_id,
                field="access_policy",
                actual=row.get("access_policy"),
            )
        if row.get("status") not in _STATUSES:
            _issue(
                issues,
                "MIGRATION_STATUS_INVALID",
                "claim governance status is not recognized",
                table="claim_proposals",
                record_id=claim_id,
                field="status",
                actual=row.get("status"),
            )
        confidence = row.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            _issue(
                issues,
                "MIGRATION_CONFIDENCE_INVALID",
                "claim confidence must be finite and between 0 and 1",
                table="claim_proposals",
                record_id=claim_id,
                field="confidence",
                actual=confidence,
            )
        for field in (
            "valid_from",
            "valid_to",
            "knowledge_from",
            "knowledge_to",
        ):
            _check_time(
                issues,
                row.get(field),
                table="claim_proposals",
                record_id=claim_id,
                field=field,
            )
        for field in ("created_at", "updated_at"):
            _check_time(
                issues,
                row.get(field),
                table="claim_proposals",
                record_id=claim_id,
                field=field,
                required=True,
            )
        _check_interval(
            issues,
            row.get("valid_from"),
            row.get("valid_to"),
            table="claim_proposals",
            record_id=claim_id,
            name="valid_interval",
        )
        _check_interval(
            issues,
            row.get("knowledge_from"),
            row.get("knowledge_to"),
            table="claim_proposals",
            record_id=claim_id,
            name="knowledge_interval",
        )

    def validate_evidence(table: str, owner_field: str, owner_kind: str) -> None:
        try:
            rows = _rows(connection, table)
        except sqlite3.DatabaseError:
            if table == "event_evidence_refs":
                return
            raise
        events = {
            str(row["event_id"]): row for row in _rows(connection, "narrative_events")
        }
        for row in rows:
            evidence_id = row.get("evidence_id")
            _required_id(
                issues,
                evidence_id,
                table=table,
                record_id=evidence_id,
                field="evidence_id",
            )
            _required_id(
                issues,
                row.get(owner_field),
                table=table,
                record_id=evidence_id,
                field=owner_field,
            )
            _required_id(
                issues,
                row.get("snapshot_id"),
                table=table,
                record_id=evidence_id,
                field="snapshot_id",
            )
            owner_id = str(row.get(owner_field) or "")
            owner = claims.get(owner_id) if owner_kind == "claim" else events.get(owner_id)
            snapshot = snapshots.get(str(row.get("snapshot_id") or ""))
            if owner is None or snapshot is None:
                _issue(
                    issues,
                    "MIGRATION_EVIDENCE_REFERENCE_MISSING",
                    "evidence owner or snapshot does not exist",
                    table=table,
                    record_id=evidence_id,
                    actual={owner_field: owner_id, "snapshot_id": row.get("snapshot_id")},
                )
                continue
            source = sources.get(str(snapshot.get("source_id")))
            if source is None or owner.get("continuity") != source.get("continuity"):
                _issue(
                    issues,
                    "MIGRATION_EVIDENCE_CONTINUITY_MISMATCH",
                    "evidence crosses continuity boundaries",
                    table=table,
                    record_id=evidence_id,
                    field="continuity",
                )
            start, end = row.get("start_line"), row.get("end_line")
            content = snapshot.get("content")
            line_count = len(source_lines(content)) if isinstance(content, str) else 0
            if (
                type(start) is not int
                or type(end) is not int
                or start < 1
                or end < start
                or end > line_count
            ):
                _issue(
                    issues,
                    "MIGRATION_EVIDENCE_RANGE_INVALID",
                    "evidence lines are malformed or out of bounds",
                    table=table,
                    record_id=evidence_id,
                    field="line_range",
                    actual={"start_line": start, "end_line": end, "line_count": line_count},
                )
                continue
            expected_quote = extract_line_quote(content, start, end)
            supplied_quote = row.get("quote")
            if supplied_quote is not None and (
                not isinstance(supplied_quote, str)
                or supplied_quote.replace("\r\n", "\n").replace("\r", "\n")
                != expected_quote
            ):
                _issue(
                    issues,
                    "MIGRATION_EVIDENCE_QUOTE_MISMATCH",
                    "evidence quote does not match snapshot lines",
                    table=table,
                    record_id=evidence_id,
                    field="quote",
                    actual=supplied_quote,
                )
            supplied_hash = row.get("content_hash")
            if supplied_hash is not None:
                if not _valid_digest(supplied_hash):
                    _issue(
                        issues,
                        "MIGRATION_EVIDENCE_HASH_INVALID",
                        "evidence content_hash must be SHA-256",
                        table=table,
                        record_id=evidence_id,
                        field="content_hash",
                        actual=supplied_hash,
                    )
                elif str(supplied_hash).lower() != quote_sha256(expected_quote):
                    _issue(
                        issues,
                        "MIGRATION_EVIDENCE_HASH_MISMATCH",
                        "evidence hash does not match snapshot lines",
                        table=table,
                        record_id=evidence_id,
                        field="content_hash",
                        actual=supplied_hash,
                    )
            start_char, end_char = row.get("start_char"), row.get("end_char")
            if (
                (start_char is not None and type(start_char) is not int)
                or (end_char is not None and type(end_char) is not int)
                or (start_char is None and end_char is not None)
                or (type(start_char) is int and start_char < 0)
                or (
                    type(start_char) is int
                    and type(end_char) is int
                    and end_char < start_char
                )
            ):
                _issue(
                    issues,
                    "MIGRATION_EVIDENCE_CHAR_RANGE_INVALID",
                    "evidence character coordinates are invalid",
                    table=table,
                    record_id=evidence_id,
                    field="character_range",
                    actual={"start_char": start_char, "end_char": end_char},
                )
            _check_time(
                issues,
                row.get("created_at"),
                table=table,
                record_id=evidence_id,
                field="created_at",
                required=True,
            )

    validate_evidence("evidence_refs", "claim_id", "claim")
    validate_evidence("event_evidence_refs", "event_id", "event")

    # Replay immutable decisions independently of the mutable claim status.
    decisions = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM governance_decisions ORDER BY rowid"
        )
    ]
    by_claim: dict[str, list[dict[str, Any]]] = {}
    for row in decisions:
        decision_id = _required_id(
            issues, row.get("decision_id"), table="governance_decisions", record_id=row.get("decision_id"), field="decision_id"
        )
        decision_claim_id = _required_id(
            issues, row.get("claim_id"), table="governance_decisions", record_id=decision_id, field="claim_id"
        )
        if decision_claim_id is not None:
            by_claim.setdefault(decision_claim_id, []).append(row)
    for claim_id, claim in claims.items():
        current = "PROPOSED"
        for row in by_claim.get(claim_id, []):
            decision_id = row.get("decision_id")
            source, target = row.get("from_status"), row.get("to_status")
            if source != current or target not in _TRANSITIONS.get(current, frozenset()):
                _issue(
                    issues,
                    "MIGRATION_DECISION_CHAIN_INVALID",
                    "governance decision chain is invalid",
                    table="governance_decisions",
                    record_id=decision_id,
                    actual={"expected_from": current, "from": source, "to": target},
                )
            if not isinstance(row.get("reviewer"), str) or not row["reviewer"].strip():
                _issue(
                    issues,
                    "MIGRATION_DECISION_ATTRIBUTION_MISSING",
                    "governance reviewer is required",
                    table="governance_decisions",
                    record_id=decision_id,
                    field="reviewer",
                    actual=row.get("reviewer"),
                )
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                _issue(
                    issues,
                    "MIGRATION_DECISION_ATTRIBUTION_MISSING",
                    "governance reason is required",
                    table="governance_decisions",
                    record_id=decision_id,
                    field="reason",
                    actual=row.get("reason"),
                )
            _check_time(
                issues,
                row.get("decided_at"),
                table="governance_decisions",
                record_id=decision_id,
                field="decided_at",
                required=True,
            )
            if target in _STATUSES:
                current = str(target)
        if claim.get("status") in _STATUSES and claim.get("status") != current:
            _issue(
                issues,
                "MIGRATION_CLAIM_STATUS_REPLAY_MISMATCH",
                "claim status differs from immutable decision replay",
                table="claim_proposals",
                record_id=claim_id,
                field="status",
                actual={"cached": claim.get("status"), "replayed": current},
            )

    # Existing ledger data must be cryptographically intact.  Completely
    # absent per-claim streams from the old v0.1->v0.2 migrator are eligible
    # for deterministic backfill; partially present streams fail closed.
    ledger = sorted(
        _rows(connection, "event_ledger"),
        key=lambda row: (
            row.get("sequence") if type(row.get("sequence")) is int else 2**63,
            str(row.get("sequence")),
        ),
    )
    expected_sequence = 1
    expected_previous = GENESIS_HASH
    for row in ledger:
        _required_id(
            issues, row.get("entry_id"), table="event_ledger", record_id=row.get("entry_id"), field="entry_id"
        )
        _required_id(
            issues, row.get("event_type"), table="event_ledger", record_id=row.get("entry_id"), field="event_type"
        )
        _required_id(
            issues, row.get("aggregate_type"), table="event_ledger", record_id=row.get("entry_id"), field="aggregate_type"
        )
        _required_id(
            issues, row.get("aggregate_id"), table="event_ledger", record_id=row.get("entry_id"), field="aggregate_id"
        )
        if (
            type(row.get("sequence")) is not int
            or row["sequence"] != expected_sequence
            or row.get("previous_hash") != expected_previous
            or not _valid_digest(row.get("entry_hash"))
            or row.get("entry_hash") != _ledger_digest(row)
        ):
            _issue(
                issues,
                "MIGRATION_LEDGER_INTEGRITY_INVALID",
                "event ledger hash chain is invalid",
                table="event_ledger",
                record_id=row.get("entry_id"),
                actual=row.get("sequence"),
            )
            break
        expected_previous = str(row["entry_hash"])
        expected_sequence += 1

    issues.extend(
        _validate_v02_source_audit_backfill_eligibility(
            sources=sources,
            snapshots=snapshots,
            ledger=ledger,
        )
    )

    for claim_id in claims:
        claim_stream = [
            row
            for row in ledger
            if row.get("aggregate_type") == "claim"
            and row.get("aggregate_id") == claim_id
        ]
        entries = [
            row
            for row in claim_stream
            if row.get("event_type")
            in {"claim.proposed", "claim.governance_decided"}
        ]
        stored_ids = stored_evidence_by_claim.get(claim_id, [])
        if claims[claim_id].get("status") == "AUTHORIZED" and not stored_ids:
            _issue(
                issues,
                "MIGRATION_EVIDENCE_REQUIRED",
                "every authorized claim must retain at least one valid evidence row",
                table="claim_proposals",
                record_id=claim_id,
            )
        if not entries:
            if claim_stream:
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_PARTIAL",
                    "claim has a non-empty ledger stream but no complete authority history",
                    table="event_ledger",
                    record_id=claim_id,
                )
            expected_updated_at = claims[claim_id].get("created_at")
            for decision in by_claim.get(claim_id, []):
                expected_updated_at = decision.get("decided_at")
            if claims[claim_id].get("updated_at") != expected_updated_at:
                _issue(
                    issues,
                    "MIGRATION_CLAIM_UPDATED_AT_REPLAY_MISMATCH",
                    "claim updated_at differs from its legacy decision order",
                    table="claim_proposals",
                    record_id=claim_id,
                    field="updated_at",
                    actual={
                        "cached": claims[claim_id].get("updated_at"),
                        "replayed": expected_updated_at,
                    },
                )
            continue
        proposals = [row for row in entries if row.get("event_type") == "claim.proposed"]
        ledger_decisions = [
            row for row in entries if row.get("event_type") == "claim.governance_decided"
        ]
        decision_rows = by_claim.get(claim_id, [])
        if len(proposals) != 1 or len(ledger_decisions) != len(decision_rows):
            _issue(
                issues,
                "MIGRATION_AUTHORITY_LEDGER_PARTIAL",
                "claim authority ledger is partially present and cannot be safely backfilled",
                table="event_ledger",
                record_id=claim_id,
                actual={
                    "proposal_entries": len(proposals),
                    "decision_entries": len(ledger_decisions),
                    "decision_rows": len(decision_rows),
                },
            )

        if proposals and ledger_decisions and int(proposals[0]["sequence"]) >= min(
            int(row["sequence"]) for row in ledger_decisions
        ):
            _issue(
                issues,
                "MIGRATION_AUTHORITY_LEDGER_ORDER_INVALID",
                "claim.proposed must precede every governance decision",
                table="event_ledger",
                record_id=claim_id,
            )

        ledger_by_decision: dict[str, list[tuple[dict[str, Any], Mapping[str, Any]]]] = {}
        for entry in ledger_decisions:
            try:
                payload = json.loads(str(entry.get("payload_json")))
            except (TypeError, ValueError):
                payload = None
            if not isinstance(payload, Mapping):
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_PAYLOAD_INVALID",
                    "governance ledger payload must be a JSON object",
                    table="event_ledger",
                    record_id=entry.get("entry_id"),
                )
                continue
            decision_id = payload.get("decision_id")
            if not isinstance(decision_id, str) or not decision_id:
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_DECISION_ID_MISSING",
                    "governance ledger payload must name a decision",
                    table="event_ledger",
                    record_id=entry.get("entry_id"),
                )
                continue
            ledger_by_decision.setdefault(decision_id, []).append((entry, payload))

        known_decision_ids = {str(row.get("decision_id")) for row in decision_rows}
        matched_sequences: list[int] = []
        matched_decision_times: list[tuple[int, object]] = []
        for decision in decision_rows:
            decision_id = str(decision.get("decision_id"))
            matches = ledger_by_decision.get(decision_id, [])
            if len(matches) != 1:
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_CORRESPONDENCE_INVALID",
                    "each decision row must have exactly one matching ledger entry",
                    table="event_ledger",
                    record_id=decision_id,
                    actual=len(matches),
                )
                continue
            entry, payload = matches[0]
            expected_payload = {
                "decision_id": decision_id,
                "from_status": decision.get("from_status"),
                "to_status": decision.get("to_status"),
                "reviewer": decision.get("reviewer"),
                "reason": decision.get("reason"),
            }
            if any(payload.get(key) != value for key, value in expected_payload.items()):
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_PAYLOAD_MISMATCH",
                    "decision row and governance ledger payload differ",
                    table="event_ledger",
                    record_id=entry.get("entry_id"),
                )
            sequence = int(entry["sequence"])
            if entry.get("created_at") != decision.get("decided_at"):
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_TIMESTAMP_MISMATCH",
                    "decision timestamp differs from its governance ledger entry",
                    table="event_ledger",
                    record_id=entry.get("entry_id"),
                    actual={
                        "decision": decision.get("decided_at"),
                        "ledger": entry.get("created_at"),
                    },
                )
            matched_sequences.append(sequence)
            matched_decision_times.append((sequence, decision.get("decided_at")))

        if matched_sequences != sorted(matched_sequences):
            _issue(
                issues,
                "MIGRATION_AUTHORITY_LEDGER_ORDER_INVALID",
                "decision row order and governance ledger order differ",
                table="event_ledger",
                record_id=claim_id,
            )

        expected_updated_at = claims[claim_id].get("created_at")
        for _, decided_at in sorted(matched_decision_times):
            expected_updated_at = decided_at
        if claims[claim_id].get("updated_at") != expected_updated_at:
            _issue(
                issues,
                "MIGRATION_CLAIM_UPDATED_AT_REPLAY_MISMATCH",
                "claim updated_at differs from the last ledger-ordered decision",
                table="claim_proposals",
                record_id=claim_id,
                field="updated_at",
                actual={
                    "cached": claims[claim_id].get("updated_at"),
                    "replayed": expected_updated_at,
                },
            )

        for decision_id, matches in ledger_by_decision.items():
            if decision_id not in known_decision_ids:
                _issue(
                    issues,
                    "MIGRATION_AUTHORITY_LEDGER_ORPHAN",
                    "governance ledger entry has no decision row",
                    table="event_ledger",
                    record_id=matches[0][0].get("entry_id"),
                    actual=decision_id,
                )

        audited_evidence_ids: list[str] = []
        proposal_sequence: int | None = None
        if len(proposals) == 1:
            proposal_sequence = int(proposals[0]["sequence"])
            try:
                proposal_payload = json.loads(str(proposals[0].get("payload_json")))
            except (TypeError, ValueError):
                proposal_payload = None
            proposed_ids = (
                proposal_payload.get("evidence_ids")
                if isinstance(proposal_payload, Mapping)
                else None
            )
            expected_proposal = {
                "persona_id": claims[claim_id].get("persona_id"),
                "continuity": claims[claim_id].get("continuity"),
                "text": claims[claim_id].get("text"),
                "access_policy": claims[claim_id].get("access_policy"),
                "confidence": float(claims[claim_id].get("confidence"))
                if isinstance(claims[claim_id].get("confidence"), (int, float))
                and not isinstance(claims[claim_id].get("confidence"), bool)
                else claims[claim_id].get("confidence"),
            }
            if not isinstance(proposal_payload, Mapping) or any(
                proposal_payload.get(key) != value
                for key, value in expected_proposal.items()
            ):
                _issue(
                    issues,
                    "MIGRATION_PROPOSAL_LEDGER_PAYLOAD_MISMATCH",
                    "claim proposal row and ledger payload differ",
                    table="event_ledger",
                    record_id=proposals[0].get("entry_id"),
                )
            if not isinstance(proposed_ids, list) or any(
                not isinstance(item, str) or not item for item in proposed_ids
            ):
                _issue(
                    issues,
                    "MIGRATION_PROPOSAL_EVIDENCE_LEDGER_INVALID",
                    "claim.proposed must contain a list of evidence IDs",
                    table="event_ledger",
                    record_id=proposals[0].get("entry_id"),
                )
            else:
                audited_evidence_ids.extend(proposed_ids)

        decisions_for_replay = {
            str(row.get("decision_id")): row for row in decision_rows
        }
        replayed_status = "PROPOSED"
        for entry in claim_stream:
            try:
                payload = json.loads(str(entry.get("payload_json")))
            except (TypeError, ValueError):
                payload = None
            if entry.get("event_type") == "claim.governance_decided":
                decision_id = (
                    payload.get("decision_id")
                    if isinstance(payload, Mapping)
                    else None
                )
                decision = decisions_for_replay.get(str(decision_id))
                if decision is not None and decision.get("to_status") in _STATUSES:
                    replayed_status = str(decision["to_status"])
            elif entry.get("event_type") == "claim.evidence_added":
                evidence_id = (
                    payload.get("evidence_id")
                    if isinstance(payload, Mapping)
                    else None
                )
                if not isinstance(evidence_id, str) or not evidence_id:
                    _issue(
                        issues,
                        "MIGRATION_EVIDENCE_LEDGER_ID_MISSING",
                        "claim.evidence_added must name an evidence ID",
                        table="event_ledger",
                        record_id=entry.get("entry_id"),
                    )
                else:
                    audited_evidence_ids.append(evidence_id)
                    actual_evidence = stored_evidence_rows_by_claim.get(
                        claim_id, {}
                    ).get(evidence_id)
                    if actual_evidence is not None:
                        expected_evidence = {
                            "evidence_id": evidence_id,
                            "snapshot_id": actual_evidence.get("snapshot_id"),
                            "start_line": actual_evidence.get("start_line"),
                            "end_line": actual_evidence.get("end_line"),
                        }
                        if not isinstance(payload, Mapping) or any(
                            payload.get(key) != value
                            for key, value in expected_evidence.items()
                        ):
                            _issue(
                                issues,
                                "MIGRATION_EVIDENCE_LEDGER_PAYLOAD_MISMATCH",
                                "evidence row and claim.evidence_added payload differ",
                                table="event_ledger",
                                record_id=entry.get("entry_id"),
                            )
                if (
                    proposal_sequence is None
                    or int(entry["sequence"]) <= proposal_sequence
                ):
                    _issue(
                        issues,
                        "MIGRATION_EVIDENCE_LEDGER_ORDER_INVALID",
                        "claim.evidence_added must follow claim.proposed",
                        table="event_ledger",
                        record_id=entry.get("entry_id"),
                    )
                if replayed_status not in {"PROPOSED", "DISPUTED"}:
                    _issue(
                        issues,
                        "MIGRATION_EVIDENCE_APPENDED_WITHOUT_REVIEW_REOPEN",
                        "evidence was added while the claim was not reviewable",
                        table="event_ledger",
                        record_id=entry.get("entry_id"),
                        actual=replayed_status,
                    )

        if (
            len(set(audited_evidence_ids)) != len(audited_evidence_ids)
            or len(set(stored_ids)) != len(stored_ids)
            or set(audited_evidence_ids) != set(stored_ids)
        ):
            _issue(
                issues,
                "MIGRATION_EVIDENCE_SET_LEDGER_MISMATCH",
                "stored evidence differs from the audited claim evidence set",
                table="evidence_refs",
                record_id=claim_id,
                actual={
                    "missing_from_ledger": sorted(
                        set(stored_ids) - set(audited_evidence_ids)
                    ),
                    "missing_from_storage": sorted(
                        set(audited_evidence_ids) - set(stored_ids)
                    ),
                    "ledger_has_duplicates": len(set(audited_evidence_ids))
                    != len(audited_evidence_ids),
                },
            )

    for entry in ledger:
        if entry.get("event_type") not in {
            "claim.proposed",
            "claim.governance_decided",
            "claim.evidence_added",
        }:
            continue
        aggregate_id = str(entry.get("aggregate_id") or "")
        if entry.get("aggregate_type") != "claim" or aggregate_id not in claims:
            _issue(
                issues,
                "MIGRATION_AUTHORITY_LEDGER_ORPHAN",
                "claim authority ledger entry has no claim aggregate",
                table="event_ledger",
                record_id=entry.get("entry_id"),
                actual={
                    "aggregate_type": entry.get("aggregate_type"),
                    "aggregate_id": aggregate_id,
                },
            )

    event_rows = _rows(connection, "narrative_events")
    events_by_id: dict[str, dict[str, Any]] = {}
    for row in event_rows:
        event_id = row.get("event_id")
        valid_event_id = _required_id(
            issues, event_id, table="narrative_events", record_id=event_id, field="event_id"
        )
        if valid_event_id is not None:
            events_by_id[valid_event_id] = row
        _check_aggregate_utf8_bytes(
            issues,
            row.get("title"),
            table="narrative_events",
            record_id=event_id,
            field="title",
            max_bytes=MAX_EVENT_TITLE_UTF8_BYTES,
            code="EVENT_TITLE_BYTES_LIMIT",
        )
        _check_aggregate_utf8_bytes(
            issues,
            row.get("summary"),
            table="narrative_events",
            record_id=event_id,
            field="summary",
            max_bytes=MAX_EVENT_SUMMARY_UTF8_BYTES,
            code="EVENT_SUMMARY_BYTES_LIMIT",
        )
        _check_aggregate_utf8_bytes(
            issues,
            row.get("details_json"),
            table="narrative_events",
            record_id=event_id,
            field="details_json",
            max_bytes=MAX_EVENT_DETAILS_JSON_BYTES,
            code="MIGRATION_EVENT_DETAILS_INVALID",
        )
        for field in ("persona_id", "continuity", "event_type"):
            if not _valid_metadata_text(row.get(field)):
                _issue(
                    issues,
                    "MIGRATION_REQUIRED_TEXT_MISSING",
                    f"event {field} is required and must be safe metadata",
                    table="narrative_events",
                    record_id=event_id,
                    field=field,
                    actual=row.get(field),
                )
        if row.get("access_policy") not in _ACCESS:
            _issue(
                issues,
                "MIGRATION_ACCESS_INVALID",
                "event access policy is not recognized",
                table="narrative_events",
                record_id=event_id,
                field="access_policy",
                actual=row.get("access_policy"),
            )
        for field in ("valid_from", "valid_to", "knowledge_from", "knowledge_to"):
            _check_time(
                issues,
                row.get(field),
                table="narrative_events",
                record_id=event_id,
                field=field,
            )
        _check_time(
            issues,
            row.get("created_at"),
            table="narrative_events",
            record_id=event_id,
            field="created_at",
            required=True,
        )
        try:
            details = parse_json_content(str(row.get("details_json")))
        except (TypeError, ValueError, SourceInputError):
            details = None
        if not isinstance(details, Mapping):
            _issue(
                issues,
                "MIGRATION_EVENT_DETAILS_INVALID",
                "event details_json must encode an object",
                table="narrative_events",
                record_id=event_id,
                field="details_json",
                actual=row.get("details_json"),
            )

    for entry in ledger:
        if entry.get("event_type") != "narrative_event.created":
            continue
        aggregate_id = str(entry.get("aggregate_id") or "")
        if (
            entry.get("aggregate_type") != "narrative_event"
            or aggregate_id not in events_by_id
        ):
            _issue(
                issues,
                "MIGRATION_EVENT_AUDIT_ORPHAN",
                "event creation ledger entry has no narrative event aggregate",
                table="event_ledger",
                record_id=entry.get("entry_id"),
                actual={
                    "aggregate_type": entry.get("aggregate_type"),
                    "aggregate_id": aggregate_id,
                },
            )

    event_evidence_by_event: dict[str, dict[str, dict[str, Any]]] = {}
    try:
        event_evidence_rows = _rows(connection, "event_evidence_refs")
    except sqlite3.DatabaseError:
        event_evidence_rows = []
    for row in event_evidence_rows:
        event_id = str(row.get("event_id") or "")
        evidence_id = str(row.get("evidence_id") or "")
        event_evidence_by_event.setdefault(event_id, {})[evidence_id] = row

    for event_id, event in events_by_id.items():
        actual_evidence = event_evidence_by_event.get(event_id, {})
        if not actual_evidence:
            _issue(
                issues,
                "MIGRATION_EVENT_EVIDENCE_REQUIRED",
                "every materialized event must retain at least one valid evidence row",
                table="narrative_events",
                record_id=event_id,
            )
        stream = [
            row for row in ledger
            if row.get("aggregate_type") == "narrative_event"
            and row.get("aggregate_id") == event_id
        ]
        if not stream:
            # The old v0.1->v0.2 migrator omitted the entire event stream;
            # only this all-or-nothing shape is eligible for backfill.
            continue
        created = [
            row for row in stream if row.get("event_type") == "narrative_event.created"
        ]
        if len(created) != 1:
            _issue(
                issues,
                "MIGRATION_EVENT_AUDIT_PARTIAL",
                "event audit stream must contain exactly one creation entry",
                table="event_ledger",
                record_id=event_id,
                actual=len(created),
            )
            continue
        entry = created[0]
        try:
            payload = json.loads(str(entry.get("payload_json")))
        except (TypeError, ValueError):
            payload = None
        expected_core = {
            "persona_id": event.get("persona_id"),
            "continuity": event.get("continuity"),
            "event_type": event.get("event_type"),
            "valid_from": event.get("valid_from"),
            "knowledge_from": event.get("knowledge_from"),
            "access_policy": event.get("access_policy"),
        }
        expected_ids = set(actual_evidence)
        payload_ids = payload.get("evidence_ids") if isinstance(payload, Mapping) else None
        payload_refs = payload.get("evidence_refs") if isinstance(payload, Mapping) else None
        valid_payload_ids = isinstance(payload_ids, list) and all(
            isinstance(item, str) and item for item in payload_ids
        )
        valid_payload_refs = isinstance(payload_refs, list) and all(
            isinstance(item, Mapping)
            and isinstance(item.get("evidence_id"), str)
            and bool(item.get("evidence_id"))
            for item in payload_refs
        )
        ref_ids = (
            [str(item["evidence_id"]) for item in payload_refs]
            if valid_payload_refs
            else []
        )
        refs_by_id = (
            {str(item["evidence_id"]): item for item in payload_refs}
            if valid_payload_refs
            else {}
        )
        mismatch = (
            not isinstance(payload, Mapping)
            or any(payload.get(key) != value for key, value in expected_core.items())
            or not valid_payload_ids
            or not valid_payload_refs
            or len(payload_ids) != len(set(payload_ids))
            or len(ref_ids) != len(set(ref_ids))
            or payload_ids != ref_ids
            or set(payload_ids) != expected_ids
            or set(refs_by_id) != expected_ids
        )
        if not mismatch:
            for evidence_id, evidence in actual_evidence.items():
                ref = refs_by_id[evidence_id]
                expected_ref = {
                    "evidence_id": evidence_id,
                    "snapshot_id": evidence.get("snapshot_id"),
                    "start_line": evidence.get("start_line"),
                    "end_line": evidence.get("end_line"),
                    "content_hash": evidence.get("content_hash"),
                }
                if any(ref.get(key) != value for key, value in expected_ref.items()):
                    mismatch = True
                    break
        if mismatch or entry.get("created_at") != event.get("created_at"):
            _issue(
                issues,
                "MIGRATION_EVENT_AUDIT_PAYLOAD_MISMATCH",
                "event row, evidence, and creation ledger payload differ",
                table="event_ledger",
                record_id=entry.get("entry_id"),
            )
    return issues


def _validate_v02_source_audit_backfill_eligibility(
    *,
    sources: Mapping[str, Mapping[str, Any]],
    snapshots: Mapping[str, Mapping[str, Any]],
    ledger: list[dict[str, Any]],
) -> list[MigrationIssue]:
    """Validate complete Source audit streams or an all-empty backfill shape.

    Historical v0.2 databases may omit Source audit entries entirely.  Those
    rows can be deterministically backfilled, but a partial stream must be
    rejected before a backup is published.  Row-derived ``updated_at`` is
    checked even for the empty-stream shape so postflight cannot discover a
    mismatch only after migration work has started.
    """

    issues: list[MigrationIssue] = []
    try:
        source_models = [
            Source(
                source_id=str(row["source_id"]),
                source_key=str(row["source_key"]),
                continuity=str(row["continuity"]),
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
            )
            for row in sources.values()
        ]
        snapshot_models = [
            SourceAuditSnapshot(
                snapshot_id=str(row["snapshot_id"]),
                source_id=str(row["source_id"]),
                version=int(row["version"]),
                content_hash=str(row["content_hash"]),
                media_type=str(row["media_type"]),
                origin_path=row.get("origin_path"),
                previous_snapshot_id=row.get("previous_snapshot_id"),
                line_count=int(row["line_count"]),
                created_at=str(row["created_at"]),
            )
            for row in snapshots.values()
        ]
        audit_entries: list[LedgerEntry] = []
        for row in ledger:
            if row.get("event_type") not in {
                "source.created",
                "source_snapshot.created",
            }:
                continue
            payload = json.loads(str(row.get("payload_json")))
            if not isinstance(payload, Mapping):
                raise ValueError("Source audit payload is not an object")
            audit_entries.append(
                LedgerEntry(
                    sequence=int(row["sequence"]),
                    entry_id=str(row["entry_id"]),
                    event_type=str(row["event_type"]),
                    aggregate_type=str(row["aggregate_type"]),
                    aggregate_id=str(row["aggregate_id"]),
                    payload=payload,
                    previous_hash=str(row["previous_hash"]),
                    entry_hash=str(row["entry_hash"]),
                    created_at=str(row["created_at"]),
                )
            )
    except (
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeError,
    ) as exc:
        return [
            MigrationIssue(
                "MIGRATION_SOURCE_AUDIT_INVALID",
                "v0.2 Source audit material is malformed",
                table="sources",
                actual={"error_type": type(exc).__name__},
            )
        ]

    reports = replay_source_audits(source_models, snapshot_models, audit_entries)
    snapshots_by_source: dict[str, list[SourceAuditSnapshot]] = {}
    for snapshot in snapshot_models:
        snapshots_by_source.setdefault(snapshot.source_id, []).append(snapshot)
    known_source_ids = {source.source_id for source in source_models}

    for source in source_models:
        owned = snapshots_by_source.get(source.source_id, [])
        owned_ids = {snapshot.snapshot_id for snapshot in owned}
        has_any_stream = any(
            (
                entry.event_type == "source.created"
                and entry.aggregate_id == source.source_id
            )
            or (
                entry.event_type == "source_snapshot.created"
                and entry.aggregate_id in owned_ids
            )
            for entry in audit_entries
        )
        if not has_any_stream:
            if not owned:
                issues.append(
                    MigrationIssue(
                        "MIGRATION_SOURCE_AUDIT_INVALID",
                        "every committed Source must own at least one SourceSnapshot",
                        table="sources",
                        record_id=source.source_id,
                        actual={"issue_codes": ["SOURCE_SNAPSHOT_REQUIRED"]},
                    )
                )
                continue
            latest = max(owned, key=lambda item: (item.version, item.snapshot_id))
            if source.updated_at != latest.created_at:
                issues.append(
                    MigrationIssue(
                        "MIGRATION_SOURCE_AUDIT_INVALID",
                        "Source updated_at differs from its latest SourceSnapshot",
                        table="sources",
                        record_id=source.source_id,
                        field="updated_at",
                        actual={
                            "issue_codes": ["SOURCE_UPDATED_AT_MISMATCH"],
                            "cached": source.updated_at,
                            "replayed": latest.created_at,
                        },
                    )
                )
            continue

        report = reports.get(source.source_id)
        if report is not None and report.is_valid:
            continue
        issues.append(
            MigrationIssue(
                "MIGRATION_SOURCE_AUDIT_INVALID",
                "v0.2 Source audit stream is partial or inconsistent",
                table="sources",
                record_id=source.source_id,
                actual={
                    "issue_codes": [item.code for item in report.issues]
                    if report is not None
                    else ["SOURCE_AUDIT_DATA_UNAVAILABLE"],
                },
            )
        )

    for source_id, report in reports.items():
        if source_id in known_source_ids or report.is_valid:
            continue
        issues.append(
            MigrationIssue(
                "MIGRATION_SOURCE_AUDIT_INVALID",
                "v0.2 Source audit stream contains an orphan entry",
                table="event_ledger",
                record_id=source_id,
                actual={"issue_codes": [item.code for item in report.issues]},
            )
        )
    return issues


def _validate_v03_alpha2_source_audit(
    connection: sqlite3.Connection,
) -> list[MigrationIssue]:
    """Require complete Source audit before the same-version hardening edge."""

    issues: list[MigrationIssue] = []
    try:
        sources = [
            Source(
                source_id=str(row["source_id"]),
                source_key=str(row["source_key"]),
                continuity=str(row["continuity"]),
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
            )
            for row in _rows(connection, "sources")
        ]
        snapshots = [
            SourceAuditSnapshot(
                snapshot_id=str(row["snapshot_id"]),
                source_id=str(row["source_id"]),
                version=int(row["version"]),
                content_hash=str(row["content_hash"]),
                media_type=str(row["media_type"]),
                origin_path=row.get("origin_path"),
                previous_snapshot_id=row.get("previous_snapshot_id"),
                line_count=int(row["line_count"]),
                created_at=str(row["created_at"]),
            )
            for row in _rows(connection, "source_snapshots")
        ]
        entries: list[LedgerEntry] = []
        for row in _rows(connection, "event_ledger"):
            if row.get("event_type") not in {
                "source.created",
                "source_snapshot.created",
            }:
                continue
            try:
                payload = json.loads(str(row.get("payload_json")))
            except (TypeError, ValueError):
                payload = {"malformed": True}
            if not isinstance(payload, Mapping):
                payload = {"malformed": True}
            entries.append(
                LedgerEntry(
                    sequence=int(row["sequence"]),
                    entry_id=str(row["entry_id"]),
                    event_type=str(row["event_type"]),
                    aggregate_type=str(row["aggregate_type"]),
                    aggregate_id=str(row["aggregate_id"]),
                    payload=payload,
                    previous_hash=str(row["previous_hash"]),
                    entry_hash=str(row["entry_hash"]),
                    created_at=str(row["created_at"]),
                )
            )
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        return [
            MigrationIssue(
                "MIGRATION_SOURCE_AUDIT_INVALID",
                "v0.3.0a2 Source audit material is malformed",
                table="sources",
                actual={"error_type": type(exc).__name__},
            )
        ]

    reports = replay_source_audits(sources, snapshots, entries)
    for source_id, report in reports.items():
        if report.is_valid:
            continue
        issues.append(
            MigrationIssue(
                "MIGRATION_SOURCE_AUDIT_INVALID",
                "v0.3.0a2 Source identity or revisions do not match EventLedger",
                table="sources",
                record_id=source_id,
                actual={"issue_codes": [item.code for item in report.issues]},
            )
        )
    return issues


def validate_migration_data(
    connection: sqlite3.Connection, kind: SchemaKind
) -> tuple[MigrationIssue, ...]:
    """Validate legacy content before any schema mutation occurs."""

    if kind is SchemaKind.V01:
        return tuple(_validate_v01(connection))
    if kind is SchemaKind.V02:
        return tuple(_validate_v02(connection))
    if kind in {SchemaKind.V03_ALPHA2, SchemaKind.V03_ALPHA3}:
        issues = _validate_v02(connection)
        issues.extend(_validate_v03_alpha2_source_audit(connection))
        return tuple(issues)
    return ()


def _database_path(connection: sqlite3.Connection) -> Path | None:
    for _, name, path in connection.execute("PRAGMA database_list").fetchall():
        if str(name) == "main" and str(path):
            return Path(str(path)).resolve()
    return None


def _unused_backup_path(database: Path) -> Path:
    """Return a non-existent backup path without following hostile links.

    Existing regular backup files are preserved by selecting a numbered name.
    A symbolic link at any candidate is treated as an unsafe publication
    target rather than silently followed or skipped.
    """

    candidate = database.with_name(database.name + ".pre-v3.bak")
    suffix = 2
    while os.path.lexists(candidate):
        if candidate.is_symlink():
            raise MigrationError("unsafe symbolic-link backup target")
        candidate = database.with_name(database.name + f".pre-v3.{suffix}.bak")
        suffix += 1
    if os.path.normcase(os.path.abspath(candidate)) == os.path.normcase(
        os.path.abspath(database)
    ):
        raise MigrationError("backup target must differ from the database")
    return candidate


def _secure_backup_temp(database: Path) -> tuple[Path, tuple[int, int]]:
    """Create a private, unpredictable same-directory SQLite backup target."""

    descriptor, name = tempfile.mkstemp(
        prefix=f".{database.name}.pre-v3-",
        suffix=".tmp",
        dir=database.parent,
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(name, 0o600)
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return Path(name), (int(info.st_dev), int(info.st_ino))


def _assert_private_regular_file(
    path: Path,
    identity: tuple[int, int],
) -> None:
    """Fail closed if a backup path was replaced or its permissions widened."""

    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise MigrationError("backup target is not a regular file")
    if (int(info.st_dev), int(info.st_ino)) != identity:
        raise MigrationError("backup target identity changed")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
        raise MigrationError("backup permissions are not private")


def _unlink_if_identity(path: Path, identity: tuple[int, int]) -> bool:
    """Unlink only the exact regular file created by this process.

    Returning ``False`` is intentional for a missing or replaced path: a
    cleanup path must never follow or remove an attacker-controlled name.
    """

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    if (int(info.st_dev), int(info.st_ino)) != identity:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def _fsync_file(path: Path) -> None:
    # Windows requires a writable descriptor for fsync/FlushFileBuffers.
    descriptor = os.open(path, os.O_RDWR)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Persist a published directory entry where the platform supports it."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_backup(
    temporary: Path,
    destination: Path,
    identity: tuple[int, int],
) -> None:
    """Publish a verified backup atomically without replacing any path."""

    if os.path.lexists(destination):
        raise MigrationError("backup destination already exists")
    _assert_private_regular_file(temporary, identity)
    os.link(temporary, destination, follow_symlinks=False)
    try:
        _assert_private_regular_file(destination, identity)
        _fsync_directory(destination.parent)
    except Exception:
        _unlink_if_identity(destination, identity)
        raise
    if not _unlink_if_identity(temporary, identity):
        _unlink_if_identity(destination, identity)
        raise MigrationError("temporary backup target identity changed")


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _logical_database_sha256(connection: sqlite3.Connection) -> str:
    """Stream a deterministic logical dump digest for source/backup binding."""

    digest = sha256()
    for statement in connection.iterdump():
        encoded = statement.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _open_readonly(path: Path) -> sqlite3.Connection:
    resolved = path.expanduser().resolve()
    try:
        validate_readonly_sidecars(resolved)
    except SQLiteSidecarError as exc:
        raise MigrationError(
            f"read-only migration preflight rejected an unsafe sidecar: {exc}"
        ) from exc
    uri = resolved.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except BaseException:
        connection.close()
        raise


def preflight_migration(
    database: str | Path | sqlite3.Connection,
    *,
    mode: MigrationMode | str = MigrationMode.STRICT,
    create_backup: bool = True,
    minimum_free_bytes: int = 1024 * 1024,
    attest_current_legacy_material: bool = False,
) -> MigrationReport:
    """Run read-only validation and optionally create a consistent backup.

    Unknown and partial schemas are reported before backup creation.  The
    original database is never modified by this function.
    """

    if type(attest_current_legacy_material) is not bool:
        raise TypeError("attest_current_legacy_material must be a bool")
    selected_mode = MigrationMode(mode)
    owns_connection = not isinstance(database, sqlite3.Connection)
    connection = (
        _open_readonly(Path(database))
        if owns_connection
        else database
    )
    assert isinstance(connection, sqlite3.Connection)
    previous_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    started = _now()
    try:
        source = fingerprint_schema(connection)
        issues: list[MigrationIssue] = []
        if source.kind in {SchemaKind.UNKNOWN, SchemaKind.PARTIAL}:
            _issue(
                issues,
                "MIGRATION_SCHEMA_UNRECOGNIZED",
                "database is unknown or only partially matches a known schema",
                actual=source.kind.value,
            )
        elif source.kind is SchemaKind.V03:
            _issue(
                issues,
                "MIGRATION_ALREADY_CURRENT",
                "database already uses schema v3",
                severity="info",
            )
        elif source.kind is not SchemaKind.EMPTY and (
            source.kind,
            SchemaKind.V03,
        ) not in ALLOWED_MIGRATIONS:
            _issue(
                issues,
                "MIGRATION_PATH_NOT_ALLOWED",
                "no migration edge exists for this schema",
                actual=source.kind.value,
            )

        path = _database_path(connection)
        physical_bytes = 0
        if path is not None and path.exists():
            wal_path = path.with_name(path.name + "-wal")
            physical_bytes = path.stat().st_size + (
                wal_path.stat().st_size if wal_path.exists() else 0
            )
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        database_bytes = max(physical_bytes, page_count * page_size)
        if database_bytes > MAX_MIGRATION_DATABASE_BYTES:
            _issue(
                issues,
                "MIGRATION_RESOURCE_LIMIT",
                "database exceeds the migration byte limit",
                actual={"kind": "database_bytes", "value": database_bytes, "limit": MAX_MIGRATION_DATABASE_BYTES},
            )

        total_rows = 0
        if source.kind in {
            SchemaKind.V01,
            SchemaKind.V02,
            SchemaKind.V03_ALPHA2,
            SchemaKind.V03_ALPHA3,
        }:
            for table in source.tables:
                escaped = '"' + table.replace('"', '""') + '"'
                count = int(connection.execute(f"SELECT COUNT(*) FROM {escaped}").fetchone()[0])
                total_rows += count
                if count > MAX_MIGRATION_ROWS_PER_TABLE:
                    _issue(
                        issues,
                        "MIGRATION_RESOURCE_LIMIT",
                        "table exceeds the migration row limit",
                        table=table,
                        actual={"kind": "table_rows", "value": count, "limit": MAX_MIGRATION_ROWS_PER_TABLE},
                    )
                    break
                if total_rows > MAX_MIGRATION_TOTAL_ROWS:
                    _issue(
                        issues,
                        "MIGRATION_RESOURCE_LIMIT",
                        "database exceeds the total migration row limit",
                        actual={"kind": "total_rows", "value": total_rows, "limit": MAX_MIGRATION_TOTAL_ROWS},
                    )
                    break

        resource_limited = any(issue.code == "MIGRATION_RESOURCE_LIMIT" for issue in issues)
        if resource_limited:
            quick_check = "not-run"
            foreign_keys: list[sqlite3.Row] = []
        else:
            quick_rows = connection.execute("PRAGMA quick_check").fetchall()
            quick_check = (
                "ok"
                if len(quick_rows) == 1 and str(quick_rows[0][0]).lower() == "ok"
                else "; ".join(str(row[0]) for row in quick_rows) or "no result"
            )
            if quick_check != "ok":
                _issue(
                    issues,
                    "MIGRATION_SQLITE_QUICK_CHECK_FAILED",
                    "SQLite quick_check did not return ok",
                    actual=quick_check,
                )
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_keys:
                _issue(
                    issues,
                    "MIGRATION_FOREIGN_KEY_CHECK_FAILED",
                    "SQLite foreign_key_check found violations",
                    actual=len(foreign_keys),
                )

        quarantined: set[tuple[str, str]] = set()
        if source.kind in {
            SchemaKind.V01,
            SchemaKind.V02,
            SchemaKind.V03_ALPHA2,
            SchemaKind.V03_ALPHA3,
        } and not resource_limited:
            data_issues = list(validate_migration_data(connection, source.kind))
            if selected_mode is MigrationMode.QUARANTINE and source.kind is SchemaKind.V01:
                for issue in data_issues:
                    if issue.table is not None and issue.record_id is not None:
                        quarantined.add((issue.table, issue.record_id))

                invalid_snapshots = {
                    record_id
                    for table, record_id in quarantined
                    if table in {"source_snapshots", "snapshots"}
                }
                if invalid_snapshots:
                    for claim in _rows(connection, "claims"):
                        snapshot_id = str(claim.get("source_snapshot_id") or "")
                        if snapshot_id in invalid_snapshots:
                            claim_id = str(claim.get("id"))
                            quarantined.add(("claims", claim_id))
                            data_issues.append(
                                MigrationIssue(
                                    code="MIGRATION_DEPENDS_ON_QUARANTINED_SNAPSHOT",
                                    message=(
                                        "claim depends on a quarantined source snapshot"
                                    ),
                                    table="claims",
                                    record_id=claim_id,
                                    field="source_snapshot_id",
                                    actual=snapshot_id,
                                )
                            )

                # Quarantine is whole-row isolation, not coercion.  Every
                # affected raw row remains in the renamed table and
                # legacy_records, while no active domain row is created.
                converted: list[MigrationIssue] = []
                for issue in data_issues:
                    key = (
                        (issue.table, issue.record_id)
                        if issue.table is not None and issue.record_id is not None
                        else None
                    )
                    converted.append(
                        replace(issue, severity="warning")
                        if key is not None and key in quarantined
                        else issue
                    )
                data_issues = converted
            issues.extend(data_issues)

        material_plan = LegacyMaterialPlan(source_kind=source.kind)
        if source.kind in {
            SchemaKind.V01,
            SchemaKind.V02,
            SchemaKind.V03_ALPHA2,
            SchemaKind.V03_ALPHA3,
        } and not resource_limited:
            material_plan = plan_legacy_material_checkpoints(
                connection,
                source.kind,
            )
            if source.kind is SchemaKind.V01 and quarantined:
                quarantined_claims = {
                    record_id
                    for table, record_id in quarantined
                    if table == "claims"
                }
                quarantined_events = {
                    record_id
                    for table, record_id in quarantined
                    if table in {"narrative_events", "events"}
                }
                material_plan = replace(
                    material_plan,
                    claim_backfills=tuple(
                        item
                        for item in material_plan.claim_backfills
                        if item not in quarantined_claims
                    ),
                    event_backfills=tuple(
                        item
                        for item in material_plan.event_backfills
                        if item not in quarantined_events
                    ),
                )
            issues.extend(material_plan.issues)
            if (
                material_plan.requires_explicit_attestation
                and not attest_current_legacy_material
            ):
                _issue(
                    issues,
                    "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED",
                    "explicit operator acceptance of current legacy material is required",
                    actual={
                        "material_version": MATERIAL_VERSION,
                        **dict(material_plan.acceptance_counts),
                    },
                )

        database_bytes = database_bytes if path is not None else None
        required_free = (
            max(minimum_free_bytes, (database_bytes or 0) * 2)
            if path is not None
            else None
        )
        available_free = (
            shutil.disk_usage(path.parent).free if path is not None else None
        )
        if (
            required_free is not None
            and available_free is not None
            and available_free < required_free
        ):
            _issue(
                issues,
                "MIGRATION_CAPACITY_INSUFFICIENT",
                "insufficient free capacity for backup and migration",
                actual={"required": required_free, "available": available_free},
            )

        report = MigrationReport(
            mode=selected_mode,
            source=source,
            issues=tuple(issues),
            quick_check=quick_check,
            foreign_key_violations=len(foreign_keys),
            database_bytes=database_bytes,
            required_free_bytes=required_free,
            available_free_bytes=available_free,
            started_at=started,
            finished_at=_now(),
            attestation_material_version=(
                MATERIAL_VERSION
                if source.kind
                in {
                    SchemaKind.V01,
                    SchemaKind.V02,
                    SchemaKind.V03_ALPHA2,
                    SchemaKind.V03_ALPHA3,
                }
                else None
            ),
            attestation_counts=material_plan.checkpoint_counts,
            quarantined=tuple(sorted(quarantined)),
        )

        if (
            create_backup
            and path is not None
            and source.kind
            in {
                SchemaKind.V01,
                SchemaKind.V02,
                SchemaKind.V03_ALPHA2,
                SchemaKind.V03_ALPHA3,
            }
            and report.is_ready
        ):
            backup_path: Path | None = None
            temporary_backup: Path | None = None
            backup_identity: tuple[int, int] | None = None
            backup: sqlite3.Connection | None = None
            backup_source: sqlite3.Connection = connection
            close_backup_source = False
            try:
                backup_path = _unused_backup_path(path)
                temporary_backup, backup_identity = _secure_backup_temp(path)
                source_logical_digest = _logical_database_sha256(connection)
                backup = sqlite3.connect(
                    str(temporary_backup), isolation_level=None
                )
                # ``mkstemp`` must be closed before SQLite opens the file on
                # Windows.  Re-check immediately after that open and before
                # sqlite3_backup writes any page, so a replaced pathname can
                # never redirect the backup into another regular database.
                _assert_private_regular_file(temporary_backup, backup_identity)
                if connection.in_transaction:
                    # ``sqlite3_backup`` cannot make progress when its source is
                    # the same connection holding BEGIN IMMEDIATE.  A second
                    # read-only connection sees the locked, pre-DDL source while
                    # the RESERVED lock prevents any competing writer commit.
                    backup_source = _open_readonly(path)
                    close_backup_source = True
                backup_source.backup(backup)
                backup.close()
                backup = None
                if close_backup_source:
                    backup_source.close()
                    close_backup_source = False
                _assert_private_regular_file(temporary_backup, backup_identity)
                _fsync_file(temporary_backup)
                backup_digest = _file_sha256(temporary_backup)
                # A backup must itself have the same structural fingerprint,
                # pass quick_check, and preserve referential integrity before
                # it can admit the destructive phase.
                backup_ro = _open_readonly(temporary_backup)
                try:
                    backup_fp = fingerprint_schema(backup_ro)
                    backup_quick = backup_ro.execute("PRAGMA quick_check").fetchone()
                    backup_foreign_keys = backup_ro.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                    backup_logical_digest = _logical_database_sha256(backup_ro)
                finally:
                    backup_ro.close()
                if (
                    backup_fp.digest != source.digest
                    or not backup_quick
                    or str(backup_quick[0]).lower() != "ok"
                    or backup_foreign_keys
                    or backup_logical_digest != source_logical_digest
                ):
                    raise MigrationError("backup verification failed")
                _publish_backup(
                    temporary_backup,
                    backup_path,
                    backup_identity,
                )
                temporary_backup = None
            except Exception as exc:
                if backup is not None:
                    backup.close()
                if close_backup_source:
                    backup_source.close()
                if temporary_backup is not None:
                    if backup_identity is not None:
                        # A replaced path is deliberately left untouched for
                        # operator inspection.  Only our exact inode/file ID is
                        # eligible for cleanup.
                        _unlink_if_identity(temporary_backup, backup_identity)
                backup_issue = MigrationIssue(
                    "MIGRATION_BACKUP_VERIFICATION_FAILED",
                    "backup creation or verification failed",
                    actual={"error_type": type(exc).__name__},
                )
                report = replace(report, issues=report.issues + (backup_issue,))
            else:
                assert backup_path is not None
                report = replace(
                    report,
                    backup_path=str(backup_path),
                    backup_sha256=backup_digest,
                    finished_at=_now(),
                )
        return report
    finally:
        if owns_connection:
            connection.close()
        else:
            connection.row_factory = previous_factory


def migrate_to_v3(
    database: str | Path,
    *,
    mode: MigrationMode | str = MigrationMode.STRICT,
    create_backup: bool = True,
    attest_current_legacy_material: bool = False,
) -> MigrationReport:
    """Migrate a path through :class:`~continuityforge.storage.Storage`.

    The import is intentionally delayed so schema tooling remains usable while
    inspecting a damaged database and no module-level cycle is introduced.
    """

    if type(attest_current_legacy_material) is not bool:
        raise TypeError("attest_current_legacy_material must be a bool")

    from .storage import Storage

    try:
        with Storage(
            database,
            migration_mode=mode,
            create_backup=create_backup,
            attest_current_legacy_material=attest_current_legacy_material,
        ) as storage:
            report = storage.migration_report
    except MigrationError:
        raise
    if report is None:
        raise MigrationError("migration completed without a report")
    return report


__all__ = [
    "MAX_MIGRATION_DATABASE_BYTES",
    "MAX_MIGRATION_ROWS_PER_TABLE",
    "MAX_MIGRATION_TOTAL_ROWS",
    "MAX_METADATA_UTF8_BYTES",
    "MigrationIssue",
    "MigrationMode",
    "MigrationReport",
    "LegacyMaterialPlan",
    "MaterialAttestationTarget",
    "migrate_to_v3",
    "preflight_migration",
    "plan_legacy_material_checkpoints",
    "validate_migration_data",
]
