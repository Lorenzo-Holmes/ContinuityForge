"""Transport-neutral, report-only SourceSnapshot impact inspection."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from typing import Any

from .evidence import quote_sha256
from .exceptions import (
    ContinuityViolation,
    EvidenceValidationError,
    InspectionIntegrityError,
    InspectionLimitError,
    NotFoundError,
)
from .governance_integrity import replay_claim_authority
from .impact import ImpactEngine, PreparedImpactTarget
from .impact_models import ImpactOutcome, ImpactReport, ImpactTargetError
from .ingest import DEFAULT_INGEST_LIMITS, source_lines
from .models import ClaimProposal, EvidenceRef, SourceSnapshot
from .readonly import ClaimAuthorityMaterial, ProvenanceRecord, ReadOnlyProject


MAX_SOURCE_REVISIONS = 10_000
MAX_AFFECTED_EVIDENCE = 10_000
MAX_REPORT_CANDIDATES = 50_000
MAX_AUTHORITY_RECORDS = 100_000
MAX_INSPECTION_MATERIAL_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ENTRIES = 250_000
MAX_LEDGER_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_SINGLE_LEDGER_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_REPORT_METADATA_BYTES = 1024


_BIDI_CONTROLS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def _validate_report_metadata(name: str, value: object) -> str:
    """Reject terminal/JSON control material before it reaches a report."""

    if not isinstance(value, str) or not value:
        raise InspectionIntegrityError(
            "REPORT_METADATA_INVALID", f"{name} must be non-empty text"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InspectionIntegrityError(
            "REPORT_METADATA_INVALID_UNICODE",
            f"{name} contains invalid Unicode",
        ) from exc
    if len(encoded) > MAX_REPORT_METADATA_BYTES:
        raise InspectionLimitError(
            "REPORT_METADATA_BYTES_LIMIT_EXCEEDED",
            f"{name} exceeds the report metadata byte limit",
        )
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or character in _BIDI_CONTROLS
        for character in value
    ):
        raise InspectionIntegrityError(
            "REPORT_METADATA_CONTROL_CHARACTER",
            f"{name} contains a forbidden control character",
        )
    return value


def _validate_snapshot_digest(name: str, value: object) -> str:
    digest = _validate_report_metadata(name, value).lower()
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise InspectionIntegrityError(
            "SNAPSHOT_CONTENT_HASH_INVALID",
            "snapshot content hash is not a SHA-256 hexadecimal digest",
        )
    return digest


@dataclass(frozen=True, slots=True)
class AffectedEvidence:
    """One provenance edge classified against a target source revision.

    The aggregate body and evidence quote are deliberately absent.  Consumers
    that need those values must explicitly query the read-only repository.
    """

    aggregate_type: str
    aggregate_id: str
    evidence_id: str
    persona_id: str
    governance_status: str | None
    impact: ImpactReport

    def __post_init__(self) -> None:
        if self.aggregate_type not in {"claim", "event"}:
            raise ValueError("aggregate_type must be 'claim' or 'event'")
        for name, value in (
            ("aggregate_id", self.aggregate_id),
            ("evidence_id", self.evidence_id),
            ("persona_id", self.persona_id),
        ):
            _validate_report_metadata(name, value)
        if self.aggregate_type == "claim" and self.governance_status is None:
            raise ValueError("claim impact entries require governance_status")
        if self.aggregate_type == "event" and self.governance_status is not None:
            raise ValueError("event impact entries do not have governance status")
        if self.governance_status is not None:
            _validate_report_metadata("governance_status", self.governance_status)
        _validate_report_metadata("old_snapshot_id", self.impact.old_snapshot_id)
        _validate_report_metadata(
            "target_snapshot_id", self.impact.target_snapshot_id
        )

    @property
    def outcome(self) -> ImpactOutcome:
        return self.impact.outcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_type": self.aggregate_type,
            "aggregate_id": self.aggregate_id,
            "evidence_id": self.evidence_id,
            "persona_id": self.persona_id,
            "governance_status": self.governance_status,
            "impact": self.impact.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SourceImpactReport:
    """Frozen aggregate report for one source revision comparison."""

    source_id: str
    source_key: str
    continuity: str
    from_snapshot_id: str
    from_version: int
    from_snapshot_sha256: str
    to_snapshot_id: str
    to_version: int
    to_snapshot_sha256: str
    affected: tuple[AffectedEvidence, ...]
    report_only: bool = True

    def __post_init__(self) -> None:
        for name, value in (
            ("source_id", self.source_id),
            ("source_key", self.source_key),
            ("continuity", self.continuity),
            ("from_snapshot_id", self.from_snapshot_id),
            ("from_snapshot_sha256", self.from_snapshot_sha256),
            ("to_snapshot_id", self.to_snapshot_id),
            ("to_snapshot_sha256", self.to_snapshot_sha256),
        ):
            _validate_report_metadata(name, value)
        for name, digest in (
            ("from_snapshot_sha256", self.from_snapshot_sha256),
            ("to_snapshot_sha256", self.to_snapshot_sha256),
        ):
            object.__setattr__(self, name, _validate_snapshot_digest(name, digest))
        if (
            type(self.from_version) is not int
            or type(self.to_version) is not int
            or self.from_version < 1
            or self.to_version <= self.from_version
        ):
            raise ValueError("expected 1 <= from_version < to_version")
        if self.report_only is not True:
            raise ValueError("source impact is report-only")
        normalized = tuple(
            sorted(
                tuple(self.affected),
                key=lambda item: (
                    item.aggregate_type,
                    item.aggregate_id,
                    item.impact.original_start_line or 0,
                    item.impact.original_end_line or 0,
                    item.evidence_id,
                ),
            )
        )
        if len(normalized) > MAX_AFFECTED_EVIDENCE:
            raise InspectionLimitError(
                "AFFECTED_EVIDENCE_LIMIT_EXCEEDED",
                "source impact affected evidence exceeds the report limit",
            )
        if sum(len(item.impact.candidates) for item in normalized) > MAX_REPORT_CANDIDATES:
            raise InspectionLimitError(
                "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED",
                "source impact candidates exceed the aggregate report limit",
            )
        object.__setattr__(self, "affected", normalized)

    @property
    def affected_count(self) -> int:
        return len(self.affected)

    @property
    def claim_count(self) -> int:
        return len(
            {item.aggregate_id for item in self.affected if item.aggregate_type == "claim"}
        )

    @property
    def event_count(self) -> int:
        return len(
            {item.aggregate_id for item in self.affected if item.aggregate_type == "event"}
        )

    @property
    def outcome_counts(self) -> dict[str, int]:
        counts = {outcome.value: 0 for outcome in ImpactOutcome}
        for item in self.affected:
            counts[item.outcome.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON data without source text or evidence quotes."""

        return {
            "schema": "continuityforge.source-impact/v0.3-alpha",
            "report_only": True,
            "source": {
                "source_id": self.source_id,
                "source_key": self.source_key,
                "continuity": self.continuity,
            },
            "from_snapshot": {
                "snapshot_id": self.from_snapshot_id,
                "version": self.from_version,
                "sha256": self.from_snapshot_sha256,
            },
            "to_snapshot": {
                "snapshot_id": self.to_snapshot_id,
                "version": self.to_version,
                "sha256": self.to_snapshot_sha256,
            },
            "summary": {
                "affected_evidence": self.affected_count,
                "claims": self.claim_count,
                "events": self.event_count,
                "outcomes": self.outcome_counts,
            },
            "affected": [item.to_dict() for item in self.affected],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
        )


class InspectionService:
    """Coordinate trusted reads, evidence validation, and pure impact logic."""

    __slots__ = ("repository", "impact_engine")

    def __init__(
        self,
        repository: ReadOnlyProject,
        *,
        impact_engine: ImpactEngine | None = None,
    ) -> None:
        if not isinstance(repository, ReadOnlyProject):
            raise TypeError("repository must be ReadOnlyProject")
        self.repository = repository
        self.impact_engine = impact_engine or ImpactEngine()

    def source_impact(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str,
        from_version: int | None = None,
        to_version: int | None = None,
        target_version: int | None = None,
    ) -> SourceImpactReport:
        """Inspect evidence anchored to one revision against a later revision.

        ``source_id`` and ``source_key`` are mutually exclusive.  ``continuity``
        is always required, including with an opaque source ID, so callers
        cannot accidentally cross a worldline.  ``target_version`` is a CLI-
        friendly alias for ``to_version``.  An omitted target means latest; an
        omitted ``from_version`` means the target's direct predecessor.

        The method is report-only.  It never changes Claim status or any other
        database value.
        """

        with self.repository.read_transaction():
            return self._source_impact_in_transaction(
                source_id,
                source_key=source_key,
                continuity=continuity,
                from_version=from_version,
                to_version=to_version,
                target_version=target_version,
            )

    def _source_impact_in_transaction(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str,
        from_version: int | None = None,
        to_version: int | None = None,
        target_version: int | None = None,
    ) -> SourceImpactReport:
        """Implementation run inside one pinned SQLite read snapshot."""

        if (source_id is None) == (source_key is None):
            raise TypeError("specify exactly one of source_id or source_key")
        if not isinstance(continuity, str) or not continuity:
            raise ValueError("continuity must be a non-empty string")
        if target_version is not None:
            if to_version is not None and to_version != target_version:
                raise ValueError("to_version and target_version disagree")
            to_version = target_version

        source = self.repository.get_source(
            source_id,
            source_key=source_key,
            continuity=continuity,
        )
        if source.continuity != continuity:
            raise ContinuityViolation("source continuity mismatch")
        _validate_report_metadata("source_id", source.source_id)
        _validate_report_metadata("source_key", source.source_key)
        _validate_report_metadata("continuity", source.continuity)
        if to_version is None:
            to_version = self.repository.get_latest_snapshot_metadata(
                source.source_id
            ).version
        if type(to_version) is not int or to_version < 1:
            raise ValueError("to_version must be a positive integer")
        if from_version is None:
            from_version = to_version - 1
        if type(from_version) is not int or from_version < 1:
            raise ValueError("from_version must be a positive integer")
        if from_version >= to_version:
            raise ValueError("from_version must be earlier than to_version")

        lineage = self.repository.list_snapshot_metadata(
            source.source_id,
            from_version=from_version,
            to_version=to_version,
            limit=MAX_SOURCE_REVISIONS,
        )
        expected_versions = tuple(range(from_version, to_version + 1))
        if tuple(item.version for item in lineage) != expected_versions:
            raise ContinuityViolation(
                "snapshot lineage contains a missing or duplicate intermediate version"
            )
        by_version = {item.version: item for item in lineage}

        # Establish every edge in the ancestry chain, rather than merely
        # trusting equal source IDs at the endpoints.  These rows contain only
        # metadata; source bodies for intermediate revisions are never loaded.
        for metadata in lineage:
            _validate_report_metadata("snapshot_id", metadata.snapshot_id)
            _validate_report_metadata("snapshot_source_id", metadata.source_id)
            _validate_snapshot_digest("snapshot_content_hash", metadata.content_hash)
        for version in range(from_version + 1, to_version + 1):
            current = by_version.get(version)
            previous = by_version.get(version - 1)
            if current is None or previous is None:
                raise ContinuityViolation(
                    "snapshot lineage contains a missing intermediate version"
                )
            if (
                current.source_id != source.source_id
                or previous.source_id != source.source_id
                or current.previous_snapshot_id != previous.snapshot_id
            ):
                raise ContinuityViolation(
                    f"snapshot lineage is invalid at source version {version}"
                )

        endpoints = self.repository.get_snapshots_by_versions_bounded(
            source.source_id,
            (from_version, to_version),
            max_content_bytes=DEFAULT_INGEST_LIMITS.max_file_bytes,
        )
        old_snapshot = endpoints[from_version]
        target_snapshot = endpoints[to_version]
        for snapshot in (old_snapshot, target_snapshot):
            metadata = by_version[snapshot.version]
            if (
                snapshot.snapshot_id != metadata.snapshot_id
                or snapshot.source_id != metadata.source_id
                or snapshot.content_hash != metadata.content_hash
                or snapshot.previous_snapshot_id != metadata.previous_snapshot_id
                or snapshot.line_count != metadata.line_count
            ):
                raise InspectionIntegrityError(
                    "SNAPSHOT_METADATA_INCONSISTENT",
                    "snapshot endpoint and lineage metadata are inconsistent",
                )
        old_digest, old_lines = self._validate_snapshot_integrity(old_snapshot)
        target_digest, target_lines = self._validate_snapshot_integrity(target_snapshot)

        # Reported authority is trusted only after the database-wide append-only
        # chain verifies in the same pinned SQLite snapshot.
        self.repository.verify_ledger_bounded(
            max_entries=MAX_LEDGER_ENTRIES,
            max_payload_bytes=MAX_LEDGER_PAYLOAD_BYTES,
            max_single_payload_bytes=MAX_SINGLE_LEDGER_PAYLOAD_BYTES,
        )
        provenance = self.repository.get_provenance_for_snapshots(
            (old_snapshot.snapshot_id,),
            max_records=MAX_AFFECTED_EVIDENCE,
            max_material_bytes=MAX_INSPECTION_MATERIAL_BYTES,
        )[old_snapshot.snapshot_id]
        for record in provenance:
            self._validate_provenance_metadata(record)
        authority = self.repository.get_claim_authority_for_snapshot(
            old_snapshot.snapshot_id,
            max_records=MAX_AUTHORITY_RECORDS,
            max_material_bytes=MAX_INSPECTION_MATERIAL_BYTES,
        )
        self._validate_claim_authority(provenance, authority)

        prepared_target = PreparedImpactTarget(
            snapshot_id=target_snapshot.snapshot_id,
            version=target_snapshot.version,
            lines=target_lines,
        )
        anchor_items: list[EvidenceRef] = []
        anchor_material_bytes = 0
        for record in provenance:
            anchor = self._validated_anchor(record, old_snapshot, old_lines)
            assert anchor.quote is not None
            anchor_material_bytes += len(anchor.quote.encode("utf-8"))
            if anchor_material_bytes > MAX_INSPECTION_MATERIAL_BYTES:
                raise InspectionLimitError(
                    "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED",
                    "source impact evidence material exceeds the inspection byte limit",
                )
            anchor_items.append(anchor)
        anchors = tuple(anchor_items)
        try:
            impacts = self.impact_engine.analyze_validated_batch(
                anchors,
                prepared_target,
                max_total_candidates=MAX_REPORT_CANDIDATES,
            )
        except ImpactTargetError as exc:
            if exc.code not in {
                "IMPACT_REPORT_CANDIDATE_LIMIT_EXCEEDED",
                "IMPACT_PATTERN_LINES_LIMIT_EXCEEDED",
            }:
                raise
            raise InspectionLimitError(exc.code, exc.message) from exc
        affected: list[AffectedEvidence] = []
        for record, anchor, impact in zip(provenance, anchors, impacts):
            aggregate = record.aggregate
            affected.append(
                AffectedEvidence(
                    aggregate_type=record.aggregate_type,
                    aggregate_id=record.aggregate_id,
                    evidence_id=anchor.evidence_id or record.evidence.evidence_id or "",
                    persona_id=aggregate.persona_id,
                    governance_status=(
                        aggregate.status.value
                        if isinstance(aggregate, ClaimProposal)
                        else None
                    ),
                    impact=impact,
                )
            )

        return SourceImpactReport(
            source_id=source.source_id,
            source_key=source.source_key,
            continuity=continuity,
            from_snapshot_id=old_snapshot.snapshot_id,
            from_version=old_snapshot.version,
            from_snapshot_sha256=old_digest,
            to_snapshot_id=target_snapshot.snapshot_id,
            to_version=target_snapshot.version,
            to_snapshot_sha256=target_digest,
            affected=tuple(affected),
        )

    @staticmethod
    def _validate_snapshot_integrity(
        snapshot: SourceSnapshot,
    ) -> tuple[str, tuple[str, ...]]:
        """Hash-bind a bounded snapshot body and return its lines once."""

        _validate_report_metadata("snapshot_id", snapshot.snapshot_id)
        _validate_report_metadata("snapshot_source_id", snapshot.source_id)
        stored_digest = _validate_snapshot_digest(
            "snapshot_content_hash", snapshot.content_hash
        )
        if not isinstance(snapshot.content, str):
            raise InspectionIntegrityError(
                "SNAPSHOT_CONTENT_MISSING", "snapshot endpoint has no textual content"
            )
        try:
            encoded = snapshot.content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise InspectionIntegrityError(
                "SNAPSHOT_CONTENT_INVALID_UNICODE",
                "snapshot endpoint contains invalid Unicode",
            ) from exc
        if len(encoded) > DEFAULT_INGEST_LIMITS.max_file_bytes:
            raise InspectionLimitError(
                "SNAPSHOT_BYTES_LIMIT_EXCEEDED",
                "source impact endpoint exceeds the snapshot byte limit",
            )
        lines = tuple(source_lines(snapshot.content))
        if len(lines) > DEFAULT_INGEST_LIMITS.max_lines:
            raise InspectionLimitError(
                "SNAPSHOT_LINES_LIMIT_EXCEEDED",
                "source impact endpoint exceeds the snapshot line limit",
            )
        for line in lines:
            try:
                line_bytes = len(line.encode("utf-8"))
            except UnicodeEncodeError as exc:  # defensive; full encode already ran
                raise InspectionIntegrityError(
                    "SNAPSHOT_CONTENT_INVALID_UNICODE",
                    "snapshot endpoint contains invalid Unicode",
                ) from exc
            if line_bytes > DEFAULT_INGEST_LIMITS.max_line_bytes:
                raise InspectionLimitError(
                    "SNAPSHOT_LINE_BYTES_LIMIT_EXCEEDED",
                    "source impact endpoint contains an overlong line",
                )
        if snapshot.line_count != len(lines):
            raise InspectionIntegrityError(
                "SNAPSHOT_LINE_COUNT_MISMATCH",
                "stored snapshot line count does not match its content",
            )
        actual_digest = sha256(encoded).hexdigest()
        if actual_digest != stored_digest:
            raise InspectionIntegrityError(
                "SNAPSHOT_CONTENT_HASH_MISMATCH",
                "stored snapshot content hash does not match its content",
            )
        return actual_digest, lines

    @staticmethod
    def _validate_provenance_metadata(record: ProvenanceRecord) -> None:
        aggregate = record.aggregate
        _validate_report_metadata("aggregate_id", record.aggregate_id)
        _validate_report_metadata("persona_id", aggregate.persona_id)
        _validate_report_metadata("evidence_snapshot_id", record.evidence.snapshot_id)
        _validate_report_metadata("evidence_id", record.evidence.evidence_id)
        if isinstance(aggregate, ClaimProposal):
            _validate_report_metadata("governance_status", aggregate.status.value)

    @staticmethod
    def _validate_claim_authority(
        provenance: tuple[ProvenanceRecord, ...],
        material: ClaimAuthorityMaterial,
    ) -> None:
        claims: dict[str, ClaimProposal] = {}
        for record in provenance:
            if not isinstance(record.aggregate, ClaimProposal):
                continue
            previous = claims.setdefault(record.aggregate.claim_id, record.aggregate)
            if previous != record.aggregate:
                raise InspectionIntegrityError(
                    "CLAIM_AUTHORITY_MATERIAL_INCONSISTENT",
                    "affected claim rows are inconsistent",
                )
        decisions_by_claim: dict[str, list[Any]] = {}
        for decision in material.decisions:
            decisions_by_claim.setdefault(decision.claim_id, []).append(decision)
        entries_by_claim: dict[str, list[Any]] = {}
        for entry in material.ledger_entries:
            entries_by_claim.setdefault(entry.aggregate_id, []).append(entry)
        evidence_by_claim: dict[str, list[EvidenceRef]] = {}
        for evidence in material.evidence:
            if evidence.claim_id is not None:
                evidence_by_claim.setdefault(evidence.claim_id, []).append(evidence)

        expected_ids = set(claims)
        if (
            set(decisions_by_claim) - expected_ids
            or set(entries_by_claim) - expected_ids
            or set(evidence_by_claim) - expected_ids
        ):
            raise InspectionIntegrityError(
                "CLAIM_AUTHORITY_SCOPE_MISMATCH",
                "claim authority material contains an unexpected aggregate",
            )
        for claim_id, claim in claims.items():
            report = replay_claim_authority(
                claim,
                decisions_by_claim.get(claim_id, ()),
                entries_by_claim.get(claim_id, ()),
                evidence_by_claim.get(claim_id, ()),
            )
            if not report.is_valid:
                raise InspectionIntegrityError(
                    "CLAIM_AUTHORITY_INVALID",
                    "affected claim authority failed deterministic replay",
                )

    def _validated_anchor(
        self,
        record: ProvenanceRecord,
        old_snapshot: SourceSnapshot,
        old_lines: tuple[str, ...],
    ) -> EvidenceRef:
        evidence = record.evidence
        if (
            record.aggregate.continuity != old_snapshot.continuity
            or evidence.snapshot_id != old_snapshot.snapshot_id
        ):
            raise EvidenceValidationError("stored evidence continuity is invalid")
        if (
            type(evidence.start_line) is not int
            or type(evidence.end_line) is not int
            or evidence.start_line < 1
            or evidence.end_line < evidence.start_line
            or evidence.end_line > len(old_lines)
        ):
            raise EvidenceValidationError("stored evidence line range is invalid")
        expected_quote = "\n".join(
            old_lines[evidence.start_line - 1 : evidence.end_line]
        )
        quote = evidence.quote
        if quote is not None:
            if not isinstance(quote, str) or quote.replace("\r\n", "\n").replace(
                "\r", "\n"
            ) != expected_quote:
                raise EvidenceValidationError("stored evidence quote does not match")
        else:
            quote = expected_quote
        expected_digest = quote_sha256(expected_quote)
        digest = evidence.content_hash
        if digest is not None:
            if not isinstance(digest, str):
                raise EvidenceValidationError("stored evidence digest is invalid")
            normalized = digest.strip().lower()
            if normalized.startswith("sha256:"):
                normalized = normalized[7:]
            if normalized != expected_digest:
                raise EvidenceValidationError("stored evidence digest does not match")
            digest = normalized
        else:
            digest = expected_digest

        # v0.2 allowed quote/digest to be omitted.  Coordinates against the
        # immutable, now-validated old snapshot still form a complete anchor;
        # derive only missing fields locally so the pure engine receives its
        # canonical exact-match value without altering persistence.
        return replace(evidence, quote=quote, content_hash=digest)


__all__ = [
    "AffectedEvidence",
    "InspectionService",
    "MAX_AFFECTED_EVIDENCE",
    "MAX_REPORT_CANDIDATES",
    "MAX_SOURCE_REVISIONS",
    "SourceImpactReport",
]
