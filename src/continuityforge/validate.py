"""Whole-project deterministic validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Protocol

from .evidence import EvidenceValidator
from .event_integrity import EventAuditStorage, validate_event_audits
from .governance import claims_contradict
from .governance_integrity import AuthorityStorage, validate_claim_authorities
from .models import (
    ClaimProposal,
    GovernanceStatus,
    NarrativeEvent,
    Source,
    SourceSnapshot,
)
from .timeutil import validate_interval


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class ProjectIssue:
    code: str
    severity: Severity
    message: str
    aggregate_type: str | None = None
    aggregate_id: str | None = None
    details: dict[str, Any] | None = None


@dataclass(slots=True)
class ProjectValidationReport:
    issues: list[ProjectIssue]

    @property
    def is_valid(self) -> bool:
        return not any(item.severity is Severity.ERROR for item in self.issues)

    @property
    def error_count(self) -> int:
        return sum(item.severity is Severity.ERROR for item in self.issues)

    @property
    def warning_count(self) -> int:
        return sum(item.severity is Severity.WARNING for item in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [
                {
                    **asdict(issue),
                    "severity": issue.severity.value,
                }
                for issue in self.issues
            ],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class ValidationStorage(AuthorityStorage, EventAuditStorage, Protocol):
    def list_claim_proposals(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        status: GovernanceStatus | str | None = None,
    ) -> list[ClaimProposal]: ...

    def get_claim_evidence(self, claim_id: str) -> list[Any]: ...

    def list_sources(self) -> list[Source]: ...

    def list_snapshots(self, source_id: str | None = None) -> list[SourceSnapshot]: ...

    def verify_ledger(self) -> Any: ...

    def list_narrative_events(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
    ) -> list[NarrativeEvent]: ...

    def get_event_evidence(self, event_id: str) -> list[Any]: ...


class ProjectValidator:
    """Validate provenance, continuity, temporal ranges, conflicts, and ledger."""

    def __init__(self, storage: ValidationStorage) -> None:
        self.storage = storage
        self.evidence = EvidenceValidator(storage)

    def validate(self, *, strict_proposals: bool = False) -> ProjectValidationReport:
        issues: list[ProjectIssue] = []
        claims = self.storage.list_claim_proposals()
        issues.extend(self._validate_claims(claims, strict_proposals=strict_proposals))
        issues.extend(self._validate_events())
        issues.extend(self._validate_contradictions(claims))
        issues.extend(self._validate_snapshots())
        issues.extend(self._validate_ledger())
        issues.sort(
            key=lambda item: (
                0 if item.severity is Severity.ERROR else 1,
                item.code,
                item.aggregate_id or "",
            )
        )
        return ProjectValidationReport(issues)

    run = validate

    def _validate_claims(
        self, claims: list[ClaimProposal], *, strict_proposals: bool
    ) -> list[ProjectIssue]:
        result: list[ProjectIssue] = []
        authority_reports = validate_claim_authorities(self.storage, claims)
        for claim in claims:
            authority = authority_reports[claim.claim_id]
            for authority_issue in authority.issues:
                result.append(
                    ProjectIssue(
                        authority_issue.code,
                        Severity.ERROR,
                        authority_issue.message,
                        "claim",
                        claim.claim_id,
                        dict(authority_issue.details),
                    )
                )
            for name, start, end in (
                ("valid", claim.valid_from, claim.valid_to),
                ("knowledge", claim.knowledge_from, claim.knowledge_to),
            ):
                try:
                    validate_interval(start, end, name=f"{name} interval")
                except (TypeError, ValueError) as exc:
                    result.append(
                        ProjectIssue(
                            "INVALID_TEMPORAL_INTERVAL",
                            Severity.ERROR,
                            str(exc),
                            "claim",
                            claim.claim_id,
                            {"interval": name, "start": start, "end": end},
                        )
                    )

            refs = self.storage.get_claim_evidence(claim.claim_id)
            report = self.evidence.validate_claim(claim, refs)
            if report.is_valid or claim.status is GovernanceStatus.REJECTED:
                continue
            severity = (
                Severity.ERROR
                if claim.status is GovernanceStatus.AUTHORIZED or strict_proposals
                else Severity.WARNING
            )
            for evidence_issue in report.issues:
                result.append(
                    ProjectIssue(
                        evidence_issue.code,
                        severity,
                        evidence_issue.message,
                        "claim",
                        claim.claim_id,
                        evidence_issue.to_dict(),
                    )
                )
        return result

    def _validate_events(self) -> list[ProjectIssue]:
        try:
            events = self.storage.list_narrative_events()
        except AttributeError:
            return []
        result: list[ProjectIssue] = []
        audit_reports = validate_event_audits(self.storage, events)
        for event in events:
            audit = audit_reports[event.event_id]
            for audit_issue in audit.issues:
                result.append(
                    ProjectIssue(
                        audit_issue.code,
                        Severity.ERROR,
                        audit_issue.message,
                        "narrative_event",
                        event.event_id,
                        dict(audit_issue.details),
                    )
                )
            for name, start, end in (
                ("valid", event.valid_from, event.valid_to),
                ("knowledge", event.knowledge_from, event.knowledge_to),
            ):
                try:
                    validate_interval(start, end, name=f"{name} interval")
                except (TypeError, ValueError) as exc:
                    result.append(
                        ProjectIssue(
                            "INVALID_TEMPORAL_INTERVAL",
                            Severity.ERROR,
                            str(exc),
                            "narrative_event",
                            event.event_id,
                            {"interval": name, "start": start, "end": end},
                        )
                    )
            try:
                refs = self.storage.get_event_evidence(event.event_id)
            except AttributeError:
                refs = []
            report = self.evidence.validate_claim(event, refs)
            for evidence_issue in report.issues:
                result.append(
                    ProjectIssue(
                        evidence_issue.code,
                        Severity.ERROR,
                        evidence_issue.message,
                        "narrative_event",
                        event.event_id,
                        evidence_issue.to_dict(),
                    )
                )
        return result

    def _validate_contradictions(
        self, claims: list[ClaimProposal]
    ) -> list[ProjectIssue]:
        authorized = [
            item for item in claims if item.status is GovernanceStatus.AUTHORIZED
        ]
        result: list[ProjectIssue] = []
        for index, left in enumerate(authorized):
            for right in authorized[index + 1 :]:
                if claims_contradict(left, right):
                    result.append(
                        ProjectIssue(
                            "AUTHORIZED_CLAIM_CONTRADICTION",
                            Severity.ERROR,
                            "authorized atomic claims conflict in the same continuity",
                            "claim",
                            left.claim_id,
                            {"conflicting_claim_id": right.claim_id},
                        )
                    )
        return result

    def _validate_snapshots(self) -> list[ProjectIssue]:
        try:
            sources = self.storage.list_sources()
        except AttributeError:
            return []
        result: list[ProjectIssue] = []
        for source in sources:
            snapshots = sorted(
                self.storage.list_snapshots(source.source_id), key=lambda item: item.version
            )
            previous: SourceSnapshot | None = None
            for expected_version, snapshot in enumerate(snapshots, start=1):
                actual_hash = hashlib.sha256(snapshot.content.encode("utf-8")).hexdigest()
                if snapshot.content_hash != actual_hash:
                    result.append(
                        ProjectIssue(
                            "SNAPSHOT_HASH_MISMATCH",
                            Severity.ERROR,
                            "snapshot content no longer matches its immutable hash",
                            "source_snapshot",
                            snapshot.snapshot_id,
                            {"expected": snapshot.content_hash, "actual": actual_hash},
                        )
                    )
                if snapshot.version != expected_version:
                    result.append(
                        ProjectIssue(
                            "SNAPSHOT_VERSION_GAP",
                            Severity.ERROR,
                            "source snapshot versions must be contiguous",
                            "source_snapshot",
                            snapshot.snapshot_id,
                            {"expected": expected_version, "actual": snapshot.version},
                        )
                    )
                expected_previous = previous.snapshot_id if previous else None
                if snapshot.previous_snapshot_id != expected_previous:
                    result.append(
                        ProjectIssue(
                            "SNAPSHOT_CHAIN_BROKEN",
                            Severity.ERROR,
                            "previous_snapshot_id does not match the prior version",
                            "source_snapshot",
                            snapshot.snapshot_id,
                            {
                                "expected": expected_previous,
                                "actual": snapshot.previous_snapshot_id,
                            },
                        )
                    )
                if snapshot.continuity != source.continuity:
                    result.append(
                        ProjectIssue(
                            "SOURCE_CONTINUITY_MISMATCH",
                            Severity.ERROR,
                            "snapshot and logical source have different continuities",
                            "source_snapshot",
                            snapshot.snapshot_id,
                            {
                                "source": source.continuity,
                                "snapshot": snapshot.continuity,
                            },
                        )
                    )
                previous = snapshot
        return result

    def _validate_ledger(self) -> list[ProjectIssue]:
        try:
            verdict = self.storage.verify_ledger()
        except Exception as exc:  # verification failure itself is reportable
            return [
                ProjectIssue(
                    "EVENT_LEDGER_INVALID",
                    Severity.ERROR,
                    str(exc),
                    "event_ledger",
                )
            ]
        if verdict is False:
            return [
                ProjectIssue(
                    "EVENT_LEDGER_INVALID",
                    Severity.ERROR,
                    "EventLedger hash-chain verification failed",
                    "event_ledger",
                )
            ]
        # Some storage implementations return (bool, issues) or a report.
        if isinstance(verdict, tuple) and verdict and verdict[0] is False:
            return [
                ProjectIssue(
                    "EVENT_LEDGER_INVALID",
                    Severity.ERROR,
                    "EventLedger hash-chain verification failed",
                    "event_ledger",
                    details={"verdict": repr(verdict)},
                )
            ]
        if hasattr(verdict, "is_valid") and not verdict.is_valid:
            return [
                ProjectIssue(
                    "EVENT_LEDGER_INVALID",
                    Severity.ERROR,
                    "EventLedger hash-chain verification failed",
                    "event_ledger",
                    details={"verdict": repr(verdict)},
                )
            ]
        return []


__all__ = [
    "ProjectIssue",
    "ProjectValidationReport",
    "ProjectValidator",
    "Severity",
]
