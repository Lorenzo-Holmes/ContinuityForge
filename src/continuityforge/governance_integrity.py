"""Deterministic replay of claim authority and its audit correspondence.

The current value in ``claim_proposals.status`` is a cache, not a source of
authority.  A claim is authoritative only when its immutable decision stream
replays from ``PROPOSED`` to that value and every decision has exactly one
matching EventLedger entry.  This module deliberately contains no SQLite or
LLM code so validators, compilers, and alternate repositories use the same
fail-closed rule.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .models import (
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
)


ALLOWED_GOVERNANCE_TRANSITIONS: Mapping[
    GovernanceStatus, frozenset[GovernanceStatus]
] = {
    GovernanceStatus.PROPOSED: frozenset(
        {
            GovernanceStatus.AUTHORIZED,
            GovernanceStatus.REJECTED,
            GovernanceStatus.DISPUTED,
        }
    ),
    GovernanceStatus.DISPUTED: frozenset(
        {GovernanceStatus.AUTHORIZED, GovernanceStatus.REJECTED}
    ),
    GovernanceStatus.AUTHORIZED: frozenset({GovernanceStatus.DISPUTED}),
    GovernanceStatus.REJECTED: frozenset({GovernanceStatus.DISPUTED}),
}


class AuthorityStorage(Protocol):
    """Read-only repository surface required for authority replay."""

    def list_governance_decisions(
        self, *, claim_id: str | None = None
    ) -> list[GovernanceDecision]: ...

    def list_ledger_entries(
        self,
        *,
        after_sequence: int = 0,
        event_type: str | None = None,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        limit: int | None = None,
    ) -> list[LedgerEntry]: ...

    def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]: ...

    def list_all_claim_evidence(self) -> list[EvidenceRef]: ...


@dataclass(frozen=True, slots=True)
class AuthorityIssue:
    """One deterministic authority-chain violation."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthorityReport:
    """Replay result for one claim."""

    claim_id: str
    current_status: GovernanceStatus
    replayed_status: GovernanceStatus | None
    decision_count: int
    ledger_decision_count: int
    issues: tuple[AuthorityIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues and self.replayed_status is self.current_status

    @property
    def is_authorized(self) -> bool:
        return self.is_valid and self.replayed_status is GovernanceStatus.AUTHORIZED

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "current_status": self.current_status.value,
            "replayed_status": (
                self.replayed_status.value if self.replayed_status is not None else None
            ),
            "decision_count": self.decision_count,
            "ledger_decision_count": self.ledger_decision_count,
            "is_valid": self.is_valid,
            "is_authorized": self.is_authorized,
            "issues": [asdict(issue) for issue in self.issues],
        }


def _issue(
    issues: list[AuthorityIssue],
    code: str,
    message: str,
    **details: Any,
) -> None:
    issues.append(AuthorityIssue(code, message, details))


def _decision_payload_matches(
    decision: GovernanceDecision, payload: Mapping[str, Any]
) -> bool:
    expected = {
        "decision_id": decision.decision_id,
        "from_status": decision.from_status.value,
        "to_status": decision.to_status.value,
        "reviewer": decision.reviewer,
        "reason": decision.reason,
    }
    return all(payload.get(key) == value for key, value in expected.items())


def replay_claim_authority(
    claim: ClaimProposal,
    decisions: Sequence[GovernanceDecision],
    ledger_entries: Sequence[LedgerEntry],
    evidence_ids: Iterable[EvidenceRef | str] | None = None,
) -> AuthorityReport:
    """Replay a claim's decision chain and bind it to EventLedger entries."""

    issues: list[AuthorityIssue] = []
    current = GovernanceStatus.PROPOSED
    proposed_entries = [
        entry
        for entry in ledger_entries
        if entry.event_type == "claim.proposed"
        and entry.aggregate_type == "claim"
        and entry.aggregate_id == claim.claim_id
    ]
    if len(proposed_entries) != 1:
        _issue(
            issues,
            "CLAIM_PROPOSAL_LEDGER_MISMATCH",
            "claim must have exactly one claim.proposed ledger entry",
            count=len(proposed_entries),
        )
    else:
        payload = proposed_entries[0].payload
        expected = {
            "persona_id": claim.persona_id,
            "continuity": claim.continuity,
            "text": claim.text,
            "access_policy": claim.access_policy.value,
            "confidence": float(claim.confidence),
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            _issue(
                issues,
                "CLAIM_PROPOSAL_LEDGER_PAYLOAD_MISMATCH",
                "claim proposal row and ledger payload differ",
                sequence=proposed_entries[0].sequence,
            )

    decision_entries = [
        entry
        for entry in ledger_entries
        if entry.event_type == "claim.governance_decided"
        and entry.aggregate_type == "claim"
        and entry.aggregate_id == claim.claim_id
    ]
    ledger_by_decision: dict[str, list[LedgerEntry]] = {}
    for entry in decision_entries:
        decision_id = entry.payload.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            _issue(
                issues,
                "LEDGER_DECISION_ID_MISSING",
                "governance ledger entry has no decision_id",
                sequence=entry.sequence,
            )
            continue
        ledger_by_decision.setdefault(decision_id, []).append(entry)

    # Ledger sequence is the immutable ordering authority.  ``decided_at`` is
    # operator metadata and can move backward when the system clock changes.
    supplied_decisions = list(decisions)
    supplied_order = {id(decision): index for index, decision in enumerate(supplied_decisions)}
    ordered_decisions = sorted(
        supplied_decisions,
        key=lambda decision: (
            ledger_by_decision[decision.decision_id][0].sequence
            if len(ledger_by_decision.get(decision.decision_id, ())) == 1
            else 2**63,
            supplied_order[id(decision)],
        ),
    )
    for index, decision in enumerate(ordered_decisions):
        if decision.claim_id != claim.claim_id:
            _issue(
                issues,
                "DECISION_CLAIM_MISMATCH",
                "governance decision belongs to another claim",
                decision_id=decision.decision_id,
                decision_claim_id=decision.claim_id,
            )
            continue
        if decision.from_status is not current:
            _issue(
                issues,
                "DECISION_CHAIN_BROKEN",
                "decision from_status does not match the replayed state",
                decision_id=decision.decision_id,
                index=index,
                expected=current.value,
                actual=decision.from_status.value,
            )
            # Continue from the recorded target so all downstream defects are
            # observable in one report; the report remains invalid.
        if decision.to_status not in ALLOWED_GOVERNANCE_TRANSITIONS.get(
            current, frozenset()
        ):
            _issue(
                issues,
                "DECISION_TRANSITION_INVALID",
                "decision transition is not allowed by the governance graph",
                decision_id=decision.decision_id,
                from_status=current.value,
                to_status=decision.to_status.value,
            )
        if not decision.reviewer.strip() or not decision.reason.strip():
            _issue(
                issues,
                "DECISION_ATTRIBUTION_MISSING",
                "decision reviewer and reason must be non-empty",
                decision_id=decision.decision_id,
            )
        current = decision.to_status

    known_ids = {decision.decision_id for decision in ordered_decisions}
    for decision in ordered_decisions:
        matches = ledger_by_decision.get(decision.decision_id, [])
        if len(matches) != 1:
            _issue(
                issues,
                "DECISION_LEDGER_MISMATCH",
                "governance decision must have exactly one matching ledger entry",
                decision_id=decision.decision_id,
                count=len(matches),
            )
        elif not _decision_payload_matches(decision, matches[0].payload):
            _issue(
                issues,
                "DECISION_LEDGER_PAYLOAD_MISMATCH",
                "governance decision and ledger payload differ",
                decision_id=decision.decision_id,
                sequence=matches[0].sequence,
            )

    matched_sequences = [
        ledger_by_decision[decision.decision_id][0].sequence
        for decision in ordered_decisions
        if len(ledger_by_decision.get(decision.decision_id, [])) == 1
    ]
    if matched_sequences != sorted(matched_sequences):
        _issue(
            issues,
            "DECISION_LEDGER_ORDER_MISMATCH",
            "decision row order and governance ledger order differ",
            sequences=matched_sequences,
        )
    if proposed_entries and decision_entries:
        if proposed_entries[0].sequence >= min(entry.sequence for entry in decision_entries):
            _issue(
                issues,
                "CLAIM_PROPOSAL_LEDGER_ORDER_INVALID",
                "claim.proposed must precede every governance decision",
                proposal_sequence=proposed_entries[0].sequence,
            )

    for decision_id, entries in ledger_by_decision.items():
        if decision_id not in known_ids:
            _issue(
                issues,
                "ORPHAN_GOVERNANCE_LEDGER_ENTRY",
                "governance ledger entry has no immutable decision row",
                decision_id=decision_id,
                sequences=[entry.sequence for entry in entries],
            )

    # Evidence is part of what the reviewer authorized. Appending to an
    # AUTHORIZED or REJECTED claim without reopening it as DISPUTED makes the
    # immutable decision refer to a different evidence set.
    decision_by_id = {decision.decision_id: decision for decision in ordered_decisions}
    replayed_during_ledger = GovernanceStatus.PROPOSED
    ledger_evidence_ids: list[str] = []
    proposal_sequence = proposed_entries[0].sequence if len(proposed_entries) == 1 else None
    if len(proposed_entries) == 1:
        proposed_ids = proposed_entries[0].payload.get("evidence_ids")
        if not isinstance(proposed_ids, (list, tuple)) or any(
            not isinstance(item, str) or not item for item in proposed_ids
        ):
            _issue(
                issues,
                "PROPOSAL_EVIDENCE_LEDGER_INVALID",
                "claim.proposed evidence_ids must be a list of non-empty IDs",
                sequence=proposed_entries[0].sequence,
            )
        else:
            ledger_evidence_ids.extend(proposed_ids)
    for entry in sorted(ledger_entries, key=lambda item: item.sequence):
        if entry.event_type == "claim.governance_decided":
            decision_id = entry.payload.get("decision_id")
            decision = decision_by_id.get(decision_id) if isinstance(decision_id, str) else None
            if decision is not None:
                replayed_during_ledger = decision.to_status
        elif entry.event_type == "claim.evidence_added":
            evidence_id = entry.payload.get("evidence_id")
            if not isinstance(evidence_id, str) or not evidence_id:
                _issue(
                    issues,
                    "EVIDENCE_LEDGER_ID_MISSING",
                    "claim.evidence_added must name one evidence ID",
                    sequence=entry.sequence,
                )
            else:
                ledger_evidence_ids.append(evidence_id)
            if proposal_sequence is None or entry.sequence <= proposal_sequence:
                _issue(
                    issues,
                    "EVIDENCE_LEDGER_ORDER_INVALID",
                    "claim.evidence_added must follow claim.proposed",
                    sequence=entry.sequence,
                )
            if replayed_during_ledger not in {
                GovernanceStatus.PROPOSED,
                GovernanceStatus.DISPUTED,
            }:
                _issue(
                    issues,
                    "EVIDENCE_APPENDED_WITHOUT_REVIEW_REOPEN",
                    "evidence was appended while the claim was not reviewable",
                    sequence=entry.sequence,
                    status=replayed_during_ledger.value,
                    evidence_id=entry.payload.get("evidence_id"),
                )

    if len(set(ledger_evidence_ids)) != len(ledger_evidence_ids):
        _issue(
            issues,
            "DUPLICATE_EVIDENCE_LEDGER_ID",
            "claim authority ledger names an evidence ID more than once",
        )
    if evidence_ids is not None:
        supplied_evidence = list(evidence_ids)
        evidence_by_id = {
            item.evidence_id: item
            for item in supplied_evidence
            if isinstance(item, EvidenceRef) and item.evidence_id
        }
        stored_evidence_ids = [
            item.evidence_id or "" if isinstance(item, EvidenceRef) else item
            for item in supplied_evidence
        ]
        if any(not isinstance(item, str) or not item for item in stored_evidence_ids):
            _issue(
                issues,
                "STORED_EVIDENCE_ID_INVALID",
                "stored evidence must use non-empty string IDs",
            )
        if len(set(stored_evidence_ids)) != len(stored_evidence_ids):
            _issue(
                issues,
                "DUPLICATE_STORED_EVIDENCE_ID",
                "stored evidence IDs must be unique",
            )
        if set(stored_evidence_ids) != set(ledger_evidence_ids):
            _issue(
                issues,
                "EVIDENCE_SET_LEDGER_MISMATCH",
                "stored evidence set differs from the audited claim evidence set",
                missing_from_ledger=sorted(
                    set(stored_evidence_ids) - set(ledger_evidence_ids)
                ),
                missing_from_storage=sorted(
                    set(ledger_evidence_ids) - set(stored_evidence_ids)
                ),
            )
        for entry in ledger_entries:
            if entry.event_type != "claim.evidence_added":
                continue
            evidence_id = entry.payload.get("evidence_id")
            actual = evidence_by_id.get(evidence_id) if isinstance(evidence_id, str) else None
            if actual is None:
                continue
            expected = {
                "evidence_id": actual.evidence_id,
                "snapshot_id": actual.snapshot_id,
                "start_line": actual.start_line,
                "end_line": actual.end_line,
            }
            if any(entry.payload.get(key) != value for key, value in expected.items()):
                _issue(
                    issues,
                    "EVIDENCE_LEDGER_PAYLOAD_MISMATCH",
                    "evidence row and claim.evidence_added payload differ",
                    evidence_id=evidence_id,
                    sequence=entry.sequence,
                )

    if claim.status is not current:
        _issue(
            issues,
            "CLAIM_STATUS_REPLAY_MISMATCH",
            "cached claim status differs from the replayed decision chain",
            cached=claim.status.value,
            replayed=current.value,
        )

    return AuthorityReport(
        claim_id=claim.claim_id,
        current_status=claim.status,
        replayed_status=current,
        decision_count=len(ordered_decisions),
        ledger_decision_count=len(decision_entries),
        issues=tuple(issues),
    )


def validate_claim_authority(
    storage: AuthorityStorage, claim: ClaimProposal
) -> AuthorityReport:
    """Load and replay authority data, failing closed when it is unavailable."""

    try:
        decisions = storage.list_governance_decisions(claim_id=claim.claim_id)
        entries = storage.list_ledger_entries(
            aggregate_type="claim", aggregate_id=claim.claim_id
        )
        evidence = storage.get_claim_evidence(claim.claim_id)
    except (AttributeError, NotImplementedError) as exc:
        return AuthorityReport(
            claim_id=claim.claim_id,
            current_status=claim.status,
            replayed_status=None,
            decision_count=0,
            ledger_decision_count=0,
            issues=(
                AuthorityIssue(
                    "AUTHORITY_DATA_UNAVAILABLE",
                    "storage cannot provide immutable governance and ledger history",
                    {"error_type": type(exc).__name__},
                ),
            ),
        )
    return replay_claim_authority(
        claim,
        decisions,
        entries,
        evidence,
    )


def validate_claim_authorities(
    storage: AuthorityStorage, claims: Iterable[ClaimProposal]
) -> dict[str, AuthorityReport]:
    """Bulk-load and replay authority without per-claim repository queries."""

    claim_items = list(claims)
    try:
        decisions = storage.list_governance_decisions()
        entries = storage.list_ledger_entries(aggregate_type="claim")
        evidence = storage.list_all_claim_evidence()
    except (AttributeError, NotImplementedError) as exc:
        return {
            claim.claim_id: AuthorityReport(
                claim_id=claim.claim_id,
                current_status=claim.status,
                replayed_status=None,
                decision_count=0,
                ledger_decision_count=0,
                issues=(
                    AuthorityIssue(
                        "AUTHORITY_DATA_UNAVAILABLE",
                        "storage cannot provide immutable governance and ledger history",
                        {"error_type": type(exc).__name__},
                    ),
                ),
            )
            for claim in claim_items
        }

    decisions_by_claim: dict[str, list[GovernanceDecision]] = {}
    for decision in decisions:
        decisions_by_claim.setdefault(decision.claim_id, []).append(decision)
    entries_by_claim: dict[str, list[LedgerEntry]] = {}
    for entry in entries:
        if entry.aggregate_type == "claim":
            entries_by_claim.setdefault(entry.aggregate_id, []).append(entry)
    evidence_by_claim: dict[str, list[EvidenceRef]] = {}
    for item in evidence:
        if item.claim_id is not None:
            evidence_by_claim.setdefault(item.claim_id, []).append(item)
    return {
        claim.claim_id: replay_claim_authority(
            claim,
            decisions_by_claim.get(claim.claim_id, ()),
            entries_by_claim.get(claim.claim_id, ()),
            evidence_by_claim.get(claim.claim_id, ()),
        )
        for claim in claim_items
    }


__all__ = [
    "ALLOWED_GOVERNANCE_TRANSITIONS",
    "AuthorityIssue",
    "AuthorityReport",
    "AuthorityStorage",
    "replay_claim_authority",
    "validate_claim_authorities",
    "validate_claim_authority",
]
