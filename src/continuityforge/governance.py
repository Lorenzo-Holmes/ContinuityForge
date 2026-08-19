"""Claim proposal and governance state machine.

The central safety property is architectural rather than prompt-based: model
output can only call :meth:`ClaimGovernance.propose`; it has no parameter that
can create an authorized claim.  Authorization is a separate, recorded action
that re-validates immutable source evidence.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .evidence import EvidenceValidator, ValidationReport
from .exceptions import (
    EvidenceValidationError,
    GovernanceConflictError,
    InvalidTransitionError,
)
from .models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
)
from .timeutil import intervals_overlap, validate_interval


class GovernanceStorage(Protocol):
    """Storage surface required by the governance service."""

    def create_claim_proposal(
        self, proposal: ClaimProposal, evidence_refs: Sequence[EvidenceRef]
    ) -> ClaimProposal: ...

    def get_claim_proposal(self, claim_id: str) -> ClaimProposal: ...

    def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]: ...

    def list_claim_proposals(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        status: GovernanceStatus | str | None = None,
    ) -> list[ClaimProposal]: ...

    def record_governance_decision(
        self,
        claim_id: str,
        status: GovernanceStatus,
        reviewer: str,
        reason: str,
    ) -> GovernanceDecision: ...


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def validate_claim_shape(claim: ClaimProposal) -> None:
    """Validate deterministic, provider-independent claim fields."""

    _required_text(claim.persona_id, "persona_id")
    _required_text(claim.continuity, "continuity")
    _required_text(claim.text, "text")
    validate_interval(claim.valid_from, claim.valid_to, name="valid interval")
    validate_interval(
        claim.knowledge_from, claim.knowledge_to, name="knowledge interval"
    )
    if not 0.0 <= float(getattr(claim, "confidence", 1.0)) <= 1.0:
        raise ValueError("confidence must be between 0 and 1")


def claims_contradict(left: ClaimProposal, right: ClaimProposal) -> bool:
    """Return whether two claims express mutually exclusive atomic facts.

    Contradiction detection stays deliberately conservative: both claims need
    the same persona, continuity, subject, and predicate; their object values
    must differ; and their validity intervals must overlap.  Rich semantic
    contradiction can be proposed by an LLM later, but never replaces this
    deterministic gate.
    """

    comparable = (
        left.claim_id != right.claim_id
        and left.persona_id == right.persona_id
        and left.continuity == right.continuity
        and bool(left.subject)
        and left.subject == right.subject
        and bool(left.predicate)
        and left.predicate == right.predicate
        and left.object_value is not None
        and right.object_value is not None
        and left.object_value != right.object_value
    )
    return comparable and intervals_overlap(
        left.valid_from,
        left.valid_to,
        right.valid_from,
        right.valid_to,
    )


class ClaimGovernance:
    """Orchestrate proposals, deterministic review, and immutable decisions."""

    _TRANSITIONS: dict[GovernanceStatus, frozenset[GovernanceStatus]] = {
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
        # New source versions may invalidate a formerly authorized claim, and
        # an appeal may reopen a rejected proposal. Both moves are explicit,
        # reasoned DISPUTED decisions preserved by EventLedger.
        GovernanceStatus.AUTHORIZED: frozenset({GovernanceStatus.DISPUTED}),
        GovernanceStatus.REJECTED: frozenset({GovernanceStatus.DISPUTED}),
    }

    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage
        self.evidence = EvidenceValidator(storage)

    def _transaction(self):
        """Use the repository transaction when available.

        SQLiteStorage exposes a re-entrant transaction.  Holding its
        ``BEGIN IMMEDIATE`` across evidence/conflict checks and the decision
        closes the race in which two reviewers could authorize contradictory
        claims concurrently. Lightweight embedding stores remain supported.
        """

        factory = getattr(self.storage, "transaction", None)
        return factory() if callable(factory) else nullcontext()

    def propose(
        self,
        proposal: ClaimProposal,
        evidence_refs: Iterable[EvidenceRef] = (),
        *,
        proposed_by: str | None = None,
    ) -> ClaimProposal:
        """Persist an untrusted claim proposal without granting authority."""

        validate_claim_shape(proposal)
        refs = list(evidence_refs)
        # Ignore any status supplied by a caller.  This is the hard boundary
        # that makes an LLM-generated ``AUTHORIZED`` field inert.
        pending = replace(
            proposal,
            status=GovernanceStatus.PROPOSED,
            proposed_by=proposed_by or proposal.proposed_by or "human",
        )
        return self.storage.create_claim_proposal(pending, refs)

    def propose_from_llm(
        self,
        payload: Mapping[str, Any],
        evidence_refs: Iterable[EvidenceRef] = (),
        *,
        provider: str = "llm",
        model: str | None = None,
    ) -> ClaimProposal:
        """Convert model output into a proposal while dropping authority fields."""

        allowed = {
            "persona_id",
            "continuity",
            "text",
            "subject",
            "predicate",
            "object_value",
            "valid_from",
            "valid_to",
            "knowledge_from",
            "knowledge_to",
            "access_policy",
            "confidence",
            "rationale",
        }
        values = {key: payload[key] for key in allowed if key in payload}
        if "access_policy" in values:
            values["access_policy"] = AccessPolicy(values["access_policy"])
        values["proposal_model"] = model
        proposal = ClaimProposal(**values)
        return self.propose(
            proposal,
            evidence_refs,
            proposed_by=f"llm:{_required_text(provider, 'provider')}",
        )

    def validate_evidence(self, claim_id: str) -> ValidationReport:
        claim = self.storage.get_claim_proposal(claim_id)
        refs = self.storage.get_claim_evidence(claim_id)
        return self.evidence.validate_claim(claim, refs)

    def find_conflicts(self, proposal: ClaimProposal) -> list[ClaimProposal]:
        authorized = self.storage.list_claim_proposals(
            persona_id=proposal.persona_id,
            continuity=proposal.continuity,
            status=GovernanceStatus.AUTHORIZED,
        )
        return [candidate for candidate in authorized if claims_contradict(proposal, candidate)]

    def review(
        self,
        claim_id: str,
        decision: GovernanceStatus | str,
        *,
        reviewer: str,
        reason: str,
    ) -> GovernanceDecision:
        """Record an explicit governance decision.

        Authorization re-checks source evidence and deterministic conflicts at
        decision time, not merely at proposal time.  Rejected and disputed
        proposals remain queryable but never enter compiled memory packs.
        """

        target = GovernanceStatus(decision)
        if target is GovernanceStatus.PROPOSED:
            raise InvalidTransitionError("review target cannot be PROPOSED")
        reviewer = _required_text(reviewer, "reviewer")
        reason = _required_text(reason, "reason")
        with self._transaction():
            proposal = self.storage.get_claim_proposal(claim_id)
            allowed = self._TRANSITIONS[proposal.status]
            if target not in allowed:
                raise InvalidTransitionError(
                    f"claim {claim_id} cannot transition from {proposal.status.value} "
                    f"to {target.value}"
                )

            if target is GovernanceStatus.AUTHORIZED:
                validate_claim_shape(proposal)
                report = self.evidence.validate_claim(
                    proposal, self.storage.get_claim_evidence(claim_id)
                )
                if not report.is_valid:
                    raise EvidenceValidationError(
                        f"claim {claim_id} has inadmissible evidence", report=report
                    )
                conflicts = self.find_conflicts(proposal)
                if conflicts:
                    ids = [item.claim_id for item in conflicts]
                    raise GovernanceConflictError(
                        f"claim {claim_id} conflicts with authorized claim(s): "
                        + ", ".join(ids),
                        conflicting_ids=ids,
                    )

            return self.storage.record_governance_decision(
                claim_id, target, reviewer, reason
            )

    def add_authorized_human_claim(
        self,
        proposal: ClaimProposal,
        evidence_refs: Iterable[EvidenceRef],
        *,
        reviewer: str = "cli:human",
        reason: str = "v0.1 claim-add compatibility path",
    ) -> ClaimProposal:
        """v0.1-compatible manual add implemented through the v0.2 ledger."""

        with self._transaction():
            pending = self.propose(proposal, evidence_refs, proposed_by="human")
            self.review(
                pending.claim_id,
                GovernanceStatus.AUTHORIZED,
                reviewer=reviewer,
                reason=reason,
            )
            return self.storage.get_claim_proposal(pending.claim_id)


__all__ = [
    "ClaimGovernance",
    "GovernanceStorage",
    "claims_contradict",
    "validate_claim_shape",
]
