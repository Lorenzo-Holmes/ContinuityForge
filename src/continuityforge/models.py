"""Core, dependency-free domain models for ContinuityForge.

The models deliberately contain no database or LLM code. They are small
values that can be used by the CLI, validators, and downstream adapters
without opening SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


def _new_id(prefix: str) -> str:
    """Return an opaque identifier without external packages."""

    return f"{prefix}_{uuid4().hex}"


class _CoercibleStrEnum(str, Enum):
    """A string enum accepting member names and values case-insensitively."""

    @classmethod
    def _missing_(cls, value: object) -> "_CoercibleStrEnum | None":
        if isinstance(value, str):
            normalized = value.strip().replace("-", "_").lower()
            for member in cls:
                if member.name.lower() == normalized or member.value.lower() == normalized:
                    return member
        return None

    def __str__(self) -> str:
        return self.value


class AccessPolicy(_CoercibleStrEnum):
    """Who may receive a memory after all other filters have passed."""

    AGENT_ACCESSIBLE = "agent_accessible"
    HUMAN_ONLY = "human_only"
    HIDDEN = "hidden"


class GovernanceStatus(_CoercibleStrEnum):
    """Lifecycle state of a claim proposed by a model or a human."""

    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"


# Compatibility spelling used by some early v0.2 clients.
ClaimStatus = GovernanceStatus


@dataclass(frozen=True, slots=True)
class Source:
    """A stable logical source across one or more content revisions."""

    source_id: str
    source_key: str
    continuity: str
    created_at: str
    updated_at: str

    @property
    def id(self) -> str:
        return self.source_id


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """An immutable, content-addressed revision of a logical source."""

    snapshot_id: str
    source_id: str
    source_key: str
    continuity: str
    version: int
    content_hash: str
    content: str
    media_type: str = "text/plain"
    origin_path: str | None = None
    previous_snapshot_id: str | None = None
    line_count: int | None = None
    created_at: str | None = None

    def __post_init__(self) -> None:
        if self.line_count is None:
            object.__setattr__(self, "line_count", len(self.content.splitlines()))

    @property
    def id(self) -> str:
        return self.snapshot_id

    @property
    def sha256(self) -> str:
        return self.content_hash


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A one-based, inclusive line span supporting a claim.

    ``content_hash`` hashes the selected lines joined with LF. It is distinct
    from :attr:`SourceSnapshot.content_hash`, which hashes the complete source.
    ``quote`` is retained for deterministic drift detection and auditability.
    """

    snapshot_id: str
    start_line: int
    end_line: int
    quote: str | None = None
    evidence_id: str | None = None
    claim_id: str | None = None
    start_char: int | None = None
    end_char: int | None = None
    content_hash: str | None = None
    created_at: str | None = None
    event_id: str | None = None

    @property
    def line_start(self) -> int:
        return self.start_line

    @property
    def line_end(self) -> int:
        return self.end_line

    @property
    def quote_sha256(self) -> str | None:
        return self.content_hash


@dataclass(slots=True)
class ClaimProposal:
    """A provenance-bearing assertion awaiting explicit governance.

    Empty defaults make compatibility imports straightforward; storage
    validates required fields before a proposal can be persisted. LLM-facing
    code may construct this object, but only the governance API may advance
    its status.
    """

    claim_id: str = field(default_factory=lambda: _new_id("clm"))
    persona_id: str = ""
    continuity: str = ""
    text: str = ""
    subject: str | None = None
    predicate: str | None = None
    object_value: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    knowledge_from: str | None = None
    knowledge_to: str | None = None
    access_policy: AccessPolicy = AccessPolicy.AGENT_ACCESSIBLE
    confidence: float = 1.0
    status: GovernanceStatus = GovernanceStatus.PROPOSED
    proposed_by: str | None = None
    proposal_model: str | None = None
    rationale: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    @property
    def id(self) -> str:
        return self.claim_id

    @property
    def content(self) -> str:
        return self.text


# The v0.1 public name remains importable. In v0.2 every claim starts as a
# proposal and is promoted only through a recorded governance decision.
Claim = ClaimProposal


@dataclass(frozen=True, slots=True)
class GovernanceDecision:
    """An immutable transition in a claim's governance lifecycle."""

    decision_id: str
    claim_id: str
    from_status: GovernanceStatus
    to_status: GovernanceStatus
    reviewer: str
    reason: str
    decided_at: str


@dataclass(slots=True)
class NarrativeEvent:
    """A timeline event usable independently from atomic claims."""

    event_id: str = field(default_factory=lambda: _new_id("evt"))
    persona_id: str = ""
    continuity: str = ""
    event_type: str = "narrative"
    title: str = ""
    summary: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    valid_from: str | None = None
    valid_to: str | None = None
    knowledge_from: str | None = None
    knowledge_to: str | None = None
    access_policy: AccessPolicy = AccessPolicy.AGENT_ACCESSIBLE
    created_at: str | None = None

    @property
    def id(self) -> str:
        return self.event_id


@dataclass(frozen=True, slots=True)
class MemoryCutoff:
    """The identity, worldline, time, and access boundary for compilation."""

    persona_id: str
    continuity: str
    knowledge_at: str
    valid_at: str | None = None
    access_policies: tuple[AccessPolicy, ...] = (AccessPolicy.AGENT_ACCESSIBLE,)

    @property
    def cutoff_at(self) -> str:
        """Compatibility alias for the primary knowledge cutoff."""

        return self.knowledge_at


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One immutable entry in the database-wide EventLedger hash chain."""

    sequence: int
    entry_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    previous_hash: str
    entry_hash: str
    created_at: str

    @property
    def id(self) -> str:
        return self.entry_id


EventLedgerEntry = LedgerEntry


__all__ = [
    "AccessPolicy",
    "Claim",
    "ClaimProposal",
    "ClaimStatus",
    "EventLedgerEntry",
    "EvidenceRef",
    "GovernanceDecision",
    "GovernanceStatus",
    "LedgerEntry",
    "MemoryCutoff",
    "NarrativeEvent",
    "Source",
    "SourceSnapshot",
]
