"""ContinuityForge domain exceptions.

The CLI maps these exceptions to stable, user-facing exit codes.  Keeping
domain failures separate from ``sqlite3``/``ValueError`` exceptions also
makes the governance boundary explicit for embedders.
"""

from __future__ import annotations


class ContinuityForgeError(Exception):
    """Base class for expected domain failures."""


class NotFoundError(ContinuityForgeError):
    """The requested aggregate does not exist."""


class SchemaError(ContinuityForgeError):
    """The database schema is unsupported or cannot be migrated safely."""


class ContinuityViolation(ContinuityForgeError):
    """Data from different continuities would be combined."""


class EvidenceValidationError(ContinuityForgeError):
    """A claim failed deterministic provenance validation."""

    def __init__(self, message: str, *, report: object | None = None) -> None:
        super().__init__(message)
        self.report = report


class InvalidTransitionError(ContinuityForgeError):
    """A governance state transition is not permitted."""


class GovernanceConflictError(ContinuityForgeError):
    """Authorization would conflict with an already authorized claim."""

    def __init__(self, message: str, *, conflicting_ids: list[str] | None = None) -> None:
        super().__init__(message)
        self.conflicting_ids = conflicting_ids or []


class LedgerIntegrityError(ContinuityForgeError):
    """The append-only EventLedger hash chain is invalid."""

