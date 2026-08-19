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


class MigrationError(SchemaError):
    """A schema migration failed its fail-closed gate."""

    def __init__(self, message: str, *, report: object | None = None) -> None:
        super().__init__(message)
        self.report = report


class ReadOnlyStorageError(SchemaError):
    """A mutation was requested through a SQLite ``mode=ro`` repository."""


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


class InspectionError(ContinuityForgeError):
    """A read-only impact inspection failed a deterministic safety gate."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or not code.strip():
            raise ValueError("inspection error code must be non-empty")
        self.code = code.strip()
        super().__init__(message)


class InspectionLimitError(InspectionError):
    """Inspection input or output would exceed a documented resource bound."""


class InspectionIntegrityError(InspectionError):
    """Stored inspection data failed a content, authority, or metadata check."""
