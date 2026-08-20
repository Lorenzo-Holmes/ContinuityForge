"""Strict read-only repository used by inspection and audit workflows.

``Storage`` owns schema creation, migration, and all mutations.  This module is
deliberately separate: opening a project through :class:`ReadOnlyProject`
never creates a database, runs DDL, changes journal mode, or performs a
migration.  SQLite's URI ``mode=ro`` and ``PRAGMA query_only`` provide two
independent write barriers.  The connection deliberately participates in
SQLite's normal locking/WAL protocol so committed concurrent revisions remain
visible; it never uses the potentially stale ``immutable=1`` shortcut.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import threading
from types import MappingProxyType
from typing import Iterable, Iterator, Mapping, Sequence

from .exceptions import (
    ContinuityViolation,
    InspectionIntegrityError,
    InspectionLimitError,
    LedgerIntegrityError,
    NotFoundError,
    ReadOnlyStorageError,
    SchemaError,
)
from .models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
    NarrativeEvent,
    Source,
    SourceSnapshot,
)
from .ingest import SourceInputError, parse_json_content
from .schema import SchemaFingerprint, SchemaKind, fingerprint_schema
from .source_integrity import SourceAuditSnapshot


GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class SnapshotMetadata:
    """A SourceSnapshot descriptor that deliberately excludes source content."""

    snapshot_id: str
    source_id: str
    version: int
    content_hash: str
    media_type: str
    origin_path: str | None
    previous_snapshot_id: str | None
    line_count: int
    created_at: str


@dataclass(frozen=True, slots=True)
class ClaimAuthorityMaterial:
    """Bounded bulk inputs for replaying claims affected by one snapshot."""

    decisions: tuple[GovernanceDecision, ...]
    ledger_entries: tuple[LedgerEntry, ...]
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class EventAuditMaterial:
    """Bounded bulk inputs for replaying events affected by one snapshot."""

    ledger_entries: tuple[LedgerEntry, ...]
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class SourceAuditMaterial:
    """Bounded Source lineage and ledger correspondence for inspection."""

    snapshots: tuple[SourceAuditSnapshot, ...]
    ledger_entries: tuple[LedgerEntry, ...]


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """One stored evidence reference and the aggregate that owns it."""

    snapshot_id: str
    aggregate_type: str
    aggregate_id: str
    aggregate: ClaimProposal | NarrativeEvent
    evidence: EvidenceRef

    def __post_init__(self) -> None:
        if self.aggregate_type not in {"claim", "event"}:
            raise ValueError("aggregate_type must be 'claim' or 'event'")
        if self.snapshot_id != self.evidence.snapshot_id:
            raise ValueError("record and evidence snapshot IDs differ")
        if self.aggregate_type == "claim":
            if not isinstance(self.aggregate, ClaimProposal):
                raise TypeError("claim provenance requires ClaimProposal")
            if self.aggregate_id != self.aggregate.claim_id:
                raise ValueError("record and claim IDs differ")
        else:
            if not isinstance(self.aggregate, NarrativeEvent):
                raise TypeError("event provenance requires NarrativeEvent")
            if self.aggregate_id != self.aggregate.event_id:
                raise ValueError("record and event IDs differ")

    @property
    def claim(self) -> ClaimProposal | None:
        return self.aggregate if isinstance(self.aggregate, ClaimProposal) else None

    @property
    def event(self) -> NarrativeEvent | None:
        return self.aggregate if isinstance(self.aggregate, NarrativeEvent) else None


class ReadOnlyProject:
    """A fail-closed repository for an existing ContinuityForge SQLite file.

    Use :meth:`open` rather than constructing this class directly.  Both v0.2
    and v0.3 layouts are readable; every other fingerprint is rejected without
    attempting an implicit migration.
    """

    __slots__ = (
        "path",
        "_connection",
        "schema_fingerprint",
        "_tables",
        "_transaction_depth",
        "_lock",
    )

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        schema_fingerprint: SchemaFingerprint,
    ) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = connection
        self.schema_fingerprint = schema_fingerprint
        self._tables = frozenset(schema_fingerprint.tables)
        self._transaction_depth = 0
        self._lock = threading.RLock()

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        timeout: float = 5.0,
    ) -> "ReadOnlyProject":
        """Open an existing v0.2/v0.3 project without changing domain state.

        Missing paths, non-files, unknown schemas, partial schemas, and corrupt
        SQLite files fail before a repository is returned.  No parent or
        missing sidecar is created.  SQLite may update coordination bytes in
        an already-existing ``-shm`` file while the logical database, main
        file, and WAL remain unchanged.
        """

        candidate = Path(path).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise NotFoundError(f"project database not found: {candidate}") from exc
        if not resolved.is_file():
            raise NotFoundError(f"project database is not a file: {resolved}")

        # SQLite may create a missing shared-memory index even for mode=ro when
        # a WAL is present.  That would violate this repository's file-level
        # read-only promise, so reject this incomplete sidecar set before
        # opening the database at all.
        wal_path = resolved.with_name(resolved.name + "-wal")
        shm_path = resolved.with_name(resolved.name + "-shm")
        if wal_path.exists() and not shm_path.exists():
            raise ReadOnlyStorageError(
                "read-only inspection requires an existing -shm sidecar when -wal exists"
            )

        # Path.as_uri percent-encodes reserved characters and works for both
        # Windows drive paths and POSIX paths.  Do not add immutable=1 here: it
        # may ignore a live WAL and return a stale inspection result.
        uri = f"{resolved.as_uri()}?mode=ro"
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=timeout,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            query_only = connection.execute("PRAGMA query_only").fetchone()
            if query_only is None or int(query_only[0]) != 1:
                raise SchemaError("SQLite query_only write barrier was not enabled")
            # fingerprint_schema performs several catalog reads.  Pin them to
            # one view so a concurrent migration can never yield a hybrid
            # classification.
            connection.execute("BEGIN")
            try:
                fingerprint = fingerprint_schema(connection)
                quick = connection.execute("PRAGMA quick_check").fetchone()
                if quick is None or str(quick[0]).lower() != "ok":
                    raise SchemaError(
                        "SQLite quick_check failed: "
                        f"{quick[0] if quick is not None else 'no result'}"
                    )
                foreign_key_violations = connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall()
                if foreign_key_violations:
                    raise SchemaError(
                        "SQLite foreign_key_check reported "
                        f"{len(foreign_key_violations)} violation(s)"
                    )
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            if fingerprint.kind not in {SchemaKind.V02, SchemaKind.V03}:
                raise SchemaError(
                    "read-only inspection requires a complete v0.2 or v0.3 "
                    f"schema; found {fingerprint.kind.value} "
                    f"(fingerprint {fingerprint.digest})"
                )
        except SchemaError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                connection.close()
            raise SchemaError(f"invalid ContinuityForge database: {resolved}") from exc
        assert connection is not None
        return cls(resolved, connection, fingerprint)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("read-only project is closed")
        return self._connection

    @property
    def schema_version(self) -> int:
        return self.schema_fingerprint.user_version

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                self._connection.close()
                self._connection = None
                self._transaction_depth = 0

    def __enter__(self) -> "ReadOnlyProject":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @contextmanager
    def read_transaction(self) -> Iterator["ReadOnlyProject"]:
        """Pin all reads in the block to one SQLite snapshot.

        Nested blocks share the outer snapshot.  The outermost block always
        rolls back on exit (success or failure), which is deterministic for a
        query-only connection and leaves the repository immediately reusable.
        """

        with self._lock:
            connection = self.connection
            outermost = self._transaction_depth == 0
            if outermost:
                connection.execute("BEGIN")
            self._transaction_depth += 1
            try:
                yield self
            finally:
                self._transaction_depth -= 1
                if outermost and connection.in_transaction:
                    connection.execute("ROLLBACK")

    # Familiar spelling for repository consumers; it is still read-only.
    transaction = read_transaction

    @staticmethod
    def _source(row: sqlite3.Row) -> Source:
        return Source(
            source_id=str(row["source_id"]),
            source_key=str(row["source_key"]),
            continuity=str(row["continuity"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> SourceSnapshot:
        return SourceSnapshot(
            snapshot_id=str(row["snapshot_id"]),
            source_id=str(row["source_id"]),
            source_key=str(row["source_key"]),
            continuity=str(row["continuity"]),
            version=int(row["version"]),
            content_hash=str(row["content_hash"]),
            content=str(row["content"]),
            media_type=str(row["media_type"]),
            origin_path=row["origin_path"],
            previous_snapshot_id=row["previous_snapshot_id"],
            line_count=int(row["line_count"]),
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _snapshot_metadata(row: sqlite3.Row) -> SnapshotMetadata:
        return SnapshotMetadata(
            snapshot_id=str(row["snapshot_id"]),
            source_id=str(row["source_id"]),
            version=int(row["version"]),
            content_hash=str(row["content_hash"]),
            media_type=str(row["media_type"]),
            origin_path=row["origin_path"],
            previous_snapshot_id=row["previous_snapshot_id"],
            line_count=int(row["line_count"]),
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _claim(row: sqlite3.Row) -> ClaimProposal:
        return ClaimProposal(
            claim_id=str(row["claim_id"]),
            persona_id=str(row["persona_id"]),
            continuity=str(row["continuity"]),
            text=str(row["text"]),
            subject=row["subject"],
            predicate=row["predicate"],
            object_value=row["object_value"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            knowledge_from=row["knowledge_from"],
            knowledge_to=row["knowledge_to"],
            access_policy=AccessPolicy(row["access_policy"]),
            confidence=float(row["confidence"]),
            status=GovernanceStatus(row["status"]),
            proposed_by=row["proposed_by"],
            proposal_model=row["proposal_model"],
            rationale=row["rationale"],
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> NarrativeEvent:
        try:
            details = parse_json_content(str(row["details_json"]))
        except (SourceInputError, TypeError, ValueError, RecursionError) as exc:
            raise InspectionIntegrityError(
                "EVENT_DETAILS_INVALID",
                "narrative event details are not valid bounded JSON",
            ) from exc
        if not isinstance(details, Mapping):
            raise InspectionIntegrityError(
                "EVENT_DETAILS_INVALID",
                "narrative event details must be a JSON object",
            )
        return NarrativeEvent(
            event_id=str(row["event_id"]),
            persona_id=str(row["persona_id"]),
            continuity=str(row["continuity"]),
            event_type=str(row["event_type"]),
            title=str(row["title"]),
            summary=str(row["summary"]),
            details=details,
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            knowledge_from=row["knowledge_from"],
            knowledge_to=row["knowledge_to"],
            access_policy=AccessPolicy(row["access_policy"]),
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _governance_decision(row: sqlite3.Row) -> GovernanceDecision:
        return GovernanceDecision(
            decision_id=str(row["decision_id"]),
            claim_id=str(row["claim_id"]),
            from_status=GovernanceStatus(row["from_status"]),
            to_status=GovernanceStatus(row["to_status"]),
            reviewer=str(row["reviewer"]),
            reason=str(row["reason"]),
            decided_at=str(row["decided_at"]),
        )

    @staticmethod
    def _ledger_entry(row: sqlite3.Row) -> LedgerEntry:
        try:
            payload = parse_json_content(str(row["payload_json"]))
        except (SourceInputError, TypeError, ValueError, RecursionError) as exc:
            raise InspectionIntegrityError(
                "LEDGER_PAYLOAD_INVALID",
                "EventLedger contains an invalid JSON payload",
            ) from exc
        if not isinstance(payload, Mapping):
            raise InspectionIntegrityError(
                "LEDGER_PAYLOAD_INVALID",
                "EventLedger payload must be a JSON object",
            )
        return LedgerEntry(
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

    @staticmethod
    def _claim_evidence(row: sqlite3.Row) -> EvidenceRef:
        return EvidenceRef(
            snapshot_id=str(row["snapshot_id"]),
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            quote=row["quote"],
            evidence_id=str(row["evidence_id"]),
            claim_id=str(row["claim_id"]),
            event_id=None,
            start_char=row["start_char"],
            end_char=row["end_char"],
            content_hash=row["content_hash"],
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _event_evidence(row: sqlite3.Row) -> EvidenceRef:
        return EvidenceRef(
            snapshot_id=str(row["snapshot_id"]),
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            quote=row["quote"],
            evidence_id=str(row["evidence_id"]),
            claim_id=None,
            event_id=str(row["event_id"]),
            start_char=row["start_char"],
            end_char=row["end_char"],
            content_hash=row["content_hash"],
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _joined_claim_evidence(row: sqlite3.Row) -> EvidenceRef:
        """Map the explicitly aliased evidence half of a provenance join."""

        return EvidenceRef(
            snapshot_id=str(row["e_snapshot_id"]),
            start_line=int(row["e_start_line"]),
            end_line=int(row["e_end_line"]),
            quote=row["e_quote"],
            evidence_id=str(row["e_evidence_id"]),
            claim_id=str(row["claim_id"]),
            event_id=None,
            start_char=row["e_start_char"],
            end_char=row["e_end_char"],
            content_hash=row["e_content_hash"],
            created_at=str(row["e_created_at"]),
        )

    @staticmethod
    def _joined_event_evidence(row: sqlite3.Row) -> EvidenceRef:
        """Map the explicitly aliased evidence half of an event join."""

        return EvidenceRef(
            snapshot_id=str(row["e_snapshot_id"]),
            start_line=int(row["e_start_line"]),
            end_line=int(row["e_end_line"]),
            quote=row["e_quote"],
            evidence_id=str(row["e_evidence_id"]),
            claim_id=None,
            event_id=str(row["event_id"]),
            start_char=row["e_start_char"],
            end_char=row["e_end_char"],
            content_hash=row["e_content_hash"],
            created_at=str(row["e_created_at"]),
        )

    # ------------------------------------------------------------------
    # Logical sources and snapshots
    # ------------------------------------------------------------------

    def get_source(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str | None = None,
    ) -> Source:
        if source_id is not None and source_key is not None:
            raise TypeError("specify source_id or source_key, not both")
        if source_id is not None:
            rows = self.connection.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source_id,)
            ).fetchall()
        elif source_key is not None:
            sql = "SELECT * FROM sources WHERE source_key = ?"
            params: list[object] = [source_key]
            if continuity is not None:
                sql += " AND continuity = ?"
                params.append(continuity)
            rows = self.connection.execute(sql, params).fetchall()
        else:
            raise TypeError("source_id or source_key is required")
        if not rows:
            raise NotFoundError("source not found")
        if len(rows) != 1:
            raise ContinuityViolation(
                "source_key exists in more than one continuity; specify continuity"
            )
        source = self._source(rows[0])
        if continuity is not None and source.continuity != continuity:
            raise ContinuityViolation("source continuity mismatch")
        return source

    def list_sources(self, *, continuity: str | None = None) -> list[Source]:
        sql = "SELECT * FROM sources"
        params: tuple[object, ...] = ()
        if continuity is not None:
            sql += " WHERE continuity = ?"
            params = (continuity,)
        sql += " ORDER BY source_key, continuity, source_id"
        return [self._source(row) for row in self.connection.execute(sql, params)]

    _SNAPSHOT_SELECT = (
        "SELECT ss.*, s.source_key, s.continuity FROM source_snapshots ss "
        "JOIN sources s ON s.source_id = ss.source_id"
    )

    def get_snapshot(self, snapshot_id: str) -> SourceSnapshot:
        row = self.connection.execute(
            self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"snapshot not found: {snapshot_id}")
        return self._snapshot(row)

    def get_snapshot_by_version(self, source_id: str, version: int) -> SourceSnapshot:
        if type(version) is not int or version < 1:
            raise ValueError("version must be a positive integer")
        row = self.connection.execute(
            self._SNAPSHOT_SELECT
            + " WHERE ss.source_id = ? AND ss.version = ?",
            (source_id, version),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"source {source_id} has no snapshot version {version}")
        return self._snapshot(row)

    def get_latest_snapshot(self, source_id: str) -> SourceSnapshot:
        row = self.connection.execute(
            self._SNAPSHOT_SELECT
            + " WHERE ss.source_id = ? ORDER BY ss.version DESC LIMIT 1",
            (source_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"source has no snapshots: {source_id}")
        return self._snapshot(row)

    _SNAPSHOT_METADATA_COLUMNS = (
        "snapshot_id, source_id, version, content_hash, media_type, origin_path, "
        "previous_snapshot_id, line_count, created_at"
    )

    def get_latest_snapshot_metadata(self, source_id: str) -> SnapshotMetadata:
        """Resolve the latest revision without materializing its content."""

        row = self.connection.execute(
            "SELECT "
            + self._SNAPSHOT_METADATA_COLUMNS
            + " FROM source_snapshots WHERE source_id = ? "
            "ORDER BY version DESC LIMIT 1",
            (source_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("source has no snapshots")
        return self._snapshot_metadata(row)

    def list_snapshot_metadata(
        self,
        source_id: str,
        *,
        from_version: int,
        to_version: int,
        limit: int,
    ) -> tuple[SnapshotMetadata, ...]:
        """Load one bounded lineage interval without loading revision bodies."""

        if type(from_version) is not int or type(to_version) is not int:
            raise TypeError("snapshot versions must be built-in integers")
        if from_version < 1 or to_version < from_version:
            raise ValueError("expected 1 <= from_version <= to_version")
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive built-in integer")
        # Reject a caller-supplied interval before even scanning SQLite.  LIMIT
        # + 1 remains a second fail-closed guard against malformed duplicate
        # version rows in legacy databases.
        if to_version - from_version + 1 > limit:
            raise InspectionLimitError(
                "SOURCE_REVISION_LIMIT_EXCEEDED",
                "source impact revision interval exceeds the inspection limit",
            )
        rows = self.connection.execute(
            "SELECT "
            + self._SNAPSHOT_METADATA_COLUMNS
            + " FROM source_snapshots WHERE source_id = ? "
            "AND version BETWEEN ? AND ? ORDER BY version, snapshot_id LIMIT ?",
            (source_id, from_version, to_version, limit + 1),
        ).fetchall()
        if len(rows) > limit:
            raise InspectionLimitError(
                "SOURCE_REVISION_LIMIT_EXCEEDED",
                "source impact revision interval exceeds the inspection limit",
            )
        return tuple(self._snapshot_metadata(row) for row in rows)

    def get_snapshots_by_versions_bounded(
        self,
        source_id: str,
        versions: Sequence[int],
        *,
        max_content_bytes: int,
    ) -> Mapping[int, SourceSnapshot]:
        """Load only named revision bodies after a SQL-side byte-size gate."""

        supplied = tuple(versions)
        if not supplied or len(supplied) > 2:
            raise ValueError("one or two endpoint versions are required")
        if any(type(version) is not int or version < 1 for version in supplied):
            raise ValueError("endpoint versions must be positive built-in integers")
        normalized = tuple(sorted(set(supplied)))
        if len(normalized) != len(supplied):
            raise ValueError("endpoint versions must be distinct")
        if type(max_content_bytes) is not int or max_content_bytes < 1:
            raise ValueError("max_content_bytes must be a positive integer")
        placeholders = ",".join("?" for _ in normalized)
        params: tuple[object, ...] = (source_id, *normalized)
        size_rows = self.connection.execute(
            "SELECT version, length(CAST(content AS BLOB)) AS content_bytes "
            "FROM source_snapshots WHERE source_id = ? "
            f"AND version IN ({placeholders}) ORDER BY version",
            params,
        ).fetchall()
        if len(size_rows) != len(normalized):
            raise NotFoundError("one or more source snapshot endpoint versions are missing")
        if any(
            row["content_bytes"] is None
            or int(row["content_bytes"]) > max_content_bytes
            for row in size_rows
        ):
            raise InspectionLimitError(
                "SNAPSHOT_BYTES_LIMIT_EXCEEDED",
                "source impact endpoint exceeds the snapshot byte limit",
            )
        rows = self.connection.execute(
            self._SNAPSHOT_SELECT
            + f" WHERE ss.source_id = ? AND ss.version IN ({placeholders}) "
            "ORDER BY ss.version",
            params,
        ).fetchall()
        if len(rows) != len(normalized):
            raise NotFoundError("one or more source snapshot endpoint versions are missing")
        result = {int(row["version"]): self._snapshot(row) for row in rows}
        if len(result) != len(rows):
            raise ContinuityViolation("source contains duplicate snapshot versions")
        return MappingProxyType(result)

    def list_snapshots(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str | None = None,
    ) -> list[SourceSnapshot]:
        clauses: list[str] = []
        params: list[object] = []
        if source_id is not None:
            clauses.append("ss.source_id = ?")
            params.append(source_id)
        if source_key is not None:
            clauses.append("s.source_key = ?")
            params.append(source_key)
        if continuity is not None:
            clauses.append("s.continuity = ?")
            params.append(continuity)
        sql = self._SNAPSHOT_SELECT
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY s.source_key, s.continuity, ss.version, ss.snapshot_id"
        return [self._snapshot(row) for row in self.connection.execute(sql, params)]

    def list_source_audit_snapshots(self) -> list[SourceAuditSnapshot]:
        rows = self.connection.execute(
            "SELECT snapshot_id, source_id, version, content_hash, media_type, "
            "origin_path, previous_snapshot_id, line_count, created_at "
            "FROM source_snapshots ORDER BY source_id, version, snapshot_id"
        )
        return [self._source_audit_snapshot(row) for row in rows]

    @staticmethod
    def _source_audit_snapshot(row: sqlite3.Row) -> SourceAuditSnapshot:
        return SourceAuditSnapshot(
            snapshot_id=str(row["snapshot_id"]),
            source_id=str(row["source_id"]),
            version=int(row["version"]),
            content_hash=str(row["content_hash"]),
            media_type=str(row["media_type"]),
            origin_path=row["origin_path"],
            previous_snapshot_id=row["previous_snapshot_id"],
            line_count=int(row["line_count"]),
            created_at=str(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Claims, events, and evidence
    # ------------------------------------------------------------------

    def get_claim_proposal(self, claim_id: str) -> ClaimProposal:
        row = self.connection.execute(
            "SELECT * FROM claim_proposals WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"claim not found: {claim_id}")
        return self._claim(row)

    get_claim = get_claim_proposal

    def list_claim_proposals(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        status: GovernanceStatus | str | None = None,
        snapshot_id: str | None = None,
    ) -> list[ClaimProposal]:
        clauses: list[str] = []
        params: list[object] = []
        if persona_id is not None:
            clauses.append("cp.persona_id = ?")
            params.append(persona_id)
        if continuity is not None:
            clauses.append("cp.continuity = ?")
            params.append(continuity)
        if status is not None:
            clauses.append("cp.status = ?")
            params.append(GovernanceStatus(status).value)
        if snapshot_id is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM evidence_refs er WHERE er.claim_id = "
                "cp.claim_id AND er.snapshot_id = ?)"
            )
            params.append(snapshot_id)
        sql = "SELECT cp.* FROM claim_proposals cp"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY cp.created_at, cp.claim_id"
        return [self._claim(row) for row in self.connection.execute(sql, params)]

    list_claims = list_claim_proposals

    def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]:
        if self.connection.execute(
            "SELECT 1 FROM claim_proposals WHERE claim_id = ?", (claim_id,)
        ).fetchone() is None:
            raise NotFoundError(f"claim not found: {claim_id}")
        rows = self.connection.execute(
            "SELECT * FROM evidence_refs WHERE claim_id = ? "
            "ORDER BY snapshot_id, start_line, end_line, evidence_id",
            (claim_id,),
        )
        return [self._claim_evidence(row) for row in rows]

    def list_all_claim_evidence(self) -> list[EvidenceRef]:
        """Bulk-load claim evidence for authority replay in one query."""

        rows = self.connection.execute(
            "SELECT * FROM evidence_refs "
            "ORDER BY claim_id, snapshot_id, start_line, end_line, evidence_id"
        )
        return [self._claim_evidence(row) for row in rows]

    list_claim_evidence = get_claim_evidence

    def get_narrative_event(self, event_id: str) -> NarrativeEvent:
        row = self.connection.execute(
            "SELECT * FROM narrative_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"narrative event not found: {event_id}")
        return self._event(row)

    get_event = get_narrative_event

    def list_narrative_events(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
    ) -> list[NarrativeEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if persona_id is not None:
            clauses.append("persona_id = ?")
            params.append(persona_id)
        if continuity is not None:
            clauses.append("continuity = ?")
            params.append(continuity)
        sql = "SELECT * FROM narrative_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY COALESCE(valid_from, knowledge_from, created_at), event_id"
        return [self._event(row) for row in self.connection.execute(sql, params)]

    list_events = list_narrative_events

    def get_event_evidence(self, event_id: str) -> list[EvidenceRef]:
        if self.connection.execute(
            "SELECT 1 FROM narrative_events WHERE event_id = ?", (event_id,)
        ).fetchone() is None:
            raise NotFoundError(f"narrative event not found: {event_id}")
        if "event_evidence_refs" not in self._tables:
            return []
        rows = self.connection.execute(
            "SELECT * FROM event_evidence_refs WHERE event_id = ? "
            "ORDER BY snapshot_id, start_line, end_line, evidence_id",
            (event_id,),
        )
        return [self._event_evidence(row) for row in rows]

    def list_all_event_evidence(self) -> list[EvidenceRef]:
        """Bulk-load event evidence for audit replay in one query."""

        if "event_evidence_refs" not in self._tables:
            return []
        rows = self.connection.execute(
            "SELECT * FROM event_evidence_refs "
            "ORDER BY event_id, snapshot_id, start_line, end_line, evidence_id"
        )
        return [self._event_evidence(row) for row in rows]

    list_event_evidence = get_event_evidence

    def get_evidence(self, evidence_id: str) -> EvidenceRef:
        """Return a uniquely identified claim or event evidence reference."""

        claim_row = self.connection.execute(
            "SELECT * FROM evidence_refs WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        event_row = None
        if "event_evidence_refs" in self._tables:
            event_row = self.connection.execute(
                "SELECT * FROM event_evidence_refs WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        if claim_row is not None and event_row is not None:
            raise SchemaError(
                f"evidence ID is ambiguous across claim and event tables: {evidence_id}"
            )
        if claim_row is not None:
            return self._claim_evidence(claim_row)
        if event_row is not None:
            return self._event_evidence(event_row)
        raise NotFoundError(f"evidence not found: {evidence_id}")

    def list_evidence(
        self,
        *,
        snapshot_id: str | None = None,
        claim_id: str | None = None,
        event_id: str | None = None,
    ) -> list[EvidenceRef]:
        """List immutable evidence without loading owner aggregates."""

        if claim_id is not None and event_id is not None:
            raise TypeError("claim_id and event_id are mutually exclusive")
        results: list[EvidenceRef] = []
        if event_id is None:
            clauses: list[str] = []
            params: list[object] = []
            if snapshot_id is not None:
                clauses.append("snapshot_id = ?")
                params.append(snapshot_id)
            if claim_id is not None:
                clauses.append("claim_id = ?")
                params.append(claim_id)
            sql = "SELECT * FROM evidence_refs"
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            results.extend(
                self._claim_evidence(row)
                for row in self.connection.execute(sql, params)
            )
        if claim_id is None and "event_evidence_refs" in self._tables:
            clauses = []
            params = []
            if snapshot_id is not None:
                clauses.append("snapshot_id = ?")
                params.append(snapshot_id)
            if event_id is not None:
                clauses.append("event_id = ?")
                params.append(event_id)
            sql = "SELECT * FROM event_evidence_refs"
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            results.extend(
                self._event_evidence(row)
                for row in self.connection.execute(sql, params)
            )
        return sorted(
            results,
            key=lambda item: (
                item.snapshot_id,
                item.claim_id or "",
                item.event_id or "",
                item.start_line,
                item.end_line,
                item.evidence_id or "",
            ),
        )

    def list_snapshot_evidence(self, snapshot_id: str) -> list[EvidenceRef]:
        return self.list_evidence(snapshot_id=snapshot_id)

    def get_provenance_for_snapshots(
        self,
        snapshot_ids: Iterable[str],
        *,
        max_records: int | None = None,
        max_material_bytes: int | None = None,
    ) -> Mapping[str, tuple[ProvenanceRecord, ...]]:
        """Return claim and event provenance for snapshots using fixed queries.

        The method executes one set query per evidence table, not one query per
        aggregate.  This is the repository boundary used by impact inspection
        to avoid N+1 reads.
        """

        if isinstance(snapshot_ids, (str, bytes)):
            raise TypeError("snapshot_ids must be an iterable of IDs, not one string")
        supplied = tuple(snapshot_ids)
        if any(not isinstance(value, str) or not value for value in supplied):
            raise ValueError("snapshot_ids must contain non-empty strings")
        identifiers = tuple(sorted(set(supplied)))
        if not identifiers:
            return MappingProxyType({})
        # SQLite's default host-parameter limit is at least 999.  Refusing a
        # huge caller batch is safer than silently splitting into N queries.
        if len(identifiers) > 900:
            raise ValueError("at most 900 snapshot IDs may be inspected per batch")
        if max_records is not None and (
            type(max_records) is not int or max_records < 1
        ):
            raise ValueError("max_records must be a positive built-in integer")
        if max_material_bytes is not None and (
            type(max_material_bytes) is not int or max_material_bytes < 1
        ):
            raise ValueError("max_material_bytes must be a positive built-in integer")

        placeholders = ",".join("?" for _ in identifiers)
        if max_records is not None:
            claim_stats = self.connection.execute(
                "SELECT COUNT(*) AS record_count, COALESCE(SUM("
                "length(CAST(COALESCE(er.quote, '') AS BLOB)) + "
                "length(CAST(cp.text AS BLOB)) + "
                "length(CAST(COALESCE(cp.subject, '') AS BLOB)) + "
                "length(CAST(COALESCE(cp.predicate, '') AS BLOB)) + "
                "length(CAST(COALESCE(cp.object_value, '') AS BLOB)) + "
                "length(CAST(COALESCE(cp.rationale, '') AS BLOB))"
                "), 0) AS material_bytes FROM evidence_refs er "
                "JOIN claim_proposals cp ON cp.claim_id = er.claim_id "
                f"WHERE er.snapshot_id IN ({placeholders})",
                identifiers,
            ).fetchone()
            assert claim_stats is not None
            claim_count = int(claim_stats["record_count"])
            material_bytes = int(claim_stats["material_bytes"])
            event_count = 0
            if "event_evidence_refs" in self._tables:
                event_stats = self.connection.execute(
                    "SELECT COUNT(*) AS record_count, COALESCE(SUM("
                    "length(CAST(COALESCE(eer.quote, '') AS BLOB)) + "
                    "length(CAST(ne.title AS BLOB)) + "
                    "length(CAST(ne.summary AS BLOB)) + "
                    "length(CAST(ne.details_json AS BLOB))"
                    "), 0) AS material_bytes FROM event_evidence_refs eer "
                    "JOIN narrative_events ne ON ne.event_id = eer.event_id "
                    f"WHERE eer.snapshot_id IN ({placeholders})",
                    identifiers,
                ).fetchone()
                assert event_stats is not None
                event_count = int(event_stats["record_count"])
                material_bytes += int(event_stats["material_bytes"])
            if claim_count + event_count > max_records:
                raise InspectionLimitError(
                    "AFFECTED_EVIDENCE_LIMIT_EXCEEDED",
                    "source impact affected evidence exceeds the report limit",
                )
            if (
                max_material_bytes is not None
                and material_bytes > max_material_bytes
            ):
                raise InspectionLimitError(
                    "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED",
                    "source impact evidence material exceeds the inspection byte limit",
                )
        grouped: dict[str, list[ProvenanceRecord]] = {
            snapshot_id: [] for snapshot_id in identifiers
        }
        evidence_columns = (
            "evidence_id AS e_evidence_id, snapshot_id AS e_snapshot_id, "
            "start_line AS e_start_line, end_line AS e_end_line, "
            "start_char AS e_start_char, end_char AS e_end_char, "
            "quote AS e_quote, content_hash AS e_content_hash, "
            "created_at AS e_created_at"
        )
        claim_rows = self.connection.execute(
            "SELECT cp.*, "
            + ", ".join(f"er.{part}" for part in evidence_columns.split(", "))
            + " FROM evidence_refs er "
            "JOIN claim_proposals cp ON cp.claim_id = er.claim_id "
            f"WHERE er.snapshot_id IN ({placeholders}) "
            "ORDER BY er.snapshot_id, cp.claim_id, er.start_line, er.end_line, "
            "er.evidence_id",
            identifiers,
        ).fetchall()
        for row in claim_rows:
            evidence = self._joined_claim_evidence(row)
            claim = self._claim(row)
            grouped[evidence.snapshot_id].append(
                ProvenanceRecord(
                    snapshot_id=evidence.snapshot_id,
                    aggregate_type="claim",
                    aggregate_id=claim.claim_id,
                    aggregate=claim,
                    evidence=evidence,
                )
            )

        if "event_evidence_refs" in self._tables:
            event_rows = self.connection.execute(
                "SELECT ne.*, "
                + ", ".join(f"eer.{part}" for part in evidence_columns.split(", "))
                + " FROM event_evidence_refs eer "
                "JOIN narrative_events ne ON ne.event_id = eer.event_id "
                f"WHERE eer.snapshot_id IN ({placeholders}) "
                "ORDER BY eer.snapshot_id, ne.event_id, eer.start_line, "
                "eer.end_line, eer.evidence_id",
                identifiers,
            ).fetchall()
            for row in event_rows:
                evidence = self._joined_event_evidence(row)
                event = self._event(row)
                grouped[evidence.snapshot_id].append(
                    ProvenanceRecord(
                        snapshot_id=evidence.snapshot_id,
                        aggregate_type="event",
                        aggregate_id=event.event_id,
                        aggregate=event,
                        evidence=evidence,
                    )
                )

        frozen = {
            snapshot_id: tuple(
                sorted(
                    records,
                    key=lambda item: (
                        item.aggregate_type,
                        item.aggregate_id,
                        item.evidence.start_line,
                        item.evidence.end_line,
                        item.evidence.evidence_id or "",
                    ),
                )
            )
            for snapshot_id, records in grouped.items()
        }
        return MappingProxyType(frozen)

    # Readable aliases for single- and multi-snapshot call sites.
    batch_provenance = get_provenance_for_snapshots

    def list_provenance(self, snapshot_id: str) -> tuple[ProvenanceRecord, ...]:
        return self.get_provenance_for_snapshots((snapshot_id,))[snapshot_id]

    list_snapshot_provenance = list_provenance
    get_provenance_for_snapshot = list_provenance
    provenance_for_snapshots = get_provenance_for_snapshots

    # ------------------------------------------------------------------
    # Bounded integrity material for report-producing inspection
    # ------------------------------------------------------------------

    @staticmethod
    def _ledger_digest(
        *,
        sequence: int,
        entry_id: str,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        payload_json: str,
        previous_hash: str,
        created_at: str,
    ) -> str:
        material = json.dumps(
            {
                "sequence": sequence,
                "entry_id": entry_id,
                "event_type": event_type,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "payload_json": payload_json,
                "previous_hash": previous_hash,
                "created_at": created_at,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(material.encode("utf-8")).hexdigest()

    def verify_ledger_bounded(
        self,
        *,
        max_entries: int,
        max_payload_bytes: int,
        max_single_payload_bytes: int,
    ) -> None:
        """Verify the complete global chain under explicit memory bounds.

        The aggregate SQL query returns only integers, allowing a huge or
        malformed project to be rejected before Python materializes any
        payload.  A second, single cursor scan then verifies every link in the
        pinned read transaction.
        """

        for name, value in (
            ("max_entries", max_entries),
            ("max_payload_bytes", max_payload_bytes),
            ("max_single_payload_bytes", max_single_payload_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive built-in integer")
        stats = self.connection.execute(
            "SELECT COUNT(*) AS entry_count, "
            "COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0) AS payload_bytes, "
            "COALESCE(MAX(length(CAST(payload_json AS BLOB))), 0) AS max_payload_bytes "
            "FROM event_ledger"
        ).fetchone()
        assert stats is not None
        if int(stats["entry_count"]) > max_entries:
            raise InspectionLimitError(
                "INSPECTION_LEDGER_ENTRY_LIMIT_EXCEEDED",
                "EventLedger exceeds the read-only inspection entry limit",
            )
        if (
            int(stats["payload_bytes"]) > max_payload_bytes
            or int(stats["max_payload_bytes"]) > max_single_payload_bytes
        ):
            raise InspectionLimitError(
                "INSPECTION_LEDGER_PAYLOAD_LIMIT_EXCEEDED",
                "EventLedger exceeds the read-only inspection payload limit",
            )

        expected_sequence = 1
        expected_previous = GENESIS_HASH
        for row in self.connection.execute(
            "SELECT sequence, entry_id, event_type, aggregate_type, aggregate_id, "
            "payload_json, previous_hash, entry_hash, created_at "
            "FROM event_ledger ORDER BY sequence"
        ):
            try:
                sequence = int(row["sequence"])
                previous_hash = str(row["previous_hash"])
                entry_hash = str(row["entry_hash"])
                payload_json = str(row["payload_json"])
                calculated = self._ledger_digest(
                    sequence=sequence,
                    entry_id=str(row["entry_id"]),
                    event_type=str(row["event_type"]),
                    aggregate_type=str(row["aggregate_type"]),
                    aggregate_id=str(row["aggregate_id"]),
                    payload_json=payload_json,
                    previous_hash=previous_hash,
                    created_at=str(row["created_at"]),
                )
            except (TypeError, ValueError, UnicodeError) as exc:
                raise LedgerIntegrityError("EventLedger row is malformed") from exc
            if sequence != expected_sequence:
                raise LedgerIntegrityError(
                    f"ledger sequence gap: expected {expected_sequence}, got {sequence}"
                )
            if previous_hash != expected_previous:
                raise LedgerIntegrityError(
                    f"ledger previous_hash mismatch at sequence {sequence}"
                )
            if calculated != entry_hash:
                raise LedgerIntegrityError(
                    f"ledger entry_hash mismatch at sequence {sequence}"
                )
            expected_previous = entry_hash
            expected_sequence += 1

    def get_source_audit_for_source(
        self,
        source_id: str,
        *,
        max_records: int,
        max_material_bytes: int,
    ) -> SourceAuditMaterial:
        """Load one complete Source audit stream under explicit SQL-side bounds."""

        if not isinstance(source_id, str) or not source_id:
            raise ValueError("source_id must be non-empty")
        if type(max_records) is not int or max_records < 1:
            raise ValueError("max_records must be a positive built-in integer")
        if type(max_material_bytes) is not int or max_material_bytes < 1:
            raise ValueError("max_material_bytes must be a positive built-in integer")
        snapshots = "SELECT snapshot_id FROM source_snapshots WHERE source_id = ?"
        stats = self.connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM source_snapshots WHERE source_id = ?) AS snapshots, "
            "(SELECT COUNT(*) FROM event_ledger WHERE "
            "(event_type = 'source.created' AND aggregate_id = ?) OR "
            "(event_type = 'source_snapshot.created' AND aggregate_id IN ("
            + snapshots
            + "))) AS ledger_entries, "
            "(SELECT COALESCE(SUM("
            "length(CAST(snapshot_id AS BLOB)) + length(CAST(source_id AS BLOB)) + "
            "length(CAST(content_hash AS BLOB)) + length(CAST(media_type AS BLOB)) + "
            "length(CAST(COALESCE(origin_path, '') AS BLOB)) + "
            "length(CAST(COALESCE(previous_snapshot_id, '') AS BLOB)) + "
            "length(CAST(created_at AS BLOB))), 0) FROM source_snapshots "
            "WHERE source_id = ?) + "
            "(SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0) "
            "FROM event_ledger WHERE "
            "(event_type = 'source.created' AND aggregate_id = ?) OR "
            "(event_type = 'source_snapshot.created' AND aggregate_id IN ("
            + snapshots
            + "))) AS material_bytes",
            (source_id, source_id, source_id, source_id, source_id, source_id),
        ).fetchone()
        assert stats is not None
        total = int(stats["snapshots"]) + int(stats["ledger_entries"])
        if total > max_records:
            raise InspectionLimitError(
                "INSPECTION_SOURCE_AUDIT_RECORD_LIMIT_EXCEEDED",
                "Source audit material exceeds the inspection record limit",
            )
        if int(stats["material_bytes"]) > max_material_bytes:
            raise InspectionLimitError(
                "INSPECTION_SOURCE_AUDIT_BYTES_LIMIT_EXCEEDED",
                "Source audit material exceeds the inspection byte limit",
            )
        snapshot_rows = self.connection.execute(
            "SELECT snapshot_id, source_id, version, content_hash, media_type, "
            "origin_path, previous_snapshot_id, line_count, created_at "
            "FROM source_snapshots WHERE source_id = ? "
            "ORDER BY version, snapshot_id",
            (source_id,),
        )
        audit_snapshots = tuple(
            self._source_audit_snapshot(row) for row in snapshot_rows
        )
        ledger_rows = self.connection.execute(
            "SELECT * FROM event_ledger WHERE "
            "(event_type = 'source.created' AND aggregate_id = ?) OR "
            "(event_type = 'source_snapshot.created' AND aggregate_id IN ("
            + snapshots
            + ")) ORDER BY sequence",
            (source_id, source_id),
        )
        return SourceAuditMaterial(
            audit_snapshots,
            tuple(self._ledger_entry(row) for row in ledger_rows),
        )

    def get_claim_authority_for_snapshot(
        self,
        snapshot_id: str,
        *,
        max_records: int,
        max_material_bytes: int,
    ) -> ClaimAuthorityMaterial:
        """Bulk-load all authority inputs for claims citing one snapshot.

        Three set queries are used after one scalar count query.  The affected
        claim set is expressed as a subquery rather than interpolated IDs, so
        query count and SQLite host parameters remain constant at the report
        limit.
        """

        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ValueError("snapshot_id must be non-empty")
        if type(max_records) is not int or max_records < 1:
            raise ValueError("max_records must be a positive built-in integer")
        if type(max_material_bytes) is not int or max_material_bytes < 1:
            raise ValueError("max_material_bytes must be a positive built-in integer")
        affected = (
            "SELECT DISTINCT claim_id FROM evidence_refs WHERE snapshot_id = ?"
        )
        stats = self.connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM governance_decisions WHERE claim_id IN ("
            + affected
            + ")) AS decisions, "
            "(SELECT COUNT(*) FROM event_ledger WHERE aggregate_type = 'claim' "
            "AND aggregate_id IN ("
            + affected
            + ")) AS ledger_entries, "
            "(SELECT COUNT(*) FROM evidence_refs WHERE claim_id IN ("
            + affected
            + ")) AS evidence, "
            "(SELECT COALESCE(SUM(length(CAST(reviewer AS BLOB)) + "
            "length(CAST(reason AS BLOB))), 0) FROM governance_decisions "
            "WHERE claim_id IN ("
            + affected
            + ")) + "
            "(SELECT COALESCE(SUM(length(CAST(COALESCE(quote, '') AS BLOB))), 0) "
            "FROM evidence_refs WHERE claim_id IN ("
            + affected
            + ")) AS material_bytes",
            (snapshot_id, snapshot_id, snapshot_id, snapshot_id, snapshot_id),
        ).fetchone()
        assert stats is not None
        total = int(stats["decisions"]) + int(stats["ledger_entries"]) + int(
            stats["evidence"]
        )
        if total > max_records:
            raise InspectionLimitError(
                "INSPECTION_AUTHORITY_RECORD_LIMIT_EXCEEDED",
                "claim authority material exceeds the inspection record limit",
            )
        if int(stats["material_bytes"]) > max_material_bytes:
            raise InspectionLimitError(
                "INSPECTION_AUTHORITY_BYTES_LIMIT_EXCEEDED",
                "claim authority material exceeds the inspection byte limit",
            )
        decision_rows = self.connection.execute(
            "SELECT * FROM governance_decisions WHERE claim_id IN ("
            + affected
            + ") ORDER BY rowid",
            (snapshot_id,),
        )
        decisions = tuple(self._governance_decision(row) for row in decision_rows)
        ledger_rows = self.connection.execute(
            "SELECT * FROM event_ledger WHERE aggregate_type = 'claim' "
            "AND aggregate_id IN ("
            + affected
            + ") ORDER BY sequence",
            (snapshot_id,),
        )
        ledger_entries = tuple(self._ledger_entry(row) for row in ledger_rows)
        evidence_rows = self.connection.execute(
            "SELECT * FROM evidence_refs WHERE claim_id IN ("
            + affected
            + ") ORDER BY claim_id, snapshot_id, start_line, end_line, evidence_id",
            (snapshot_id,),
        )
        evidence = tuple(self._claim_evidence(row) for row in evidence_rows)
        return ClaimAuthorityMaterial(decisions, ledger_entries, evidence)

    def get_event_audit_for_snapshot(
        self,
        snapshot_id: str,
        *,
        max_records: int,
        max_material_bytes: int,
    ) -> EventAuditMaterial:
        """Bulk-load bounded audit inputs for events citing one snapshot.

        The affected event IDs are resolved inside each fixed set query.  The
        method loads the complete evidence set for every affected event, not
        only the evidence anchored to ``snapshot_id``, because the creation
        ledger binds that complete set.  No query count depends on the number
        of affected events.
        """

        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ValueError("snapshot_id must be non-empty")
        if type(max_records) is not int or max_records < 1:
            raise ValueError("max_records must be a positive built-in integer")
        if type(max_material_bytes) is not int or max_material_bytes < 1:
            raise ValueError("max_material_bytes must be a positive built-in integer")
        if "event_evidence_refs" not in self._tables:
            return EventAuditMaterial((), ())

        affected_cte = (
            "WITH affected(event_id) AS ("
            "SELECT DISTINCT event_id FROM event_evidence_refs WHERE snapshot_id = ?"
            ") "
        )
        stats = self.connection.execute(
            affected_cte
            + "SELECT "
            "(SELECT COUNT(*) FROM event_ledger el JOIN affected a "
            "ON a.event_id = el.aggregate_id "
            "WHERE el.aggregate_type = 'narrative_event') AS ledger_entries, "
            "(SELECT COUNT(*) FROM event_evidence_refs eer JOIN affected a "
            "ON a.event_id = eer.event_id) AS evidence, "
            "(SELECT COALESCE(SUM("
            "length(CAST(el.entry_id AS BLOB)) + "
            "length(CAST(el.event_type AS BLOB)) + "
            "length(CAST(el.aggregate_type AS BLOB)) + "
            "length(CAST(el.aggregate_id AS BLOB)) + "
            "length(CAST(el.payload_json AS BLOB)) + "
            "length(CAST(el.previous_hash AS BLOB)) + "
            "length(CAST(el.entry_hash AS BLOB)) + "
            "length(CAST(el.created_at AS BLOB))"
            "), 0) FROM event_ledger el JOIN affected a "
            "ON a.event_id = el.aggregate_id "
            "WHERE el.aggregate_type = 'narrative_event') + "
            "(SELECT COALESCE(SUM("
            "length(CAST(eer.evidence_id AS BLOB)) + "
            "length(CAST(eer.event_id AS BLOB)) + "
            "length(CAST(eer.snapshot_id AS BLOB)) + "
            "length(CAST(COALESCE(eer.quote, '') AS BLOB)) + "
            "length(CAST(COALESCE(eer.content_hash, '') AS BLOB)) + "
            "length(CAST(eer.created_at AS BLOB))"
            "), 0) FROM event_evidence_refs eer JOIN affected a "
            "ON a.event_id = eer.event_id) AS material_bytes",
            (snapshot_id,),
        ).fetchone()
        assert stats is not None
        total = int(stats["ledger_entries"]) + int(stats["evidence"])
        if total > max_records:
            raise InspectionLimitError(
                "INSPECTION_EVENT_AUDIT_RECORD_LIMIT_EXCEEDED",
                "event audit material exceeds the inspection record limit",
            )
        if int(stats["material_bytes"]) > max_material_bytes:
            raise InspectionLimitError(
                "INSPECTION_EVENT_AUDIT_BYTES_LIMIT_EXCEEDED",
                "event audit material exceeds the inspection byte limit",
            )

        ledger_rows = self.connection.execute(
            affected_cte
            + "SELECT el.* FROM event_ledger el JOIN affected a "
            "ON a.event_id = el.aggregate_id "
            "WHERE el.aggregate_type = 'narrative_event' ORDER BY el.sequence",
            (snapshot_id,),
        )
        ledger_entries = tuple(self._ledger_entry(row) for row in ledger_rows)
        evidence_rows = self.connection.execute(
            affected_cte
            + "SELECT eer.* FROM event_evidence_refs eer JOIN affected a "
            "ON a.event_id = eer.event_id "
            "ORDER BY eer.event_id, eer.snapshot_id, eer.start_line, "
            "eer.end_line, eer.evidence_id",
            (snapshot_id,),
        )
        evidence = tuple(self._event_evidence(row) for row in evidence_rows)
        return EventAuditMaterial(ledger_entries, evidence)


__all__ = [
    "ClaimAuthorityMaterial",
    "EventAuditMaterial",
    "ProvenanceRecord",
    "ReadOnlyProject",
    "SnapshotMetadata",
    "SourceAuditMaterial",
]
