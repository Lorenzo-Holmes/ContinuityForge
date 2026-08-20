"""SQLite persistence, migration, and append-only audit ledger.

The storage boundary enforces the invariants that do not require semantic
judgement: logical-source uniqueness, immutable snapshot revisions,
worldline-safe evidence references, explicit claim-state transitions, and a
database-wide SHA-256 EventLedger chain.  It uses only the Python standard
library and supports Python 3.10+.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import math
from pathlib import Path
import sqlite3
import threading
import unicodedata
from typing import Any, Iterable, Iterator, Mapping, Sequence
from uuid import uuid4

from .constants import SCHEMA_VERSION
from .evidence import validate_line_range_types
from .exceptions import (
    ContinuityViolation,
    InvalidTransitionError,
    LedgerIntegrityError,
    MigrationError,
    NotFoundError,
    ReadOnlyStorageError,
    SchemaError,
)
from .migrations import MigrationMode, MigrationReport, preflight_migration
from .ingest import parse_json_content
from .limits import (
    MAX_CLAIM_METADATA_UTF8_BYTES,
    MAX_CLAIM_RATIONALE_UTF8_BYTES,
    MAX_CLAIM_TEXT_UTF8_BYTES,
    MAX_EVENT_DETAILS_JSON_BYTES,
    MAX_EVENT_SUMMARY_UTF8_BYTES,
    MAX_EVENT_TITLE_UTF8_BYTES,
    validate_claim_fields,
    validate_event_fields,
)
from .models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceDecision,
    GovernanceStatus,
    LedgerEntry,
    MemoryCutoff,
    NarrativeEvent,
    Source,
    SourceSnapshot,
)
from .timeutil import isoformat_utc, validate_interval
from .schema import SchemaKind, fingerprint_schema, validate_schema
from .source_integrity import SourceAuditSnapshot, validate_source_audits
from .sqlite_safety import SQLiteSidecarError, validate_readonly_sidecars


GENESIS_HASH = "0" * 64
MAX_EVENT_DETAILS_DEPTH = 128
MAX_METADATA_UTF8_BYTES = 4096
_BIDI_CONTROL_CLASSES = frozenset({"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _identifier(name: str) -> str:
    """Quote an introspected SQLite identifier."""

    return '"' + name.replace('"', '""') + '"'


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return str(value)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def _strict_json_object(value: object) -> tuple[dict[str, Any], str]:
    """Validate and canonically encode one untrusted JSON object."""

    if not isinstance(value, Mapping):
        raise TypeError("event details must be a JSON object")
    pending: list[tuple[object, int]] = [(value, 1)]
    seen: set[int] = set()
    while pending:
        item, depth = pending.pop()
        if depth > MAX_EVENT_DETAILS_DEPTH:
            raise ValueError("event details exceed the JSON nesting limit")
        if isinstance(item, Mapping):
            marker = id(item)
            if marker in seen:
                raise ValueError("event details contain a cyclic/shared container")
            seen.add(marker)
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("event details object keys must be strings")
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            marker = id(item)
            if marker in seen:
                raise ValueError("event details contain a cyclic/shared container")
            seen.add(marker)
            pending.extend((child, depth + 1) for child in item)
        elif item is None or isinstance(item, (str, bool, int)):
            continue
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("event details contain a non-finite number")
            continue
        else:
            raise TypeError("event details contain a non-JSON value")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        size = len(encoded.encode("utf-8"))
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise ValueError("event details are not deterministic JSON") from exc
    if size > MAX_EVENT_DETAILS_JSON_BYTES:
        raise ValueError("event details exceed the JSON byte limit")
    decoded = parse_json_content(encoded)
    if not isinstance(decoded, dict):  # defensive: top-level Mapping encoded oddly
        raise TypeError("event details must encode a JSON object")
    return decoded, encoded


def _parse_json(value: str | None, *, fallback: object) -> object:
    if value is None:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _nonempty(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} must not be empty")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError(f"{name} contains invalid Unicode") from exc
    if size > MAX_METADATA_UTF8_BYTES:
        raise ValueError(f"{name} exceeds the metadata byte limit")
    if any(
        unicodedata.category(character) in {"Cc", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
        for character in text
    ):
        raise ValueError(f"{name} contains unsafe control characters")
    return text


def _normal_time(value: str | datetime | None) -> str | None:
    return isoformat_utc(value)


class Storage:
    """Transactional ContinuityForge repository backed by SQLite.

    Constructing the object initializes the database by default.  ``Storage``
    is also a context manager, and nested calls to :meth:`transaction` use
    savepoints so a service can compose several repository operations into one
    atomic unit.
    """

    schema_version = SCHEMA_VERSION

    _MANAGED_TABLES = {
        "schema_metadata",
        "sources",
        "source_snapshots",
        "claim_proposals",
        "claims",
        "evidence_refs",
        "governance_decisions",
        "narrative_events",
        "event_evidence_refs",
        "event_ledger",
        "legacy_records",
    }

    _ALLOWED_TRANSITIONS: Mapping[GovernanceStatus, frozenset[GovernanceStatus]] = {
        GovernanceStatus.PROPOSED: frozenset(
            {
                GovernanceStatus.AUTHORIZED,
                GovernanceStatus.REJECTED,
                GovernanceStatus.DISPUTED,
            }
        ),
        GovernanceStatus.AUTHORIZED: frozenset({GovernanceStatus.DISPUTED}),
        GovernanceStatus.REJECTED: frozenset({GovernanceStatus.DISPUTED}),
        GovernanceStatus.DISPUTED: frozenset(
            {GovernanceStatus.AUTHORIZED, GovernanceStatus.REJECTED}
        ),
    }

    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        initialize: bool = True,
        timeout: float = 30.0,
        readonly: bool = False,
        migration_mode: MigrationMode | str = MigrationMode.STRICT,
        create_backup: bool = True,
    ) -> None:
        self.database = str(database)
        self.timeout = timeout
        self.readonly = bool(readonly)
        self.migration_mode = MigrationMode(migration_mode)
        self.create_backup = bool(create_backup)
        self.migration_report: MigrationReport | None = None
        self._quarantined_legacy: set[tuple[str, str]] = set()
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._transaction_depth = 0
        if initialize:
            self.initialize()

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose the initialized connection for read-only integration work."""

        if self._connection is None:
            self.initialize()
        assert self._connection is not None
        return self._connection

    def initialize(self) -> "Storage":
        """Open v3, create it, or transactionally migrate a recognized layout."""

        with self._lock:
            if self._connection is not None:
                return self

            if (
                not self.readonly
                and self.database not in {":memory:", ""}
                and not self.database.startswith("file:")
            ):
                Path(self.database).expanduser().parent.mkdir(parents=True, exist_ok=True)

            database_argument = self.database
            uri = self.database.startswith("file:")
            if self.readonly:
                if self.database in {":memory:", ""}:
                    raise ReadOnlyStorageError("read-only storage requires a database path")
                if uri:
                    # Accepting caller-supplied SQLite URIs would let query
                    # parameters and alternate URI spellings bypass the stable
                    # local-path sidecar gate below.  The public read-only API
                    # therefore accepts filesystem paths only and constructs
                    # the sole supported ``mode=ro`` URI itself.
                    raise ReadOnlyStorageError(
                        "read-only storage requires a filesystem path, not a SQLite URI"
                    )
                path = Path(self.database).expanduser().resolve()
                try:
                    validate_readonly_sidecars(path)
                except SQLiteSidecarError as exc:
                    raise ReadOnlyStorageError(
                        f"read-only storage rejected an unsafe sidecar: {exc}"
                    ) from exc
                database_argument = path.as_uri() + "?mode=ro"
                uri = True
            connection = sqlite3.connect(
                database_argument,
                timeout=self.timeout,
                isolation_level=None,
                check_same_thread=False,
                uri=uri,
            )
            self._connection = connection
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA busy_timeout = 30000")
                if self.readonly:
                    connection.execute("PRAGMA query_only = ON")
                    query_only = connection.execute("PRAGMA query_only").fetchone()
                    if query_only is None or int(query_only[0]) != 1:
                        raise ReadOnlyStorageError(
                            "SQLite did not enable the read-only query barrier"
                        )
                source = fingerprint_schema(connection)
                if self.readonly:
                    if source.kind is not SchemaKind.V03:
                        raise ReadOnlyStorageError(
                            "read-only storage opens only a complete schema v3 database; "
                            f"found {source.kind.value}"
                        )
                    target = validate_schema(connection)
                    self.migration_report = MigrationReport(
                        mode=self.migration_mode,
                        source=source,
                        target=target,
                        status="already-current",
                        quick_check="ok",
                    )
                    return self

                if source.kind is SchemaKind.V03:
                    target = validate_schema(connection)
                    self.migration_report = MigrationReport(
                        mode=self.migration_mode,
                        source=source,
                        target=target,
                        status="already-current",
                        quick_check="ok",
                    )
                    return self

                if source.kind in {SchemaKind.UNKNOWN, SchemaKind.PARTIAL}:
                    report = preflight_migration(
                        connection,
                        mode=self.migration_mode,
                        create_backup=False,
                    )
                    self.migration_report = report
                    raise MigrationError(
                        "database failed the schema migration preflight",
                        report=report,
                    )

                # Hold a RESERVED lock across preflight, backup, and DDL.  A
                # second writer therefore cannot invalidate the inspected
                # fingerprint or make the backup differ from migrated input.
                connection.execute("BEGIN IMMEDIATE")
                locked_source = fingerprint_schema(connection)
                if locked_source.digest != source.digest:
                    report = MigrationReport(
                        mode=self.migration_mode,
                        source=locked_source,
                        status="failed",
                        quick_check="not-run",
                    )
                    self.migration_report = report
                    raise MigrationError(
                        "database changed while acquiring the migration lock",
                        report=report,
                    )
                report = preflight_migration(
                    connection,
                    mode=self.migration_mode,
                    create_backup=self.create_backup,
                )
                self.migration_report = report
                if not report.is_ready:
                    raise MigrationError(
                        "database failed the schema migration preflight",
                        report=report,
                    )

                self._quarantined_legacy = set(report.quarantined)
                self._initialize_or_migrate(connection, source.kind)
                # The target schema and audit chain are part of the migration
                # transaction's commit gate.  A post-COMMIT validation would
                # report failure after making the destructive phase durable.
                target = validate_schema(connection)
                if not self.verify_ledger():
                    raise LedgerIntegrityError(
                        "migrated EventLedger failed verification before commit"
                    )
                from .event_integrity import validate_event_audits
                from .governance_integrity import validate_claim_authorities
                from .evidence import EvidenceValidator

                claims = self.list_claim_proposals()
                events = self.list_narrative_events()
                source_reports = validate_source_audits(self)
                claim_reports = validate_claim_authorities(self, claims)
                event_reports = validate_event_audits(self, events)
                evidence_validator = EvidenceValidator(self)
                evidence_valid = all(
                    evidence_validator.validate_claim(
                        claim, self.get_claim_evidence(claim.claim_id)
                    ).is_valid
                    for claim in claims
                    if claim.status is GovernanceStatus.AUTHORIZED
                ) and all(
                    evidence_validator.validate_claim(
                        event, self.get_event_evidence(event.event_id)
                    ).is_valid
                    for event in events
                )
                if (
                    any(not report.is_valid for report in source_reports.values())
                    or any(not report.is_valid for report in claim_reports.values())
                    or any(not report.is_valid for report in event_reports.values())
                    or not evidence_valid
                ):
                    raise LedgerIntegrityError(
                        "migrated domain rows failed authority/audit replay before commit"
                    )
                count_tables = {
                    "sources": "sources",
                    "snapshots": "source_snapshots",
                    "claims": "claim_proposals",
                    "evidence": "evidence_refs",
                    "events": "narrative_events",
                    "event_evidence": "event_evidence_refs",
                    "decisions": "governance_decisions",
                    "ledger": "event_ledger",
                    "legacy_records": "legacy_records",
                }
                migrated_counts = tuple(
                    (
                        label,
                        int(
                            connection.execute(
                                f"SELECT COUNT(*) FROM {_identifier(table)}"
                            ).fetchone()[0]
                        ),
                    )
                    for label, table in count_tables.items()
                )
                connection.execute("COMMIT")
                self.migration_report = replace(
                    report,
                    status=(
                        "initialized"
                        if source.kind is SchemaKind.EMPTY
                        else "migrated"
                    ),
                    target=target,
                    migrated_counts=migrated_counts,
                    finished_at=_now(),
                )
            except BaseException as exc:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
                self._connection = None
                if isinstance(exc, (MigrationError, ReadOnlyStorageError, SchemaError)):
                    raise
                if self.migration_report is not None:
                    self.migration_report = replace(
                        self.migration_report,
                        status="failed",
                        finished_at=_now(),
                    )
                    raise MigrationError(
                        "schema migration transaction failed",
                        report=self.migration_report,
                    ) from exc
                raise
        return self

    @classmethod
    def open_readonly(
        cls, database: str | Path, *, timeout: float = 30.0
    ) -> "Storage":
        """Open an existing v3 database through SQLite ``mode=ro``.

        This entry point never creates a file, runs DDL, migrates, or changes a
        journal mode.
        """

        return cls(database, timeout=timeout, readonly=True)

    # Common spelling retained for callers that separate the words.
    open_read_only = open_readonly

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                self._connection.close()
                self._connection = None
                self._transaction_depth = 0

    def __enter__(self) -> "Storage":
        return self.initialize()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Open an immediate transaction, nesting safely through savepoints."""

        if self.readonly:
            raise ReadOnlyStorageError("read-only storage does not allow transactions")
        connection = self.connection
        with self._lock:
            depth = self._transaction_depth
            savepoint = f"continuityforge_sp_{depth}"
            if depth == 0:
                connection.execute("BEGIN IMMEDIATE")
            else:
                connection.execute(f"SAVEPOINT {_identifier(savepoint)}")
            self._transaction_depth += 1
            try:
                yield connection
            except BaseException:
                self._transaction_depth -= 1
                if depth == 0:
                    connection.execute("ROLLBACK")
                else:
                    connection.execute(f"ROLLBACK TO SAVEPOINT {_identifier(savepoint)}")
                    connection.execute(f"RELEASE SAVEPOINT {_identifier(savepoint)}")
                raise
            else:
                self._transaction_depth -= 1
                if depth == 0:
                    connection.execute("COMMIT")
                else:
                    connection.execute(f"RELEASE SAVEPOINT {_identifier(savepoint)}")

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Pin all reads in the context to one SQLite snapshot.

        The context is nestable and reuses an active write transaction.  It
        deliberately holds the per-storage re-entrant lock so another thread
        cannot interleave operations on the same SQLite connection.
        """

        connection = self.connection
        with self._lock:
            started = not connection.in_transaction
            if started:
                connection.execute("BEGIN")
            try:
                yield connection
            except BaseException:
                if started and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            else:
                if started and connection.in_transaction:
                    connection.execute("COMMIT")

    # ------------------------------------------------------------------
    # Schema creation and v0.1 migration
    # ------------------------------------------------------------------

    def get_schema_version(self) -> int:
        row = self.connection.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    def _initialize_or_migrate(
        self, connection: sqlite3.Connection, source_kind: SchemaKind
    ) -> None:
        """Apply one preflight-approved migration edge inside the caller transaction."""

        if source_kind is SchemaKind.V02:
            tables = self._table_names(connection)
            added_event_evidence = "event_evidence_refs" not in tables
            removed_hash_constraint = self._snapshot_hash_has_unique_constraint(connection)
            if removed_hash_constraint:
                retained_table = self._remove_snapshot_hash_unique_constraint(connection)
            else:
                retained_table = None
            self._create_schema_v2(connection)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            source_audit_entries = self._backfill_source_audit_ledger(connection)
            self._backfill_claim_authority_ledger(connection)
            self._backfill_event_audit_ledger(connection)
            if removed_hash_constraint:
                self._append_ledger_in_transaction(
                    connection,
                    event_type="schema.snapshot_hash_constraint_removed",
                    aggregate_type="schema",
                    aggregate_id=str(SCHEMA_VERSION),
                    payload={
                        "reason": "A -> B -> A must create a visible rollback revision",
                        "retained_legacy_table": retained_table,
                    },
                )
            if added_event_evidence:
                self._append_ledger_in_transaction(
                    connection,
                    event_type="schema.event_evidence_enabled",
                    aggregate_type="schema",
                    aggregate_id=str(SCHEMA_VERSION),
                    payload={
                        "table": "event_evidence_refs",
                        "invariant": "narrative event provenance is immutable",
                    },
                )
            self._append_ledger_in_transaction(
                connection,
                event_type="schema.migrated",
                aggregate_type="schema",
                aggregate_id=f"2->{SCHEMA_VERSION}",
                payload={
                    "from_schema_version": 2,
                    "to_schema_version": SCHEMA_VERSION,
                    "authority_ledger_backfill": True,
                    "source_audit_ledger_entries": source_audit_entries,
                },
            )
            self._install_v3_triggers(connection)
            return

        if source_kind is SchemaKind.EMPTY:
            self._create_schema_v2(connection)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._install_v3_triggers(connection)
            self._append_ledger_in_transaction(
                connection,
                event_type="schema.initialized",
                aggregate_type="schema",
                aggregate_id=str(SCHEMA_VERSION),
                payload={"schema_version": SCHEMA_VERSION},
            )
            return

        if source_kind is SchemaKind.V01:
            tables = self._table_names(connection)
            self._migrate_legacy_v1(connection, tables, 1)
            self._backfill_source_audit_ledger(connection)
            self._install_v3_triggers(connection)
            return

        if source_kind is SchemaKind.V03_ALPHA2:
            # Same-version hardening is deliberately structure-only.  Preflight
            # requires complete, matching Source audit material; this edge must
            # neither repair it nor append to/change the existing ledger head.
            self._install_v3_triggers(connection)
            return

        raise SchemaError(
            f"migration source is not admitted: {source_kind.value}"
        )

    @staticmethod
    def _table_names(connection: sqlite3.Connection) -> list[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [str(row[0]) for row in rows]

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        rows = connection.execute(f"PRAGMA table_info({_identifier(table)})").fetchall()
        return {str(row[1]) for row in rows}

    def _looks_like_v2(self, connection: sqlite3.Connection, tables: Sequence[str]) -> bool:
        required = {"sources", "source_snapshots", "claim_proposals", "event_ledger"}
        if not required.issubset(tables):
            return False
        return (
            {"source_id", "source_key", "continuity"}
            <= self._columns(connection, "sources")
            and {
                "snapshot_id",
                "source_id",
                "version",
                "content_hash",
                "previous_snapshot_id",
            }
            <= self._columns(connection, "source_snapshots")
            and {"claim_id", "status", "persona_id", "continuity", "confidence"}
            <= self._columns(connection, "claim_proposals")
            and {"sequence", "previous_hash", "entry_hash"}
            <= self._columns(connection, "event_ledger")
        )

    @staticmethod
    def _snapshot_hash_has_unique_constraint(connection: sqlite3.Connection) -> bool:
        """Detect the short-lived pre-release v2 `(source_id, hash)` constraint."""

        for index in connection.execute("PRAGMA index_list(source_snapshots)").fetchall():
            # PRAGMA index_list: seq, name, unique, origin, partial
            if not bool(index[2]):
                continue
            columns = [
                str(row[2])
                for row in connection.execute(
                    f"PRAGMA index_info({_identifier(str(index[1]))})"
                ).fetchall()
            ]
            if columns == ["source_id", "content_hash"]:
                return True
        return False

    def _unused_table_name(self, connection: sqlite3.Connection, base: str) -> str:
        occupied = set(self._table_names(connection))
        candidate = base
        suffix = 2
        while candidate in occupied:
            candidate = f"{base}_{suffix}"
            suffix += 1
        return candidate

    def _remove_snapshot_hash_unique_constraint(
        self, connection: sqlite3.Connection
    ) -> str:
        """Transactionally rebuild early v2 tables without losing references.

        SQLite cannot drop an auto-index created by a table-level UNIQUE
        constraint. The old snapshot table is therefore retained as an audit
        copy while active claim/event evidence is copied to tables referencing
        the rebuilt revision history.
        """

        snapshot_legacy = self._unused_table_name(
            connection, "legacy_v2_source_snapshots_hash_unique"
        )
        evidence_legacy = self._unused_table_name(
            connection, "legacy_v2_evidence_refs_hash_unique"
        )
        tables = set(self._table_names(connection))
        has_event_evidence = "event_evidence_refs" in tables
        event_evidence_legacy = self._unused_table_name(
            connection, "legacy_v2_event_evidence_refs_hash_unique"
        )

        for trigger in (
            "continuityforge_snapshots_no_update",
            "continuityforge_snapshots_no_delete",
            "continuityforge_evidence_no_update",
            "continuityforge_evidence_no_delete",
            "continuityforge_event_evidence_no_update",
            "continuityforge_event_evidence_no_delete",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {_identifier(trigger)}")
        for index in (
            "idx_snapshots_source_version",
            "idx_snapshots_source_content_hash",
            "idx_evidence_claim",
            "idx_evidence_snapshot",
            "idx_event_evidence_event",
            "idx_event_evidence_snapshot",
        ):
            connection.execute(f"DROP INDEX IF EXISTS {_identifier(index)}")

        connection.execute(
            f"ALTER TABLE source_snapshots RENAME TO {_identifier(snapshot_legacy)}"
        )
        connection.execute(
            f"ALTER TABLE evidence_refs RENAME TO {_identifier(evidence_legacy)}"
        )
        if has_event_evidence:
            connection.execute(
                "ALTER TABLE event_evidence_refs RENAME TO "
                + _identifier(event_evidence_legacy)
            )

        self._create_schema_v2(connection)
        snapshot_columns = (
            "snapshot_id, source_id, version, content_hash, content, media_type, "
            "origin_path, previous_snapshot_id, line_count, created_at"
        )
        connection.execute(
            f"INSERT INTO source_snapshots ({snapshot_columns}) "
            f"SELECT {snapshot_columns} FROM {_identifier(snapshot_legacy)}"
        )
        evidence_columns = (
            "evidence_id, claim_id, snapshot_id, start_line, end_line, start_char, "
            "end_char, quote, content_hash, created_at"
        )
        connection.execute(
            f"INSERT INTO evidence_refs ({evidence_columns}) "
            f"SELECT {evidence_columns} FROM {_identifier(evidence_legacy)}"
        )
        if has_event_evidence:
            event_columns = (
                "evidence_id, event_id, snapshot_id, start_line, end_line, start_char, "
                "end_char, quote, content_hash, created_at"
            )
            connection.execute(
                f"INSERT INTO event_evidence_refs ({event_columns}) "
                f"SELECT {event_columns} FROM {_identifier(event_evidence_legacy)}"
            )

        # Evidence copies have served their rollback purpose and have no
        # self-references. The snapshot audit copy remains intentionally.
        connection.execute(f"DROP TABLE {_identifier(evidence_legacy)}")
        if has_event_evidence:
            connection.execute(f"DROP TABLE {_identifier(event_evidence_legacy)}")
        return snapshot_legacy

    @staticmethod
    def _metadata_version(connection: sqlite3.Connection) -> int | None:
        try:
            row = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error:
            return None
        return int(row[0]) if row is not None else None

    @staticmethod
    def _execute_script_atomic(connection: sqlite3.Connection, script: str) -> None:
        """Execute a DDL script without ``executescript``'s implicit COMMIT.

        ``sqlite3.complete_statement`` understands trigger bodies, so each
        complete statement can remain inside the caller's migration
        transaction.
        """

        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                if statement.strip():
                    connection.execute(statement)
                statement = ""
        if statement.strip():
            raise SchemaError("incomplete SQL statement in v2 schema")

    def _create_schema_v2(self, connection: sqlite3.Connection) -> None:
        self._execute_script_atomic(
            connection,
            """
            CREATE TABLE IF NOT EXISTS schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                migrated_at TEXT NOT NULL,
                migration_notes TEXT
            );

            CREATE TABLE IF NOT EXISTS sources (
                source_id TEXT PRIMARY KEY,
                source_key TEXT NOT NULL,
                continuity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (source_key, continuity)
            );

            CREATE TABLE IF NOT EXISTS source_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
                version INTEGER NOT NULL CHECK (version >= 1),
                content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
                content TEXT NOT NULL,
                media_type TEXT NOT NULL,
                origin_path TEXT,
                previous_snapshot_id TEXT REFERENCES source_snapshots(snapshot_id) ON DELETE RESTRICT,
                line_count INTEGER NOT NULL CHECK (line_count >= 0),
                created_at TEXT NOT NULL,
                UNIQUE (source_id, version)
            );

            CREATE TABLE IF NOT EXISTS claim_proposals (
                claim_id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                continuity TEXT NOT NULL,
                text TEXT NOT NULL,
                subject TEXT,
                predicate TEXT,
                object_value TEXT,
                valid_from TEXT,
                valid_to TEXT,
                knowledge_from TEXT,
                knowledge_to TEXT,
                access_policy TEXT NOT NULL CHECK (
                    access_policy IN ('agent_accessible', 'human_only', 'hidden')
                ),
                confidence REAL NOT NULL DEFAULT 1.0 CHECK (
                    confidence >= 0.0 AND confidence <= 1.0
                ),
                status TEXT NOT NULL CHECK (
                    status IN ('PROPOSED', 'AUTHORIZED', 'REJECTED', 'DISPUTED')
                ),
                proposed_by TEXT,
                proposal_model TEXT,
                rationale TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_refs (
                evidence_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL REFERENCES claim_proposals(claim_id) ON DELETE RESTRICT,
                snapshot_id TEXT NOT NULL REFERENCES source_snapshots(snapshot_id) ON DELETE RESTRICT,
                start_line INTEGER NOT NULL CHECK (start_line >= 1),
                end_line INTEGER NOT NULL CHECK (end_line >= start_line),
                start_char INTEGER CHECK (start_char IS NULL OR start_char >= 0),
                end_char INTEGER CHECK (
                    end_char IS NULL OR (start_char IS NOT NULL AND end_char >= start_char)
                ),
                quote TEXT,
                content_hash TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (claim_id, snapshot_id, start_line, end_line, start_char, end_char)
            );

            CREATE TABLE IF NOT EXISTS governance_decisions (
                decision_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL REFERENCES claim_proposals(claim_id) ON DELETE RESTRICT,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                reason TEXT NOT NULL,
                decided_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS narrative_events (
                event_id TEXT PRIMARY KEY,
                persona_id TEXT NOT NULL,
                continuity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                valid_from TEXT,
                valid_to TEXT,
                knowledge_from TEXT,
                knowledge_to TEXT,
                access_policy TEXT NOT NULL CHECK (
                    access_policy IN ('agent_accessible', 'human_only', 'hidden')
                ),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS event_evidence_refs (
                evidence_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL REFERENCES narrative_events(event_id) ON DELETE RESTRICT,
                snapshot_id TEXT NOT NULL REFERENCES source_snapshots(snapshot_id) ON DELETE RESTRICT,
                start_line INTEGER NOT NULL CHECK (start_line >= 1),
                end_line INTEGER NOT NULL CHECK (end_line >= start_line),
                start_char INTEGER CHECK (start_char IS NULL OR start_char >= 0),
                end_char INTEGER CHECK (
                    end_char IS NULL OR (start_char IS NOT NULL AND end_char >= start_char)
                ),
                quote TEXT,
                content_hash TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (event_id, snapshot_id, start_line, end_line, start_char, end_char)
            );

            CREATE TABLE IF NOT EXISTS event_ledger (
                sequence INTEGER PRIMARY KEY,
                entry_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                aggregate_type TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS legacy_records (
                legacy_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_table TEXT NOT NULL,
                legacy_key TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                migrated_entity_type TEXT,
                migrated_entity_id TEXT,
                migrated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_source_version
                ON source_snapshots(source_id, version DESC);
            CREATE INDEX IF NOT EXISTS idx_snapshots_source_content_hash
                ON source_snapshots(source_id, content_hash);
            CREATE INDEX IF NOT EXISTS idx_claims_persona_continuity_status
                ON claim_proposals(persona_id, continuity, status);
            CREATE INDEX IF NOT EXISTS idx_claims_knowledge
                ON claim_proposals(knowledge_from, knowledge_to);
            CREATE INDEX IF NOT EXISTS idx_evidence_claim
                ON evidence_refs(claim_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_snapshot
                ON evidence_refs(snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_events_persona_continuity
                ON narrative_events(persona_id, continuity);
            CREATE INDEX IF NOT EXISTS idx_event_evidence_event
                ON event_evidence_refs(event_id);
            CREATE INDEX IF NOT EXISTS idx_event_evidence_snapshot
                ON event_evidence_refs(snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_ledger_aggregate
                ON event_ledger(aggregate_type, aggregate_id, sequence);

            DROP TRIGGER IF EXISTS continuityforge_snapshots_no_update;
            DROP TRIGGER IF EXISTS continuityforge_snapshots_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_evidence_no_update;
            DROP TRIGGER IF EXISTS continuityforge_evidence_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_decisions_no_update;
            DROP TRIGGER IF EXISTS continuityforge_decisions_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_event_evidence_no_update;
            DROP TRIGGER IF EXISTS continuityforge_event_evidence_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_ledger_no_update;
            DROP TRIGGER IF EXISTS continuityforge_ledger_no_delete;

            CREATE TRIGGER continuityforge_snapshots_no_update
            BEFORE UPDATE ON source_snapshots BEGIN
                SELECT RAISE(ABORT, 'SourceSnapshot rows are immutable');
            END;
            CREATE TRIGGER continuityforge_snapshots_no_delete
            BEFORE DELETE ON source_snapshots BEGIN
                SELECT RAISE(ABORT, 'SourceSnapshot rows are immutable');
            END;
            CREATE TRIGGER continuityforge_evidence_no_update
            BEFORE UPDATE ON evidence_refs BEGIN
                SELECT RAISE(ABORT, 'EvidenceRef rows are immutable');
            END;
            CREATE TRIGGER continuityforge_evidence_no_delete
            BEFORE DELETE ON evidence_refs BEGIN
                SELECT RAISE(ABORT, 'EvidenceRef rows are immutable');
            END;
            CREATE TRIGGER continuityforge_decisions_no_update
            BEFORE UPDATE ON governance_decisions BEGIN
                SELECT RAISE(ABORT, 'GovernanceDecision rows are immutable');
            END;
            CREATE TRIGGER continuityforge_decisions_no_delete
            BEFORE DELETE ON governance_decisions BEGIN
                SELECT RAISE(ABORT, 'GovernanceDecision rows are immutable');
            END;
            CREATE TRIGGER continuityforge_event_evidence_no_update
            BEFORE UPDATE ON event_evidence_refs BEGIN
                SELECT RAISE(ABORT, 'NarrativeEvent EvidenceRef rows are immutable');
            END;
            CREATE TRIGGER continuityforge_event_evidence_no_delete
            BEFORE DELETE ON event_evidence_refs BEGIN
                SELECT RAISE(ABORT, 'NarrativeEvent EvidenceRef rows are immutable');
            END;
            CREATE TRIGGER continuityforge_ledger_no_update
            BEFORE UPDATE ON event_ledger BEGIN
                SELECT RAISE(ABORT, 'EventLedger is append-only');
            END;
            CREATE TRIGGER continuityforge_ledger_no_delete
            BEFORE DELETE ON event_ledger BEGIN
                SELECT RAISE(ABORT, 'EventLedger is append-only');
            END;
            """,
        )
        timestamp = _now()
        connection.execute(
            "INSERT OR IGNORE INTO schema_metadata "
            "(singleton, schema_version, migrated_at, migration_notes) VALUES (1, ?, ?, ?)",
            (SCHEMA_VERSION, timestamp, "ContinuityForge v0.3 schema"),
        )
        existing = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if existing is None or int(existing[0]) > SCHEMA_VERSION:
            raise SchemaError("invalid schema_metadata row")
        if int(existing[0]) < SCHEMA_VERSION:
            connection.execute(
                "UPDATE schema_metadata SET schema_version = ?, migrated_at = ?, "
                "migration_notes = ? WHERE singleton = 1",
                (SCHEMA_VERSION, timestamp, "Migrated to ContinuityForge v0.3"),
            )

    def _install_v3_triggers(self, connection: sqlite3.Connection) -> None:
        """Install v3's application-integrity and immutability boundary.

        This method is called only while creating or migrating a database.
        Opening an already-current database performs no DDL.
        """

        self._execute_script_atomic(
            connection,
            f"""
            DROP TRIGGER IF EXISTS continuityforge_claims_insert_proposed;
            DROP TRIGGER IF EXISTS continuityforge_claims_fields_immutable;
            DROP TRIGGER IF EXISTS continuityforge_claims_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_claims_status_transition;
            DROP TRIGGER IF EXISTS continuityforge_evidence_reviewable_insert;
            DROP TRIGGER IF EXISTS continuityforge_decision_transition_insert;
            DROP TRIGGER IF EXISTS continuityforge_events_no_update;
            DROP TRIGGER IF EXISTS continuityforge_events_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_snapshot_lineage_insert;
            DROP TRIGGER IF EXISTS continuityforge_evidence_continuity_insert;
            DROP TRIGGER IF EXISTS continuityforge_event_evidence_continuity_insert;
            DROP TRIGGER IF EXISTS continuityforge_sources_identity_immutable;
            DROP TRIGGER IF EXISTS continuityforge_sources_updated_at_guard;
            DROP TRIGGER IF EXISTS continuityforge_sources_no_delete;
            DROP TRIGGER IF EXISTS continuityforge_claims_input_limits;
            DROP TRIGGER IF EXISTS continuityforge_events_input_limits;

            CREATE TRIGGER continuityforge_sources_identity_immutable
            BEFORE UPDATE ON sources
            WHEN OLD.source_id IS NOT NEW.source_id
              OR OLD.source_key IS NOT NEW.source_key
              OR OLD.continuity IS NOT NEW.continuity
              OR OLD.created_at IS NOT NEW.created_at
            BEGIN
                SELECT RAISE(ABORT, 'Source identity is immutable');
            END;

            CREATE TRIGGER continuityforge_sources_updated_at_guard
            BEFORE UPDATE OF updated_at ON sources
            WHEN OLD.updated_at IS NOT NEW.updated_at
              AND NEW.updated_at IS NOT (
                  SELECT ss.created_at
                  FROM source_snapshots ss
                  WHERE ss.source_id = OLD.source_id
                  ORDER BY ss.version DESC
                  LIMIT 1
              )
            BEGIN
                SELECT RAISE(ABORT, 'Source updated_at must equal latest SourceSnapshot created_at');
            END;

            CREATE TRIGGER continuityforge_sources_no_delete
            BEFORE DELETE ON sources BEGIN
                SELECT RAISE(ABORT, 'Source rows cannot be deleted');
            END;

            CREATE TRIGGER continuityforge_claims_input_limits
            BEFORE INSERT ON claim_proposals
            BEGIN
                SELECT CASE
                    WHEN length(CAST(NEW.text AS BLOB)) > {MAX_CLAIM_TEXT_UTF8_BYTES}
                    THEN RAISE(ABORT, 'CLAIM_TEXT_BYTES_LIMIT')
                END;
                SELECT CASE
                    WHEN length(CAST(COALESCE(NEW.rationale, '') AS BLOB)) > {MAX_CLAIM_RATIONALE_UTF8_BYTES}
                    THEN RAISE(ABORT, 'CLAIM_RATIONALE_BYTES_LIMIT')
                END;
                SELECT CASE
                    WHEN length(CAST(COALESCE(NEW.subject, '') AS BLOB)) > {MAX_CLAIM_METADATA_UTF8_BYTES}
                      OR length(CAST(COALESCE(NEW.predicate, '') AS BLOB)) > {MAX_CLAIM_METADATA_UTF8_BYTES}
                      OR length(CAST(COALESCE(NEW.object_value, '') AS BLOB)) > {MAX_CLAIM_METADATA_UTF8_BYTES}
                      OR length(CAST(COALESCE(NEW.proposed_by, '') AS BLOB)) > {MAX_CLAIM_METADATA_UTF8_BYTES}
                      OR length(CAST(COALESCE(NEW.proposal_model, '') AS BLOB)) > {MAX_CLAIM_METADATA_UTF8_BYTES}
                    THEN RAISE(ABORT, 'CLAIM_METADATA_BYTES_LIMIT')
                END;
            END;

            CREATE TRIGGER continuityforge_events_input_limits
            BEFORE INSERT ON narrative_events
            BEGIN
                SELECT CASE
                    WHEN length(CAST(NEW.title AS BLOB)) > {MAX_EVENT_TITLE_UTF8_BYTES}
                    THEN RAISE(ABORT, 'EVENT_TITLE_BYTES_LIMIT')
                END;
                SELECT CASE
                    WHEN length(CAST(NEW.summary AS BLOB)) > {MAX_EVENT_SUMMARY_UTF8_BYTES}
                    THEN RAISE(ABORT, 'EVENT_SUMMARY_BYTES_LIMIT')
                END;
                SELECT CASE
                    WHEN length(CAST(NEW.details_json AS BLOB)) > {MAX_EVENT_DETAILS_JSON_BYTES}
                    THEN RAISE(ABORT, 'EVENT_DETAILS_INVALID')
                END;
            END;

            CREATE TRIGGER continuityforge_claims_insert_proposed
            BEFORE INSERT ON claim_proposals
            WHEN NEW.status <> 'PROPOSED'
            BEGIN
                SELECT RAISE(ABORT, 'ClaimProposal rows must begin as PROPOSED');
            END;

            CREATE TRIGGER continuityforge_claims_fields_immutable
            BEFORE UPDATE ON claim_proposals
            WHEN OLD.claim_id IS NOT NEW.claim_id
              OR OLD.persona_id IS NOT NEW.persona_id
              OR OLD.continuity IS NOT NEW.continuity
              OR OLD.text IS NOT NEW.text
              OR OLD.subject IS NOT NEW.subject
              OR OLD.predicate IS NOT NEW.predicate
              OR OLD.object_value IS NOT NEW.object_value
              OR OLD.valid_from IS NOT NEW.valid_from
              OR OLD.valid_to IS NOT NEW.valid_to
              OR OLD.knowledge_from IS NOT NEW.knowledge_from
              OR OLD.knowledge_to IS NOT NEW.knowledge_to
              OR OLD.access_policy IS NOT NEW.access_policy
              OR OLD.confidence IS NOT NEW.confidence
              OR OLD.proposed_by IS NOT NEW.proposed_by
              OR OLD.proposal_model IS NOT NEW.proposal_model
              OR OLD.rationale IS NOT NEW.rationale
              OR OLD.created_at IS NOT NEW.created_at
            BEGIN
                SELECT RAISE(ABORT, 'ClaimProposal content is immutable');
            END;

            CREATE TRIGGER continuityforge_claims_no_delete
            BEFORE DELETE ON claim_proposals BEGIN
                SELECT RAISE(ABORT, 'ClaimProposal rows cannot be deleted');
            END;

            CREATE TRIGGER continuityforge_claims_status_transition
            BEFORE UPDATE OF status, updated_at ON claim_proposals
            WHEN OLD.status IS NOT NEW.status OR OLD.updated_at IS NOT NEW.updated_at
            BEGIN
                SELECT CASE
                    WHEN OLD.status = NEW.status
                    THEN RAISE(ABORT, 'updated_at changes require a governance transition')
                END;
                SELECT CASE
                    WHEN NOT (
                        (OLD.status = 'PROPOSED' AND NEW.status IN ('AUTHORIZED', 'REJECTED', 'DISPUTED'))
                        OR (OLD.status = 'AUTHORIZED' AND NEW.status = 'DISPUTED')
                        OR (OLD.status = 'REJECTED' AND NEW.status = 'DISPUTED')
                        OR (OLD.status = 'DISPUTED' AND NEW.status IN ('AUTHORIZED', 'REJECTED'))
                    )
                    THEN RAISE(ABORT, 'invalid ClaimProposal governance transition')
                END;
                SELECT CASE
                    WHEN NOT EXISTS (
                        SELECT 1 FROM governance_decisions gd
                        WHERE gd.claim_id = OLD.claim_id
                          AND gd.from_status = OLD.status
                          AND gd.to_status = NEW.status
                          AND gd.decided_at = NEW.updated_at
                    )
                    THEN RAISE(ABORT, 'ClaimProposal status requires GovernanceDecision')
                END;
            END;

            CREATE TRIGGER continuityforge_evidence_reviewable_insert
            BEFORE INSERT ON evidence_refs
            WHEN COALESCE(
                (SELECT status FROM claim_proposals WHERE claim_id = NEW.claim_id),
                ''
            ) NOT IN ('PROPOSED', 'DISPUTED')
            BEGIN
                SELECT RAISE(ABORT, 'evidence can be appended only while a claim is reviewable');
            END;

            CREATE TRIGGER continuityforge_decision_transition_insert
            BEFORE INSERT ON governance_decisions
            BEGIN
                SELECT CASE
                    WHEN NEW.from_status <> COALESCE(
                        (SELECT status FROM claim_proposals WHERE claim_id = NEW.claim_id),
                        ''
                    )
                    THEN RAISE(ABORT, 'GovernanceDecision from_status differs from claim status')
                END;
                SELECT CASE
                    WHEN NOT (
                        (NEW.from_status = 'PROPOSED' AND NEW.to_status IN ('AUTHORIZED', 'REJECTED', 'DISPUTED'))
                        OR (NEW.from_status = 'AUTHORIZED' AND NEW.to_status = 'DISPUTED')
                        OR (NEW.from_status = 'REJECTED' AND NEW.to_status = 'DISPUTED')
                        OR (NEW.from_status = 'DISPUTED' AND NEW.to_status IN ('AUTHORIZED', 'REJECTED'))
                    )
                    THEN RAISE(ABORT, 'invalid GovernanceDecision transition')
                END;
                SELECT CASE
                    WHEN length(trim(NEW.reviewer)) = 0 OR length(trim(NEW.reason)) = 0
                    THEN RAISE(ABORT, 'GovernanceDecision attribution is required')
                END;
            END;

            CREATE TRIGGER continuityforge_events_no_update
            BEFORE UPDATE ON narrative_events BEGIN
                SELECT RAISE(ABORT, 'NarrativeEvent rows are immutable');
            END;
            CREATE TRIGGER continuityforge_events_no_delete
            BEFORE DELETE ON narrative_events BEGIN
                SELECT RAISE(ABORT, 'NarrativeEvent rows are immutable');
            END;

            CREATE TRIGGER continuityforge_snapshot_lineage_insert
            BEFORE INSERT ON source_snapshots
            BEGIN
                SELECT CASE
                    WHEN NEW.version = 1 AND NEW.previous_snapshot_id IS NOT NULL
                    THEN RAISE(ABORT, 'first SourceSnapshot cannot have a predecessor')
                END;
                SELECT CASE
                    WHEN NEW.version > 1 AND NOT EXISTS (
                        SELECT 1 FROM source_snapshots previous
                        WHERE previous.snapshot_id = NEW.previous_snapshot_id
                          AND previous.source_id = NEW.source_id
                          AND previous.version = NEW.version - 1
                    )
                    THEN RAISE(ABORT, 'SourceSnapshot predecessor must be the prior source version')
                END;
            END;

            CREATE TRIGGER continuityforge_evidence_continuity_insert
            BEFORE INSERT ON evidence_refs
            WHEN NOT EXISTS (
                SELECT 1
                FROM claim_proposals cp
                JOIN source_snapshots ss ON ss.snapshot_id = NEW.snapshot_id
                JOIN sources s ON s.source_id = ss.source_id
                WHERE cp.claim_id = NEW.claim_id
                  AND cp.continuity = s.continuity
            )
            BEGIN
                SELECT RAISE(ABORT, 'EvidenceRef crosses a continuity boundary');
            END;

            CREATE TRIGGER continuityforge_event_evidence_continuity_insert
            BEFORE INSERT ON event_evidence_refs
            WHEN NOT EXISTS (
                SELECT 1
                FROM narrative_events ne
                JOIN source_snapshots ss ON ss.snapshot_id = NEW.snapshot_id
                JOIN sources s ON s.source_id = ss.source_id
                WHERE ne.event_id = NEW.event_id
                  AND ne.continuity = s.continuity
            )
            BEGIN
                SELECT RAISE(ABORT, 'NarrativeEvent evidence crosses a continuity boundary');
            END;
            """,
        )

    def _backfill_claim_authority_ledger(
        self, connection: sqlite3.Connection
    ) -> int:
        """Backfill the all-or-nothing authority stream omitted by old migration.

        Normal v0.2 claims already have complete streams and remain untouched.
        Preflight rejects partially present streams, so an empty stream is the
        only backfill case admitted here.
        """

        count = 0
        claims = connection.execute(
            "SELECT * FROM claim_proposals ORDER BY created_at, claim_id"
        ).fetchall()
        for claim in claims:
            claim_id = str(claim["claim_id"])
            existing = connection.execute(
                "SELECT COUNT(*) FROM event_ledger WHERE aggregate_type = 'claim' "
                "AND aggregate_id = ? AND event_type IN "
                "('claim.proposed', 'claim.governance_decided')",
                (claim_id,),
            ).fetchone()
            if existing and int(existing[0]):
                continue
            evidence_rows = connection.execute(
                "SELECT evidence_id FROM evidence_refs WHERE claim_id = ? "
                "ORDER BY snapshot_id, start_line, end_line, evidence_id",
                (claim_id,),
            ).fetchall()
            self._append_ledger_in_transaction(
                connection,
                event_type="claim.proposed",
                aggregate_type="claim",
                aggregate_id=claim_id,
                payload={
                    "persona_id": str(claim["persona_id"]),
                    "continuity": str(claim["continuity"]),
                    "text": str(claim["text"]),
                    "access_policy": str(claim["access_policy"]),
                    "confidence": float(claim["confidence"]),
                    "evidence_ids": [str(row[0]) for row in evidence_rows],
                },
                created_at=str(claim["created_at"]),
            )
            count += 1
            decisions = connection.execute(
                "SELECT rowid, * FROM governance_decisions WHERE claim_id = ? "
                "ORDER BY rowid",
                (claim_id,),
            ).fetchall()
            for decision in decisions:
                self._append_ledger_in_transaction(
                    connection,
                    event_type="claim.governance_decided",
                    aggregate_type="claim",
                    aggregate_id=claim_id,
                    payload={
                        "decision_id": str(decision["decision_id"]),
                        "from_status": str(decision["from_status"]),
                        "to_status": str(decision["to_status"]),
                        "reviewer": str(decision["reviewer"]),
                        "reason": str(decision["reason"]),
                    },
                    created_at=str(decision["decided_at"]),
                )
                count += 1
        return count

    def _backfill_event_audit_ledger(self, connection: sqlite3.Connection) -> int:
        """Backfill only a wholly absent legacy NarrativeEvent audit stream."""

        count = 0
        events = connection.execute(
            "SELECT * FROM narrative_events ORDER BY created_at, event_id"
        ).fetchall()
        tables = set(self._table_names(connection))
        for event in events:
            event_id = str(event["event_id"])
            existing = connection.execute(
                "SELECT COUNT(*) FROM event_ledger WHERE aggregate_type = 'narrative_event' "
                "AND aggregate_id = ?", (event_id,)
            ).fetchone()
            if existing and int(existing[0]):
                continue
            evidence_rows = (
                connection.execute(
                    "SELECT * FROM event_evidence_refs WHERE event_id = ? "
                    "ORDER BY snapshot_id, start_line, end_line, evidence_id",
                    (event_id,),
                ).fetchall()
                if "event_evidence_refs" in tables
                else []
            )
            evidence_refs = [
                {
                    "evidence_id": str(row["evidence_id"]),
                    "snapshot_id": str(row["snapshot_id"]),
                    "start_line": int(row["start_line"]),
                    "end_line": int(row["end_line"]),
                    "content_hash": row["content_hash"],
                }
                for row in evidence_rows
            ]
            self._append_ledger_in_transaction(
                connection,
                event_type="narrative_event.created",
                aggregate_type="narrative_event",
                aggregate_id=event_id,
                payload={
                    "persona_id": str(event["persona_id"]),
                    "continuity": str(event["continuity"]),
                    "event_type": str(event["event_type"]),
                    "valid_from": event["valid_from"],
                    "knowledge_from": event["knowledge_from"],
                    "access_policy": str(event["access_policy"]),
                    "evidence_ids": [item["evidence_id"] for item in evidence_refs],
                    "evidence_refs": evidence_refs,
                },
                created_at=str(event["created_at"]),
            )
            count += 1
        return count

    def _backfill_source_audit_ledger(self, connection: sqlite3.Connection) -> int:
        """Backfill only legacy-eligible gaps in Source creation correspondence.

        A normal Source stream is already complete and remains untouched.  A
        wholly absent stream (the historical legacy shape) can be reconstructed
        deterministically from immutable rows.  Every partial shape fails
        closed instead of mixing reconstructed history with extant audit data.
        """

        count = 0
        sources = connection.execute(
            "SELECT * FROM sources ORDER BY created_at, source_id"
        ).fetchall()
        for source in sources:
            source_id = str(source["source_id"])
            snapshots = connection.execute(
                "SELECT * FROM source_snapshots WHERE source_id = ? "
                "ORDER BY version, snapshot_id",
                (source_id,),
            ).fetchall()
            source_entries = connection.execute(
                "SELECT * FROM event_ledger WHERE event_type = 'source.created' "
                "AND aggregate_type = 'source' AND aggregate_id = ? ORDER BY sequence",
                (source_id,),
            ).fetchall()
            if len(source_entries) > 1:
                raise LedgerIntegrityError(
                    f"Source {source_id} has duplicate source.created entries"
                )
            snapshot_entries = connection.execute(
                "SELECT * FROM event_ledger WHERE event_type = 'source_snapshot.created' "
                "AND aggregate_type = 'source_snapshot' AND aggregate_id IN "
                "(SELECT snapshot_id FROM source_snapshots WHERE source_id = ?) "
                "ORDER BY sequence",
                (source_id,),
            ).fetchall()
            by_snapshot: dict[str, list[sqlite3.Row]] = {}
            for entry in snapshot_entries:
                by_snapshot.setdefault(str(entry["aggregate_id"]), []).append(entry)
            if any(len(items) != 1 for items in by_snapshot.values()):
                raise LedgerIntegrityError(
                    f"Source {source_id} has duplicate SourceSnapshot audit entries"
                )

            missing = [
                snapshot
                for snapshot in snapshots
                if str(snapshot["snapshot_id"]) not in by_snapshot
            ]
            if (source_entries and missing) or (not source_entries and by_snapshot):
                raise LedgerIntegrityError(
                    f"Source {source_id} has a partial Source audit stream"
                )

            if not source_entries:
                self._append_ledger_in_transaction(
                    connection,
                    event_type="source.created",
                    aggregate_type="source",
                    aggregate_id=source_id,
                    payload={
                        "source_key": str(source["source_key"]),
                        "continuity": str(source["continuity"]),
                        "audit_backfill": True,
                    },
                    created_at=str(source["created_at"]),
                )
                count += 1

            for snapshot in missing:
                self._append_ledger_in_transaction(
                    connection,
                    event_type="source_snapshot.created",
                    aggregate_type="source_snapshot",
                    aggregate_id=str(snapshot["snapshot_id"]),
                    payload={
                        "source_id": source_id,
                        "source_key": str(source["source_key"]),
                        "continuity": str(source["continuity"]),
                        "version": int(snapshot["version"]),
                        "content_hash": str(snapshot["content_hash"]),
                        "previous_snapshot_id": snapshot["previous_snapshot_id"],
                        "media_type": str(snapshot["media_type"]),
                        "origin_path": snapshot["origin_path"],
                        "line_count": int(snapshot["line_count"]),
                        "audit_backfill": True,
                    },
                    created_at=str(snapshot["created_at"]),
                )
                count += 1
        return count

    def _migrate_legacy_v1(
        self,
        connection: sqlite3.Connection,
        tables: Sequence[str],
        pragma_version: int,
    ) -> None:
        """Copy a permissive v0.1 layout into v2 without deleting old columns.

        Every old table is renamed and retained verbatim.  Every row is also
        serialized into ``legacy_records`` so unknown v0.1 columns remain
        queryable even when they have no v0.2 analogue.
        """

        renamed: dict[str, str] = {}
        occupied = set(tables)
        for original in tables:
            base = f"legacy_v1_{original}"
            candidate = base
            suffix = 2
            while candidate in occupied:
                candidate = f"{base}_{suffix}"
                suffix += 1
            connection.execute(
                f"ALTER TABLE {_identifier(original)} RENAME TO {_identifier(candidate)}"
            )
            occupied.add(candidate)
            renamed[original] = candidate

        self._create_schema_v2(connection)

        legacy_rows: dict[str, list[dict[str, Any]]] = {}
        for original, table in renamed.items():
            rows = connection.execute(f"SELECT * FROM {_identifier(table)}").fetchall()
            legacy_rows[original] = [dict(row) for row in rows]

        mapped: dict[tuple[str, int], tuple[str, str]] = {}
        source_id_map = self._migrate_legacy_sources(connection, legacy_rows, mapped)
        snapshot_id_map = self._migrate_legacy_snapshots(
            connection, legacy_rows, source_id_map, mapped
        )
        claim_id_map = self._migrate_legacy_claims(
            connection, legacy_rows, snapshot_id_map, mapped
        )
        self._migrate_legacy_evidence(
            connection, legacy_rows, claim_id_map, snapshot_id_map, mapped
        )
        self._migrate_legacy_events(connection, legacy_rows, mapped)
        authority_entries = self._backfill_claim_authority_ledger(connection)

        migrated_at = _now()
        row_total = 0
        for original, rows in legacy_rows.items():
            for index, row in enumerate(rows):
                row_total += 1
                entity = mapped.get((original, index))
                legacy_key = self._legacy_key(row, index)
                connection.execute(
                    "INSERT INTO legacy_records "
                    "(original_table, legacy_key, payload_json, migrated_entity_type, "
                    "migrated_entity_id, migrated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        original,
                        legacy_key,
                        _canonical_json(row),
                        entity[0] if entity else None,
                        entity[1] if entity else None,
                        migrated_at,
                    ),
                )

        connection.execute(
            "UPDATE schema_metadata SET schema_version = ?, migrated_at = ?, "
            "migration_notes = ? WHERE singleton = 1",
            (
                SCHEMA_VERSION,
                migrated_at,
                f"Transactional v0.1 migration; retained tables: {sorted(renamed.values())}",
            ),
        )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._append_ledger_in_transaction(
            connection,
            event_type="schema.migrated",
            aggregate_type="schema",
            aggregate_id=f"{pragma_version}->{SCHEMA_VERSION}",
            payload={
                "from_user_version": pragma_version,
                "to_schema_version": SCHEMA_VERSION,
                "legacy_tables": renamed,
                "legacy_row_count": row_total,
                "migrated_sources": len(source_id_map),
                "migrated_snapshots": len(snapshot_id_map),
                "migrated_claims": len(claim_id_map),
                "authority_ledger_entries": authority_entries,
            },
            created_at=migrated_at,
        )

    @staticmethod
    def _first(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
        lowered = {str(key).lower(): value for key, value in row.items()}
        for name in names:
            value = lowered.get(name.lower())
            if value is not None and value != "":
                return value
        return default

    @classmethod
    def _legacy_key(cls, row: Mapping[str, Any], index: int) -> str:
        value = cls._first(
            row,
            "id",
            "source_id",
            "snapshot_id",
            "claim_id",
            "evidence_id",
            "event_id",
            default=index,
        )
        return str(value)

    def _legacy_is_quarantined(
        self, table: str, row: Mapping[str, Any], index: int
    ) -> bool:
        return (table, self._legacy_key(row, index)) in self._quarantined_legacy

    @staticmethod
    def _stable_id(prefix: str, *parts: object) -> str:
        digest = sha256("\x1f".join(map(str, parts)).encode("utf-8")).hexdigest()[:24]
        return f"{prefix}_{digest}"

    @staticmethod
    def _legacy_time(value: object, *, fallback: str | None = None) -> str | None:
        if value is None or value == "":
            return fallback
        try:
            return isoformat_utc(str(value))
        except (TypeError, ValueError):
            return fallback

    @staticmethod
    def _legacy_access(value: object) -> AccessPolicy:
        if value is None:
            return AccessPolicy.AGENT_ACCESSIBLE
        aliases = {
            "agent": AccessPolicy.AGENT_ACCESSIBLE,
            "accessible": AccessPolicy.AGENT_ACCESSIBLE,
            "public": AccessPolicy.AGENT_ACCESSIBLE,
            "human": AccessPolicy.HUMAN_ONLY,
            "private": AccessPolicy.HUMAN_ONLY,
            "none": AccessPolicy.HIDDEN,
        }
        text = str(value).strip().lower().replace("-", "_")
        try:
            return AccessPolicy(text)
        except ValueError:
            return aliases.get(text, AccessPolicy.HIDDEN)

    @staticmethod
    def _legacy_status(value: object) -> GovernanceStatus:
        if value is None or value == "":
            # v0.1 claims were authoritative records rather than proposals.
            return GovernanceStatus.AUTHORIZED
        aliases = {
            "accepted": GovernanceStatus.AUTHORIZED,
            "approved": GovernanceStatus.AUTHORIZED,
            "active": GovernanceStatus.AUTHORIZED,
            "denied": GovernanceStatus.REJECTED,
            "invalid": GovernanceStatus.REJECTED,
            "pending": GovernanceStatus.PROPOSED,
            "conflicted": GovernanceStatus.DISPUTED,
        }
        text = str(value).strip()
        try:
            return GovernanceStatus(text)
        except ValueError:
            return aliases.get(text.lower(), GovernanceStatus.DISPUTED)

    def _migrate_legacy_sources(
        self,
        connection: sqlite3.Connection,
        legacy_rows: Mapping[str, list[dict[str, Any]]],
        mapped: dict[tuple[str, int], tuple[str, str]],
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        for table_name in ("sources", "source"):
            for index, row in enumerate(legacy_rows.get(table_name, [])):
                old_id = str(self._first(row, "source_id", "id", default=f"{table_name}:{index}"))
                source_key = str(
                    self._first(
                        row,
                        "source_key",
                        "key",
                        "path",
                        "origin_path",
                        "uri",
                        "name",
                        default=old_id,
                    )
                )
                continuity = str(
                    self._first(row, "continuity", "worldline", "timeline", default="default")
                )
                timestamp = self._legacy_time(
                    self._first(row, "created_at", "ingested_at"), fallback=_now()
                ) or _now()
                existing = connection.execute(
                    "SELECT source_id FROM sources WHERE source_key = ? AND continuity = ?",
                    (source_key, continuity),
                ).fetchone()
                if existing:
                    new_id = str(existing[0])
                else:
                    desired = old_id or self._stable_id("src", source_key, continuity)
                    collision = connection.execute(
                        "SELECT 1 FROM sources WHERE source_id = ?", (desired,)
                    ).fetchone()
                    new_id = (
                        self._stable_id("src", source_key, continuity)
                        if collision
                        else desired
                    )
                    connection.execute(
                        "INSERT INTO sources "
                        "(source_id, source_key, continuity, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (new_id, source_key, continuity, timestamp, timestamp),
                    )
                result[old_id] = new_id
                mapped[(table_name, index)] = ("source", new_id)
        return result

    def _migrate_legacy_snapshots(
        self,
        connection: sqlite3.Connection,
        legacy_rows: Mapping[str, list[dict[str, Any]]],
        source_id_map: dict[str, str],
        mapped: dict[tuple[str, int], tuple[str, str]],
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        candidates: list[tuple[str, int, dict[str, Any]]] = []
        for table_name in ("source_snapshots", "snapshots"):
            candidates.extend(
                (table_name, index, row)
                for index, row in enumerate(legacy_rows.get(table_name, []))
            )
        candidates.sort(
            key=lambda item: (
                str(self._first(item[2], "source_id", "source_key", "path", default="")),
                int(self._first(item[2], "version", "revision", default=0) or 0),
                str(self._first(item[2], "created_at", "ingested_at", default="")),
                item[1],
            )
        )

        for table_name, index, row in candidates:
            if self._legacy_is_quarantined(table_name, row, index):
                continue
            old_snapshot_id = str(
                self._first(row, "snapshot_id", "id", default=f"{table_name}:{index}")
            )
            old_source_id = str(self._first(row, "source_id", default=""))
            continuity = str(
                self._first(row, "continuity", "worldline", "timeline", default="default")
            )
            source_key = str(
                self._first(
                    row,
                    "source_key",
                    "path",
                    "origin_path",
                    "uri",
                    "name",
                    default=old_source_id or old_snapshot_id,
                )
            )
            source_id = source_id_map.get(old_source_id)
            if source_id is None:
                existing = connection.execute(
                    "SELECT source_id FROM sources WHERE source_key = ? AND continuity = ?",
                    (source_key, continuity),
                ).fetchone()
                if existing:
                    source_id = str(existing[0])
                else:
                    desired = old_source_id or self._stable_id("src", source_key, continuity)
                    if connection.execute(
                        "SELECT 1 FROM sources WHERE source_id = ?", (desired,)
                    ).fetchone():
                        desired = self._stable_id("src", source_key, continuity, index)
                    timestamp = self._legacy_time(
                        self._first(row, "created_at", "ingested_at"), fallback=_now()
                    ) or _now()
                    connection.execute(
                        "INSERT INTO sources "
                        "(source_id, source_key, continuity, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (desired, source_key, continuity, timestamp, timestamp),
                    )
                    source_id = desired
                if old_source_id:
                    source_id_map[old_source_id] = source_id

            raw_content = self._first(row, "content", "text", "raw_text", "body", default="")
            if isinstance(raw_content, bytes):
                content = raw_content.decode("utf-8", errors="replace")
            else:
                content = str(raw_content)
            content_hash = sha256(content.encode("utf-8")).hexdigest()
            latest = connection.execute(
                "SELECT snapshot_id, version, content_hash FROM source_snapshots "
                "WHERE source_id = ? ORDER BY version DESC LIMIT 1",
                (source_id,),
            ).fetchone()
            if latest and str(latest["content_hash"]) == content_hash:
                # Repeated adjacent imports are idempotent. A later rollback
                # A -> B -> A remains an explicit new revision.
                snapshot_id = str(latest["snapshot_id"])
            else:
                version = int(latest[1]) + 1 if latest else 1
                previous_snapshot_id = str(latest[0]) if latest else None
                desired = old_snapshot_id
                if connection.execute(
                    "SELECT 1 FROM source_snapshots WHERE snapshot_id = ?", (desired,)
                ).fetchone():
                    desired = self._stable_id("snp", table_name, old_snapshot_id, index)
                snapshot_id = desired
                timestamp = self._legacy_time(
                    self._first(row, "created_at", "ingested_at"), fallback=_now()
                ) or _now()
                connection.execute(
                    "INSERT INTO source_snapshots "
                    "(snapshot_id, source_id, version, content_hash, content, media_type, "
                    "origin_path, previous_snapshot_id, line_count, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        snapshot_id,
                        source_id,
                        version,
                        content_hash,
                        content,
                        str(self._first(row, "media_type", "mime_type", default="text/plain")),
                        self._first(row, "origin_path", "path", "uri"),
                        previous_snapshot_id,
                        len(content.splitlines()),
                        timestamp,
                    ),
                )
                connection.execute(
                    "UPDATE sources SET updated_at = ? WHERE source_id = ?",
                    (timestamp, source_id),
                )
            result[old_snapshot_id] = snapshot_id
            mapped[(table_name, index)] = ("source_snapshot", snapshot_id)
        return result

    def _migrate_legacy_claims(
        self,
        connection: sqlite3.Connection,
        legacy_rows: Mapping[str, list[dict[str, Any]]],
        snapshot_id_map: Mapping[str, str],
        mapped: dict[tuple[str, int], tuple[str, str]],
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        for table_name in ("claims", "claim", "claim_proposals"):
            for index, row in enumerate(legacy_rows.get(table_name, [])):
                if self._legacy_is_quarantined(table_name, row, index):
                    continue
                old_claim_id = str(
                    self._first(row, "claim_id", "id", default=f"{table_name}:{index}")
                )
                claim_id = old_claim_id
                if connection.execute(
                    "SELECT 1 FROM claim_proposals WHERE claim_id = ?", (claim_id,)
                ).fetchone():
                    claim_id = self._stable_id("clm", table_name, old_claim_id, index)
                persona_id = str(
                    self._first(row, "persona_id", "character_id", "persona", default="default")
                )
                continuity = str(
                    self._first(row, "continuity", "worldline", "timeline", default="default")
                )
                subject = self._first(row, "subject")
                predicate = self._first(row, "predicate", "relation")
                object_value = self._first(row, "object_value", "object", "value")
                text = str(
                    self._first(row, "text", "content", "claim", "statement", default="")
                )
                if not text:
                    text = " ".join(
                        str(value) for value in (subject, predicate, object_value) if value is not None
                    )
                status = self._legacy_status(self._first(row, "status", "governance_status"))
                created_at = self._legacy_time(
                    self._first(row, "created_at", "proposed_at"), fallback=_now()
                ) or _now()
                updated_at = self._legacy_time(
                    self._first(row, "updated_at", "authorized_at"), fallback=created_at
                ) or created_at
                try:
                    confidence = float(self._first(row, "confidence", default=1.0))
                except (TypeError, ValueError):
                    confidence = 1.0
                confidence = max(0.0, min(1.0, confidence))
                connection.execute(
                    "INSERT INTO claim_proposals "
                    "(claim_id, persona_id, continuity, text, subject, predicate, object_value, "
                    "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, "
                    "confidence, status, proposed_by, proposal_model, rationale, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        claim_id,
                        persona_id,
                        continuity,
                        text,
                        subject,
                        predicate,
                        object_value,
                        self._legacy_time(self._first(row, "valid_from", "valid_start")),
                        self._legacy_time(
                            self._first(row, "valid_to", "valid_until", "valid_end")
                        ),
                        self._legacy_time(
                            self._first(row, "knowledge_from", "knowledge_start", "known_from")
                        ),
                        self._legacy_time(
                            self._first(
                                row,
                                "knowledge_to",
                                "knowledge_until",
                                "knowledge_end",
                                "known_to",
                            )
                        ),
                        self._legacy_access(
                            self._first(row, "access_policy", "access", "visibility")
                        ).value,
                        confidence,
                        status.value,
                        self._first(row, "proposed_by", "created_by", default="migration:v0.1"),
                        self._first(row, "proposal_model", "model"),
                        self._first(row, "rationale", "notes"),
                        created_at,
                        updated_at,
                    ),
                )
                if status != GovernanceStatus.PROPOSED:
                    connection.execute(
                        "INSERT INTO governance_decisions "
                        "(decision_id, claim_id, from_status, to_status, reviewer, reason, decided_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            self._stable_id("dec", "migration", claim_id),
                            claim_id,
                            GovernanceStatus.PROPOSED.value,
                            status.value,
                            "migration:v0.1",
                            "Preserved v0.1 claim authority during schema migration",
                            updated_at,
                        ),
                    )

                legacy_snapshot = self._first(
                    row, "snapshot_id", "source_snapshot_id", "source_id"
                )
                new_snapshot = snapshot_id_map.get(str(legacy_snapshot)) if legacy_snapshot else None
                if new_snapshot:
                    snapshot_row = connection.execute(
                        "SELECT line_count FROM source_snapshots WHERE snapshot_id = ?",
                        (new_snapshot,),
                    ).fetchone()
                    line_count = int(snapshot_row[0]) if snapshot_row else 0
                    start_line = int(
                        self._first(row, "start_line", "line_start", "source_line_start", default=1)
                    )
                    end_line = int(
                        self._first(
                            row,
                            "end_line",
                            "line_end",
                            "source_line_end",
                            default=start_line,
                        )
                    )
                    if line_count and 1 <= start_line <= end_line <= line_count:
                        evidence_id = self._stable_id("evr", claim_id, new_snapshot, start_line, end_line)
                        connection.execute(
                            "INSERT OR IGNORE INTO evidence_refs "
                            "(evidence_id, claim_id, snapshot_id, start_line, end_line, "
                            "start_char, end_char, quote, content_hash, created_at) "
                            "VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)",
                            (
                                evidence_id,
                                claim_id,
                                new_snapshot,
                                start_line,
                                end_line,
                                self._first(row, "quote", "source_text"),
                                self._first(row, "quote_sha256", "evidence_hash"),
                                created_at,
                            ),
                        )
                result[old_claim_id] = claim_id
                mapped[(table_name, index)] = ("claim_proposal", claim_id)
        return result

    def _migrate_legacy_evidence(
        self,
        connection: sqlite3.Connection,
        legacy_rows: Mapping[str, list[dict[str, Any]]],
        claim_id_map: Mapping[str, str],
        snapshot_id_map: Mapping[str, str],
        mapped: dict[tuple[str, int], tuple[str, str]],
    ) -> None:
        for table_name in ("evidence_refs", "evidence", "source_spans"):
            for index, row in enumerate(legacy_rows.get(table_name, [])):
                old_claim = str(self._first(row, "claim_id", default=""))
                old_snapshot = str(
                    self._first(row, "snapshot_id", "source_snapshot_id", default="")
                )
                claim_id = claim_id_map.get(old_claim, old_claim)
                snapshot_id = snapshot_id_map.get(old_snapshot, old_snapshot)
                if not connection.execute(
                    "SELECT 1 FROM claim_proposals WHERE claim_id = ?", (claim_id,)
                ).fetchone() or not connection.execute(
                    "SELECT 1 FROM source_snapshots WHERE snapshot_id = ?", (snapshot_id,)
                ).fetchone():
                    continue
                try:
                    start_line = int(
                        self._first(row, "start_line", "line_start", "start", default=1)
                    )
                    end_line = int(
                        self._first(row, "end_line", "line_end", "end", default=start_line)
                    )
                except (TypeError, ValueError):
                    continue
                line_count = int(
                    connection.execute(
                        "SELECT line_count FROM source_snapshots WHERE snapshot_id = ?",
                        (snapshot_id,),
                    ).fetchone()[0]
                )
                if not (line_count and 1 <= start_line <= end_line <= line_count):
                    continue
                evidence_id = str(
                    self._first(
                        row,
                        "evidence_id",
                        "id",
                        default=self._stable_id(
                            "evr", claim_id, snapshot_id, start_line, end_line, index
                        ),
                    )
                )
                if connection.execute(
                    "SELECT 1 FROM evidence_refs WHERE evidence_id = ?", (evidence_id,)
                ).fetchone():
                    evidence_id = self._stable_id("evr", table_name, evidence_id, index)
                created_at = self._legacy_time(
                    self._first(row, "created_at"), fallback=_now()
                ) or _now()
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO evidence_refs "
                    "(evidence_id, claim_id, snapshot_id, start_line, end_line, start_char, "
                    "end_char, quote, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        evidence_id,
                        claim_id,
                        snapshot_id,
                        start_line,
                        end_line,
                        self._first(row, "start_char", "char_start"),
                        self._first(row, "end_char", "char_end"),
                        self._first(row, "quote", "text"),
                        self._first(row, "content_hash", "quote_sha256", "sha256"),
                        created_at,
                    ),
                )
                if cursor.rowcount:
                    mapped[(table_name, index)] = ("evidence_ref", evidence_id)

    def _migrate_legacy_events(
        self,
        connection: sqlite3.Connection,
        legacy_rows: Mapping[str, list[dict[str, Any]]],
        mapped: dict[tuple[str, int], tuple[str, str]],
    ) -> None:
        for table_name in ("narrative_events", "events"):
            for index, row in enumerate(legacy_rows.get(table_name, [])):
                if self._legacy_is_quarantined(table_name, row, index):
                    continue
                event_id = str(
                    self._first(row, "event_id", "id", default=f"{table_name}:{index}")
                )
                if connection.execute(
                    "SELECT 1 FROM narrative_events WHERE event_id = ?", (event_id,)
                ).fetchone():
                    event_id = self._stable_id("evt", table_name, event_id, index)
                timestamp = self._legacy_time(
                    self._first(row, "created_at"), fallback=_now()
                ) or _now()
                details = self._first(row, "details", "details_json", "metadata", default={})
                if isinstance(details, str):
                    details = _parse_json(details, fallback={"legacy_value": details})
                connection.execute(
                    "INSERT INTO narrative_events "
                    "(event_id, persona_id, continuity, event_type, title, summary, details_json, "
                    "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        str(self._first(row, "persona_id", default="default")),
                        str(
                            self._first(
                                row, "continuity", "worldline", "timeline", default="default"
                            )
                        ),
                        str(self._first(row, "event_type", "type", default="narrative")),
                        str(self._first(row, "title", "name", default="")),
                        str(self._first(row, "summary", "text", "content", default="")),
                        _canonical_json(details),
                        self._legacy_time(self._first(row, "valid_from", "valid_start")),
                        self._legacy_time(
                            self._first(row, "valid_to", "valid_until", "valid_end")
                        ),
                        self._legacy_time(
                            self._first(row, "knowledge_from", "knowledge_start")
                        ),
                        self._legacy_time(
                            self._first(
                                row, "knowledge_to", "knowledge_until", "knowledge_end"
                            )
                        ),
                        self._legacy_access(self._first(row, "access_policy", "access")).value,
                        timestamp,
                    ),
                )
                persisted = connection.execute(
                    "SELECT * FROM narrative_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                self._append_ledger_in_transaction(
                    connection,
                    event_type="narrative_event.created",
                    aggregate_type="narrative_event",
                    aggregate_id=event_id,
                    payload={
                        "persona_id": str(persisted["persona_id"]),
                        "continuity": str(persisted["continuity"]),
                        "event_type": str(persisted["event_type"]),
                        "valid_from": persisted["valid_from"],
                        "knowledge_from": persisted["knowledge_from"],
                        "access_policy": str(persisted["access_policy"]),
                        "evidence_ids": [],
                        "evidence_refs": [],
                    },
                    created_at=timestamp,
                )
                mapped[(table_name, index)] = ("narrative_event", event_id)

    # ------------------------------------------------------------------
    # Logical Source and immutable SourceSnapshot API
    # ------------------------------------------------------------------

    def ingest_snapshot(
        self,
        source_key: str,
        continuity: str,
        content: str,
        media_type: str = "text/plain",
        origin_path: str | None = None,
    ) -> tuple[Source, SourceSnapshot, bool]:
        """Ingest content idempotently and return ``(source, snapshot, created)``.

        The same content in the same logical source returns the existing
        revision.  Changed content increments ``version`` and points
        ``previous_snapshot_id`` at the immediately preceding revision.
        """

        source_key = _nonempty(source_key, name="source_key")
        continuity = _nonempty(continuity, name="continuity")
        media_type = _nonempty(media_type, name="media_type")
        if not isinstance(content, str):
            raise TypeError("content must be str")
        content_hash = sha256(content.encode("utf-8")).hexdigest()
        timestamp = _now()

        with self.transaction() as connection:
            source_row = connection.execute(
                "SELECT * FROM sources WHERE source_key = ? AND continuity = ?",
                (source_key, continuity),
            ).fetchone()
            if source_row is None:
                source_id = _new_id("src")
                connection.execute(
                    "INSERT INTO sources "
                    "(source_id, source_key, continuity, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (source_id, source_key, continuity, timestamp, timestamp),
                )
                self._append_ledger_in_transaction(
                    connection,
                    event_type="source.created",
                    aggregate_type="source",
                    aggregate_id=source_id,
                    payload={"source_key": source_key, "continuity": continuity},
                    created_at=timestamp,
                )
                source_row = connection.execute(
                    "SELECT * FROM sources WHERE source_id = ?", (source_id,)
                ).fetchone()
            source = self._row_to_source(source_row)

            latest = connection.execute(
                "SELECT snapshot_id, version, content_hash FROM source_snapshots "
                "WHERE source_id = ? ORDER BY version DESC LIMIT 1",
                (source.source_id,),
            ).fetchone()
            if latest is not None and str(latest["content_hash"]) == content_hash:
                existing = connection.execute(
                    self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?",
                    (str(latest["snapshot_id"]),),
                ).fetchone()
                return source, self._row_to_snapshot(existing), False
            version = int(latest["version"]) + 1 if latest else 1
            previous_snapshot_id = str(latest["snapshot_id"]) if latest else None
            snapshot_id = _new_id("snp")
            line_count = len(content.splitlines())
            connection.execute(
                "INSERT INTO source_snapshots "
                "(snapshot_id, source_id, version, content_hash, content, media_type, "
                "origin_path, previous_snapshot_id, line_count, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot_id,
                    source.source_id,
                    version,
                    content_hash,
                    content,
                    media_type,
                    origin_path,
                    previous_snapshot_id,
                    line_count,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE sources SET updated_at = ? WHERE source_id = ?",
                (timestamp, source.source_id),
            )
            self._append_ledger_in_transaction(
                connection,
                event_type="source_snapshot.created",
                aggregate_type="source_snapshot",
                aggregate_id=snapshot_id,
                payload={
                    "source_id": source.source_id,
                    "source_key": source_key,
                    "continuity": continuity,
                    "version": version,
                    "content_hash": content_hash,
                    "previous_snapshot_id": previous_snapshot_id,
                    "media_type": media_type,
                    "origin_path": origin_path,
                    "line_count": line_count,
                },
                created_at=timestamp,
            )
            refreshed_source = connection.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source.source_id,)
            ).fetchone()
            snapshot_row = connection.execute(
                self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?", (snapshot_id,)
            ).fetchone()
            return (
                self._row_to_source(refreshed_source),
                self._row_to_snapshot(snapshot_row),
                True,
            )

    _SNAPSHOT_SELECT = (
        "SELECT ss.*, s.source_key, s.continuity "
        "FROM source_snapshots AS ss JOIN sources AS s ON s.source_id = ss.source_id"
    )

    @staticmethod
    def _row_to_source(row: sqlite3.Row) -> Source:
        return Source(
            source_id=str(row["source_id"]),
            source_key=str(row["source_key"]),
            continuity=str(row["continuity"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> SourceSnapshot:
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

    def get_source(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str | None = None,
    ) -> Source:
        if source_id:
            rows = self.connection.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source_id,)
            ).fetchall()
        elif source_key:
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
        if len(rows) > 1:
            raise ContinuityViolation(
                "source_key exists in more than one continuity; specify continuity"
            )
        return self._row_to_source(rows[0])

    def list_sources(self, *, continuity: str | None = None) -> list[Source]:
        sql = "SELECT * FROM sources"
        params: list[object] = []
        if continuity is not None:
            sql += " WHERE continuity = ?"
            params.append(continuity)
        sql += " ORDER BY source_key, continuity"
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row_to_source(row) for row in rows]

    def get_snapshot(self, snapshot_id: str) -> SourceSnapshot:
        row = self.connection.execute(
            self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"snapshot not found: {snapshot_id}")
        return self._row_to_snapshot(row)

    def get_latest_snapshot(self, source_id: str) -> SourceSnapshot:
        row = self.connection.execute(
            self._SNAPSHOT_SELECT
            + " WHERE ss.source_id = ? ORDER BY ss.version DESC LIMIT 1",
            (source_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"source has no snapshots: {source_id}")
        return self._row_to_snapshot(row)

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
        sql += " ORDER BY s.source_key, s.continuity, ss.version"
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def list_source_audit_snapshots(self) -> list[SourceAuditSnapshot]:
        """Bulk-load content-free snapshot material for Source audit replay."""

        rows = self.connection.execute(
            "SELECT snapshot_id, source_id, version, content_hash, media_type, "
            "origin_path, previous_snapshot_id, line_count, created_at "
            "FROM source_snapshots ORDER BY source_id, version, snapshot_id"
        ).fetchall()
        return [
            SourceAuditSnapshot(
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
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Claim proposals, evidence, and explicit governance
    # ------------------------------------------------------------------

    def create_claim_proposal(
        self,
        proposal: ClaimProposal,
        evidence_refs: Iterable[EvidenceRef] = (),
    ) -> ClaimProposal:
        """Persist a PROPOSED claim and its evidence in one audited transaction."""

        if not isinstance(proposal, ClaimProposal):
            raise TypeError("proposal must be ClaimProposal")
        claim_id = _nonempty(proposal.claim_id, name="claim_id")
        persona_id = _nonempty(proposal.persona_id, name="persona_id")
        continuity = _nonempty(proposal.continuity, name="continuity")
        status = GovernanceStatus(proposal.status)
        if status != GovernanceStatus.PROPOSED:
            raise InvalidTransitionError(
                "new claims must start as PROPOSED; use record_governance_decision"
            )
        access_policy = AccessPolicy(proposal.access_policy)
        confidence = float(proposal.confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        validate_interval(proposal.valid_from, proposal.valid_to, name="valid interval")
        validate_interval(
            proposal.knowledge_from, proposal.knowledge_to, name="knowledge interval"
        )
        valid_from = _normal_time(proposal.valid_from)
        valid_to = _normal_time(proposal.valid_to)
        knowledge_from = _normal_time(proposal.knowledge_from)
        knowledge_to = _normal_time(proposal.knowledge_to)
        if not isinstance(proposal.text, str):
            raise TypeError("claim.text must be text")
        validate_claim_fields(
            text=proposal.text,
            subject=proposal.subject,
            predicate=proposal.predicate,
            object_value=proposal.object_value,
            proposed_by=proposal.proposed_by,
            proposal_model=proposal.proposal_model,
            rationale=proposal.rationale,
        )
        text = proposal.text.strip()
        if not text:
            text = " ".join(
                str(value)
                for value in (proposal.subject, proposal.predicate, proposal.object_value)
                if value is not None and str(value).strip()
            )
        if not text:
            raise ValueError("claim text or subject/predicate/object_value is required")
        timestamp = _normal_time(proposal.created_at) or _now()
        evidence_items = list(evidence_refs)

        persisted = replace(
            proposal,
            claim_id=claim_id,
            persona_id=persona_id,
            continuity=continuity,
            text=text,
            valid_from=valid_from,
            valid_to=valid_to,
            knowledge_from=knowledge_from,
            knowledge_to=knowledge_to,
            access_policy=access_policy,
            confidence=confidence,
            status=GovernanceStatus.PROPOSED,
            created_at=timestamp,
            updated_at=timestamp,
        )

        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO claim_proposals "
                "(claim_id, persona_id, continuity, text, subject, predicate, object_value, "
                "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, confidence, "
                "status, proposed_by, proposal_model, rationale, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    persisted.claim_id,
                    persisted.persona_id,
                    persisted.continuity,
                    persisted.text,
                    persisted.subject,
                    persisted.predicate,
                    persisted.object_value,
                    persisted.valid_from,
                    persisted.valid_to,
                    persisted.knowledge_from,
                    persisted.knowledge_to,
                    persisted.access_policy.value,
                    persisted.confidence,
                    persisted.status.value,
                    persisted.proposed_by,
                    persisted.proposal_model,
                    persisted.rationale,
                    persisted.created_at,
                    persisted.updated_at,
                ),
            )
            stored_evidence = [
                self._insert_evidence_ref(connection, claim_id, continuity, item, timestamp)
                for item in evidence_items
            ]
            self._append_ledger_in_transaction(
                connection,
                event_type="claim.proposed",
                aggregate_type="claim",
                aggregate_id=claim_id,
                payload={
                    "persona_id": persona_id,
                    "continuity": continuity,
                    "text": text,
                    "access_policy": access_policy.value,
                    "confidence": confidence,
                    "evidence_ids": [item.evidence_id for item in stored_evidence],
                },
                created_at=timestamp,
            )
        return persisted

    def add_claim_evidence(self, claim_id: str, evidence: EvidenceRef) -> EvidenceRef:
        """Append a new immutable evidence span to an existing proposal."""

        timestamp = _now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT continuity, status FROM claim_proposals WHERE claim_id = ?", (claim_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"claim not found: {claim_id}")
            current = GovernanceStatus(row["status"])
            if current not in {
                GovernanceStatus.PROPOSED,
                GovernanceStatus.DISPUTED,
            }:
                raise InvalidTransitionError(
                    "claim evidence can be appended only while PROPOSED or DISPUTED"
                )
            stored = self._insert_evidence_ref(
                connection, claim_id, str(row["continuity"]), evidence, timestamp
            )
            self._append_ledger_in_transaction(
                connection,
                event_type="claim.evidence_added",
                aggregate_type="claim",
                aggregate_id=claim_id,
                payload={
                    "evidence_id": stored.evidence_id,
                    "snapshot_id": stored.snapshot_id,
                    "start_line": stored.start_line,
                    "end_line": stored.end_line,
                },
                created_at=timestamp,
            )
            return stored

    def _insert_evidence_ref(
        self,
        connection: sqlite3.Connection,
        claim_id: str,
        claim_continuity: str,
        evidence: EvidenceRef,
        timestamp: str,
    ) -> EvidenceRef:
        if not isinstance(evidence, EvidenceRef):
            raise TypeError("evidence_refs must contain EvidenceRef values")
        snapshot = connection.execute(
            self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?", (evidence.snapshot_id,)
        ).fetchone()
        if snapshot is None:
            raise NotFoundError(f"snapshot not found: {evidence.snapshot_id}")
        if str(snapshot["continuity"]) != claim_continuity:
            raise ContinuityViolation(
                "claim evidence belongs to a different continuity: "
                f"{snapshot['continuity']} != {claim_continuity}"
            )
        start_line, end_line = validate_line_range_types(
            evidence.start_line, evidence.end_line
        )
        line_count = int(snapshot["line_count"])
        if start_line < 1 or end_line < start_line or end_line > line_count:
            raise ValueError(
                f"evidence lines {start_line}-{end_line} outside snapshot range 1-{line_count}"
            )
        if evidence.start_char is None and evidence.end_char is not None:
            raise ValueError("end_char requires start_char")
        if evidence.start_char is not None and int(evidence.start_char) < 0:
            raise ValueError("start_char must be non-negative")
        if (
            evidence.end_char is not None
            and evidence.start_char is not None
            and int(evidence.end_char) < int(evidence.start_char)
        ):
            raise ValueError("end_char must be greater than or equal to start_char")
        evidence_id = evidence.evidence_id or _new_id("evr")
        created_at = _normal_time(evidence.created_at) or timestamp
        connection.execute(
            "INSERT INTO evidence_refs "
            "(evidence_id, claim_id, snapshot_id, start_line, end_line, start_char, "
            "end_char, quote, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id,
                claim_id,
                evidence.snapshot_id,
                start_line,
                end_line,
                evidence.start_char,
                evidence.end_char,
                evidence.quote,
                evidence.content_hash,
                created_at,
            ),
        )
        return replace(
            evidence,
            evidence_id=evidence_id,
            claim_id=claim_id,
            event_id=None,
            start_line=start_line,
            end_line=end_line,
            created_at=created_at,
        )

    @staticmethod
    def _row_to_claim(row: sqlite3.Row) -> ClaimProposal:
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
    def _row_to_evidence(row: sqlite3.Row) -> EvidenceRef:
        return EvidenceRef(
            snapshot_id=str(row["snapshot_id"]),
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            quote=row["quote"],
            evidence_id=str(row["evidence_id"]),
            claim_id=str(row["claim_id"]),
            start_char=row["start_char"],
            end_char=row["end_char"],
            content_hash=row["content_hash"],
            created_at=str(row["created_at"]),
        )

    def get_claim_proposal(self, claim_id: str) -> ClaimProposal:
        row = self.connection.execute(
            "SELECT * FROM claim_proposals WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"claim not found: {claim_id}")
        return self._row_to_claim(row)

    # Compatibility name retained for v0.1 embedders.
    get_claim = get_claim_proposal

    def list_claim_proposals(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        status: GovernanceStatus | str | None = None,
        access_policy: AccessPolicy | str | None = None,
        snapshot_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
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
        if access_policy is not None:
            clauses.append("cp.access_policy = ?")
            params.append(AccessPolicy(access_policy).value)
        if snapshot_id is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM evidence_refs er "
                "WHERE er.claim_id = cp.claim_id AND er.snapshot_id = ?)"
            )
            params.append(snapshot_id)
        sql = "SELECT cp.* FROM claim_proposals cp"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY cp.created_at, cp.claim_id"
        if limit is not None:
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += " LIMIT ? OFFSET ?"
            params.extend((limit, max(0, offset)))
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row_to_claim(row) for row in rows]

    # Compatibility name retained for v0.1 embedders.
    list_claims = list_claim_proposals

    def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]:
        if not self.connection.execute(
            "SELECT 1 FROM claim_proposals WHERE claim_id = ?", (claim_id,)
        ).fetchone():
            raise NotFoundError(f"claim not found: {claim_id}")
        rows = self.connection.execute(
            "SELECT * FROM evidence_refs WHERE claim_id = ? "
            "ORDER BY snapshot_id, start_line, end_line, evidence_id",
            (claim_id,),
        ).fetchall()
        return [self._row_to_evidence(row) for row in rows]

    def list_all_claim_evidence(self) -> list[EvidenceRef]:
        """Bulk-load claim evidence for authority replay in one query."""

        rows = self.connection.execute(
            "SELECT * FROM evidence_refs "
            "ORDER BY claim_id, snapshot_id, start_line, end_line, evidence_id"
        ).fetchall()
        return [self._row_to_evidence(row) for row in rows]

    def record_governance_decision(
        self,
        claim_id: str,
        status: GovernanceStatus | str,
        reviewer: str,
        reason: str,
    ) -> GovernanceDecision:
        """Review through the safe governance façade.

        The public v0.2 spelling remains source-compatible, but it no longer
        bypasses evidence validation or conflict detection.  The governance
        service calls :meth:`_commit_governance_decision` only after those
        deterministic gates pass.
        """

        from .governance import ClaimGovernance

        return ClaimGovernance(self).review(
            claim_id,
            status,
            reviewer=reviewer,
            reason=reason,
        )

    def _commit_governance_decision(
        self,
        claim_id: str,
        status: GovernanceStatus | str,
        reviewer: str,
        reason: str,
    ) -> GovernanceDecision:
        """Atomically persist a decision after ``ClaimGovernance`` gates it."""

        target = GovernanceStatus(status)
        reviewer = _nonempty(reviewer, name="reviewer")
        reason = _nonempty(reason, name="reason")
        timestamp = _now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT status FROM claim_proposals WHERE claim_id = ?", (claim_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"claim not found: {claim_id}")
            current = GovernanceStatus(row["status"])
            if target not in self._ALLOWED_TRANSITIONS[current]:
                raise InvalidTransitionError(
                    f"invalid governance transition: {current.value} -> {target.value}"
                )
            decision = GovernanceDecision(
                decision_id=_new_id("dec"),
                claim_id=claim_id,
                from_status=current,
                to_status=target,
                reviewer=reviewer,
                reason=reason,
                decided_at=timestamp,
            )
            connection.execute(
                "INSERT INTO governance_decisions "
                "(decision_id, claim_id, from_status, to_status, reviewer, reason, decided_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    decision.decision_id,
                    decision.claim_id,
                    decision.from_status.value,
                    decision.to_status.value,
                    decision.reviewer,
                    decision.reason,
                    decision.decided_at,
                ),
            )
            connection.execute(
                "UPDATE claim_proposals SET status = ?, updated_at = ? WHERE claim_id = ?",
                (target.value, timestamp, claim_id),
            )
            self._append_ledger_in_transaction(
                connection,
                event_type="claim.governance_decided",
                aggregate_type="claim",
                aggregate_id=claim_id,
                payload={
                    "decision_id": decision.decision_id,
                    "from_status": current.value,
                    "to_status": target.value,
                    "reviewer": reviewer,
                    "reason": reason,
                },
                created_at=timestamp,
            )
            return decision

    def list_governance_decisions(
        self, *, claim_id: str | None = None
    ) -> list[GovernanceDecision]:
        sql = "SELECT * FROM governance_decisions"
        params: list[object] = []
        if claim_id is not None:
            sql += " WHERE claim_id = ?"
            params.append(claim_id)
        # Immutable insertion order mirrors EventLedger order. ``decided_at``
        # is metadata and may move backward when the system clock changes.
        sql += " ORDER BY rowid"
        rows = self.connection.execute(sql, params).fetchall()
        return [
            GovernanceDecision(
                decision_id=str(row["decision_id"]),
                claim_id=str(row["claim_id"]),
                from_status=GovernanceStatus(row["from_status"]),
                to_status=GovernanceStatus(row["to_status"]),
                reviewer=str(row["reviewer"]),
                reason=str(row["reason"]),
                decided_at=str(row["decided_at"]),
            )
            for row in rows
        ]

    def query_claims_for_cutoff(
        self,
        cutoff: MemoryCutoff,
        *,
        status: GovernanceStatus | str = GovernanceStatus.AUTHORIZED,
    ) -> list[ClaimProposal]:
        """Return worldline-safe claims visible at a MemoryCutoff."""

        knowledge_at = _normal_time(cutoff.knowledge_at)
        if knowledge_at is None:
            raise ValueError("cutoff.knowledge_at is required")
        valid_at = _normal_time(cutoff.valid_at)
        policies = tuple(AccessPolicy(value).value for value in cutoff.access_policies)
        if not policies:
            return []
        placeholders = ",".join("?" for _ in policies)
        clauses = [
            "persona_id = ?",
            "continuity = ?",
            "status = ?",
            f"access_policy IN ({placeholders})",
            "(knowledge_from IS NULL OR knowledge_from <= ?)",
            "(knowledge_to IS NULL OR knowledge_to > ?)",
        ]
        params: list[object] = [
            cutoff.persona_id,
            cutoff.continuity,
            GovernanceStatus(status).value,
            *policies,
            knowledge_at,
            knowledge_at,
        ]
        if valid_at is not None:
            clauses.extend(
                [
                    "(valid_from IS NULL OR valid_from <= ?)",
                    "(valid_to IS NULL OR valid_to > ?)",
                ]
            )
            params.extend((valid_at, valid_at))
        rows = self.connection.execute(
            "SELECT * FROM claim_proposals WHERE "
            + " AND ".join(clauses)
            + " ORDER BY COALESCE(valid_from, knowledge_from, created_at), claim_id",
            params,
        ).fetchall()
        return [self._row_to_claim(row) for row in rows]

    query_authorized_claims = query_claims_for_cutoff

    # ------------------------------------------------------------------
    # Narrative Event API
    # ------------------------------------------------------------------

    def create_narrative_event(
        self,
        event: NarrativeEvent,
        evidence_refs: Iterable[EvidenceRef] = (),
    ) -> NarrativeEvent:
        if not isinstance(event, NarrativeEvent):
            raise TypeError("event must be NarrativeEvent")
        event_id = _nonempty(event.event_id, name="event_id")
        persona_id = _nonempty(event.persona_id, name="persona_id")
        continuity = _nonempty(event.continuity, name="continuity")
        event_type = _nonempty(event.event_type, name="event_type")
        validate_event_fields(title=event.title, summary=event.summary)
        validate_interval(event.valid_from, event.valid_to, name="valid interval")
        validate_interval(
            event.knowledge_from, event.knowledge_to, name="knowledge interval"
        )
        validated_details, details_json = _strict_json_object(event.details)
        timestamp = _normal_time(event.created_at) or _now()
        persisted = replace(
            event,
            event_id=event_id,
            persona_id=persona_id,
            continuity=continuity,
            event_type=event_type,
            valid_from=_normal_time(event.valid_from),
            valid_to=_normal_time(event.valid_to),
            knowledge_from=_normal_time(event.knowledge_from),
            knowledge_to=_normal_time(event.knowledge_to),
            access_policy=AccessPolicy(event.access_policy),
            details=validated_details,
            created_at=timestamp,
        )
        evidence_items = list(evidence_refs)
        if not evidence_items:
            raise ValueError("narrative events require at least one evidence reference")
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO narrative_events "
                "(event_id, persona_id, continuity, event_type, title, summary, details_json, "
                "valid_from, valid_to, knowledge_from, knowledge_to, access_policy, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    persisted.event_id,
                    persisted.persona_id,
                    persisted.continuity,
                    persisted.event_type,
                    persisted.title,
                    persisted.summary,
                    details_json,
                    persisted.valid_from,
                    persisted.valid_to,
                    persisted.knowledge_from,
                    persisted.knowledge_to,
                    persisted.access_policy.value,
                    persisted.created_at,
                ),
            )
            stored_evidence = [
                self._insert_event_evidence_ref(
                    connection,
                    event_id,
                    continuity,
                    item,
                    timestamp,
                )
                for item in evidence_items
            ]
            self._append_ledger_in_transaction(
                connection,
                event_type="narrative_event.created",
                aggregate_type="narrative_event",
                aggregate_id=event_id,
                payload={
                    "persona_id": persona_id,
                    "continuity": continuity,
                    "event_type": event_type,
                    "valid_from": persisted.valid_from,
                    "knowledge_from": persisted.knowledge_from,
                    "access_policy": persisted.access_policy.value,
                    "evidence_ids": [item.evidence_id for item in stored_evidence],
                    "evidence_refs": [
                        {
                            "evidence_id": item.evidence_id,
                            "snapshot_id": item.snapshot_id,
                            "start_line": item.start_line,
                            "end_line": item.end_line,
                            "content_hash": item.content_hash,
                        }
                        for item in stored_evidence
                    ],
                },
                created_at=timestamp,
            )
        return persisted

    def _insert_event_evidence_ref(
        self,
        connection: sqlite3.Connection,
        event_id: str,
        event_continuity: str,
        evidence: EvidenceRef,
        timestamp: str,
    ) -> EvidenceRef:
        if not isinstance(evidence, EvidenceRef):
            raise TypeError("evidence_refs must contain EvidenceRef values")
        snapshot = connection.execute(
            self._SNAPSHOT_SELECT + " WHERE ss.snapshot_id = ?", (evidence.snapshot_id,)
        ).fetchone()
        if snapshot is None:
            raise NotFoundError(f"snapshot not found: {evidence.snapshot_id}")
        if str(snapshot["continuity"]) != event_continuity:
            raise ContinuityViolation(
                "event evidence belongs to a different continuity: "
                f"{snapshot['continuity']} != {event_continuity}"
            )
        start_line, end_line = validate_line_range_types(
            evidence.start_line, evidence.end_line
        )
        line_count = int(snapshot["line_count"])
        if start_line < 1 or end_line < start_line or end_line > line_count:
            raise ValueError(
                f"evidence lines {start_line}-{end_line} outside snapshot range 1-{line_count}"
            )
        if evidence.start_char is None and evidence.end_char is not None:
            raise ValueError("end_char requires start_char")
        if evidence.start_char is not None and int(evidence.start_char) < 0:
            raise ValueError("start_char must be non-negative")
        if (
            evidence.end_char is not None
            and evidence.start_char is not None
            and int(evidence.end_char) < int(evidence.start_char)
        ):
            raise ValueError("end_char must be greater than or equal to start_char")
        evidence_id = evidence.evidence_id or _new_id("evr")
        created_at = _normal_time(evidence.created_at) or timestamp
        connection.execute(
            "INSERT INTO event_evidence_refs "
            "(evidence_id, event_id, snapshot_id, start_line, end_line, start_char, "
            "end_char, quote, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id,
                event_id,
                evidence.snapshot_id,
                start_line,
                end_line,
                evidence.start_char,
                evidence.end_char,
                evidence.quote,
                evidence.content_hash,
                created_at,
            ),
        )
        return replace(
            evidence,
            evidence_id=evidence_id,
            claim_id=None,
            event_id=event_id,
            start_line=start_line,
            end_line=end_line,
            created_at=created_at,
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> NarrativeEvent:
        details = _parse_json(row["details_json"], fallback={})
        if not isinstance(details, Mapping):
            details = {"value": details}
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

    def get_narrative_event(self, event_id: str) -> NarrativeEvent:
        row = self.connection.execute(
            "SELECT * FROM narrative_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"narrative event not found: {event_id}")
        return self._row_to_event(row)

    def get_event_evidence(self, event_id: str) -> list[EvidenceRef]:
        """Return immutable, ordered source spans attached to an event."""

        if not self.connection.execute(
            "SELECT 1 FROM narrative_events WHERE event_id = ?", (event_id,)
        ).fetchone():
            raise NotFoundError(f"narrative event not found: {event_id}")
        rows = self.connection.execute(
            "SELECT * FROM event_evidence_refs WHERE event_id = ? "
            "ORDER BY snapshot_id, start_line, end_line, evidence_id",
            (event_id,),
        ).fetchall()
        return [
            EvidenceRef(
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
            for row in rows
        ]

    def list_all_event_evidence(self) -> list[EvidenceRef]:
        """Bulk-load event evidence for audit replay in one query."""

        rows = self.connection.execute(
            "SELECT * FROM event_evidence_refs "
            "ORDER BY event_id, snapshot_id, start_line, end_line, evidence_id"
        ).fetchall()
        return [
            EvidenceRef(
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
            for row in rows
        ]

    def list_narrative_events(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        cutoff: MemoryCutoff | None = None,
        access_policies: Iterable[AccessPolicy | str] | None = None,
    ) -> list[NarrativeEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if cutoff is not None:
            if persona_id is not None and persona_id != cutoff.persona_id:
                raise ValueError("persona_id conflicts with cutoff")
            if continuity is not None and continuity != cutoff.continuity:
                raise ContinuityViolation("continuity conflicts with cutoff")
            persona_id = cutoff.persona_id
            continuity = cutoff.continuity
            access_policies = cutoff.access_policies
            knowledge_at = _normal_time(cutoff.knowledge_at)
            clauses.extend(
                [
                    "(knowledge_from IS NULL OR knowledge_from <= ?)",
                    "(knowledge_to IS NULL OR knowledge_to > ?)",
                ]
            )
            params.extend((knowledge_at, knowledge_at))
            valid_at = _normal_time(cutoff.valid_at)
            if valid_at is not None:
                clauses.extend(
                    [
                        "(valid_from IS NULL OR valid_from <= ?)",
                        "(valid_to IS NULL OR valid_to > ?)",
                    ]
                )
                params.extend((valid_at, valid_at))
        if persona_id is not None:
            clauses.append("persona_id = ?")
            params.append(persona_id)
        if continuity is not None:
            clauses.append("continuity = ?")
            params.append(continuity)
        if access_policies is not None:
            policies = [AccessPolicy(value).value for value in access_policies]
            if not policies:
                return []
            clauses.append("access_policy IN (" + ",".join("?" for _ in policies) + ")")
            params.extend(policies)
        sql = "SELECT * FROM narrative_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY COALESCE(valid_from, knowledge_from, created_at), event_id"
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row_to_event(row) for row in rows]

    # ------------------------------------------------------------------
    # Append-only hash-chain EventLedger
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
        material = _canonical_json(
            {
                "sequence": sequence,
                "entry_id": entry_id,
                "event_type": event_type,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "payload_json": payload_json,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }
        )
        return sha256(material.encode("utf-8")).hexdigest()

    def append_ledger(
        self,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> LedgerEntry:
        """Append a custom domain event without exposing mutable ledger SQL."""

        with self.transaction() as connection:
            return self._append_ledger_in_transaction(
                connection,
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                payload=payload or {},
            )

    def _append_ledger_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        payload: Mapping[str, Any],
        created_at: str | None = None,
    ) -> LedgerEntry:
        event_type = _nonempty(event_type, name="event_type")
        aggregate_type = _nonempty(aggregate_type, name="aggregate_type")
        aggregate_id = _nonempty(aggregate_id, name="aggregate_id")
        previous = connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["entry_hash"]) if previous else GENESIS_HASH
        entry_id = _new_id("led")
        timestamp = created_at or _now()
        payload_json = _canonical_json(dict(payload))
        entry_hash = self._ledger_digest(
            sequence=sequence,
            entry_id=entry_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload_json=payload_json,
            previous_hash=previous_hash,
            created_at=timestamp,
        )
        connection.execute(
            "INSERT INTO event_ledger "
            "(sequence, entry_id, event_type, aggregate_type, aggregate_id, payload_json, "
            "previous_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                entry_id,
                event_type,
                aggregate_type,
                aggregate_id,
                payload_json,
                previous_hash,
                entry_hash,
                timestamp,
            ),
        )
        return LedgerEntry(
            sequence=sequence,
            entry_id=entry_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload=dict(payload),
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            created_at=timestamp,
        )

    @staticmethod
    def _row_to_ledger(row: sqlite3.Row) -> LedgerEntry:
        payload = _parse_json(row["payload_json"], fallback={})
        if not isinstance(payload, Mapping):
            payload = {"value": payload}
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

    def list_ledger_entries(
        self,
        *,
        after_sequence: int = 0,
        event_type: str | None = None,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        limit: int | None = None,
    ) -> list[LedgerEntry]:
        clauses = ["sequence > ?"]
        params: list[object] = [max(0, after_sequence)]
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if aggregate_type is not None:
            clauses.append("aggregate_type = ?")
            params.append(aggregate_type)
        if aggregate_id is not None:
            clauses.append("aggregate_id = ?")
            params.append(aggregate_id)
        sql = "SELECT * FROM event_ledger WHERE " + " AND ".join(clauses)
        sql += " ORDER BY sequence"
        if limit is not None:
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += " LIMIT ?"
            params.append(limit)
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row_to_ledger(row) for row in rows]

    def verify_ledger(self, *, raise_on_error: bool = False) -> bool:
        """Recompute every link and digest; optionally raise on first failure."""

        rows = self.connection.execute(
            "SELECT * FROM event_ledger ORDER BY sequence"
        ).fetchall()
        expected_sequence = 1
        expected_previous = GENESIS_HASH
        error: str | None = None
        for row in rows:
            sequence = int(row["sequence"])
            if sequence != expected_sequence:
                error = f"ledger sequence gap: expected {expected_sequence}, got {sequence}"
                break
            if str(row["previous_hash"]) != expected_previous:
                error = f"ledger previous_hash mismatch at sequence {sequence}"
                break
            calculated = self._ledger_digest(
                sequence=sequence,
                entry_id=str(row["entry_id"]),
                event_type=str(row["event_type"]),
                aggregate_type=str(row["aggregate_type"]),
                aggregate_id=str(row["aggregate_id"]),
                payload_json=str(row["payload_json"]),
                previous_hash=str(row["previous_hash"]),
                created_at=str(row["created_at"]),
            )
            if calculated != str(row["entry_hash"]):
                error = f"ledger entry_hash mismatch at sequence {sequence}"
                break
            expected_previous = str(row["entry_hash"])
            expected_sequence += 1
        if error and raise_on_error:
            raise LedgerIntegrityError(error)
        return error is None

    # ------------------------------------------------------------------
    # Migration audit query
    # ------------------------------------------------------------------

    def list_legacy_records(
        self, *, original_table: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM legacy_records"
        params: list[object] = []
        if original_table is not None:
            sql += " WHERE original_table = ?"
            params.append(original_table)
        sql += " ORDER BY legacy_record_id"
        rows = self.connection.execute(sql, params).fetchall()
        return [
            {
                "legacy_record_id": int(row["legacy_record_id"]),
                "original_table": str(row["original_table"]),
                "legacy_key": str(row["legacy_key"]),
                "payload": _parse_json(row["payload_json"], fallback={}),
                "migrated_entity_type": row["migrated_entity_type"],
                "migrated_entity_id": row["migrated_entity_id"],
                "migrated_at": str(row["migrated_at"]),
            }
            for row in rows
        ]


# Explicit spelling for embedders that prefer to name the backend.
SQLiteStorage = Storage


__all__ = [
    "GENESIS_HASH",
    "SCHEMA_VERSION",
    "SQLiteStorage",
    "Storage",
]
