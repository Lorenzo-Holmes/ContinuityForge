from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import math
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import continuityforge.migrations as migrations
import continuityforge.schema as schema
import continuityforge.storage as storage_module
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import (
    ContinuityViolation,
    InvalidTransitionError,
    LedgerIntegrityError,
    MigrationError,
    NotFoundError,
    ReadOnlyStorageError,
    SchemaError,
)
from continuityforge.governance import ClaimGovernance
from continuityforge.ingest import ingest_content
from continuityforge.migrations import (
    MigrationIssue,
    MigrationMode,
    MigrationReport,
    preflight_migration,
    validate_migration_data,
)
from continuityforge.models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceStatus,
    MemoryCutoff,
    NarrativeEvent,
)
from continuityforge.schema import (
    SchemaFingerprint,
    SchemaKind,
    classify_schema,
    fingerprint_schema,
    validate_schema,
)
from continuityforge.storage import Storage


def _create_v01(database: Path, project_root: Path) -> None:
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript(
            (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.commit()


def _fingerprint(kind: SchemaKind) -> SchemaFingerprint:
    return SchemaFingerprint(
        kind=kind,
        digest="a" * 64,
        user_version={SchemaKind.V01: 0, SchemaKind.V02: 2}.get(kind, 3),
        metadata_version=None if kind is SchemaKind.V01 else 3,
        tables=("sources",),
        indexes=(),
        triggers=(),
    )


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _PragmaOverride:
    """Delegate SQLite except for integrity PRAGMAs under fault injection."""

    def __init__(self, connection: sqlite3.Connection, *, quick=None, foreign=None):
        self.connection = connection
        self.quick = quick
        self.foreign = foreign

    def execute(self, sql: str, parameters=()):
        normalized = " ".join(sql.lower().split())
        if normalized == "pragma quick_check" and self.quick is not None:
            return _Rows(self.quick)
        if normalized == "pragma foreign_key_check" and self.foreign is not None:
            return _Rows(self.foreign)
        return self.connection.execute(sql, parameters)


class _FaultConnection(sqlite3.Connection):
    quick_rows = None
    foreign_rows = None

    def execute(self, sql: str, parameters=()):
        normalized = " ".join(sql.lower().split())
        if normalized == "pragma quick_check" and self.quick_rows is not None:
            return _Rows(self.quick_rows)
        if normalized == "pragma foreign_key_check" and self.foreign_rows is not None:
            return _Rows(self.foreign_rows)
        return super().execute(sql, parameters)


def test_schema_fingerprint_json_redacts_hostile_object_names() -> None:
    unsafe = "trigger\u202ehidden"
    surrogate = "table\ud800name"
    long_name = "x" * 257
    fingerprint = SchemaFingerprint(
        kind=SchemaKind.PARTIAL,
        digest="b" * 64,
        user_version=3,
        metadata_version=3,
        tables=("ordinary", surrogate),
        indexes=(long_name,),
        triggers=(unsafe,),
    )

    material = fingerprint.to_dict()
    assert material["tables"][0] == "ordinary"
    for descriptor in (
        material["tables"][1],
        material["indexes"][0],
        material["triggers"][0],
    ):
        assert descriptor["redacted"] is True
        assert descriptor["type"] == "schema_object_name"
        assert len(descriptor["sha256"]) == 64
    encoded = fingerprint.to_json(indent=2)
    assert "ordinary" in encoded
    assert unsafe not in encoded and surrogate not in encoded and long_name not in encoded


def test_schema_metadata_requires_one_integer_singleton_row() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata "
            "(singleton INTEGER, schema_version, migrated_at TEXT, migration_notes TEXT)"
        )
        connection.executemany(
            "INSERT INTO schema_metadata VALUES (?, ?, '', '')",
            [(1, "3"), (2, 3)],
        )
        fingerprint = fingerprint_schema(connection)

    assert fingerprint.metadata_version is None
    assert fingerprint.kind is SchemaKind.PARTIAL


def test_schema_with_an_extra_view_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "view.db"
    with Storage(database):
        pass
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE VIEW unexpected_projection AS SELECT source_id FROM sources")
        connection.commit()
        assert classify_schema(connection) is SchemaKind.PARTIAL


def test_schema_columns_treat_database_errors_as_no_columns() -> None:
    class BrokenConnection:
        def execute(self, sql: str):
            raise sqlite3.DatabaseError("malformed schema")

    assert schema._columns(BrokenConnection(), "hostile") == frozenset()


def test_validate_schema_rejects_unsupported_and_wrong_versions() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        with pytest.raises(SchemaError, match="unsupported expected schema version"):
            validate_schema(connection, expected_version=99)
        with pytest.raises(SchemaError, match="expected v0.1, found empty"):
            validate_schema(connection, expected_version=1)


def test_validate_schema_reports_quick_check_fault(tmp_path: Path) -> None:
    database = tmp_path / "quick.db"
    with Storage(database):
        pass
    with closing(sqlite3.connect(database)) as connection:
        proxy = _PragmaOverride(connection, quick=[("disk image is malformed",)])
        with pytest.raises(SchemaError, match="quick_check failed"):
            validate_schema(proxy)  # type: ignore[arg-type]


def test_validate_schema_reports_foreign_key_fault(tmp_path: Path) -> None:
    database = tmp_path / "foreign.db"
    with Storage(database):
        pass
    with closing(sqlite3.connect(database)) as connection:
        proxy = _PragmaOverride(
            connection,
            quick=[("ok",)],
            foreign=[("evidence_refs", 1, "source_snapshots", 0)],
        )
        with pytest.raises(SchemaError, match="1 violation"):
            validate_schema(proxy)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "actual"),
    [
        ("content", "secret source body"),
        ("path", Path("/operator/private/story.txt")),
        ("quote", b"secret bytes"),
        ("details_json", {"text": "nested secret"}),
    ],
)
def test_migration_issue_redacts_sensitive_actuals(field: str, actual: object) -> None:
    issue = MigrationIssue(
        "MIGRATION_TEST",
        "bounded diagnostic",
        table="records",
        record_id="record-1",
        field=field,
        actual=actual,
    )
    material = issue.to_dict()

    assert material["actual"]["redacted"] is True
    assert len(material["actual"]["sha256"]) == 64
    assert "secret" not in json.dumps(material, ensure_ascii=False)


def test_migration_issue_bounds_nested_and_non_finite_diagnostics() -> None:
    material = MigrationIssue(
        "MIGRATION_TEST",
        "bounded diagnostic",
        actual={
            "ordinary": "useful",
            "absolute": str(Path.cwd().resolve()),
            "control": "bad\nvalue",
            "many": list(range(51)),
            "nan": math.nan,
            "positive": math.inf,
            "negative": -math.inf,
            "opaque": object(),
        },
    ).to_dict()["actual"]

    assert material["ordinary"] == "useful"
    assert material["absolute"]["redacted"] is True
    assert material["control"]["redacted"] is True
    assert material["many"]["redacted"] is True
    assert material["nan"] == {"type": "float", "value": "nan"}
    assert material["positive"] == {"type": "float", "value": "inf"}
    assert material["negative"] == {"type": "float", "value": "-inf"}
    assert material["opaque"] == {"redacted": True, "type": "object"}


@pytest.mark.parametrize(
    ("status", "succeeded", "changed"),
    [
        ("preflight", False, False),
        ("already-current", True, False),
        ("initialized", True, True),
        ("migrated", True, True),
        ("failed", False, False),
    ],
)
def test_migration_report_status_contract(status: str, succeeded: bool, changed: bool) -> None:
    report = MigrationReport(
        mode=MigrationMode.STRICT,
        source=_fingerprint(SchemaKind.V01),
        status=status,
        quick_check="ok",
        quarantined=(("claims", "ordinary-id"), ("claims", "x" * 129)),
    )

    material = report.to_dict()
    assert report.succeeded is succeeded
    assert report.changed is changed
    assert report.is_ready is True
    assert material["quarantine"]["count"] == 2
    assert material["quarantine"]["records"][0]["record_id"] == "ordinary-id"
    assert material["quarantine"]["records"][1]["record_id"]["redacted"] is True
    assert json.loads(report.to_json())["status"] == status


def test_preflight_in_memory_is_read_only_and_restores_row_factory() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        factory = lambda _cursor, row: tuple(row)  # noqa: E731
        connection.row_factory = factory
        report = preflight_migration(connection, create_backup=True)

        assert connection.row_factory is factory
        assert connection.execute("SELECT 1").fetchone() == (1,)

    assert report.source.kind is SchemaKind.EMPTY
    assert report.is_ready
    assert report.database_bytes is None
    assert report.backup_path is None


def test_preflight_current_database_is_ready_without_backup(tmp_path: Path) -> None:
    database = tmp_path / "current.db"
    with Storage(database):
        pass

    report = preflight_migration(database, create_backup=True)

    assert report.source.kind is SchemaKind.V03
    assert report.is_ready
    assert report.backup_path is None
    assert [issue.code for issue in report.issues] == ["MIGRATION_ALREADY_CURRENT"]


@pytest.mark.parametrize(
    ("quick_rows", "foreign_rows", "code", "foreign_count"),
    [
        ([('corrupt page',)], [], "MIGRATION_SQLITE_QUICK_CHECK_FAILED", 0),
        ([('ok',)], [("child", 1, "parent", 0)], "MIGRATION_FOREIGN_KEY_CHECK_FAILED", 1),
    ],
)
def test_preflight_surfaces_sqlite_integrity_failures(
    quick_rows, foreign_rows, code: str, foreign_count: int
) -> None:
    connection = sqlite3.connect(":memory:", factory=_FaultConnection)
    try:
        connection.quick_rows = quick_rows
        connection.foreign_rows = foreign_rows
        report = preflight_migration(connection, create_backup=False)
    finally:
        connection.close()

    assert not report.is_ready
    assert code in {issue.code for issue in report.issues}
    assert report.foreign_key_violations == foreign_count


def test_preflight_restores_borrowed_connection_after_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    factory = lambda _cursor, row: tuple(row)  # noqa: E731
    connection.row_factory = factory

    def fail_fingerprint(_connection):
        raise RuntimeError("simulated fingerprint failure")

    monkeypatch.setattr(migrations, "fingerprint_schema", fail_fingerprint)
    try:
        with pytest.raises(RuntimeError, match="fingerprint failure"):
            preflight_migration(connection, create_backup=False)
        assert connection.row_factory is factory
        assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        connection.close()


def test_preflight_resource_limit_skips_expensive_integrity_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "resource.db"
    with Storage(database):
        pass
    monkeypatch.setattr(migrations, "MAX_MIGRATION_DATABASE_BYTES", -1)

    report = preflight_migration(database, create_backup=False)

    assert not report.is_ready
    assert report.quick_check == "not-run"
    issue = next(item for item in report.issues if item.code == "MIGRATION_RESOURCE_LIMIT")
    assert issue.actual["kind"] == "database_bytes"
    assert report.foreign_key_violations == 0


def test_preflight_enforces_per_table_row_limit(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "rows.db"
    _create_v01(database, project_root)
    monkeypatch.setattr(migrations, "MAX_MIGRATION_ROWS_PER_TABLE", 0)

    report = preflight_migration(database, create_backup=False)

    issue = next(item for item in report.issues if item.code == "MIGRATION_RESOURCE_LIMIT")
    assert issue.table in {"claims", "source_snapshots"}
    assert issue.actual["kind"] == "table_rows"
    assert report.quick_check == "not-run"


def test_preflight_enforces_total_row_limit(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "total-rows.db"
    _create_v01(database, project_root)
    monkeypatch.setattr(migrations, "MAX_MIGRATION_ROWS_PER_TABLE", 10**9)
    monkeypatch.setattr(migrations, "MAX_MIGRATION_TOTAL_ROWS", 0)

    report = preflight_migration(database, create_backup=False)

    issue = next(item for item in report.issues if item.code == "MIGRATION_RESOURCE_LIMIT")
    assert issue.actual["kind"] == "total_rows"
    assert issue.table is None


def test_preflight_capacity_failure_is_machine_readable(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "capacity.db"
    _create_v01(database, project_root)
    monkeypatch.setattr(
        migrations.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=1, used=1, free=0),
    )

    report = preflight_migration(
        database, create_backup=False, minimum_free_bytes=4096
    )

    issue = next(
        item for item in report.issues if item.code == "MIGRATION_CAPACITY_INSUFFICIENT"
    )
    assert not report.is_ready
    assert issue.actual == {"required": report.required_free_bytes, "available": 0}


def test_backup_temp_identity_and_cleanup_are_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "project.db"
    database.touch()
    temporary, identity = migrations._secure_backup_temp(database)
    try:
        migrations._assert_private_regular_file(temporary, identity)
        assert not migrations._unlink_if_identity(temporary, (identity[0], identity[1] + 1))
        assert temporary.exists()
        assert not migrations._unlink_if_identity(tmp_path, identity)
        assert migrations._unlink_if_identity(temporary, identity)
        assert not temporary.exists()
        assert not migrations._unlink_if_identity(temporary, identity)
    finally:
        temporary.unlink(missing_ok=True)


def test_backup_identity_rejects_directory_and_replaced_file(tmp_path: Path) -> None:
    regular = tmp_path / "regular.tmp"
    regular.write_bytes(b"data")
    info = regular.stat()
    identity = (int(info.st_dev), int(info.st_ino))

    with pytest.raises(MigrationError, match="not a regular file"):
        migrations._assert_private_regular_file(tmp_path, identity)
    with pytest.raises(MigrationError, match="identity changed"):
        migrations._assert_private_regular_file(regular, (identity[0], identity[1] + 1))


def test_backup_publish_failure_removes_only_new_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "project.db"
    database.touch()
    temporary, identity = migrations._secure_backup_temp(database)
    destination = tmp_path / "project.db.pre-v3.bak"

    def fail_directory_sync(_path: Path) -> None:
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(migrations, "_fsync_directory", fail_directory_sync)
    try:
        with pytest.raises(OSError, match="directory sync"):
            migrations._publish_backup(temporary, destination, identity)
        assert temporary.exists()
        assert not destination.exists()
    finally:
        temporary.unlink(missing_ok=True)


def test_backup_publish_never_replaces_existing_destination(tmp_path: Path) -> None:
    database = tmp_path / "project.db"
    database.touch()
    temporary, identity = migrations._secure_backup_temp(database)
    destination = tmp_path / "project.db.pre-v3.bak"
    destination.write_bytes(b"operator backup")
    try:
        with pytest.raises(MigrationError, match="already exists"):
            migrations._publish_backup(temporary, destination, identity)
        assert destination.read_bytes() == b"operator backup"
        assert temporary.exists()
    finally:
        temporary.unlink(missing_ok=True)


def test_validate_v2_reports_corrupt_domain_rows_without_leaking_content(
    tmp_path: Path,
) -> None:
    database = tmp_path / "corrupt-v2.db"
    with Storage(database) as storage:
        _, snapshot, _ = ingest_content(storage, "first\nsecond\n", "story", "alpha")
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        claim = ClaimGovernance(storage).propose(
            ClaimProposal(persona_id="mira", continuity="alpha", text="claim"),
            [evidence],
        )
        event = storage.create_narrative_event(
            NarrativeEvent(
                persona_id="mira",
                continuity="alpha",
                event_type="narrative",
                title="title",
                summary="summary",
            ),
            [evidence],
        )

    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA ignore_check_constraints = ON")
        for name, in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall():
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "UPDATE sources SET source_key = ?, continuity = '', created_at = '', "
            "updated_at = 7",
            ("unsafe\nsource",),
        )
        connection.execute(
            "UPDATE source_snapshots SET source_id = 'missing-source', media_type = '', "
            "content = ?, content_hash = 'bad', line_count = 99, version = 0, "
            "created_at = 'not-a-time' WHERE snapshot_id = ?",
            (sqlite3.Binary(b"not text"), snapshot.snapshot_id),
        )
        connection.execute(
            "UPDATE claim_proposals SET persona_id = '', continuity = ?, text = '   ', "
            "access_policy = 'unknown', status = 'UNKNOWN', confidence = 2, "
            "valid_from = '2026-02-02T00:00:00Z', valid_to = '2026-01-01T00:00:00Z', "
            "knowledge_from = 'not-a-time', created_at = '', updated_at = 5 "
            "WHERE claim_id = ?",
            ("unsafe\u202econtinuity", claim.claim_id),
        )
        connection.execute(
            "UPDATE evidence_refs SET snapshot_id = 'missing-snapshot', start_line = 0, "
            "end_line = -1, start_char = -1, end_char = -2, quote = ?, "
            "content_hash = 'bad' WHERE claim_id = ?",
            ("private quote", claim.claim_id),
        )
        connection.execute(
            "UPDATE narrative_events SET persona_id = '', continuity = ?, event_type = '', "
            "access_policy = 'unknown', valid_from = 'not-a-time', created_at = '', "
            "details_json = '[]' WHERE event_id = ?",
            ("unsafe\ncontinuity", event.event_id),
        )
        connection.commit()

        issues = validate_migration_data(connection, SchemaKind.V02)

    codes = {issue.code for issue in issues}
    assert {
        "MIGRATION_REQUIRED_TEXT_MISSING",
        "MIGRATION_TIME_REQUIRED",
        "MIGRATION_TIME_INVALID",
        "MIGRATION_SNAPSHOT_SOURCE_MISSING",
        "MIGRATION_SNAPSHOT_CONTENT_INVALID",
        "MIGRATION_SNAPSHOT_HASH_INVALID",
        "MIGRATION_SNAPSHOT_LINE_COUNT_INVALID",
        "MIGRATION_SNAPSHOT_VERSION_INVALID",
        "MIGRATION_ACCESS_INVALID",
        "MIGRATION_STATUS_INVALID",
        "MIGRATION_CONFIDENCE_INVALID",
        "MIGRATION_INTERVAL_INVALID",
        "MIGRATION_EVIDENCE_REFERENCE_MISSING",
        "MIGRATION_EVENT_DETAILS_INVALID",
    } <= codes
    encoded = json.dumps([issue.to_dict() for issue in issues], ensure_ascii=False)
    assert "private quote" not in encoded


@dataclass(frozen=True)
class _PayloadRecord:
    label: str


def test_ledger_json_encoder_preserves_supported_structural_types(storage: Storage) -> None:
    storage.append_ledger(
        "custom.recorded",
        "coverage",
        "json-types",
        {
            "enum": AccessPolicy.HIDDEN,
            "dataclass": _PayloadRecord("record"),
            "path": Path("relative/story.txt"),
            "set": {"beta", "alpha"},
            "bytes": b"\x00\xff",
            "opaque": object(),
        },
    )

    payload = storage.list_ledger_entries(
        event_type="custom.recorded", aggregate_id="json-types"
    )[0].payload
    assert payload["enum"] == "hidden"
    assert payload["dataclass"] == {"label": "record"}
    assert payload["path"] == str(Path("relative/story.txt"))
    assert payload["set"] == ["alpha", "beta"]
    assert payload["bytes"] == {"encoding": "hex", "value": "00ff"}
    assert isinstance(payload["opaque"], str)


def test_json_helpers_cover_enum_and_corrupt_persisted_fallbacks() -> None:
    assert storage_module._json_default(AccessPolicy.HIDDEN) == "hidden"
    fallback = {"safe": True}
    assert storage_module._parse_json(None, fallback=fallback) is fallback
    assert storage_module._parse_json("not-json", fallback=fallback) is fallback
    assert storage_module._parse_json('{"valid":true}', fallback=fallback) == {
        "valid": True
    }


def _deep_object(depth: int) -> dict[str, object]:
    root: dict[str, object] = {}
    cursor = root
    for _ in range(depth):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    return root


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ([], TypeError),
        ({1: "value"}, TypeError),
        ({"value": math.nan}, ValueError),
        ({"value": object()}, TypeError),
        ({"value": "\ud800"}, ValueError),
    ],
)
def test_strict_event_json_rejects_non_json_values(value: object, error: type[Exception]) -> None:
    with pytest.raises(error):
        storage_module._strict_json_object(value)


def test_strict_event_json_rejects_cycles_shared_containers_and_depth() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    shared: list[object] = []

    with pytest.raises(ValueError, match="cyclic/shared"):
        storage_module._strict_json_object(cyclic)
    with pytest.raises(ValueError, match="cyclic/shared"):
        storage_module._strict_json_object({"left": shared, "right": shared})
    with pytest.raises(ValueError, match="nesting limit"):
        storage_module._strict_json_object(_deep_object(130))


def test_strict_event_json_enforces_utf8_byte_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "MAX_EVENT_DETAILS_JSON_BYTES", 10)
    with pytest.raises(ValueError, match="byte limit"):
        storage_module._strict_json_object({"value": "0123456789"})


@pytest.mark.parametrize(
    "event_type",
    [123, "   ", "\ud800", "x" * 4097, "safe\nunsafe", "safe\u202eunsafe"],
)
def test_ledger_metadata_validation_is_atomic(storage: Storage, event_type: object) -> None:
    before = len(storage.list_ledger_entries())
    with pytest.raises((TypeError, ValueError)):
        storage.append_ledger(event_type, "aggregate", "id")  # type: ignore[arg-type]
    assert len(storage.list_ledger_entries()) == before


def test_claim_proposal_validation_and_text_synthesis_are_atomic(storage: Storage) -> None:
    before = storage.connection.execute("SELECT COUNT(*) FROM claim_proposals").fetchone()[0]
    with pytest.raises(TypeError, match="must be ClaimProposal"):
        storage.create_claim_proposal("claim")  # type: ignore[arg-type]
    with pytest.raises(InvalidTransitionError, match="start as PROPOSED"):
        storage.create_claim_proposal(
            ClaimProposal(
                persona_id="mira",
                continuity="alpha",
                text="claim",
                status=GovernanceStatus.AUTHORIZED,
            )
        )
    with pytest.raises(ValueError, match="confidence"):
        storage.create_claim_proposal(
            ClaimProposal(
                persona_id="mira", continuity="alpha", text="claim", confidence=2
            )
        )
    with pytest.raises(ValueError, match="claim text"):
        storage.create_claim_proposal(
            ClaimProposal(persona_id="mira", continuity="alpha", text="   ")
        )

    synthesized = storage.create_claim_proposal(
        ClaimProposal(
            persona_id="mira",
            continuity="alpha",
            text="",
            subject="Mira",
            predicate="entered",
            object_value="the archive",
        )
    )
    assert synthesized.text == "Mira entered the archive"
    assert storage.connection.execute(
        "SELECT COUNT(*) FROM claim_proposals"
    ).fetchone()[0] == before + 1


@pytest.mark.parametrize(
    "evidence",
    [
        "not-evidence",
        EvidenceRef("missing", 1, 1),
        EvidenceRef("SNAPSHOT", 0, 1),
        EvidenceRef("SNAPSHOT", 1, 1, end_char=1),
        EvidenceRef("SNAPSHOT", 1, 1, start_char=-1),
        EvidenceRef("SNAPSHOT", 1, 1, start_char=2, end_char=1),
    ],
)
def test_claim_evidence_validation_rolls_back_partial_claim(
    storage: Storage, evidence: object
) -> None:
    _, snapshot, _ = ingest_content(storage, "line\n", "story", "alpha")
    if isinstance(evidence, EvidenceRef) and evidence.snapshot_id == "SNAPSHOT":
        evidence = EvidenceRef(
            snapshot.snapshot_id,
            evidence.start_line,
            evidence.end_line,
            start_char=evidence.start_char,
            end_char=evidence.end_char,
        )
    proposal = ClaimProposal(
        persona_id="mira", continuity="alpha", text="atomic evidence validation"
    )
    before = storage.connection.execute("SELECT COUNT(*) FROM claim_proposals").fetchone()[0]

    with pytest.raises((TypeError, ValueError, NotFoundError)):
        storage.create_claim_proposal(proposal, [evidence])  # type: ignore[list-item]

    assert storage.connection.execute(
        "SELECT COUNT(*) FROM claim_proposals"
    ).fetchone()[0] == before


def test_nested_transaction_rolls_back_only_failed_savepoint(storage: Storage) -> None:
    with storage.transaction() as connection:
        connection.execute("CREATE TEMP TABLE transaction_probe (value INTEGER)")
        connection.execute("INSERT INTO transaction_probe VALUES (1)")
        with pytest.raises(RuntimeError, match="inner"):
            with storage.transaction() as nested:
                nested.execute("INSERT INTO transaction_probe VALUES (2)")
                raise RuntimeError("inner")
        connection.execute("INSERT INTO transaction_probe VALUES (3)")

    assert [
        tuple(row)
        for row in storage.connection.execute(
            "SELECT value FROM transaction_probe ORDER BY value"
        ).fetchall()
    ] == [(1,), (3,)]


def test_outer_transaction_and_close_roll_back_uncommitted_writes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rollback.db"
    storage = Storage(database)
    with pytest.raises(RuntimeError, match="outer"):
        with storage.transaction() as connection:
            connection.execute(
                "UPDATE schema_metadata SET migration_notes = 'outer-write' WHERE singleton = 1"
            )
            raise RuntimeError("outer")
    assert storage.connection.execute(
        "SELECT migration_notes FROM schema_metadata WHERE singleton = 1"
    ).fetchone()[0] != "outer-write"

    storage.connection.execute("BEGIN IMMEDIATE")
    storage.connection.execute(
        "UPDATE schema_metadata SET migration_notes = 'close-write' WHERE singleton = 1"
    )
    storage.close()
    storage.close()
    with Storage(database) as reopened:
        assert reopened.connection.execute(
            "SELECT migration_notes FROM schema_metadata WHERE singleton = 1"
        ).fetchone()[0] != "close-write"


def test_read_transaction_nests_reuses_writer_and_cleans_up(storage: Storage) -> None:
    assert not storage.connection.in_transaction
    with storage.read_transaction() as connection:
        assert connection.in_transaction
        with storage.read_transaction() as nested:
            assert nested is connection and nested.in_transaction
    assert not storage.connection.in_transaction

    with pytest.raises(RuntimeError, match="read failure"):
        with storage.read_transaction() as connection:
            assert connection.in_transaction
            raise RuntimeError("read failure")
    assert not storage.connection.in_transaction

    with storage.transaction() as writer:
        with storage.read_transaction() as reader:
            assert reader is writer and reader.in_transaction


def test_lazy_initialize_and_readonly_memory_boundary(tmp_path: Path) -> None:
    database = tmp_path / "nested" / "lazy.db"
    storage = Storage(database, initialize=False)
    assert not database.exists()
    assert storage.connection.execute("SELECT 1").fetchone()[0] == 1
    assert database.exists()
    assert storage.initialize() is storage
    storage.close()

    with pytest.raises(ReadOnlyStorageError, match="requires a database path"):
        Storage(":memory:", readonly=True)


def test_storage_lookup_and_filter_boundaries(storage: Storage) -> None:
    source_a, snapshot_a, _ = ingest_content(storage, "alpha\n", "story", "alpha")
    source_b, snapshot_b, _ = ingest_content(storage, "beta\n", "story", "beta")
    evidence = build_evidence_ref(storage, snapshot_a.snapshot_id, 1, 1)
    claim = ClaimGovernance(storage).propose(
        ClaimProposal(persona_id="mira", continuity="alpha", text="claim"),
        [evidence],
    )
    event = storage.create_narrative_event(
        NarrativeEvent(
            persona_id="mira",
            continuity="alpha",
            title="event",
            summary="alpha",
            knowledge_from="2026-01-01T00:00:00Z",
        ),
        [evidence],
    )

    with pytest.raises(TypeError, match="source_id or source_key"):
        storage.get_source()
    with pytest.raises(ContinuityViolation, match="more than one continuity"):
        storage.get_source(source_key="story")
    assert storage.get_source(source_key="story", continuity="alpha") == source_a
    assert storage.list_sources(continuity="beta") == [source_b]
    assert storage.list_snapshots(source_key="story", continuity="alpha") == [snapshot_a]
    assert storage.list_snapshots(source_id=source_b.source_id) == [snapshot_b]
    assert storage.list_claim_proposals(
        persona_id="mira",
        continuity="alpha",
        status="PROPOSED",
        access_policy="agent_accessible",
        snapshot_id=snapshot_a.snapshot_id,
        limit=1,
        offset=-9,
    ) == [claim]
    with pytest.raises(ValueError, match="limit must be non-negative"):
        storage.list_claim_proposals(limit=-1)
    assert storage.get_claim_evidence(claim.claim_id)
    assert storage.get_event_evidence(event.event_id)


@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("get_source", ("missing",)),
        ("get_snapshot", ("missing",)),
        ("get_latest_snapshot", ("missing",)),
        ("get_claim_proposal", ("missing",)),
        ("get_claim_evidence", ("missing",)),
        ("get_narrative_event", ("missing",)),
        ("get_event_evidence", ("missing",)),
        ("add_claim_evidence", ("missing", EvidenceRef("missing", 1, 1))),
    ],
)
def test_storage_missing_entity_errors_are_stable(
    storage: Storage, method: str, arguments: tuple[object, ...]
) -> None:
    with pytest.raises(NotFoundError, match="not found|no snapshots"):
        getattr(storage, method)(*arguments)


def test_cutoff_and_event_filter_parameter_boundaries(storage: Storage) -> None:
    _, snapshot, _ = ingest_content(storage, "event\n", "story", "alpha")
    event = storage.create_narrative_event(
        NarrativeEvent(
            persona_id="mira",
            continuity="alpha",
            title="event",
            summary="event",
            valid_from="2026-01-01T00:00:00Z",
            knowledge_from="2026-01-01T00:00:00Z",
        ),
        [build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)],
    )
    cutoff = MemoryCutoff(
        "mira",
        "alpha",
        "2026-01-02T00:00:00Z",
        valid_at="2026-01-02T00:00:00Z",
    )

    assert storage.list_narrative_events(cutoff=cutoff) == [event]
    assert storage.list_narrative_events(access_policies=()) == []
    assert storage.query_claims_for_cutoff(
        MemoryCutoff("mira", "alpha", "2026-01-02T00:00:00Z", access_policies=())
    ) == []
    with pytest.raises(ValueError, match="persona_id conflicts"):
        storage.list_narrative_events(persona_id="other", cutoff=cutoff)
    with pytest.raises(ContinuityViolation, match="continuity conflicts"):
        storage.list_narrative_events(continuity="beta", cutoff=cutoff)


def test_ledger_filters_limits_and_non_mapping_payload_fallback(storage: Storage) -> None:
    custom = storage.append_ledger("custom", "thing", "one", {"value": 1})
    assert storage.list_ledger_entries(after_sequence=-5, event_type="custom") == [custom]
    assert storage.list_ledger_entries(aggregate_type="thing", aggregate_id="one", limit=0) == []
    with pytest.raises(ValueError, match="limit must be non-negative"):
        storage.list_ledger_entries(limit=-1)

    storage.connection.execute("DROP TRIGGER continuityforge_ledger_no_update")
    storage.connection.execute(
        "UPDATE event_ledger SET payload_json = '[]' WHERE entry_id = ?",
        (custom.entry_id,),
    )
    fallback = storage.list_ledger_entries(event_type="custom")[0]
    assert fallback.payload == {"value": []}


@pytest.mark.parametrize("corruption", ["sequence", "previous", "digest"])
def test_ledger_verification_distinguishes_corruption(
    tmp_path: Path, corruption: str
) -> None:
    database = tmp_path / f"ledger-{corruption}.db"
    with Storage(database) as storage:
        storage.append_ledger("custom", "thing", "one", {})
        storage.connection.execute("DROP TRIGGER continuityforge_ledger_no_update")
        storage.connection.execute("DROP TRIGGER continuityforge_ledger_no_delete")
        if corruption == "sequence":
            storage.connection.execute("DELETE FROM event_ledger WHERE sequence = 1")
        elif corruption == "previous":
            storage.connection.execute(
                "UPDATE event_ledger SET previous_hash = ? WHERE sequence = 1",
                ("1" * 64,),
            )
        else:
            storage.connection.execute(
                "UPDATE event_ledger SET entry_hash = ? WHERE sequence = 1",
                ("f" * 64,),
            )

        assert storage.verify_ledger() is False
        with pytest.raises(LedgerIntegrityError):
            storage.verify_ledger(raise_on_error=True)
