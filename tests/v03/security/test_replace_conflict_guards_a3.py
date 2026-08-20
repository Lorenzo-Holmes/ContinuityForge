from __future__ import annotations

from dataclasses import replace
import sqlite3

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.governance import ClaimGovernance
from continuityforge.models import ClaimProposal, GovernanceStatus, NarrativeEvent
from continuityforge.schema import SchemaKind, fingerprint_schema
from continuityforge.storage import Storage


_A3_SCHEMA_DIGEST = "f6f99a75e0f036fe511bc394eb58f1b39571731dee84283b9be3e554a6a16171"


def _row(connection: sqlite3.Connection, table: str, key: str, value: object) -> dict:
    result = connection.execute(
        f'SELECT * FROM "{table}" WHERE "{key}" = ?', (value,)
    ).fetchone()
    assert result is not None
    return dict(result)


def _table_rows(connection: sqlite3.Connection, table: str) -> list[tuple]:
    return [
        tuple(row)
        for row in connection.execute(
            f'SELECT * FROM "{table}" ORDER BY rowid'
        ).fetchall()
    ]


def _assert_replace_rejected(
    connection: sqlite3.Connection,
    table: str,
    values: dict,
    *,
    message: str,
) -> None:
    before = _table_rows(connection, table)
    columns = tuple(values)
    identifiers = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join("?" for _ in columns)

    with pytest.raises(sqlite3.IntegrityError, match=message):
        connection.execute(
            f'INSERT OR REPLACE INTO "{table}" ({identifiers}) '
            f"VALUES ({placeholders})",
            tuple(values[column] for column in columns),
        )

    assert _table_rows(connection, table) == before


def _insert_source(
    connection: sqlite3.Connection,
    *,
    source_id: str,
    source_key: str,
) -> None:
    connection.execute(
        "INSERT INTO sources "
        "(source_id, source_key, continuity, created_at, updated_at) "
        "VALUES (?, ?, 'alpha', '2026-08-20T00:00:00Z', '2026-08-20T00:00:00Z')",
        (source_id, source_key),
    )


def test_storage_enables_replace_delete_trigger_barrier_without_schema_change(
    tmp_path,
) -> None:
    database = tmp_path / "published-a3.db"

    with Storage(database) as storage:
        connection = storage.connection
        assert connection.execute("PRAGMA recursive_triggers").fetchone()[0] == 1
        fingerprint = fingerprint_schema(connection)
        assert fingerprint.kind is SchemaKind.V03
        assert fingerprint.digest == _A3_SCHEMA_DIGEST

    with Storage(database) as reopened:
        assert reopened.migration_report is not None
        assert reopened.migration_report.status == "already-current"
        assert reopened.connection.execute(
            "PRAGMA recursive_triggers"
        ).fetchone()[0] == 1
        assert fingerprint_schema(reopened.connection).digest == _A3_SCHEMA_DIGEST

    assert list(tmp_path.glob("published-a3.db.pre-v3*.bak")) == []


def test_sources_and_snapshots_reject_replace_on_primary_and_unique_conflicts(
    storage: Storage,
) -> None:
    connection = storage.connection
    _insert_source(connection, source_id="src_replace", source_key="replace/source")
    source = _row(connection, "sources", "source_id", "src_replace")

    primary_conflict = dict(source, source_key="replace/primary-conflict")
    _assert_replace_rejected(
        connection,
        "sources",
        primary_conflict,
        message="Source rows cannot be deleted",
    )

    identity_unique_conflict = dict(source, source_id="src_unique_conflict")
    _assert_replace_rejected(
        connection,
        "sources",
        identity_unique_conflict,
        message="Source rows cannot be deleted",
    )
    assert connection.execute(
        "SELECT 1 FROM sources WHERE source_id = 'src_unique_conflict'"
    ).fetchone() is None

    _, snapshot, _ = storage.ingest_snapshot(
        "replace/snapshot", "alpha", "immutable snapshot\n"
    )
    _insert_source(
        connection,
        source_id="src_snapshot_primary_target",
        source_key="replace/snapshot-primary-target",
    )
    snapshot_row = _row(
        connection, "source_snapshots", "snapshot_id", snapshot.snapshot_id
    )

    snapshot_primary_conflict = dict(
        snapshot_row, source_id="src_snapshot_primary_target"
    )
    _assert_replace_rejected(
        connection,
        "source_snapshots",
        snapshot_primary_conflict,
        message="SourceSnapshot rows are immutable",
    )

    snapshot_version_unique_conflict = dict(
        snapshot_row, snapshot_id="snp_unique_conflict"
    )
    _assert_replace_rejected(
        connection,
        "source_snapshots",
        snapshot_version_unique_conflict,
        message="SourceSnapshot rows are immutable",
    )
    assert connection.execute(
        "SELECT 1 FROM source_snapshots WHERE snapshot_id = 'snp_unique_conflict'"
    ).fetchone() is None


def test_all_other_immutable_tables_reject_replace_conflicts(storage: Storage) -> None:
    connection = storage.connection
    _, snapshot, _ = storage.ingest_snapshot(
        "replace/domain", "alpha", "immutable domain evidence\n"
    )
    evidence = replace(
        build_evidence_ref(storage, snapshot.snapshot_id, 1, 1),
        start_char=0,
        end_char=1,
    )
    pending = ClaimGovernance(storage).propose(
        ClaimProposal(
            claim_id="clm_replace_pending",
            persona_id="persona",
            continuity="alpha",
            text="immutable domain evidence",
        ),
        (evidence,),
    )
    claim_row = _row(connection, "claim_proposals", "claim_id", pending.claim_id)
    _assert_replace_rejected(
        connection,
        "claim_proposals",
        claim_row,
        message="ClaimProposal rows cannot be deleted",
    )

    evidence_row = connection.execute(
        "SELECT * FROM evidence_refs WHERE claim_id = ?", (pending.claim_id,)
    ).fetchone()
    assert evidence_row is not None
    evidence_values = dict(evidence_row)
    _assert_replace_rejected(
        connection,
        "evidence_refs",
        dict(evidence_values, end_char=2),
        message="EvidenceRef rows are immutable",
    )
    _assert_replace_rejected(
        connection,
        "evidence_refs",
        dict(evidence_values, evidence_id="evr_unique_conflict"),
        message="EvidenceRef rows are immutable",
    )

    authorized = ClaimGovernance(storage).add_authorized_human_claim(
        ClaimProposal(
            claim_id="clm_replace_decision",
            persona_id="persona",
            continuity="alpha",
            text="immutable decision evidence",
        ),
        (build_evidence_ref(storage, snapshot.snapshot_id, 1, 1),),
        reviewer="reviewer",
        reason="the immutable source directly supports this claim",
    )
    decision_row = connection.execute(
        "SELECT * FROM governance_decisions WHERE claim_id = ?",
        (authorized.claim_id,),
    ).fetchone()
    assert decision_row is not None
    _assert_replace_rejected(
        connection,
        "governance_decisions",
        dict(
            dict(decision_row),
            from_status=GovernanceStatus.AUTHORIZED.value,
            to_status=GovernanceStatus.DISPUTED.value,
        ),
        message="GovernanceDecision rows are immutable",
    )

    event = storage.create_narrative_event(
        NarrativeEvent(
            event_id="evt_replace",
            persona_id="persona",
            continuity="alpha",
            title="Immutable event",
            summary="immutable domain evidence",
        ),
        (
            replace(
                build_evidence_ref(storage, snapshot.snapshot_id, 1, 1),
                start_char=0,
                end_char=1,
            ),
        ),
    )
    event_row = _row(connection, "narrative_events", "event_id", event.event_id)
    _assert_replace_rejected(
        connection,
        "narrative_events",
        event_row,
        message="NarrativeEvent rows are immutable",
    )

    event_evidence_row = connection.execute(
        "SELECT * FROM event_evidence_refs WHERE event_id = ?", (event.event_id,)
    ).fetchone()
    assert event_evidence_row is not None
    event_evidence_values = dict(event_evidence_row)
    _assert_replace_rejected(
        connection,
        "event_evidence_refs",
        dict(event_evidence_values, end_char=2),
        message="NarrativeEvent EvidenceRef rows are immutable",
    )
    _assert_replace_rejected(
        connection,
        "event_evidence_refs",
        dict(event_evidence_values, evidence_id="evr_event_unique_conflict"),
        message="NarrativeEvent EvidenceRef rows are immutable",
    )

    ledger_row = connection.execute(
        "SELECT * FROM event_ledger ORDER BY sequence LIMIT 1"
    ).fetchone()
    assert ledger_row is not None
    ledger_values = dict(ledger_row)
    maximum_sequence = connection.execute(
        "SELECT MAX(sequence) FROM event_ledger"
    ).fetchone()[0]
    _assert_replace_rejected(
        connection,
        "event_ledger",
        dict(
            ledger_values,
            entry_id="led_primary_conflict",
            entry_hash="a" * 64,
        ),
        message="EventLedger is append-only",
    )
    _assert_replace_rejected(
        connection,
        "event_ledger",
        dict(
            ledger_values,
            sequence=maximum_sequence + 1,
            entry_hash="b" * 64,
        ),
        message="EventLedger is append-only",
    )
    _assert_replace_rejected(
        connection,
        "event_ledger",
        dict(
            ledger_values,
            sequence=maximum_sequence + 1,
            entry_id="led_hash_conflict",
        ),
        message="EventLedger is append-only",
    )


def test_storage_connection_docstring_marks_raw_sql_as_unsafe() -> None:
    documentation = Storage.connection.__doc__ or ""

    assert "unsafe writable compatibility escape hatch" in documentation
    assert "Storage.open_readonly" in documentation
    assert "ReadOnlyProject" in documentation
