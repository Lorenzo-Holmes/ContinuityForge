from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

import pytest

from continuityforge.audit_material import (
    CLAIM_CREATION_EVENT,
    EVENT_CREATION_EVENT,
    MATERIAL_ATTESTATION_KEYS,
    MATERIAL_VERSION,
    build_material_attestation_payload,
    claim_material_digests,
    event_material_digests,
)
from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import MigrationError
from continuityforge.governance import ClaimGovernance
from continuityforge.migrations import migrate_to_v3, preflight_migration
from continuityforge.models import ClaimProposal, NarrativeEvent
from continuityforge.schema import (
    SchemaKind,
    V02_REQUIRED_TRIGGERS,
    V03_ALPHA2_REQUIRED_TRIGGERS,
    V03_ALPHA3_REQUIRED_TRIGGERS,
    V03_ALPHA3_SCHEMA_DIGEST,
    V03_REQUIRED_TRIGGERS,
    fingerprint_schema,
)
from continuityforge.storage import Storage


_MATERIAL_FIELDS = {
    "material_version",
    "aggregate_sha256",
    "evidence_set_sha256",
}
_CREATION_EVENTS = {"claim.proposed", "narrative_event.created"}
_ATTESTATION_EVENTS = {
    "claim.material_attested",
    "narrative_event.material_attested",
}


def _rehash_ledger(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT * FROM event_ledger ORDER BY sequence"
    ).fetchall()
    previous_hash = "0" * 64
    for row in rows:
        entry_hash = Storage._ledger_digest(
            sequence=int(row["sequence"]),
            entry_id=str(row["entry_id"]),
            event_type=str(row["event_type"]),
            aggregate_type=str(row["aggregate_type"]),
            aggregate_id=str(row["aggregate_id"]),
            payload_json=str(row["payload_json"]),
            previous_hash=previous_hash,
            created_at=str(row["created_at"]),
        )
        connection.execute(
            "UPDATE event_ledger SET previous_hash = ?, entry_hash = ? "
            "WHERE sequence = ?",
            (previous_hash, entry_hash, int(row["sequence"])),
        )
        previous_hash = entry_hash


def _make_v03_alpha3(
    database: Path,
    *,
    with_added_evidence: bool = False,
    with_second_event_evidence: bool = False,
    authorize_claim: bool = False,
) -> dict[tuple[str, str], str]:
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot(
            "alpha3/material", "alpha", "material anchor\n"
        )
        evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
        governance = ClaimGovernance(storage)
        governance.propose(
            ClaimProposal(
                claim_id="clm_alpha3_material",
                persona_id="persona",
                continuity="alpha",
                text="material anchor",
                subject="subject omitted by the legacy creation payload",
                rationale="rationale omitted by the legacy creation payload",
            ),
            (evidence,),
        )
        if with_added_evidence:
            _, second_snapshot, _ = storage.ingest_snapshot(
                "alpha3/material", "alpha", "material anchor\nsecond anchor\n"
            )
            storage.add_claim_evidence(
                "clm_alpha3_material",
                build_evidence_ref(storage, second_snapshot.snapshot_id, 2, 2),
            )
        if authorize_claim:
            governance.review(
                "clm_alpha3_material",
                "AUTHORIZED",
                reviewer="migration-test",
                reason="the exact source span supports the claim",
            )
        event_evidence = [evidence]
        if with_second_event_evidence:
            event_evidence.append(
                build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
            )
        storage.create_narrative_event(
            NarrativeEvent(
                event_id="evt_alpha3_material",
                persona_id="persona",
                continuity="alpha",
                title="Legacy title",
                summary="material anchor",
                details={"omitted": "legacy creation payload"},
                valid_to="2030-01-01T00:00:00Z",
            ),
            tuple(event_evidence),
        )

    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        trigger_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        trigger_sql = {str(row["name"]): str(row["sql"]) for row in trigger_rows}
        for name in V03_REQUIRED_TRIGGERS - V03_ALPHA3_REQUIRED_TRIGGERS:
            connection.execute(f'DROP TRIGGER "{name}"')

        # Reproduce the exact pre-material a3 ledger without rewriting any
        # creation entry during the migration under test.
        for name in (
            "continuityforge_ledger_no_update",
            "continuityforge_ledger_no_delete",
        ):
            connection.execute(f'DROP TRIGGER "{name}"')
        rows = connection.execute(
            "SELECT sequence, payload_json FROM event_ledger "
            "WHERE event_type IN ('claim.proposed', 'narrative_event.created')"
        ).fetchall()
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            for field in _MATERIAL_FIELDS:
                payload.pop(field, None)
            connection.execute(
                "UPDATE event_ledger SET payload_json = ? WHERE sequence = ?",
                (
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    int(row["sequence"]),
                ),
            )
        _rehash_ledger(connection)
        for name in (
            "continuityforge_ledger_no_update",
            "continuityforge_ledger_no_delete",
        ):
            connection.execute(trigger_sql[name])
        connection.commit()

        fingerprint = fingerprint_schema(connection)
        assert fingerprint.kind is SchemaKind.V03_ALPHA3
        assert fingerprint.digest == V03_ALPHA3_SCHEMA_DIGEST
        creation_rows = connection.execute(
            "SELECT event_type, entry_id, payload_json FROM event_ledger "
            "WHERE event_type IN ('claim.proposed', 'narrative_event.created') "
            "ORDER BY sequence"
        ).fetchall()
        return {
            (str(row["event_type"]), str(row["entry_id"])): str(row["payload_json"])
            for row in creation_rows
        }


def _creation_payloads(database: Path) -> dict[tuple[str, str], str]:
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT event_type, entry_id, payload_json FROM event_ledger "
            "WHERE event_type IN ('claim.proposed', 'narrative_event.created') "
            "ORDER BY sequence"
        ).fetchall()
    return {(str(row[0]), str(row[1])): str(row[2]) for row in rows}


def _downgrade_alpha3_structure(database: Path, kind: SchemaKind) -> None:
    with closing(sqlite3.connect(database)) as connection:
        if kind is SchemaKind.V02:
            retained = V02_REQUIRED_TRIGGERS
            connection.execute("UPDATE schema_metadata SET schema_version = 2")
            connection.execute("PRAGMA user_version = 2")
        elif kind is SchemaKind.V03_ALPHA2:
            retained = V03_ALPHA2_REQUIRED_TRIGGERS
        else:  # pragma: no cover - test helper has a closed input set
            raise AssertionError(kind)
        for trigger in V03_ALPHA3_REQUIRED_TRIGGERS - retained:
            connection.execute(f'DROP TRIGGER "{trigger}"')
        connection.commit()
        assert fingerprint_schema(connection).kind is kind


def _database_sha256(database: Path) -> str:
    return sha256(database.read_bytes()).hexdigest()


def test_published_a3_shape_has_one_exact_fail_closed_classification(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-classification.db"
    _make_v03_alpha3(database)

    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
        connection.execute(
            "CREATE TRIGGER hostile_alpha3_alias BEFORE INSERT ON sources "
            "BEGIN SELECT 1; END"
        )
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.PARTIAL


def test_alpha3_material_requires_explicit_operator_attestation_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-opt-in.db"
    original_creation = _make_v03_alpha3(database)
    before = _database_sha256(database)

    report = preflight_migration(database, create_backup=True)

    assert report.source.kind is SchemaKind.V03_ALPHA3
    assert report.is_ready is False
    assert report.backup_path is None
    assert report.attestation_material_version == MATERIAL_VERSION
    assert dict(report.attestation_counts) == {"claims": 1, "events": 1}
    assert "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED" in {
        issue.code for issue in report.issues
    }
    assert _database_sha256(database) == before
    assert _creation_payloads(database) == original_creation
    assert list(tmp_path.glob("*.bak")) == []

    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(database, create_backup=True)
    assert caught.value.report is not None
    assert caught.value.report.backup_path is None
    assert _database_sha256(database) == before


@pytest.mark.parametrize("legacy_kind", (SchemaKind.V02, SchemaKind.V03_ALPHA2))
def test_older_partial_creation_edges_use_the_same_explicit_attestation_gate(
    tmp_path: Path,
    legacy_kind: SchemaKind,
) -> None:
    database = tmp_path / f"{legacy_kind.name.lower()}-material.db"
    original_creation = _make_v03_alpha3(database)
    _downgrade_alpha3_structure(database, legacy_kind)

    preflight = preflight_migration(database, create_backup=True)
    assert preflight.source.kind is legacy_kind
    assert preflight.backup_path is None
    assert "MIGRATION_LEGACY_MATERIAL_ATTESTATION_REQUIRED" in {
        issue.code for issue in preflight.issues
    }

    report = migrate_to_v3(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )
    assert report.source.kind is legacy_kind
    assert report.target is not None and report.target.kind is SchemaKind.V03
    assert dict(report.attestation_counts) == {"claims": 1, "events": 1}
    assert _creation_payloads(database) == original_creation
    with closing(sqlite3.connect(database)) as connection:
        source_kinds = {
            json.loads(str(row[0]))["migration_source_kind"]
            for row in connection.execute(
                "SELECT payload_json FROM event_ledger WHERE event_type IN "
                "('claim.material_attested', 'narrative_event.material_attested')"
            ).fetchall()
        }
    assert source_kinds == {legacy_kind.value}


def test_alpha3_opt_in_appends_bound_attestations_without_rewriting_creation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-migrate.db"
    original_creation = _make_v03_alpha3(database)

    report = migrate_to_v3(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert report.status == "migrated"
    assert report.source.kind is SchemaKind.V03_ALPHA3
    assert report.target is not None and report.target.kind is SchemaKind.V03
    assert report.target.digest != V03_ALPHA3_SCHEMA_DIGEST
    assert report.attestation_material_version == MATERIAL_VERSION
    assert dict(report.attestation_counts) == {"claims": 1, "events": 1}
    assert report.to_dict()["attestations"] == {
        "material_version": MATERIAL_VERSION,
        "claims": 1,
        "events": 1,
    }
    assert report.backup_path is not None
    assert _creation_payloads(database) == original_creation

    with closing(sqlite3.connect(report.backup_path)) as backup:
        assert fingerprint_schema(backup).kind is SchemaKind.V03_ALPHA3
        assert backup.execute(
            "SELECT COUNT(*) FROM event_ledger WHERE event_type IN "
            "('claim.material_attested', 'narrative_event.material_attested')"
        ).fetchone()[0] == 0

    with Storage.open_readonly(database) as storage:
        assert storage.verify_ledger()
        attestations = storage.connection.execute(
            "SELECT event_type, aggregate_type, aggregate_id, payload_json "
            "FROM event_ledger WHERE event_type IN "
            "('claim.material_attested', 'narrative_event.material_attested') "
            "ORDER BY sequence"
        ).fetchall()
    assert len(attestations) == 2
    for row in attestations:
        payload = json.loads(str(row["payload_json"]))
        assert set(payload) == MATERIAL_ATTESTATION_KEYS
        assert payload["material_version"] == MATERIAL_VERSION
        assert payload["migration_source_kind"] == SchemaKind.V03_ALPHA3.value
        expected_creation_type = (
            "claim.proposed"
            if row["event_type"] == "claim.material_attested"
            else "narrative_event.created"
        )
        assert payload["attested_event_type"] == expected_creation_type
        assert (
            expected_creation_type,
            payload["attested_entry_id"],
        ) in original_creation
        assert row["aggregate_type"] == (
            "claim"
            if row["event_type"] == "claim.material_attested"
            else "narrative_event"
        )


def test_preexisting_legacy_attestation_never_substitutes_for_current_opt_in(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-preexisting-attestation.db"
    _make_v03_alpha3(database)

    with closing(sqlite3.connect(database, isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        compatibility = Storage(database, initialize=False)
        compatibility._connection = connection
        claim_row = connection.execute(
            "SELECT * FROM claim_proposals WHERE claim_id = ?",
            ("clm_alpha3_material",),
        ).fetchone()
        event_row = connection.execute(
            "SELECT * FROM narrative_events WHERE event_id = ?",
            ("evt_alpha3_material",),
        ).fetchone()
        assert claim_row is not None and event_row is not None
        claim = compatibility._row_to_claim(claim_row)
        event = compatibility._row_to_event(event_row)
        claim_evidence = compatibility.get_claim_evidence(claim.claim_id)
        event_evidence = compatibility.get_event_evidence(event.event_id)
        creation_ids = {
            str(row["event_type"]): str(row["entry_id"])
            for row in connection.execute(
                "SELECT event_type, entry_id FROM event_ledger WHERE event_type IN "
                "('claim.proposed', 'narrative_event.created')"
            ).fetchall()
        }
        connection.execute("BEGIN IMMEDIATE")
        compatibility._append_ledger_in_transaction(
            connection,
            event_type="claim.material_attested",
            aggregate_type="claim",
            aggregate_id=claim.claim_id,
            payload=build_material_attestation_payload(
                claim_material_digests(claim, claim_evidence),
                attested_event_type=CLAIM_CREATION_EVENT,
                attested_entry_id=creation_ids[CLAIM_CREATION_EVENT],
                migration_source_kind=SchemaKind.V03_ALPHA3.value,
            ),
        )
        compatibility._append_ledger_in_transaction(
            connection,
            event_type="narrative_event.material_attested",
            aggregate_type="narrative_event",
            aggregate_id=event.event_id,
            payload=build_material_attestation_payload(
                event_material_digests(event, event_evidence),
                attested_event_type=EVENT_CREATION_EVENT,
                attested_entry_id=creation_ids[EVENT_CREATION_EVENT],
                migration_source_kind=SchemaKind.V03_ALPHA3.value,
            ),
        )
        connection.execute("COMMIT")
        compatibility._connection = None
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3

    for accepted in (False, True):
        report = preflight_migration(
            database,
            create_backup=True,
            attest_current_legacy_material=accepted,
        )
        assert report.is_ready is False
        assert report.backup_path is None
        assert "MIGRATION_MATERIAL_ATTESTATION_PREEXISTING" in {
            issue.code for issue in report.issues
        }

    with pytest.raises(MigrationError):
        migrate_to_v3(
            database,
            create_backup=True,
            attest_current_legacy_material=True,
        )
    assert list(tmp_path.glob("*.bak")) == []


def test_alpha3_attestation_and_trigger_installation_roll_back_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "alpha3-rollback.db"
    original_creation = _make_v03_alpha3(database)
    with closing(sqlite3.connect(database)) as connection:
        original_head = connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()

    monkeypatch.setattr(Storage, "verify_ledger", lambda _self: False)
    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(
            database,
            create_backup=True,
            attest_current_legacy_material=True,
        )

    assert caught.value.report is not None
    assert caught.value.report.status == "failed"
    assert caught.value.report.backup_path is not None
    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
        assert connection.execute(
            "SELECT COUNT(*) FROM event_ledger WHERE event_type IN "
            "('claim.material_attested', 'narrative_event.material_attested')"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT sequence, entry_hash FROM event_ledger "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone() == original_head
    assert _creation_payloads(database) == original_creation


@pytest.mark.parametrize(
    ("event_type", "aggregate_type", "payload"),
    [
        ("claim.proposed", "claim", {}),
        (
            "claim.proposed",
            "claim",
            {
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "claim.proposed",
            "claim",
            {
                "material_version": 2,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "claim.proposed",
            "claim",
            {
                "material_version": 2,
                "aggregate_sha256": "a" * 64,
            },
        ),
        (
            "claim.proposed",
            "narrative_event",
            {
                "material_version": 2,
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "narrative_event.created",
            "narrative_event",
            {
                "material_version": True,
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "claim.material_attested",
            "claim",
            {
                "material_version": 2,
                "aggregate_sha256": "A" * 64,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "claim.material_attested",
            "claim",
            {
                "material_version": 2,
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "b" * 64,
            },
        ),
        (
            "claim.material_attested",
            "claim",
            {
                "material_version": 2,
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "b" * 64,
                "attested_event_type": "claim.proposed",
                "attested_entry_id": "led_creation",
                "migration_source_kind": "v0.3-alpha3",
                "unexpected": True,
            },
        ),
        (
            "narrative_event.material_attested",
            "narrative_event",
            {
                "material_version": 2,
                "aggregate_sha256": "a" * 64,
                "evidence_set_sha256": "short",
            },
        ),
    ],
)
def test_final_material_trigger_rejects_invalid_ledger_material(
    storage: Storage,
    event_type: str,
    aggregate_type: str,
    payload: dict[str, object],
) -> None:
    previous = storage.connection.execute(
        "SELECT sequence, entry_hash FROM event_ledger ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    assert previous is not None

    with pytest.raises(sqlite3.IntegrityError, match="ledger material"):
        storage.connection.execute(
            "INSERT INTO event_ledger "
            "(sequence, entry_id, event_type, aggregate_type, aggregate_id, payload_json, "
            "previous_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(previous["sequence"]) + 1,
                "led_invalid_material",
                event_type,
                aggregate_type,
                "aggregate",
                json.dumps(payload, separators=(",", ":")),
                str(previous["entry_hash"]),
                "c" * 64,
                "2026-08-20T00:00:00Z",
            ),
        )


def test_final_and_alpha3_trigger_sets_differ_by_real_material_guard() -> None:
    assert V03_REQUIRED_TRIGGERS - V03_ALPHA3_REQUIRED_TRIGGERS == {
        "continuityforge_ledger_material_guard"
    }
    assert V03_ALPHA3_REQUIRED_TRIGGERS < V03_REQUIRED_TRIGGERS


@pytest.mark.parametrize("invalid", [None, 0, 1, "false"])
def test_material_attestation_opt_in_requires_a_strict_bool(
    tmp_path: Path, invalid: object
) -> None:
    database = tmp_path / "strict-bool.db"
    with Storage(database):
        pass

    with pytest.raises(TypeError, match="must be a bool"):
        preflight_migration(
            database,
            create_backup=False,
            attest_current_legacy_material=invalid,  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="must be a bool"):
        migrate_to_v3(
            database,
            create_backup=False,
            attest_current_legacy_material=invalid,  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="must be a bool"):
        Storage(
            database,
            initialize=False,
            attest_current_legacy_material=invalid,  # type: ignore[arg-type]
        )


def test_legacy_material_acceptance_cannot_write_without_verified_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-no-backup.db"
    original_creation = _make_v03_alpha3(database)
    before = _database_sha256(database)
    backups_before = set(tmp_path.glob("alpha3-no-backup.db.pre-v3*.bak"))

    inspection = preflight_migration(
        database,
        create_backup=False,
        attest_current_legacy_material=True,
    )
    assert inspection.is_ready
    assert inspection.backup_path is None

    with pytest.raises(MigrationError) as caught:
        migrate_to_v3(
            database,
            create_backup=False,
            attest_current_legacy_material=True,
        )

    assert caught.value.report is not None
    assert "MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP" in {
        issue.code for issue in caught.value.report.issues
    }
    assert caught.value.report.backup_path is None
    assert _database_sha256(database) == before
    assert _creation_payloads(database) == original_creation
    with closing(sqlite3.connect(database)) as connection:
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
    assert set(tmp_path.glob("alpha3-no-backup.db.pre-v3*.bak")) == backups_before


def test_alpha3_claim_updated_at_mismatch_fails_before_backup(tmp_path: Path) -> None:
    database = tmp_path / "alpha3-updated-at.db"
    _make_v03_alpha3(database)
    with closing(sqlite3.connect(database)) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            ("continuityforge_claims_status_transition",),
        ).fetchone()[0]
        connection.execute("DROP TRIGGER continuityforge_claims_status_transition")
        connection.execute(
            "UPDATE claim_proposals SET updated_at = ? WHERE claim_id = ?",
            ("2029-01-01T00:00:00Z", "clm_alpha3_material"),
        )
        connection.execute(str(trigger_sql))
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
    backups_before = set(tmp_path.glob("alpha3-updated-at.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_CLAIM_UPDATED_AT_REPLAY_MISMATCH" in {
        issue.code for issue in report.issues
    }
    assert set(tmp_path.glob("alpha3-updated-at.db.pre-v3*.bak")) == backups_before


def test_alpha3_decision_timestamp_must_match_ledger_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-decision-time.db"
    _make_v03_alpha3(database, authorize_claim=True)
    with closing(sqlite3.connect(database)) as connection:
        trigger_sql = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name IN (?, ?)",
                (
                    "continuityforge_claims_status_transition",
                    "continuityforge_decisions_no_update",
                ),
            ).fetchall()
        }
        for name in trigger_sql:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "UPDATE governance_decisions SET decided_at = ? WHERE claim_id = ?",
            ("2030-01-01T00:00:00Z", "clm_alpha3_material"),
        )
        connection.execute(
            "UPDATE claim_proposals SET updated_at = ? WHERE claim_id = ?",
            ("2030-01-01T00:00:00Z", "clm_alpha3_material"),
        )
        for sql in trigger_sql.values():
            connection.execute(sql)
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
    backups_before = set(tmp_path.glob("alpha3-decision-time.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_AUTHORITY_LEDGER_TIMESTAMP_MISMATCH" in {
        issue.code for issue in report.issues
    }
    assert (
        set(tmp_path.glob("alpha3-decision-time.db.pre-v3*.bak"))
        == backups_before
    )


def test_legacy_evidence_checkpoint_material_is_validated_before_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "alpha3-checkpoint.db"
    _make_v03_alpha3(database, with_added_evidence=True)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        trigger_sql = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name IN (?, ?)",
                (
                    "continuityforge_ledger_no_update",
                    "continuityforge_ledger_no_delete",
                ),
            ).fetchall()
        }
        for name in trigger_sql:
            connection.execute(f'DROP TRIGGER "{name}"')
        row = connection.execute(
            "SELECT sequence, payload_json FROM event_ledger "
            "WHERE event_type = 'claim.evidence_added'"
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[1]))
        payload["aggregate_sha256"] = "0" * 64
        connection.execute(
            "UPDATE event_ledger SET payload_json = ? WHERE sequence = ?",
            (
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                int(row[0]),
            ),
        )
        _rehash_ledger(connection)
        for sql in trigger_sql.values():
            connection.execute(sql)
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
    backups_before = set(tmp_path.glob("alpha3-checkpoint.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_MATERIAL_EVIDENCE_CHECKPOINT_INVALID" in {
        issue.code for issue in report.issues
    }
    assert set(tmp_path.glob("alpha3-checkpoint.db.pre-v3*.bak")) == backups_before


@pytest.mark.parametrize("mutation", ("duplicate", "reverse", "unhashable_ids"))
def test_legacy_event_evidence_order_and_uniqueness_fail_before_backup(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = tmp_path / f"alpha3-event-{mutation}.db"
    _make_v03_alpha3(database, with_second_event_evidence=True)
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        trigger_sql = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name IN (?, ?)",
                (
                    "continuityforge_ledger_no_update",
                    "continuityforge_ledger_no_delete",
                ),
            ).fetchall()
        }
        for name in trigger_sql:
            connection.execute(f'DROP TRIGGER "{name}"')
        row = connection.execute(
            "SELECT sequence, payload_json FROM event_ledger "
            "WHERE event_type = 'narrative_event.created'"
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row["payload_json"]))
        refs = list(payload["evidence_refs"])
        assert len(refs) == 2
        if mutation == "duplicate":
            refs.append(dict(refs[0]))
        elif mutation == "reverse":
            refs.reverse()
        else:
            payload["evidence_ids"] = [{}]
        payload["evidence_refs"] = refs
        connection.execute(
            "UPDATE event_ledger SET payload_json = ? WHERE sequence = ?",
            (
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                int(row["sequence"]),
            ),
        )
        _rehash_ledger(connection)
        for sql in trigger_sql.values():
            connection.execute(sql)
        connection.commit()
        assert fingerprint_schema(connection).kind is SchemaKind.V03_ALPHA3
    backups_before = set(tmp_path.glob(f"alpha3-event-{mutation}.db.pre-v3*.bak"))

    report = preflight_migration(
        database,
        create_backup=True,
        attest_current_legacy_material=True,
    )

    assert not report.is_ready
    assert report.backup_path is None
    assert "MIGRATION_EVENT_AUDIT_PAYLOAD_MISMATCH" in {
        issue.code for issue in report.issues
    }
    assert (
        set(tmp_path.glob(f"alpha3-event-{mutation}.db.pre-v3*.bak"))
        == backups_before
    )
