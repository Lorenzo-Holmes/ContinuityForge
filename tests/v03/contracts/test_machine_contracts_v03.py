from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

import continuityforge.cli as cli
from continuityforge.constants import (
    CLI_COMMAND_LIFECYCLE,
    CLI_ERROR_SCHEMA,
    EXIT_GOVERNANCE_FAILED,
    EXIT_LEDGER_FAILED,
    EXIT_OK,
    EXIT_SCHEMA_FAILED,
    EXIT_USAGE,
    EXIT_VALIDATION_FAILED,
    MIGRATION_REPORT_SCHEMA,
    SOURCE_IMPACT_SCHEMA,
)
from continuityforge.impact_models import (
    ImpactCandidate,
    ImpactErrorCode,
    ImpactOutcome,
    ImpactReasonCode,
    ImpactReport,
)
from continuityforge.inspection import AffectedEvidence, SourceImpactReport
from continuityforge.migrations import (
    MigrationIssue,
    MigrationMode,
    MigrationReport,
)
from continuityforge.schema import SchemaFingerprint, SchemaKind
from continuityforge.serialization import json_dumps


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = ROOT / "schemas"
GOLDEN_DIR = Path(__file__).with_name("golden")

ERROR_SCHEMA = "continuityforge.error/v0.3"
FROZEN_IMPACT_OUTCOMES = (
    "SAME_POSITION",
    "EXACT_MOVED_UNIQUE",
    "EXACT_MOVED_AMBIGUOUS",
    "NO_EXACT_MATCH",
    "INVALID_EVIDENCE",
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schema(name: str) -> dict[str, Any]:
    return _load_json(SCHEMA_DIR / name)


def _golden(name: str) -> dict[str, Any]:
    return _load_json(GOLDEN_DIR / name)


def _runtime_impact_report(value: dict[str, Any]) -> ImpactReport:
    original = value["original_span"]
    error_code = value["error_code"]
    return ImpactReport(
        outcome=ImpactOutcome(value["outcome"]),
        old_snapshot_id=value["old_snapshot_id"],
        target_snapshot_id=value["target_snapshot_id"],
        target_snapshot_version=value["target_snapshot_version"],
        original_start_line=None if original is None else original["start_line"],
        original_end_line=None if original is None else original["end_line"],
        candidates=tuple(
            ImpactCandidate(span["start_line"], span["end_line"])
            for span in reversed(value["candidates"])
        ),
        reason_code=ImpactReasonCode(value["reason_code"]),
        reason=value["reason"],
        error_code=None if error_code is None else ImpactErrorCode(error_code),
    )


def _runtime_source_impact(value: dict[str, Any]) -> SourceImpactReport:
    affected = tuple(
        AffectedEvidence(
            aggregate_type=item["aggregate_type"],
            aggregate_id=item["aggregate_id"],
            evidence_id=item["evidence_id"],
            persona_id=item["persona_id"],
            governance_status=item["governance_status"],
            impact=_runtime_impact_report(item["impact"]),
        )
        for item in reversed(value["affected"])
    )
    return SourceImpactReport(
        source_id=value["source"]["source_id"],
        source_key=value["source"]["source_key"],
        continuity=value["source"]["continuity"],
        from_snapshot_id=value["from_snapshot"]["snapshot_id"],
        from_version=value["from_snapshot"]["version"],
        from_snapshot_sha256=value["from_snapshot"]["sha256"],
        to_snapshot_id=value["to_snapshot"]["snapshot_id"],
        to_version=value["to_snapshot"]["version"],
        to_snapshot_sha256=value["to_snapshot"]["sha256"],
        affected=affected,
    )


def _runtime_fingerprint(value: dict[str, Any]) -> SchemaFingerprint:
    return SchemaFingerprint(
        kind=SchemaKind(value["kind"]),
        digest=value["digest"],
        user_version=value["user_version"],
        metadata_version=value["metadata_version"],
        tables=tuple(value["tables"]),
        indexes=tuple(value["indexes"]),
        triggers=tuple(value["triggers"]),
    )


def _runtime_migration_report(value: dict[str, Any]) -> MigrationReport:
    checks = value["checks"]
    return MigrationReport(
        mode=MigrationMode(value["mode"]),
        source=_runtime_fingerprint(value["source"]),
        target_version=value["target_version"],
        status=value["status"],
        issues=tuple(
            MigrationIssue(
                code=issue["code"],
                message=issue["message"],
                table=issue["table"],
                record_id=issue["record_id"],
                field=issue["field"],
                actual=issue["actual"],
                severity=issue["severity"],
            )
            for issue in value["issues"]
        ),
        quick_check=checks["quick_check"],
        foreign_key_violations=checks["foreign_key_violations"],
        database_bytes=checks["database_bytes"],
        required_free_bytes=checks["required_free_bytes"],
        available_free_bytes=checks["available_free_bytes"],
        backup_path=checks["backup_path"],
        backup_sha256=checks["backup_sha256"],
        target=(
            None
            if value["target"] is None
            else _runtime_fingerprint(value["target"])
        ),
        started_at=value["started_at"],
        finished_at=value["finished_at"],
        migrated_counts=tuple(value["migrated_counts"].items()),
        quarantined=tuple(
            (record["table"], record["record_id"])
            for record in value["quarantine"]["records"]
        ),
    )


@pytest.mark.parametrize(
    ("schema_name", "golden_name"),
    (
        ("source-impact-v0.3.schema.json", "source-impact-v0.3.json"),
        ("error-v0.3.schema.json", "error-v0.3.json"),
        (
            "migration-report-v0.3.schema.json",
            "migration-report-not-ready-v0.3.json",
        ),
        (
            "migration-report-v0.3.schema.json",
            "migration-report-migrated-v0.3.json",
        ),
    ),
)
def test_v03_schema_and_golden_are_valid(
    schema_name: str, golden_name: str
) -> None:
    schema = _schema(schema_name)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_golden(golden_name))


def test_v03_goldens_use_the_cli_canonical_json_form() -> None:
    for path in sorted(GOLDEN_DIR.glob("*.json")):
        value = _load_json(path)
        assert path.read_text(encoding="utf-8") == f"{json_dumps(value)}\n"


def test_source_impact_contract_freezes_marker_outcomes_and_order() -> None:
    schema = _schema("source-impact-v0.3.schema.json")
    golden = _golden("source-impact-v0.3.json")

    assert schema["properties"]["schema"]["const"] == SOURCE_IMPACT_SCHEMA
    assert tuple(schema["$defs"]["impactOutcome"]["enum"]) == (
        FROZEN_IMPACT_OUTCOMES
    )
    assert tuple(item.value for item in ImpactOutcome) == FROZEN_IMPACT_OUTCOMES
    assert golden["schema"] == SOURCE_IMPACT_SCHEMA

    affected = golden["affected"]
    assert isinstance(affected, list)
    sort_keys = [
        (
            item["aggregate_type"],
            item["aggregate_id"],
            (item["impact"]["original_span"] or {}).get("start_line", 0),
            (item["impact"]["original_span"] or {}).get("end_line", 0),
            item["evidence_id"],
        )
        for item in affected
    ]
    assert sort_keys == sorted(sort_keys)
    for item in affected:
        candidates = item["impact"]["candidates"]
        assert candidates == sorted(
            candidates, key=lambda span: (span["start_line"], span["end_line"])
        )


def test_source_impact_runtime_serialization_matches_golden_and_schema() -> None:
    golden = _golden("source-impact-v0.3.json")
    material = _runtime_source_impact(golden).to_dict()

    assert material == golden
    assert json_dumps(material) + "\n" == (
        GOLDEN_DIR / "source-impact-v0.3.json"
    ).read_text(encoding="utf-8")
    Draft202012Validator(_schema("source-impact-v0.3.schema.json")).validate(
        material
    )


def test_source_impact_schema_rejects_unknown_fields_and_inconsistent_outcome() -> None:
    validator = Draft202012Validator(_schema("source-impact-v0.3.schema.json"))
    unknown_field = deepcopy(_golden("source-impact-v0.3.json"))
    unknown_field["source"]["unexpected"] = True
    with pytest.raises(ValidationError):
        validator.validate(unknown_field)

    inconsistent = deepcopy(_golden("source-impact-v0.3.json"))
    inconsistent["affected"][0]["impact"]["classification"] = (
        "EXACT_MOVED_UNIQUE"
    )
    with pytest.raises(ValidationError):
        validator.validate(inconsistent)


@pytest.mark.parametrize(
    ("schema_name", "golden_name", "mutate"),
    (
        (
            "error-v0.3.schema.json",
            "error-v0.3.json",
            lambda value: value.update({"unexpected": True}),
        ),
        (
            "migration-report-v0.3.schema.json",
            "migration-report-not-ready-v0.3.json",
            lambda value: value["checks"].update({"unexpected": True}),
        ),
    ),
)
def test_closed_v03_objects_reject_unknown_fields(
    schema_name: str,
    golden_name: str,
    mutate: Any,
) -> None:
    value = deepcopy(_golden(golden_name))
    mutate(value)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(schema_name)).validate(value)


def test_error_and_migration_markers_are_frozen() -> None:
    error_schema = _schema("error-v0.3.schema.json")
    migration_schema = _schema("migration-report-v0.3.schema.json")
    assert error_schema["properties"]["schema"]["const"] == ERROR_SCHEMA
    assert migration_schema["properties"]["schema"]["const"] == (
        MIGRATION_REPORT_SCHEMA
    )
    assert CLI_ERROR_SCHEMA == ERROR_SCHEMA


def test_runtime_error_serialization_matches_golden_and_schema(capsys) -> None:
    golden = _golden("error-v0.3.json")
    cli._emit_error(
        ValueError(golden["message"]),
        argparse.Namespace(redact_errors=False, db=Path("forge.db")),
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{json_dumps(golden)}\n"
    Draft202012Validator(_schema("error-v0.3.schema.json")).validate(
        json.loads(captured.err)
    )


@pytest.mark.parametrize(
    "golden_name",
    (
        "migration-report-not-ready-v0.3.json",
        "migration-report-migrated-v0.3.json",
    ),
)
def test_migration_runtime_serialization_matches_golden_and_schema(
    golden_name: str,
) -> None:
    golden = _golden(golden_name)
    material = _runtime_migration_report(golden).to_dict()

    assert material == golden
    assert json_dumps(material) + "\n" == (GOLDEN_DIR / golden_name).read_text(
        encoding="utf-8"
    )
    Draft202012Validator(_schema("migration-report-v0.3.schema.json")).validate(
        material
    )


def test_cli_lifecycle_exit_and_stream_contract_matches_golden() -> None:
    contract = _golden("cli-contract-v0.3.json")
    assert CLI_COMMAND_LIFECYCLE == contract["command_lifecycle"]
    assert {
        "ok": EXIT_OK,
        "usage": EXIT_USAGE,
        "validation_failed": EXIT_VALIDATION_FAILED,
        "governance_failed": EXIT_GOVERNANCE_FAILED,
        "ledger_failed": EXIT_LEDGER_FAILED,
        "schema_failed": EXIT_SCHEMA_FAILED,
    } == contract["exit_codes"]
    assert tuple(mode.value for mode in MigrationMode) == tuple(
        contract["migration_modes"]
    )
    assert contract["json_schemas"] == {
        "error": ERROR_SCHEMA,
        "migration_report": MIGRATION_REPORT_SCHEMA,
        "source_impact": SOURCE_IMPACT_SCHEMA,
    }


def test_source_impact_aliases_remain_accepted() -> None:
    by_key = cli.build_parser().parse_args(
        [
            "source-impact",
            "--source-key",
            "story",
            "--continuity",
            "alpha",
            "--to-version",
            "2",
        ]
    )
    by_id = cli.build_parser().parse_args(
        [
            "source-impact",
            "--source-id",
            "src_0001",
            "--continuity",
            "alpha",
            "--target-version",
            "2",
        ]
    )
    assert (by_key.source_key, by_key.target_version) == ("story", 2)
    assert (by_id.source_id, by_id.target_version) == ("src_0001", 2)


def test_argparse_usage_error_remains_text_on_stderr(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["--definitely-not-a-continuityforge-option"])

    captured = capsys.readouterr()
    assert caught.value.code == EXIT_USAGE
    assert captured.out == ""
    assert captured.err.startswith("usage: continuityforge")
    assert "error:" in captured.err
    with pytest.raises(json.JSONDecodeError):
        json.loads(captured.err)
