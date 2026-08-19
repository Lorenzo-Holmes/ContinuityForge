from __future__ import annotations

import json

import continuityforge.cli as cli
from continuityforge.constants import (
    CLI_COMMAND_LIFECYCLE,
    CLI_ERROR_SCHEMA,
    CLI_LIFECYCLE_CREATE_CAPABLE,
    CLI_LIFECYCLE_EXPLICIT_MIGRATE,
    CLI_LIFECYCLE_READ_EXISTING,
    CLI_LIFECYCLE_WRITE_EXISTING,
    EXIT_GOVERNANCE_FAILED,
    EXIT_LEDGER_FAILED,
    EXIT_OK,
    EXIT_SCHEMA_FAILED,
    EXIT_USAGE,
    EXIT_VALIDATION_FAILED,
)
from continuityforge.storage import Storage


def test_v03_cli_lifecycle_and_exit_contract_is_frozen() -> None:
    assert CLI_ERROR_SCHEMA == "continuityforge.error/v0.3"
    assert CLI_COMMAND_LIFECYCLE == {
        "ingest": CLI_LIFECYCLE_CREATE_CAPABLE,
        "demo": CLI_LIFECYCLE_CREATE_CAPABLE,
        "claim-propose": CLI_LIFECYCLE_WRITE_EXISTING,
        "claim-add": CLI_LIFECYCLE_WRITE_EXISTING,
        "claim-review": CLI_LIFECYCLE_WRITE_EXISTING,
        "event-add": CLI_LIFECYCLE_WRITE_EXISTING,
        "source-list": CLI_LIFECYCLE_READ_EXISTING,
        "claim-list": CLI_LIFECYCLE_READ_EXISTING,
        "validate": CLI_LIFECYCLE_READ_EXISTING,
        "compile": CLI_LIFECYCLE_READ_EXISTING,
        "ledger-verify": CLI_LIFECYCLE_READ_EXISTING,
        "ledger-show": CLI_LIFECYCLE_READ_EXISTING,
        "source-impact": CLI_LIFECYCLE_READ_EXISTING,
        "migration-check": CLI_LIFECYCLE_READ_EXISTING,
        "migrate": CLI_LIFECYCLE_EXPLICIT_MIGRATE,
    }
    assert {
        "ok": EXIT_OK,
        "usage": EXIT_USAGE,
        "validation": EXIT_VALIDATION_FAILED,
        "governance": EXIT_GOVERNANCE_FAILED,
        "ledger": EXIT_LEDGER_FAILED,
        "schema": EXIT_SCHEMA_FAILED,
    } == {
        "ok": 0,
        "usage": 2,
        "validation": 3,
        "governance": 4,
        "ledger": 5,
        "schema": 6,
    }


def test_empty_v3_read_json_shapes_are_stable(tmp_path, capsys) -> None:
    database = tmp_path / "forge.db"
    with Storage(database):
        pass

    expected = {
        ("source-list",): {"sources": []},
        ("claim-list",): {"claims": []},
        ("ledger-show", "--limit", "0"): {"entries": []},
    }
    for arguments, golden in expected.items():
        assert cli.main(["--db", str(database), *arguments]) == 0
        assert json.loads(capsys.readouterr().out) == golden


def test_error_code_contract_does_not_trust_arbitrary_exception_attributes() -> None:
    class ExternalError(ValueError):
        def __init__(self, code: str) -> None:
            super().__init__("external")
            self.code = code

    assert cli._stable_error_code(ExternalError("ATTACKER_CONTROLLED")) == (
        "INVALID_ARGUMENT"
    )
    assert cli._stable_error_code(ExternalError("NONFINITE_JSON_NUMBER")) == (
        "NONFINITE_JSON_NUMBER"
    )


def test_argument_alias_contract_is_stable() -> None:
    args = cli.build_parser().parse_args(
        [
            "claim-propose",
            "--persona",
            "mira",
            "--continuity",
            "alpha",
            "--text",
            "fact",
            "--visibility",
            "human_only",
            "--valid-until",
            "2026-01-02",
            "--knowledge-until",
            "2026-01-03",
        ]
    )
    assert args.claim_text == "fact"
    assert args.access_policy == "human_only"
    assert args.valid_to == "2026-01-02"
    assert args.knowledge_to == "2026-01-03"

    impact = cli.build_parser().parse_args(
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
    assert impact.target_version == 2
