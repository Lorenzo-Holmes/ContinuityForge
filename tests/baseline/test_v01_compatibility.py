from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from continuityforge.cli import main
from continuityforge.compiler import MemoryCompiler
from continuityforge.models import GovernanceStatus, MemoryCutoff
from continuityforge.storage import Storage


def _last_json(capsys):
    output = capsys.readouterr().out.strip()
    return json.loads(output)


def test_v01_contract_files_match_frozen_baseline(project_root: Path):
    lock_path = project_root / "tests" / "baseline" / "v01_baseline.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["contract"] == "continuityforge/v0.1-baseline-lock"
    assert lock["algorithm"] == "sha256"
    for relative_path, expected in lock["files"].items():
        actual = hashlib.sha256((project_root / relative_path).read_bytes()).hexdigest()
        assert actual == expected, (
            f"frozen v0.1 contract changed: {relative_path}; add an explicit "
            "versioned migration and release note before updating the lock"
        )


def test_v01_cli_contract_is_preserved(tmp_path, capsys):
    db = tmp_path / "project.db"
    source = tmp_path / "alpha.txt"
    source.write_text("Mira knows the archive code.\n", encoding="utf-8")

    assert main(["--db", str(db), "ingest", str(source), "--continuity", "alpha"]) == 0
    snapshot = _last_json(capsys)["ingested"][0]["snapshot_id"]
    assert (
        main(
            [
                "--db",
                str(db),
                "claim-add",
                "--persona",
                "mira",
                "--continuity",
                "alpha",
                "--claim",
                "Mira knows the archive code.",
                "--subject",
                "mira",
                "--predicate",
                "knows",
                "--object",
                "archive-code",
                "--knowledge-from",
                "2026-01-03",
                "--evidence",
                f"{snapshot}:1:1",
            ]
        )
        == 0
    )
    claim_result = _last_json(capsys)
    assert claim_result["authorization_granted"] is True

    assert (
        main(
            [
                "--db",
                str(db),
                "compile",
                "--persona",
                "mira",
                "--continuity",
                "alpha",
                "--cutoff",
                "2026-01-02",
            ]
        )
        == 0
    )
    before = _last_json(capsys)
    assert before["claims"] == []

    assert (
        main(
            [
                "--db",
                str(db),
                "compile",
                "--persona",
                "mira",
                "--continuity",
                "alpha",
                "--cutoff",
                "2026-01-04",
            ]
        )
        == 0
    )
    after = _last_json(capsys)
    claim = after["claims"][0]
    required = {
        "persona_id",
        "continuity",
        "claim",
        "valid_from",
        "valid_until",
        "knowledge_from",
        "knowledge_until",
        "visibility",
        "confidence",
        "status",
        "source_id",
        "source_span",
    }
    assert required <= claim.keys()
    assert claim["status"] == "supported"
    assert claim["governance_status"] == "AUTHORIZED"


def test_v01_database_is_migrated_without_silent_data_loss(
    tmp_path, project_root: Path
):
    db = tmp_path / "legacy.db"
    connection = sqlite3.connect(db)
    connection.executescript(
        (project_root / "tests" / "baseline" / "v01_schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.close()

    with Storage(db) as storage:
        assert storage.get_schema_version() == 2
        migrated = storage.get_claim_proposal("legacy-claim-alpha")
        assert migrated.status is GovernanceStatus.AUTHORIZED
        assert migrated.knowledge_from == "2026-01-03T00:00:00Z"
        assert storage.get_claim_evidence(migrated.claim_id)
        assert storage.verify_ledger()

        before = MemoryCompiler(storage).compile(
            MemoryCutoff("alice", "alpha", "2026-01-02T00:00:00Z")
        )
        after = MemoryCompiler(storage).compile(
            MemoryCutoff("alice", "alpha", "2026-01-04T00:00:00Z")
        )
        assert before["claims"] == []
        assert [item["id"] for item in after["claims"]] == ["legacy-claim-alpha"]
        # Raw legacy rows remain auditable even when their original columns do
        # not have a direct v0.2 equivalent.
        assert storage.list_legacy_records()
