from __future__ import annotations

import json

from continuityforge.cli import main


def _json_output(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_proposal_review_event_and_compile_round_trip(tmp_path, capsys):
    db = tmp_path / "forge.db"
    source = tmp_path / "story.md"
    source.write_text(
        "Mira entered the observatory.\nThe observatory opened at midnight.\n",
        encoding="utf-8",
    )
    prefix = ["--db", str(db)]

    assert main(prefix + ["ingest", str(source), "--continuity", "alpha"]) == 0
    snapshot_id = _json_output(capsys)["ingested"][0]["snapshot_id"]

    assert (
        main(
            prefix
            + [
                "claim-propose",
                "--persona",
                "mira",
                "--continuity",
                "alpha",
                "--claim",
                "Mira entered the observatory.",
                "--subject",
                "mira",
                "--predicate",
                "location",
                "--object",
                "observatory",
                "--knowledge-from",
                "2026-01-01",
                "--evidence",
                f"{snapshot_id}:1:1",
                "--provider",
                "fixture",
                "--model",
                "MODEL",
            ]
        )
        == 0
    )
    proposed = _json_output(capsys)
    claim_id = proposed["claim"]["claim_id"]
    assert proposed["claim"]["status"] == "PROPOSED"
    assert proposed["authorization_granted"] is False

    assert (
        main(
            prefix
            + [
                "claim-review",
                claim_id,
                "--status",
                "authorized",
                "--reviewer",
                "editor",
                "--reason",
                "source line directly supports the claim",
            ]
        )
        == 0
    )
    assert _json_output(capsys)["decision"]["to_status"] == "AUTHORIZED"

    assert (
        main(
            prefix
            + [
                "event-add",
                "--persona",
                "mira",
                "--continuity",
                "alpha",
                "--type",
                "observatory.opened",
                "--title",
                "Observatory opened",
                "--summary",
                "The observatory opened at midnight.",
                "--knowledge-from",
                "2026-01-01",
                "--evidence",
                f"{snapshot_id}:2:2",
            ]
        )
        == 0
    )
    event_id = _json_output(capsys)["event"]["event_id"]

    assert (
        main(
            prefix
            + [
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
    pack = _json_output(capsys)
    assert [item["id"] for item in pack["claims"]] == [claim_id]
    assert [item["id"] for item in pack["events"]] == [event_id]
    assert pack["events"][0]["provenance"][0]["source_span"]["start_line"] == 2

    assert main(prefix + ["validate", "--json"]) == 0
    validation = _json_output(capsys)
    assert validation["is_valid"] is True

    assert main(prefix + ["ledger-verify"]) == 0
    assert _json_output(capsys)["valid"] is True

