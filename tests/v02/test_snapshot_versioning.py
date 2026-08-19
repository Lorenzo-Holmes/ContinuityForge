from __future__ import annotations

import json

import pytest

from continuityforge.evidence import EvidenceValidator, build_evidence_ref
from continuityforge.ingest import ingest_content, ingest_path
from continuityforge.models import ClaimProposal


def test_snapshot_versions_are_immutable_and_latest_import_is_idempotent(storage):
    source, v1, created1 = ingest_content(storage, "alpha\n", "story", "alpha")
    same_source, same_v1, created_again = ingest_content(
        storage, "alpha\n", "story", "alpha"
    )
    _, v2, created2 = ingest_content(storage, "beta\n", "story", "alpha")
    _, v3, created3 = ingest_content(storage, "alpha\n", "story", "alpha")

    assert created1 is True
    assert created_again is False
    assert same_source.source_id == source.source_id
    assert same_v1.snapshot_id == v1.snapshot_id
    assert (v1.version, v2.version, v3.version) == (1, 2, 3)
    assert v2.previous_snapshot_id == v1.snapshot_id
    assert v3.previous_snapshot_id == v2.snapshot_id
    assert v3.content_hash == v1.content_hash
    assert v3.snapshot_id != v1.snapshot_id
    assert created2 is created3 is True


def test_source_formats_preserve_original_text(storage, tmp_path):
    fixtures = {
        "source.txt": "first\r\nsecond\r\n",
        "source.md": "# 标题\r\n正文\r\n",
        "source.json": '{\r\n  "name": "米拉"\r\n}\r\n',
        "source.srt": "1\r\n00:00:01,000 --> 00:00:02,000\r\nSignal.\r\n",
    }
    for name, content in fixtures.items():
        path = tmp_path / name
        path.write_bytes(content.encode("utf-8"))
        _, snapshot, created = ingest_path(storage, path, name, "alpha")
        assert created
        assert snapshot.content == content

    malformed = tmp_path / "bad.json"
    malformed.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        ingest_path(storage, malformed, "bad", "alpha")


def test_evidence_is_line_exact_and_continuity_isolated(storage):
    _, snapshot, _ = ingest_content(
        storage, "Line one\r\nLine two\r\nLine three\r\n", "story", "alpha"
    )
    evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 2)
    assert evidence.quote == "Line one\nLine two"
    assert len(evidence.content_hash or "") == 64

    alpha = ClaimProposal(
        persona_id="mira", continuity="alpha", text="Two lines support this."
    )
    beta = ClaimProposal(
        persona_id="mira", continuity="beta", text="Wrong worldline."
    )
    assert EvidenceValidator(storage).validate_claim(alpha, [evidence]).is_valid
    report = EvidenceValidator(storage).validate_claim(beta, [evidence])
    assert not report.is_valid
    assert [issue.code for issue in report.issues] == ["CONTINUITY_MISMATCH"]

