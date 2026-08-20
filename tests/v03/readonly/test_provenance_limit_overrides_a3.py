from __future__ import annotations

from pathlib import Path

import pytest

from continuityforge.evidence import build_evidence_ref
from continuityforge.exceptions import InspectionLimitError
from continuityforge.models import ClaimProposal
from continuityforge.readonly import ReadOnlyProject
from continuityforge.storage import Storage


def _material_project(database: Path, *, claims: int = 1) -> tuple[str, int]:
    """Create a one-span fixture and return its exact loaded UTF-8 material size."""

    quote = "\u951a\u70b9"
    text = "\u89d2\u8272\u77e5\u9053\u79d8\u5bc6"
    subject = "\u89d2\u8272"
    predicate = "\u77e5\u9053"
    object_value = "\u79d8\u5bc6"
    rationale = "\u539f\u6587\u8bc1\u636e"
    with Storage(database) as storage:
        _, snapshot, _ = storage.ingest_snapshot("story", "alpha", quote)
        for index in range(claims):
            evidence = build_evidence_ref(storage, snapshot.snapshot_id, 1, 1)
            storage.create_claim_proposal(
                ClaimProposal(
                    claim_id=f"claim_{index}",
                    persona_id="persona",
                    continuity="alpha",
                    text=text,
                    subject=subject,
                    predicate=predicate,
                    object_value=object_value,
                    rationale=rationale,
                ),
                (evidence,),
            )

    per_record_bytes = sum(
        len(value.encode("utf-8"))
        for value in (quote, text, subject, predicate, object_value, rationale)
    )
    return snapshot.snapshot_id, per_record_bytes * claims


def test_bytes_only_override_is_enforced_before_material_rows_are_loaded(
    tmp_path: Path,
) -> None:
    database = tmp_path / "bytes-only.db"
    snapshot_id, material_bytes = _material_project(database)

    with ReadOnlyProject.open(database) as project:
        at_boundary = project.get_provenance_for_snapshots(
            (snapshot_id,), max_material_bytes=material_bytes
        )
        assert len(at_boundary[snapshot_id]) == 1

        with pytest.raises(InspectionLimitError) as caught:
            project.get_provenance_for_snapshots(
                (snapshot_id,), max_material_bytes=material_bytes - 1
            )

    assert caught.value.code == "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED"


def test_records_only_override_is_independent_from_the_byte_override(
    tmp_path: Path,
) -> None:
    database = tmp_path / "records-only.db"
    snapshot_id, _ = _material_project(database, claims=2)

    with ReadOnlyProject.open(database) as project:
        assert len(
            project.get_provenance_for_snapshots(
                (snapshot_id,), max_records=2
            )[snapshot_id]
        ) == 2
        with pytest.raises(InspectionLimitError) as caught:
            project.get_provenance_for_snapshots((snapshot_id,), max_records=1)

    assert caught.value.code == "AFFECTED_EVIDENCE_LIMIT_EXCEEDED"


def test_record_and_byte_overrides_each_fail_closed_when_both_are_supplied(
    tmp_path: Path,
) -> None:
    database = tmp_path / "combined.db"
    snapshot_id, material_bytes = _material_project(database, claims=2)

    with ReadOnlyProject.open(database) as project:
        result = project.get_provenance_for_snapshots(
            (snapshot_id,), max_records=2, max_material_bytes=material_bytes
        )
        assert len(result[snapshot_id]) == 2

        with pytest.raises(InspectionLimitError) as record_error:
            project.get_provenance_for_snapshots(
                (snapshot_id,), max_records=1, max_material_bytes=material_bytes
            )
        with pytest.raises(InspectionLimitError) as byte_error:
            project.get_provenance_for_snapshots(
                (snapshot_id,), max_records=2, max_material_bytes=material_bytes - 1
            )

    assert record_error.value.code == "AFFECTED_EVIDENCE_LIMIT_EXCEEDED"
    assert byte_error.value.code == "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED"


def test_material_override_counts_utf8_bytes_not_unicode_code_points(
    tmp_path: Path,
) -> None:
    database = tmp_path / "utf8-bytes.db"
    snapshot_id, material_bytes = _material_project(database)

    # Every fixture field contains CJK text, so the encoded size is strictly
    # larger than the number of Unicode code points loaded for the record.
    code_point_budget = len(
        "\u951a\u70b9"
        "\u89d2\u8272\u77e5\u9053\u79d8\u5bc6"
        "\u89d2\u8272"
        "\u77e5\u9053"
        "\u79d8\u5bc6"
        "\u539f\u6587\u8bc1\u636e"
    )
    assert code_point_budget < material_bytes

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(InspectionLimitError) as caught:
            project.get_provenance_for_snapshots(
                (snapshot_id,), max_material_bytes=code_point_budget
            )

    assert caught.value.code == "AFFECTED_EVIDENCE_BYTES_LIMIT_EXCEEDED"


@pytest.mark.parametrize("value", [True, 0, -1])
@pytest.mark.parametrize("parameter", ["max_records", "max_material_bytes"])
def test_limit_overrides_require_positive_builtin_integers(
    tmp_path: Path, parameter: str, value: object
) -> None:
    database = tmp_path / f"invalid-{parameter}-{value}.db"
    snapshot_id, _ = _material_project(database)

    with ReadOnlyProject.open(database) as project:
        with pytest.raises(ValueError, match="positive built-in integer"):
            project.get_provenance_for_snapshots(
                (snapshot_id,), **{parameter: value}
            )
