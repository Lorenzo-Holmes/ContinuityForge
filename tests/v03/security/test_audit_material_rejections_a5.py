from __future__ import annotations

from itertools import combinations

import pytest

from continuityforge.audit_material import (
    AuditMaterialDigests,
    CLAIM_CREATION_EVENT,
    EVENT_CREATION_EVENT,
    MATERIAL_ATTESTATION_KEYS,
    MATERIAL_DIGEST_KEYS,
    MATERIAL_VERSION,
    build_material_attestation_payload,
    canonical_json,
    parse_material_digests,
    validate_material_attestation_payload,
)


AGGREGATE_DIGEST = "a" * 64
EVIDENCE_DIGEST = "b" * 64
ENTRY_ID = "led_material_creation"


def _digests() -> AuditMaterialDigests:
    return AuditMaterialDigests(AGGREGATE_DIGEST, EVIDENCE_DIGEST)


def _digest_payload() -> dict[str, object]:
    return _digests().to_payload()


def _attestation_payload() -> dict[str, object]:
    return build_material_attestation_payload(
        _digests(),
        attested_event_type=CLAIM_CREATION_EVENT,
        attested_entry_id=ENTRY_ID,
        migration_source_kind="v0.2",
    )


def _nested_list(depth: int) -> object:
    value: object = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def test_canonical_json_accepts_the_exact_depth_boundary_and_rejects_the_next_level() -> None:
    assert canonical_json(_nested_list(129)).startswith("[")

    with pytest.raises(ValueError, match="canonical JSON depth limit"):
        canonical_json(_nested_list(130))


def test_canonical_json_preserves_strict_json_and_negative_zero_boundaries() -> None:
    assert canonical_json((None, False, True, 0, -0.0, "雪")) == (
        '[null,false,true,0,-0.0,"雪"]'
    )
    with pytest.raises(ValueError, match="non-finite number"):
        canonical_json(float("-inf"))
    with pytest.raises(UnicodeEncodeError):
        canonical_json("\ud800")


def test_material_digest_fields_are_all_or_none() -> None:
    assert parse_material_digests({}) is None
    assert parse_material_digests({"unrelated": "value"}) is None

    complete = _digest_payload()
    keys = tuple(sorted(MATERIAL_DIGEST_KEYS))
    for size in range(1, len(keys)):
        for subset in combinations(keys, size):
            partial = {key: complete[key] for key in subset}
            with pytest.raises(ValueError, match="digest fields are incomplete"):
                parse_material_digests(partial)


@pytest.mark.parametrize("version", [False, True, 1, 3, 2.0, "2", None])
def test_material_version_is_an_exact_non_boolean_integer(version: object) -> None:
    payload = _digest_payload()
    payload["material_version"] = version

    with pytest.raises(ValueError, match="unsupported audit material version"):
        parse_material_digests(payload)


@pytest.mark.parametrize("field", ["aggregate_sha256", "evidence_set_sha256"])
@pytest.mark.parametrize(
    "invalid_digest",
    [
        "A" * 64,
        "a" * 63,
        "a" * 65,
        "g" * 64,
        b"a" * 64,
        None,
    ],
    ids=["uppercase", "short", "long", "nonhex", "bytes", "null"],
)
def test_material_digests_require_exact_lowercase_sha256_text(
    field: str, invalid_digest: object
) -> None:
    payload = _digest_payload()
    payload[field] = invalid_digest

    with pytest.raises(ValueError, match=f"{field} must be a canonical lowercase SHA-256"):
        parse_material_digests(payload)


def test_valid_material_digest_payload_round_trips_exactly() -> None:
    assert parse_material_digests(_digest_payload()) == _digests()
    assert _digests().material_version == MATERIAL_VERSION


@pytest.mark.parametrize(
    "event_type",
    ["claim.evidence_added", "claim.material_attested", "CLAIM.PROPOSED", "", None],
)
def test_attestation_builder_rejects_non_creation_event_types(event_type: object) -> None:
    with pytest.raises(ValueError, match="not a material creation event"):
        build_material_attestation_payload(
            _digests(),
            attested_event_type=event_type,  # type: ignore[arg-type]
            attested_entry_id=ENTRY_ID,
            migration_source_kind="v0.2",
        )


@pytest.mark.parametrize("entry_id", ["", None, 0, False])
def test_attestation_builder_requires_a_non_empty_text_entry_id(entry_id: object) -> None:
    with pytest.raises(ValueError, match="attested_entry_id must be non-empty"):
        build_material_attestation_payload(
            _digests(),
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id=entry_id,  # type: ignore[arg-type]
            migration_source_kind="v0.2",
        )


@pytest.mark.parametrize("source_kind", ["v0.1", "v0.3", "V0.2", "", None])
def test_attestation_builder_rejects_unknown_source_kinds(source_kind: object) -> None:
    with pytest.raises(ValueError, match="not eligible for attestation"):
        build_material_attestation_payload(
            _digests(),
            attested_event_type=EVENT_CREATION_EVENT,
            attested_entry_id=ENTRY_ID,
            migration_source_kind=source_kind,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("missing_key", sorted(MATERIAL_ATTESTATION_KEYS))
def test_attestation_validator_rejects_every_missing_key(missing_key: str) -> None:
    payload = _attestation_payload()
    del payload[missing_key]

    with pytest.raises(ValueError, match="unexpected fields"):
        validate_material_attestation_payload(
            payload,
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id=ENTRY_ID,
        )


def test_attestation_validator_rejects_extra_keys() -> None:
    payload = _attestation_payload()
    payload["unexpected"] = "field"

    with pytest.raises(ValueError, match="unexpected fields"):
        validate_material_attestation_payload(
            payload,
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id=ENTRY_ID,
        )


def test_attestation_validator_rejects_the_wrong_event_type() -> None:
    with pytest.raises(ValueError, match="wrong creation event type"):
        validate_material_attestation_payload(
            _attestation_payload(),
            attested_event_type=EVENT_CREATION_EVENT,
            attested_entry_id=ENTRY_ID,
        )


@pytest.mark.parametrize("entry_id", ["", "led_other", None])
def test_attestation_validator_rejects_the_wrong_entry_id(entry_id: object) -> None:
    with pytest.raises(ValueError, match="wrong creation ledger entry"):
        validate_material_attestation_payload(
            _attestation_payload(),
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id=entry_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("source_kind", ["v0.1", "v0.3", "V0.2", "", None])
def test_attestation_validator_rejects_unknown_source_kinds(source_kind: object) -> None:
    payload = _attestation_payload()
    payload["migration_source_kind"] = source_kind

    with pytest.raises(ValueError, match="source schema is not eligible"):
        validate_material_attestation_payload(
            payload,
            attested_event_type=CLAIM_CREATION_EVENT,
            attested_entry_id=ENTRY_ID,
        )
