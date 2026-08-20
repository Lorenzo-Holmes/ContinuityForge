"""Canonical v2 audit material for Claims, Events, and Evidence sets.

The EventLedger is useful only when its payload binds every persisted field
that can affect compilation or inspection.  This module is deliberately pure:
it accepts domain values, normalizes them to a strict JSON tree, and returns
stable SHA-256 digests without opening SQLite or consulting wall-clock state.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re
from typing import Any, Iterable, Mapping

from .models import ClaimProposal, EvidenceRef, GovernanceStatus, NarrativeEvent


MATERIAL_VERSION = 2
CLAIM_ATTESTATION_EVENT = "claim.material_attested"
EVENT_ATTESTATION_EVENT = "narrative_event.material_attested"
CLAIM_CREATION_EVENT = "claim.proposed"
CLAIM_EVIDENCE_EVENT = "claim.evidence_added"
EVENT_CREATION_EVENT = "narrative_event.created"
MATERIAL_DIGEST_KEYS = frozenset(
    {"material_version", "aggregate_sha256", "evidence_set_sha256"}
)
MATERIAL_ATTESTATION_KEYS = MATERIAL_DIGEST_KEYS | {
    "attested_event_type",
    "attested_entry_id",
    "migration_source_kind",
}
MIGRATION_ATTESTATION_SOURCE_KINDS = frozenset(
    {"v0.2", "v0.3-alpha2", "v0.3-alpha3"}
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Match the strict operator-details persistence boundary.  A value accepted by
# Storage must always remain hashable by the audit layer in the same
# transaction.
# ``Storage._strict_json_object`` counts the details root as depth one.  The
# material envelope adds one effective level before the same details tree is
# visited, so its canonicalizer needs one extra level to accept every value
# that the persistence boundary accepts.
_MAX_CANONICAL_DEPTH = 129


@dataclass(frozen=True, slots=True)
class AuditMaterialDigests:
    """Versioned digests stored in creation or migration-attestation payloads."""

    aggregate_sha256: str
    evidence_set_sha256: str
    material_version: int = MATERIAL_VERSION

    def to_payload(self) -> dict[str, Any]:
        return {
            "material_version": self.material_version,
            "aggregate_sha256": self.aggregate_sha256,
            "evidence_set_sha256": self.evidence_set_sha256,
        }


def _normalize_json(value: object, *, depth: int = 0) -> Any:
    if depth > _MAX_CANONICAL_DEPTH:
        raise ValueError("audit material exceeds the canonical JSON depth limit")
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("audit material contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("audit material JSON object keys must be strings")
            normalized[key] = _normalize_json(item, depth=depth + 1)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, depth=depth + 1) for item in value]
    raise TypeError(f"unsupported audit material value: {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Encode one strict JSON value with stable Unicode/key/number behavior."""

    normalized = _normalize_json(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    # Reject unpaired surrogates instead of producing platform-dependent bytes.
    encoded.encode("utf-8", errors="strict")
    return encoded


def canonical_sha256(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def claim_aggregate_material(claim: ClaimProposal) -> dict[str, Any]:
    """Return the complete persisted Claim row at proposal creation.

    ``status`` and ``updated_at`` are governance-derived cache fields after
    creation.  Their creation values are deterministic (``PROPOSED`` and
    ``created_at``), while current authority is independently replayed from
    immutable decisions.
    """

    confidence = float(claim.confidence)
    # SQLite REAL canonicalizes IEEE-754 negative zero to positive zero on
    # round-trip.  Hash the persisted representation, not the caller spelling.
    if confidence == 0.0:
        confidence = 0.0
    return {
        "claim_id": claim.claim_id,
        "persona_id": claim.persona_id,
        "continuity": claim.continuity,
        "text": claim.text,
        "subject": claim.subject,
        "predicate": claim.predicate,
        "object_value": claim.object_value,
        "valid_from": claim.valid_from,
        "valid_to": claim.valid_to,
        "knowledge_from": claim.knowledge_from,
        "knowledge_to": claim.knowledge_to,
        "access_policy": claim.access_policy.value,
        "confidence": confidence,
        "status": GovernanceStatus.PROPOSED.value,
        "proposed_by": claim.proposed_by,
        "proposal_model": claim.proposal_model,
        "rationale": claim.rationale,
        "created_at": claim.created_at,
        "updated_at": claim.created_at,
    }


def event_aggregate_material(event: NarrativeEvent) -> dict[str, Any]:
    """Return every persisted NarrativeEvent column in domain form."""

    return {
        "event_id": event.event_id,
        "persona_id": event.persona_id,
        "continuity": event.continuity,
        "event_type": event.event_type,
        "title": event.title,
        "summary": event.summary,
        "details": dict(event.details),
        "valid_from": event.valid_from,
        "valid_to": event.valid_to,
        "knowledge_from": event.knowledge_from,
        "knowledge_to": event.knowledge_to,
        "access_policy": event.access_policy.value,
        "created_at": event.created_at,
    }


def evidence_material(evidence: EvidenceRef) -> dict[str, Any]:
    """Return every persisted Evidence row field shared by both owner tables."""

    return {
        "evidence_id": evidence.evidence_id,
        "claim_id": evidence.claim_id,
        "event_id": evidence.event_id,
        "snapshot_id": evidence.snapshot_id,
        "start_line": evidence.start_line,
        "end_line": evidence.end_line,
        "start_char": evidence.start_char,
        "end_char": evidence.end_char,
        "quote": evidence.quote,
        "content_hash": evidence.content_hash,
        "created_at": evidence.created_at,
    }


def evidence_set_material(
    evidence: Iterable[EvidenceRef], *, aggregate_type: str
) -> dict[str, Any]:
    """Return a stable, order-independent, duplicate-preserving Evidence set."""

    items = [evidence_material(item) for item in evidence]
    items.sort(key=canonical_json)
    return {
        "material_version": MATERIAL_VERSION,
        "aggregate_type": aggregate_type,
        "evidence": items,
    }


def _digests(
    *, aggregate_type: str, aggregate: Mapping[str, Any], evidence: Iterable[EvidenceRef]
) -> AuditMaterialDigests:
    aggregate_envelope = {
        "material_version": MATERIAL_VERSION,
        "aggregate_type": aggregate_type,
        "aggregate": dict(aggregate),
    }
    return AuditMaterialDigests(
        aggregate_sha256=canonical_sha256(aggregate_envelope),
        evidence_set_sha256=canonical_sha256(
            evidence_set_material(evidence, aggregate_type=aggregate_type)
        ),
    )


def claim_material_digests(
    claim: ClaimProposal, evidence: Iterable[EvidenceRef]
) -> AuditMaterialDigests:
    return _digests(
        aggregate_type="claim",
        aggregate=claim_aggregate_material(claim),
        evidence=evidence,
    )


def event_material_digests(
    event: NarrativeEvent, evidence: Iterable[EvidenceRef]
) -> AuditMaterialDigests:
    return _digests(
        aggregate_type="narrative_event",
        aggregate=event_aggregate_material(event),
        evidence=evidence,
    )


def parse_material_digests(
    payload: Mapping[str, Any],
) -> AuditMaterialDigests | None:
    """Parse exactly the three v2 digest fields, rejecting partial/loose values."""

    present = MATERIAL_DIGEST_KEYS.intersection(payload)
    if not present:
        return None
    if present != MATERIAL_DIGEST_KEYS:
        raise ValueError("audit material digest fields are incomplete")
    version = payload.get("material_version")
    aggregate = payload.get("aggregate_sha256")
    evidence = payload.get("evidence_set_sha256")
    if type(version) is not int or version != MATERIAL_VERSION:
        raise ValueError("unsupported audit material version")
    if not isinstance(aggregate, str) or _LOWER_SHA256.fullmatch(aggregate) is None:
        raise ValueError("aggregate_sha256 must be a canonical lowercase SHA-256")
    if not isinstance(evidence, str) or _LOWER_SHA256.fullmatch(evidence) is None:
        raise ValueError("evidence_set_sha256 must be a canonical lowercase SHA-256")
    return AuditMaterialDigests(aggregate, evidence, version)


def build_material_attestation_payload(
    digests: AuditMaterialDigests,
    *,
    attested_event_type: str,
    attested_entry_id: str,
    migration_source_kind: str,
) -> dict[str, Any]:
    """Build the sole legacy-creation attestation shape accepted by replay."""

    if attested_event_type not in {CLAIM_CREATION_EVENT, EVENT_CREATION_EVENT}:
        raise ValueError("attested_event_type is not a material creation event")
    if not isinstance(attested_entry_id, str) or not attested_entry_id:
        raise ValueError("attested_entry_id must be non-empty")
    if migration_source_kind not in MIGRATION_ATTESTATION_SOURCE_KINDS:
        raise ValueError("migration_source_kind is not eligible for attestation")
    return {
        **digests.to_payload(),
        "attested_event_type": attested_event_type,
        "attested_entry_id": attested_entry_id,
        "migration_source_kind": migration_source_kind,
    }


def validate_material_attestation_payload(
    payload: Mapping[str, Any],
    *,
    attested_event_type: str,
    attested_entry_id: str,
) -> AuditMaterialDigests:
    """Validate exact migration provenance and return its material digests."""

    if set(payload) != MATERIAL_ATTESTATION_KEYS:
        raise ValueError("material attestation payload has unexpected fields")
    digests = parse_material_digests(payload)
    assert digests is not None
    if payload.get("attested_event_type") != attested_event_type:
        raise ValueError("material attestation names the wrong creation event type")
    if payload.get("attested_entry_id") != attested_entry_id:
        raise ValueError("material attestation names the wrong creation ledger entry")
    source_kind = payload.get("migration_source_kind")
    if source_kind not in MIGRATION_ATTESTATION_SOURCE_KINDS:
        raise ValueError("material attestation source schema is not eligible")
    return digests


__all__ = [
    "AuditMaterialDigests",
    "CLAIM_ATTESTATION_EVENT",
    "CLAIM_CREATION_EVENT",
    "CLAIM_EVIDENCE_EVENT",
    "EVENT_ATTESTATION_EVENT",
    "EVENT_CREATION_EVENT",
    "MATERIAL_ATTESTATION_KEYS",
    "MATERIAL_DIGEST_KEYS",
    "MATERIAL_VERSION",
    "MIGRATION_ATTESTATION_SOURCE_KINDS",
    "build_material_attestation_payload",
    "canonical_json",
    "canonical_sha256",
    "claim_aggregate_material",
    "claim_material_digests",
    "event_aggregate_material",
    "event_material_digests",
    "evidence_material",
    "evidence_set_material",
    "parse_material_digests",
    "validate_material_attestation_payload",
]
