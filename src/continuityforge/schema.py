"""Fail-closed SQLite schema identification for ContinuityForge.

Schema identity is established from structure *and* version markers.  A
``PRAGMA user_version`` value is never trusted by itself: databases with only
some ContinuityForge objects are classified as :class:`SchemaKind.PARTIAL`,
and unrelated layouts as :class:`SchemaKind.UNKNOWN`.

The fingerprint digest is diagnostic rather than an authorization token.  It
is a stable hash of normalized ``sqlite_master`` records and is useful in
migration reports, backups, and support bundles.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
import sqlite3
import unicodedata
from typing import Any, Mapping

from .constants import SCHEMA_VERSION
from .exceptions import SchemaError


class SchemaKind(str, Enum):
    """Known database layouts and fail-closed classification outcomes."""

    EMPTY = "empty"
    V01 = "v0.1"
    V02 = "v0.2"
    V03 = "v0.3"
    UNKNOWN = "unknown"
    PARTIAL = "partial"


V01_TABLE_COLUMNS: Mapping[str, frozenset[str]] = {
    "source_snapshots": frozenset(
        {"id", "path", "sha256", "continuity", "content", "created_at"}
    ),
    "claims": frozenset(
        {
            "id",
            "persona_id",
            "continuity",
            "claim",
            "subject",
            "predicate",
            "object_value",
            "source_snapshot_id",
            "start_line",
            "end_line",
            "valid_from",
            "valid_until",
            "knowledge_from",
            "knowledge_until",
            "access_policy",
            "confidence",
            "created_at",
        }
    ),
}

V01_CANONICAL_TABLE_SQL_DIGESTS: Mapping[str, str] = {
    "claims": "8a6eeeed219ce19b6e0ec511ac74d6f54de76f34cf8593637848d7c2aa614923",
    "source_snapshots": "b00755b36e20d84734530a8c22d1456f5a8ab037fb0e321b117d33c1ea2f8063",
}


V2_CORE_TABLE_COLUMNS: Mapping[str, frozenset[str]] = {
    "schema_metadata": frozenset(
        {"singleton", "schema_version", "migrated_at", "migration_notes"}
    ),
    "sources": frozenset(
        {"source_id", "source_key", "continuity", "created_at", "updated_at"}
    ),
    "source_snapshots": frozenset(
        {
            "snapshot_id",
            "source_id",
            "version",
            "content_hash",
            "content",
            "media_type",
            "origin_path",
            "previous_snapshot_id",
            "line_count",
            "created_at",
        }
    ),
    "claim_proposals": frozenset(
        {
            "claim_id",
            "persona_id",
            "continuity",
            "text",
            "subject",
            "predicate",
            "object_value",
            "valid_from",
            "valid_to",
            "knowledge_from",
            "knowledge_to",
            "access_policy",
            "confidence",
            "status",
            "proposed_by",
            "proposal_model",
            "rationale",
            "created_at",
            "updated_at",
        }
    ),
    "evidence_refs": frozenset(
        {
            "evidence_id",
            "claim_id",
            "snapshot_id",
            "start_line",
            "end_line",
            "start_char",
            "end_char",
            "quote",
            "content_hash",
            "created_at",
        }
    ),
    "governance_decisions": frozenset(
        {
            "decision_id",
            "claim_id",
            "from_status",
            "to_status",
            "reviewer",
            "reason",
            "decided_at",
        }
    ),
    "narrative_events": frozenset(
        {
            "event_id",
            "persona_id",
            "continuity",
            "event_type",
            "title",
            "summary",
            "details_json",
            "valid_from",
            "valid_to",
            "knowledge_from",
            "knowledge_to",
            "access_policy",
            "created_at",
        }
    ),
    "event_ledger": frozenset(
        {
            "sequence",
            "entry_id",
            "event_type",
            "aggregate_type",
            "aggregate_id",
            "payload_json",
            "previous_hash",
            "entry_hash",
            "created_at",
        }
    ),
    "legacy_records": frozenset(
        {
            "legacy_record_id",
            "original_table",
            "legacy_key",
            "payload_json",
            "migrated_entity_type",
            "migrated_entity_id",
            "migrated_at",
        }
    ),
}


EVENT_EVIDENCE_COLUMNS = frozenset(
    {
        "evidence_id",
        "event_id",
        "snapshot_id",
        "start_line",
        "end_line",
        "start_char",
        "end_char",
        "quote",
        "content_hash",
        "created_at",
    }
)


# These triggers are the v0.3 application-integrity boundary.  Classification
# requires them all; merely changing user_version to 3 cannot bless a partial
# database.
V03_REQUIRED_TRIGGERS = frozenset(
    {
        "continuityforge_snapshots_no_update",
        "continuityforge_snapshots_no_delete",
        "continuityforge_evidence_no_update",
        "continuityforge_evidence_no_delete",
        "continuityforge_decisions_no_update",
        "continuityforge_decisions_no_delete",
        "continuityforge_event_evidence_no_update",
        "continuityforge_event_evidence_no_delete",
        "continuityforge_ledger_no_update",
        "continuityforge_ledger_no_delete",
        "continuityforge_claims_insert_proposed",
        "continuityforge_claims_fields_immutable",
        "continuityforge_claims_no_delete",
        "continuityforge_claims_status_transition",
        "continuityforge_evidence_reviewable_insert",
        "continuityforge_decision_transition_insert",
        "continuityforge_events_no_update",
        "continuityforge_events_no_delete",
        "continuityforge_snapshot_lineage_insert",
        "continuityforge_evidence_continuity_insert",
        "continuityforge_event_evidence_continuity_insert",
    }
)


V02_REQUIRED_TRIGGERS = frozenset(
    {
        "continuityforge_snapshots_no_update",
        "continuityforge_snapshots_no_delete",
        "continuityforge_evidence_no_update",
        "continuityforge_evidence_no_delete",
        "continuityforge_decisions_no_update",
        "continuityforge_decisions_no_delete",
        "continuityforge_ledger_no_update",
        "continuityforge_ledger_no_delete",
    }
)


# SHA-256 of whitespace-normalized sqlite_master SQL emitted by the published
# schema.  Column names alone are insufficient: a same-column table without
# its CHECK/FK/UNIQUE constraints, or a same-name no-op trigger, must not be
# treated as a trusted version.  The early v0.2 snapshot table additionally
# allowed UNIQUE(source_id, content_hash); migration removes that one known
# historical variant.
CANONICAL_TABLE_SQL_DIGESTS: Mapping[str, frozenset[str]] = {
    "claim_proposals": frozenset({"27655ad85a1006c4b120225de5f818b16803081391239914fa6a648b7101e664"}),
    "event_evidence_refs": frozenset({"bc2c0e2c2af4a05d9b16e6c1e6dedc89e03614b45927d802b24af2ff7ad2253e"}),
    "event_ledger": frozenset({"80d792f59f05d8314ccefb9abec7aff4985d7927c2dcfc8e12736f5b6e69d53f"}),
    "evidence_refs": frozenset({"3e473f9b57d81c85dd6da7ce9e9ecb5479702da43384c4abbe57be490982f15e"}),
    "governance_decisions": frozenset({"1d53259506669f77d9652bbf9509410c9b8fc11e6ac0552b9e6103a2b7a71870"}),
    "legacy_records": frozenset({"aa7cb43dc0a9f50d33129d1dea33a85a6c9beecefcdb81c038d212ec78485a49"}),
    "narrative_events": frozenset({"cc3292aeb12581cd671288e68c6fd632b3cfb6a18c37016ddeb4056192197c1d"}),
    "schema_metadata": frozenset({"8ca8d7eaec4f192407eadf12996db5d6b204a42e83a9e5cf0df7f881b6a01f5b"}),
    "source_snapshots": frozenset({"b91ef5dc2f497309d02c8121ec360f5f95aebd7baf08ea35f6e0813f7bddeece"}),
    "sources": frozenset({"09cc0c1c5caaa1985a76abf22b380a0fae7225f38b6e69b792be37cdb824b4da"}),
}

V02_SOURCE_SNAPSHOT_SQL_DIGESTS = CANONICAL_TABLE_SQL_DIGESTS["source_snapshots"] | {
    "5d60b901eb340082501d6923e569dd18b6334a0d8eb44bab4da87dc2011ed68f"
}

CANONICAL_TRIGGER_SQL_DIGESTS: Mapping[str, str] = {
    "continuityforge_claims_fields_immutable": "82e95d9b64bc6ba2193b41d7adc06c6c2b8338ca80b5c4b49210502cbcd3cc4f",
    "continuityforge_claims_insert_proposed": "202f92163c4669b37176b6e1d9a6ad2c0a7a1b3a010705247eaec6f827b8f740",
    "continuityforge_claims_no_delete": "b109272c34bba45b24d8256dad83f91d4b59b63e11baf34ebc814a06ce3429b6",
    "continuityforge_claims_status_transition": "d9a98f648008e24f9d547f747f94730ef567f5731af5239a1e936dc41431d630",
    "continuityforge_decision_transition_insert": "b27120b7b9d717c050d1b3e40be5244fefe336c015ce574038d4c75b62bc6238",
    "continuityforge_decisions_no_delete": "86dc1fc4d430d88404b08cd995a03e2eae18cd651ee70674765883b5a1fd7799",
    "continuityforge_decisions_no_update": "bc583f4d2020c5746af9e09f72128231401cec7bb301a7edd6b78f85cd2ff70c",
    "continuityforge_event_evidence_continuity_insert": "953e666c92503ebbaaba68ab375da64f838c5b119dbe9c87d91a5b24abc9c84e",
    "continuityforge_event_evidence_no_delete": "bc5a7346109f5d56f4853bece05043c043d80b8cedadfd823188a48cceeeeb8e",
    "continuityforge_event_evidence_no_update": "c1a4facae4d0e25b940ebd113963fbbd89272fa492971d453738ebe07df77d6b",
    "continuityforge_events_no_delete": "110500f824eeb2fbfee2aeb5c733eca142079e03f7a541a50848bb25219d12fa",
    "continuityforge_events_no_update": "c96a0314aaa7fe0dc98ceef18e693bad4e0ef0d67bce3927d7caf89966781dc6",
    "continuityforge_evidence_continuity_insert": "df418d66bfa5f2ed9eb56d242c3dc2beb0a50c9a52f289ce91fcf1efba4bfa61",
    "continuityforge_evidence_no_delete": "1c1f8070811975e31cd044ad8733768c47273db6a985e11b2b00bd42b96dd4c1",
    "continuityforge_evidence_no_update": "6b9fe887b795913771db5bb074694ed49bffea8f908b7ad4d4c5180ec80d1a3f",
    "continuityforge_evidence_reviewable_insert": "3b6e1b7d61c273c1dddbc800c056a494fd84658319f6fb20a11ec059f99aa244",
    "continuityforge_ledger_no_delete": "4b4ff8c4b878135e0bd6e9b4507422ae4d54d4e5bff1810e091b6f41c92d94c0",
    "continuityforge_ledger_no_update": "792984a5ea8bd60b0fb0a735981c0f147803a033311a770195186cae6679736f",
    "continuityforge_snapshot_lineage_insert": "e9324f417a83f9389ca5db4c08faceda8e1125c1f04fb47378896a0beab1e4e9",
    "continuityforge_snapshots_no_delete": "a5556a7a9dd123500d81aabfa01836a1abcdc1c1f9eb57a625b6cf47a6d39b57",
    "continuityforge_snapshots_no_update": "2eaa224c6cee9cd8a91047784f3506ae509707cce42224f701fda39971bc2817",
}

CANONICAL_INDEX_SQL_DIGESTS: Mapping[str, str] = {
    "idx_claims_knowledge": "a7e6118df9c0eb6f431fc7b0d89fb8bfa77c2d947a1485a89ce725343bb5f172",
    "idx_claims_persona_continuity_status": "405ea46386c4ca72dc64fe67bdd8a2042f9b99355fab7e20251e6b3b48e8af05",
    "idx_event_evidence_event": "ecf4e4a272686ad5da1efd99961be90521e6a1cd3a1a4b3fae0929293f75ea39",
    "idx_event_evidence_snapshot": "f7d00a865a14a506ecea249692dd4c95a4a23d39bdebf44889413a0f97b7cbae",
    "idx_events_persona_continuity": "677bb5be3a15a5043691f19634be09004ba6f0ef0220dc6b81df591f2c1d54e8",
    "idx_evidence_claim": "907470eecfffe379b4a471ecbc31530e47b274d9699678569756e2c4ef8a8f7d",
    "idx_evidence_snapshot": "f70f4bbec15f5894adcb53871fce535e35e8cfb7db42ae9eff7e2b5517b01a22",
    "idx_ledger_aggregate": "79d2971c21fa4b997da4c6d3a712b30c639c082b67c6dce9e5d8d14b4c8a3ea8",
    "idx_snapshots_source_content_hash": "7ba55870a16c91a3c9cd8c067d154baddf7f3066c6109b1e0682ee61858d2275",
    "idx_snapshots_source_version": "6dffaea815935b46c6574ced87ce31d346eb7b8a2bcff8f317f427623a9439bc",
}


ALLOWED_MIGRATIONS = frozenset(
    {
        (SchemaKind.V01, SchemaKind.V03),
        (SchemaKind.V02, SchemaKind.V03),
    }
)


@dataclass(frozen=True, slots=True)
class SchemaFingerprint:
    """Frozen, JSON-serializable description of a SQLite structure."""

    kind: SchemaKind
    digest: str
    user_version: int
    metadata_version: int | None
    tables: tuple[str, ...]
    indexes: tuple[str, ...]
    triggers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "digest": self.digest,
            "user_version": self.user_version,
            "metadata_version": self.metadata_version,
            "tables": [_safe_object_name(item) for item in self.tables],
            "indexes": [_safe_object_name(item) for item in self.indexes],
            "triggers": [_safe_object_name(item) for item in self.triggers],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent)


_BIDI_CONTROL_CLASSES = frozenset(
    {"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"}
)


def _safe_object_name(value: str) -> object:
    unsafe = any(
        unicodedata.category(character) in {"Cc", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
        for character in value
    )
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        data = value.encode("utf-8", errors="surrogatepass")
        unsafe = True
    if unsafe or len(data) > 256:
        return {
            "redacted": True,
            "type": "schema_object_name",
            "length": len(value),
            "sha256": sha256(data).hexdigest(),
        }
    return value


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _objects(connection: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    rows = connection.execute(
        "SELECT type, name, COALESCE(tbl_name, ''), COALESCE(sql, '') "
        "FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
        "AND type IN ('table', 'index', 'trigger', 'view') "
        "ORDER BY type, name"
    ).fetchall()
    normalized: list[tuple[str, str, str, str]] = []
    for row in rows:
        sql = re.sub(r"\s+", " ", str(row[3] or "").strip())
        normalized.append((str(row[0]), str(row[1]), str(row[2]), sql))
    return normalized


def _columns(connection: sqlite3.Connection, table: str) -> frozenset[str]:
    try:
        rows = connection.execute(
            f"PRAGMA table_info({_quote_identifier(table)})"
        ).fetchall()
    except sqlite3.DatabaseError:
        return frozenset()
    return frozenset(str(row[1]) for row in rows)


def _metadata_version(connection: sqlite3.Connection, tables: set[str]) -> int | None:
    if "schema_metadata" not in tables:
        return None
    if "schema_version" not in _columns(connection, "schema_metadata"):
        return None
    try:
        rows = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchall()
    except sqlite3.DatabaseError:
        return None
    if len(rows) != 1 or type(rows[0][0]) is not int:
        return None
    return int(rows[0][0])


def _contains_columns(
    connection: sqlite3.Connection,
    tables: set[str],
    signature: Mapping[str, frozenset[str]],
) -> bool:
    return all(
        table in tables and required <= _columns(connection, table)
        for table, required in signature.items()
    )


def _has_exact_columns(
    connection: sqlite3.Connection,
    tables: set[str],
    signature: Mapping[str, frozenset[str]],
) -> bool:
    """Return whether every current-schema table has its canonical columns.

    Accepting a required-column *subset* would let aliases or modified tables
    masquerade as a known schema and defer ambiguity until a later write.
    """

    return all(
        table in tables and required == _columns(connection, table)
        for table, required in signature.items()
    )


def _is_retained_audit_table(name: str) -> bool:
    return name.startswith("legacy_v1_") or name.startswith("legacy_v2_")


def _has_only_known_tables(tables: set[str], *, allow_event_evidence: bool) -> bool:
    canonical = set(V2_CORE_TABLE_COLUMNS)
    if allow_event_evidence:
        canonical.add("event_evidence_refs")
    return all(name in canonical or _is_retained_audit_table(name) for name in tables)


def _has_canonical_sql(
    objects: list[tuple[str, str, str, str]],
    *,
    tables: set[str],
    triggers: set[str],
    indexes: set[str],
    allow_v02_snapshot_hash_unique: bool,
    allow_event_evidence: bool,
) -> bool:
    sql_by_object = {
        (type_, name): sql for type_, name, _, sql in objects
    }
    for table in tables:
        if _is_retained_audit_table(table):
            continue
        allowed = CANONICAL_TABLE_SQL_DIGESTS.get(table)
        if table == "source_snapshots" and allow_v02_snapshot_hash_unique:
            allowed = V02_SOURCE_SNAPSHOT_SQL_DIGESTS
        sql = sql_by_object.get(("table", table), "")
        if allowed is None or sha256(sql.encode("utf-8")).hexdigest() not in allowed:
            return False
    for trigger in triggers:
        expected = CANONICAL_TRIGGER_SQL_DIGESTS.get(trigger)
        sql = sql_by_object.get(("trigger", trigger), "")
        if expected is None or sha256(sql.encode("utf-8")).hexdigest() != expected:
            return False
    expected_indexes = set(CANONICAL_INDEX_SQL_DIGESTS)
    if not allow_event_evidence:
        expected_indexes -= {
            "idx_event_evidence_event",
            "idx_event_evidence_snapshot",
        }
    if indexes != expected_indexes:
        return False
    for index in indexes:
        sql = sql_by_object.get(("index", index), "")
        if sha256(sql.encode("utf-8")).hexdigest() != CANONICAL_INDEX_SQL_DIGESTS[index]:
            return False
    return True


def _known_name(name: str) -> bool:
    known = set(V01_TABLE_COLUMNS) | set(V2_CORE_TABLE_COLUMNS) | {
        "event_evidence_refs"
    }
    return (
        name in known
        or name.startswith("legacy_v1_")
        or name.startswith("legacy_v2_")
    )


V01_ALLOWED_TABLES = frozenset(
    {"source_snapshots", "claims", "narrative_events", "events"}
)


def _classify(
    connection: sqlite3.Connection,
    *,
    objects: list[tuple[str, str, str, str]],
    user_version: int,
    metadata_version: int | None,
) -> SchemaKind:
    tables = {name for type_, name, _, _ in objects if type_ == "table"}
    triggers = {name for type_, name, _, _ in objects if type_ == "trigger"}
    indexes = {name for type_, name, _, _ in objects if type_ == "index"}
    views = {name for type_, name, _, _ in objects if type_ == "view"}

    if not tables:
        return SchemaKind.EMPTY if user_version == 0 else SchemaKind.PARTIAL

    v1_columns = _has_exact_columns(connection, tables, V01_TABLE_COLUMNS)
    v2_columns = _has_exact_columns(connection, tables, V2_CORE_TABLE_COLUMNS)
    has_event_evidence = (
        "event_evidence_refs" in tables
        and EVENT_EVIDENCE_COLUMNS == _columns(connection, "event_evidence_refs")
    )

    if v2_columns:
        if user_version == SCHEMA_VERSION and metadata_version == SCHEMA_VERSION:
            if (
                has_event_evidence
                and _has_only_known_tables(tables, allow_event_evidence=True)
                and triggers == V03_REQUIRED_TRIGGERS
                and not views
                and _has_canonical_sql(
                    objects,
                    tables=tables,
                    triggers=triggers,
                    indexes=indexes,
                    allow_v02_snapshot_hash_unique=False,
                    allow_event_evidence=True,
                )
            ):
                return SchemaKind.V03
            return SchemaKind.PARTIAL
        if user_version == 2 and metadata_version == 2:
            # v0.2 had one short-lived layout before event evidence was added;
            # both published shapes retain the core immutable triggers.
            if (
                _has_only_known_tables(
                    tables, allow_event_evidence=has_event_evidence
                )
                and triggers == V02_REQUIRED_TRIGGERS
                and not views
                and _has_canonical_sql(
                    objects,
                    tables=tables,
                    triggers=triggers,
                    indexes=indexes,
                    allow_v02_snapshot_hash_unique=True,
                    allow_event_evidence=has_event_evidence,
                )
            ):
                return SchemaKind.V02
            return SchemaKind.PARTIAL
        return SchemaKind.PARTIAL

    if v1_columns:
        # The frozen public fixture has no version pragma or metadata table.
        sql_by_object = {(type_, name): sql for type_, name, _, sql in objects}
        canonical_v1 = all(
            sha256(sql_by_object.get(("table", table), "").encode("utf-8")).hexdigest()
            == digest
            for table, digest in V01_CANONICAL_TABLE_SQL_DIGESTS.items()
        )
        if (
            user_version == 0
            and metadata_version is None
            and tables == set(V01_TABLE_COLUMNS)
            and canonical_v1
            and not indexes
            and not triggers
            and not views
        ):
            return SchemaKind.V01
        return SchemaKind.PARTIAL

    if any(_known_name(name) for name in tables):
        return SchemaKind.PARTIAL
    return SchemaKind.UNKNOWN


def fingerprint_schema(connection: sqlite3.Connection) -> SchemaFingerprint:
    """Return a deterministic structural fingerprint without writing SQLite."""

    objects = _objects(connection)
    row = connection.execute("PRAGMA user_version").fetchone()
    user_version = int(row[0]) if row else 0
    tables_set = {name for type_, name, _, _ in objects if type_ == "table"}
    metadata_version = _metadata_version(connection, tables_set)
    kind = _classify(
        connection,
        objects=objects,
        user_version=user_version,
        metadata_version=metadata_version,
    )
    material = json.dumps(
        {
            "user_version": user_version,
            "metadata_version": metadata_version,
            "objects": objects,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return SchemaFingerprint(
        kind=kind,
        digest=sha256(material.encode("utf-8")).hexdigest(),
        user_version=user_version,
        metadata_version=metadata_version,
        tables=tuple(sorted(tables_set)),
        indexes=tuple(
            sorted(name for type_, name, _, _ in objects if type_ == "index")
        ),
        triggers=tuple(
            sorted(name for type_, name, _, _ in objects if type_ == "trigger")
        ),
    )


def classify_schema(connection: sqlite3.Connection) -> SchemaKind:
    """Classify a database from its structure and mutually consistent markers."""

    return fingerprint_schema(connection).kind


def validate_schema(
    connection: sqlite3.Connection, *, expected_version: int = SCHEMA_VERSION
) -> SchemaFingerprint:
    """Validate the current schema and return its fingerprint.

    Only the current v0.3 layout is accepted by default.  ``expected_version``
    exists for migration tooling and deliberately supports only the frozen
    versions known to this package.
    """

    expected = {
        1: SchemaKind.V01,
        2: SchemaKind.V02,
        3: SchemaKind.V03,
    }.get(expected_version)
    if expected is None:
        raise SchemaError(f"unsupported expected schema version: {expected_version}")
    fingerprint = fingerprint_schema(connection)
    if fingerprint.kind is not expected:
        raise SchemaError(
            "schema validation failed: expected "
            f"{expected.value}, found {fingerprint.kind.value} "
            f"(fingerprint {fingerprint.digest})"
        )
    quick = connection.execute("PRAGMA quick_check").fetchone()
    if quick is None or str(quick[0]).lower() != "ok":
        raise SchemaError(f"SQLite quick_check failed: {quick[0] if quick else 'no result'}")
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_keys:
        raise SchemaError(
            f"SQLite foreign_key_check reported {len(foreign_keys)} violation(s)"
        )
    return fingerprint


__all__ = [
    "ALLOWED_MIGRATIONS",
    "EVENT_EVIDENCE_COLUMNS",
    "SCHEMA_VERSION",
    "SchemaFingerprint",
    "SchemaKind",
    "V01_TABLE_COLUMNS",
    "V02_REQUIRED_TRIGGERS",
    "V03_REQUIRED_TRIGGERS",
    "V2_CORE_TABLE_COLUMNS",
    "classify_schema",
    "fingerprint_schema",
    "validate_schema",
]
