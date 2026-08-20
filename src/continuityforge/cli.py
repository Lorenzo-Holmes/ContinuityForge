"""Command-line interface for the complete SQLite/CLI governance loop."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import __version__
from .compiler import MemoryCompiler
from .constants import (
    CLI_COMMAND_LIFECYCLE,
    CLI_ERROR_SCHEMA,
    CLI_LIFECYCLE_CREATE_CAPABLE,
    CLI_LIFECYCLE_EXPLICIT_MIGRATE,
    CLI_LIFECYCLE_READ_EXISTING,
    CLI_LIFECYCLE_WRITE_EXISTING,
    CLI_STABLE_DOMAIN_ERROR_CODES,
    EXIT_GOVERNANCE_FAILED,
    EXIT_LEDGER_FAILED,
    EXIT_OK,
    EXIT_SCHEMA_FAILED,
    EXIT_VALIDATION_FAILED,
)
from .evidence import EvidenceValidator, build_evidence_ref
from .exceptions import (
    ContinuityForgeError,
    DatabaseNotFoundError,
    EvidenceValidationError,
    ExplicitMigrationRequiredError,
    GovernanceConflictError,
    InspectionError,
    LedgerIntegrityError,
    MigrationError,
    NotFoundError,
    ReadOnlyStorageError,
    SchemaError,
)
from .governance import ClaimGovernance
from .ingest import ingest_content, ingest_path, parse_json_content
from .inspection import InspectionService
from .migrations import MigrationMode, migrate_to_v3, preflight_migration
from .models import (
    AccessPolicy,
    ClaimProposal,
    GovernanceStatus,
    MemoryCutoff,
    NarrativeEvent,
)
from .serialization import json_dumps, to_primitive, write_json
from .readonly import ReadOnlyProject
from .schema import SchemaKind, fingerprint_schema
from .storage import Storage
from .timeutil import isoformat_utc
from .validate import ProjectValidator


DEFAULT_DB = Path(".continuityforge") / "continuityforge.db"


def _add_db_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help=f"SQLite database path (default: {DEFAULT_DB})",
    )


def _add_claim_fields(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--persona", required=True, dest="persona_id")
    parser.add_argument("--continuity", required=True)
    parser.add_argument("--claim", "--text", required=True, dest="claim_text")
    parser.add_argument("--subject")
    parser.add_argument("--predicate")
    parser.add_argument("--object", dest="object_value")
    parser.add_argument("--valid-from")
    parser.add_argument("--valid-to", "--valid-until", dest="valid_to")
    parser.add_argument("--knowledge-from")
    parser.add_argument(
        "--knowledge-to", "--knowledge-until", dest="knowledge_to"
    )
    parser.add_argument(
        "--access",
        "--visibility",
        dest="access_policy",
        choices=[item.value for item in AccessPolicy],
        default=AccessPolicy.AGENT_ACCESSIBLE.value,
    )
    parser.add_argument("--confidence", type=float, default=1.0)
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="SNAPSHOT:START:END",
        help="one-based inclusive source span; repeat for multiple spans",
    )
    parser.add_argument("--rationale")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="continuityforge",
        description=(
            "Compile provenance-aware, timeline-safe memory packs for long-lived "
            "AI personas."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_db_option(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="import a versioned source snapshot")
    ingest.add_argument("path", nargs="+", type=Path)
    ingest.add_argument("--continuity", required=True)
    ingest.add_argument("--source-key")
    ingest.add_argument("--encoding")
    ingest.set_defaults(
        handler=_handle_ingest,
        lifecycle=CLI_COMMAND_LIFECYCLE["ingest"],
    )

    source_list = commands.add_parser("source-list", help="list logical sources")
    source_list.add_argument("--continuity")
    source_list.set_defaults(
        handler=_handle_source_list,
        lifecycle=CLI_COMMAND_LIFECYCLE["source-list"],
    )

    propose = commands.add_parser(
        "claim-propose", help="store untrusted model/human output as PROPOSED"
    )
    _add_claim_fields(propose)
    propose.add_argument("--provider", default="llm")
    propose.add_argument("--model")
    propose.add_argument(
        "--human",
        action="store_true",
        help="mark proposer as human; still does not authorize",
    )
    propose.set_defaults(
        handler=_handle_claim_propose,
        lifecycle=CLI_COMMAND_LIFECYCLE["claim-propose"],
    )

    claim_add = commands.add_parser(
        "claim-add",
        help="v0.1-compatible human add (propose, validate, authorize, ledger)",
    )
    _add_claim_fields(claim_add)
    claim_add.add_argument("--reviewer", default="cli:human")
    claim_add.add_argument(
        "--reason", default="v0.1 claim-add compatibility path"
    )
    claim_add.set_defaults(
        handler=_handle_claim_add,
        lifecycle=CLI_COMMAND_LIFECYCLE["claim-add"],
    )

    review = commands.add_parser(
        "claim-review", help="record AUTHORIZED, REJECTED, or DISPUTED"
    )
    review.add_argument("claim_id")
    review.add_argument(
        "--status",
        required=True,
        choices=[
            GovernanceStatus.AUTHORIZED.value.lower(),
            GovernanceStatus.REJECTED.value.lower(),
            GovernanceStatus.DISPUTED.value.lower(),
        ],
    )
    review.add_argument("--reviewer", required=True)
    review.add_argument("--reason", required=True)
    review.set_defaults(
        handler=_handle_claim_review,
        lifecycle=CLI_COMMAND_LIFECYCLE["claim-review"],
    )

    claim_list = commands.add_parser("claim-list", help="list claim proposals")
    claim_list.add_argument("--persona", dest="persona_id")
    claim_list.add_argument("--continuity")
    claim_list.add_argument(
        "--status", choices=[item.value.lower() for item in GovernanceStatus]
    )
    claim_list.set_defaults(
        handler=_handle_claim_list,
        lifecycle=CLI_COMMAND_LIFECYCLE["claim-list"],
    )

    event = commands.add_parser("event-add", help="append a source-backed narrative event")
    event.add_argument("--persona", required=True, dest="persona_id")
    event.add_argument("--continuity", required=True)
    event.add_argument("--type", default="narrative", dest="event_type")
    event.add_argument("--title", required=True)
    event.add_argument("--summary", required=True)
    event.add_argument("--details", default="{}", help="JSON object")
    event.add_argument("--valid-from")
    event.add_argument("--valid-to", "--valid-until", dest="valid_to")
    event.add_argument("--knowledge-from")
    event.add_argument("--knowledge-to", "--knowledge-until", dest="knowledge_to")
    event.add_argument(
        "--access",
        choices=[item.value for item in AccessPolicy],
        default=AccessPolicy.AGENT_ACCESSIBLE.value,
    )
    event.add_argument("--evidence", action="append", default=[])
    event.set_defaults(
        handler=_handle_event_add,
        lifecycle=CLI_COMMAND_LIFECYCLE["event-add"],
    )

    validate = commands.add_parser("validate", help="validate the complete project")
    validate.add_argument("--json", action="store_true", dest="as_json")
    validate.add_argument("--strict-proposals", action="store_true")
    validate.set_defaults(
        handler=_handle_validate,
        lifecycle=CLI_COMMAND_LIFECYCLE["validate"],
    )

    compile_command = commands.add_parser(
        "compile", help="compile an authorized memory pack at a cutoff"
    )
    compile_command.add_argument("--persona", required=True, dest="persona_id")
    compile_command.add_argument("--continuity", required=True)
    compile_command.add_argument("--cutoff", required=True, dest="knowledge_at")
    compile_command.add_argument("--valid-at")
    compile_command.add_argument("--include-human-only", action="store_true")
    compile_command.add_argument("-o", "--output", type=Path)
    compile_command.set_defaults(
        handler=_handle_compile,
        lifecycle=CLI_COMMAND_LIFECYCLE["compile"],
    )

    ledger_verify = commands.add_parser(
        "ledger-verify", help="verify the append-only EventLedger hash chain"
    )
    ledger_verify.set_defaults(
        handler=_handle_ledger_verify,
        lifecycle=CLI_COMMAND_LIFECYCLE["ledger-verify"],
    )

    ledger_show = commands.add_parser("ledger-show", help="print EventLedger entries")
    ledger_show.add_argument("--limit", type=int)
    ledger_show.set_defaults(
        handler=_handle_ledger_show,
        lifecycle=CLI_COMMAND_LIFECYCLE["ledger-show"],
    )

    source_impact = commands.add_parser(
        "source-impact",
        help="inspect source-revision impact without changing the project",
    )
    source_identity = source_impact.add_mutually_exclusive_group(required=True)
    source_identity.add_argument("--source-key")
    source_identity.add_argument("--source-id")
    source_impact.add_argument("--continuity", required=True)
    source_impact.add_argument("--from-version", type=int)
    source_impact.add_argument(
        "--target-version",
        "--to-version",
        dest="target_version",
        type=int,
        help="target revision (default: latest)",
    )
    source_impact.set_defaults(
        handler=_handle_source_impact,
        lifecycle=CLI_COMMAND_LIFECYCLE["source-impact"],
        owns_storage=True,
        requires_current=False,
        redact_errors=True,
    )

    migration_check = commands.add_parser(
        "migration-check",
        help="run a read-only schema-v3 migration preflight",
    )
    migration_check.add_argument(
        "--mode",
        choices=[item.value for item in MigrationMode],
        default=MigrationMode.STRICT.value,
    )
    migration_check.set_defaults(
        handler=_handle_migration_check,
        lifecycle=CLI_COMMAND_LIFECYCLE["migration-check"],
        owns_storage=True,
        requires_current=False,
        redact_errors=True,
    )

    migrate = commands.add_parser(
        "migrate",
        help="backup, migrate to schema v3, and verify the result",
    )
    migrate.add_argument(
        "--mode",
        choices=[item.value for item in MigrationMode],
        default=MigrationMode.STRICT.value,
    )
    migrate.set_defaults(
        handler=_handle_migrate,
        lifecycle=CLI_COMMAND_LIFECYCLE["migrate"],
        owns_storage=True,
        redact_errors=True,
    )

    demo = commands.add_parser("demo", help="run the Alpha/Beta isolation demo")
    demo.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    demo.add_argument("--reset", action="store_true")
    demo.set_defaults(
        handler=_handle_demo,
        lifecycle=CLI_COMMAND_LIFECYCLE["demo"],
        owns_storage=True,
    )
    return parser


def _parse_evidence_spec(spec: str) -> tuple[str, int, int]:
    try:
        snapshot_id, start, end = spec.rsplit(":", 2)
        start_line = int(start)
        end_line = int(end)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"invalid evidence {spec!r}; expected SNAPSHOT:START:END"
        ) from exc
    if not snapshot_id or start_line < 1 or end_line < start_line:
        raise ValueError(f"invalid evidence line span: {spec!r}")
    return snapshot_id, start_line, end_line


def _build_evidence(storage: Storage, specs: Iterable[str]) -> list[Any]:
    return [
        build_evidence_ref(storage, snapshot_id, start, end)
        for snapshot_id, start, end in map(_parse_evidence_spec, specs)
    ]


def _normalize_optional(value: str | None) -> str | None:
    return isoformat_utc(value) if value else None


def _claim_from_args(args: argparse.Namespace) -> ClaimProposal:
    return ClaimProposal(
        persona_id=args.persona_id,
        continuity=args.continuity,
        text=args.claim_text,
        subject=args.subject,
        predicate=args.predicate,
        object_value=args.object_value,
        valid_from=_normalize_optional(args.valid_from),
        valid_to=_normalize_optional(args.valid_to),
        knowledge_from=_normalize_optional(args.knowledge_from),
        knowledge_to=_normalize_optional(args.knowledge_to),
        access_policy=AccessPolicy(args.access_policy),
        confidence=args.confidence,
        rationale=args.rationale,
    )


def _handle_ingest(storage: Storage, args: argparse.Namespace) -> int:
    if args.source_key and len(args.path) != 1:
        raise ValueError("--source-key can only be used with one path")
    imported: list[dict[str, Any]] = []
    for path in args.path:
        source_key = args.source_key or path.name
        source, snapshot, created = ingest_path(
            storage,
            path,
            source_key,
            args.continuity,
            encoding=args.encoding,
        )
        imported.append(
            {
                "source_id": source.source_id,
                "source_key": source.source_key,
                "snapshot_id": snapshot.snapshot_id,
                "version": snapshot.version,
                "sha256": snapshot.content_hash,
                "created": created,
            }
        )
    print(json_dumps({"ingested": imported}))
    return EXIT_OK


def _handle_source_list(storage: Storage, args: argparse.Namespace) -> int:
    sources = storage.list_sources(continuity=args.continuity)
    print(json_dumps({"sources": sources}))
    return EXIT_OK


def _handle_claim_propose(storage: Storage, args: argparse.Namespace) -> int:
    governance = ClaimGovernance(storage)
    proposal = _claim_from_args(args)
    refs = _build_evidence(storage, args.evidence)
    if args.human:
        saved = governance.propose(proposal, refs, proposed_by="human")
    else:
        payload = to_primitive(proposal)
        saved = governance.propose_from_llm(
            payload, refs, provider=args.provider, model=args.model
        )
    report = governance.validate_evidence(saved.claim_id)
    print(
        json_dumps(
            {
                "claim": saved,
                "evidence_validation": report.to_dict(),
                "authorization_granted": False,
            }
        )
    )
    return EXIT_OK


def _handle_claim_add(storage: Storage, args: argparse.Namespace) -> int:
    governance = ClaimGovernance(storage)
    saved = governance.add_authorized_human_claim(
        _claim_from_args(args),
        _build_evidence(storage, args.evidence),
        reviewer=args.reviewer,
        reason=args.reason,
    )
    print(json_dumps({"claim": saved, "authorization_granted": True}))
    return EXIT_OK


def _handle_claim_review(storage: Storage, args: argparse.Namespace) -> int:
    governance = ClaimGovernance(storage)
    decision = governance.review(
        args.claim_id,
        GovernanceStatus(args.status),
        reviewer=args.reviewer,
        reason=args.reason,
    )
    print(json_dumps({"decision": decision}))
    return EXIT_OK


def _handle_claim_list(storage: Storage, args: argparse.Namespace) -> int:
    claims = storage.list_claim_proposals(
        persona_id=args.persona_id,
        continuity=args.continuity,
        status=GovernanceStatus(args.status) if args.status else None,
    )
    print(json_dumps({"claims": claims}))
    return EXIT_OK


def _handle_event_add(storage: Storage, args: argparse.Namespace) -> int:
    details = parse_json_content(args.details)
    if not isinstance(details, dict):
        raise ValueError("--details must be a JSON object")
    event = NarrativeEvent(
        persona_id=args.persona_id,
        continuity=args.continuity,
        event_type=args.event_type,
        title=args.title,
        summary=args.summary,
        details=details,
        valid_from=_normalize_optional(args.valid_from),
        valid_to=_normalize_optional(args.valid_to),
        knowledge_from=_normalize_optional(args.knowledge_from),
        knowledge_to=_normalize_optional(args.knowledge_to),
        access_policy=AccessPolicy(args.access),
    )
    refs = _build_evidence(storage, args.evidence)
    report = EvidenceValidator(storage).validate_claim(event, refs)
    report.raise_for_errors()
    saved = storage.create_narrative_event(event, refs)
    print(json_dumps({"event": saved, "evidence_validation": report.to_dict()}))
    return EXIT_OK


def _handle_validate(storage: Storage, args: argparse.Namespace) -> int:
    report = ProjectValidator(storage).validate(
        strict_proposals=args.strict_proposals
    )
    if args.as_json:
        print(report.to_json())
    else:
        state = "PASS" if report.is_valid else "FAIL"
        print(
            f"{state}: {report.error_count} error(s), "
            f"{report.warning_count} warning(s)"
        )
        for issue in report.issues:
            target = f" {issue.aggregate_type}:{issue.aggregate_id}" if issue.aggregate_id else ""
            print(f"[{issue.severity.value.upper()}] {issue.code}{target} - {issue.message}")
    return EXIT_OK if report.is_valid else EXIT_VALIDATION_FAILED


def _handle_compile(storage: Storage, args: argparse.Namespace) -> int:
    policies = [AccessPolicy.AGENT_ACCESSIBLE]
    if args.include_human_only:
        policies.append(AccessPolicy.HUMAN_ONLY)
    cutoff = MemoryCutoff(
        persona_id=args.persona_id,
        continuity=args.continuity,
        knowledge_at=isoformat_utc(args.knowledge_at) or args.knowledge_at,
        valid_at=_normalize_optional(args.valid_at),
        access_policies=tuple(policies),
    )
    compiler = MemoryCompiler(storage)
    pack = compiler.compile(cutoff)
    if args.output:
        destination = write_json(args.output, pack)
        print(json_dumps({"output": str(destination), "stats": pack["stats"]}))
    else:
        print(json_dumps(pack))
    return EXIT_OK


def _handle_ledger_verify(storage: Storage, args: argparse.Namespace) -> int:
    verdict = storage.verify_ledger()
    valid = verdict if isinstance(verdict, bool) else bool(getattr(verdict, "is_valid", verdict))
    print(json_dumps({"valid": valid, "result": verdict}))
    return EXIT_OK if valid else EXIT_LEDGER_FAILED


def _handle_ledger_show(storage: Storage, args: argparse.Namespace) -> int:
    entries = storage.list_ledger_entries(limit=args.limit)
    print(json_dumps({"entries": entries}))
    return EXIT_OK


def _handle_source_impact(
    _storage: Storage | None, args: argparse.Namespace
) -> int:
    """Emit a metadata-only, report-only source revision assessment."""

    with ReadOnlyProject.open(args.db) as repository:
        report = InspectionService(repository).source_impact(
            source_id=args.source_id,
            source_key=args.source_key,
            continuity=args.continuity,
            from_version=args.from_version,
            target_version=args.target_version,
        )
    print(json_dumps(report.to_dict()))
    return EXIT_OK


def _handle_migration_check(
    _storage: Storage | None, args: argparse.Namespace
) -> int:
    """Inspect migration eligibility without creating, backing up, or changing DB."""

    report = preflight_migration(
        args.db,
        mode=MigrationMode(args.mode),
        create_backup=False,
    )
    print(json_dumps(report.to_dict()))
    return EXIT_OK if report.is_ready else EXIT_SCHEMA_FAILED


def _handle_migrate(_storage: Storage | None, args: argparse.Namespace) -> int:
    """Run the explicit backup-gated schema-v3 migration workflow."""

    report = migrate_to_v3(
        args.db,
        mode=MigrationMode(args.mode),
        create_backup=True,
    )
    print(json_dumps(report.to_dict()))
    return EXIT_OK if report.succeeded else EXIT_SCHEMA_FAILED


def _handle_demo(_storage: Storage | None, args: argparse.Namespace) -> int:
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "continuityforge-demo.db"
    if args.reset and db_path.exists():
        db_path.unlink()
    elif db_path.exists() or db_path.is_symlink():
        # Demo is create-capable, not migration-capable.  Reusing a legacy or
        # malformed file must never silently run Storage's migration path.
        db_path = _require_current_database(db_path)
    with Storage(db_path) as storage:
        alpha = "Mira entered the Alpha observatory.\nThe archive code is ORION-7.\n"
        beta = "Mira never reached the Beta observatory.\nThe archive remained sealed.\n"
        _, alpha_snapshot, _ = ingest_content(
            storage, alpha, "demo-story", "alpha", origin_path="generated:demo-alpha"
        )
        _, beta_snapshot, _ = ingest_content(
            storage, beta, "demo-story", "beta", origin_path="generated:demo-beta"
        )
        governance = ClaimGovernance(storage)
        early = governance.add_authorized_human_claim(
            ClaimProposal(
                persona_id="mira",
                continuity="alpha",
                text="Mira entered the Alpha observatory.",
                subject="mira",
                predicate="location",
                object_value="alpha-observatory",
                valid_from="2026-01-01T00:00:00Z",
                knowledge_from="2026-01-01T00:00:00Z",
            ),
            [build_evidence_ref(storage, alpha_snapshot.snapshot_id, 1, 1)],
        )
        future = governance.add_authorized_human_claim(
            ClaimProposal(
                persona_id="mira",
                continuity="alpha",
                text="The archive code is ORION-7.",
                subject="archive",
                predicate="code",
                object_value="ORION-7",
                valid_from="2026-01-01T00:00:00Z",
                knowledge_from="2026-01-03T00:00:00Z",
            ),
            [build_evidence_ref(storage, alpha_snapshot.snapshot_id, 2, 2)],
        )
        beta_claim = governance.add_authorized_human_claim(
            ClaimProposal(
                persona_id="mira",
                continuity="beta",
                text="Mira never reached the Beta observatory.",
                subject="mira",
                predicate="location",
                object_value="not-beta-observatory",
                valid_from="2026-01-01T00:00:00Z",
                knowledge_from="2026-01-01T00:00:00Z",
            ),
            [build_evidence_ref(storage, beta_snapshot.snapshot_id, 1, 1)],
        )
        cutoff = MemoryCutoff(
            persona_id="mira",
            continuity="alpha",
            knowledge_at="2026-01-02T00:00:00Z",
        )
        compiler = MemoryCompiler(storage)
        pack = compiler.compile(cutoff)
        pack_path = compiler.compile_to_path(cutoff, output_dir / "alpha-jan-02.pack.json")
        claim_ids = {item["id"] for item in pack["claims"]}
        checks = {
            "alpha_claim_included": early.claim_id in claim_ids,
            "future_knowledge_excluded": future.claim_id not in claim_ids,
            "beta_continuity_excluded": beta_claim.claim_id not in claim_ids,
            "ledger_valid": bool(storage.verify_ledger()),
        }
        print(
            json_dumps(
                {
                    "database": str(db_path),
                    "memory_pack": str(pack_path),
                    "checks": checks,
                    "pass": all(checks.values()),
                }
            )
        )
        return EXIT_OK if all(checks.values()) else EXIT_VALIDATION_FAILED


def _require_existing_database(database: str | Path) -> Path:
    """Resolve an existing regular DB without creating parents or sidecars."""

    candidate = Path(database).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DatabaseNotFoundError("project database not found") from exc
    if not resolved.is_file():
        raise DatabaseNotFoundError("project database not found")
    return resolved


def _database_schema_kind(database: Path) -> SchemaKind:
    """Fingerprint a database through SQLite's existing-file read-only mode."""

    connection = sqlite3.connect(
        f"{database.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
    )
    try:
        return fingerprint_schema(connection).kind
    finally:
        connection.close()


def _require_readonly_sidecars(database: Path) -> None:
    """Prevent SQLite from creating a missing shared-memory WAL sidecar."""

    wal_path = database.with_name(database.name + "-wal")
    shm_path = database.with_name(database.name + "-shm")
    if os.path.lexists(wal_path) and not os.path.lexists(shm_path):
        raise ReadOnlyStorageError(
            "read-only command requires an existing -shm sidecar when -wal exists"
        )


def _require_current_database(database: str | Path) -> Path:
    resolved = _require_existing_database(database)
    kind = _database_schema_kind(resolved)
    if kind in {SchemaKind.V01, SchemaKind.V02, SchemaKind.V03_ALPHA2}:
        raise ExplicitMigrationRequiredError(
            "database requires explicit migration; run 'continuityforge migrate'"
        )
    if kind is not SchemaKind.V03:
        raise SchemaError("database schema is unsupported or incomplete")
    return resolved


def _run(args: argparse.Namespace) -> int:
    lifecycle = getattr(args, "lifecycle", None)

    if lifecycle == CLI_LIFECYCLE_EXPLICIT_MIGRATE:
        args.db = _require_existing_database(args.db)
        return args.handler(None, args)

    if lifecycle == CLI_LIFECYCLE_READ_EXISTING:
        args.db = _require_existing_database(args.db)
        _require_readonly_sidecars(args.db)
        if getattr(args, "requires_current", True):
            args.db = _require_current_database(args.db)
        if getattr(args, "owns_storage", False):
            return args.handler(None, args)
        with Storage.open_readonly(args.db) as storage:
            return args.handler(storage, args)

    if lifecycle == CLI_LIFECYCLE_WRITE_EXISTING:
        args.db = _require_current_database(args.db)
        with Storage(args.db) as storage:
            return args.handler(storage, args)

    if lifecycle == CLI_LIFECYCLE_CREATE_CAPABLE:
        if getattr(args, "owns_storage", False):
            return args.handler(None, args)
        candidate = Path(args.db).expanduser()
        if candidate.exists() or candidate.is_symlink():
            args.db = _require_current_database(candidate)
        else:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            args.db = candidate
        with Storage(args.db) as storage:
            return args.handler(storage, args)

    raise SchemaError("command lifecycle contract is missing or invalid")


def _stable_error_code(exc: BaseException) -> str:
    domain_code = getattr(exc, "code", None)
    if (
        isinstance(domain_code, str)
        and domain_code.strip() in CLI_STABLE_DOMAIN_ERROR_CODES
    ):
        return domain_code.strip()
    if isinstance(exc, DatabaseNotFoundError):
        return "DATABASE_NOT_FOUND"
    if isinstance(exc, ExplicitMigrationRequiredError):
        return "MIGRATION_REQUIRED"
    if isinstance(exc, MigrationError):
        return "MIGRATION_FAILED"
    if isinstance(exc, ReadOnlyStorageError):
        return "READ_ONLY_STORAGE_ERROR"
    if isinstance(exc, SchemaError):
        return "SCHEMA_ERROR"
    if isinstance(exc, EvidenceValidationError):
        return "EVIDENCE_VALIDATION_FAILED"
    if isinstance(exc, GovernanceConflictError):
        return "GOVERNANCE_CONFLICT"
    if isinstance(exc, LedgerIntegrityError):
        return "LEDGER_INTEGRITY_FAILED"
    if isinstance(exc, InspectionError):
        return "INSPECTION_ERROR"
    if isinstance(exc, NotFoundError):
        return "NOT_FOUND"
    if isinstance(exc, FileNotFoundError):
        return "NOT_FOUND"
    if isinstance(exc, sqlite3.Error):
        return "SQLITE_ERROR"
    if isinstance(exc, ContinuityForgeError):
        return "DOMAIN_ERROR"
    return "INVALID_ARGUMENT"


def _public_error_message(
    exc: BaseException, args: argparse.Namespace
) -> str:
    """Keep administrative errors useful without disclosing local DB paths."""

    message = str(exc)
    if not getattr(args, "redact_errors", False):
        return message
    candidates = {str(args.db), str(Path(args.db).expanduser())}
    try:
        candidates.add(str(Path(args.db).expanduser().resolve()))
    except OSError:
        pass
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            message = message.replace(candidate, "<DB>")
    return message


def _emit_error(
    exc: BaseException,
    args: argparse.Namespace,
    *, details: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "schema": CLI_ERROR_SCHEMA,
        "code": _stable_error_code(exc),
        # Retained for v0.2 CLI consumers that keyed on the exception name.
        "error": type(exc).__name__,
        "message": _public_error_message(exc, args),
    }
    if details and not getattr(args, "redact_errors", False):
        payload.update(details)
    print(json_dumps(payload), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return _run(args)
    except (EvidenceValidationError, GovernanceConflictError) as exc:
        details: dict[str, Any] = {}
        if getattr(exc, "report", None) is not None:
            details["report"] = exc.report.to_dict()
        if getattr(exc, "conflicting_ids", None):
            details["conflicting_ids"] = exc.conflicting_ids
        _emit_error(exc, args, details=details)
        return EXIT_GOVERNANCE_FAILED
    except LedgerIntegrityError as exc:
        _emit_error(exc, args)
        return EXIT_LEDGER_FAILED
    except (MigrationError, ReadOnlyStorageError, SchemaError, sqlite3.Error) as exc:
        details = {}
        if getattr(exc, "report", None) is not None:
            details["report"] = exc.report.to_dict()
        _emit_error(exc, args, details=details)
        return EXIT_SCHEMA_FAILED
    except (ContinuityForgeError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        _emit_error(exc, args)
        return EXIT_VALIDATION_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
