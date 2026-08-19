"""Compile governed claims into timeline-safe persona memory packs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .constants import PACKAGE_SCHEMA, V01_PACKAGE_SCHEMA
from .evidence import EvidenceValidator
from .event_integrity import EventAuditStorage, validate_event_audits
from .exceptions import LedgerIntegrityError
from .governance_integrity import AuthorityStorage, validate_claim_authorities
from .models import (
    AccessPolicy,
    ClaimProposal,
    EvidenceRef,
    GovernanceStatus,
    MemoryCutoff,
    NarrativeEvent,
    Source,
    SourceSnapshot,
)
from .serialization import write_json
from .timeutil import contains_instant, isoformat_utc


class CompilerStorage(AuthorityStorage, EventAuditStorage, Protocol):
    def list_claim_proposals(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
        status: GovernanceStatus | str | None = None,
    ) -> list[ClaimProposal]: ...

    def get_claim_evidence(self, claim_id: str) -> list[EvidenceRef]: ...

    def get_snapshot(self, snapshot_id: str) -> SourceSnapshot: ...

    def get_source(
        self,
        source_id: str | None = None,
        *,
        source_key: str | None = None,
        continuity: str | None = None,
    ) -> Source: ...

    def list_narrative_events(
        self,
        *,
        persona_id: str | None = None,
        continuity: str | None = None,
    ) -> list[NarrativeEvent]: ...

    def get_event_evidence(self, event_id: str) -> list[EvidenceRef]: ...

    def verify_ledger(self) -> Any: ...


@dataclass(frozen=True, slots=True)
class CompilationDiagnostic:
    code: str
    aggregate_id: str
    message: str
    details: dict[str, Any]


def _visible_at(
    *,
    knowledge_from: str | None,
    knowledge_to: str | None,
    valid_from: str | None,
    valid_to: str | None,
    cutoff: MemoryCutoff,
) -> bool:
    if not contains_instant(knowledge_from, knowledge_to, cutoff.knowledge_at):
        return False
    if cutoff.valid_at is not None and not contains_instant(
        valid_from, valid_to, cutoff.valid_at
    ):
        return False
    return True


class MemoryCompiler:
    """Build a provenance-complete pack at an explicit MemoryCutoff."""

    def __init__(self, storage: CompilerStorage) -> None:
        self.storage = storage
        self.evidence = EvidenceValidator(storage)

    def compile(self, cutoff: MemoryCutoff) -> dict[str, Any]:
        """Compile against one pinned repository snapshot when supported."""

        read_transaction = getattr(self.storage, "read_transaction", None)
        if callable(read_transaction):
            with read_transaction():
                return self._compile_pinned(cutoff)
        return self._compile_pinned(cutoff)

    def _compile_pinned(self, cutoff: MemoryCutoff) -> dict[str, Any]:
        if not cutoff.persona_id.strip():
            raise ValueError("persona_id must be non-empty")
        if not cutoff.continuity.strip():
            raise ValueError("continuity must be non-empty")
        knowledge_at = isoformat_utc(cutoff.knowledge_at)
        valid_at = isoformat_utc(cutoff.valid_at)
        assert knowledge_at is not None

        # Governance decisions are authoritative only while the database-wide
        # audit chain that binds them is intact.  Per-claim replay below checks
        # exact decision correspondence; this global check also detects a
        # broken predecessor/successor link elsewhere in EventLedger.  Failing
        # here rather than emitting a partial pack prevents callers from
        # mistaking a result produced from tampered authority history for a
        # valid compilation.
        try:
            ledger_verdict = self.storage.verify_ledger()
        except (AttributeError, NotImplementedError) as exc:
            raise LedgerIntegrityError(
                "compiler storage cannot verify the EventLedger hash chain"
            ) from exc
        ledger_valid = (
            bool(ledger_verdict[0])
            if isinstance(ledger_verdict, tuple) and ledger_verdict
            else bool(
                getattr(ledger_verdict, "is_valid", ledger_verdict)
            )
        )
        if not ledger_valid:
            raise LedgerIntegrityError(
                "EventLedger hash-chain verification failed before compilation"
            )

        allowed = {AccessPolicy(item) for item in cutoff.access_policies}
        # HIDDEN is never exportable, including human inspection packs.
        allowed.discard(AccessPolicy.HIDDEN)
        diagnostics: list[CompilationDiagnostic] = []
        compiled_claims: list[dict[str, Any]] = []

        claims = self.storage.list_claim_proposals(
            persona_id=cutoff.persona_id,
            continuity=cutoff.continuity,
            status=GovernanceStatus.AUTHORIZED,
        )
        authority_reports = validate_claim_authorities(self.storage, claims)
        for claim in claims:
            if claim.persona_id != cutoff.persona_id or claim.continuity != cutoff.continuity:
                diagnostics.append(
                    CompilationDiagnostic(
                        "ISOLATION_GUARD",
                        claim.claim_id,
                        "storage returned a claim outside the requested identity boundary",
                        {
                            "persona_id": claim.persona_id,
                            "continuity": claim.continuity,
                        },
                    )
                )
                continue
            if claim.status is not GovernanceStatus.AUTHORIZED:
                diagnostics.append(
                    CompilationDiagnostic(
                        "UNAUTHORIZED_CLAIM",
                        claim.claim_id,
                        "only AUTHORIZED claims may be compiled",
                        {"status": claim.status.value},
                    )
                )
                continue
            authority = authority_reports[claim.claim_id]
            if not authority.is_authorized:
                diagnostics.append(
                    CompilationDiagnostic(
                        "AUTHORITY_CHAIN_INVALID",
                        claim.claim_id,
                        "claim status is not backed by a complete decision and ledger chain",
                        authority.to_dict(),
                    )
                )
                continue
            if claim.access_policy not in allowed:
                continue
            if not _visible_at(
                knowledge_from=claim.knowledge_from,
                knowledge_to=claim.knowledge_to,
                valid_from=claim.valid_from,
                valid_to=claim.valid_to,
                cutoff=cutoff,
            ):
                continue

            refs = self.storage.get_claim_evidence(claim.claim_id)
            evidence_report = self.evidence.validate_claim(claim, refs)
            if not evidence_report.is_valid:
                diagnostics.append(
                    CompilationDiagnostic(
                        "EVIDENCE_INVALID",
                        claim.claim_id,
                        "authorized claim failed compile-time evidence revalidation",
                        evidence_report.to_dict(),
                    )
                )
                continue
            compiled_claims.append(self._compile_claim(claim, refs))

        compiled_claims.sort(
            key=lambda item: (
                item.get("knowledge_from") or "",
                item.get("valid_from") or "",
                item["id"],
            )
        )
        compiled_events = self._compile_events(cutoff, allowed, diagnostics)

        return {
            "schema": PACKAGE_SCHEMA,
            "schema_version": "0.2",
            "compatibility_schema": V01_PACKAGE_SCHEMA,
            "persona_id": cutoff.persona_id,
            "continuity": cutoff.continuity,
            # v0.1 key retained verbatim.
            "memory_cutoff": knowledge_at,
            "cutoff": {"knowledge_at": knowledge_at, "valid_at": valid_at},
            "access_policies": sorted(policy.value for policy in allowed),
            "compiled_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "claims": compiled_claims,
            "events": compiled_events,
            "diagnostics": [asdict(item) for item in diagnostics],
            "stats": {
                "claims": len(compiled_claims),
                "events": len(compiled_events),
                "excluded_with_diagnostics": len(diagnostics),
            },
        }

    def compile_to_path(self, cutoff: MemoryCutoff, path: str | Path) -> Path:
        return write_json(path, self.compile(cutoff))

    def _compile_claim(
        self, claim: ClaimProposal, refs: list[EvidenceRef]
    ) -> dict[str, Any]:
        provenance = self._compile_provenance(refs)

        first = provenance[0]
        return {
            "id": claim.claim_id,
            # v0.1 name plus v0.2's explicit text name.
            "claim": claim.text,
            "text": claim.text,
            "persona_id": claim.persona_id,
            "continuity": claim.continuity,
            "subject": claim.subject,
            "predicate": claim.predicate,
            "object": claim.object_value,
            "object_value": claim.object_value,
            "valid_from": claim.valid_from,
            "valid_until": claim.valid_to,
            "valid_to": claim.valid_to,
            "knowledge_from": claim.knowledge_from,
            "knowledge_until": claim.knowledge_to,
            "knowledge_to": claim.knowledge_to,
            "visibility": claim.access_policy.value,
            "access_policy": claim.access_policy.value,
            "confidence": float(getattr(claim, "confidence", 1.0)),
            # v0.1 treated a compiled claim as supported. v0.2 exposes the
            # governance decision alongside that compatibility spelling.
            "status": "supported",
            "governance_status": claim.status.value,
            "source_id": first["source_id"],
            "source_snapshot_id": first["snapshot_id"],
            "source_span": first["source_span"],
            "provenance": provenance,
        }

    def _compile_provenance(self, refs: list[EvidenceRef]) -> list[dict[str, Any]]:
        provenance: list[dict[str, Any]] = []
        for ref in refs:
            snapshot = self.storage.get_snapshot(ref.snapshot_id)
            source = self.storage.get_source(snapshot.source_id)
            provenance.append(
                {
                    "source_id": source.source_id,
                    "source_key": source.source_key,
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_version": snapshot.version,
                    "snapshot_sha256": snapshot.content_hash,
                    "source_span": {
                        "start_line": ref.start_line,
                        "end_line": ref.end_line,
                        "start_char": ref.start_char,
                        "end_char": ref.end_char,
                    },
                    "quote": ref.quote,
                    "quote_sha256": ref.content_hash,
                }
            )
        return provenance

    def _compile_events(
        self,
        cutoff: MemoryCutoff,
        allowed: set[AccessPolicy],
        diagnostics: list[CompilationDiagnostic],
    ) -> list[dict[str, Any]]:
        try:
            events = self.storage.list_narrative_events(
                persona_id=cutoff.persona_id, continuity=cutoff.continuity
            )
        except AttributeError:
            # Storage implementations from the v0.1 embedding API did not have
            # narrative events; compiling claims remains backward compatible.
            return []
        audit_reports = validate_event_audits(self.storage, events)
        result: list[dict[str, Any]] = []
        for event in events:
            if event.persona_id != cutoff.persona_id or event.continuity != cutoff.continuity:
                continue
            if event.access_policy not in allowed:
                continue
            if not _visible_at(
                knowledge_from=event.knowledge_from,
                knowledge_to=event.knowledge_to,
                valid_from=event.valid_from,
                valid_to=event.valid_to,
                cutoff=cutoff,
            ):
                continue
            audit = audit_reports[event.event_id]
            if not audit.is_valid:
                diagnostics.append(
                    CompilationDiagnostic(
                        "EVENT_AUDIT_INVALID",
                        event.event_id,
                        "narrative event is not backed by one complete ledger record",
                        audit.to_dict(),
                    )
                )
                continue
            try:
                refs = self.storage.get_event_evidence(event.event_id)
            except AttributeError:
                refs = []
            evidence_report = self.evidence.validate_claim(event, refs)
            if not evidence_report.is_valid:
                diagnostics.append(
                    CompilationDiagnostic(
                        "EVIDENCE_INVALID",
                        event.event_id,
                        "narrative event failed compile-time evidence validation",
                        evidence_report.to_dict(),
                    )
                )
                continue
            result.append(
                {
                    "id": event.event_id,
                    "event_type": event.event_type,
                    "title": event.title,
                    "summary": event.summary,
                    "details": dict(event.details),
                    "persona_id": event.persona_id,
                    "continuity": event.continuity,
                    "valid_from": event.valid_from,
                    "valid_to": event.valid_to,
                    "knowledge_from": event.knowledge_from,
                    "knowledge_to": event.knowledge_to,
                    "access_policy": event.access_policy.value,
                    "provenance": self._compile_provenance(refs),
                }
            )
        result.sort(key=lambda item: (item.get("valid_from") or "", item["id"]))
        return result


__all__ = ["CompilationDiagnostic", "CompilerStorage", "MemoryCompiler"]
