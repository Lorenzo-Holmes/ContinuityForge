# ContinuityForge v0.3 owner decisions

**Status:** Accepted
**Date:** 2026-08-19
**Theme:** SourceSnapshot Revision Impact Review

These decisions define the trust and product boundary for v0.3. They do not
weaken the frozen v0.1 observable contract or the v0.2 provenance model.

## Accepted decisions

1. **The operating-system and SQLite file owner is trusted.** v0.3 defends
   against application defects, untrusted model output, malformed input, and
   ordinary integration misuse. Protection against an attacker who can replace
   the entire database requires an external signed checkpoint and is out of
   scope.
2. **NarrativeEvent remains human/operator-only.** Model extraction produces
   ClaimProposal values. A future EventProposal lifecycle would require a
   separate design.
3. **Snapshot impact is report-only.** Ingesting a new SourceSnapshot never
   changes Claim governance state automatically. A reviewer may explicitly
   move an affected Claim to DISPUTED.
4. **Malformed legacy data fails closed.** Canonical migrations are strict by
   default. An explicit quarantine mode may only reduce authority or access;
   it never converts malformed time to unbounded time or missing access to
   agent_accessible.
5. **Schema version 3 is approved.** The migration must be transactional,
   fingerprinted, backed up, machine-reportable, and covered by restoration and
   regression tests.

## v0.3 implementation order

1. Trust boundary and migration gate.
2. Deterministic SourceSnapshot impact engine and read-only inspection.
3. CLI integration, adversarial testing, packaging, documentation, and demos.

## Explicitly deferred

- FastAPI or another HTTP transport
- MCP, OpenAI-compatible, or memory-store adapters
- provider SDK interfaces
- a graphical workbench
- semantic or LLM-decided impact classification
- automatic AUTHORIZED to DISPUTED transitions
