# ContinuityForge v0.1 Baseline Contract

This contract, its legacy SQLite fixture, and the machine-readable contract are SHA-256 locked in `tests/baseline/v01_baseline.lock.json`. Any intentional change must carry a visible lock update, versioned migration, regression update, and release note.

Status: **frozen compatibility baseline**  
Applies to: all v0.2 and later changes unless a new major-version contract explicitly replaces it

## Purpose

v0.1 established the first complete ContinuityForge loop: ingest source material, attach exact evidence to claims, enforce persona/continuity/time/access boundaries, persist the result in SQLite, validate it, and compile a JSON Memory Pack.

v0.2 may extend this loop. It must not silently weaken it.

“Baseline” here means observable guarantees, not an implementation freeze. Internal modules, indexes, and schemas may evolve when migrations and regression tests preserve the behaviors below.

## Baseline guarantees

### B1. Supported source ingestion

The CLI accepts the following source types:

- plain text: `.txt`;
- Markdown: `.md`, `.markdown`;
- JSON text: `.json`;
- SubRip subtitles: `.srt`.

The imported text remains addressable by source line. Importers must not silently rewrite content in a way that changes evidence coordinates.

### B2. Content-addressed source snapshots

Every imported `SourceSnapshot` has a SHA-256 identity derived from its content. A claim cites the snapshot it was actually derived from, not merely a mutable file path or display name.

v0.2 adds logical source IDs and ordered versions while retaining this content identity. Existing evidence remains anchored to the historical snapshot.

### B3. Exact provenance

Claim evidence uses a `SourceSpan` / `EvidenceRef` with an existing snapshot and bounded line range.

- lines are 1-based;
- the end line is inclusive;
- `1 <= start_line <= end_line <= snapshot.line_count`;
- a missing source or out-of-range span is invalid;
- an authorized, compilable claim cannot be source-free.

Memory Pack output retains enough claim/source identity to trace emitted memory back to the cited source.

### B4. Persona and continuity isolation

Claims are scoped by `persona_id` and `continuity`.

- compiling continuity Alpha must not emit continuity Beta claims;
- evidence from one continuity must not authorize a claim in another;
- a compile request for one persona must not leak another persona's scoped memory.

No fuzzy, case-insensitive, or model-inferred continuity matching is allowed in the trusted compiler path.

### B5. Separate fact time and knowledge time

The model distinguishes:

- **valid time**: when a fact holds in the represented world;
- **knowledge time**: when the persona may know the fact.

These intervals are not interchangeable. A fact may already be true while remaining unavailable to a persona until a later learning event.

### B6. `MemoryCutoff`

Compilation takes an explicit cutoff. A claim learned after the cutoff is excluded even if its supporting source already exists in the database.

The canonical fixture demonstrates this boundary:

```text
knowledge begins: 2026-01-03
compile cutoff:   2026-01-02
result:           excluded
```

### B7. Access isolation

The baseline access classes are:

- `agent_accessible` — eligible for agent-facing compilation;
- `human_only` — retained for human workflows but excluded from agent memory packs;
- `hidden` — excluded from normal compilation.

An access default or missing value must not silently broaden visibility.

### B8. Deterministic validation

Validation detects at least:

- a claim with no evidence;
- a reference to a missing snapshot;
- an evidence range outside the snapshot;
- evidence and claim continuity mismatch;
- contradictory facts within the same scoped continuity when represented by the baseline conflict key.

Adding validators is compatible. Removing or weakening one requires an explicit replacement with equal or stronger coverage.

### B9. SQLite and CLI loop

The baseline remains usable without importing internal Python modules:

```text
ingest -> claim-add -> validate -> compile
```

Data persists in a local SQLite database. The compiled artifact is JSON and is suitable for downstream memory adapters.

v0.2 extends the loop with `claim-propose`, `claim-review`, `event-add`, and `ledger-verify`; it does not remove the human `claim-add` compatibility path.

### B10. Alpha/Beta proof fixture

The repository retains an original, synthetic dual-continuity scenario that proves:

1. Alpha claims can enter an Alpha pack;
2. Beta claims cannot enter an Alpha pack;
3. knowledge acquired on January 3 cannot enter a January 2 pack;
4. source provenance remains inspectable in the result.

The fixture contains no dependency on proprietary fiction or user data.

## Compatibility policy

### Changes permitted in a minor release

- additive tables, columns, indexes, commands, and output fields;
- stricter validation that identifies previously unsafe data;
- new source adapters that preserve raw line addressing;
- performance improvements with equivalent results;
- explicit migrations that retain provenance and scope.

### Changes requiring an explicit breaking contract

- changing line-number semantics;
- overwriting historical source snapshots;
- compiling cross-continuity matches;
- treating model confidence as authorization;
- making `human_only` or `hidden` agent-accessible;
- removing cutoff enforcement;
- accepting source-free claims into normal compiled output;
- deleting or rewriting audit history;
- changing an existing field's meaning without a migration.

Such a change must include all of the following:

1. a versioned migration or conversion path;
2. an updated contract document;
3. regression tests that make the new boundary explicit;
4. release notes calling out the behavior change;
5. a rollback or export path when persisted data is affected.

## Regression gate

Before a release, the baseline suite under `tests/baseline/` must pass together with the v0.2 suite:

```bash
python -m pytest
continuityforge demo --output-dir demo-output
```

At minimum, release verification must cover:

| Test | Expected result |
|---|---|
| Alpha evidence used by an Alpha claim | valid |
| Beta evidence used by an Alpha claim | invalid |
| missing or out-of-range evidence | invalid |
| `human_only` claim compiled for an agent | excluded |
| January 3 knowledge compiled at January 2 cutoff | excluded |
| authorized, in-scope Alpha claim at a later cutoff | included with provenance |

## v0.2 relationship

v0.2 strengthens the baseline in five ways:

1. a logical source gains immutable ordered snapshots;
2. evidence may verify both its quoted text and normalized-text hash;
3. an LLM can create proposals but cannot write authorized canon;
4. governance decisions explicitly produce `AUTHORIZED`, `REJECTED`, or `DISPUTED` outcomes;
5. material operations are recorded in a verifiable append-only `EventLedger`.

These additions are defined in [V0_2_DESIGN.md](V0_2_DESIGN.md).
