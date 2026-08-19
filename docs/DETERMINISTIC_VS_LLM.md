# Deterministic Core vs LLM Assistance

## Governing principle

An LLM may propose language and structure. It may not decide provenance, authority, continuity, access, time eligibility, migration safety, ledger integrity, or snapshot impact.

```text
LLM output -> PROPOSED data -> deterministic validation -> explicit human review
```

## Responsibility matrix

| Task | LLM allowed? | Trusted decision maker |
|---|:---:|---|
| Suggest claim text | Yes | Proposal only |
| Suggest subject/predicate/object | Yes | Proposal only |
| Suggest evidence coordinates | Yes | Deterministic evidence validator |
| Set model confidence | Yes | Metadata only |
| Set `AUTHORIZED` | No | Explicit governance review |
| Resolve continuity/persona scope | No | Exact stored IDs and reviewer input |
| Validate quote/hash | No | Deterministic validator |
| Detect strict atomic conflicts | No | Deterministic conflict rule |
| Create `NarrativeEvent` | No | Human/operator-only path |
| Classify SourceSnapshot impact | No | Exact deterministic Impact engine |
| Choose among ambiguous impact candidates | Advisory text only | Human reviewer |
| Change a claim to `DISPUTED` | No | Explicit governance decision |
| Choose migration defaults | No | Versioned migration policy |
| Repair malformed legacy time/access | No | Fail-closed migration/quarantine policy |
| Verify EventLedger | No | Deterministic hash-chain verification |
| Compile a Memory Pack | No | Deterministic filters |

## LLM proposal boundary

A provider adapter may produce fields such as:

```json
{
  "persona_id": "mira",
  "continuity": "alpha",
  "text": "The compass is stored in Locker Seven.",
  "subject": "compass",
  "predicate": "stored_in",
  "object_value": "locker-seven",
  "knowledge_from": "2026-01-01T18:00:00Z",
  "confidence": 0.98
}
```

The trusted proposal service forces status to `PROPOSED`. A payload field claiming `AUTHORIZED` is inert. Provider and model names do not change this rule.

## Evidence

A model may nominate `SNAPSHOT_ID:START_LINE:END_LINE`. The validator independently checks:

- built-in-integer, 1-based, inclusive coordinates;
- snapshot existence and text content;
- claim/snapshot continuity equality;
- range bounds and stored line-count consistency;
- exact quote and optional SHA-256 match.

Passing those checks proves citation integrity, not that the proposed wording is the only possible interpretation. Human governance remains necessary.

## Snapshot impact

Impact classification is exact and deterministic:

- line separators normalize to LF;
- semantic whitespace, case, punctuation, and Unicode composition remain unchanged;
- all continuous exact occurrences are found in stable line order;
- duplicates become an ambiguous report;
- no fuzzy or embedding search is consulted.

An LLM may summarize an already-produced report for a reviewer, but it must not change the outcome, drop candidates, or trigger a governance transition.

## Narrative events

`NarrativeEvent` remains human/operator-only because it enters the timeline without the `ClaimProposal` governance lifecycle. A future model-generated event feature requires a distinct `EventProposal` design, evidence rules, review states, and tests.

## Migration and quarantine

Migration is a deterministic transformation of known schemas. An LLM must not:

- infer missing access policy;
- reinterpret malformed dates;
- invent missing evidence;
- decide a legacy row was authorized;
- repair a broken ledger;
- choose which conflicting record to retain.

Strict mode stops. In v0.3.0a2, explicit quarantine retains malformed v0.1 rows only in legacy storage and creates no active mapping for them; malformed v0.2 data still stops. No model participates in that decision.

## Confidence is not authority

Model confidence can support reviewer prioritization but cannot:

- satisfy evidence validation;
- overcome a continuity mismatch;
- select an ambiguous impact candidate;
- grant authorization;
- bypass access or time filters.

The same payload must produce the same trusted result regardless of confidence value.

## Adding future model features

A proposal to add LLM behavior must answer:

1. What untrusted data does the model produce?
2. Which deterministic schema validates it?
3. Which fields are discarded or forced by the trusted boundary?
4. What explicit human action grants authority?
5. How are persona, continuity, access, and time isolated?
6. What adversarial tests prove bypasses fail?
7. Does any report disclose source content by default?

If a decision cannot be reproduced offline from stored inputs and fixed rules, it does not belong in the trusted core.
