# North Pier Source-Revision Demo

North Pier is an original two-version narrative fixture for deterministic SourceSnapshot impact analysis. It is deliberately small enough to audit line by line.

## Files

| File | Purpose |
|---|---|
| [`north_pier_v1.txt`](north_pier_v1.txt) | Original ten-line field log. |
| [`north_pier_v2.txt`](north_pier_v2.txt) | Revised log with one insertion, one author-edited fixture fact, and one duplicated maintenance note. |
| [`impact-cases.json`](impact-cases.json) | Expected exact-match outcomes; demo schema only. |
| [`run_demo.py`](run_demo.py) | Executable package-API demo with three authorized claims and one operator event. |

The fixtures are CC0-1.0. See the [dedicated notice](../../LICENSES/NORTH_PIER_DEMO.md) and [demo provenance](../../docs/DEMO_LICENSES.md).

## Run the complete demo

Install the package from the repository root, then run:

```bash
python examples/north_pier/run_demo.py \
  --output-dir demo-output/north-pier \
  --reset
```

The script uses package APIs only. It creates a new schema-v3 database, imports v1, authorizes three evidence-backed human claims, adds one evidence-backed operator event, imports v2, opens the database through `ReadOnlyProject`, and writes `north-pier-impact-report.json`. Assertions require exactly one result in each of `SAME_POSITION`, `EXACT_MOVED_UNIQUE`, `EXACT_MOVED_AMBIGUOUS`, and `NO_EXACT_MATCH`.

## What changed

1. A storm-watch line was inserted before the custody record.
2. The two-line custody record moved intact from v1 lines 4–5 to v2 lines 5–6.
3. The fixture author changed Mira's locker-code knowledge sentence, so the old exact quote is absent.
4. The maintenance note moved and appears twice in v2.

## Expected classifications

| v1 evidence span | Expected v2 outcome | Candidate spans |
|---|---|---|
| 2–2, arrival | `SAME_POSITION` | 2–2 |
| 4–5, custody record | `EXACT_MOVED_UNIQUE` | 5–6 |
| 8–8, maintenance note | `EXACT_MOVED_AMBIGUOUS` | 9–9, 11–11 |
| 6–6, code knowledge | `NO_EXACT_MATCH` | none |

The author-controlled fixture tells us why the final case changed. The Impact
engine proves only `NO_EXACT_MATCH`; it does not classify the cause as an edit
or deletion.

The event-owned custody case is explicitly marked `operator_authored`. `NarrativeEvent` is not an LLM proposal type. Claim-owned descriptors represent evidence anchors only and do not imply authorization.

## Import the versions with the stable v0.2 CLI

From the repository root:

```bash
continuityforge --db north-pier.db ingest examples/north_pier/north_pier_v1.txt \
  --continuity alpha --source-key north-pier-field-log
continuityforge --db north-pier.db ingest examples/north_pier/north_pier_v2.txt \
  --continuity alpha --source-key north-pier-field-log
```

The second import creates v2 because the latest content changed. Importing v1 again after v2 would create v3, not reuse the historical v1 row.

## v0.3.0a4 alpha pre-release impact command

The pure-domain v0.3 API can analyze an `EvidenceRef` after the caller resolves and verifies the target snapshot:

```python
from continuityforge.impact import analyze_evidence_impact

report = analyze_evidence_impact(evidence, target_snapshot)
```

The v0.3.0a4 alpha pre-release includes storage-aware aggregation for claim and event evidence:

```bash
continuityforge --db north-pier.db source-impact \
  --source-key north-pier-field-log \
  --continuity alpha \
  --from-version 1 \
  --target-version 2
```

The command is read-only and metadata-only. The two ingest commands alone create no evidence owners, so the first report has an empty `affected` list; add evidence-backed claims/events against v1 to exercise aggregation. `source-impact` is an alpha pre-release interface, and its formal JSON report schema is frozen for this pre-release.

Impact remains report-only. No result in this fixture authorizes, rejects, disputes, or rewrites a claim or event.
