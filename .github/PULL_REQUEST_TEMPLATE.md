## Summary

<!-- What changed and why? Keep released behavior separate from unreleased v0.3 alpha work. -->

## Contract impact

- Affected layer(s):
- Released behavior changed: yes / no
- Database or migration impact: yes / no
- Disclosure surface changed: yes / no
- LLM-assisted behavior involved: yes / no

## Verification

<!-- List exact tests or documentation checks run. Use synthetic data only. -->

```text
python -m pytest
python -m compileall -q src tests
```

## Checklist

- [ ] I preserved the frozen v0.1 baseline bytes and observable contract.
- [ ] I preserved v0.2 compatibility or documented an explicit versioned migration.
- [ ] I kept LLM output non-authoritative; confidence does not grant access or approval.
- [ ] I preserved persona/continuity isolation, evidence provenance, access policy, and time semantics.
- [ ] I did not make `NarrativeEvent` model-generated.
- [ ] I kept Snapshot Impact report-only with no automatic governance mutation.
- [ ] I added deterministic tests for new behavior and fail-closed edge cases.
- [ ] I considered database-owner trust, ledger/authority integrity, backup, restore, and rollback where relevant.
- [ ] I kept administrative reports metadata-first and added redaction tests for any new report field.
- [ ] I marked v0.3 alpha commands, flags, and report schemas as implemented but unreleased.
- [ ] I updated the README, changelog, design/security docs, and demo license map where relevant.
- [ ] I used only synthetic, redistributable fixtures and removed secrets or personal data.

## Reviewer focus

<!-- Call out security-sensitive assumptions, invariants, migration cases, or compatibility risks. -->
