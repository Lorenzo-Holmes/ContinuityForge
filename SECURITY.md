# Security Policy

## Supported versions

| Version | Security status |
|---|---|
| `0.3.0a4` | Current alpha pre-release; actively tested |
| `main` | Development branch; actively tested |
| `0.2.x` | Current supported stable release line |
| `0.1.x` | Frozen compatibility reference; upgrade recommended |

## Reporting a vulnerability

Use the repository's **Security** tab and select **Report a vulnerability** to create a private security advisory:

<https://github.com/Lorenzo-Holmes/ContinuityForge/security/advisories/new>

Include:

- affected version or commit;
- operating system and Python version;
- minimal reproduction using synthetic data;
- expected and observed security boundary;
- whether source content, database files, backups, or credentials may have been exposed;
- suggested remediation, if known.

Do not attach real user sources, private SQLite databases, tokens, or exploit data to a public issue. If private reporting is temporarily unavailable, open a minimal public issue requesting a private maintainer contact without disclosing the vulnerability details.

## Security boundary

ContinuityForge treats these inputs as untrusted:

- source files and structured imports;
- model-generated claims and evidence coordinates;
- integration-provided IDs, timestamps, policies, and report options;
- legacy databases awaiting preflight and migration;
- Claim/Event/Evidence rows and legacy creation payloads whose complete material must be replayed or explicitly attested.

ContinuityForge trusts the operating-system account and SQLite file owner. Audit Material v2 and the final SQLite material guard detect internal aggregate/evidence divergence only while the database and ledger remain within that boundary. They do not detect an attacker who replaces the complete database and its internally consistent ledger; that threat requires an external signed checkpoint, which is not currently provided.

Legacy material acceptance is an explicit migration-time decision, not proof of historical correctness. It is required for both partial legacy creation payloads and empty v0.2 Claim/Event audit streams; canonical v0.1 conversion remains deterministic and needs no opt-in. Empty v0.2 streams receive Material-v2 creation backfills rather than attestation events. Default migration fails closed when acceptance is required, and a pre-existing legacy attestation is treated as invalid rather than as current operator consent.

Read-only `migration-check` may validate the accepted plan without creating a backup. A write migration must have a verified backup before any accepted backfill or attestation and otherwise fails with `MIGRATION_MATERIAL_ATTESTATION_REQUIRES_BACKUP`.

See [Threat Model](docs/THREAT_MODEL.md) for assets, mitigations, and residual risks.

## Sensitive data handling

- SQLite databases and backups contain source material and should inherit restrictive file permissions.
- ContinuityForge does not provide database or backup encryption; use operating-system or external encryption where required.
- Administrative v0.3 reports are designed to omit complete source bodies by default.
- Evidence validation errors and Memory Packs may include cited quote spans; review before sharing.
- Do not publish logs or issue attachments that contain source text, claim text, filesystem paths, or personal data without redaction.

## Out-of-scope reports

The following are product limitations rather than vulnerabilities unless documented behavior is bypassed:

- semantic disagreement with a human review decision;
- lack of fuzzy or LLM-based impact matching;
- lack of protection from the trusted database owner;
- lack of built-in encryption or remote authentication;
- changes within documented v0.3 alpha pre-release commands or report schemas that do not bypass a documented boundary.
