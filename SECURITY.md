# Security Policy

## Supported versions

| Version | Security status |
|---|---|
| `main` / unreleased v0.3.0a2 | Actively developed and tested |
| `0.2.x` | Current supported release line |
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
- legacy databases awaiting preflight and migration.

ContinuityForge trusts the operating-system account and SQLite file owner. It does not detect an attacker who can replace the complete database and its internal ledger. That threat requires an external signed checkpoint, which is not currently provided.

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
- changes to explicitly unreleased v0.3 alpha commands or report schemas that do not bypass a documented boundary.
