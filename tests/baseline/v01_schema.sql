-- Frozen compatibility fixture reconstructed from the v0.1 public contract.
-- v0.2 tests use this schema to prove that an existing local database is
-- upgraded transactionally instead of being silently replaced.
CREATE TABLE source_snapshots (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    continuity TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE claims (
    id TEXT PRIMARY KEY,
    persona_id TEXT NOT NULL,
    continuity TEXT NOT NULL,
    claim TEXT NOT NULL,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_value TEXT NOT NULL,
    source_snapshot_id TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    valid_from TEXT,
    valid_until TEXT,
    knowledge_from TEXT,
    knowledge_until TEXT,
    access_policy TEXT NOT NULL DEFAULT 'agent_accessible',
    confidence REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL
);

INSERT INTO source_snapshots (
    id, path, sha256, continuity, content, created_at
) VALUES (
    'legacy-snapshot-alpha',
    'alpha.txt',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'alpha',
    'abc',
    '2026-08-19T00:00:00Z'
);

INSERT INTO claims (
    id, persona_id, continuity, claim, subject, predicate, object_value,
    source_snapshot_id, start_line, end_line, valid_from, valid_until,
    knowledge_from, knowledge_until, access_policy, confidence, created_at
) VALUES (
    'legacy-claim-alpha',
    'alice',
    'alpha',
    'Alice knows the archive code.',
    'alice',
    'knows',
    'archive-code',
    'legacy-snapshot-alpha',
    1,
    1,
    '2026-01-01T00:00:00Z',
    NULL,
    '2026-01-03T00:00:00Z',
    NULL,
    'agent_accessible',
    1.0,
    '2026-08-19T00:00:00Z'
);
