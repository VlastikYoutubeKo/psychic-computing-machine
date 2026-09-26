-- One public GitHub reply per issue/PR at most, whether posted automatically
-- by the leak checker (allowlisted repos) or manually from the admin.
CREATE TABLE IF NOT EXISTS leak_replies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url  TEXT NOT NULL UNIQUE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    comment_url TEXT,
    actor       TEXT NOT NULL,          -- leakchecker | operator:<id>
    posted_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Leak response is always automatic now (the per-stream choice was
-- confusing and the default did nothing); existing streams follow.
UPDATE streams SET rotation_mode = 'auto';

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0005_leak_replies');
