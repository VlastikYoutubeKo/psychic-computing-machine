-- Multi-user ownership and per-account scan coverage. Forward-only.
ALTER TABLE operators ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','user'));
ALTER TABLE operators ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('invited','active','disabled'));
ALTER TABLE operators ADD COLUMN max_streams INTEGER NOT NULL DEFAULT 3 CHECK (max_streams >= 0);
ALTER TABLE operators ADD COLUMN max_access_points INTEGER NOT NULL DEFAULT 10 CHECK (max_access_points >= 0);
ALTER TABLE operators ADD COLUMN allow_remux INTEGER NOT NULL DEFAULT 0 CHECK (allow_remux IN (0,1));
ALTER TABLE operators ADD COLUMN invite_token_hash TEXT;
ALTER TABLE operators ADD COLUMN invite_expires_at TEXT;
ALTER TABLE operators ADD COLUMN github_token_enc TEXT;
ALTER TABLE operators ADD COLUMN leak_scan_requested_at TEXT;
CREATE UNIQUE INDEX idx_operator_invite_hash ON operators(invite_token_hash) WHERE invite_token_hash IS NOT NULL;

ALTER TABLE streams ADD COLUMN owner_id INTEGER REFERENCES operators(id) ON DELETE RESTRICT;
UPDATE streams SET owner_id = (SELECT id FROM operators ORDER BY id LIMIT 1) WHERE owner_id IS NULL;
CREATE INDEX idx_streams_owner ON streams(owner_id);
CREATE TRIGGER limit_user_streams BEFORE INSERT ON streams
WHEN NEW.owner_id IS NOT NULL AND (SELECT role FROM operators WHERE id=NEW.owner_id)='user'
AND (SELECT COUNT(*) FROM streams WHERE owner_id=NEW.owner_id) >= (SELECT max_streams FROM operators WHERE id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'stream quota reached'); END;
CREATE TRIGGER limit_user_access_points BEFORE INSERT ON access_points
WHEN (SELECT role FROM operators WHERE id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))='user'
AND (SELECT COUNT(*) FROM access_points WHERE stream_id IN
  (SELECT id FROM streams WHERE owner_id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))) >=
  (SELECT max_access_points FROM operators WHERE id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))
BEGIN SELECT RAISE(ABORT,'access point quota reached'); END;

-- Rebuild this independent table to replace its old global UNIQUE constraint:
-- the same repo can now be watched by two users and the global scanner.
CREATE TABLE leak_sources_0008 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL CHECK (provider IN ('github_repo','github_org','gitlab_project','gitlab_group','playlist_url')),
    identifier TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_scanned_at TEXT,
    last_cursor TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    owner_id INTEGER REFERENCES operators(id) ON DELETE CASCADE
);
INSERT INTO leak_sources_0008(id,provider,identifier,enabled,last_scanned_at,last_cursor,created_at)
SELECT id,provider,identifier,enabled,last_scanned_at,last_cursor,created_at FROM leak_sources;
DROP TABLE leak_sources;
ALTER TABLE leak_sources_0008 RENAME TO leak_sources;
CREATE UNIQUE INDEX idx_leak_sources_global_unique ON leak_sources(provider,identifier) WHERE owner_id IS NULL;
CREATE UNIQUE INDEX idx_leak_sources_owner_unique ON leak_sources(owner_id,provider,identifier) WHERE owner_id IS NOT NULL;
CREATE INDEX idx_leak_sources_owner ON leak_sources(owner_id);

ALTER TABLE leak_checker_runs ADD COLUMN owner_id INTEGER REFERENCES operators(id) ON DELETE SET NULL;
CREATE INDEX idx_leak_runs_owner ON leak_checker_runs(owner_id,id);

INSERT OR IGNORE INTO schema_migrations(version) VALUES ('0008_accounts');
