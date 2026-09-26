-- Capture the actual state transition time; updated_at is not a revocation time.
ALTER TABLE access_points ADD COLUMN revoked_at TEXT;
ALTER TABLE streams ADD COLUMN disabled_at TEXT;
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0004_slate_timestamps');
