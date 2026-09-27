-- Always-on relays: the gateway keeps one persistent ffmpeg relay per such
-- stream (see gateway/internal/gatewayhttp/alwayson.go). Additive only.
ALTER TABLE streams ADD COLUMN always_on INTEGER NOT NULL DEFAULT 0 CHECK (always_on IN (0,1));
-- Per-account permission (admins always may): a relay holds a remux slot 24/7.
ALTER TABLE operators ADD COLUMN allow_always_on INTEGER NOT NULL DEFAULT 0 CHECK (allow_always_on IN (0,1));
-- Written by the gateway, read by the admin: current relay state per stream.
CREATE TABLE IF NOT EXISTS stream_runtime (
    stream_id  INTEGER PRIMARY KEY REFERENCES streams(id) ON DELETE CASCADE,
    state      TEXT NOT NULL,          -- starting|running|backoff|error|stopped
    detail     TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0009_always_on');
