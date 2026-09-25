-- StreamVault initial schema.
-- Applied by admin/includes/db.php on first run (simple forward-only migration runner,
-- tracked in schema_migrations). Keep migrations additive; never edit an already-applied file.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- A configured operator account for the admin UI (single or multi-user).
CREATE TABLE IF NOT EXISTS operators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at   TEXT
);

-- A logical stream: one upstream source, independent of how many public
-- addresses point at it. Renaming a stream never touches access_points,
-- so existing shared links keep working (requirement: rename must not
-- invalidate existing access).
CREATE TABLE IF NOT EXISTS streams (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    source_type         TEXT NOT NULL CHECK (source_type IN ('restreamer','tvheadend','hls','mpegts','generic')),
    source_url          TEXT NOT NULL,       -- credential-free URL only
    source_username     TEXT,                -- NULL if no auth
    source_password_enc TEXT,                -- libsodium-sealed, NULL if no auth
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    rotation_mode       TEXT NOT NULL DEFAULT 'manual_approval' CHECK (rotation_mode IN ('auto','manual_approval','monitor_only')),
    replacement_reason  TEXT NOT NULL DEFAULT 'unauthorized_redistribution',
    replacement_message TEXT,                -- custom text override, NULL = use default template
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- A public-facing path for a stream. A stream can have many (public
-- unlisted path, private per-recipient path, etc). The gateway resolves
-- incoming request paths to a row here, never to the raw source_url.
CREATE TABLE IF NOT EXISTS access_points (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id       INTEGER NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
    public_path     TEXT NOT NULL UNIQUE,   -- e.g. "live/nova" (no leading/trailing slash)
    visibility      TEXT NOT NULL CHECK (visibility IN ('public','private')),
    output_format   TEXT NOT NULL DEFAULT 'hls' CHECK (output_format IN ('hls','mpegts')),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Individual bearer tokens for a private access_point. A 'public'
-- access_point has zero rows here (no token required). Only the hash is
-- stored -- the raw token is shown once at creation time and never again.
CREATE TABLE IF NOT EXISTS access_tokens (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    access_point_id     INTEGER NOT NULL REFERENCES access_points(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,   -- sha256(hex) of raw token
    token_display       TEXT NOT NULL,          -- first 8 chars, for admin UI identification only
    label               TEXT NOT NULL DEFAULT '',
    expires_at          TEXT,
    revoked_at          TEXT,
    revoked_reason      TEXT,
    last_used_at        TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_access_point ON access_tokens(access_point_id);

-- Security incidents (leak checker writes here; also usable for manual entries).
-- Schema is ready now so future leak-checker work doesn't need a migration,
-- but the detection/rotation logic itself is NOT implemented yet (see ROADMAP.md).
CREATE TABLE IF NOT EXISTS incidents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id           INTEGER REFERENCES streams(id) ON DELETE SET NULL,
    access_token_id     INTEGER REFERENCES access_tokens(id) ON DELETE SET NULL,
    source              TEXT NOT NULL,          -- github|gitlab|manual|...
    source_url          TEXT,
    status              TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','probable','confirmed','dismissed','resolved')),
    detected_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actions_taken       TEXT,                   -- JSON array, append-only log
    notes               TEXT
);

-- Raw leak-checker findings before dedup/grouping into an incident.
-- Schema-only for now; see ROADMAP.md Phase 6.
CREATE TABLE IF NOT EXISTS leak_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    source          TEXT NOT NULL,
    source_url      TEXT NOT NULL,
    matched_value   TEXT NOT NULL,          -- normalized matched token/URL, not the raw secret in logs
    found_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    dismissed       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT NOT NULL,        -- operator username, "discord:<id>", or "system"
    action      TEXT NOT NULL,
    target      TEXT,
    details     TEXT,                 -- JSON
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0001_init');
