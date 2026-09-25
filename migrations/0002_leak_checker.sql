-- Phase 6: Leak Checker schema. Additive only -- 0001_init.sql's
-- leak_findings/incidents tables stay as they were; this adds what's
-- needed to actually run scans and show honest coverage status.
--
-- Design constraint that shapes this whole schema: access_tokens never
-- stores a raw token (see 0001_init.sql), only sha256(token). The leak
-- checker therefore can never search external sources for "our secret
-- URL" directly -- it searches for the non-secret anchor
-- (access_points.public_path, which is plaintext and fine to reveal in a
-- search query), then for any candidate token found trailing that path in
-- a result, hashes IT and compares against stored hashes. See
-- ARCHITECTURE.md "Leak Checker" for the full matching algorithm.

PRAGMA foreign_keys = ON;

-- One row per external thing the checker watches. A stream doesn't need
-- explicit rows here to be covered by global GitHub code search (see
-- ARCHITECTURE.md) -- this table is for *additional*, explicitly
-- requested repos/orgs/playlists (spec: "Umožni přidat konkrétní
-- repozitáře, organizace a veřejné playlisty").
CREATE TABLE IF NOT EXISTS leak_sources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT NOT NULL CHECK (provider IN ('github_repo','github_org','gitlab_project','gitlab_group','playlist_url')),
    identifier      TEXT NOT NULL,            -- e.g. "iptv-org/iptv", "some-org", a playlist URL
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_scanned_at TEXT,
    last_cursor     TEXT,                     -- opaque, provider-specific (e.g. an issue search "since" timestamp)
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (provider, identifier)
);

-- A record of every scan run, so the admin UI can show real coverage
-- ("last successful run", "GitHub only, GitLab not implemented", "hit a
-- rate limit, partial") instead of the static disclaimer alone. Spec:
-- "Pokud vyhledávání nemá úplné pokrytí, zobraz tuto skutečnost v
-- administraci."
CREATE TABLE IF NOT EXISTS leak_checker_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at         TEXT,
    providers_run       TEXT NOT NULL,        -- JSON array, e.g. ["github"]
    streams_checked     INTEGER NOT NULL DEFAULT 0,
    queries_made        INTEGER NOT NULL DEFAULT 0,
    findings_created    INTEGER NOT NULL DEFAULT 0,
    error               TEXT                  -- non-NULL if the run aborted early (e.g. rate limited, no token configured)
);

-- Extend leak_findings with what the matcher needs: a coarse confidence
-- tier (see ARCHITECTURE.md classification rules) and a dedupe key so
-- re-scanning the same, unchanged source doesn't create duplicate rows
-- (spec: "Jeden únik nesmí vyvolat desítky zbytečných rotací" starts with
-- not even recording it twice).
ALTER TABLE leak_findings ADD COLUMN confidence TEXT NOT NULL DEFAULT 'mention'
    CHECK (confidence IN ('mention','probable','confirmed'));
ALTER TABLE leak_findings ADD COLUMN dedupe_key TEXT;
ALTER TABLE leak_findings ADD COLUMN access_point_id INTEGER REFERENCES access_points(id) ON DELETE SET NULL;
ALTER TABLE leak_findings ADD COLUMN access_token_id INTEGER REFERENCES access_tokens(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_leak_findings_dedupe ON leak_findings(dedupe_key) WHERE dedupe_key IS NOT NULL;

-- access_points.public_path is only automatically "safe to be found
-- anywhere" for a normal public stream. Some public access points use the
-- "long random path IS the secret" pattern from spec section 1 (e.g.
-- "nova/6f8e1b3c9a72d4e0") -- for those, ANY external mention of the
-- exact path is itself a confirmed leak, not just a "mention". This flag
-- lets the admin tell the checker which case it's looking at; it has no
-- effect on gateway routing (Go gateway code untouched by this migration).
ALTER TABLE access_points ADD COLUMN path_is_secret INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0002_leak_checker');
