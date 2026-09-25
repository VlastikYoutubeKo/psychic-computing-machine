-- Phase 6 follow-up: prevent two leakchecker processes from running a scan
-- at the same time. 0002_leak_checker.sql has already been applied on
-- this host's live database (and by tests), so this has to be its own
-- migration -- editing an already-applied migration file's contents
-- wouldn't retroactively reach databases that already recorded it as done.
--
-- Needed because the intended deployment (see DEPLOYMENT.md) runs the
-- one-shot leakchecker binary from a systemd timer firing every minute
-- (so a manual "Scan now" feels responsive), while a single scan can take
-- up to ~10 minutes. Without a lock, a manual request landing while a
-- scan is already in flight would start a second, overlapping scan.
--
-- A single-row table with a CHECK-enforced fixed id is used instead of a
-- filesystem lock (flock) so it works the same way regardless of where
-- the binary runs, and self-heals if a process crashes without releasing
-- it (see Store.AcquireLock's staleness check).
CREATE TABLE IF NOT EXISTS leak_checker_lock (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    acquired_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0003_leak_checker_lock');
