-- Failed admin logins, for per-IP and per-username throttling
-- (includes/auth.php sv_login_retry_after). Successful logins clear the IP.
CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username, created_at);
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0007_login_attempts');
