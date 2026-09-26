-- Operator-editable slate copy. Keep historical migrations immutable.
CREATE TABLE IF NOT EXISTS slate_texts (
    reason TEXT PRIMARY KEY CHECK (reason IN ('limited_bandwidth','not_intended_for_public','unauthorized_redistribution','access_revoked_by_owner','stream_permanently_discontinued','temporarily_unavailable')),
    title TEXT NOT NULL,
    subtitle TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT OR IGNORE INTO slate_texts(reason,title,subtitle) VALUES
 ('limited_bandwidth','Capacity limit reached','This stream is unavailable because its bandwidth limit was reached.'),
 ('not_intended_for_public','Private stream','This stream is not intended for public distribution.'),
 ('unauthorized_redistribution','Stream unavailable','This access URL has been revoked.'),
 ('access_revoked_by_owner','Access revoked','The stream owner has revoked access to this URL.'),
 ('stream_permanently_discontinued','Stream discontinued','This stream is permanently unavailable at this address.'),
 ('temporarily_unavailable','Temporarily unavailable','The source is not responding. Please try again shortly.');

-- Charge attempts before the API call so concurrent requests cannot bypass
-- either quota by racing. Failed calls count too: they can still cost money.
CREATE TABLE IF NOT EXISTS ai_generation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_generation_op_time ON ai_generation_log(operator_id,created_at);
INSERT OR IGNORE INTO schema_migrations(version) VALUES ('0006_slate_texts_ai');
