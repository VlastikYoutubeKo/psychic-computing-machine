-- Relay nodes: other servers running the gateway in node mode. A node
-- authenticates with "svn_<id>_<secret>"; only SHA-256(secret) is stored for
-- auth, plus the secret itself encrypted with the main key (sv_encrypt /
-- secretbox) because the control plane needs it to sign viewer URLs and to
-- encrypt source credentials for that node.
CREATE TABLE IF NOT EXISTS nodes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    public_url       TEXT NOT NULL,          -- e.g. https://node1.example.com
    token_hash       TEXT NOT NULL,
    secret_enc       TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
    last_seen_at     TEXT,
    last_status_json TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- A stream assigned to a node is relayed 24/7 there; viewers are redirected
-- to it while it is online, and served locally when it is not.
ALTER TABLE streams ADD COLUMN node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_streams_node ON streams(node_id);
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0010_nodes');
