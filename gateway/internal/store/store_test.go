package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB applies the real migration file so the test stays honest about
// the actual schema shipped to production, not a hand-maintained duplicate.
func openTestDB(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.sqlite")

	schema, err := os.ReadFile("../../../migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("reading migration file: %v", err)
	}

	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("opening raw db: %v", err)
	}
	if _, err := raw.Exec(string(schema)); err != nil {
		t.Fatalf("applying schema: %v", err)
	}
	raw.Close()

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func seedStreamAndAccessPoint(t *testing.T, st *Store, visibility string) int64 {
	t.Helper()
	res, err := st.db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Nova', 'hls', 'https://source.internal/memfs/x.m3u8')`)
	if err != nil {
		t.Fatalf("insert stream: %v", err)
	}
	streamID, _ := res.LastInsertId()
	res, err = st.db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/nova', ?)`, streamID, visibility)
	if err != nil {
		t.Fatalf("insert access_point: %v", err)
	}
	apID, _ := res.LastInsertId()
	return apID
}

func TestResolveAccessPointNotFound(t *testing.T) {
	st := openTestDB(t)
	if _, err := st.ResolveAccessPoint("does/not/exist"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestResolveAccessPointFound(t *testing.T) {
	st := openTestDB(t)
	seedStreamAndAccessPoint(t, st, "public")

	ap, err := st.ResolveAccessPoint("live/nova")
	if err != nil {
		t.Fatalf("ResolveAccessPoint: %v", err)
	}
	if ap.Visibility != "public" || ap.Stream.Name != "Nova" {
		t.Fatalf("unexpected access point: %+v", ap)
	}
}

func TestValidateTokenLifecycle(t *testing.T) {
	st := openTestDB(t)
	apID := seedStreamAndAccessPoint(t, st, "private")

	const raw = "supersecrettoken123"
	_, err := st.db.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display, label) VALUES (?, ?, 'super', 'test')`,
		apID, hashToken(raw))
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	info, err := st.ValidateToken(apID, raw)
	if err != nil || info.Status != TokenValid {
		t.Fatalf("expected valid token, got %+v err=%v", info, err)
	}

	if info, err := st.ValidateToken(apID, "wrong-token"); err != nil || info.Status != TokenInvalid {
		t.Fatalf("expected invalid for wrong token, got %+v err=%v", info, err)
	}

	// Revoke it -- this is the "leak confirmed, kill this recipient's access"
	// path. A subsequent request with the same raw token must never succeed
	// again, which is the whole point of hashing rather than deriving.
	if _, err := st.db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID); err != nil {
		t.Fatalf("revoking token: %v", err)
	}
	info, err = st.ValidateToken(apID, raw)
	if err != nil || info.Status != TokenRevoked {
		t.Fatalf("expected revoked, got %+v err=%v", info, err)
	}
}

func TestValidateTokenExpired(t *testing.T) {
	st := openTestDB(t)
	apID := seedStreamAndAccessPoint(t, st, "private")
	const raw = "expiring-token"
	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, err := st.db.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display, label, expires_at) VALUES (?, ?, 'expi', 'test', ?)`,
		apID, hashToken(raw), past)
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}
	info, err := st.ValidateToken(apID, raw)
	if err != nil || info.Status != TokenExpired {
		t.Fatalf("expected expired, got %+v err=%v", info, err)
	}
}

func TestTwoTokensOnSameAccessPointAreIndependent(t *testing.T) {
	// This is the "one leaked recipient shouldn't take down others sharing
	// the same public_path" requirement from the spec.
	st := openTestDB(t)
	apID := seedStreamAndAccessPoint(t, st, "private")
	tokA, tokB := "token-for-alice", "token-for-bob"
	for _, tok := range []string{tokA, tokB} {
		if _, err := st.db.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display, label) VALUES (?, ?, 'x', ?)`,
			apID, hashToken(tok), tok); err != nil {
			t.Fatalf("insert token %s: %v", tok, err)
		}
	}
	if _, err := st.db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE token_hash = ?`, hashToken(tokA)); err != nil {
		t.Fatalf("revoking alice: %v", err)
	}

	if info, _ := st.ValidateToken(apID, tokA); info.Status != TokenRevoked {
		t.Fatalf("alice should be revoked, got %v", info.Status)
	}
	if info, _ := st.ValidateToken(apID, tokB); info.Status != TokenValid {
		t.Fatalf("bob should be unaffected by alice's revocation, got %v", info.Status)
	}
}
