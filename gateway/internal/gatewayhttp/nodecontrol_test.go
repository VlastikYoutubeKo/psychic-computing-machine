package gatewayhttp

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"streamvault/gateway/internal/nodeproto"
	"streamvault/gateway/internal/secretbox"
)

// addNode inserts a node the way the admin does and returns its token.
func addNode(t *testing.T, h *Handler, db *sql.DB, publicURL string) (int64, string, string) {
	t.Helper()
	if h.Key == nil {
		h.Key = make([]byte, 32)
		rand.Read(h.Key)
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	secret := hex.EncodeToString(raw)
	enc, err := secretbox.Encrypt(h.Key, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`INSERT INTO nodes (name, public_url, token_hash, secret_enc) VALUES ('n1', ?, ?, ?)`, publicURL, nodeproto.SecretHash(secret), enc)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id, "svn_" + strconv.FormatInt(id, 10) + "_" + secret, secret
}

func nodeReq(t *testing.T, h *Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNodeAPIAuthentication(t *testing.T) {
	h, db := newTestHandler(t)
	id, token, _ := addNode(t, h, db, "https://node1.example")
	if got := nodeReq(t, h, "GET", "/_sv/node/config", token, ""); got.Code != 200 {
		t.Fatalf("valid token: %d", got.Code)
	}
	wrongSecret := "svn_" + strconv.FormatInt(id, 10) + "_" + strings.Repeat("0", 64)
	for name, tok := range map[string]string{"none": "", "malformed": "abc", "wrong secret": wrongSecret, "unknown node": "svn_999_" + strings.Repeat("a", 64)} {
		if got := nodeReq(t, h, "GET", "/_sv/node/config", tok, ""); got.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", name, got.Code)
		}
	}
	db.Exec(`UPDATE nodes SET status = 'disabled' WHERE id = ?`, id)
	if got := nodeReq(t, h, "GET", "/_sv/node/config", token, ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("disabled node: expected 401, got %d", got.Code)
	}
	if got := nodeReq(t, h, "GET", "/_sv/node/binary", "", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("binary without token: %d", got.Code)
	}
	if got := nodeReq(t, h, "GET", "/_sv/node/install.sh", "", ""); got.Code != 200 || !strings.Contains(got.Body.String(), "STREAMVAULT_NODE_TOKEN") || strings.Contains(got.Body.String(), "svn_1_") {
		t.Fatalf("install script: %d", got.Code)
	}
}

func TestNodeConfigEncryptsCredentialsAndListsRevocations(t *testing.T) {
	h, db := newTestHandler(t)
	nodeID, token, secret := addNode(t, h, db, "https://node1.example")
	pwEnc, _ := secretbox.Encrypt(h.Key, []byte("s3cret-source-pw"))
	apID := seedStream(t, db, "https://src.example/live.m3u8", "live/n", "private")
	var streamID int64
	db.QueryRow(`SELECT stream_id FROM access_points WHERE id = ?`, apID).Scan(&streamID)
	db.Exec(`UPDATE streams SET node_id = ?, source_username = 'u', source_password_enc = ? WHERE id = ?`, nodeID, pwEnc, streamID)
	addToken(t, db, apID, "tok-a")
	db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID)
	other := seedStream(t, db, "https://src.example/other.m3u8", "live/other", "public") // not assigned
	_ = other

	got := nodeReq(t, h, "GET", "/_sv/node/config", token, "")
	if strings.Contains(got.Body.String(), "s3cret-source-pw") {
		t.Fatal("source password sent in plaintext")
	}
	var cfg nodeproto.Config
	if err := json.Unmarshal(got.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.NodeID != nodeID || len(cfg.Streams) != 1 || cfg.Streams[0].ID != streamID {
		t.Fatalf("expected exactly the assigned stream, got %+v", cfg)
	}
	pw, err := secretbox.Decrypt(nodeproto.ConfigKey(secret), cfg.Streams[0].SourcePasswordEnc)
	if err != nil || string(pw) != "s3cret-source-pw" {
		t.Fatalf("node cannot decrypt its credentials: %v %q", err, pw)
	}
	if len(cfg.RevokedTokens) != 1 {
		t.Fatalf("revoked token not listed: %+v", cfg.RevokedTokens)
	}
}

func TestNodeStatusMarksNodeActive(t *testing.T) {
	h, db := newTestHandler(t)
	id, token, _ := addNode(t, h, db, "https://node1.example")
	if got := nodeReq(t, h, "POST", "/_sv/node/status", token, `{"version":"x","load1":0.5,"streams":[],"injected":"<script>"}`); got.Code != http.StatusNoContent {
		t.Fatalf("status: %d %s", got.Code, got.Body.String())
	}
	var status, js string
	db.QueryRow(`SELECT status, last_status_json FROM nodes WHERE id = ?`, id).Scan(&status, &js)
	if status != "active" || strings.Contains(js, "injected") {
		t.Fatalf("status=%s json=%s (unknown fields must be dropped)", status, js)
	}
	if got := nodeReq(t, h, "POST", "/_sv/node/status", token, strings.Repeat("x", 70<<10)); got.Code != http.StatusBadRequest {
		t.Fatalf("oversized status accepted: %d", got.Code)
	}
}

func TestViewerIsProxiedThroughOnlineNodeAndFallsBackToSource(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Write([]byte("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\nfrom-source.ts\n"))
	}))
	defer src.Close()
	var nodeHits, badSig, viewerHdr int
	nodeStatus := http.StatusOK
	h, db := newTestHandler(t)
	var secret string
	var streamID int64
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodeHits++
		q := r.URL.Query()
		exp, _ := strconv.ParseInt(q.Get("exp"), 10, 64)
		if q.Get("ap") != "0" || q.Get("tok") != "0" || !nodeproto.Verify(secret, streamID, 0, 0, exp, q.Get("sig")) {
			badSig++
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if len(r.Header.Get(nodeproto.ViewerHeader)) == 16 {
			viewerHdr++
		}
		if nodeStatus != http.StatusOK {
			http.Error(w, "starting", nodeStatus)
			return
		}
		if strings.HasSuffix(r.URL.Path, "index.m3u8") {
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			w.Write([]byte("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\nseg000001.ts?" + r.URL.RawQuery + "\n"))
			return
		}
		w.Header().Set("Content-Type", "video/mp2t")
		w.Write(bytes.Repeat(append([]byte{0x47}, make([]byte, 187)...), 3))
	}))
	defer node.Close()
	nodeID, _, sec := addNode(t, h, db, node.URL)
	secret = sec
	apID := seedStream(t, db, src.URL+"/live.m3u8", "live/nd", "private")
	addToken(t, db, apID, "viewer-token")
	db.QueryRow(`SELECT stream_id FROM access_points WHERE id = ?`, apID).Scan(&streamID)
	db.Exec(`UPDATE streams SET node_id = ? WHERE id = ?`, nodeID, streamID)
	online := func() {
		db.Exec(`UPDATE nodes SET status = 'active', last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, nodeID)
	}

	// Offline (never seen): served from the source, node untouched.
	got := slateRequest(t, h, "GET", "/live/nd/viewer-token.m3u8", "*/*")
	if got.Code != 200 || nodeHits != 0 {
		t.Fatalf("offline node: code %d, node hits %d", got.Code, nodeHits)
	}
	// Online: proxied through this domain, never a redirect.
	online()
	got = slateRequest(t, h, "GET", "/live/nd/viewer-token.m3u8", "*/*")
	body := got.Body.String()
	if got.Code != 200 || got.Header().Get("Location") != "" || !strings.Contains(body, "/live/nd/viewer-token/r/") ||
		strings.Contains(body, node.URL) || strings.Contains(body, "sig=") || nodeHits != 1 || badSig != 0 || viewerHdr != 1 {
		t.Fatalf("online node not proxied correctly: code=%d hits=%d badSig=%d viewer=%d body=%q", got.Code, nodeHits, badSig, viewerHdr, body)
	}
	var segPath string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "/live/nd/") {
			segPath = l
		}
	}
	seg := slateRequest(t, h, "GET", segPath, "*/*")
	if seg.Code != 200 || seg.Body.Bytes()[0] != 0x47 || nodeHits != 2 {
		t.Fatalf("segment not proxied from node: %d hits=%d", seg.Code, nodeHits)
	}
	// Node relay not ready (503): fall back to the source.
	nodeStatus = http.StatusServiceUnavailable
	got = slateRequest(t, h, "GET", "/live/nd/viewer-token.m3u8", "*/*")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "/live/nd/viewer-token/r/") {
		t.Fatalf("fallback to source failed: %d %s", got.Code, got.Body.String())
	}
	nodeStatus = http.StatusOK
	// Revoked token never reaches the node.
	hitsBefore := nodeHits
	db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID)
	installFakeSlate(t, h)
	slateRequest(t, h, "GET", "/live/nd/viewer-token.m3u8", "*/*")
	if nodeHits != hitsBefore {
		t.Fatal("revoked token was proxied to the node")
	}
	db.Exec(`UPDATE access_tokens SET revoked_at = NULL WHERE access_point_id = ?`, apID)
	// Disabled or stale node: source again.
	for _, q := range []string{`UPDATE nodes SET status = 'disabled' WHERE id = ?`, `UPDATE nodes SET status = 'active', last_seen_at = '2000-01-01T00:00:00.000Z' WHERE id = ?`} {
		db.Exec(q, nodeID)
		hitsBefore = nodeHits
		slateRequest(t, h, "GET", "/live/nd/viewer-token.m3u8", "*/*")
		if nodeHits != hitsBefore {
			t.Fatalf("node used although %q", q)
		}
	}
}
