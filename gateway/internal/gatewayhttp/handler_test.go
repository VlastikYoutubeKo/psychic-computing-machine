package gatewayhttp

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"

	"streamvault/gateway/internal/store"
)

// These tests exercise the full HTTP handler end to end (real net/http round
// trips against httptest servers, real SQLite), rather than mocking pieces
// out -- the bugs a security review found here (reversible blob encoding,
// unchecked redirects, a missing leading slash) were exactly the kind that
// only show up when you actually make the request the way a client would,
// not when you unit-test each function in isolation.

func newTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.sqlite")

	schema, err := os.ReadFile("../../../migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("reading migration: %v", err)
	}
	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("opening raw db: %v", err)
	}
	if _, err := raw.Exec(string(schema)); err != nil {
		t.Fatalf("applying schema: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	h, err := New(st, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(h.Remux.Close)
	return h, raw
}

func seedStream(t *testing.T, db *sql.DB, sourceURL, publicPath, visibility string) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Test', 'hls', ?)`, sourceURL)
	if err != nil {
		t.Fatalf("insert stream: %v", err)
	}
	streamID, _ := res.LastInsertId()
	res, err = db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, ?, ?)`, streamID, publicPath, visibility)
	if err != nil {
		t.Fatalf("insert access_point: %v", err)
	}
	apID, _ := res.LastInsertId()
	return apID
}

func addToken(t *testing.T, db *sql.DB, apID int64, raw string) {
	t.Helper()
	sum := sha256.Sum256([]byte(raw))
	_, err := db.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display, label) VALUES (?, ?, 'x', 'test')`,
		apID, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}
}

func TestPublicEntryHidesSourceAndRewritesAbsolute(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.m3u8":
			io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
		case "/seg1.ts":
			w.Write([]byte("fake-segment-bytes"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	seedStream(t, db, source.URL+"/index.m3u8", "live/nova", "public")

	gw := httptest.NewServer(h)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/live/nova.m3u8")
	if err != nil {
		t.Fatalf("GET entry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	manifest := string(body)
	if strings.Contains(manifest, source.URL) {
		t.Fatalf("source URL leaked into manifest:\n%s", manifest)
	}

	var segLine string
	for _, line := range strings.Split(manifest, "\n") {
		if strings.Contains(line, "/r/") {
			segLine = line
		}
	}
	if segLine == "" {
		t.Fatalf("no proxied segment line found in manifest:\n%s", manifest)
	}
	if !strings.HasPrefix(segLine, "/") {
		t.Fatalf("proxied segment reference must be an absolute path, got %q", segLine)
	}

	// Resolve exactly like a real HLS player would: relative to the
	// manifest's own URL, not by naive string concatenation.
	entryURL, _ := url.Parse(gw.URL + "/live/nova.m3u8")
	segRef, _ := url.Parse(segLine)
	segURL := entryURL.ResolveReference(segRef).String()

	segResp, err := http.Get(segURL)
	if err != nil {
		t.Fatalf("GET segment: %v", err)
	}
	defer segResp.Body.Close()
	segBody, _ := io.ReadAll(segResp.Body)
	if string(segBody) != "fake-segment-bytes" {
		t.Fatalf("unexpected segment body: %q", segBody)
	}
}

func TestPrivateAccessTokenLifecycleOverHTTP(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	apID := seedStream(t, db, source.URL+"/index.m3u8", "live/priv", "private")
	addToken(t, db, apID, "raw-token-123")

	gw := httptest.NewServer(h)
	defer gw.Close()

	code := func(path string) int {
		resp, err := http.Get(gw.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if c := code("/live/priv/raw-token-123.m3u8"); c != 200 {
		t.Fatalf("valid token: expected 200, got %d", c)
	}
	if c := code("/live/priv/wrong-token.m3u8"); c != 404 {
		t.Fatalf("wrong token: expected 404, got %d", c)
	}

	if _, err := db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if c := code("/live/priv/raw-token-123.m3u8"); c != 410 {
		t.Fatalf("revoked token: expected 410, got %d", c)
	}
}

func TestCrossOriginBlobRejectedEvenWhenValidlyEncoded(t *testing.T) {
	// This specifically tests the defense-in-depth host allowlist
	// (ARCHITECTURE.md "SSRF boundary" layer 2): even a blob that *is*
	// correctly encrypted by this gateway's own codec, but points at a
	// host other than the stream's configured source, must be rejected.
	// A black-box test can no longer forge this (the whole point of
	// encrypting the blob), so this has to run at this level, using the
	// handler's own Codec the way the gateway itself would.
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	apID := seedStream(t, db, source.URL+"/index.m3u8", "live/nova", "public")

	gw := httptest.NewServer(h)
	defer gw.Close()

	blob, err := h.Codec.Encode("http://169.254.169.254/latest/meta-data/", fmt.Sprint(apID))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(gw.URL + "/live/nova/r/" + blob)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin (but validly encoded) blob, got %d", resp.StatusCode)
	}
}

func TestHandCraftedBlobIsRejected(t *testing.T) {
	// The old base64-only scheme let anyone construct a blob from scratch.
	// Confirms that no longer works: a base64url string that happens to
	// decode to a URL, but wasn't produced by this gateway's codec, must
	// be rejected (as 404, indistinguishable from "never existed").
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	seedStream(t, db, source.URL+"/index.m3u8", "live/nova", "public")
	_ = h

	gw := httptest.NewServer(h)
	defer gw.Close()

	forged := "aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8" // base64url("http://169.254.169.254/") roughly
	resp, err := http.Get(gw.URL + "/live/nova/r/" + forged)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a hand-crafted non-encrypted blob, got %d", resp.StatusCode)
	}
}

func TestSameOriginRedirectResolvesSegmentsFromFinalPlaylistURL(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/entry.m3u8":
			http.Redirect(w, r, "/nested/index.m3u8", http.StatusFound)
		case "/nested/index.m3u8":
			io.WriteString(w, "#EXTM3U\n#EXTINF:2,\nseg.ts\n")
		case "/nested/seg.ts":
			io.WriteString(w, "right-segment")
		default:
			http.NotFound(w, r)
		}
	}))
	defer source.Close()
	h, db := newTestHandler(t)
	seedStream(t, db, source.URL+"/entry.m3u8", "redirect/test", "public")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/redirect/test.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var ref string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "/r/") {
			ref = line
		}
	}
	if ref == "" {
		t.Fatalf("missing rewritten segment: %s", body)
	}
	seg, err := http.Get(gw.URL + ref)
	if err != nil {
		t.Fatal(err)
	}
	defer seg.Body.Close()
	got, _ := io.ReadAll(seg.Body)
	if string(got) != "right-segment" {
		t.Fatalf("segment after redirect: %d %q", seg.StatusCode, got)
	}
}

func TestRedirectToDifferentOriginIsNeverFetched(t *testing.T) {
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "#EXTM3U\n")
	}))
	defer evil.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/internal", http.StatusFound)
	}))
	defer source.Close()
	h, db := newTestHandler(t)
	seedStream(t, db, source.URL+"/entry.m3u8", "redirect/blocked", "public")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/redirect/blocked.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("cross-origin redirect: status=%d target hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestMPEGTSIsRemuxedToHLSAndTokenRevocationStillApplies(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	tsPath := filepath.Join(t.TempDir(), "input.ts")
	cmd := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=160x90:rate=10", "-t", "8", "-pix_fmt", "yuv420p", "-c:v", "mpeg2video", "-f", "mpegts", tsPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating MPEG-TS: %v: %s", err, out)
	}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, tsPath)
	}))
	defer source.Close()
	h, db := newTestHandler(t)
	apID := seedStream(t, db, source.URL+"/input.ts", "ts/test", "private")
	addToken(t, db, apID, "ts-token")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/ts/test/ts-token.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "#EXTM3U") {
		t.Fatalf("remux manifest: status=%d body=%s", resp.StatusCode, body)
	}
	var ref string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "/r/") {
			ref = line
			break
		}
	}
	if ref == "" {
		t.Fatalf("no remuxed segment: %s", body)
	}
	seg, err := http.Get(gw.URL + ref)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(seg.Body)
	seg.Body.Close()
	if seg.StatusCode != 200 || len(data) < 188 || data[0] != 0x47 {
		t.Fatalf("remux segment: status=%d bytes=%d", seg.StatusCode, len(data))
	}
	if _, err := db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID); err != nil {
		t.Fatal(err)
	}
	blocked, err := http.Get(gw.URL + ref)
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusGone {
		t.Fatalf("revoked remux segment: got %d", blocked.StatusCode)
	}
}
