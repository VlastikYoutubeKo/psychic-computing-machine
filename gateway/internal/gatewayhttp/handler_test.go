package gatewayhttp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
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
	// Every httptest server in this file binds to 127.0.0.1, which real DNS
	// resolution (h.Resolve's default) would correctly call private -- but
	// that would make every test's "source" look like a trusted-private
	// LAN box and silently disable the SSRF checks these tests exist to
	// exercise. Default to "everything is public" here; tests that
	// specifically need a private source or target override this.
	h.Resolve = func(ctx context.Context, host string) (bool, error) { return false, nil }
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

func TestCrossOriginBlobToPrivateAddressRejectedEvenWhenValidlyEncoded(t *testing.T) {
	// This specifically tests the defense-in-depth SSRF check
	// (ARCHITECTURE.md "SSRF boundary" / checkFetchTarget): even a blob
	// that *is* correctly encrypted by this gateway's own codec, but
	// resolves to a private/reserved address while the stream's own
	// source is public, must be rejected. A black-box test can no longer
	// forge this (the whole point of encrypting the blob), so this has to
	// run at this level, using the handler's own Codec the way the
	// gateway itself would.
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	h.Resolve = func(ctx context.Context, host string) (bool, error) {
		return host == "169.254.169.254", nil // the classic cloud-metadata SSRF target
	}
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
		t.Fatalf("expected 403 for a blob resolving to a private address from a public source, got %d", resp.StatusCode)
	}
}

func TestCrossOriginBlobToPublicHostIsAllowed(t *testing.T) {
	// The policy this project shipped with first required the blob's
	// target to be the *exact same host* as the stream's source_url. That
	// broke real streams (see checkFetchTarget's doc comment): many
	// legitimate sources redirect to a different, still-public, CDN host
	// per request. A blob pointing at a different but public host must be
	// allowed.
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
	}))
	defer source.Close()
	otherPublicHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "segment-from-a-different-but-public-host")
	}))
	defer otherPublicHost.Close()

	h, db := newTestHandler(t) // default resolver: everything is public
	apID := seedStream(t, db, source.URL+"/index.m3u8", "live/nova", "public")

	gw := httptest.NewServer(h)
	defer gw.Close()

	blob, err := h.Codec.Encode(otherPublicHost.URL+"/seg1.ts", fmt.Sprint(apID))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(gw.URL + "/live/nova/r/" + blob)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "segment-from-a-different-but-public-host" {
		t.Fatalf("expected a different-but-public host to be fetched, got status=%d body=%q", resp.StatusCode, body)
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

// newServerOn starts an httptest-style server on a specific loopback
// address (httptest.NewServer always uses 127.0.0.1, which makes it
// impossible to tell "the source" and "an evil redirect target" apart by
// hostname alone -- both would be the literal string "127.0.0.1"). Using
// a distinct address in 127.0.0.0/8 lets a test's mock Resolve tell them
// apart the same way it would tell apart two genuinely different hosts.
func newServerOn(t *testing.T, addr string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("cannot bind %s (sandboxed environment?): %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestRedirectToPrivateAddressIsNeverFetched(t *testing.T) {
	// The actual risk checkFetchTarget defends against: a source
	// redirecting the gateway into a private/internal address (cloud
	// metadata, another container, localhost), not simply "a different
	// host" -- see its doc comment for why those are different things.
	var hits atomic.Int32
	evil := newServerOn(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "#EXTM3U\n")
	})
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/internal", http.StatusFound)
	}))
	defer source.Close()
	h, db := newTestHandler(t)
	h.Resolve = func(ctx context.Context, host string) (bool, error) {
		return host == "127.0.0.2", nil // the redirect target only; source (127.0.0.1) stays "public"
	}
	seedStream(t, db, source.URL+"/entry.m3u8", "redirect/blocked", "public")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/redirect/blocked.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("redirect to a private address: status=%d target hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestRedirectAllowedWhenSourceItselfIsPrivate(t *testing.T) {
	// A LAN Tvheadend/Restreamer box (spec section 7) is itself on a
	// private address, and its own redirects/segment references landing
	// on that same private network are expected, not an attack -- see
	// checkFetchTarget's doc comment. This is what actually lets a
	// same-Docker-network or same-LAN source work at all under this
	// policy, not just an edge case.
	var hits atomic.Int32
	lanEdge := newServerOn(t, "127.0.0.3", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "#EXTM3U\n#EXTINF:2,\nseg.ts\n")
	})
	lanSource := newServerOn(t, "127.0.0.4", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, lanEdge.URL+"/index.m3u8", http.StatusFound)
	})
	h, db := newTestHandler(t)
	h.Resolve = func(ctx context.Context, host string) (bool, error) {
		return host == "127.0.0.3" || host == "127.0.0.4", nil // both "LAN" addresses
	}
	seedStream(t, db, lanSource.URL+"/entry.m3u8", "redirect/lan", "public")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/redirect/lan.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() == 0 {
		t.Fatalf("expected a private source's own redirect within its network to be allowed: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestRedirectToDifferentPublicHostIsFetched(t *testing.T) {
	// Regression test for the bug this project's first live end-to-end
	// test actually hit: a source 302ing its entry point to a different
	// (but public) CDN host must work, not be rejected as "cross-origin".
	var hits atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "#EXTM3U\n#EXTINF:2,\nseg.ts\n")
	}))
	defer cdn.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cdn.URL+"/edge/index.m3u8", http.StatusFound)
	}))
	defer source.Close()
	h, db := newTestHandler(t) // default resolver: everything is public
	seedStream(t, db, source.URL+"/entry.m3u8", "redirect/cdn", "public")
	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/redirect/cdn.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() == 0 {
		t.Fatalf("expected the different-but-public CDN host to be followed: status=%d hits=%d", resp.StatusCode, hits.Load())
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
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
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
	// Regression check: an earlier version fetched the entry point once to
	// sniff its format, then a *second* time (a fresh request) to actually
	// feed ffmpeg -- two back-to-back requests to the same source. That's
	// exactly the pattern that got this project's own first real
	// production stream rate-limited by its origin (see CHANGELOG.md "SSRF
	// redirect policy" / the entry above it on double-fetching). The
	// sniffed response must be reused, not re-fetched.
	if got := sourceHits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 request to the source for the entry fetch, got %d (the sniffed response must be reused for remux, not re-fetched)", got)
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
