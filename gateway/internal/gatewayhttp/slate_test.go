package gatewayhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSlate struct {
	dir   string
	calls int
	key   string
}

func (f *fakeSlate) GetPath(variant, key, name string) (string, error) {
	if key != "" && key != f.key {
		return "", os.ErrNotExist
	}
	f.calls++
	return filepath.Join(f.dir, name), nil
}
func (f *fakeSlate) Prepare(variant string, apID, tokenID int64, cutoff time.Time) string {
	return f.key
}
func (*fakeSlate) Close() {}

func installFakeSlate(t *testing.T, h *Handler) *fakeSlate {
	t.Helper()
	h.Slate.Close()
	f := &fakeSlate{dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(f.dir, "index.m3u8"), []byte("#EXTM3U\n#EXTINF:2,\nseg000001.ts\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "seg000001.ts"), []byte("segment"), 0600); err != nil {
		t.Fatal(err)
	}
	h.Slate = f
	return f
}

func slateRequest(t *testing.T, h *Handler, method, path, accept string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRevokedEntrySelectsSharedSlateAndKeepsHTML(t *testing.T) {
	h, db := newTestHandler(t)
	f := installFakeSlate(t, h)
	apID := seedStream(t, db, "https://example.org/index.m3u8", "live/slate", "private")
	addToken(t, db, apID, "real-token")
	if _, err := db.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID); err != nil {
		t.Fatal(err)
	}
	if got := slateRequest(t, h, "GET", "/live/slate/wrong-token.m3u8", "application/vnd.apple.mpegurl"); got.Code != 404 {
		t.Fatalf("invalid token revealed path: %d", got.Code)
	}
	player := slateRequest(t, h, "GET", "/live/slate/real-token.m3u8", "application/vnd.apple.mpegurl")
	if player.Code != 200 || !strings.Contains(player.Body.String(), "/_sv/slate/unavailable/unauthorized_redistribution/") {
		t.Fatalf("player response: %d %s", player.Code, player.Body.String())
	}
	if f.calls != 0 {
		t.Fatal("entry response must not create FFmpeg session per client")
	}
	page := slateRequest(t, h, "GET", "/live/slate/real-token.m3u8", "text/html,application/xhtml+xml")
	if page.Code != 410 || !strings.Contains(page.Body.String(), "<html") {
		t.Fatalf("HTML response: %d", page.Code)
	}
	head := slateRequest(t, h, "HEAD", "/live/slate/real-token.m3u8", "application/vnd.apple.mpegurl")
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Fatalf("HEAD response: %d bytes=%d", head.Code, head.Body.Len())
	}
	if _, err := db.Exec(`UPDATE streams SET status = 'disabled' WHERE id = (SELECT stream_id FROM access_points WHERE id = ?)`, apID); err != nil {
		t.Fatal(err)
	}
	if got := slateRequest(t, h, "GET", "/live/slate/wrong-token.m3u8", ""); got.Code != 404 {
		t.Fatalf("disabled stream revealed invalid token: %d", got.Code)
	}
}

func TestGlobalSlateRoutingAndNameValidation(t *testing.T) {
	h, _ := newTestHandler(t)
	f := installFakeSlate(t, h)
	for _, path := range []string{"/_sv/slate/unavailable/index.m3u8", "/_sv/slate/unavailable/seg000001.ts"} {
		got := slateRequest(t, h, "GET", path, "")
		if got.Code != 200 {
			t.Fatalf("%s: %d", path, got.Code)
		}
	}
	if f.calls != 2 {
		t.Fatalf("expected one call per resource, got %d", f.calls)
	}
	for _, path := range []string{"/_sv/slate/nope/index.m3u8", "/_sv/slate/unavailable/../message.txt", "/_sv/slate/unavailable/seg1.ts", "/_sv/slate/unavailable/message.txt", "/_sv/slate/unavailable/index.m3u8/extra"} {
		got := slateRequest(t, h, "GET", path, "")
		if got.Code != 404 {
			t.Fatalf("%s: expected 404, got %d", path, got.Code)
		}
	}
	if f.calls != 2 {
		t.Fatalf("invalid names reached provider (%d calls)", f.calls)
	}
	head := slateRequest(t, h, "HEAD", "/_sv/slate/unavailable/seg000001.ts", "")
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Fatalf("HEAD slate segment: %d bytes=%d", head.Code, head.Body.Len())
	}
}

func TestPersonalSlateRouteAndTokenValidation(t *testing.T) {
	h, db := newTestHandler(t)
	f := installFakeSlate(t, h)
	f.key = strings.Repeat("a", 40)
	apID := seedStream(t, db, "https://example.org/index.m3u8", "live/personal", "private")
	addToken(t, db, apID, "valid-token")
	if _, err := db.Exec("UPDATE access_tokens SET revoked_at='2026-09-26T17:31:00.000Z' WHERE access_point_id=?", apID); err != nil {
		t.Fatal(err)
	}
	if got := slateRequest(t, h, "GET", "/live/personal/invalid-token.m3u8", "*/*"); got.Code != 404 {
		t.Fatalf("invalid token: %d", got.Code)
	}
	got := slateRequest(t, h, "GET", "/live/personal/valid-token.m3u8", "*/*")
	want := "/_sv/slate/unavailable/unauthorized_redistribution/" + f.key + "/index.m3u8"
	if got.Code != 200 || !strings.Contains(got.Body.String(), want) {
		t.Fatalf("entry: %d %s", got.Code, got.Body.String())
	}
	if got := slateRequest(t, h, "GET", want, ""); got.Code != 200 {
		t.Fatalf("personal playlist: %d", got.Code)
	}
	for _, bad := range []string{
		"/_sv/slate/unavailable/" + strings.Repeat("b", 40) + "/index.m3u8",
		"/_sv/slate/unavailable/" + f.key + "/../../secret.key",
		"/_sv/slate/unavailable/" + f.key + "/seg1.ts",
	} {
		if got := slateRequest(t, h, "GET", bad, ""); got.Code != 404 {
			t.Fatalf("%s: %d", bad, got.Code)
		}
	}
}

func TestDisabledAndExpiredEntriesSelectUnavailableSlate(t *testing.T) {
	h, db := newTestHandler(t)
	installFakeSlate(t, h)
	publicID := seedStream(t, db, "https://example.org/public.m3u8", "live/disabled", "public")
	if _, err := db.Exec(`UPDATE streams SET status = 'disabled' WHERE id = (SELECT stream_id FROM access_points WHERE id = ?)`, publicID); err != nil {
		t.Fatal(err)
	}
	if got := slateRequest(t, h, "GET", "/live/disabled.m3u8", "application/vnd.apple.mpegurl"); got.Code != 200 || !strings.Contains(got.Body.String(), "/_sv/slate/unavailable/") {
		t.Fatalf("disabled stream: %d %s", got.Code, got.Body.String())
	}
	privateID := seedStream(t, db, "https://example.org/private.m3u8", "live/expired", "private")
	addToken(t, db, privateID, "expired-token")
	if _, err := db.Exec(`UPDATE access_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE access_point_id = ?`, privateID); err != nil {
		t.Fatal(err)
	}
	if got := slateRequest(t, h, "GET", "/live/expired/expired-token.m3u8", "application/vnd.apple.mpegurl"); got.Code != 200 || !strings.Contains(got.Body.String(), "/_sv/slate/unavailable/") {
		t.Fatalf("expired token: %d %s", got.Code, got.Body.String())
	}
}

func TestUpstreamFailureSelectsTemporarySlateForPlayersOnly(t *testing.T) {
	oldMin := finiteSlateMinSegments
	finiteSlateMinSegments = 1
	defer func() { finiteSlateMinSegments = oldMin }()
	h, db := newTestHandler(t)
	f := installFakeSlate(t, h)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer src.Close()
	seedStream(t, db, src.URL+"/index.m3u8", "live/down", "public")
	if _, err := db.Exec(`UPDATE slate_texts SET title='Source cooling down', subtitle='Please retry soon.' WHERE reason='temporarily_unavailable'`); err != nil {
		t.Fatal(err)
	}

	player := slateRequest(t, h, "GET", "/live/down.m3u8", "*/*")
	// A FINITE playlist of the shared temporary slate's segments, ending in
	// ENDLIST, so the player drops back to the entry URL instead of being
	// parked on an endless slate stream.
	pb := player.Body.String()
	if player.Code != 200 || !strings.Contains(pb, "/_sv/slate/temporarily-unavailable/temporarily_unavailable/seg000001.ts") || !strings.Contains(pb, "#EXT-X-ENDLIST") || strings.Contains(pb, "index.m3u8") {
		t.Fatalf("player on upstream failure: %d %s", player.Code, pb)
	}
	callsAfterPlayer := f.calls
	browser := slateRequest(t, h, "GET", "/live/down.m3u8", "text/html")
	// 503 (not 502) so Cloudflare passes our page through instead of its own.
	if browser.Code != http.StatusServiceUnavailable || browser.Header().Get("Retry-After") == "" || !strings.Contains(browser.Body.String(), "Source cooling down") || !strings.Contains(browser.Body.String(), "Please retry soon.") {
		t.Fatalf("browser on upstream failure: %d %s", browser.Code, browser.Body.String())
	}
	if callsAfterPlayer != 1 || f.calls != 1 {
		t.Fatalf("player should read the shared temporary slate once and the browser not at all: %d/%d", callsAfterPlayer, f.calls)
	}
}

func TestReasonSpecificCopyReachesPlayerAndBrowser(t *testing.T) {
	h, db := newTestHandler(t)
	f := installFakeSlate(t, h)
	f.key = strings.Repeat("a", 40)
	apID := seedStream(t, db, "https://example.org/index.m3u8", "live/reason", "private")
	addToken(t, db, apID, "reason-token")
	if _, err := db.Exec(`UPDATE streams SET replacement_reason='limited_bandwidth' WHERE id=(SELECT stream_id FROM access_points WHERE id=?)`, apID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE access_tokens SET revoked_at='2026-09-26T17:31:00.000Z' WHERE access_point_id=?`, apID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE slate_texts SET title='Capacity paused', subtitle='Try again later.' WHERE reason='limited_bandwidth'`); err != nil {
		t.Fatal(err)
	}
	player := slateRequest(t, h, "GET", "/live/reason/reason-token.m3u8", "application/vnd.apple.mpegurl")
	path := "/_sv/slate/unavailable/limited_bandwidth/" + f.key + "/index.m3u8"
	if player.Code != 200 || !strings.Contains(player.Body.String(), path) {
		t.Fatalf("player: %d %s", player.Code, player.Body.String())
	}
	if got := slateRequest(t, h, "GET", path, ""); got.Code != 200 {
		t.Fatalf("reason route: %d", got.Code)
	}
	if got := slateRequest(t, h, "GET", "/_sv/slate/temporarily-unavailable/limited_bandwidth/index.m3u8", ""); got.Code != 404 {
		t.Fatalf("wrong variant: %d", got.Code)
	}
	page := slateRequest(t, h, "GET", "/live/reason/reason-token.m3u8", "text/html")
	if page.Code != 410 || !strings.Contains(page.Body.String(), "Capacity paused") || !strings.Contains(page.Body.String(), "Try again later.") {
		t.Fatalf("browser: %d %s", page.Code, page.Body.String())
	}
}

func TestNoticeImageIsServedWithoutAccessPointLookup(t *testing.T) {
	h, _ := newTestHandler(t)
	got := slateRequest(t, h, "GET", "/_sv/notice.png", "")
	if got.Code != 200 || got.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(got.Body.String(), "\x89PNG") {
		t.Fatalf("notice: %d %s", got.Code, got.Header().Get("Content-Type"))
	}
}

func TestColdSourceEntryIsRetriedOnceAfterHeaderTimeout(t *testing.T) {
	oldFirst, oldRetry := entryHeaderTimeout, entryRetryHeaderTimeout
	entryHeaderTimeout, entryRetryHeaderTimeout = 200*time.Millisecond, 2*time.Second
	defer func() { entryHeaderTimeout, entryRetryHeaderTimeout = oldFirst, oldRetry }()

	h, db := newTestHandler(t)
	installFakeSlate(t, h)
	var hits atomic.Int32
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			time.Sleep(600 * time.Millisecond) // cold tuner: slower than the first header timeout
		}
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		io.WriteString(w, "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\nlive000.ts\n")
	}))
	defer src.Close()
	seedStream(t, db, src.URL+"/index.m3u8", "live/cold", "public")
	got := slateRequest(t, h, "GET", "/live/cold.m3u8", "*/*")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "/live/cold/r/") || strings.Contains(got.Body.String(), "_sv/slate") {
		t.Fatalf("cold source should be served after one retry, got %d %s", got.Code, got.Body.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("expected exactly one retry (2 source hits), got %d", hits.Load())
	}
}
