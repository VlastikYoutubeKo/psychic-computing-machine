package gatewayhttp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSlate struct {
	dir   string
	calls int
}

func (f *fakeSlate) GetPath(variant, name string) (string, error) {
	f.calls++
	return filepath.Join(f.dir, name), nil
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
	if player.Code != 200 || !strings.Contains(player.Body.String(), "/_sv/slate/unavailable/index.m3u8") {
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
	h, db := newTestHandler(t)
	f := installFakeSlate(t, h)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer src.Close()
	seedStream(t, db, src.URL+"/index.m3u8", "live/down", "public")

	player := slateRequest(t, h, "GET", "/live/down.m3u8", "*/*")
	if player.Code != 200 || !strings.Contains(player.Body.String(), "/_sv/slate/temporarily-unavailable/index.m3u8") {
		t.Fatalf("player on upstream failure: %d %s", player.Code, player.Body.String())
	}
	browser := slateRequest(t, h, "GET", "/live/down.m3u8", "text/html")
	if browser.Code != http.StatusBadGateway {
		t.Fatalf("browser on upstream failure: %d", browser.Code)
	}
	if f.calls != 0 {
		t.Fatal("entry response must not touch the slate encoder")
	}
}
