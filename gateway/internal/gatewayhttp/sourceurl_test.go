package gatewayhttp

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

func TestSourceEntryURLSubstitutesPlaceholders(t *testing.T) {
	h := &Handler{Key: bytes.Repeat([]byte{9}, 32)}
	enc, err := secretbox.Encrypt(h.Key, []byte("p/ss w?rd&x"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.Stream{
		SourceURL:         "http://panel.example:8080/live/{username}/{password}/7.ts?u={username}&p={password}",
		SourceUsername:    sql.NullString{String: "us er", Valid: true},
		SourcePasswordEnc: sql.NullString{String: enc, Valid: true},
	}
	u, err := h.sourceEntryURL(st)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.EscapedPath(), "/live/us%20er/p%2Fss%20w%3Frd&x/7.ts"; got != want {
		t.Fatalf("path: got %q want %q", got, want)
	}
	if q := u.Query(); q.Get("u") != "us er" || q.Get("p") != "p/ss w?rd&x" {
		t.Fatalf("query not substituted/escaped correctly: %q", u.RawQuery)
	}

	st.SourcePasswordEnc = sql.NullString{}
	if _, err := h.sourceEntryURL(st); err == nil {
		t.Fatal("placeholders without stored credentials must be an error")
	}
	plain := store.Stream{SourceURL: "https://src.example/a.m3u8"}
	if u, err := (&Handler{}).sourceEntryURL(plain); err != nil || u.String() != plain.SourceURL {
		t.Fatalf("plain URL must pass through untouched: %v %v", u, err)
	}
}

func TestRedactURLErrorDropsPathAndKeepsChain(t *testing.T) {
	inner := errors.New("boom")
	err := redactURLError(&url.Error{Op: "Get", URL: "http://panel.example:8080/live/user/secretpw/7.ts", Err: inner})
	if strings.Contains(err.Error(), "secretpw") || !strings.Contains(err.Error(), "panel.example:8080") {
		t.Fatalf("unexpected redaction: %v", err)
	}
	if !errors.Is(err, inner) {
		t.Fatal("error chain lost")
	}
}

// An Xtream-style source: credentials live in the URL path, are stored
// encrypted, never reach the viewer and are not also sent as Basic auth.
func TestPlaceholderSourceIsFetchedWithCredentialsInPath(t *testing.T) {
	var mu sync.Mutex
	var sawAuthHeader bool
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Header.Get("Authorization") != "" {
			sawAuthHeader = true
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/live/alice/s3cretpw/7.m3u8":
			io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
		case "/live/alice/s3cretpw/seg1.ts":
			w.Header().Set("Content-Type", "text/plain") // mislabelled, but binary: must still pass
			w.Write([]byte("\x47segment-bytes\x00\x01"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	h.Key = bytes.Repeat([]byte{3}, 32)
	seedStream(t, db, source.URL+"/live/{username}/{password}/7.m3u8", "live/x", "public")
	enc, err := secretbox.Encrypt(h.Key, []byte("s3cretpw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE streams SET source_username='alice', source_password_enc=?`, enc); err != nil {
		t.Fatal(err)
	}

	gw := httptest.NewServer(h)
	defer gw.Close()
	resp, err := http.Get(gw.URL + "/live/x.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("entry: HTTP %d: %s", resp.StatusCode, body)
	}
	manifest := string(body)
	if strings.Contains(manifest, "s3cretpw") || strings.Contains(manifest, "alice") {
		t.Fatalf("credentials leaked into the manifest:\n%s", manifest)
	}
	var seg string
	for _, line := range strings.Split(manifest, "\n") {
		if strings.Contains(line, "/r/") {
			seg = strings.TrimSpace(line)
		}
	}
	if seg == "" {
		t.Fatalf("no segment reference in manifest:\n%s", manifest)
	}
	segResp, err := http.Get(gw.URL + seg)
	if err != nil {
		t.Fatal(err)
	}
	segBody, _ := io.ReadAll(segResp.Body)
	segResp.Body.Close()
	if string(segBody) != "\x47segment-bytes\x00\x01" {
		t.Fatalf("segment: HTTP %d %q", segResp.StatusCode, segBody)
	}
	mu.Lock()
	defer mu.Unlock()
	if sawAuthHeader {
		t.Fatal("placeholder sources must not also receive Basic auth")
	}
}

// A panel that answers 200 with a diagnostic page echoing the requested
// path (which contains the credentials) must not reach the viewer.
func TestPlaceholderSourceErrorPageIsNotForwarded(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case strings.HasSuffix(r.URL.Path, "/8.m3u8"):
			io.WriteString(w, "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n")
		default:
			io.WriteString(w, "<html>not allowed: "+r.URL.Path+"</html>")
		}
	}))
	defer source.Close()

	h, db := newTestHandler(t)
	h.Key = bytes.Repeat([]byte{3}, 32)
	enc, err := secretbox.Encrypt(h.Key, []byte("s3cretpw"))
	if err != nil {
		t.Fatal(err)
	}
	seedStream(t, db, source.URL+"/live/{username}/{password}/7.ts", "live/doc", "public")
	seedStream(t, db, source.URL+"/live/{username}/{password}/8.m3u8", "live/seg", "public")
	if _, err := db.Exec(`UPDATE streams SET source_username='alice', source_password_enc=?`, enc); err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	defer gw.Close()

	get := func(path string) (int, string) {
		resp, err := http.Get(gw.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if _, body := get("/live/doc.m3u8"); strings.Contains(body, "s3cretpw") || strings.Contains(body, "not allowed") {
		t.Fatalf("entry error page forwarded to the viewer: %q", body)
	}
	_, manifest := get("/live/seg.m3u8")
	var seg string
	for _, line := range strings.Split(manifest, "\n") {
		if strings.Contains(line, "/r/") {
			seg = strings.TrimSpace(line)
		}
	}
	if seg == "" {
		t.Fatalf("no segment reference:\n%s", manifest)
	}
	if _, body := get(seg); strings.Contains(body, "s3cretpw") || strings.Contains(body, "not allowed") {
		t.Fatalf("resource error page forwarded to the viewer: %q", body)
	}
}
