package leakcheck

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestStore applies every migration file in order, the same way
// admin/includes/db.php does, so a new migration (like 0003's lock table)
// is picked up automatically without editing this helper again.
func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.sqlite")

	matches, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil || len(matches) == 0 {
		t.Fatalf("globbing migrations: %v (matches=%v)", err, matches)
	}
	sort.Strings(matches)

	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("opening raw db: %v", err)
	}
	for _, m := range matches {
		content, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("reading %s: %v", m, err)
		}
		if _, err := raw.Exec(string(content)); err != nil {
			t.Fatalf("applying %s: %v", m, err)
		}
	}

	st, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, raw
}

func TestScannerEndToEndFindsAndDedupesConfirmedLeak(t *testing.T) {
	st, db := newTestStore(t)

	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Nova', 'hls', 'https://source.internal/x.m3u8')`)
	if err != nil {
		t.Fatal(err)
	}
	streamID, _ := res.LastInsertId()
	res, err = db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/nova', 'private')`, streamID)
	if err != nil {
		t.Fatal(err)
	}
	apID, _ := res.LastInsertId()
	rawToken := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 48 hex chars
	rawToken = rawToken[:48]
	sum := sha256.Sum256([]byte(rawToken))
	if _, err := db.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display, label) VALUES (?, ?, 'x', 'test')`,
		apID, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('gateway_base_url', 'https://restream.example.com')`); err != nil {
		t.Fatal(err)
	}

	leakedFragment := "m3u8: https://restream.example.com/live/nova/" + rawToken + ".m3u8"
	callCount := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("X-RateLimit-Remaining", "10")
		if r.URL.Path == "/search/code" {
			w.Write([]byte(`{"items":[{"html_url":"https://github.com/x/y/blob/main/f","path":"f","repository":{"full_name":"x/y"},"text_matches":[{"fragment":"` + leakedFragment + `"}]}]}`))
			return
		}
		w.Write([]byte(`{"items":[]}`)) // issue search: nothing
	}))
	defer gh.Close()

	client := NewClient("test-token")
	client.BaseURL = gh.URL
	scanner := &Scanner{Store: st, GitHub: client, BaseURL: "https://restream.example.com"}

	sum1 := scanner.Run(context.Background())
	if sum1.Err != nil {
		t.Fatalf("unexpected run error: %v", sum1.Err)
	}
	if sum1.StreamsChecked != 1 {
		t.Fatalf("expected 1 access point checked, got %d", sum1.StreamsChecked)
	}
	if sum1.FindingsCreated != 1 {
		t.Fatalf("expected 1 new finding, got %d", sum1.FindingsCreated)
	}

	var incidentCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&incidentCount); err != nil {
		t.Fatal(err)
	}
	if incidentCount != 1 {
		t.Fatalf("expected exactly 1 incident created, got %d", incidentCount)
	}
	var status, confidence string
	if err := db.QueryRow(`SELECT status FROM incidents`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "probable" {
		t.Fatalf("expected a Confirmed-confidence match to open an incident at 'probable' (not auto-confirmed), got %q", status)
	}
	if err := db.QueryRow(`SELECT confidence FROM leak_findings`).Scan(&confidence); err != nil {
		t.Fatal(err)
	}
	if confidence != "confirmed" {
		t.Fatalf("expected finding confidence 'confirmed', got %q", confidence)
	}

	// Re-running the scan against the same (unchanged) result must not
	// create a second finding or a second incident -- spec: "Jeden únik
	// nesmí vyvolat desítky zbytečných rotací" starts with not even
	// recording it twice.
	sum2 := scanner.Run(context.Background())
	if sum2.FindingsCreated != 0 {
		t.Fatalf("expected 0 new findings on re-scan (dedupe), got %d", sum2.FindingsCreated)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&incidentCount); err != nil {
		t.Fatal(err)
	}
	if incidentCount != 1 {
		t.Fatalf("expected still exactly 1 incident after re-scan, got %d", incidentCount)
	}
	var findingCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM leak_findings`).Scan(&findingCount); err != nil {
		t.Fatal(err)
	}
	if findingCount != 1 {
		t.Fatalf("expected still exactly 1 leak_findings row after re-scan, got %d", findingCount)
	}
	if callCount < 6 { // 3 queries (code+issue+pr) per run x 2 runs
		t.Fatalf("expected the mock GitHub server to actually be called, got %d calls", callCount)
	}
}

// Regression test for Codex's review finding: leak_sources rows must
// actually reach the GitHub query, not just sit in the database as inert
// configuration the admin UI displays.
func TestScannerQueriesEnabledLeakSources(t *testing.T) {
	st, db := newTestStore(t)
	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Nova', 'hls', 'https://source.internal/x.m3u8')`)
	if err != nil {
		t.Fatal(err)
	}
	streamID, _ := res.LastInsertId()
	if _, err := db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/nova', 'public')`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('gateway_base_url', 'https://restream.example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leak_sources (provider, identifier, enabled) VALUES ('github_repo', 'iptv-org/iptv', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leak_sources (provider, identifier, enabled) VALUES ('github_org', 'some-org', 0)`); err != nil { // disabled -- must be skipped
		t.Fatal(err)
	}

	var queries []string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("X-RateLimit-Remaining", "10")
		w.Write([]byte(`{"items":[]}`))
	}))
	defer gh.Close()

	client := NewClient("")
	client.BaseURL = gh.URL
	scanner := &Scanner{Store: st, GitHub: client, BaseURL: "https://restream.example.com"}
	sum := scanner.Run(context.Background())
	if sum.Err != nil {
		t.Fatalf("unexpected run error: %v", sum.Err)
	}

	foundScoped := false
	foundOrgScoped := false
	for _, q := range queries {
		if strings.Contains(q, "repo%3Aiptv-org%2Fiptv") || strings.Contains(q, "repo:iptv-org/iptv") {
			foundScoped = true
		}
		if strings.Contains(q, "org%3Asome-org") || strings.Contains(q, "org:some-org") {
			foundOrgScoped = true
		}
	}
	if !foundScoped {
		t.Fatalf("expected a query scoped to the enabled repo:iptv-org/iptv source, got queries: %v", queries)
	}
	if foundOrgScoped {
		t.Fatal("disabled leak_sources row must not be queried")
	}

	var lastScanned sql.NullString
	if err := db.QueryRow(`SELECT last_scanned_at FROM leak_sources WHERE identifier = 'iptv-org/iptv'`).Scan(&lastScanned); err != nil {
		t.Fatal(err)
	}
	if !lastScanned.Valid {
		t.Fatal("expected last_scanned_at to be updated for the used source")
	}
}

// Regression test for the review finding that ordinary query failures
// (a bad token, a network blip, a decode error) were logged and then
// ignored, letting a run that scanned nothing successfully still finish
// with Err == nil -- indistinguishable from a real, clean "nothing found".
func TestScannerReportsPartialCoverageOnQueryFailure(t *testing.T) {
	st, db := newTestStore(t)
	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Nova', 'hls', 'https://source.internal/x.m3u8')`)
	if err != nil {
		t.Fatal(err)
	}
	streamID, _ := res.LastInsertId()
	if _, err := db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/nova', 'public')`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('gateway_base_url', 'https://restream.example.com')`); err != nil {
		t.Fatal(err)
	}

	// Not a rate limit (429/403 with remaining=0) -- an ordinary API error,
	// e.g. a revoked token, which must not look like a clean success.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "10")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer gh.Close()

	client := NewClient("invalid-token")
	client.BaseURL = gh.URL
	scanner := &Scanner{Store: st, GitHub: client, BaseURL: "https://restream.example.com"}
	sum := scanner.Run(context.Background())
	if sum.Err == nil {
		t.Fatal("expected Err to be set when every query fails, so the run isn't mistaken for a clean scan")
	}
	if sum.FindingsCreated != 0 {
		t.Fatalf("expected 0 findings from failed queries, got %d", sum.FindingsCreated)
	}
}

func TestScannerStopsEarlyOnRateLimit(t *testing.T) {
	st, db := newTestStore(t)
	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url) VALUES ('Nova', 'hls', 'https://source.internal/x.m3u8')`)
	if err != nil {
		t.Fatal(err)
	}
	streamID, _ := res.LastInsertId()
	if _, err := db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/nova', 'public')`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('gateway_base_url', 'https://restream.example.com')`); err != nil {
		t.Fatal(err)
	}

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"rate limit"}`))
	}))
	defer gh.Close()

	client := NewClient("")
	client.BaseURL = gh.URL
	scanner := &Scanner{Store: st, GitHub: client, BaseURL: "https://restream.example.com"}
	sum := scanner.Run(context.Background())
	if sum.Err == nil {
		t.Fatal("expected the run to report a rate-limit note, not silently succeed")
	}
}
