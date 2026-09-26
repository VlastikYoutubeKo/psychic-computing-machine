package leakcheck

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testBase = "https://rest.example.com"

// seedPublicSecret creates a stream (rotation mode given) with one public
// access point whose path is marked secret.
func seedPublicSecret(t *testing.T, db *sql.DB, mode, path string, secret bool) (streamID, apID int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO streams (name, source_type, source_url, rotation_mode) VALUES ('S', 'hls', 'https://src.example/x.m3u8', ?)`, mode)
	if err != nil {
		t.Fatal(err)
	}
	streamID, _ = res.LastInsertId()
	sec := 0
	if secret {
		sec = 1
	}
	res, err = db.Exec(`INSERT INTO access_points (stream_id, public_path, visibility, path_is_secret) VALUES (?, ?, 'public', ?)`, streamID, path, sec)
	if err != nil {
		t.Fatal(err)
	}
	apID, _ = res.LastInsertId()
	if _, err := db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('gateway_base_url', ?)`, testBase); err != nil {
		t.Fatal(err)
	}
	return
}

// fakeGitHub returns an issue containing text on issue search, nothing on
// code/pr search, and records comment POSTs.
func fakeGitHub(t *testing.T, issueURL, text string) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var posts atomic.Int32
	var lastBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "10")
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			lastBody.Store(string(b))
			posts.Add(1)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"html_url":"` + issueURL + `#issuecomment-1"}`))
			return
		}
		if r.URL.Path == "/search/issues" && strings.Contains(r.URL.RawQuery, "is%3Aissue") {
			w.Write([]byte(`{"items":[{"html_url":"` + issueURL + `","title":"add this","body":"` + text + `"}]}`))
			return
		}
		w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &posts, &lastBody
}

func newScanner(st *Store, gh *httptest.Server) *Scanner {
	c := NewClient("t")
	c.BaseURL = gh.URL
	return &Scanner{Store: st, GitHub: c, BaseURL: testBase}
}

func TestAutoModeRevokesSecretPathAndRepliesOnceInAllowlistedRepo(t *testing.T) {
	st, db := newTestStore(t)
	_, apID := seedPublicSecret(t, db, "auto", "test", true)
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('github_reply_allowlist', 'Owner/Repo')`); err != nil {
		t.Fatal(err)
	}
	issue := "https://github.com/owner/repo/issues/2"
	gh, posts, body := fakeGitHub(t, issue, testBase+"/test.m3u8")
	sc := newScanner(st, gh)

	sum := sc.Run(context.Background())
	if sum.Err != nil {
		t.Fatal(sum.Err)
	}
	if sum.AutoRevoked != 1 || sum.RepliesPosted != 1 {
		t.Fatalf("auto-revoked=%d replies=%d", sum.AutoRevoked, sum.RepliesPosted)
	}
	var apStatus, incStatus, actions string
	db.QueryRow(`SELECT status FROM access_points WHERE id = ?`, apID).Scan(&apStatus)
	db.QueryRow(`SELECT status, actions_taken FROM incidents`).Scan(&incStatus, &actions)
	if apStatus != "revoked" || incStatus != "confirmed" {
		t.Fatalf("ap=%s incident=%s", apStatus, incStatus)
	}
	if !strings.Contains(actions, "auto_revoked") || !strings.Contains(actions, "github_reply") {
		t.Fatalf("actions log missing entries: %s", actions)
	}
	b, _ := body.Load().(string)
	if !strings.Contains(b, testBase+NoticeImagePath) || strings.Contains(b, "/test") {
		t.Fatalf("comment should embed the notice image and not name the path: %s", b)
	}

	// Second scan: the access point is no longer active, nothing new.
	sc.Run(context.Background())
	if posts.Load() != 1 {
		t.Fatalf("expected exactly one reply ever, got %d", posts.Load())
	}
}

func TestAutoModeDoesNotReplyOutsideAllowlist(t *testing.T) {
	st, db := newTestStore(t)
	seedPublicSecret(t, db, "auto", "test", true)
	gh, posts, _ := fakeGitHub(t, "https://github.com/someone/else/issues/9", testBase+"/test.m3u8")
	sum := newScanner(st, gh).Run(context.Background())
	if sum.AutoRevoked != 1 {
		t.Fatalf("expected revoke even without reply, got %d", sum.AutoRevoked)
	}
	if posts.Load() != 0 {
		t.Fatal("must not comment on a repo that isn't allowlisted")
	}
}

func TestManualModeNeverRevokesOrReplies(t *testing.T) {
	st, db := newTestStore(t)
	_, apID := seedPublicSecret(t, db, "manual_approval", "test", true)
	db.Exec(`INSERT INTO settings (key, value) VALUES ('github_reply_allowlist', 'owner/repo')`)
	gh, posts, _ := fakeGitHub(t, "https://github.com/owner/repo/issues/2", testBase+"/test.m3u8")
	newScanner(st, gh).Run(context.Background())
	var apStatus, incStatus string
	db.QueryRow(`SELECT status FROM access_points WHERE id = ?`, apID).Scan(&apStatus)
	db.QueryRow(`SELECT status FROM incidents`).Scan(&incStatus)
	if apStatus != "active" || incStatus != "probable" || posts.Load() != 0 {
		t.Fatalf("manual mode acted: ap=%s incident=%s posts=%d", apStatus, incStatus, posts.Load())
	}
}

func TestExistingMentionFindingIsUpgradedAndActedOn(t *testing.T) {
	// Findings recorded as Mentions before public links counted as leaks
	// (same dedupe key) must be upgraded in place and acted on, not
	// silently skipped as "already seen".
	st, db := newTestStore(t)
	_, apID := seedPublicSecret(t, db, "auto", "test", false)
	issue := "https://github.com/owner/repo/issues/2"
	anchor := testBase + "/test"
	if _, err := db.Exec(`INSERT INTO leak_findings (source, source_url, matched_value, confidence, dedupe_key, access_point_id)
		VALUES ('github_issue', ?, ?, 'mention', ?, ?)`, issue, anchor, DedupeKey("github_issue", issue, anchor), apID); err != nil {
		t.Fatal(err)
	}
	gh, _, _ := fakeGitHub(t, issue, anchor+".m3u8")
	sum := newScanner(st, gh).Run(context.Background())
	var n int
	var conf string
	db.QueryRow(`SELECT COUNT(*) FROM leak_findings`).Scan(&n)
	db.QueryRow(`SELECT confidence FROM leak_findings`).Scan(&conf)
	if n != 1 || conf != "confirmed" || sum.AutoRevoked != 1 {
		t.Fatalf("expected the same finding upgraded and acted on: rows=%d conf=%s revoked=%d", n, conf, sum.AutoRevoked)
	}
}

func TestDismissedIncidentIsNotReopenedOrActedOn(t *testing.T) {
	st, db := newTestStore(t)
	_, apID := seedPublicSecret(t, db, "manual_approval", "test", true)
	gh, _, _ := fakeGitHub(t, "https://github.com/owner/repo/issues/2", testBase+"/test.m3u8")
	sc := newScanner(st, gh)
	sc.Run(context.Background())
	db.Exec(`UPDATE incidents SET status = 'dismissed'`)
	db.Exec(`UPDATE streams SET rotation_mode = 'auto'`)

	sc.Run(context.Background())
	var incidents int
	var apStatus string
	db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&incidents)
	db.QueryRow(`SELECT status FROM access_points WHERE id = ?`, apID).Scan(&apStatus)
	if incidents != 1 || apStatus != "active" {
		t.Fatalf("dismissed incident re-opened or acted on: incidents=%d ap=%s", incidents, apStatus)
	}
}

func TestParseIssueURL(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"https://github.com/o/r/issues/2", true},
		{"https://github.com/o/r.x/pull/15", true},
		{"https://github.com/o/r/blob/main/f.m3u", false},
		{"https://github.com/o/r/issues/0", false},
		{"https://evil.com/o/r/issues/2", false},
		{"https://github.com/o/r/issues/2#x", false},
	} {
		if _, _, _, ok := ParseIssueURL(c.in); ok != c.ok {
			t.Errorf("%s: ok=%v", c.in, ok)
		}
	}
}
