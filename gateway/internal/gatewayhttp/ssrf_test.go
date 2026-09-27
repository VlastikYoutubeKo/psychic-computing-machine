package gatewayhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIsPrivateOrReserved(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":       true,
		"10.0.0.5":        true,
		"172.17.0.2":      true, // default Docker bridge range
		"192.168.1.1":     true,
		"169.254.169.254": true, // cloud metadata
		"0.0.0.0":         true,
		"8.8.8.8":         false,
		"1.1.1.1":         false,
		"46.229.243.219":  false, // a real public IP this project's own live test hit
	}
	for addr, want := range cases {
		ip := mustParseIP(t, addr)
		if got := isPrivateOrReserved(ip); got != want {
			t.Errorf("isPrivateOrReserved(%s) = %v, want %v", addr, got, want)
		}
	}
}

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("could not parse IP %q", s)
	}
	return ip
}

func TestCheckFetchTargetRejectsNonHTTPScheme(t *testing.T) {
	target, _ := url.Parse("file:///etc/passwd")
	resolve := func(ctx context.Context, host string) (bool, error) { return false, nil }
	if err := checkFetchTarget(context.Background(), resolve, target, false); err == nil {
		t.Fatal("expected a non-HTTP(S) scheme to be rejected")
	}
}

func TestCheckFetchTargetAllowsPrivateWhenSourceTrusted(t *testing.T) {
	target, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	resolve := func(ctx context.Context, host string) (bool, error) { return true, nil } // target IS private
	if err := checkFetchTarget(context.Background(), resolve, target, true); err != nil {
		t.Fatalf("expected a private target to be allowed when the source itself is private, got %v", err)
	}
}

func TestCheckFetchTargetRejectsPrivateWhenSourcePublic(t *testing.T) {
	target, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	resolve := func(ctx context.Context, host string) (bool, error) { return true, nil }
	if err := checkFetchTarget(context.Background(), resolve, target, false); err == nil {
		t.Fatal("expected a private target to be rejected when the source is public")
	}
}

func TestCheckFetchTargetPropagatesResolutionFailure(t *testing.T) {
	target, _ := url.Parse("http://does-not-resolve.invalid/x")
	resolve := func(ctx context.Context, host string) (bool, error) {
		return false, context.DeadlineExceeded
	}
	if err := checkFetchTarget(context.Background(), resolve, target, false); err == nil {
		t.Fatal("expected a resolution failure to fail closed (rejected), not silently pass")
	}
}

// Regular accounts can set source_url, so their streams must never reach
// private/internal services -- not even the entry fetch. Admin-owned streams
// keep the "private source is trusted" behaviour (LAN Tvheadend etc.).
func TestUserOwnedStreamCannotReachPrivateSource(t *testing.T) {
	oldMin := finiteSlateMinSegments
	finiteSlateMinSegments = 1
	defer func() { finiteSlateMinSegments = oldMin }()
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"admin_api":"secret config"}`))
	}))
	defer internal.Close()
	h, db := newTestHandler(t)
	installFakeSlate(t, h)
	res, err := db.Exec(`INSERT INTO operators (username, password_hash, role, status) VALUES ('mallory', 'x', 'user', 'active')`)
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := res.LastInsertId()
	apID := seedStream(t, db, internal.URL+"/config/", "user/ssrf", "public")
	db.Exec(`UPDATE streams SET owner_id = ? WHERE id = (SELECT stream_id FROM access_points WHERE id = ?)`, userID, apID)

	for _, accept := range []string{"*/*", "text/html"} {
		got := slateRequest(t, h, "GET", "/user/ssrf.m3u8", accept)
		if strings.Contains(got.Body.String(), "secret config") {
			t.Fatalf("user stream leaked an internal response (%s)", accept)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("internal service received %d requests from a user-owned stream", hits.Load())
	}

	// Same source owned by an admin: still allowed (trusted private source).
	res, _ = db.Exec(`INSERT INTO operators (username, password_hash, role, status) VALUES ('boss', 'x', 'admin', 'active')`)
	adminID, _ := res.LastInsertId()
	db.Exec(`UPDATE streams SET owner_id = ? WHERE id = (SELECT stream_id FROM access_points WHERE id = ?)`, adminID, apID)
	slateRequest(t, h, "GET", "/user/ssrf.m3u8", "*/*")
	if hits.Load() == 0 {
		t.Fatal("admin-owned private source should still be reachable")
	}
}
