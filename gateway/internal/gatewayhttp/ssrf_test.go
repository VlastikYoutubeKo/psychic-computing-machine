package gatewayhttp

import (
	"context"
	"net"
	"net/url"
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
