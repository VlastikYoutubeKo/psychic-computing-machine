package gatewayhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
)

func TestFetchFailureKindNeverIncludesURLAndClassifies(t *testing.T) {
	secret := "https://user:pass@src.example/live/SECRET.m3u8"
	wrap := func(e error) error { return &url.Error{Op: "Get", URL: secret, Err: e} }
	cases := map[string]error{
		"timeout":            wrap(context.DeadlineExceeded),
		"connection refused": wrap(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}),
		"connection reset":   wrap(&net.OpError{Op: "read", Err: syscall.ECONNRESET}),
		"DNS lookup failed":  wrap(&net.DNSError{Err: "no such host", Name: "src.example"}),
		"redirect or target blocked by SSRF policy": wrap(fmt.Errorf("%w: refusing to follow redirect: x", errBlockedTarget)),
		"network error": wrap(errors.New("weird")),
	}
	for want, err := range cases {
		got := fetchFailureKind(err)
		if got != want {
			t.Errorf("%v: got %q want %q", err, got, want)
		}
		if got == secret || len(got) > 60 {
			t.Errorf("kind must be short and URL-free: %q", got)
		}
	}
}
