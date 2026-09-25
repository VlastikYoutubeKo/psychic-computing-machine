package gatewayhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// isPrivateOrReserved reports whether ip is not a routable public address:
// RFC1918 private ranges, loopback, link-local (unicast/multicast),
// unspecified, or other multicast space.
func isPrivateOrReserved(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// resolveFunc reports whether host (a hostname or IP literal) resolves to
// at least one private/reserved address. It's a field on Handler (see
// hostResolvesToPrivate for the real DNS-backed implementation) rather
// than a bare function call so tests can substitute a deterministic
// answer: httptest servers always bind to 127.0.0.1, which is itself a
// private address, so any test exercising "this is a public source that
// redirected somewhere it shouldn't" cannot rely on real resolution --
// every httptest-based "source" would otherwise resolve as private and
// silently disable the check it's meant to test.
type resolveFunc func(ctx context.Context, host string) (bool, error)

// hostResolvesToPrivate is resolveFunc's real, DNS-backed implementation,
// used in production (see Handler.Resolve in handler.go). A resolution
// failure is returned as an error, never silently folded into true or
// false -- callers decide how to fail.
func hostResolvesToPrivate(ctx context.Context, host string) (bool, error) {
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrReserved(ip), nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, errors.New("no addresses returned")
	}
	for _, a := range addrs {
		if isPrivateOrReserved(a.IP) {
			return true, nil
		}
	}
	return false, nil
}

// checkFetchTarget decides whether the gateway may make an outbound
// request to target -- used both for a redirect the entry fetch follows
// and for a client-requested /r/ resource fetch (after blob decryption).
//
// The first version of this check required target to be the exact same
// host as the stream's configured source_url. That broke real streams:
// this project's own first live end-to-end test hit a source
// (cynessa.ottb.xyz) that 302s its entry point to a *different* host per
// request -- a fresh CDN77 edge node with a signed, single-use URL. That
// is an entirely ordinary CDN pattern, not an attack, and indistinguishable
// from one under a same-host rule.
//
// The actual risk this check exists for is narrower than "a different
// host": it's a source (compromised, malicious, or just misconfigured)
// redirecting the gateway into *this host's own private network* --
// cloud-metadata addresses, other containers on the same Docker network,
// localhost. So the rule is: any public (non-private/reserved) target is
// allowed, regardless of host, exactly as a browser would follow the same
// redirect. A private/reserved target is allowed only when the stream's
// own admin-configured source is *itself* on a private address (a LAN
// Tvheadend/Restreamer box someone deliberately pointed this at, per spec
// section 7, or simply another container on this project's own Docker
// network) -- then its own redirects/segment references landing on that
// same private network are expected, not an attack. A source that is
// itself public redirecting into a private range is always rejected.
//
// Known residual gap (see SECURITY.md): this resolves the hostname itself
// rather than pinning the IP actually connected to, so a DNS answer that
// changes between this check and the real connection (classic DNS
// rebinding) isn't caught. Accepted for now: the source is
// admin-configured, not attacker-controlled input, which is the same
// trust boundary the rest of this project's SSRF notes already lean on.
func checkFetchTarget(ctx context.Context, resolve resolveFunc, target *url.URL, sourceTrustsPrivate bool) error {
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("disallowed scheme %q", target.Scheme)
	}
	if sourceTrustsPrivate {
		return nil
	}
	private, err := resolve(ctx, target.Hostname())
	if err != nil {
		return fmt.Errorf("resolving %q: %w", target.Hostname(), err)
	}
	if private {
		return fmt.Errorf("target host %q resolves to a private/reserved address", target.Hostname())
	}
	return nil
}
