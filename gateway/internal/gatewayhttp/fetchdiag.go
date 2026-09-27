package gatewayhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"
)

// errBlockedTarget marks a fetch refused by checkFetchTarget (SSRF policy).
var errBlockedTarget = errors.New("target blocked by SSRF policy")

// fetchFailureKind names why a source fetch failed without ever including
// the URL (which can carry source credentials or a secret path), so the
// log says "timeout" or "connection reset" instead of just "failed".
func fetchFailureKind(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	switch {
	case errors.Is(err, errBlockedTarget):
		return "redirect or target blocked by SSRF policy"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "host unreachable"
	case errors.As(err, &certErr), errors.As(err, &unknownAuth), errors.As(err, &hostnameErr):
		return "TLS certificate error"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "network error"
}
