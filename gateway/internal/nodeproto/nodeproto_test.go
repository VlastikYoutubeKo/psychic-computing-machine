package nodeproto

import (
	"strings"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseToken(t *testing.T) {
	id, s, ok := ParseToken("svn_42_" + secret)
	if !ok || id != 42 || s != secret {
		t.Fatalf("valid token rejected: %v %d %q", ok, id, s)
	}
	for _, bad := range []string{
		"", "svn_42_", "svn_0_" + secret, "svn_-1_" + secret, "svn_42_" + strings.ToUpper(secret),
		"svn_42_" + secret[:63], "svn_42_" + secret + "0", "xsvn_42_" + secret, "svn_42_" + secret + "\n",
	} {
		if _, _, ok := ParseToken(bad); ok {
			t.Errorf("accepted malformed token %q", bad)
		}
	}
}

func TestHashAndSignature(t *testing.T) {
	if !HashMatches(secret, SecretHash(secret)) || HashMatches(secret[:63]+"0", SecretHash(secret)) {
		t.Fatal("hash compare broken")
	}
	sig := Sign(secret, 7, 3, 9, 2000000000)
	if !Verify(secret, 7, 3, 9, 2000000000, sig) {
		t.Fatal("valid signature rejected")
	}
	for name, ok := range map[string]bool{
		"other stream":  Verify(secret, 8, 3, 9, 2000000000, sig),
		"other ap":      Verify(secret, 7, 4, 9, 2000000000, sig),
		"other token":   Verify(secret, 7, 3, 0, 2000000000, sig),
		"extended exp":  Verify(secret, 7, 3, 9, 2000000001, sig),
		"other secret":  Verify(strings.Repeat("f", 64), 7, 3, 9, 2000000000, sig),
		"truncated sig": Verify(secret, 7, 3, 9, 2000000000, sig[:63]),
	} {
		if ok {
			t.Errorf("signature accepted for %s", name)
		}
	}
	if string(ConfigKey(secret)) == string(derive("sign", secret)) {
		t.Fatal("config and signing keys must differ")
	}
}
