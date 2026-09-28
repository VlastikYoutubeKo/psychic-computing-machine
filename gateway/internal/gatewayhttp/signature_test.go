package gatewayhttp

import (
	"bytes"
	"database/sql"
	"testing"

	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

// Nodes get freshly encrypted credentials on every config poll; the relay
// signature must not change with the ciphertext or node relays restart
// on every poll.
func TestSourceSignatureIgnoresCiphertextNonce(t *testing.T) {
	h := &Handler{Key: bytes.Repeat([]byte{7}, 32)}
	enc := func(pw string) sql.NullString {
		c, err := secretbox.Encrypt(h.Key, []byte(pw))
		if err != nil {
			t.Fatal(err)
		}
		return sql.NullString{String: c, Valid: true}
	}
	st := func(pw sql.NullString) store.Stream {
		return store.Stream{SourceURL: "https://src.example/a", SourceUsername: sql.NullString{String: "u", Valid: true}, SourcePasswordEnc: pw}
	}
	a, b := enc("pw1"), enc("pw1")
	if a.String == b.String {
		t.Fatal("expected distinct ciphertexts")
	}
	if h.sourceSignature(st(a)) != h.sourceSignature(st(b)) {
		t.Fatal("same password re-encrypted changed the signature")
	}
	if h.sourceSignature(st(a)) == h.sourceSignature(st(enc("pw2"))) {
		t.Fatal("different password kept the signature")
	}
}
