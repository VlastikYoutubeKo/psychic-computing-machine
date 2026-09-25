package secretbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	keyB64, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(keyPath, []byte(keyB64), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	key, err := LoadKey(keyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	plaintext := "s3cr3t-tvheadend-password"
	enc, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == plaintext {
		t.Fatal("ciphertext must not equal plaintext")
	}

	dec, err := Decrypt(key, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(dec) != plaintext {
		t.Fatalf("round trip mismatch: got %q want %q", dec, plaintext)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1B64, _ := GenerateKey()
	k2B64, _ := GenerateKey()
	dir := t.TempDir()
	p1 := filepath.Join(dir, "k1")
	p2 := filepath.Join(dir, "k2")
	os.WriteFile(p1, []byte(k1B64), 0o600)
	os.WriteFile(p2, []byte(k2B64), 0o600)
	k1, _ := LoadKey(p1)
	k2, _ := LoadKey(p2)

	enc, err := Encrypt(k1, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(k2, enc); err == nil {
		t.Fatal("expected decryption under the wrong key to fail")
	}
}
