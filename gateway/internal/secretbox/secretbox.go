// Package secretbox implements the shared AES-256-GCM envelope used to store
// source credentials (Tvheadend/Restreamer passwords) at rest. The exact wire
// format (base64 of nonce||ciphertext||tag) is mirrored in
// admin/includes/secret_box.php so the PHP admin (which writes secrets) and
// this Go gateway (which reads them to authenticate to sources) agree on the
// encoding. Keep the two implementations in lockstep if this ever changes.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const KeySize = 32 // AES-256

// LoadKey reads a 32-byte key from path. The file must contain either raw
// 32 bytes or a base64-encoded 32-byte value (trailing newline tolerated).
// The key file is intentionally kept outside the SQLite database (see
// SECURITY.md): losing the DB alone must not expose source passwords.
func LoadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secretbox: reading key file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(raw) == KeySize {
		return raw, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != KeySize {
		return nil, fmt.Errorf("secretbox: key file %s must contain %d raw bytes or their base64 encoding", path, KeySize)
	}
	return decoded, nil
}

// GenerateKey returns a fresh random 32-byte key, base64-encoded for storage.
func GenerateKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Encrypt seals plaintext under key, returning base64(nonce || ciphertext || tag).
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != KeySize {
		return "", errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secretbox: invalid base64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("secretbox: ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
