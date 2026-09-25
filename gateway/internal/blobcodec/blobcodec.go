// Package blobcodec encrypts the absolute source URL embedded in a
// gateway-generated resource link ("/r/<blob>"). An earlier version just
// base64-encoded the URL, which is reversible by anyone holding the link --
// that defeats the whole point of hiding the source (a security review
// caught this before production cutover; see CHANGELOG.md). AES-256-GCM
// under a key that never leaves this process makes the blob both
// unreadable and unforgeable: a tampered or hand-crafted blob fails
// authentication and is rejected outright, which also removes any
// incentive to keep the separate host-allowlist check as the *only* line
// of defense against a forged target (it remains as defense in depth).
//
// The key is generated fresh in memory on gateway startup (New()) and is
// never persisted or shared with the PHP admin -- unlike secretbox, which
// stores durable source credentials, these blobs only need to stay valid
// for the lifetime of a single manifest's playback (it's regenerated on
// every manifest re-fetch). A restart invalidates outstanding segment links
// until the player refreshes the manifest.
package blobcodec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type Codec struct {
	aead cipher.AEAD
}

func New() (*Codec, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

// Encode returns a URL-path-safe token bound to an access point. The
// associated data prevents a link issued for one access point being replayed
// under another access point on the same upstream host.
func (c *Codec) Encode(plaintext, accessPoint string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), []byte(accessPoint)) // nonce || ciphertext || tag
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decode reverses Encode. It fails closed: a truncated, tampered, or
// hand-crafted blob (e.g. someone else's base64 of an arbitrary URL) is
// rejected here rather than being trusted and merely double-checked later.
func (c *Codec) Decode(blob, accessPoint string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return "", err
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("blobcodec: ciphertext too short")
	}
	nonce, ciphertext := raw[:ns], raw[ns:]
	plain, err := c.aead.Open(nil, nonce, ciphertext, []byte(accessPoint))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
