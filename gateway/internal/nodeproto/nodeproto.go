// Package nodeproto is the contract between the control plane (the main
// gateway + admin) and relay nodes: token format, key derivation, viewer URL
// signing, and the JSON documents exchanged over /_sv/node/*.
//
// Tokens are "svn_<nodeID>_<64 hex secret>". The control plane stores
// SHA-256(secret) for authentication and the secret itself encrypted with the
// main key, because it needs the secret to sign viewer URLs for that node and
// to encrypt source credentials sent to it. Separate keys are derived for
// each purpose so one use can't be replayed as another.
package nodeproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

const TokenPrefix = "svn_"

var tokenRe = regexp.MustCompile(`^svn_([1-9][0-9]{0,17})_([0-9a-f]{64})$`)

// ParseToken splits a node token; ok is false for anything malformed.
func ParseToken(token string) (id int64, secret string, ok bool) {
	m := tokenRe.FindStringSubmatch(token)
	if m == nil {
		return 0, "", false
	}
	id, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return id, m[2], true
}

// SecretHash is what the control plane stores to authenticate a node.
func SecretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashMatches compares in constant time.
func HashMatches(secret, storedHash string) bool {
	got := SecretHash(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

func derive(purpose, secret string) []byte {
	sum := sha256.Sum256([]byte("streamvault-node/" + purpose + "\x00" + secret))
	return sum[:]
}

// ConfigKey encrypts source credentials in the node config (secretbox).
func ConfigKey(secret string) []byte { return derive("config", secret) }

func signMessage(streamID, accessPointID, tokenID, exp int64) []byte {
	return []byte(fmt.Sprintf("v1|%d|%d|%d|%d", streamID, accessPointID, tokenID, exp))
}

// Sign produces the viewer URL signature for one stream/access point/token
// until exp (unix seconds). tokenID is 0 for public access points.
func Sign(secret string, streamID, accessPointID, tokenID, exp int64) string {
	mac := hmac.New(sha256.New, derive("sign", secret))
	mac.Write(signMessage(streamID, accessPointID, tokenID, exp))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a viewer URL signature in constant time (expiry is the
// caller's job, against its own clock).
func Verify(secret string, streamID, accessPointID, tokenID, exp int64, sig string) bool {
	want := Sign(secret, streamID, accessPointID, tokenID, exp)
	return hmac.Equal([]byte(want), []byte(sig))
}

// ViewerHeader carries a hashed viewer IP from the control gateway to the
// node, so a node behind the control plane can still count distinct viewers.
const ViewerHeader = "X-SV-Viewer"

// ViewerID hashes an IP for ViewerHeader (never the raw address).
func ViewerID(ip string) string {
	sum := sha256.Sum256([]byte("streamvault-viewer\x00" + ip))
	return hex.EncodeToString(sum[:8])
}

// StreamConfig is one stream the node must relay. SourcePasswordEnc is
// encrypted with ConfigKey(secret), never sent in plaintext.
type StreamConfig struct {
	ID                int64  `json:"id"`
	SourceType        string `json:"source_type"`
	SourceURL         string `json:"source_url"`
	SourceUsername    string `json:"source_username,omitempty"`
	SourcePasswordEnc string `json:"source_password_enc,omitempty"`
	// TrustPrivateSource: the source may be on a private network (admin-owned
	// streams); otherwise the node dials it public-only, like the control.
	TrustPrivateSource bool `json:"trust_private_source"`
}

// Config is GET /_sv/node/config. Revocations cover access points and
// tokens of the node's streams, so a revoked link stops on the node within
// one poll even though its signed URL has not expired yet.
type Config struct {
	NodeID              int64          `json:"node_id"`
	ServerTime          int64          `json:"server_time"`
	PollSeconds         int            `json:"poll_seconds"`
	Streams             []StreamConfig `json:"streams"`
	RevokedAccessPoints []int64        `json:"revoked_access_points"`
	RevokedTokens       []int64        `json:"revoked_tokens"`
}

// StreamStatus is one relay's state as the node sees it.
type StreamStatus struct {
	ID      int64  `json:"id"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
	Viewers int    `json:"viewers"`
}

// Status is POST /_sv/node/status.
type Status struct {
	Version        string         `json:"version"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
	Load1          float64        `json:"load1"`
	CPUs           int            `json:"cpus"`
	MemTotalKB     int64          `json:"mem_total_kb"`
	MemAvailableKB int64          `json:"mem_available_kb"`
	NetRxBytes     int64          `json:"net_rx_bytes"`
	NetTxBytes     int64          `json:"net_tx_bytes"`
	Streams        []StreamStatus `json:"streams"`
}
