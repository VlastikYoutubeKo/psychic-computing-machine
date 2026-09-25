package leakcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// TokenInfo is the subset of an access_token row the matcher needs to
// tell a currently-dangerous leak from a historical, already-revoked one.
type TokenInfo struct {
	ID      int64
	Hash    string // sha256 hex, as stored in access_tokens.token_hash
	Revoked bool
	Expired bool
}

// AccessPointInfo is the subset of a stream+access_point the matcher
// checks candidate matches against.
type AccessPointInfo struct {
	ID           int64
	StreamID     int64
	PublicPath   string
	Visibility   string // public|private
	PathIsSecret bool
	Tokens       []TokenInfo // empty for public access points
}

// Anchor is the exact string searched for: base_url + "/" + public_path,
// with no trailing token. It's safe to send to a third-party search API
// because public_path itself is not a secret (unless PathIsSecret, in
// which case it IS the secret -- but a search query isn't publication;
// GitHub already indexes whatever's publicly out there regardless of
// whether we ever search for it).
func (ap AccessPointInfo) Anchor(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/" + ap.PublicPath
}

// candidateTokenAfter finds a 48-hex-char token (matching
// sv_generate_raw_token's bin2hex(random_bytes(24))) immediately following
// anchor in text, e.g. ".../live/nova/3f9a...c1<48 hex chars>.m3u8".
func candidateTokenAfter(anchor, text string) string {
	pattern := regexp.QuoteMeta(anchor) + `/([0-9a-fA-F]{48})`
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

type Confidence string

const (
	Mention   Confidence = "mention"
	Probable  Confidence = "probable"
	Confirmed Confidence = "confirmed"
)

type Match struct {
	Confidence    Confidence
	AccessPointID int64
	StreamID      int64
	TokenID       *int64 // set only when a specific token was identified
	MatchedValue  string // what actually gets stored -- the anchor, or anchor+token if found
}

// Classify inspects text (a code fragment or issue body) for evidence of
// ap having leaked, per the algorithm in ARCHITECTURE.md "Leak Checker":
// find the anchor; if a trailing token-shaped string follows it, hash that
// candidate and compare against ap's known token hashes rather than ever
// needing the raw token on file. Returns nil if the anchor isn't present
// at all.
func Classify(ap AccessPointInfo, baseURL, text string) *Match {
	anchor := ap.Anchor(baseURL)
	if !strings.Contains(text, anchor) {
		return nil
	}

	if ap.Visibility != "private" {
		if ap.PathIsSecret {
			return &Match{Confidence: Confirmed, AccessPointID: ap.ID, StreamID: ap.StreamID, MatchedValue: anchor}
		}
		return &Match{Confidence: Mention, AccessPointID: ap.ID, StreamID: ap.StreamID, MatchedValue: anchor}
	}

	candidate := candidateTokenAfter(anchor, text)
	if candidate == "" {
		// A private stream's bare public_path with no token attached isn't
		// itself actionable -- it needs the token to actually work -- but
		// it's still worth a low-confidence record: someone may be about
		// to post the full link, or already has it elsewhere.
		return &Match{Confidence: Mention, AccessPointID: ap.ID, StreamID: ap.StreamID, MatchedValue: anchor}
	}

	sum := sha256.Sum256([]byte(candidate))
	candidateHash := hex.EncodeToString(sum[:])
	// The matched_value gets persisted to leak_findings, so it must never
	// contain the raw candidate token: that would be storing a working
	// bearer credential in plaintext, exactly what hashing access_tokens
	// in the first place was meant to prevent. A short hash prefix is
	// enough for a human to visually correlate repeat sightings without
	// the row itself becoming a usable secret. Caught in review before
	// this ever ran against a real scan.
	redacted := anchor + "/<redacted token, hash " + candidateHash[:12] + ">"
	for _, tok := range ap.Tokens {
		if tok.Hash != candidateHash {
			continue
		}
		id := tok.ID
		// A revoked/expired token showing up publicly isn't urgent (it
		// already doesn't work), but it IS confirmed evidence that this
		// exact link was shared at some point -- useful history, not a
		// live emergency, so it's still Confirmed severity-of-evidence,
		// just no action is warranted. The admin UI's incident status
		// (Phase 7) is where "already handled" gets reflected, not here.
		return &Match{Confidence: Confirmed, AccessPointID: ap.ID, StreamID: ap.StreamID, TokenID: &id, MatchedValue: redacted}
	}
	// Pattern matches (anchor + a 48-hex-char string) but it's not a hash
	// we recognize: could be a typo'd/garbled repost, a coincidence, or a
	// token issued and then deleted outright rather than revoked. Not
	// nothing, but not proven either.
	return &Match{Confidence: Probable, AccessPointID: ap.ID, StreamID: ap.StreamID, MatchedValue: redacted}
}

// DedupeKey identifies "the same finding" across scans so re-running the
// checker doesn't create duplicate leak_findings/incidents rows for
// content that hasn't changed (spec: don't let one leak spam duplicates).
func DedupeKey(source, sourceURL, matchedValue string) string {
	sum := sha256.Sum256([]byte(source + "|" + sourceURL + "|" + matchedValue))
	return hex.EncodeToString(sum[:])
}
