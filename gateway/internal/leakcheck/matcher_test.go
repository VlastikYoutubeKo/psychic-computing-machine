package leakcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func hashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestClassifyNoMatch(t *testing.T) {
	ap := AccessPointInfo{ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private"}
	if m := Classify(ap, "https://restream.example.com", "nothing relevant here"); m != nil {
		t.Fatalf("expected no match, got %+v", m)
	}
}

func TestClassifyPublicMention(t *testing.T) {
	ap := AccessPointInfo{ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "public"}
	text := "check out https://restream.example.com/live/nova it's great"
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Mention {
		t.Fatalf("expected Mention, got %+v", m)
	}
}

func TestClassifyPublicPathIsSecretConfirmed(t *testing.T) {
	// The "random path IS the secret" pattern from spec section 1: a
	// public access point whose path itself must stay unguessable.
	ap := AccessPointInfo{ID: 1, StreamID: 1, PublicPath: "nova/6f8e1b3c9a72d4e0", Visibility: "public", PathIsSecret: true}
	text := "m3u: https://restream.example.com/nova/6f8e1b3c9a72d4e0.m3u8"
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Confirmed {
		t.Fatalf("expected Confirmed for a leaked secret path, got %+v", m)
	}
}

func TestClassifyPrivateBarePathIsOnlyMention(t *testing.T) {
	ap := AccessPointInfo{ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private"}
	text := "someone mentioned https://restream.example.com/live/nova without a token"
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Mention {
		t.Fatalf("expected Mention (no working link without a token), got %+v", m)
	}
}

func TestClassifyPrivateActiveTokenIsConfirmed(t *testing.T) {
	raw := strings.Repeat("a", 48) // 48 hex-shaped chars, matches sv_generate_raw_token's length
	ap := AccessPointInfo{
		ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private",
		Tokens: []TokenInfo{{ID: 42, Hash: hashOf(raw), Revoked: false}},
	}
	text := "leaked: https://restream.example.com/live/nova/" + raw + ".m3u8"
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Confirmed {
		t.Fatalf("expected Confirmed for an active token match, got %+v", m)
	}
	if m.TokenID == nil || *m.TokenID != 42 {
		t.Fatalf("expected TokenID 42, got %+v", m.TokenID)
	}
}

func TestClassifyPrivateUnknownTokenIsProbable(t *testing.T) {
	raw := strings.Repeat("b", 48)
	ap := AccessPointInfo{ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private"} // no tokens known
	text := "https://restream.example.com/live/nova/" + raw
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Probable {
		t.Fatalf("expected Probable for an unrecognized token-shaped match, got %+v", m)
	}
}

func TestClassifyRevokedTokenStillConfirmedEvidence(t *testing.T) {
	raw := strings.Repeat("c", 48)
	ap := AccessPointInfo{
		ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private",
		Tokens: []TokenInfo{{ID: 7, Hash: hashOf(raw), Revoked: true}},
	}
	text := "old link: https://restream.example.com/live/nova/" + raw
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil || m.Confidence != Confirmed || m.TokenID == nil || *m.TokenID != 7 {
		t.Fatalf("expected Confirmed evidence tied to token 7, got %+v", m)
	}
}

// Regression test: matched_value is persisted to leak_findings (see
// store.go RecordMatch), so it must never contain a working raw token --
// caught in review before the first real scan ran.
func TestClassifyNeverStoresRawTokenInMatchedValue(t *testing.T) {
	raw := strings.Repeat("d", 48)
	ap := AccessPointInfo{
		ID: 1, StreamID: 1, PublicPath: "live/nova", Visibility: "private",
		Tokens: []TokenInfo{{ID: 1, Hash: hashOf(raw), Revoked: false}},
	}
	text := "https://restream.example.com/live/nova/" + raw
	m := Classify(ap, "https://restream.example.com", text)
	if m == nil {
		t.Fatal("expected a match")
	}
	if strings.Contains(m.MatchedValue, raw) {
		t.Fatalf("MatchedValue must never contain the raw token, got %q", m.MatchedValue)
	}
}

func TestDedupeKeyStableAndDistinct(t *testing.T) {
	a := DedupeKey("github", "https://github.com/x/y/blob/main/f", "https://restream.example.com/live/nova")
	b := DedupeKey("github", "https://github.com/x/y/blob/main/f", "https://restream.example.com/live/nova")
	if a != b {
		t.Fatal("dedupe key must be stable for identical inputs")
	}
	c := DedupeKey("github", "https://github.com/x/y/blob/main/other", "https://restream.example.com/live/nova")
	if a == c {
		t.Fatal("dedupe key must differ for a different source URL")
	}
}
