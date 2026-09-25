package blobcodec

import "testing"

func TestRoundTrip(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const url = "https://source.internal/memfs/abc123/segment_003.ts?token=leak-if-visible"
	blob, err := c.Encode(url, "ap-1")
	if err != nil {
		t.Fatal(err)
	}
	if blob == url {
		t.Fatal("blob must not equal the plaintext URL")
	}
	decoded, err := c.Decode(blob, "ap-1")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded != url {
		t.Fatalf("round trip mismatch: got %q want %q", decoded, url)
	}
}

// This is the regression test for the finding that a base64-only encoding
// is reversible by anyone holding the link: it must be computationally
// infeasible to recover the URL, or even confirm a guess, without the
// in-memory key.
func TestBlobIsNotSelfDecodable(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	blob, err := c.Encode("https://source.internal/secret/path.ts", "ap-1")
	if err != nil {
		t.Fatal(err)
	}

	// A different codec instance (i.e. a different key, as any external
	// party necessarily has) must not be able to decode it.
	other, _ := New()
	if _, err := other.Decode(blob, "ap-1"); err == nil {
		t.Fatal("decoding under a different key must fail")
	}
}

func TestDecodeRejectsTamperedBlob(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	blob, err := c.Encode("https://source.internal/a.ts", "ap-1")
	if err != nil {
		t.Fatal(err)
	}
	tampered := blob[:len(blob)-2] + "AA" // flip the last couple of characters
	if _, err := c.Decode(tampered, "ap-1"); err == nil {
		t.Fatal("expected tampered blob to fail authentication")
	}
}

func TestDecodeRejectsHandCraftedBlob(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Someone who knows the wire format (base64url) but not the key
	// tries to forge a blob pointing at an arbitrary URL, the way the
	// old base64-only scheme would have allowed trivially.
	if _, err := c.Decode("aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8", "ap-1"); err == nil {
		t.Fatal("expected a hand-crafted, non-encrypted blob to be rejected")
	}
}

func TestBlobCannotBeReplayedUnderAnotherAccessPoint(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := c.Encode("https://source.internal/secret/segment.ts", "ap-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decode(blob, "ap-2"); err == nil {
		t.Fatal("blob for another access point must fail authentication")
	}
}
