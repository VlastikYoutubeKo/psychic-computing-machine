package hls

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

// testEncode stands in for the real (encrypted) EncodeFunc so this package's
// tests can check the playlist-rewriting logic in isolation from blobcodec.
// It must still satisfy the same absolute-path contract real callers rely
// on (leading "/") -- see EncodeFunc's doc comment for why that matters.
func testEncode(target *url.URL) (string, error) {
	return fmt.Sprintf("/enc/%s", url.QueryEscape(target.String())), nil
}

func decodeTestEncode(t *testing.T, encoded string) string {
	t.Helper()
	raw := strings.TrimPrefix(encoded, "/enc/")
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		t.Fatalf("QueryUnescape(%q): %v", raw, err)
	}
	return decoded
}

func TestResolve(t *testing.T) {
	base := mustParse(t, "https://source.internal/memfs/abc123/index.m3u8")
	target, err := Resolve("segment_003.ts", base)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if target.String() != "https://source.internal/memfs/abc123/segment_003.ts" {
		t.Fatalf("unexpected resolution: %s", target.String())
	}

	abs, err := Resolve("https://keys.example.com/k/1", base)
	if err != nil {
		t.Fatalf("Resolve absolute: %v", err)
	}
	if abs.String() != "https://keys.example.com/k/1" {
		t.Fatalf("absolute URI should be returned unchanged, got %s", abs.String())
	}
}

func TestRewritePlaylistProducesAbsolutePathReferences(t *testing.T) {
	// Regression test: an earlier version emitted a bare relative path
	// ("live/nova/r/..." with no leading slash), which a real player
	// resolves against the *manifest's own directory*, silently doubling
	// the path for any manifest not served at the site root. Every
	// rewritten reference must start with "/".
	base := mustParse(t, "https://source.internal/live/index.m3u8")
	src := "#EXTM3U\n#EXTINF:6.0,\nseg1.ts\n"
	out, err := RewritePlaylist(src, base, testEncode)
	if err != nil {
		t.Fatalf("RewritePlaylist: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			t.Fatalf("rewritten reference must be an absolute path (leading '/'), got %q", line)
		}
	}
}

func TestRewritePlaylistMasterVariants(t *testing.T) {
	base := mustParse(t, "https://source.internal/live/master.m3u8")
	src := "#EXTM3U\n" +
		"#EXT-X-VERSION:3\n" +
		"#EXT-X-STREAM-INF:BANDWIDTH=2000000\n" +
		"720p/index.m3u8\n" +
		"#EXT-X-STREAM-INF:BANDWIDTH=800000\n" +
		"480p/index.m3u8\n"

	out, err := RewritePlaylist(src, base, testEncode)
	if err != nil {
		t.Fatalf("RewritePlaylist: %v", err)
	}
	lines := strings.Split(out, "\n")
	if lines[0] != "#EXTM3U" || lines[1] != "#EXT-X-VERSION:3" {
		t.Fatalf("metadata lines must pass through unchanged, got:\n%s", out)
	}
	if decodeTestEncode(t, lines[3]) != "https://source.internal/live/720p/index.m3u8" {
		t.Fatalf("wrong resolved target for first variant: %s", lines[3])
	}
	if decodeTestEncode(t, lines[5]) != "https://source.internal/live/480p/index.m3u8" {
		t.Fatalf("wrong resolved target for second variant: %s", lines[5])
	}
}

func TestRewritePlaylistMediaSegmentsKeysAndInit(t *testing.T) {
	base := mustParse(t, "https://source.internal/live/720p/index.m3u8")
	src := "#EXTM3U\n" +
		"#EXT-X-KEY:METHOD=AES-128,URI=\"enc.key\",IV=0x1\n" +
		"#EXT-X-MAP:URI=\"init.mp4\"\n" +
		"#EXTINF:6.0,\n" +
		"seg1.ts\n" +
		"#EXTINF:6.0,\n" +
		"seg2.ts\n" +
		"#EXT-X-ENDLIST\n"

	out, err := RewritePlaylist(src, base, testEncode)
	if err != nil {
		t.Fatalf("RewritePlaylist: %v", err)
	}
	if !strings.Contains(out, `#EXT-X-KEY:METHOD=AES-128,URI="/enc/`) {
		t.Fatalf("EXT-X-KEY URI not rewritten:\n%s", out)
	}
	if !strings.Contains(out, `#EXT-X-MAP:URI="/enc/`) {
		t.Fatalf("EXT-X-MAP URI not rewritten:\n%s", out)
	}
	// testEncode is deliberately reversible (so decodeTestEncode can check
	// *what* was resolved) -- it is not a secrecy test double. What this
	// layer must guarantee is that no line was left completely unrewritten
	// (a literal "seg1.ts"/"seg2.ts" line slipping through the switch in
	// RewritePlaylist). Actual non-leakage of the source URL through the
	// real (encrypted) encoder is covered in gatewayhttp's handler tests
	// and blobcodec's own tests -- that's a property of blobcodec, not of
	// this playlist-rewriting logic.
	for _, line := range strings.Split(out, "\n") {
		if line == "seg1.ts" || line == "seg2.ts" {
			t.Fatalf("an unrewritten raw segment line slipped through:\n%s", out)
		}
	}
	if !strings.Contains(out, "#EXT-X-ENDLIST") {
		t.Fatalf("unrelated tag was dropped:\n%s", out)
	}
}

func TestIsPlaylist(t *testing.T) {
	if !IsPlaylist([]byte("#EXTM3U\n#EXT-X-VERSION:3\n")) {
		t.Fatal("expected true for a manifest")
	}
	if IsPlaylist([]byte{0x00, 0x01, 0x47, 0x40}) { // looks like an MPEG-TS sync byte, not text
		t.Fatal("expected false for binary data")
	}
}
