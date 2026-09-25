// Package hls rewrites HLS playlists so that every resource a player would
// otherwise fetch directly from the source (variant playlists, segments,
// init/map segments, encryption keys, alternate audio/subtitle renditions)
// is instead routed back through the StreamVault gateway. The source URL
// never appears in anything sent to the client.
//
// This package only resolves relative/absolute URI references to absolute
// source URLs and rewrites the playlist text; it deliberately knows nothing
// about how those URLs are encoded into a client-facing link -- that's the
// caller's `encode` callback (see gatewayhttp), currently an authenticated
// encryption envelope (blobcodec) so the source URL isn't just reversibly
// encoded in a link a recipient could decode themselves.
package hls

import (
	"net/url"
	"regexp"
	"strings"
)

// uriAttr matches URI="..." attributes found on tag lines such as
// #EXT-X-KEY, #EXT-X-MAP, #EXT-X-MEDIA, #EXT-X-I-FRAME-STREAM-INF.
var uriAttr = regexp.MustCompile(`URI="([^"]*)"`)

// IsPlaylist reports whether body looks like an HLS playlist. Content-Type
// from origins is often wrong or missing (plain "text/plain", or absent for
// some Tvheadend profiles), so sniff the actual bytes.
func IsPlaylist(body []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(trimBOM(body))), "#EXTM3U")
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// Resolve resolves rawURI (relative or absolute) against base to an
// absolute URL, per standard RFC 3986 reference resolution.
func Resolve(rawURI string, base *url.URL) (*url.URL, error) {
	ref, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	return base.ResolveReference(ref), nil
}

// EncodeFunc turns a resolved absolute source URL into the exact string the
// client should see in its place (an opaque, authenticated-encrypted
// gateway path). Implementations must return an absolute-path reference
// (leading "/"): a bare relative path here would be resolved by the player
// against the *manifest's own* directory, which silently double-nests the
// path for any manifest not served from the site root (see CHANGELOG.md --
// this bit a first version of this rewriter).
type EncodeFunc func(target *url.URL) (string, error)

// RewritePlaylist rewrites every URI reference in an HLS playlist (master or
// media) using encode. manifestURL is the absolute URL the playlist was
// fetched from, used to resolve relative references.
func RewritePlaylist(text string, manifestURL *url.URL, encode EncodeFunc) (string, error) {
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))

	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		switch {
		case trimmed == "":
			out[i] = trimmed

		case strings.HasPrefix(trimmed, "#"):
			// Tag line: only tags carrying a URI="..." attribute (EXT-X-KEY,
			// EXT-X-MAP, EXT-X-MEDIA, EXT-X-I-FRAME-STREAM-INF, ...) reference
			// a resource; everything else (EXTINF, EXT-X-STREAM-INF itself,
			// version/target-duration tags, ...) is metadata and passes through.
			rewritten, err := rewriteTagAttrs(trimmed, manifestURL, encode)
			if err != nil {
				return "", err
			}
			out[i] = rewritten

		default:
			// Any non-empty, non-# line in an HLS playlist is itself a URI:
			// a variant playlist (after EXT-X-STREAM-INF) or a media segment
			// (after EXTINF).
			target, err := Resolve(trimmed, manifestURL)
			if err != nil {
				return "", err
			}
			proxied, err := encode(target)
			if err != nil {
				return "", err
			}
			out[i] = proxied
		}
	}
	return strings.Join(out, "\n"), nil
}

func rewriteTagAttrs(line string, base *url.URL, encode EncodeFunc) (string, error) {
	var outerErr error
	result := uriAttr.ReplaceAllStringFunc(line, func(match string) string {
		sub := uriAttr.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		target, err := Resolve(sub[1], base)
		if err != nil {
			outerErr = err
			return match
		}
		proxied, err := encode(target)
		if err != nil {
			outerErr = err
			return match
		}
		return `URI="` + proxied + `"`
	})
	if outerErr != nil {
		return "", outerErr
	}
	return result, nil
}
