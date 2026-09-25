// Package gatewayhttp is the public HTTP surface of the StreamVault stream
// gateway: it resolves a request path to an access_point, enforces token
// validity on every request (not just the top-level manifest -- see
// SECURITY.md "segment-level revocation"), and proxies to the source
// without ever exposing the source URL, credentials, or a private token to
// the wrong recipient.
package gatewayhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"streamvault/gateway/internal/blobcodec"
	"streamvault/gateway/internal/hls"
	"streamvault/gateway/internal/remux"
	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

type Handler struct {
	Store     *store.Store
	Key       []byte // may be nil if no source ever needs credentials
	Codec     *blobcodec.Codec
	Transport *http.Transport
	Remux     *remux.Manager

	// Resolve backs checkFetchTarget's private/public IP classification.
	// Defaults to real DNS (hostResolvesToPrivate); tests override it,
	// since every httptest server binds to 127.0.0.1 -- itself a private
	// address -- which would otherwise make every test's "source" look
	// private and silently disable the check being tested.
	Resolve resolveFunc

	touchMu   sync.Mutex
	lastTouch map[int64]time.Time

	// sourceTrustCache avoids a DNS lookup on every single segment request
	// (checkFetchTarget's decision only changes when a stream's source_url
	// itself is edited, which is rare) -- see isSourcePrivate.
	sourceTrustMu    sync.Mutex
	sourceTrustCache map[int64]sourceTrustEntry
}

type sourceTrustEntry struct {
	private   bool
	checkedAt time.Time
}

const sourceTrustCacheTTL = 5 * time.Minute

func New(st *store.Store, key []byte) (*Handler, error) {
	codec, err := blobcodec.New()
	if err != nil {
		return nil, fmt.Errorf("gatewayhttp: initializing blob codec: %w", err)
	}
	return &Handler{
		Store: st,
		Key:   key,
		Codec: codec,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       60 * time.Second,
		},
		Remux:            remux.NewManager(),
		Resolve:          hostResolvesToPrivate,
		lastTouch:        make(map[int64]time.Time),
		sourceTrustCache: make(map[int64]sourceTrustEntry),
	}, nil
}

// isSourcePrivate reports whether stream s's own configured source_url is
// itself on a private/reserved address, cached briefly per stream so this
// doesn't cost a DNS lookup on every segment request -- see
// checkFetchTarget's doc comment for what this decision gates.
func (h *Handler) isSourcePrivate(ctx context.Context, s store.Stream, sourceEntry *url.URL) bool {
	h.sourceTrustMu.Lock()
	if e, ok := h.sourceTrustCache[s.ID]; ok && time.Since(e.checkedAt) < sourceTrustCacheTTL {
		h.sourceTrustMu.Unlock()
		return e.private
	}
	h.sourceTrustMu.Unlock()

	private, err := h.Resolve(ctx, sourceEntry.Hostname())
	if err != nil {
		private = false // unresolvable source: fail to the stricter (public-only) policy, never the more permissive one
	}

	h.sourceTrustMu.Lock()
	h.sourceTrustCache[s.ID] = sourceTrustEntry{private: private, checkedAt: time.Now()}
	h.sourceTrustMu.Unlock()
	return private
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqPath := strings.TrimPrefix(r.URL.Path, "/")

	var prefix, remainder string
	if idx := strings.Index(reqPath, "/r/"); idx >= 0 {
		prefix = reqPath[:idx]
		remainder = reqPath[idx+1:] // "r/<blob>"
	} else {
		prefix = stripKnownExt(reqPath)
		remainder = ""
	}

	ap, tokenRaw, err := h.resolvePrefix(prefix)
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("resolving access point failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if ap.Stream.Status == "disabled" || ap.Status == "revoked" {
		h.writeReplacement(w, ap.Stream)
		return
	}

	if ap.Visibility == "private" {
		info, err := h.Store.ValidateToken(ap.ID, tokenRaw)
		if err != nil {
			log.Printf("ValidateToken: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		switch info.Status {
		case store.TokenInvalid:
			http.NotFound(w, r) // never reveal whether the path itself is real
			return
		case store.TokenRevoked, store.TokenExpired:
			h.writeReplacement(w, ap.Stream)
			return
		}
		h.touchTokenThrottled(info.ID)
	}

	sourceEntry, err := url.Parse(ap.Stream.SourceURL)
	if err != nil {
		log.Printf("stream %d has unparsable source_url", ap.Stream.ID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if remainder == "" {
		h.serveEntry(w, r, ap, sourceEntry, prefix)
		return
	}

	blob := strings.TrimPrefix(remainder, "r/")
	// The trailing extension (if any) is cosmetic only (see encodeRef) and
	// can be anything (.ts, .key, .mp4, ...). base64url never contains '.',
	// so any dot here is unambiguously that separator, not part of the blob.
	if i := strings.LastIndexByte(blob, '.'); i != -1 {
		blob = blob[:i]
	}
	targetRaw, err := h.Codec.Decode(blob, strconv.FormatInt(ap.ID, 10))
	if err != nil {
		// Indistinguishable, deliberately, from "never existed": a forged
		// or tampered blob gets the same response as garbage input.
		http.NotFound(w, r)
		return
	}
	target, err := url.Parse(targetRaw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if target.Scheme == "sv-remux" {
		h.serveRemuxResource(w, r, ap, target)
		return
	}
	// The blob is authenticated (blobcodec) and bound to this access point,
	// so this is about SSRF, not about the blob being forged -- see
	// checkFetchTarget's doc comment for the actual policy and why a
	// simple "must match the source's own host" rule broke real streams.
	if err := checkFetchTarget(r.Context(), h.Resolve, target, h.isSourcePrivate(r.Context(), ap.Stream, sourceEntry)); err != nil {
		log.Printf("blocked resource fetch for stream %d: %v", ap.Stream.ID, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h.serveResource(w, r, ap, sourceEntry, target, prefix)
}

// resolvePrefix implements the routing convention described in
// ARCHITECTURE.md: a bare public_path is a public access point; a
// public_path with one extra trailing segment is a private access point
// plus its bearer token.
func (h *Handler) resolvePrefix(prefix string) (*store.AccessPoint, string, error) {
	if ap, err := h.Store.ResolveAccessPoint(prefix); err == nil {
		if ap.Visibility == "public" {
			return ap, "", nil
		}
		// A private access point matched with no token segment: treat as
		// not found rather than distinguishing "exists but needs a token".
	} else if err != store.ErrNotFound {
		return nil, "", err
	}

	idx := strings.LastIndexByte(prefix, '/')
	if idx <= 0 || idx == len(prefix)-1 {
		return nil, "", store.ErrNotFound
	}
	base, token := prefix[:idx], prefix[idx+1:]

	ap, err := h.Store.ResolveAccessPoint(base)
	if err != nil {
		return nil, "", err
	}
	if ap.Visibility != "private" {
		return nil, "", store.ErrNotFound
	}
	return ap, token, nil
}

// encodeRef builds the EncodeFunc passed to hls.RewritePlaylist for one
// request: every resolved target URL becomes an authenticated-encrypted
// blob under the same prefix (public_path[/token]) that already proved
// valid for this request, so following it re-validates from scratch.
func (h *Handler) encodeRef(prefix string, accessPointID int64) hls.EncodeFunc {
	return func(target *url.URL) (string, error) {
		blob, err := h.Codec.Encode(target.String(), strconv.FormatInt(accessPointID, 10))
		if err != nil {
			return "", err
		}
		ext := path.Ext(target.Path)
		if len(ext) > 8 { // guard against pathological "extensions" from query-heavy URLs
			ext = ""
		}
		return "/" + prefix + "/r/" + blob + ext, nil
	}
}

func sourceSignature(s store.Stream) string {
	sum := sha256.Sum256([]byte(s.SourceURL + "\x00" + s.SourceUsername.String + "\x00" + s.SourcePasswordEnc.String))
	return hex.EncodeToString(sum[:])
}

// The entry fetch deliberately does not use r.Context() or a finite
// timeout, even though a plain HLS manifest fetch would only need a few
// seconds: we don't know until *after* sniffing the response whether this
// is HLS (in which case the fetch is done in milliseconds regardless) or
// MPEG-TS (in which case this exact response body gets handed to a
// long-running remux session that can legitimately keep reading from it
// for hours). An earlier version used a fresh, separate fetch for that
// handoff instead of reusing this one -- which meant every MPEG-TS
// stream's *first* request to its entry point cost two nearly back-to-back
// requests to the source. That's exactly the pattern that got this
// project's own first real production stream rate-limited by its origin
// (see CHANGELOG.md): many single-use-redirect CDN sources penalize or
// simply can't service a second immediate hit. Reusing the sniffed
// response instead of re-fetching removes the double hit entirely.
//
// Accepted trade-off: with no deadline on the body-read phase, a
// source that responds but then drips bytes arbitrarily slowly could tie
// up this request indefinitely. The source is admin-configured, not
// attacker-supplied input -- the same trust boundary this project already
// leans on elsewhere (see SECURITY.md) -- so this is judged an acceptable
// risk rather than one worth a bespoke read-deadline mechanism right now.
func (h *Handler) serveEntry(w http.ResponseWriter, r *http.Request, ap *store.AccessPoint, sourceEntry *url.URL, prefix string) {
	if s := h.Remux.Existing(ap.Stream.ID, sourceSignature(ap.Stream)); s != nil {
		h.writeRemuxPlaylist(w, ap, s, prefix)
		return
	}
	sourcePrivate := h.isSourcePrivate(r.Context(), ap.Stream, sourceEntry)
	resp, err := h.fetch(context.Background(), sourceEntry, ap.Stream, sourcePrivate, 0)
	if err != nil {
		log.Printf("fetching source for stream %d failed", ap.Stream.ID)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	if !h.sniffAndServe(w, resp, resp.Request.URL, prefix, ap, true) {
		resp.Body.Close()
	}
	// else: ownership of resp.Body was transferred to a remux session
	// (see sniffAndServe/serveRemuxEntry) -- it will be closed when that
	// session ends, not here.
}

func (h *Handler) serveResource(w http.ResponseWriter, r *http.Request, ap *store.AccessPoint, sourceEntry, target *url.URL, prefix string) {
	sourcePrivate := h.isSourcePrivate(r.Context(), ap.Stream, sourceEntry)
	resp, err := h.fetch(r.Context(), target, ap.Stream, sourcePrivate, 20*time.Second)
	if err != nil {
		log.Printf("fetching resource for stream %d failed", ap.Stream.ID)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	h.sniffAndServe(w, resp, resp.Request.URL, prefix, ap, false)
}

// fetch builds a per-call client so CheckRedirect can enforce
// checkFetchTarget on every hop, not just the initial request. A shared
// *http.Transport underneath still gives connection reuse; only the thin
// http.Client wrapper (and its redirect policy) is per-request. Without
// this, the default client follows redirects with no re-check at all, so
// a source that starts (or is tricked into) redirecting could walk the
// gateway anywhere -- caught in security review before this ever reached
// production, then found to be *too* strict against a real source in this
// project's first live end-to-end test (see checkFetchTarget). See
// SECURITY.md.
func (h *Handler) fetch(ctx context.Context, target *url.URL, s store.Stream, sourcePrivate bool, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout:   timeout,
		Transport: h.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			if err := checkFetchTarget(req.Context(), h.Resolve, req.URL, sourcePrivate); err != nil {
				return fmt.Errorf("refusing to follow redirect: %w", err)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if s.SourceUsername.Valid && s.SourcePasswordEnc.Valid {
		if h.Key == nil {
			return nil, fmt.Errorf("stream %d requires source credentials but no encryption key is loaded", s.ID)
		}
		pw, err := secretbox.Decrypt(h.Key, s.SourcePasswordEnc.String)
		if err != nil {
			return nil, fmt.Errorf("decrypting source credentials: %w", err)
		}
		req.SetBasicAuth(s.SourceUsername.String, string(pw))
	}
	return client.Do(req)
}

const (
	sniffLimit      = 1024            // enough for three TS packet sync bytes; avoids waiting for a 64 KiB live prefix
	maxPlaylistSize = 4 * 1024 * 1024 // generous headroom for even a huge master playlist; this host runs low on RAM
)

// sniffAndServe returns true if it transferred ownership of resp.Body to a
// background remux session (the caller must then not close it) -- see
// serveEntry's doc comment for why the response is reused rather than
// re-fetched.
func (h *Handler) sniffAndServe(w http.ResponseWriter, resp *http.Response, manifestURL *url.URL, prefix string, ap *store.AccessPoint, entry bool) bool {
	head := make([]byte, sniffLimit)
	n, err := io.ReadFull(resp.Body, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		http.Error(w, "upstream read error", http.StatusBadGateway)
		return false
	}
	head = head[:n]
	if entry && remux.LooksLikeMPEGTS(head) {
		body := &prefixedReadCloser{prefix: head, r: resp.Body, closer: resp.Body}
		h.serveRemuxEntry(w, ap, body, prefix)
		return true
	}

	if hls.IsPlaylist(head) {
		// Bounded read: an oversized or malicious "playlist" must not be
		// buffered without limit on a host this memory-constrained.
		rest, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxPlaylistSize-len(head)+1)))
		if err != nil {
			http.Error(w, "upstream read error", http.StatusBadGateway)
			return false
		}
		full := append(head, rest...)
		if len(full) > maxPlaylistSize {
			log.Printf("rejecting oversized playlist for access point %d (> %d bytes)", ap.ID, maxPlaylistSize)
			http.Error(w, "upstream playlist too large", http.StatusBadGateway)
			return false
		}
		rewritten, err := hls.RewritePlaylist(string(full), manifestURL, h.encodeRef(prefix, ap.ID))
		if err != nil {
			log.Printf("rewriting playlist for access point %d: %v", ap.ID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return false
		}
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(rewritten))
		return false
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(head)
	_, _ = io.Copy(w, resp.Body) // streamed, never buffered: segments can be large
	return false
}

// prefixedReadCloser re-serves bytes already consumed from a reader (via
// an earlier Read, e.g. for format sniffing) before continuing to read
// from it directly, then closes closer when the caller is done. Lets
// sniffAndServe hand a partially-read HTTP response body to a remux
// session without losing the bytes already consumed for detection.
type prefixedReadCloser struct {
	prefix []byte
	off    int
	r      io.Reader
	closer io.Closer
}

func (p *prefixedReadCloser) Read(buf []byte) (int, error) {
	if p.off < len(p.prefix) {
		n := copy(buf, p.prefix[p.off:])
		p.off += n
		return n, nil
	}
	return p.r.Read(buf)
}

func (p *prefixedReadCloser) Close() error {
	return p.closer.Close()
}

// serveRemuxEntry starts (or, if body ends up unused because a concurrent
// request already started one, discards) a remux session fed by body --
// the same response serveEntry already fetched and sniffed, its ownership
// now transferred here. See serveEntry's doc comment for why this reuses
// that response instead of fetching a fresh one: a second immediate
// request to the same entry point is exactly what got this project's own
// first real production stream rate-limited by its origin.
func (h *Handler) serveRemuxEntry(w http.ResponseWriter, ap *store.AccessPoint, body io.ReadCloser, prefix string) {
	sig := sourceSignature(ap.Stream)
	used := false
	s, err := h.Remux.Start(ap.Stream.ID, sig, func(ctx context.Context) (io.ReadCloser, error) {
		used = true
		return body, nil
	})
	if !used {
		// A concurrent request already has (or just started) a session
		// for this stream+signature; remux.Manager reused it without
		// calling our callback. This response's body was never handed
		// off, so it's ours to close -- nothing else will.
		body.Close()
	}
	if err != nil {
		log.Printf("starting TS remux for stream %d failed: %v", ap.Stream.ID, err)
		http.Error(w, "remux unavailable", http.StatusBadGateway)
		return
	}
	h.writeRemuxPlaylist(w, ap, s, prefix)
}

func (h *Handler) writeRemuxPlaylist(w http.ResponseWriter, ap *store.AccessPoint, s *remux.Session, prefix string) {
	p, err := h.Remux.WaitPlaylist(s)
	if err != nil {
		log.Printf("remux playlist for stream %d: %v", ap.Stream.ID, err)
		http.Error(w, "remux unavailable", http.StatusBadGateway)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) > maxPlaylistSize {
		http.Error(w, "remux playlist unavailable", http.StatusBadGateway)
		return
	}
	base := &url.URL{Scheme: "sv-remux", Host: s.ID, Path: "/index.m3u8"}
	rewritten, err := hls.RewritePlaylist(string(data), base, h.encodeRef(prefix, ap.ID))
	if err != nil {
		http.Error(w, "remux playlist invalid", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, rewritten)
}

func (h *Handler) serveRemuxResource(w http.ResponseWriter, r *http.Request, ap *store.AccessPoint, target *url.URL) {
	if target.RawQuery != "" || target.User != nil || target.Fragment != "" {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(target.Path, "/")
	if name == "index.m3u8" { // only entry route exposes a rewritten manifest
		http.NotFound(w, r)
		return
	}
	p, ok := h.Remux.GetPath(ap.Stream.ID, target.Host, name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func (h *Handler) touchTokenThrottled(tokenID int64) {
	h.touchMu.Lock()
	last, seen := h.lastTouch[tokenID]
	shouldTouch := !seen || time.Since(last) > 60*time.Second
	if shouldTouch {
		h.lastTouch[tokenID] = time.Now()
	}
	h.touchMu.Unlock()
	if shouldTouch {
		h.Store.TouchToken(tokenID)
	}
}

func stripKnownExt(p string) string {
	for _, ext := range []string{".m3u8", ".ts"} {
		if strings.HasSuffix(p, ext) {
			return strings.TrimSuffix(p, ext)
		}
	}
	return p
}

var replacementReasons = map[string]string{
	"limited_bandwidth":               "Limited bandwidth.",
	"not_intended_for_public":         "This stream was not intended for public distribution.",
	"unauthorized_redistribution":     "Unauthorized public distribution.",
	"access_revoked_by_owner":         "Access revoked by the stream owner.",
	"stream_permanently_discontinued": "Stream permanently discontinued.",
}

func (h *Handler) writeReplacement(w http.ResponseWriter, s store.Stream) {
	reason := replacementReasons[s.ReplacementReason]
	if reason == "" {
		reason = "Unauthorized public distribution."
	}
	if s.ReplacementMessage.Valid && s.ReplacementMessage.String != "" {
		reason = s.ReplacementMessage.String
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusGone)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Stream unavailable</title>
<style>body{font-family:system-ui,sans-serif;background:#0b0d12;color:#e6e8ee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.5rem;margin-bottom:.5rem}p{color:#9aa2b1}</style>
</head><body><div class="card"><h1>Stream unavailable</h1>
<p>This stream is no longer available at this address.</p>
<p><strong>Reason:</strong> %s</p>
<p>The previous access URL has been permanently revoked.</p>
</div></body></html>`, html.EscapeString(reason))
}
