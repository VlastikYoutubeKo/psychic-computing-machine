// Package gatewayhttp is the public HTTP surface of the StreamVault stream
// gateway: it resolves a request path to an access_point, enforces token
// validity on every request (not just the top-level manifest -- see
// SECURITY.md "segment-level revocation"), and proxies to the source
// without ever exposing the source URL, credentials, or a private token to
// the wrong recipient.
package gatewayhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
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
	"streamvault/gateway/internal/slate"
	"streamvault/gateway/internal/store"
)

type Handler struct {
	Store     *store.Store
	Key       []byte // may be nil if no source ever needs credentials
	relayOnly bool   // relay node: every remux slot may hold an always-on relay
	Codec     *blobcodec.Codec
	Transport *http.Transport
	Remux     *remux.Manager
	Slate     slate.Provider
	// Relays overrides where always-on relays come from (nil = Store); set
	// by relay nodes, which have no database.
	Relays RelayStore

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

// NewRelayOnly builds a handler for relay nodes: no database, no slates,
// only the fetch path (SSRF policy, credentials), remux sessions and the
// always-on supervisor fed by relays. key decrypts the source passwords in
// the node config (nodeproto.ConfigKey).
func NewRelayOnly(key []byte, relays RelayStore) *Handler {
	return &Handler{
		Key:              key,
		Transport:        newSourceTransport(),
		Remux:            remux.NewRelayNodeManager(),
		relayOnly:        true,
		Resolve:          hostResolvesToPrivate,
		Relays:           relays,
		lastTouch:        make(map[int64]time.Time),
		sourceTrustCache: make(map[int64]sourceTrustEntry),
	}
}

// publicOnlyKey marks a fetch for a stream whose source is NOT trusted to be
// on a private network (regular accounts). The dialer then refuses to keep a
// connection to a private/reserved address -- checked on the address actually
// connected to, so DNS rebinding between a check and the dial can't bypass it.
type publicOnlyKey struct{}

func publicOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, publicOnlyKey{}, true)
}

func sourceDialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil || ctx.Value(publicOnlyKey{}) == nil {
			return conn, err
		}
		if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || isPrivateOrReserved(tcp.IP) {
			conn.Close()
			return nil, fmt.Errorf("%w: source resolves to a private/reserved address", errBlockedTarget)
		}
		return conn, nil
	}
}

func newSourceTransport() *http.Transport {
	return &http.Transport{
		DialContext:           sourceDialContext(&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
}

func New(st *store.Store, key []byte) (*Handler, error) {
	codec, err := blobcodec.New()
	if err != nil {
		return nil, fmt.Errorf("gatewayhttp: initializing blob codec: %w", err)
	}
	h := &Handler{
		Store:            st,
		Key:              key,
		Codec:            codec,
		Transport:        newSourceTransport(),
		Remux:            remux.NewManager(),
		Slate:            slate.NewManager(),
		Resolve:          hostResolvesToPrivate,
		lastTouch:        make(map[int64]time.Time),
		sourceTrustCache: make(map[int64]sourceTrustEntry),
	}
	h.Slate.(*slate.Manager).ConfigureAudio(func() (slate.AudioSettings, error) {
		file, streamURL, volume, err := st.SlateAudioSettings()
		return slate.AudioSettings{File: file, URL: streamURL, Volume: volume}, err
	}, st.DataDir())
	h.Slate.(*slate.Manager).ConfigureText(func(reason string) (slate.Text, error) {
		title, subtitle, err := st.SlateText(reason)
		return slate.Text{Title: title, Subtitle: subtitle}, err
	})
	return h, nil
}

// isSourcePrivate reports whether stream s's own configured source_url is
// itself on a private/reserved address, cached briefly per stream so this
// doesn't cost a DNS lookup on every segment request -- see
// checkFetchTarget's doc comment for what this decision gates.
func (h *Handler) isSourcePrivate(ctx context.Context, s store.Stream, sourceEntry *url.URL) bool {
	// Only admin-owned (or ownerless) streams may point at private networks:
	// a regular account setting source_url to an internal service must not
	// turn the gateway into a reader of that service.
	if !s.TrustPrivateSource {
		return false
	}
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
	// Node API first: it has its own auth and accepts POST (status).
	if strings.HasPrefix(r.URL.Path, "/_sv/node/") {
		h.serveNodeAPI(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "_sv/notice.png" {
		serveNotice(w, r)
		return
	}
	if reqPath == "_sv" || strings.HasPrefix(reqPath, "_sv/") {
		h.serveSlate(w, r)
		return
	}

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

	var tokenInfo store.TokenInfo
	if ap.Visibility == "private" {
		info, err := h.Store.ValidateToken(ap.ID, tokenRaw)
		if err != nil {
			log.Printf("ValidateToken: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		tokenInfo = info
		switch info.Status {
		case store.TokenInvalid:
			http.NotFound(w, r) // never reveal whether the path itself is real
			return
		case store.TokenRevoked, store.TokenExpired:
			h.writeReplacement(w, r, ap, tokenInfo, remainder == "")
			return
		}
		h.touchTokenThrottled(info.ID)
	}
	if ap.Stream.Status == "disabled" || ap.Status == "revoked" {
		h.writeReplacement(w, r, ap, tokenInfo, remainder == "")
		return
	}

	sourceEntry, err := h.sourceEntryURL(ap.Stream)
	if err != nil {
		log.Printf("stream %d has an unusable source_url: %v", ap.Stream.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if remainder == "" {
		if h.serveFromNode(w, r, ap, prefix) {
			return
		}
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
		if !ap.Stream.AllowRemux {
			h.writeTemporaryFailure(w, r)
			return
		}
		h.serveRemuxResource(w, r, ap, target)
		return
	}
	// The blob is authenticated (blobcodec) and bound to this access point,
	// so this is about SSRF, not about the blob being forged -- see
	// checkFetchTarget's doc comment for the actual policy and why a
	// simple "must match the source's own host" rule broke real streams.
	if isNodeTarget(ap, target) {
		h.serveNodeResource(w, r, ap, target, prefix)
		return
	}
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

// sourceSignature identifies a stream's source so a running remux session is
// reused only while URL and credentials are unchanged. It hashes the
// decrypted password, not the ciphertext: encryption uses a fresh nonce, and
// nodes receive newly encrypted credentials on every config poll, so hashing
// the ciphertext restarted node relays every few seconds.
func (h *Handler) sourceSignature(s store.Stream) string {
	pw := s.SourcePasswordEnc.String
	if s.SourcePasswordEnc.Valid {
		if plain, err := secretbox.Decrypt(h.Key, s.SourcePasswordEnc.String); err == nil {
			pw = "plain:" + string(plain)
		}
	}
	sum := sha256.Sum256([]byte(s.SourceURL + "\x00" + s.SourceUsername.String + "\x00" + pw))
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
	if !ap.Stream.AllowRemux && h.Remux.Existing(ap.Stream.ID, h.sourceSignature(ap.Stream)) != nil {
		log.Printf("remux refused for stream %d: owner lacks permission", ap.Stream.ID)
		h.writeTemporaryFailure(w, r)
		return
	}
	if s := h.Remux.Existing(ap.Stream.ID, h.sourceSignature(ap.Stream)); s != nil {
		h.writeRemuxPlaylist(w, ap, s, prefix)
		return
	}
	sourcePrivate := h.isSourcePrivate(r.Context(), ap.Stream, sourceEntry)
	resp, err := h.fetchWithHeaderTimeout(context.Background(), sourceEntry, ap.Stream, sourcePrivate, 0, entryHeaderTimeout)
	if err != nil && fetchFailureKind(err) == "timeout" {
		// The first attempt usually wakes a cold source (tuner); retry once.
		log.Printf("fetching source for stream %d timed out, retrying once", ap.Stream.ID)
		resp, err = h.fetchWithHeaderTimeout(context.Background(), sourceEntry, ap.Stream, sourcePrivate, 0, entryRetryHeaderTimeout)
	}
	if err != nil {
		log.Printf("fetching source for stream %d failed: %s", ap.Stream.ID, fetchFailureKind(err))
		h.writeTemporaryFailure(w, r)
		return
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		log.Printf("source for stream %d returned HTTP %d", ap.Stream.ID, resp.StatusCode)
		h.writeTemporaryFailure(w, r)
		return
	}
	if !h.sniffAndServe(w, r, resp, resp.Request.URL, prefix, ap, true) {
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
		log.Printf("fetching resource for stream %d failed: %s", ap.Stream.ID, fetchFailureKind(err))
		h.writeTemporaryHTML(w, r)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	h.sniffAndServe(w, r, resp, resp.Request.URL, prefix, ap, false)
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
	return h.fetchWithHeaderTimeout(ctx, target, s, sourcePrivate, timeout, 0)
}

// fetchWithHeaderTimeout lets entry fetches wait longer for response headers
// than the shared transport's 10 s: a cold Tvheadend source first tunes the
// channel and routinely needs more than that before answering.
func (h *Handler) fetchWithHeaderTimeout(ctx context.Context, target *url.URL, s store.Stream, sourcePrivate bool, timeout, headerTimeout time.Duration) (*http.Response, error) {
	if !s.TrustPrivateSource {
		ctx = publicOnly(ctx) // entry, redirects, resources and HLS pulls alike
	}
	transport := h.Transport
	if headerTimeout > 0 && transport != nil && transport.ResponseHeaderTimeout != headerTimeout {
		transport = transport.Clone()
		transport.ResponseHeaderTimeout = headerTimeout
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("%w: stopped after 5 redirects", errBlockedTarget)
			}
			if err := checkFetchTarget(req.Context(), h.Resolve, req.URL, sourcePrivate); err != nil {
				return fmt.Errorf("%w: refusing to follow redirect: %v", errBlockedTarget, err)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	// Placeholder URLs already carry the credentials where the source wants
	// them; don't also send them as Basic auth to every segment host.
	if s.SourceUsername.Valid && s.SourcePasswordEnc.Valid && !usesCredentialPlaceholders(s.SourceURL) {
		if h.Key == nil {
			return nil, fmt.Errorf("stream %d requires source credentials but no encryption key is loaded", s.ID)
		}
		pw, err := secretbox.Decrypt(h.Key, s.SourcePasswordEnc.String)
		if err != nil {
			return nil, fmt.Errorf("decrypting source credentials: %w", err)
		}
		req.SetBasicAuth(s.SourceUsername.String, string(pw))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactURLError(err)
	}
	return resp, nil
}

// Entry fetches: generous wait for the first response from a cold source,
// then one shorter retry. Cloudflare's own origin timeout is 100 s. Vars so
// tests can shorten them.
var (
	entryHeaderTimeout      = 25 * time.Second
	entryRetryHeaderTimeout = 15 * time.Second
)

const (
	sniffLimit      = 1024            // enough for three TS packet sync bytes; avoids waiting for a 64 KiB live prefix
	maxPlaylistSize = 4 * 1024 * 1024 // generous headroom for even a huge master playlist; this host runs low on RAM
)

// sniffAndServe returns true if it transferred ownership of resp.Body to a
// background remux session (the caller must then not close it) -- see
// serveEntry's doc comment for why the response is reused rather than
// re-fetched.
func (h *Handler) sniffAndServe(w http.ResponseWriter, r *http.Request, resp *http.Response, manifestURL *url.URL, prefix string, ap *store.AccessPoint, entry bool) bool {
	head := make([]byte, sniffLimit)
	n, err := io.ReadFull(resp.Body, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		http.Error(w, "upstream read error", http.StatusBadGateway)
		return false
	}
	head = head[:n]
	if entry && remux.LooksLikeMPEGTS(head) {
		if !ap.Stream.AllowRemux {
			log.Printf("remux refused for stream %d: owner lacks permission", ap.Stream.ID)
			h.writeTemporaryFailure(w, r)
			return false
		}
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
			// Not %v: a URL parse error quotes the child URI, which can
			// contain source credentials (placeholder sources) or a secret path.
			log.Printf("rewriting playlist for access point %d failed: unparsable URI in the source playlist", ap.ID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return false
		}
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(rewritten))
		return false
	}

	// A source whose URL carries the credentials (placeholders) may answer
	// with an error or diagnostic page that echoes the requested path. Never
	// forward that: an entry response must be a stream, and a resource must
	// not be a human-readable document.
	if usesCredentialPlaceholders(ap.Stream.SourceURL) && (entry || looksLikeDocument(resp.Header.Get("Content-Type"), head)) {
		log.Printf("source for stream %d returned an unexpected document instead of media", ap.Stream.ID)
		h.writeTemporaryFailure(w, r)
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
	sig := h.sourceSignature(ap.Stream)
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
		http.Error(w, "remux unavailable", http.StatusServiceUnavailable)
		return
	}
	h.writeRemuxPlaylist(w, ap, s, prefix)
}

func (h *Handler) writeRemuxPlaylist(w http.ResponseWriter, ap *store.AccessPoint, s *remux.Session, prefix string) {
	p, err := h.Remux.WaitPlaylist(s)
	if err != nil {
		log.Printf("remux playlist for stream %d: %v", ap.Stream.ID, err)
		http.Error(w, "remux unavailable", http.StatusServiceUnavailable)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) > maxPlaylistSize {
		http.Error(w, "remux playlist unavailable", http.StatusServiceUnavailable)
		return
	}
	base := &url.URL{Scheme: "sv-remux", Host: s.ID, Path: "/index.m3u8"}
	rewritten, err := hls.RewritePlaylist(string(data), base, h.encodeRef(prefix, ap.ID))
	if err != nil {
		http.Error(w, "remux playlist invalid", http.StatusServiceUnavailable)
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

func (h *Handler) replacementText(reason string) slate.Text {
	if !slate.ValidReason(reason) || reason == slate.TemporaryReason {
		reason = "unauthorized_redistribution"
	}
	t := slate.DefaultText(reason)
	if title, subtitle, err := h.Store.SlateText(reason); err == nil {
		if clean, err := slate.NormalizeText(slate.Text{Title: title, Subtitle: subtitle}); err == nil {
			t = clean
		}
	}
	return t
}

func (h *Handler) writeReplacement(w http.ResponseWriter, r *http.Request, ap *store.AccessPoint, token store.TokenInfo, entry bool) {
	s := ap.Stream
	reason := s.ReplacementReason
	if !slate.ValidReason(reason) || reason == slate.TemporaryReason {
		reason = "unauthorized_redistribution"
	}
	if entry && wantsSlate(r) {
		var stamp string
		switch {
		case token.RevokedAt.Valid:
			stamp = token.RevokedAt.String
		case token.Status == store.TokenExpired && token.ExpiresAt.Valid:
			stamp = token.ExpiresAt.String
		case ap.RevokedAt.Valid:
			stamp = ap.RevokedAt.String
		case s.DisabledAt.Valid:
			stamp = s.DisabledAt.String
		}
		key := ""
		if cutoff, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
			key = h.Slate.Prepare(slate.Unavailable+":"+reason, ap.ID, token.ID, cutoff)
		}
		writeSlatePlaylistKey(w, r, slate.Unavailable+":"+reason, key)
		return
	}
	copy := h.replacementText(reason)
	h.writeErrorHTML(w, r, copy, http.StatusGone)
}

func (h *Handler) writeTemporaryHTML(w http.ResponseWriter, r *http.Request) {
	copy := slate.DefaultText(slate.TemporaryReason)
	if title, subtitle, err := h.Store.SlateText(slate.TemporaryReason); err == nil {
		if clean, err := slate.NormalizeText(slate.Text{Title: title, Subtitle: subtitle}); err == nil {
			copy = clean
		}
	}
	// 503, not 502: Cloudflare replaces an origin 502 with its own "Bad
	// gateway" page but passes a 503 body through, so viewers see this one.
	w.Header().Set("Retry-After", "30")
	h.writeErrorHTML(w, r, copy, http.StatusServiceUnavailable)
}
func (h *Handler) writeErrorHTML(w http.ResponseWriter, r *http.Request, copy slate.Text, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>%s</title>
<style>body{font-family:system-ui,sans-serif;background:#0b0d12;color:#e6e8ee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.5rem;margin-bottom:.5rem}p{color:#9aa2b1}</style>
</head><body><div class="card"><h1>%s</h1>
<p>%s</p>
</div></body></html>`, html.EscapeString(copy.Title), html.EscapeString(copy.Title), html.EscapeString(copy.Subtitle))
}

// wantsSlate: anything that isn't a browser asking for HTML is treated as a
// player, which would just spin on a 4xx/5xx instead of showing a message.
func wantsSlate(r *http.Request) bool {
	return !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func writeSlatePlaylist(w http.ResponseWriter, r *http.Request, variant string) {
	writeSlatePlaylistKey(w, r, variant, "")
}

func writeSlatePlaylistKey(w http.ResponseWriter, r *http.Request, variant, key string) {
	base, reason := slateRouteParts(variant)
	if key != "" {
		key += "/"
	}
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-STREAM-INF:BANDWIDTH=600000,RESOLUTION=1920x1080\n/_sv/slate/"+base+"/"+reason+"/"+key+"index.m3u8\n")
	}
}
func slateRouteParts(v string) (string, string) {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if v == slate.Temporary {
		return v, slate.TemporaryReason
	}
	return v, "unauthorized_redistribution"
}

func (h *Handler) serveSlate(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if (len(parts) < 4 || len(parts) > 6) || parts[0] != "_sv" || parts[1] != "slate" ||
		!slate.ValidVariant(parts[2]) {
		http.NotFound(w, r)
		return
	}
	key, name, reason := "", parts[len(parts)-1], ""
	if len(parts) == 4 {
		_, reason = slateRouteParts(parts[2])
	} else if len(parts) == 5 {
		if slate.ValidReason(parts[3]) {
			reason = parts[3]
		} else {
			key = parts[3]
			_, reason = slateRouteParts(parts[2])
		}
	} else {
		reason, key = parts[3], parts[4]
	}
	variant := parts[2] + ":" + reason
	if !slate.ValidVariant(variant) {
		http.NotFound(w, r)
		return
	}
	if !slate.ValidName(name) || key != "" && !slate.ValidKey(key) {
		http.NotFound(w, r)
		return
	}
	p, err := h.Slate.GetPath(variant, key, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		log.Printf("slate %s unavailable: %v", parts[2], err)
		http.Error(w, "slate unavailable", http.StatusServiceUnavailable)
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
	if name == "index.m3u8" {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	} else {
		w.Header().Set("Content-Type", "video/mp2t")
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// noticePNG is the image embedded in public GitHub replies (see
// leakcheck.NoticeBody): a still of the "Stream unavailable" slate. It is
// served from the stream domain so a public comment never names the admin.
//
//go:embed notice.png
var noticePNG []byte

func serveNotice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "notice.png", time.Time{}, bytes.NewReader(noticePNG))
}

// writeTemporaryFailure answers an entry request whose source is down right
// now. Players get a FINITE playlist of the shared temporary slate's current
// segments ending in #EXT-X-ENDLIST: they show the notice for ~12 s and the
// stream ends, so IPTV apps reconnect to the real entry URL (and VLC can
// just press play) instead of being parked on an endless slate stream that
// never re-asks the source. Browsers get the 503 page.
func (h *Handler) writeTemporaryFailure(w http.ResponseWriter, r *http.Request) {
	if !wantsSlate(r) {
		h.writeTemporaryHTML(w, r)
		return
	}
	body, err := h.finiteTemporarySlate()
	if err != nil {
		log.Printf("temporary slate unavailable: %v", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

// Wait until the shared temporary slate has a few segments (a fresh session
// has just one): the notice then shows for ~6 s+, and a player stuck on a
// dead source reconnects at a sane pace instead of every 2 s.
var (
	finiteSlateMinSegments = 3
	finiteSlateMaxWait     = 8 * time.Second
)

func (h *Handler) finiteTemporarySlate() (string, error) {
	base, reason := slateRouteParts(slate.Temporary)
	deadline := time.Now().Add(finiteSlateMaxWait)
	for {
		body, segments, err := h.readFiniteSlate(base, reason)
		if err != nil {
			return "", err
		}
		if segments >= finiteSlateMinSegments || time.Now().After(deadline) {
			if segments == 0 {
				return "", errors.New("temporary slate has no segments yet")
			}
			return body, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (h *Handler) readFiniteSlate(base, reason string) (string, int, error) {
	p, err := h.Slate.GetPath(base+":"+reason, "", "index.m3u8")
	if err != nil {
		return "", 0, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", 0, err
	}
	prefix := "/_sv/slate/" + base + "/" + reason + "/"
	var out strings.Builder
	segments := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line == "#EXT-X-ENDLIST":
			continue
		case strings.HasPrefix(line, "#"):
			out.WriteString(line + "\n")
		case slate.ValidName(line) && line != "index.m3u8":
			out.WriteString(prefix + line + "\n")
			segments++
		}
	}
	out.WriteString("#EXT-X-ENDLIST\n")
	return out.String(), segments, nil
}
