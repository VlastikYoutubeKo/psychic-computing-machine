// Package node runs the gateway as a relay node: it pulls its assignment
// from the control plane (/_sv/node/config), keeps a 24/7 relay per assigned
// stream using the same supervisor as always-on streams, serves viewers who
// arrive with a control-signed URL, and reports health (/_sv/node/status).
//
// A node never sees the control database. It holds only its own token, the
// streams assigned to it (with source passwords encrypted under a key derived
// from that token), and the revocation lists for those streams.
package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"streamvault/gateway/internal/gatewayhttp"
	"streamvault/gateway/internal/nodeproto"
	"streamvault/gateway/internal/store"
)

type Config struct {
	ControlURL string
	Token      string
	Listen     string
	Version    string
}

type Node struct {
	cfg     Config
	id      int64
	secret  string
	control *url.URL
	client  *http.Client
	h       *gatewayhttp.Handler
	started time.Time

	mu            sync.RWMutex
	streams       []store.Stream
	assigned      map[int64]bool
	revokedAPs    map[int64]bool
	revokedTokens map[int64]bool
	pollEvery     time.Duration
	runtime       map[int64]nodeproto.StreamStatus
	viewers       map[int64]map[string]time.Time
	haveConfig    bool
	lastConfigAt  time.Time
}

const configMaxAge = 5 * time.Minute

var errConfigUnauthorized = errors.New("control plane rejected node credentials")

// New validates the configuration without starting anything.
func New(cfg Config) (*Node, error) {
	id, secret, ok := nodeproto.ParseToken(cfg.Token)
	if !ok {
		return nil, errors.New("STREAMVAULT_NODE_TOKEN is missing or malformed")
	}
	control, err := url.Parse(strings.TrimRight(cfg.ControlURL, "/"))
	if err != nil || (control.Scheme != "https" && control.Scheme != "http") || control.Host == "" {
		return nil, errors.New("STREAMVAULT_CONTROL_URL must be an http(s) URL")
	}
	n := &Node{
		cfg: cfg, id: id, secret: secret, control: control,
		client:        &http.Client{Timeout: 15 * time.Second},
		started:       time.Now(),
		assigned:      map[int64]bool{},
		revokedAPs:    map[int64]bool{},
		revokedTokens: map[int64]bool{},
		pollEvery:     10 * time.Second,
		runtime:       map[int64]nodeproto.StreamStatus{},
		viewers:       map[int64]map[string]time.Time{},
	}
	n.h = gatewayhttp.NewRelayOnly(nodeproto.ConfigKey(secret), n)
	return n, nil
}

// Run serves until ctx ends.
func (n *Node) Run(ctx context.Context) error {
	defer n.h.Remux.Close()
	go n.pollLoop(ctx)
	go n.statusLoop(ctx)
	go n.h.RunAlwaysOn(ctx, 10*time.Second)
	srv := &http.Server{Addr: n.cfg.Listen, Handler: n, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("streamvault node %d listening on %s (control %s)", n.id, n.cfg.Listen, n.control)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// --- RelayStore (feeds the always-on supervisor) ---------------------------

func (n *Node) AlwaysOnStreams() ([]store.Stream, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.haveConfig {
		return nil, nil
	}
	return append([]store.Stream(nil), n.streams...), nil
}

func (n *Node) SetRuntime(id int64, state, detail string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.runtime[id] = nodeproto.StreamStatus{ID: id, State: state, Detail: detail}
	return nil
}

func (n *Node) ClearRuntime(keep []int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	k := map[int64]bool{}
	for _, id := range keep {
		k[id] = true
	}
	for id := range n.runtime {
		if !k[id] {
			delete(n.runtime, id)
		}
	}
	return nil
}

// --- control plane ------------------------------------------------------

func (n *Node) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, n.control.String()+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.cfg.Token)
	req.Header.Set("User-Agent", "streamvault-node/"+n.cfg.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return n.client.Do(req)
}

func (n *Node) pollLoop(ctx context.Context) {
	for {
		if err := n.pollOnce(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, errConfigUnauthorized) {
			log.Printf("node: config poll failed (keeping last config): %v", err)
		}
		n.expireConfig(time.Now())
		n.mu.RLock()
		wait := n.pollEvery
		n.mu.RUnlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (n *Node) pollOnce(ctx context.Context) error {
	resp, err := n.request(ctx, http.MethodGet, "/_sv/node/config", nil)
	if err != nil {
		return errors.New("control plane unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		n.clearConfig("control plane rejected node credentials")
		return errConfigUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	var cfg nodeproto.Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&cfg); err != nil {
		return errors.New("invalid config document")
	}
	if cfg.NodeID != n.id {
		return errors.New("config is for a different node")
	}
	n.apply(cfg)
	return nil
}

func (n *Node) apply(cfg nodeproto.Config) {
	streams := make([]store.Stream, 0, len(cfg.Streams))
	assigned := map[int64]bool{}
	for _, sc := range cfg.Streams {
		st := store.Stream{ID: sc.ID, SourceType: sc.SourceType, SourceURL: sc.SourceURL, Status: "active", AllowRemux: true, TrustPrivateSource: sc.TrustPrivateSource}
		if sc.SourceUsername != "" && sc.SourcePasswordEnc != "" {
			st.SourceUsername.String, st.SourceUsername.Valid = sc.SourceUsername, true
			st.SourcePasswordEnc.String, st.SourcePasswordEnc.Valid = sc.SourcePasswordEnc, true
		}
		streams = append(streams, st)
		assigned[sc.ID] = true
	}
	toSet := func(ids []int64) map[int64]bool {
		m := make(map[int64]bool, len(ids))
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	poll := time.Duration(cfg.PollSeconds) * time.Second
	if poll < 5*time.Second || poll > time.Minute {
		poll = 10 * time.Second
	}
	n.mu.Lock()
	n.streams, n.assigned = streams, assigned
	n.revokedAPs, n.revokedTokens = toSet(cfg.RevokedAccessPoints), toSet(cfg.RevokedTokens)
	n.pollEvery, n.haveConfig, n.lastConfigAt = poll, true, time.Now()
	n.mu.Unlock()
}

// clearConfig fails closed. The relay supervisor sees no assigned streams on
// its next reconciliation and unpins them; direct viewer requests fail now.
func (n *Node) clearConfig(reason string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.clearConfigLocked(reason)
}

func (n *Node) clearConfigLocked(reason string) {
	if !n.haveConfig {
		return // Log only the transition, even if every later poll is rejected.
	}
	n.streams = nil
	n.assigned = map[int64]bool{}
	n.revokedAPs = map[int64]bool{}
	n.revokedTokens = map[int64]bool{}
	n.viewers = map[int64]map[string]time.Time{}
	n.haveConfig = false
	log.Printf("node: cleared assignments: %s", reason)
}

func (n *Node) expireConfig(now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.haveConfig && now.Sub(n.lastConfigAt) >= configMaxAge {
		n.clearConfigLocked("last successful config poll is too old")
	}
}

func (n *Node) statusLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
		body, _ := json.Marshal(n.collectStatus())
		resp, err := n.request(ctx, http.MethodPost, "/_sv/node/status", strings.NewReader(string(body)))
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("node: status report failed: control plane unreachable")
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			log.Printf("node: status report returned HTTP %d", resp.StatusCode)
		}
	}
}

func (n *Node) collectStatus() nodeproto.Status {
	st := nodeproto.Status{Version: n.cfg.Version, UptimeSeconds: int64(time.Since(n.started).Seconds()), CPUs: runtime.NumCPU(), Streams: []nodeproto.StreamStatus{}}
	st.BinarySHA256, _ = nodeproto.ExecutableSHA256()
	st.Load1 = readLoad1()
	st.MemTotalKB, st.MemAvailableKB = readMem()
	st.NetRxBytes, st.NetTxBytes = readNet()
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := time.Now().Add(-30 * time.Second)
	for id, rs := range n.runtime {
		for ip, seen := range n.viewers[id] {
			if seen.Before(cutoff) {
				delete(n.viewers[id], ip)
			}
		}
		rs.Viewers = len(n.viewers[id])
		st.Streams = append(st.Streams, rs)
	}
	return st
}

// --- viewer serving -------------------------------------------------------

func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "ok\n")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n.expireConfig(time.Now())
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "n" {
		http.NotFound(w, r)
		return
	}
	streamID, err := strconv.ParseInt(parts[1], 10, 64)
	name := parts[2]
	if err != nil || streamID <= 0 || !validName(name) {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	ap, e1 := strconv.ParseInt(q.Get("ap"), 10, 64)
	tok, e2 := strconv.ParseInt(q.Get("tok"), 10, 64)
	exp, e3 := strconv.ParseInt(q.Get("exp"), 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || time.Now().Unix() > exp ||
		!nodeproto.Verify(n.secret, streamID, ap, tok, exp, q.Get("sig")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n.mu.RLock()
	allowed := n.assigned[streamID] && !n.revokedAPs[ap] && (tok == 0 || !n.revokedTokens[tok])
	n.mu.RUnlock()
	if !allowed {
		// Revoked or no longer assigned here: the control gateway decides
		// what the viewer gets next (it serves the unavailable slate).
		http.Error(w, "gone", http.StatusGone)
		return
	}
	s := n.h.Remux.Current(streamID)
	if s == nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "relay starting", http.StatusServiceUnavailable)
		return
	}
	path, ok := n.h.Remux.GetPath(streamID, s.ID, name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if name == "index.m3u8" {
		n.noteViewer(streamID, r, ap == 0 && tok == 0)
		data, err := os.ReadFile(path)
		if err != nil {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "relay starting", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		io.WriteString(w, signSegments(string(data), r.URL.RawQuery))
		return
	}
	f, err := os.Open(path)
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
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func validName(name string) bool {
	if name == "index.m3u8" {
		return true
	}
	if !strings.HasPrefix(name, "seg") || !strings.HasSuffix(name, ".ts") || len(name) != len("seg000000.ts") {
		return false
	}
	for _, c := range name[3:9] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// signSegments appends the viewer's signed query to every segment line, so
// segment requests carry the same authorization as the playlist.
func signSegments(playlist, rawQuery string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(playlist))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") && validName(line) {
			line += "?" + rawQuery
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (n *Node) noteViewer(streamID int64, r *http.Request, viaControl bool) {
	// Requests proxied by the control gateway (control grant, ap=0/tok=0)
	// all come from the control IP; count its hashed viewer id instead.
	if viaControl {
		if id := r.Header.Get(nodeproto.ViewerHeader); len(id) == 16 && isHex(id) {
			n.recordViewer(streamID, "v:"+id)
			return
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	// Behind a local reverse proxy (Caddy/nginx on the node), use the first
	// X-Forwarded-For hop; never trust it from a remote peer.
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		if xff := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(xff) != nil {
			ip = xff
		}
	}
	n.recordViewer(streamID, ip)
}

func (n *Node) recordViewer(streamID int64, key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.viewers[streamID] == nil {
		n.viewers[streamID] = map[string]time.Time{}
	}
	n.viewers[streamID][key] = time.Now()
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// --- host metrics (Linux /proc; zero where unavailable) --------------------

func readLoad1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return f
}

func readMem() (total, avail int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total, avail
}

func readNet() (rx, tx int64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:i])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[i+1:])
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseInt(fields[0], 10, 64)
		t, _ := strconv.ParseInt(fields[8], 10, 64)
		rx, tx = rx+r, tx+t
	}
	return rx, tx
}
