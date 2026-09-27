package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"streamvault/gateway/internal/gatewayhttp"
	"streamvault/gateway/internal/nodeproto"
	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

func TestSignSegmentsAndNames(t *testing.T) {
	out := signSegments("#EXTM3U\n#EXTINF:2,\nseg000001.ts\n#EXTINF:2,\n../etc/passwd\n", "ap=1&tok=2&exp=3&sig=x")
	if !strings.Contains(out, "seg000001.ts?ap=1&tok=2&exp=3&sig=x") || strings.Contains(out, "passwd?") {
		t.Fatalf("unexpected rewrite: %q", out)
	}
	for _, bad := range []string{"", "seg1.ts", "seg00000a.ts", "../seg000001.ts", "index.m3u8x", "seg000001.ts.tmp"} {
		if validName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func newPollingNode(t *testing.T) (*Node, *atomic.Int32) {
	t.Helper()
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, `{"node_id":1,"poll_seconds":10,"streams":[{"id":42,"source_type":"hls","source_url":"https://example.test/live.m3u8"}]}`)
		}
	}))
	t.Cleanup(server.Close)
	n, err := New(Config{ControlURL: server.URL, Token: "svn_1_" + strings.Repeat("a", 64), Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.h.Remux.Close)
	return n, &status
}

func TestUnauthorizedPollClearsAndSuccessfulPollRestores(t *testing.T) {
	n, status := newPollingNode(t)
	if err := n.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.assigned[42] {
		t.Fatal("initial assignment missing")
	}
	status.Store(http.StatusUnauthorized)
	if err := n.pollOnce(context.Background()); !errors.Is(err, errConfigUnauthorized) {
		t.Fatalf("expected credential error, got %v", err)
	}
	if n.haveConfig || n.assigned[42] || len(n.streams) != 0 {
		t.Fatal("401 left stale assignments")
	}
	if streams, err := n.AlwaysOnStreams(); err != nil || len(streams) != 0 {
		t.Fatalf("relay supervisor still sees assignments: %v, %v", streams, err)
	}
	// A direct signed viewer request must be rejected while the old config is gone.
	exp := time.Now().Add(time.Minute).Unix()
	u := fmt.Sprintf("/n/42/index.m3u8?ap=0&tok=0&exp=%d&sig=%s", exp, nodeproto.Sign(n.secret, 42, 0, 0, exp))
	w := httptest.NewRecorder()
	n.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusGone {
		t.Fatalf("stale viewer access: HTTP %d", w.Code)
	}
	status.Store(http.StatusOK)
	if err := n.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.haveConfig || !n.assigned[42] {
		t.Fatal("successful poll did not restore assignments")
	}
}

func TestForbiddenPollClears(t *testing.T) {
	n, status := newPollingNode(t)
	if err := n.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusForbidden)
	if err := n.pollOnce(context.Background()); !errors.Is(err, errConfigUnauthorized) {
		t.Fatalf("expected credential error, got %v", err)
	}
	if n.haveConfig || n.assigned[42] {
		t.Fatal("403 left stale assignments")
	}
}

func TestStaleConfigClearsAndLaterPollRestores(t *testing.T) {
	n, _ := newPollingNode(t)
	if err := n.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.lastConfigAt = time.Now().Add(-configMaxAge - time.Second)
	n.mu.Unlock()
	n.expireConfig(time.Now())
	if n.haveConfig || n.assigned[42] {
		t.Fatal("expired config left stale assignments")
	}
	if err := n.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.haveConfig || !n.assigned[42] {
		t.Fatal("fresh poll did not restore assignments")
	}
}

// End to end: control gateway + running node + live HLS source + real ffmpeg.
func TestViewerIsRelayedByNodeAndRevocationReachesNode(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	// Live HLS source.
	seg := filepath.Join(t.TempDir(), "seg.ts")
	if out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=160x90:rate=10",
		"-t", "2", "-pix_fmt", "yuv420p", "-c:v", "mpeg2video", "-f", "mpegts", seg).CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg: %v %s", err, out)
	}
	clip, _ := os.ReadFile(seg)
	start := time.Now()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".m3u8") {
			n := int(time.Since(start) / (2 * time.Second))
			fmt.Fprintf(w, "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:%d\n", n)
			for i := 0; i < 4; i++ {
				fmt.Fprintf(w, "#EXTINF:2,\ns%d.ts\n", n+i)
			}
			return
		}
		w.Write(clip)
	}))
	defer src.Close()

	// Control plane DB + gateway.
	dbPath := filepath.Join(t.TempDir(), "sv.sqlite")
	raw, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	migrations, _ := filepath.Glob("../../../migrations/*.sql")
	sort.Strings(migrations)
	for _, m := range migrations {
		b, _ := os.ReadFile(m)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := make([]byte, 32)
	rand.Read(key)
	control, err := gatewayhttp.New(st, key)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Remux.Close()
	defer control.Slate.Close()
	ctlSrv := httptest.NewServer(control)
	defer ctlSrv.Close()

	nodeAddr := freePort(t)
	secretRaw := make([]byte, 32)
	rand.Read(secretRaw)
	secret := hex.EncodeToString(secretRaw)
	secretEnc, _ := secretbox.Encrypt(key, []byte(secret))
	res, err := raw.Exec(`INSERT INTO nodes (name, public_url, token_hash, secret_enc) VALUES ('n1', ?, ?, ?)`, "http://"+nodeAddr, nodeproto.SecretHash(secret), secretEnc)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, _ := res.LastInsertId()
	res, _ = raw.Exec(`INSERT INTO streams (name, source_type, source_url, node_id) VALUES ('s', 'hls', ?, ?)`, src.URL+"/live.m3u8", nodeID)
	streamID, _ := res.LastInsertId()
	res, _ = raw.Exec(`INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, 'live/relay', 'private')`, streamID)
	apID, _ := res.LastInsertId()
	sum := sha256.Sum256([]byte("viewer-token"))
	raw.Exec(`INSERT INTO access_tokens (access_point_id, token_hash, token_display) VALUES (?, ?, 'viewer')`, apID, hex.EncodeToString(sum[:]))

	// Node.
	n, err := New(Config{ControlURL: ctlSrv.URL, Token: "svn_" + strconv.FormatInt(nodeID, 10) + "_" + secret, Listen: nodeAddr, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := n.pollOnce(ctx); err != nil {
		t.Fatalf("initial config: %v", err)
	}
	go n.Run(ctx)
	deadline := time.Now().Add(40 * time.Second)
	for {
		n.mu.RLock()
		state := n.runtime[streamID].State
		n.mu.RUnlock()
		if state == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("node relay never started (state %q)", state)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Heartbeat so the control plane considers the node online.
	body := strings.NewReader(`{"version":"test","streams":[]}`)
	resp, err := n.request(ctx, http.MethodPost, "/_sv/node/status", body)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat: %v %v", err, resp)
	}
	resp.Body.Close()

	// Viewer: everything on the control domain; the control gateway fetches
	// the relay from the node and rewrites segments to its own /r/ refs.
	resp, err = http.Get(ctlSrv.URL + "/live/relay/viewer-token.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	playlist, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	final := resp.Request.URL
	if resp.StatusCode != 200 || final.Host != strings.TrimPrefix(ctlSrv.URL, "http://") || strings.Contains(string(playlist), nodeAddr) || !strings.Contains(string(playlist), "/live/relay/viewer-token/r/") {
		t.Fatalf("viewer not proxied via control: %d host=%s body=%q", resp.StatusCode, final.Host, playlist)
	}
	var segLine string
	for _, l := range strings.Split(string(playlist), "\n") {
		if strings.HasPrefix(l, "/live/relay/") {
			segLine = l
			break
		}
	}
	sresp, err := http.Get(ctlSrv.URL + segLine)
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 1)
	io.ReadFull(sresp.Body, head)
	sresp.Body.Close()
	if sresp.StatusCode != 200 || head[0] != 0x47 {
		t.Fatalf("segment via control from node: %d first byte %x", sresp.StatusCode, head)
	}
	n.mu.RLock()
	viewers := len(n.viewers[streamID])
	n.mu.RUnlock()
	if viewers != 1 {
		t.Fatalf("node should count the proxied viewer once, got %d", viewers)
	}

	// The node itself refuses anything not signed by the control plane.
	if r, _ := http.Get(fmt.Sprintf("http://%s/n/%d/index.m3u8?ap=0&tok=0&exp=9999999999&sig=%s", nodeAddr, streamID, strings.Repeat("0", 64))); r.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned node request: %d", r.StatusCode)
	}

	// Revoke the token: the control gateway stops proxying at once.
	raw.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID)
	resp, _ = http.Get(ctlSrv.URL + "/live/relay/viewer-token.m3u8")
	after, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(after), "/live/relay/viewer-token/r/") {
		t.Fatalf("revoked token still proxied: %q", after)
	}
}
