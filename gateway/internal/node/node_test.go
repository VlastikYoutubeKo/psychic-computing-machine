package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

	// Viewer: control -> 302 -> node playlist -> signed segment.
	resp, err = http.Get(ctlSrv.URL + "/live/relay/viewer-token.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	playlist, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	final := resp.Request.URL
	if resp.StatusCode != 200 || final.Host != nodeAddr || !strings.Contains(string(playlist), "sig=") {
		t.Fatalf("viewer not served by node: %d host=%s body=%q", resp.StatusCode, final.Host, playlist)
	}
	var segLine string
	for _, l := range strings.Split(string(playlist), "\n") {
		if strings.HasPrefix(l, "seg") {
			segLine = l
			break
		}
	}
	segURL, _ := final.Parse(segLine)
	sresp, err := http.Get(segURL.String())
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 1)
	io.ReadFull(sresp.Body, head)
	sresp.Body.Close()
	if sresp.StatusCode != 200 || head[0] != 0x47 {
		t.Fatalf("segment from node: %d first byte %x", sresp.StatusCode, head)
	}

	// Tampered signature.
	bad := *final
	q := bad.Query()
	q.Set("sig", strings.Repeat("0", 64))
	bad.RawQuery = q.Encode()
	if r, _ := http.Get(bad.String()); r.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered signature: %d", r.StatusCode)
	}

	// Revoke the token: after the node's next poll its signed URL stops working.
	raw.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE access_point_id = ?`, apID)
	if err := n.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := http.Get(final.String()); r.StatusCode != http.StatusGone {
		t.Fatalf("revoked token still served by node: %d", r.StatusCode)
	}
}
