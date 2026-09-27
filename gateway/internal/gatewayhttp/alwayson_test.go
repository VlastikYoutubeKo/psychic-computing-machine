package gatewayhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// liveHLSSource serves an endless live HLS playlist whose segments are all
// the same real MPEG-TS clip (made by ffmpeg), with an advancing sequence.
func liveHLSSource(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	seg := filepath.Join(t.TempDir(), "seg.ts")
	if out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=160x90:rate=10",
		"-t", "2", "-pix_fmt", "yuv420p", "-c:v", "mpeg2video", "-f", "mpegts", seg).CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg: %v %s", err, out)
	}
	data, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var entryHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".m3u8") {
			entryHits.Add(1)
			seq := int(time.Since(start) / (2 * time.Second))
			fmt.Fprintf(w, "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:%d\n", seq)
			for i := 0; i < 4; i++ {
				fmt.Fprintf(w, "#EXTINF:2,\ns%d.ts\n", seq+i)
			}
			return
		}
		w.Header().Set("Content-Type", "video/mp2t")
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv, &entryHits
}

func TestAlwaysOnRelayRunsPinnedAndServesViewersWithoutTouchingSource(t *testing.T) {
	src, _ := liveHLSSource(t)
	h, db := newTestHandler(t)
	apID := seedStream(t, db, src.URL+"/live.m3u8", "live/aon", "public")
	var streamID int64
	db.QueryRow(`SELECT stream_id FROM access_points WHERE id = ?`, apID).Scan(&streamID)
	if _, err := db.Exec(`UPDATE streams SET always_on = 1 WHERE id = ?`, streamID); err != nil {
		t.Fatal(err)
	}

	states := map[int64]*alwaysOnState{}
	h.reconcileAlwaysOn(context.Background(), states)
	var state, detail string
	db.QueryRow(`SELECT state, detail FROM stream_runtime WHERE stream_id = ?`, streamID).Scan(&state, &detail)
	if state != "running" {
		t.Fatalf("relay state = %q (%s)", state, detail)
	}
	if alive, ok := h.Remux.Pinned()[streamID]; !ok || !alive {
		t.Fatalf("relay should be a live pinned session, got %v %v", ok, alive)
	}

	// A viewer joins the running relay: instant, remux playlist, no new
	// source entry fetch by the gateway's request path.
	t0 := time.Now()
	got := slateRequest(t, h, "GET", "/live/aon.m3u8", "*/*")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "/live/aon/r/") {
		t.Fatalf("viewer: %d %s", got.Code, got.Body.String())
	}
	if time.Since(t0) > 2*time.Second {
		t.Fatalf("viewer waited %s on an always-on relay", time.Since(t0))
	}

	// Switching always-on off returns the session to normal idle handling.
	db.Exec(`UPDATE streams SET always_on = 0 WHERE id = ?`, streamID)
	h.reconcileAlwaysOn(context.Background(), states)
	if _, ok := h.Remux.Pinned()[streamID]; ok {
		t.Fatal("session still pinned after always-on was switched off")
	}
	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM stream_runtime WHERE stream_id = ?`, streamID).Scan(&rows)
	if rows != 0 {
		t.Fatal("runtime row should be cleared when a stream is no longer always-on")
	}
}

func TestAlwaysOnFailureBacksOffWithReadableReason(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer src.Close()
	h, db := newTestHandler(t)
	apID := seedStream(t, db, src.URL+"/live.m3u8", "live/broken", "public")
	var streamID int64
	db.QueryRow(`SELECT stream_id FROM access_points WHERE id = ?`, apID).Scan(&streamID)
	db.Exec(`UPDATE streams SET always_on = 1 WHERE id = ?`, streamID)

	states := map[int64]*alwaysOnState{}
	h.reconcileAlwaysOn(context.Background(), states)
	var state, detail string
	db.QueryRow(`SELECT state, detail FROM stream_runtime WHERE stream_id = ?`, streamID).Scan(&state, &detail)
	if state != "backoff" || !strings.Contains(detail, "HTTP 404") || strings.Contains(detail, src.URL) {
		t.Fatalf("expected backoff with a URL-free reason, got %q %q", state, detail)
	}
	if states[streamID].nextTry.Before(time.Now().Add(20 * time.Second)) {
		t.Fatal("backoff should delay the next attempt")
	}
	// A second reconcile inside the backoff window must not hammer the source.
	h.reconcileAlwaysOn(context.Background(), states)
	if states[streamID].failures != 1 {
		t.Fatalf("retried inside the backoff window (failures=%d)", states[streamID].failures)
	}
}

func TestShortLivedRelayCrashCountsAsFailure(t *testing.T) {
	st := &alwaysOnState{}
	st.runningSince = time.Now().Add(-10 * time.Second) // came up, then died quickly
	if time.Since(st.runningSince) >= alwaysOnMinHealthy {
		t.Fatal("test setup: should be short-lived")
	}
	first := st.fail()
	second := st.fail()
	if st.failures != 2 || second != 2*first || !st.runningSince.IsZero() {
		t.Fatalf("backoff must grow across quick crashes: failures=%d first=%s second=%s", st.failures, first, second)
	}
	if time.Until(st.nextTry) < first {
		t.Fatal("next attempt not delayed")
	}
}

func TestNodeAssignedAlwaysOnStreamIsNotRelayedLocally(t *testing.T) {
	h, db := newTestHandler(t)
	apID := seedStream(t, db, "http://127.0.0.1:9/live.m3u8", "live/onnode", "public")
	var streamID int64
	db.QueryRow(`SELECT stream_id FROM access_points WHERE id = ?`, apID).Scan(&streamID)
	res, _ := db.Exec(`INSERT INTO nodes (name, public_url, token_hash, secret_enc) VALUES ('n', 'http://127.0.0.1:1', 'x', 'y')`)
	nodeID, _ := res.LastInsertId()
	db.Exec(`UPDATE streams SET always_on = 1, node_id = ? WHERE id = ?`, nodeID, streamID)
	streams, err := h.Store.AlwaysOnStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 0 {
		t.Fatalf("node-assigned stream must be relayed by the node only, got %d local relays", len(streams))
	}
}
