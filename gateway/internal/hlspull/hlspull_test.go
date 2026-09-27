package hlspull

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tsSegment(id byte) []byte {
	pkt := make([]byte, 188)
	pkt[0] = 0x47
	pkt[4] = id // payload marker so tests can see which segment arrived
	return bytes.Repeat(pkt, 4)
}

func plainFetcher(c *http.Client) Fetcher {
	return func(ctx context.Context, u *url.URL) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		return c.Do(req)
	}
}

func readSegments(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	var ids []byte
	buf := make([]byte, 188)
	deadline := time.After(10 * time.Second)
	for len(ids) < n {
		done := make(chan error, 1)
		go func() { _, err := io.ReadFull(r, buf); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("read after %d segments: %v", len(ids), err)
			}
		case <-deadline:
			t.Fatalf("timed out after %d segments", len(ids))
		}
		if buf[0] != 0x47 {
			t.Fatal("output is not TS-aligned")
		}
		if len(ids) == 0 || ids[len(ids)-1] != buf[4] {
			ids = append(ids, buf[4])
		}
	}
	return ids
}

func TestLiveMasterPlaylistPicksBestVariantAndFollowsSequence(t *testing.T) {
	var start = time.Now()
	var lowHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/master.m3u8", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=500000\nlow.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=3000000\nhigh.m3u8\n")
	})
	mux.HandleFunc("/low.m3u8", func(w http.ResponseWriter, r *http.Request) { lowHits.Add(1) })
	mux.HandleFunc("/high.m3u8", func(w http.ResponseWriter, r *http.Request) {
		seq := 10 + int(time.Since(start)/time.Second) // a new segment every second
		fmt.Fprintf(w, "#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:%d\n", seq)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "#EXTINF:1,\nseg%d.ts\n", seq+i)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/seg%d.ts", &n); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(tsSegment(byte(n)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/master.m3u8")
	r := Open(context.Background(), plainFetcher(srv.Client()), u)
	defer r.Close()

	ids := readSegments(t, r, 5)
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1]+1 {
			t.Fatalf("segments out of order or duplicated: %v", ids)
		}
	}
	if ids[0] < 12 {
		t.Fatalf("should start near the live edge (last %d segments), started at %d", liveEdgeWindow, ids[0])
	}
	if lowHits.Load() != 0 {
		t.Fatal("low-bandwidth variant must not be used")
	}
}

func servePlaylist(t *testing.T, playlist string, seg []byte) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".m3u8") {
			fmt.Fprint(w, playlist)
			return
		}
		w.Write(seg)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/index.m3u8")
	return srv, u
}

func readErr(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func TestUnsupportedSourcesAreReported(t *testing.T) {
	cases := map[string]struct {
		playlist string
		seg      []byte
		want     error
	}{
		"encrypted": {"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\"\n#EXTINF:2,\na.ts\n", tsSegment(1), ErrEncrypted},
		"fmp4":      {"#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:2,\na.m4s\n", []byte("x"), ErrFMP4},
		"not ts":    {"#EXTM3U\n#EXTINF:2,\na.ts\n#EXT-X-ENDLIST\n", []byte("<html>not a segment</html>"), ErrNotTS},
	}
	for name, c := range cases {
		srv, u := servePlaylist(t, c.playlist, c.seg)
		r := Open(context.Background(), plainFetcher(srv.Client()), u)
		if err := readErr(r); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
		r.Close()
	}
}

func TestEndlistDeliversSegmentsThenEOF(t *testing.T) {
	srv, u := servePlaylist(t, "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\na.ts\n#EXTINF:2,\nb.ts\n#EXT-X-ENDLIST\n", tsSegment(7))
	r := Open(context.Background(), plainFetcher(srv.Client()), u)
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("expected clean EOF, got %v", err)
	}
	if len(data) != 2*4*188 {
		t.Fatalf("expected both segments (%d bytes), got %d", 2*4*188, len(data))
	}
}

func TestCloseStopsPuller(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, ".m3u8") {
			fmt.Fprint(w, "#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXT-X-MEDIA-SEQUENCE:1\n#EXTINF:1,\na.ts\n")
			return
		}
		w.Write(tsSegment(1))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/index.m3u8")
	r := Open(context.Background(), plainFetcher(srv.Client()), u)
	readSegments(t, r, 1)
	r.Close()
	time.Sleep(1500 * time.Millisecond)
	before := hits.Load()
	time.Sleep(2500 * time.Millisecond)
	if hits.Load() != before {
		t.Fatalf("puller kept polling after Close (%d -> %d)", before, hits.Load())
	}
}
