// Package hlspull turns a live HLS source into one continuous MPEG-TS byte
// stream, so an always-on relay can feed it to the same ffmpeg -c copy
// pipeline used for native MPEG-TS sources. Every playlist and segment is
// fetched through the caller's Fetcher, which is where the gateway applies
// its SSRF policy and source credentials.
//
// Supported: live media playlists with MPEG-TS segments, reached directly or
// via a master playlist (the highest-BANDWIDTH variant is used). Not
// supported (returned as errors so the relay reports them): encrypted
// segments (#EXT-X-KEY other than NONE) and fMP4 segments (#EXT-X-MAP).
package hlspull

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Fetcher performs one GET; the caller closes the body.
type Fetcher func(ctx context.Context, target *url.URL) (*http.Response, error)

var (
	ErrEncrypted   = errors.New("hlspull: encrypted HLS segments are not supported for always-on relays")
	ErrFMP4        = errors.New("hlspull: fMP4 (EXT-X-MAP) segments are not supported for always-on relays")
	ErrNotTS       = errors.New("hlspull: segment is not MPEG-TS")
	ErrNoSegments  = errors.New("hlspull: playlist has no segments")
	maxPlaylist    = int64(4 << 20)
	maxFailures    = 5
	liveEdgeWindow = 3 // segments to start from on first load
)

// Open starts pulling in the background and returns the TS stream. Closing
// the reader (or cancelling ctx) stops the puller.
func Open(ctx context.Context, fetch Fetcher, entry *url.URL) io.ReadCloser {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(run(ctx, fetch, entry, pw))
	}()
	return &reader{pr: pr, cancel: cancel}
}

type reader struct {
	pr     *io.PipeReader
	cancel context.CancelFunc
}

func (r *reader) Read(p []byte) (int, error) { return r.pr.Read(p) }
func (r *reader) Close() error {
	r.cancel()
	return r.pr.Close()
}

type media struct {
	target   time.Duration
	seq      int64
	segments []*url.URL
	ended    bool
}

func run(ctx context.Context, fetch Fetcher, entry *url.URL, w io.Writer) error {
	playlistURL, err := resolveVariant(ctx, fetch, entry)
	if err != nil {
		return err
	}
	var next int64 = -1 // next media sequence number to write
	failures := 0
	for {
		m, err := loadMedia(ctx, fetch, playlistURL)
		if err != nil {
			if errors.Is(err, ErrEncrypted) || errors.Is(err, ErrFMP4) || ctx.Err() != nil {
				return err
			}
			if failures++; failures >= maxFailures {
				return fmt.Errorf("hlspull: playlist unavailable after %d attempts: %w", failures, err)
			}
			if !sleep(ctx, time.Duration(failures)*time.Second) {
				return ctx.Err()
			}
			continue
		}
		failures = 0
		last := m.seq + int64(len(m.segments)) - 1
		if next < 0 || next > last+1 || next < m.seq {
			// First load, or the source restarted / we fell behind the
			// window: rejoin near the live edge.
			next = last - int64(liveEdgeWindow) + 1
			if next < m.seq {
				next = m.seq
			}
		}
		for ; next <= last; next++ {
			if err := copySegment(ctx, fetch, m.segments[next-m.seq], w); err != nil {
				if errors.Is(err, ErrNotTS) || ctx.Err() != nil {
					return err
				}
				// A missing/slow segment: skip it rather than stall the relay.
				continue
			}
		}
		if m.ended {
			return io.EOF
		}
		wait := m.target / 2
		if wait < time.Second {
			wait = time.Second
		}
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func get(ctx context.Context, fetch Fetcher, u *url.URL) (*http.Response, error) {
	resp, err := fetch(ctx, u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("hlspull: HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

// resolveVariant returns the media playlist URL: entry itself, or the
// highest-bandwidth variant of a master playlist.
func resolveVariant(ctx context.Context, fetch Fetcher, entry *url.URL) (*url.URL, error) {
	resp, err := get(ctx, fetch, entry)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	base := entry
	if resp.Request != nil && resp.Request.URL != nil {
		base = resp.Request.URL // after redirects
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxPlaylist))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var best *url.URL
	bestBW := int64(-1)
	pendingBW := int64(-1)
	isMaster := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "#EXT-X-STREAM-INF:"):
			isMaster = true
			pendingBW = attrInt(line, "BANDWIDTH")
		case line != "" && !strings.HasPrefix(line, "#") && pendingBW != -2 && isMaster:
			u, err := base.Parse(line)
			if err == nil && pendingBW > bestBW {
				best, bestBW = u, pendingBW
			}
			pendingBW = -2
		}
	}
	if !isMaster {
		return base, nil
	}
	if best == nil {
		return nil, errors.New("hlspull: master playlist has no variants")
	}
	return best, nil
}

func attrInt(line, key string) int64 {
	i := strings.Index(line, key+"=")
	if i < 0 {
		return 0
	}
	v := line[i+len(key)+1:]
	if j := strings.IndexByte(v, ','); j >= 0 {
		v = v[:j]
	}
	n, _ := strconv.ParseInt(strings.Trim(v, `"`), 10, 64)
	return n
}

func loadMedia(ctx context.Context, fetch Fetcher, u *url.URL) (*media, error) {
	resp, err := get(ctx, fetch, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	base := u
	if resp.Request != nil && resp.Request.URL != nil {
		base = resp.Request.URL
	}
	m := &media{target: 6 * time.Second}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxPlaylist))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "#EXT-X-TARGETDURATION:"):
			if n, err := strconv.Atoi(strings.TrimPrefix(line, "#EXT-X-TARGETDURATION:")); err == nil && n > 0 {
				m.target = time.Duration(n) * time.Second
			}
		case strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"):
			m.seq, _ = strconv.ParseInt(strings.TrimPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"), 10, 64)
		case strings.HasPrefix(line, "#EXT-X-KEY:"):
			if !strings.Contains(line, "METHOD=NONE") {
				return nil, ErrEncrypted
			}
		case strings.HasPrefix(line, "#EXT-X-MAP:"):
			return nil, ErrFMP4
		case line == "#EXT-X-ENDLIST":
			m.ended = true
		case strings.HasPrefix(line, "#EXT-X-STREAM-INF:"):
			return nil, errors.New("hlspull: expected a media playlist, got a master playlist")
		case line != "" && !strings.HasPrefix(line, "#"):
			seg, err := base.Parse(line)
			if err != nil {
				return nil, err
			}
			m.segments = append(m.segments, seg)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(m.segments) == 0 {
		return nil, ErrNoSegments
	}
	return m, nil
}

// copySegment streams one segment into w after checking it really is
// MPEG-TS (sync byte 0x47 at 188-byte packet boundaries).
func copySegment(ctx context.Context, fetch Fetcher, u *url.URL, w io.Writer) error {
	resp, err := get(ctx, fetch, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	head := make([]byte, 188*3+1)
	n, err := io.ReadFull(resp.Body, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	if !looksLikeTS(head[:n]) {
		return ErrNotTS
	}
	if _, err := w.Write(head[:n]); err != nil {
		return err
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func looksLikeTS(b []byte) bool {
	if len(b) < 188 || b[0] != 0x47 {
		return false
	}
	for off := 188; off < len(b); off += 188 {
		if b[off] != 0x47 {
			return false
		}
	}
	return true
}
