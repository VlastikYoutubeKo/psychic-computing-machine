package gatewayhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"streamvault/gateway/internal/hls"
	"streamvault/gateway/internal/hlspull"
	"streamvault/gateway/internal/remux"
	"streamvault/gateway/internal/store"
)

// Always-on relays keep one pinned remux session per flagged stream, so the
// first viewer joins a stream that is already running (no cold tuner, no
// ffmpeg start-up) and the source sees one connection instead of one per
// viewer. HLS sources are pulled by hlspull and MPEG-TS sources piped
// directly; both go through the same ffmpeg -c copy HLS output that
// on-demand remux uses, so serveEntry finds them via Remux.Existing.

const (
	alwaysOnMinBackoff = 30 * time.Second
	alwaysOnMaxBackoff = 10 * time.Minute
)

// RelayStore is where the supervisor gets its streams and reports state:
// the database on the control gateway, an in-memory list fed by the control
// plane's config on a relay node (internal/node).
type RelayStore interface {
	AlwaysOnStreams() ([]store.Stream, error)
	SetRuntime(streamID int64, state, detail string) error
	ClearRuntime(keep []int64) error
}

func (h *Handler) relayStore() RelayStore {
	if h.Relays != nil {
		return h.Relays
	}
	return h.Store
}

// A relay must stay up this long before its failure count resets; a source
// that only survives long enough to produce a first playlist would otherwise
// be restarted every reconcile interval, bypassing the backoff.
var alwaysOnMinHealthy = 2 * time.Minute

type alwaysOnState struct {
	failures     int
	nextTry      time.Time
	runningSince time.Time
}

func (st *alwaysOnState) fail() time.Duration {
	st.failures++
	backoff := alwaysOnMinBackoff << (st.failures - 1)
	if backoff > alwaysOnMaxBackoff || backoff <= 0 {
		backoff = alwaysOnMaxBackoff
	}
	st.nextTry = time.Now().Add(backoff)
	st.runningSince = time.Time{}
	return backoff
}

// RunAlwaysOn reconciles relays every interval until ctx ends.
func (h *Handler) RunAlwaysOn(ctx context.Context, interval time.Duration) {
	states := map[int64]*alwaysOnState{}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		h.reconcileAlwaysOn(ctx, states)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (h *Handler) reconcileAlwaysOn(ctx context.Context, states map[int64]*alwaysOnState) {
	streams, err := h.relayStore().AlwaysOnStreams()
	if err != nil {
		log.Printf("always-on: loading streams: %v", err)
		return
	}
	// Leave at least one slot for on-demand remux viewers.
	maxRelays := h.Remux.Slots() - 1
	if maxRelays < 1 {
		maxRelays = 1
	}
	want := map[int64]store.Stream{}
	keep := make([]int64, 0, len(streams))
	for _, st := range streams {
		keep = append(keep, st.ID)
		if len(want) >= maxRelays {
			h.setRuntime(st.ID, "error", fmt.Sprintf("no free relay slot (%d of %d used; raise STREAMVAULT_REMUX_SLOTS)", maxRelays, h.Remux.Slots()))
			continue
		}
		want[st.ID] = st
	}

	pinned := h.Remux.Pinned()
	for id := range pinned {
		if _, ok := want[id]; !ok {
			h.Remux.SetPinned(id, false) // back to normal idle handling
			delete(states, id)
		}
	}

	for id, st := range want {
		if ctx.Err() != nil {
			return
		}
		stt := states[id]
		if stt == nil {
			stt = &alwaysOnState{}
			states[id] = stt
		}
		if alive, ok := pinned[id]; ok && !alive {
			h.Remux.Stop(id) // relay process ended (source dropped)
			if !stt.runningSince.IsZero() && time.Since(stt.runningSince) < alwaysOnMinHealthy {
				ran := time.Since(stt.runningSince).Round(time.Second)
				backoff := stt.fail()
				log.Printf("always-on: stream %d relay exited after %s; retry in %s", id, ran, backoff)
				h.setRuntime(id, "backoff", fmt.Sprintf("relay exited after %s; retrying in %s", ran, backoff.Round(time.Second)))
				continue
			}
			stt.runningSince = time.Time{}
		}
		sig := sourceSignature(st)
		if h.Remux.Existing(id, sig) != nil {
			h.Remux.SetPinned(id, true)
			if !stt.runningSince.IsZero() && time.Since(stt.runningSince) >= alwaysOnMinHealthy {
				stt.failures, stt.nextTry = 0, time.Time{} // proven healthy
			}
			h.setRuntime(id, "running", "")
			continue
		}
		if time.Now().Before(stt.nextTry) {
			continue
		}
		h.setRuntime(id, "starting", "")
		err := h.startRelay(st, sig)
		if err != nil {
			backoff := stt.fail()
			reason := relayFailureReason(err)
			log.Printf("always-on: stream %d relay failed (%s); retry in %s", id, reason, backoff)
			h.setRuntime(id, "backoff", fmt.Sprintf("%s; retrying in %s", reason, backoff.Round(time.Second)))
			continue
		}
		// Failure count is kept until the relay has run alwaysOnMinHealthy.
		stt.nextTry, stt.runningSince = time.Time{}, time.Now()
		log.Printf("always-on: stream %d relay running", id)
		h.setRuntime(id, "running", "")
	}
	if err := h.relayStore().ClearRuntime(keep); err != nil {
		log.Printf("always-on: clearing runtime rows: %v", err)
	}
}

func (h *Handler) setRuntime(id int64, state, detail string) {
	if err := h.relayStore().SetRuntime(id, state, detail); err != nil {
		log.Printf("always-on: recording state for stream %d: %v", id, err)
	}
}

func (h *Handler) startRelay(st store.Stream, sig string) error {
	s, err := h.Remux.Start(st.ID, sig, func(sctx context.Context) (io.ReadCloser, error) {
		return h.openRelaySource(sctx, st)
	})
	if err != nil {
		return err
	}
	if _, err := h.Remux.WaitPlaylist(s); err != nil {
		h.Remux.Stop(st.ID)
		return err
	}
	h.Remux.SetPinned(st.ID, true)
	return nil
}

// openRelaySource fetches the source once through the gateway's normal fetch
// path (SSRF policy, credentials, redirect checks), sniffs it, and returns a
// continuous MPEG-TS stream for ffmpeg: the body itself for TS sources, or an
// hlspull stream for HLS sources.
func (h *Handler) openRelaySource(ctx context.Context, st store.Stream) (io.ReadCloser, error) {
	entry, err := url.Parse(st.SourceURL)
	if err != nil {
		return nil, fmt.Errorf("unparsable source URL")
	}
	private := h.isSourcePrivate(ctx, st, entry)
	resp, err := h.fetchWithHeaderTimeout(ctx, entry, st, private, 0, entryHeaderTimeout)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	head := make([]byte, sniffLimit)
	n, _ := io.ReadFull(resp.Body, head)
	head = head[:n]
	if remux.LooksLikeMPEGTS(head) {
		return &prefixedReadCloser{prefix: head, r: resp.Body, closer: resp.Body}, nil
	}
	resp.Body.Close()
	if !hls.IsPlaylist(head) {
		return nil, errors.New("source is neither MPEG-TS nor an HLS playlist")
	}
	fetch := func(fctx context.Context, target *url.URL) (*http.Response, error) {
		if err := checkFetchTarget(fctx, h.Resolve, target, private); err != nil {
			return nil, fmt.Errorf("%w: %v", errBlockedTarget, err)
		}
		return h.fetch(fctx, target, st, private, 20*time.Second)
	}
	return hlspull.Open(ctx, fetch, resp.Request.URL), nil
}

// relayFailureReason is URL-free (the source URL can carry secrets).
func relayFailureReason(err error) string {
	switch {
	case errors.Is(err, hlspull.ErrEncrypted):
		return "encrypted HLS is not supported for always-on"
	case errors.Is(err, hlspull.ErrFMP4):
		return "fMP4 HLS is not supported for always-on"
	case errors.Is(err, hlspull.ErrNotTS):
		return "source segments are not MPEG-TS"
	}
	msg := err.Error()
	for _, safe := range []string{"remux session limit reached", "timed out waiting for first HLS segment", "ffmpeg exited before creating a playlist", "source returned HTTP", "source is neither", "unparsable source URL"} {
		if strings.Contains(msg, safe) {
			return msg
		}
	}
	return fetchFailureKind(err)
}
