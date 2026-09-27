// Package remux owns short-lived FFmpeg MPEG-TS to HLS sessions. A session is
// shared by viewers of one stream; FFmpeg copies codecs and writes a small
// rotating HLS window into a private temporary directory.
package remux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	defaultSlots = 2
	idleTime     = 90 * time.Second
)

// slotsFromEnv: STREAMVAULT_REMUX_SLOTS (1..16), default 2. Always-on relays
// hold slots permanently, so a host that runs them may want more.
func slotsFromEnv() int {
	if n, err := strconv.Atoi(os.Getenv("STREAMVAULT_REMUX_SLOTS")); err == nil && n >= 1 && n <= 16 {
		return n
	}
	return defaultSlots
}

var segmentName = regexp.MustCompile(`^seg[0-9]{6}\.ts$`)

type Session struct {
	ID        string
	StreamID  int64
	Signature string
	Dir       string
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	lastUsed  time.Time
	done      chan struct{}
	pinned    bool // always-on relay: never idle-reaped
}

type Manager struct {
	mu       sync.Mutex
	sessions map[int64]*Session
	byID     map[string]*Session
	pending  map[int64]map[*pendingOpen]struct{}
	closed   chan struct{}
	slots    chan struct{}
}

type pendingOpen struct{ cancel context.CancelFunc }

type closeOnceReadCloser struct {
	io.ReadCloser
	once sync.Once
}

func (r *closeOnceReadCloser) Close() error {
	var err error
	r.once.Do(func() { err = r.ReadCloser.Close() })
	return err
}

// Slots is the total number of concurrent remux/relay sessions.
func (m *Manager) Slots() int { return cap(m.slots) }

// SetPinned marks the stream's current session as an always-on relay (never
// idle-reaped) or returns it to normal idle handling. False if none runs.
func (m *Manager) SetPinned(streamID int64, pinned bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[streamID]
	if s == nil {
		return false
	}
	s.pinned = pinned
	s.lastUsed = time.Now()
	return true
}

// Pinned lists stream IDs with a pinned session and whether it is alive.
func (m *Manager) Pinned() map[int64]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]bool{}
	for id, s := range m.sessions {
		if !s.pinned {
			continue
		}
		alive := true
		select {
		case <-s.done:
			alive = false
		default:
		}
		out[id] = alive
	}
	return out
}

// Current returns the stream's session regardless of signature (nil if none).
// Relay nodes use it to serve their pinned relays.
func (m *Manager) Current(streamID int64) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[streamID]
}

// Stop ends a stream's session (used when an always-on relay must restart).
func (m *Manager) Stop(streamID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for p := range m.pending[streamID] {
		p.cancel()
	}
	if s := m.sessions[streamID]; s != nil {
		m.stopLocked(s)
	}
}

func NewManager() *Manager {
	m := &Manager{sessions: make(map[int64]*Session), byID: make(map[string]*Session), pending: make(map[int64]map[*pendingOpen]struct{}), closed: make(chan struct{}), slots: make(chan struct{}, slotsFromEnv())}
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				m.ReapIdle()
			case <-m.closed:
				return
			}
		}
	}()
	return m
}

func (m *Manager) Existing(streamID int64, signature string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[streamID]
	if s == nil || s.Signature != signature {
		return nil
	}
	select {
	case <-s.done:
		if _, err := os.Stat(filepath.Join(s.Dir, "index.m3u8")); err != nil {
			m.stopLocked(s)
			return nil
		}
	default:
	}
	s.lastUsed = time.Now()
	return s
}

// Start creates at most one process per stream. open supplies a fresh HTTP
// source body whose lifetime belongs to the session, independent of the
// manifest request that triggered format detection.
func (m *Manager) Start(streamID int64, signature string, open func(context.Context) (io.ReadCloser, error)) (*Session, error) {
	m.mu.Lock()
	select {
	case <-m.closed:
		m.mu.Unlock()
		return nil, errors.New("remux manager closed")
	default:
	}
	if s := m.sessions[streamID]; s != nil {
		if s.Signature == signature {
			if _, err := os.Stat(filepath.Join(s.Dir, "index.m3u8")); err == nil {
				s.lastUsed = time.Now()
				m.mu.Unlock()
				return s, nil
			}
			select {
			case <-s.done:
				m.stopLocked(s)
			default:
				s.lastUsed = time.Now()
				m.mu.Unlock()
				return s, nil
			}
		} else {
			m.stopLocked(s)
		}
	}
	select {
	case m.slots <- struct{}{}:
	default:
		m.mu.Unlock()
		return nil, errors.New("remux session limit reached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &pendingOpen{cancel: cancel}
	if m.pending[streamID] == nil {
		m.pending[streamID] = make(map[*pendingOpen]struct{})
	}
	m.pending[streamID][p] = struct{}{}
	m.mu.Unlock()

	started := false
	var body io.ReadCloser
	var dir string
	defer func() {
		m.mu.Lock()
		delete(m.pending[streamID], p)
		if len(m.pending[streamID]) == 0 {
			delete(m.pending, streamID)
		}
		m.mu.Unlock()
		if !started {
			cancel()
			if body != nil {
				_ = body.Close()
			}
			if dir != "" {
				_ = os.RemoveAll(dir)
			}
			<-m.slots
		}
	}()
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes[:])
	var err error
	dir, err = os.MkdirTemp("", "streamvault-remux-")
	if err != nil {
		return nil, err
	}
	body, err = open(ctx)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, errors.New("remux source returned no body")
	}
	body = &closeOnceReadCloser{ReadCloser: body}
	m.mu.Lock()
	select {
	case <-ctx.Done():
		m.mu.Unlock()
		return nil, errors.New("remux start cancelled")
	case <-m.closed:
		m.mu.Unlock()
		return nil, errors.New("remux manager closed")
	default:
	}
	if s := m.sessions[streamID]; s != nil {
		// Another opener won this stream while this one was fetching.
		s.lastUsed = time.Now()
		m.mu.Unlock()
		return s, nil
	}
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error",
		"-f", "mpegts", "-i", "pipe:0", "-map", "0:v?", "-map", "0:a?", "-c", "copy",
		"-f", "hls", "-hls_time", "2", "-hls_list_size", "8",
		"-hls_flags", "delete_segments+omit_endlist",
		"-hls_segment_filename", filepath.Join(dir, "seg%06d.ts"), filepath.Join(dir, "index.m3u8"))
	cmd.Stdin = body
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("starting ffmpeg: %w", err)
	}
	context.AfterFunc(ctx, func() { _ = body.Close() })
	started = true
	s := &Session{ID: id, StreamID: streamID, Signature: signature, Dir: dir, cmd: cmd, cancel: cancel, lastUsed: time.Now(), done: make(chan struct{})}
	m.sessions[streamID] = s
	m.byID[id] = s
	m.mu.Unlock()
	go m.watch(s, body)
	return s, nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	for _, opens := range m.pending {
		for p := range opens {
			p.cancel()
		}
	}
	for _, s := range m.sessions {
		m.stopLocked(s)
	}
	m.mu.Unlock()
}

func (m *Manager) watch(s *Session, body io.ReadCloser) {
	_ = s.cmd.Wait()
	s.cancel()
	_ = body.Close()
	<-m.slots
	close(s.done)
	// Keep completed segments available until idle expiry: a finite TS input
	// may finish before the client has requested its first segment.
}

func (m *Manager) stopLocked(s *Session) {
	delete(m.sessions, s.StreamID)
	delete(m.byID, s.ID)
	s.cancel()
	go func() {
		<-s.done
		_ = os.RemoveAll(s.Dir)
	}()
}

// GetPath only exposes the generated playlist and segment filenames. The
// caller must already have validated its access point and bearer token.
func (m *Manager) GetPath(streamID int64, id, name string) (string, bool) {
	if name != "index.m3u8" && !segmentName.MatchString(name) {
		return "", false
	}
	m.mu.Lock()
	s := m.byID[id]
	if s == nil || s.StreamID != streamID {
		m.mu.Unlock()
		return "", false
	}
	s.lastUsed = time.Now()
	p := filepath.Join(s.Dir, name)
	m.mu.Unlock()
	return p, true
}

// WaitPlaylist waits for FFmpeg's first completed HLS segment. FFmpeg writes
// the manifest atomically, so a visible file is ready to parse.
func (m *Manager) WaitPlaylist(s *Session) (string, error) {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if p, ok := m.GetPath(s.StreamID, s.ID, "index.m3u8"); ok {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
		select {
		case <-s.done:
			if p, ok := m.GetPath(s.StreamID, s.ID, "index.m3u8"); ok {
				if _, err := os.Stat(p); err == nil {
					return p, nil
				}
			}
			return "", errors.New("ffmpeg exited before creating a playlist")
		case <-deadline.C:
			return "", errors.New("timed out waiting for first HLS segment")
		case <-tick.C:
		}
	}
}

// ReapIdle is called by the manager's low-frequency housekeeping ticker.
func (m *Manager) ReapIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if !s.pinned && time.Since(s.lastUsed) > idleTime {
			m.stopLocked(s)
		}
	}
}

// LooksLikeMPEGTS checks sync bytes across packets, allowing a small leading
// offset as seen with some HTTP sources. MIME alone is too often inaccurate.
func LooksLikeMPEGTS(b []byte) bool {
	for off := 0; off < 188 && off+376 < len(b); off++ {
		if b[off] == 0x47 && b[off+188] == 0x47 && b[off+376] == 0x47 {
			return true
		}
	}
	return false
}
