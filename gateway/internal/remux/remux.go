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
	"sync"
	"time"
)

const (
	maxSessions = 2
	idleTime    = 90 * time.Second
)

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
}

type Manager struct {
	mu       sync.Mutex
	sessions map[int64]*Session
	byID     map[string]*Session
	closed   chan struct{}
	slots    chan struct{}
}

func NewManager() *Manager {
	m := &Manager{sessions: make(map[int64]*Session), byID: make(map[string]*Session), closed: make(chan struct{}), slots: make(chan struct{}, maxSessions)}
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
	defer m.mu.Unlock()
	if s := m.sessions[streamID]; s != nil {
		if s.Signature == signature {
			if _, err := os.Stat(filepath.Join(s.Dir, "index.m3u8")); err == nil {
				s.lastUsed = time.Now()
				return s, nil
			}
			select {
			case <-s.done:
				m.stopLocked(s)
			default:
				s.lastUsed = time.Now()
				return s, nil
			}
		} else {
			m.stopLocked(s)
		}
	}
	select {
	case m.slots <- struct{}{}:
	default:
		return nil, errors.New("remux session limit reached")
	}
	started := false
	defer func() {
		if !started {
			<-m.slots
		}
	}()
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes[:])
	dir, err := os.MkdirTemp("", "streamvault-remux-")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	body, err := open(ctx)
	if err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error",
		"-f", "mpegts", "-i", "pipe:0", "-map", "0:v?", "-map", "0:a?", "-c", "copy",
		"-f", "hls", "-hls_time", "2", "-hls_list_size", "8",
		"-hls_flags", "delete_segments+omit_endlist",
		"-hls_segment_filename", filepath.Join(dir, "seg%06d.ts"), filepath.Join(dir, "index.m3u8"))
	cmd.Stdin = body
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		body.Close()
		cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("starting ffmpeg: %w", err)
	}
	started = true
	s := &Session{ID: id, StreamID: streamID, Signature: signature, Dir: dir, cmd: cmd, cancel: cancel, lastUsed: time.Now(), done: make(chan struct{})}
	m.sessions[streamID] = s
	m.byID[id] = s
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
	for _, s := range m.sessions {
		m.stopLocked(s)
	}
	m.mu.Unlock()
}

func (m *Manager) watch(s *Session, body io.ReadCloser) {
	_ = s.cmd.Wait()
	<-m.slots
	_ = body.Close()
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
		if time.Since(s.lastUsed) > idleTime {
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
