// Package slate produces a small, shared HLS error stream. It has its own
// lifecycle and does not consume MPEG-TS remux session slots.
package slate

import (
	"context"
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
	Unavailable = "unavailable"
	Temporary   = "temporarily-unavailable"
	idleTime    = 90 * time.Second
)

// FFmpeg starts at six digits and grows the counter after long runtimes.
var segmentName = regexp.MustCompile(`^seg[0-9]{6,9}\.ts$`)

func ValidName(name string) bool       { return name == "index.m3u8" || segmentName.MatchString(name) }
func ValidVariant(variant string) bool { return variant == Unavailable || variant == Temporary }

// Provider is the gateway's boundary to the FFmpeg-dependent manager. Tests
// supply a fake, so routing and authorization tests never need FFmpeg.
type Provider interface {
	GetPath(variant, name string) (string, error)
	Close()
}

type session struct {
	dir      string
	cancel   context.CancelFunc
	done     chan struct{}
	lastUsed time.Time
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*session
	closed   chan struct{}
	stopped  bool
}

func NewManager() *Manager {
	m := &Manager{sessions: make(map[string]*session), closed: make(chan struct{})}
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

func (m *Manager) GetPath(variant, name string) (string, error) {
	if !ValidVariant(variant) || !ValidName(name) {
		return "", os.ErrNotExist
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return "", errors.New("slate manager closed")
	}
	s := m.sessions[variant]
	if s != nil {
		select {
		case <-s.done:
			delete(m.sessions, variant)
			_ = os.RemoveAll(s.dir)
			s = nil
		default:
		}
	}
	if s == nil {
		var err error
		s, err = m.startLocked(variant)
		if err != nil {
			m.mu.Unlock()
			return "", err
		}
		m.sessions[variant] = s
	}
	s.lastUsed = time.Now()
	p := filepath.Join(s.dir, name)
	m.mu.Unlock()

	if name == "index.m3u8" {
		deadline := time.NewTimer(12 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
			select {
			case <-s.done:
				return "", errors.New("slate encoder exited before writing a playlist")
			case <-deadline.C:
				return "", errors.New("slate playlist startup timed out")
			case <-tick.C:
			}
		}
	}
	return p, nil
}

func (m *Manager) startLocked(variant string) (*session, error) {
	dir, err := os.MkdirTemp("", "streamvault-slate-")
	if err != nil {
		return nil, err
	}
	message := "Stream unavailable.\nThis access URL has been revoked."
	if variant == Temporary {
		message = "Stream temporarily unavailable.\nPlease try again shortly."
	}
	textfile := filepath.Join(dir, "message.txt")
	if err := os.WriteFile(textfile, []byte(message), 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	font := ""
	for _, candidate := range []string{
		"/usr/share/fonts/ttf-dejavu/DejaVuSans.ttf",      // Alpine image
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", // Debian development host
	} {
		if _, err := os.Stat(candidate); err == nil {
			font = candidate
			break
		}
	}
	if font == "" {
		cancel()
		os.RemoveAll(dir)
		return nil, errors.New("slate font unavailable")
	}
	filter := fmt.Sprintf("drawtext=fontfile=%s:textfile=%s:fontcolor=white:fontsize=28:line_spacing=12:x=(w-text_w)/2:y=(h-text_h)/2", font, textfile)
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
		"-f", "lavfi", "-i", "color=c=0x101827:s=854x480:r=5",
		"-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo",
		"-vf", filter, "-map", "0:v:0", "-map", "1:a:0",
		"-c:v", "libx264", "-preset", "ultrafast", "-tune", "stillimage",
		"-crf", "32", "-pix_fmt", "yuv420p", "-r", "5", "-g", "10", "-keyint_min", "10", "-sc_threshold", "0",
		"-c:a", "aac", "-b:a", "48k", "-ar", "48000", "-ac", "2", "-threads", "1",
		"-f", "hls", "-hls_time", "2", "-hls_list_size", "6",
		"-hls_flags", "delete_segments+omit_endlist+temp_file",
		"-hls_segment_filename", filepath.Join(dir, "seg%06d.ts"), filepath.Join(dir, "index.m3u8"))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("starting slate ffmpeg: %w", err)
	}
	s := &session{dir: dir, cancel: cancel, done: make(chan struct{}), lastUsed: time.Now()}
	go func() { _ = cmd.Wait(); close(s.done) }()
	return s, nil
}

func (m *Manager) ReapIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for variant, s := range m.sessions {
		if time.Since(s.lastUsed) <= idleTime {
			continue
		}
		delete(m.sessions, variant)
		s.cancel()
		go func() { <-s.done; _ = os.RemoveAll(s.dir) }()
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	close(m.closed)
	sessions := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
		s.cancel()
	}
	m.sessions = nil
	m.mu.Unlock()
	for _, s := range sessions {
		<-s.done
		_ = os.RemoveAll(s.dir)
	}
}
