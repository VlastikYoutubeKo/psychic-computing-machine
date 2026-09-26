// Package slate produces shared HLS error streams from pre-rendered artwork.
package slate

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Unavailable    = "unavailable"
	Temporary      = "temporarily-unavailable"
	idleTime       = 90 * time.Second
	restartBackoff = 10 * time.Second
	shortLived     = 30 * time.Second
	maxPersonal    = 3
	// Each 1080p slate ffmpeg is ~130 MiB RSS and ~9% of a core; this host
	// also runs MariaDB under a 5G cgroup cap, so keep the worst case ~530 MiB.
	maxProcesses = 4
)

var segmentName = regexp.MustCompile(`^seg[0-9]{6,9}\.ts$`)
var opaqueKey = regexp.MustCompile(`^[0-9a-f]{40}$`)
var audioName = regexp.MustCompile(`^[0-9a-f]{32}\.(mp3|ogg|opus|flac|aac|m4a|wav)$`)

func ValidName(n string) bool    { return n == "index.m3u8" || segmentName.MatchString(n) }
func ValidVariant(v string) bool { _, _, ok := splitVariant(v); return ok }
func ValidKey(k string) bool     { return opaqueKey.MatchString(k) }
func splitVariant(v string) (base, reason string, ok bool) {
	parts := strings.SplitN(v, ":", 2)
	base = parts[0]
	if base != Unavailable && base != Temporary {
		return "", "", false
	}
	reason = "unauthorized_redistribution"
	if base == Temporary {
		reason = TemporaryReason
	}
	if len(parts) == 2 {
		reason = parts[1]
	}
	if !ValidReason(reason) || base == Temporary && reason != TemporaryReason || base == Unavailable && reason == TemporaryReason {
		return "", "", false
	}
	return base, reason, true
}

// An empty key denotes a generic variant. HTTP tests replace this provider.
type Provider interface {
	GetPath(variant, key, name string) (string, error)
	Prepare(variant string, apID, tokenID int64, cutoff time.Time) string
	Close()
}
type AudioSettings struct {
	File, URL string
	Volume    int
}
type AudioLoader func() (AudioSettings, error)
type descriptor struct {
	variant       string
	apID, tokenID int64
	cutoff        time.Time
	lastUsed      time.Time
}
type session struct {
	started   time.Time
	dir       string
	cancel    context.CancelFunc
	done      chan struct{}
	lastUsed  time.Time
	usedRadio bool
	// The audio settings as configured when this session started (not the
	// effective ones: a muted radio fallback still records the radio), so a
	// settings change can restart it without a failing radio restart-looping.
	audio    AudioSettings
	hasAudio bool
	text     Text
	hasText  bool
}
type Manager struct {
	mu              sync.Mutex
	secret          [32]byte
	sessions        map[string]*session
	personal        map[string]descriptor
	failedAt        map[string]time.Time
	radioMuted      map[string]time.Time
	closed          chan struct{}
	stopped         bool
	assets, dataDir string
	loadAudio       AudioLoader
	loadText        func(string) (Text, error)
	fallbacks       map[string]string
}

func NewManager() *Manager {
	m := &Manager{sessions: map[string]*session{}, personal: map[string]descriptor{}, failedAt: map[string]time.Time{}, radioMuted: map[string]time.Time{}, fallbacks: map[string]string{}, closed: make(chan struct{}), assets: os.Getenv("STREAMVAULT_SLATE_ASSETS")}
	if m.assets == "" {
		m.assets = "../../assets/slate"
	}
	if _, err := rand.Read(m.secret[:]); err != nil {
		panic("slate HMAC random source unavailable")
	}
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				m.ReapIdle()
				m.RestartOnAudioChange()
			case <-m.closed:
				return
			}
		}
	}()
	return m
}
func (m *Manager) ConfigureAudio(loader AudioLoader, dataDir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadAudio = loader
	m.dataDir = dataDir
}
func (m *Manager) ConfigureText(loader func(string) (Text, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadText = loader
}
func (m *Manager) signature(d descriptor) string {
	mac := hmac.New(sha256.New, m.secret[:])
	_, _ = fmt.Fprintf(mac, "%s|%d|%d|%s", d.variant, d.apID, d.tokenID, d.cutoff.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(mac.Sum(nil)[:20])
}

// Prepare allocates a shared personal slot; callers fall back to generic on cap.
func (m *Manager) Prepare(variant string, apID, tokenID int64, cutoff time.Time) string {
	if !ValidVariant(variant) || apID <= 0 || cutoff.IsZero() {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return ""
	}
	d := descriptor{variant: variant, apID: apID, tokenID: tokenID, cutoff: cutoff, lastUsed: time.Now()}
	key := m.signature(d)
	if old, ok := m.personal[key]; ok {
		old.lastUsed = time.Now()
		m.personal[key] = old
		return key
	}
	if len(m.personal) >= maxPersonal {
		return ""
	}
	m.personal[key] = d
	return key
}
func (m *Manager) GetPath(variant, key, name string) (string, error) {
	if !ValidVariant(variant) || !ValidName(name) || (key != "" && !ValidKey(key)) {
		return "", os.ErrNotExist
	}
	id := variant
	var d descriptor
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return "", errors.New("slate manager closed")
	}
	if key != "" {
		var ok bool
		d, ok = m.personal[key]
		if !ok || d.variant != variant || !hmac.Equal([]byte(key), []byte(m.signature(d))) {
			m.mu.Unlock()
			return "", os.ErrNotExist
		}
		d.lastUsed = time.Now()
		m.personal[key] = d
		id = variant + "/" + key
	}
	s := m.sessions[id]
	actualID := id
	if s == nil {
		if target := m.fallbacks[id]; target != "" {
			if len(m.sessions) < 6 {
				delete(m.fallbacks, id)
			} else {
				s = m.sessions[target]
				actualID = target
				if s == nil {
					delete(m.fallbacks, id)
				}
			}
		}
	}
	if s != nil {
		select {
		case <-s.done:
			if s.usedRadio {
				m.radioMuted[actualID] = time.Now().Add(5 * time.Minute)
				delete(m.failedAt, actualID) // restart immediately with silence
			} else if time.Since(s.started) < shortLived {
				m.failedAt[actualID] = time.Now()
			}
			delete(m.sessions, actualID)
			delete(m.fallbacks, id)
			_ = os.RemoveAll(s.dir)
			s = nil
		default:
		}
	}
	if s == nil {
		if t, ok := m.failedAt[id]; ok && time.Since(t) < restartBackoff {
			m.mu.Unlock()
			return "", errors.New("slate encoder backing off")
		}
		if len(m.sessions) >= maxProcesses {
			base, _, _ := splitVariant(variant)
			for target, candidate := range m.sessions {
				cbase, _, _ := splitVariant(strings.SplitN(target, "/", 2)[0])
				if !strings.Contains(target, "/") && cbase == base {
					s = candidate
					m.fallbacks[id] = target
					break
				}
			}
			if s == nil {
				for target, candidate := range m.sessions {
					if !strings.Contains(target, "/") {
						s = candidate
						m.fallbacks[id] = target
						break
					}
				}
			}
			if s == nil {
				m.mu.Unlock()
				return "", errors.New("slate session cap reached")
			}
		}
		if s == nil {
			var err error
			s, err = m.startLocked(variant, d, time.Now().Before(m.radioMuted[id]))
			if err != nil {
				m.failedAt[id] = time.Now()
				m.mu.Unlock()
				return "", err
			}
			m.sessions[id] = s
		}
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
				if s.usedRadio {
					return m.GetPath(variant, key, name)
				}
				return "", errors.New("slate encoder exited before playlist")
			case <-deadline.C:
				if s.usedRadio {
					s.cancel()
					<-s.done
					return m.GetPath(variant, key, name)
				}
				return "", errors.New("slate playlist startup timeout")
			case <-tick.C:
			}
		}
	}
	return p, nil
}
func fontPath() (string, error) {
	for _, p := range []string{"/usr/local/share/streamvault/fonts/DejaVuSans.ttf", "../../assets/fonts/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("slate font unavailable")
}
func writeCutoff(dir string, t time.Time) (string, error) {
	p := filepath.Join(dir, "cutoff.txt")
	loc, err := time.LoadLocation("Europe/Prague")
	if err != nil {
		return "", err
	}
	err = os.WriteFile(p, []byte("Cut off: "+t.In(loc).Format("02.01.2006 15:04")), 0600)
	return p, err
}
func audioArgs(a AudioSettings, dataDir string) ([]string, bool, error) {
	if a.Volume < 0 || a.Volume > 100 {
		return nil, false, errors.New("invalid volume")
	}
	if a.Volume == 0 || a.File == "" && a.URL == "" {
		return []string{"-re", "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo"}, false, nil
	}
	if a.File != "" {
		if filepath.Base(a.File) != a.File || !audioName.MatchString(a.File) {
			return nil, false, errors.New("invalid audio filename")
		}
		return []string{"-re", "-stream_loop", "-1", "-i", filepath.Join(dataDir, "slate-audio", a.File)}, false, nil
	}
	if err := validateAudioURL(a.URL); err != nil {
		return nil, false, err
	}
	return []string{"-reconnect", "1", "-reconnect_streamed", "1", "-reconnect_delay_max", "5", "-reconnect_max_retries", "3", "-rw_timeout", "5000000", "-max_redirects", "0", "-protocol_whitelist", "http,https,tcp,tls", "-i", a.URL}, true, nil
}
func validateAudioURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil {
		return errors.New("invalid radio URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return errors.New("radio host could not be resolved")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return errors.New("radio host resolves to private address")
		}
	}
	return nil
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 0 || b[0] == 100 && b[1] >= 64 && b[1] <= 127 || b[0] >= 224 {
			return false
		}
	}
	return true
}
func (m *Manager) startLocked(variant string, d descriptor, forceSilent bool) (*session, error) {
	dir, err := os.MkdirTemp("", "streamvault-slate-")
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*session, error) { _ = os.RemoveAll(dir); return nil, e }
	base, reason, _ := splitVariant(variant)
	font, err := fontPath()
	if err != nil {
		return fail(err)
	}
	asset := filepath.Join(m.assets, base+".mp4")
	if _, err = os.Stat(asset); err != nil {
		return fail(err)
	}
	copy := DefaultText(reason)
	if m.loadText != nil {
		if loaded, e := m.loadText(reason); e == nil {
			if clean, e := NormalizeText(loaded); e == nil {
				copy = clean
			}
		}
	}
	titleFile := filepath.Join(dir, "title.txt")
	subtitleFile := filepath.Join(dir, "subtitle.txt")
	wrapped := wrapSubtitle(copy.Subtitle)
	if e := os.WriteFile(titleFile, []byte(copy.Title), 0600); e != nil {
		return fail(e)
	}
	if e := os.WriteFile(subtitleFile, []byte(wrapped), 0600); e != nil {
		return fail(e)
	}
	bold := filepath.Join(filepath.Dir(font), "DejaVuSans-Bold.ttf")
	if _, e := os.Stat(bold); e != nil {
		return fail(e)
	}
	// Only file paths and fixed expressions enter the filter graph.
	filter := "drawtext=fontfile=" + bold + ":textfile=" + titleFile + ":fontcolor=0xedf3ff:fontsize=" + strconv.Itoa(fitFontSize(copy.Title, 117)) + ":x=432:y=360"
	filter += ",drawtext=fontfile=" + font + ":textfile=" + subtitleFile + ":fontcolor=0xa8b7d0:fontsize=" + strconv.Itoa(fitFontSize(wrapped, 47)) + ":line_spacing=12:x=432:y=515"
	filter += ",drawtext=fontfile=" + font + ":text='%{localtime\\:%d.%m.%Y %H\\\\\\:%M\\\\\\:%S}':fontcolor=0xedf3ff:fontsize=46:x=153:y=903"
	if !d.cutoff.IsZero() {
		p, e := writeCutoff(dir, d.cutoff)
		if e != nil {
			return fail(e)
		}
		filter += ",drawtext=fontfile=" + font + ":textfile=" + p + ":fontcolor=0xa8b7d0:fontsize=38:x=153:y=968"
	}
	a, configured, hasConfigured := AudioSettings{}, AudioSettings{}, false
	if m.loadAudio != nil {
		if loaded, e := m.loadAudio(); e == nil {
			configured, hasConfigured = loaded, true
			if !forceSilent {
				a = loaded
			}
		}
	}
	audio, radio, e := audioArgs(a, m.dataDir)
	if e != nil {
		a = AudioSettings{}
		audio, radio, _ = audioArgs(a, m.dataDir)
	}
	args := []string{"-hide_banner", "-loglevel", "error", "-nostdin", "-re", "-stream_loop", "-1", "-i", asset}
	args = append(args, audio...)
	args = append(args, "-vf", filter, "-map", "0:v:0", "-map", "1:a:0", "-c:v", "libx264", "-preset", "ultrafast", "-tune", "stillimage", "-crf", "30", "-pix_fmt", "yuv420p", "-r", "10", "-g", "20", "-keyint_min", "20", "-sc_threshold", "0", "-c:a", "aac", "-b:a", "48k", "-ar", "48000", "-ac", "2", "-af", "volume="+strconv.FormatFloat(float64(a.Volume)/100, 'f', 2, 64), "-threads", "1", "-f", "hls", "-hls_time", "2", "-hls_list_size", "6", "-hls_flags", "delete_segments+omit_endlist+temp_file", "-hls_segment_filename", filepath.Join(dir, "seg%06d.ts"), filepath.Join(dir, "index.m3u8"))
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	cmd.Env = append(os.Environ(), "TZ=Europe/Prague")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		cancel()
		return fail(fmt.Errorf("starting slate ffmpeg: %w", err))
	}
	s := &session{started: time.Now(), dir: dir, cancel: cancel, done: make(chan struct{}), lastUsed: time.Now(), usedRadio: radio, audio: configured, hasAudio: hasConfigured, text: copy, hasText: true}
	go func() { _ = cmd.Wait(); close(s.done) }()
	return s, nil
}
func (m *Manager) ReapIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if time.Since(s.lastUsed) <= idleTime {
			continue
		}
		s.cancel()
		<-s.done // Keep the process in the six-slot count until it exits.
		delete(m.sessions, id)
		_ = os.RemoveAll(s.dir)
	}
	for key, d := range m.personal {
		if time.Since(d.lastUsed) > idleTime {
			delete(m.personal, key)
		}
	}
}

// RestartOnAudioChange stops sessions whose audio settings differ from the
// current ones; the next playlist request starts them again with the new
// audio (viewers see a brief hiccup). Runs on the reaper tick, so a change in
// the admin applies within ~30 s instead of only after the session idles out.
func (m *Manager) RestartOnAudioChange() {
	m.mu.Lock()
	load := m.loadAudio
	m.mu.Unlock()
	cur := AudioSettings{}
	if load != nil {
		var err error
		cur, err = load()
		if err != nil {
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		textChanged := false
		if m.loadText != nil && s.hasText {
			_, reason, ok := splitVariant(strings.SplitN(id, "/", 2)[0])
			if ok {
				if current, e := m.loadText(reason); e == nil {
					if clean, e := NormalizeText(current); e == nil && clean != s.text {
						textChanged = true
					}
				}
			}
		}
		if (load == nil || !s.hasAudio || s.audio == cur) && !textChanged {
			continue
		}
		s.cancel()
		<-s.done // A replacement must not briefly exceed the process cap.
		delete(m.sessions, id)
		_ = os.RemoveAll(s.dir)
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
