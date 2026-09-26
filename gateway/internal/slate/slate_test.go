package slate

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRouteNames(t *testing.T) {
	for _, name := range []string{"index.m3u8", "seg000001.ts", "seg999999.ts", "seg1000000.ts"} {
		if !ValidName(name) {
			t.Fatalf("valid name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "../seg000001.ts", "seg1.ts", "seg000001.ts/../secret.key", "message.txt", "seg000001.ts.tmp", "index.m3u8/"} {
		if ValidName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
	if !ValidVariant(Unavailable) || !ValidVariant(Temporary) || ValidVariant("other") {
		t.Fatal("variant allowlist incorrect")
	}
}

func TestManagerRendersOneSharedHLSStream(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	if _, err := os.Stat("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"); err != nil {
		if _, err := os.Stat("/usr/share/fonts/ttf-dejavu/DejaVuSans.ttf"); err != nil {
			t.Skip("DejaVu font unavailable")
		}
	}
	m := NewManager()
	p, err := m.GetPath(Unavailable, "", "index.m3u8")
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	first := m.sessions[Unavailable]
	p2, err := m.GetPath(Unavailable, "", "index.m3u8")
	if err != nil || p2 != p || m.sessions[Unavailable] != first {
		m.Close()
		t.Fatal("second viewer started another encoder")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "#EXTM3U") {
		m.Close()
		t.Fatalf("invalid playlist: %s", data)
	}
	var segment string
	for _, line := range strings.Split(string(data), "\n") {
		if ValidName(line) && line != "index.m3u8" {
			segment = line
			break
		}
	}
	if segment == "" {
		m.Close()
		t.Fatalf("missing segment: %s", data)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), segment)); err != nil {
		m.Close()
		t.Fatal(err)
	}
	dir := filepath.Dir(p)
	m.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("slate temp dir not cleaned: %v", err)
	}
}

func TestRestartBackoffAfterFailedStart(t *testing.T) {
	m := &Manager{sessions: make(map[string]*session), failedAt: map[string]time.Time{Unavailable: time.Now()}, closed: make(chan struct{})}
	if _, err := m.GetPath(Unavailable, "", "index.m3u8"); err == nil || !strings.Contains(err.Error(), "backing off") {
		t.Fatalf("expected backoff error, got %v", err)
	}
}

func TestPersonalKeyCapAndValidation(t *testing.T) {
	m := NewManager()
	defer m.Close()
	at := time.Date(2026, 9, 26, 17, 31, 0, 0, time.UTC)
	first := m.Prepare(Unavailable, 7, 8, at)
	if !ValidKey(first) || first != m.Prepare(Unavailable, 7, 8, at) {
		t.Fatal("personal key is not stable and opaque")
	}
	if m.Prepare(Unavailable, 9, 8, at) == "" || m.Prepare(Unavailable, 10, 8, at) == "" {
		t.Fatal("three slots should be available")
	}
	if m.Prepare(Unavailable, 11, 8, at) != "" {
		t.Fatal("fourth slot did not fall back to generic")
	}
	for _, bad := range []string{"", "../" + first, strings.ToUpper(first), first[:39], first[:39] + "z"} {
		if ValidKey(bad) {
			t.Fatalf("accepted key %q", bad)
		}
	}
	// Flip the last hex digit to a *different* one: the key is random, so a
	// fixed replacement like "0" equals the real digit 1 run in 16.
	flip := "0"
	if first[39] == '0' {
		flip = "1"
	}
	if _, err := m.GetPath(Unavailable, first[:39]+flip, "index.m3u8"); !os.IsNotExist(err) {
		t.Fatalf("tampered key: %v", err)
	}
	if _, err := m.GetPath(Temporary, first, "index.m3u8"); !os.IsNotExist(err) {
		t.Fatalf("wrong variant: %v", err)
	}
}

func TestCutoffTextFileAndAudioInputSelection(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 26, 17, 31, 0, 0, time.UTC)
	p, err := writeCutoff(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "Cut off: 26.09.2026 19:31" {
		t.Fatalf("cutoff: %q %v", b, err)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0600 {
		t.Fatalf("cutoff mode: %v", info.Mode())
	}
	none, radio, err := audioArgs(AudioSettings{}, dir)
	if err != nil || radio || !reflect.DeepEqual(none, []string{"-re", "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo"}) {
		t.Fatalf("silence: %v %v %v", none, radio, err)
	}
	file, radio, err := audioArgs(AudioSettings{File: strings.Repeat("a", 32) + ".mp3", Volume: 50}, dir)
	if err != nil || radio || !strings.Contains(strings.Join(file, " "), "slate-audio") {
		t.Fatalf("file: %v %v %v", file, radio, err)
	}
	if _, _, err := audioArgs(AudioSettings{File: "../secret.key", Volume: 50}, dir); err == nil {
		t.Fatal("accepted traversal")
	}
	if _, _, err := audioArgs(AudioSettings{URL: "file:///etc/passwd", Volume: 50}, dir); err == nil {
		t.Fatal("accepted file URL")
	}
	if _, _, err := audioArgs(AudioSettings{URL: "http://127.0.0.1/radio", Volume: 50}, dir); err == nil {
		t.Fatal("accepted loopback URL")
	}
	radioArgs, radio, err := audioArgs(AudioSettings{URL: "https://1.1.1.1/radio", Volume: 50}, dir)
	joined := strings.Join(radioArgs, " ")
	if err != nil || !radio || !strings.Contains(joined, "-protocol_whitelist http,https,tcp,tls") || !strings.Contains(joined, "-max_redirects 0") {
		t.Fatalf("radio: %v %v %v", radioArgs, radio, err)
	}
}

func TestFailedRadioSessionRestartsMuted(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	if _, err := fontPath(); err != nil {
		t.Skip("font unavailable")
	}
	m := NewManager()
	defer m.Close()
	m.ConfigureAudio(func() (AudioSettings, error) { return AudioSettings{URL: "https://1.1.1.1/radio", Volume: 50}, nil }, t.TempDir())
	done := make(chan struct{})
	close(done)
	m.sessions[Unavailable] = &session{started: time.Now(), dir: t.TempDir(), done: done, usedRadio: true}
	p, err := m.GetPath(Unavailable, "", "index.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if m.sessions[Unavailable].usedRadio {
		t.Fatal("radio retried immediately instead of silence")
	}
	if !time.Now().Before(m.radioMuted[Unavailable]) {
		t.Fatal("radio retry not held back")
	}
}
