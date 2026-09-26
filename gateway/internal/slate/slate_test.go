package slate

import (
	"os"
	"os/exec"
	"path/filepath"
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
	p, err := m.GetPath(Unavailable, "index.m3u8")
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	first := m.sessions[Unavailable]
	p2, err := m.GetPath(Unavailable, "index.m3u8")
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
	if _, err := m.GetPath(Unavailable, "index.m3u8"); err == nil || !strings.Contains(err.Error(), "backing off") {
		t.Fatalf("expected backoff error, got %v", err)
	}
}
