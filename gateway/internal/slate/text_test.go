package slate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReasonAndTextLimits(t *testing.T) {
	for _, reason := range []string{"limited_bandwidth", "not_intended_for_public", "unauthorized_redistribution", "access_revoked_by_owner", "stream_permanently_discontinued"} {
		if !ValidVariant(Unavailable + ":" + reason) {
			t.Fatalf("rejected %s", reason)
		}
	}
	if !ValidVariant(Temporary+":"+TemporaryReason) || ValidVariant(Unavailable+":"+TemporaryReason) || ValidVariant(Temporary+":limited_bandwidth") {
		t.Fatal("variant/reason mix accepted")
	}
	longest := Text{Title: strings.Repeat("W", 32), Subtitle: strings.Repeat("W", 90)}
	if _, err := NormalizeText(longest); err != nil {
		t.Fatal(err)
	}
	if fitFontSize(longest.Title, 117)*32 > 1260 {
		t.Fatal("title exceeds safe width")
	}
	w := wrapSubtitle(longest.Subtitle)
	if len(strings.Split(w, "\n")) != 2 {
		t.Fatalf("expected two lines: %q", w)
	}
	for _, line := range strings.Split(w, "\n") {
		if fitFontSize(w, 47)*len([]rune(line)) > 1260 {
			t.Fatalf("subtitle exceeds safe width: %q", line)
		}
	}
	if _, err := NormalizeText(Text{Title: strings.Repeat("W", 33), Subtitle: "x"}); err == nil {
		t.Fatal("accepted long title")
	}
	if _, err := NormalizeText(Text{Title: "x", Subtitle: strings.Repeat("W", 91)}); err == nil {
		t.Fatal("accepted long subtitle")
	}
	clean, err := NormalizeText(Text{Title: "A\x00B", Subtitle: "C\x1bD"})
	if err != nil || clean.Title != "A B" || clean.Subtitle != "C D" {
		t.Fatalf("control strip: %#v %v", clean, err)
	}
}

func TestTotalSessionCapFallsBackToExistingGeneric(t *testing.T) {
	m := NewManager()
	defer func() { m.mu.Lock(); m.sessions = map[string]*session{}; m.mu.Unlock(); m.Close() }()
	for _, reason := range []string{"limited_bandwidth", "not_intended_for_public", "unauthorized_redistribution", "access_revoked_by_owner", "stream_permanently_discontinued"} {
		id := Unavailable + ":" + reason
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "index.m3u8"), []byte("#EXTM3U\n"), 0600); err != nil {
			t.Fatal(err)
		}
		m.sessions[id] = &session{dir: d, done: make(chan struct{}), lastUsed: time.Now()}
	}
	m.sessions[Temporary+":"+TemporaryReason] = &session{dir: t.TempDir(), done: make(chan struct{}), lastUsed: time.Now()}
	key := m.Prepare(Unavailable+":limited_bandwidth", 7, 8, time.Now())
	p, err := m.GetPath(Unavailable+":limited_bandwidth", key, "index.m3u8")
	validFallback := false
	for id, s := range m.sessions {
		if strings.HasPrefix(id, Unavailable+":") && p == filepath.Join(s.dir, "index.m3u8") {
			validFallback = true
		}
	}
	if err != nil || !validFallback {
		t.Fatalf("cap fallback: %q %v", p, err)
	}
	if len(m.sessions) != 6 {
		t.Fatalf("spawned past cap: %d", len(m.sessions))
	}
	// These fake sessions have no subprocess and are owned by the test.
}

func TestTextChangeStopsOnlyAffectedSession(t *testing.T) {
	m := NewManager()
	defer func() { m.mu.Lock(); m.sessions = map[string]*session{}; m.mu.Unlock(); m.Close() }()
	old := DefaultText("limited_bandwidth")
	newText := Text{Title: "Changed title", Subtitle: "Changed subtitle"}
	m.ConfigureText(func(reason string) (Text, error) {
		if reason == "limited_bandwidth" {
			return newText, nil
		}
		return DefaultText(reason), nil
	})
	makeSession := func(copy Text) (*session, *bool) {
		cancelled := false
		done := make(chan struct{})
		close(done)
		return &session{dir: t.TempDir(), cancel: func() { cancelled = true }, done: done, text: copy, hasText: true}, &cancelled
	}
	stale, staleCancelled := makeSession(old)
	same, sameCancelled := makeSession(DefaultText("access_revoked_by_owner"))
	m.sessions[Unavailable+":limited_bandwidth"] = stale
	m.sessions[Unavailable+":access_revoked_by_owner"] = same
	m.RestartOnAudioChange()
	if !*staleCancelled || m.sessions[Unavailable+":limited_bandwidth"] != nil {
		t.Fatal("changed text did not restart")
	}
	if *sameCancelled || m.sessions[Unavailable+":access_revoked_by_owner"] == nil {
		t.Fatal("unaffected session restarted")
	}
}
