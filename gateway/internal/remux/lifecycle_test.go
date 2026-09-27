package remux

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
}

func TestSlowOpenDoesNotHoldManagerLock(t *testing.T) {
	requireFFmpeg(t)
	t.Setenv("STREAMVAULT_REMUX_SLOTS", "2")
	m := NewManager()
	defer m.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := m.Start(1, "one", func(ctx context.Context) (io.ReadCloser, error) {
			close(entered)
			select {
			case <-release:
				return io.NopCloser(strings.NewReader("")), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		first <- err
	}()
	<-entered
	other := make(chan error, 1)
	go func() {
		if got := m.Existing(999, "absent"); got != nil {
			other <- io.ErrUnexpectedEOF
			return
		}
		_, err := m.Start(2, "two", func(context.Context) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("")), nil
		})
		other <- err
	}()
	select {
	case err := <-other:
		if err != nil {
			t.Fatalf("other stream blocked or failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow open held manager mutex")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentOpenForSameStreamReturnsWinnerAndClosesLoser(t *testing.T) {
	requireFFmpeg(t)
	m := NewManager()
	defer m.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	type result struct {
		s   *Session
		err error
	}
	first := make(chan result, 1)
	loserBody := &blockingBody{done: make(chan struct{})}
	go func() {
		s, err := m.Start(10, "same", func(ctx context.Context) (io.ReadCloser, error) {
			close(entered)
			select {
			case <-release:
				return loserBody, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		first <- result{s, err}
	}()
	<-entered
	winner, err := m.Start(10, "same", func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	got := <-first
	if got.err != nil || got.s != winner {
		t.Fatalf("concurrent start returned %#v, %v instead of winner", got.s, got.err)
	}
	select {
	case <-loserBody.done:
	default:
		t.Fatal("losing source body was not closed")
	}
}

type blockingBody struct {
	done chan struct{}
	once sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) { <-b.done; return 0, io.EOF }
func (b *blockingBody) Close() error             { b.once.Do(func() { close(b.done) }); return nil }

func TestStopClosesBlockedInputAndReleasesResources(t *testing.T) {
	requireFFmpeg(t)
	m := NewManager()
	defer m.Close()
	body := &blockingBody{done: make(chan struct{})}
	s, err := m.Start(7, "blocked", func(context.Context) (io.ReadCloser, error) { return body, nil })
	if err != nil {
		t.Fatal(err)
	}
	m.Stop(7)
	select {
	case <-s.done:
	case <-time.After(4 * time.Second):
		t.Fatal("stopping a blocked source did not release the session")
	}
	select {
	case <-body.done:
	default:
		t.Fatal("source body was not closed")
	}
	if len(m.slots) != 0 {
		t.Fatal("slot was not released")
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, err := os.Stat(s.Dir)
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("temporary directory still exists: %s", s.Dir)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
