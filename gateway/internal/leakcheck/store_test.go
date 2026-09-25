package leakcheck

import (
	"testing"
	"time"
)

func TestShouldRunTrueWhenNoPriorRun(t *testing.T) {
	st, _ := newTestStore(t)
	run, requested, err := st.ShouldRun(20 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !run || requested != "" {
		t.Fatalf("expected run=true with no pending request, got run=%v requested=%q", run, requested)
	}
}

func TestShouldRunFalseWithinInterval(t *testing.T) {
	st, _ := newTestStore(t)
	if _, err := st.StartRun([]string{"github"}); err != nil {
		t.Fatal(err)
	}
	run, _, err := st.ShouldRun(20 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if run {
		t.Fatal("expected run=false immediately after a run with a long interval")
	}
}

func TestShouldRunTrueWhenManuallyRequestedEvenWithinInterval(t *testing.T) {
	st, db := newTestStore(t)
	if _, err := st.StartRun([]string{"github"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('leak_scan_requested_at', '2026-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	run, requested, err := st.ShouldRun(20 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !run || requested != "2026-01-01T00:00:00.000Z" {
		t.Fatalf("expected an immediate run for a pending manual request, got run=%v requested=%q", run, requested)
	}
}

// This is the regression test for the race Codex's review caught: a
// second "Scan now" click that lands while a run is already in progress
// must not be silently dropped by that run's cleanup.
func TestClearScanRequestIfUnchangedPreservesNewerRequest(t *testing.T) {
	st, db := newTestStore(t)
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('leak_scan_requested_at', 'first')`); err != nil {
		t.Fatal(err)
	}
	seenValue, _, err := st.ScanRequestedAt()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a second click arriving mid-run, overwriting the value.
	if _, err := db.Exec(`UPDATE settings SET value = 'second' WHERE key = 'leak_scan_requested_at'`); err != nil {
		t.Fatal(err)
	}

	if err := st.ClearScanRequestIfUnchanged(seenValue); err != nil {
		t.Fatal(err)
	}

	current, ok, err := st.ScanRequestedAt()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current != "second" {
		t.Fatalf("expected the newer request ('second') to survive, got ok=%v value=%q", ok, current)
	}
}

// Regression test for the second concurrency gap Codex's review caught:
// a scan can run for minutes while a timer fires every minute, so two
// overlapping scans must not both proceed.
func TestAcquireLockPreventsConcurrentRuns(t *testing.T) {
	st, _ := newTestStore(t)
	ok1, err := st.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if !ok1 {
		t.Fatal("expected the first AcquireLock to succeed")
	}
	ok2, err := st.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("expected a second AcquireLock to fail while the first is held")
	}
	if err := st.ReleaseLock(); err != nil {
		t.Fatal(err)
	}
	ok3, err := st.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if !ok3 {
		t.Fatal("expected AcquireLock to succeed again after release")
	}
}

func TestAcquireLockStealsStaleLock(t *testing.T) {
	st, db := newTestStore(t)
	// Simulate a crashed process: a lock row old enough to be considered
	// abandoned rather than actively held.
	if _, err := db.Exec(`INSERT INTO leak_checker_lock (id, acquired_at) VALUES (1, '2020-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	ok, err := st.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a stale lock to be stolen rather than block forever")
	}
}

func TestClearScanRequestIfUnchangedClearsWhenStillSame(t *testing.T) {
	st, db := newTestStore(t)
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('leak_scan_requested_at', 'only')`); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearScanRequestIfUnchanged("only"); err != nil {
		t.Fatal(err)
	}
	_, ok, err := st.ScanRequestedAt()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected the request flag to be cleared")
	}
}
