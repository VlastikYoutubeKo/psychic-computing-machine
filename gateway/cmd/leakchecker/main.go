// Command leakchecker is a one-shot Phase 6 scan: check every active
// stream's public_path against GitHub code and issue search, record what's
// found, and exit.
//
// Meant to be invoked frequently (e.g. every minute) by a systemd timer or
// cron -- see DEPLOYMENT.md -- but it only actually performs a scan when
// either a manual "Scan now" request is pending or minScanInterval has
// elapsed since the last run; otherwise it's a fast, near-free no-op. This
// two-level design (frequent invocation, throttled work) is what makes
// "Scan now" feel responsive from the admin UI without a full GitHub
// search sweep running every single minute and burning through the search
// rate limit in a few minutes flat.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"streamvault/gateway/internal/leakcheck"
	"streamvault/gateway/internal/secretbox"
)

// How often a full scan runs absent a manual request. GitHub's search API
// allows roughly 30 requests/minute authenticated; two queries per access
// point per run means this interval should scale with how many streams
// exist, but 20 minutes is a reasonable default for the handful of streams
// this project is sized for -- revisit if that changes.
const minScanInterval = 20 * time.Minute

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	dbPath := getenv("STREAMVAULT_DB", "../data/streamvault.sqlite")
	keyPath := getenv("STREAMVAULT_KEY_FILE", "../data/secret.key")

	store, err := leakcheck.OpenStore(dbPath)
	if err != nil {
		log.Fatalf("opening database %s: %v", dbPath, err)
	}
	defer store.Close()

	shouldRun, requestedValue, err := store.ShouldRun(minScanInterval)
	if err != nil {
		log.Fatalf("checking whether a scan is due: %v", err)
	}
	if !shouldRun {
		return // quiet no-op; the timer tries again on its next tick
	}

	// A scan can take up to the context timeout below (10 min) while the
	// timer fires every minute; without this, a manual "Scan now" request
	// landing mid-scan would start a second, overlapping run. See
	// migrations/0003_leak_checker_lock.sql.
	locked, err := store.AcquireLock()
	if err != nil {
		log.Fatalf("acquiring scan lock: %v", err)
	}
	if !locked {
		log.Printf("leakchecker: a scan is already in progress, skipping this tick")
		return
	}
	// From here on, every exit path must be a plain `return`, never
	// log.Fatalf/os.Exit: those skip deferred functions entirely, which
	// would leak this lock for its full 15-minute staleness window on
	// something as ordinary as "no GitHub token configured yet" --
	// exactly the state this project is in until a token is added. Caught
	// in review before this ever ran for real.
	defer func() {
		if err := store.ReleaseLock(); err != nil {
			log.Printf("releasing scan lock: %v", err)
		}
	}()

	var key []byte
	if k, err := secretbox.LoadKey(keyPath); err != nil {
		log.Printf("warning: no secret key loaded from %s (%v) -- cannot decrypt a configured GitHub token", keyPath, err)
	} else {
		key = k
	}

	runID, err := store.StartRun([]string{"github"})
	if err != nil {
		log.Printf("recording run start: %v", err)
		return
	}

	token, configured, err := store.GitHubToken(key)
	if err != nil {
		finishWithError(store, runID, err)
		return
	}
	if !configured {
		finishWithError(store, runID, errStr("no GitHub token configured in Settings -- Leak Checker has nothing to scan with"))
		return
	}

	baseURL, err := store.BaseURL()
	if err != nil {
		finishWithError(store, runID, err)
		return
	}

	scanner := &leakcheck.Scanner{
		Store:   store,
		GitHub:  leakcheck.NewClient(token),
		BaseURL: baseURL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sum := scanner.Run(ctx)
	if err := store.FinishRun(runID, sum); err != nil {
		log.Printf("recording run finish: %v", err)
	}
	if sum.Err != nil {
		log.Printf("leakchecker run finished with a note: %v", sum.Err)
	}
	log.Printf("leakchecker: checked %d access points, %d queries, %d new findings",
		sum.StreamsChecked, sum.QueriesMade, sum.FindingsCreated)

	if requestedValue != "" {
		// Only clears the flag if it still holds the exact value seen at
		// the start of this run -- a click that landed mid-run wrote a new
		// timestamp, which must survive for the next invocation to pick up.
		if err := store.ClearScanRequestIfUnchanged(requestedValue); err != nil {
			log.Printf("clearing scan request flag: %v", err)
		}
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

// finishWithError records the run as failed and logs it. It deliberately
// does not call log.Fatalf/os.Exit -- see the comment above the lock
// release defer in main() for why that would leak the scan lock.
func finishWithError(store *leakcheck.Store, runID int64, err error) {
	_ = store.FinishRun(runID, leakcheck.RunSummary{Err: err})
	log.Printf("leakchecker: %v", err)
}
