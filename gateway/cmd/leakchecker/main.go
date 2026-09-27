// Command leakchecker is a one-shot Phase 6 scan: check every active
// stream's public_path against GitHub code and issue search, record what's
// found, and exit.
//
// Meant to be invoked frequently (every 5 minutes in deploy/systemd) by a timer or
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
	userDue, err := store.AnyUserScanDue(minScanInterval)
	if err != nil {
		log.Fatalf("checking user scan schedule: %v", err)
	}
	if !shouldRun && !userDue {
		return // quiet no-op; the timer tries again on its next tick
	}

	// A scan can take up to the context timeout below (10 min) while the
	// timer fires every few minutes; without this, a manual "Scan now" request
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

	baseURL, err := store.BaseURL()
	baseErr := err

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if shouldRun {
		runID, e := store.StartRun([]string{"github"})
		if e != nil {
			log.Printf("recording global run start: %v", e)
		} else {
			token, configured, e := store.GitHubToken(key)
			switch {
			case e != nil:
				finishWithError(store, runID, e)
			case !configured:
				finishWithError(store, runID, errStr("no global GitHub token configured"))
			case baseErr != nil:
				finishWithError(store, runID, baseErr)
			default:
				sum := (&leakcheck.Scanner{Store: store, GitHub: leakcheck.NewClient(token), BaseURL: baseURL}).Run(ctx)
				finishRun(store, runID, "global", sum)
				if requestedValue != "" {
					if e := store.ClearScanRequestIfUnchanged(requestedValue); e != nil {
						log.Printf("clearing global scan request: %v", e)
					}
				}
			}
		}
	}
	accounts, e := store.UserScanAccounts(key)
	if e != nil {
		log.Printf("loading user scanner credentials: %v", e)
		return
	}
	for _, account := range accounts {
		due, e := store.UserShouldRun(account.ID, account.Requested, minScanInterval)
		if e != nil {
			log.Printf("checking user %d scan schedule: %v", account.ID, e)
			continue
		}
		if !due {
			continue
		}
		id := account.ID
		runID, e := store.StartRunForOwner(&id, []string{"github"})
		if e != nil {
			log.Printf("recording user %d run start: %v", id, e)
			continue
		}
		switch {
		case account.Err != nil:
			finishWithError(store, runID, account.Err)
		case baseErr != nil:
			finishWithError(store, runID, baseErr)
		default:
			sum := (&leakcheck.Scanner{Store: store, GitHub: leakcheck.NewClient(account.Token), BaseURL: baseURL, OwnerID: &id}).Run(ctx)
			finishRun(store, runID, "user", sum)
			if account.Requested != "" {
				if e := store.ClearUserRequestIfUnchanged(id, account.Requested); e != nil {
					log.Printf("clearing user %d scan request: %v", id, e)
				}
			}
		}
	}
}

func finishRun(store *leakcheck.Store, runID int64, scope string, sum leakcheck.RunSummary) {
	if err := store.FinishRun(runID, sum); err != nil {
		log.Printf("recording %s run finish: %v", scope, err)
	}
	if sum.Err != nil {
		log.Printf("leakchecker %s run incomplete: %v", scope, sum.Err)
	}
	log.Printf("leakchecker %s: checked %d access points, %d queries, %d new findings", scope, sum.StreamsChecked, sum.QueriesMade, sum.FindingsCreated)
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
