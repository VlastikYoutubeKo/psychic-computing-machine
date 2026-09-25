package leakcheck

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Scanner ties the GitHub client, the matcher, and the store together into
// one pass over every active access point. One run == one process
// invocation (see cmd/leakchecker); there is no internal scheduling loop
// here on purpose -- see ARCHITECTURE.md "Leak Checker" for why a one-shot
// binary driven by an external timer was chosen over a long-running daemon.
type Scanner struct {
	Store   *Store
	GitHub  *Client
	BaseURL string
}

// Run scans every active access point via GitHub code + issue search: one
// global (all of public GitHub) query per access point, plus one more
// per enabled leak_sources row (spec: "Umožni přidat konkrétní
// repozitáře, organizace" -- e.g. iptv-org/iptv gets its own dedicated
// query even if global search's ranking would otherwise miss a hit).
//
// A failure that stops the run outright (rate limit exhausted, DB error)
// sets RunSummary.Err. But *individual* query failures or GitHub-reported
// incomplete results don't stop the run -- they're tallied instead and
// folded into Err at the end if any occurred, so the admin UI's coverage
// display (SECURITY.md, spec section 12) never shows a run with silently
// failed or truncated queries as a clean success. Caught in review: the
// first version of this function logged those and moved on, which could
// make "the GitHub token is invalid, every single query 401'd" look
// exactly like "scanned everything, found nothing".
func (sc *Scanner) Run(ctx context.Context) RunSummary {
	sum := RunSummary{}
	var queryErrors, incompleteQueries, recordErrors int

	aps, err := sc.Store.ActiveAccessPoints()
	if err != nil {
		sum.Err = fmt.Errorf("loading access points: %w", err)
		return sum
	}

	sources, err := sc.Store.EnabledGitHubSources()
	if err != nil {
		sum.Err = fmt.Errorf("loading leak sources: %w", err)
		return sum
	}

	for _, ap := range aps {
		select {
		case <-ctx.Done():
			sum.Err = ctx.Err()
			return sum
		default:
		}

		anchor := ap.Anchor(sc.BaseURL)
		sum.StreamsChecked++

		stop, qerrs, incomplete, rerrs := sc.searchAndRecord(ctx, ap, BuildAnchorQuery(anchor), "github_code", "github_issue", &sum)
		queryErrors += qerrs
		incompleteQueries += incomplete
		recordErrors += rerrs
		if stop != nil {
			sum.Err = stop
			return sum
		}

		for _, src := range sources {
			qualifier := scopeQualifier(src)
			if qualifier == "" {
				continue
			}
			scoped := BuildAnchorQuery(anchor) + " " + qualifier
			stop, qerrs, incomplete, rerrs := sc.searchAndRecord(ctx, ap, scoped, "github_code:"+src.Identifier, "github_issue:"+src.Identifier, &sum)
			queryErrors += qerrs
			incompleteQueries += incomplete
			recordErrors += rerrs
			if stop != nil {
				sum.Err = stop
				return sum
			}
			if terr := sc.Store.TouchLeakSource(src.ID); terr != nil {
				log.Printf("leakcheck: updating last_scanned_at for source %d: %v", src.ID, terr)
				recordErrors++
			}
		}
	}

	if queryErrors > 0 || incompleteQueries > 0 || recordErrors > 0 {
		sum.Err = fmt.Errorf("partial coverage: %d/%d queries failed, %d returned incomplete_results from GitHub, %d findings failed to record -- see logs for detail (never logged: search query text, to avoid leaking a path_is_secret anchor)",
			queryErrors, sum.QueriesMade, incompleteQueries, recordErrors)
	}

	return sum
}

func scopeQualifier(src LeakSource) string {
	switch src.Provider {
	case "github_repo":
		return "repo:" + src.Identifier
	case "github_org":
		return "org:" + src.Identifier
	default:
		return "" // gitlab_project/gitlab_group/playlist_url: not implemented yet, see ROADMAP.md
	}
}

// searchAndRecord runs one code search + one issue search for query and
// records any matches. Returns (stopErr, queryErrors, incompleteQueries,
// recordErrors): stopErr is non-nil only for a rate-limit exhaustion,
// which aborts the whole run; the three counts are soft failures the
// caller tallies and folds into a final "partial coverage" note instead
// of failing outright. Deliberately never logs the query text itself --
// it can contain a path_is_secret anchor, which must not end up in
// ordinary application logs (same principle as never logging a raw
// token elsewhere in this project).
func (sc *Scanner) searchAndRecord(ctx context.Context, ap AccessPointInfo, query, codeSource, issueSource string, sum *RunSummary) (stopErr error, queryErrors, incompleteQueries, recordErrors int) {
	codeResults, codeMeta, err := sc.GitHub.SearchCode(ctx, query)
	sum.QueriesMade++
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			return fmt.Errorf("stopped early: GitHub search rate limit exhausted after %d access points", sum.StreamsChecked), queryErrors, incompleteQueries, recordErrors
		}
		log.Printf("leakcheck: code search for access point %d failed: %v", ap.ID, err)
		queryErrors++
	}
	if codeMeta.Incomplete {
		log.Printf("leakcheck: GitHub reported incomplete code search results for access point %d", ap.ID)
		incompleteQueries++
	}
	for _, r := range codeResults {
		for _, frag := range r.Fragments {
			if !sc.recordIfMatch(ap, frag, codeSource, r.HTMLURL, sum) {
				recordErrors++
			}
		}
	}
	if codeMeta.RateLimit.Remaining == 0 {
		return fmt.Errorf("stopped early: GitHub search rate limit exhausted after %d access points", sum.StreamsChecked), queryErrors, incompleteQueries, recordErrors
	}

	issueResults, issueMeta, err := sc.GitHub.SearchIssues(ctx, query, time.Time{})
	sum.QueriesMade++
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			return fmt.Errorf("stopped early: GitHub search rate limit exhausted after %d access points", sum.StreamsChecked), queryErrors, incompleteQueries, recordErrors
		}
		log.Printf("leakcheck: issue search for access point %d failed: %v", ap.ID, err)
		queryErrors++
	}
	if issueMeta.Incomplete {
		log.Printf("leakcheck: GitHub reported incomplete issue search results for access point %d", ap.ID)
		incompleteQueries++
	}
	for _, r := range issueResults {
		if !sc.recordIfMatch(ap, r.Title+"\n"+r.Body, issueSource, r.HTMLURL, sum) {
			recordErrors++
		}
	}
	if issueMeta.RateLimit.Remaining == 0 {
		return fmt.Errorf("stopped early: GitHub search rate limit exhausted after %d access points", sum.StreamsChecked), queryErrors, incompleteQueries, recordErrors
	}
	return nil, queryErrors, incompleteQueries, recordErrors
}

// recordIfMatch returns false only when RecordMatch itself failed (a DB
// error) -- not finding a match is the normal case and returns true.
func (sc *Scanner) recordIfMatch(ap AccessPointInfo, text, source, sourceURL string, sum *RunSummary) bool {
	m := Classify(ap, sc.BaseURL, text)
	if m == nil {
		return true
	}
	created, err := sc.Store.RecordMatch(*m, source, sourceURL)
	if err != nil {
		log.Printf("leakcheck: recording finding for access point %d: %v", ap.ID, err)
		return false
	}
	if created {
		sum.FindingsCreated++
	}
	return true
}
