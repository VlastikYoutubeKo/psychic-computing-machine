// Package leakcheck implements Phase 6 (Leak Checker): searching public
// sources for evidence that a private stream's access URL has leaked, and
// classifying what's found without ever needing to store a raw access
// token (see the design note at the top of migrations/0002_leak_checker.sql).
//
// GitHub is implemented first per the spec's stated priority (section 12
// singles out iptv-org/iptv, but explicitly says not to limit to it --
// global code search covers that). GitLab is not implemented yet; see
// ROADMAP.md.
package leakcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultGitHubBaseURL = "https://api.github.com"

// Client talks to the GitHub Search API. BaseURL is overridable so tests
// run against an httptest server instead of the real GitHub API -- this
// package has no automated test that makes a real network call.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient(token string) *Client {
	return &Client{
		BaseURL: defaultGitHubBaseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// RateLimit reflects GitHub's response headers for the search endpoints
// (a separate, much stricter bucket than the general API rate limit).
type RateLimit struct {
	Remaining int
	Reset     time.Time
}

type CodeResult struct {
	HTMLURL      string
	RepoFullName string
	Path         string
	// Fragments are matching text snippets from GitHub's text-match
	// metadata. We scan these instead of fetching full file content: it's
	// one API call instead of two, and avoids downloading arbitrarily
	// large files just to find one line.
	Fragments []string
}

type IssueResult struct {
	HTMLURL   string
	Title     string
	Body      string
	UpdatedAt time.Time
}

var ErrRateLimited = fmt.Errorf("leakcheck: GitHub search rate limit exhausted")

func (c *Client) do(ctx context.Context, path string, accept string) ([]byte, RateLimit, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, RateLimit{}, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "streamvault-leakchecker")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Never include err.Error() here: a transport failure from
		// http.Client.Do is typically a *url.Error, whose Error() method
		// concatenates the *full request URL* -- including our query
		// string, which can be a path_is_secret anchor. A first fix
		// stripped the query from log.Printf's arguments directly but
		// missed that it was still reachable through this error's own
		// text (caught in a second review pass). Status/kind is enough
		// for an operator to act on; the URL never is.
		kind := "network error"
		if errors.Is(err, context.DeadlineExceeded) {
			kind = "timeout"
		}
		return nil, RateLimit{}, fmt.Errorf("leakcheck: request to %s failed: %s", endpointOnly(path), kind)
	}
	defer resp.Body.Close()

	var rl RateLimit
	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		rl.Remaining, _ = strconv.Atoi(v)
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			rl.Reset = time.Unix(secs, 0)
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, rl, err
	}
	if resp.StatusCode == http.StatusForbidden && rl.Remaining == 0 {
		return nil, rl, ErrRateLimited
	}
	if resp.StatusCode >= 400 {
		// endpointOnly, never path (it carries the raw query, which can be
		// a path_is_secret anchor), and never the response body either:
		// GitHub's search API validation errors sometimes echo back part
		// of an invalid query in the message text, so "the body is just
		// GitHub's fixed error shape" isn't a safe assumption to build a
		// secrecy guarantee on. The status code is enough for an operator
		// to act on (401 = bad token, 422 = malformed query, ...); this
		// error's text ends up in application logs via a bare %v in
		// scanner.go, so nothing request- or response-derived belongs in
		// it. Caught across two review passes -- see git history for how
		// incomplete the first fix was.
		return nil, rl, fmt.Errorf("leakcheck: GitHub API %s returned status %d", endpointOnly(path), resp.StatusCode)
	}
	return body, rl, nil
}

// endpointOnly strips a request path down to everything before its query
// string, e.g. "/search/code?q=..." -> "/search/code".
func endpointOnly(path string) string {
	if i := strings.IndexByte(path, '?'); i != -1 {
		return path[:i]
	}
	return path
}

type codeSearchResponse struct {
	IncompleteResults bool `json:"incomplete_results"`
	Items             []struct {
		HTMLURL    string `json:"html_url"`
		Path       string `json:"path"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		TextMatches []struct {
			Fragment string `json:"fragment"`
		} `json:"text_matches"`
	} `json:"items"`
}

// SearchMeta carries per-call metadata a caller needs to judge coverage
// honestly: the rate limit remaining, and whether GitHub itself flagged
// the results as incomplete (its own search timed out internally and
// returned a partial result set on a 200 -- easy to miss since it isn't
// an error). Also caps results at one page (30): neither this project's
// stream count nor its search volume currently justifies paginating
// further, but that's a real coverage limit, not a hidden one -- see
// ARCHITECTURE.md "Leak Checker".
type SearchMeta struct {
	RateLimit  RateLimit
	Incomplete bool
}

// SearchCode runs an exact-phrase code search across all public GitHub
// (query should already be quoted by the caller if an exact phrase is
// wanted -- see BuildAnchorQuery).
func (c *Client) SearchCode(ctx context.Context, query string) ([]CodeResult, SearchMeta, error) {
	path := "/search/code?q=" + urlQueryEscape(query) + "&per_page=30"
	body, rl, err := c.do(ctx, path, "application/vnd.github.v3.text-match+json")
	if err != nil {
		return nil, SearchMeta{RateLimit: rl}, err
	}
	var parsed codeSearchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, SearchMeta{RateLimit: rl}, fmt.Errorf("leakcheck: decoding code search response: %w", err)
	}
	results := make([]CodeResult, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		fragments := make([]string, 0, len(item.TextMatches))
		for _, tm := range item.TextMatches {
			fragments = append(fragments, tm.Fragment)
		}
		results = append(results, CodeResult{
			HTMLURL:      item.HTMLURL,
			RepoFullName: item.Repository.FullName,
			Path:         item.Path,
			Fragments:    fragments,
		})
	}
	return results, SearchMeta{RateLimit: rl, Incomplete: parsed.IncompleteResults}, nil
}

type issueSearchResponse struct {
	IncompleteResults bool `json:"incomplete_results"`
	Items             []struct {
		HTMLURL   string `json:"html_url"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		UpdatedAt string `json:"updated_at"`
	} `json:"items"`
}

// SearchIssues searches either issues or pull requests -- never both in one
// call. kind must be "issue" or "pr": GitHub's search API used to default
// to both when neither was specified, but now rejects the request outright
// (422 "Query must include 'is:issue' or 'is:pull-request'") if a query
// carries no `is:` qualifier at all. Found by running this against the
// real API for the first time, not by any mocked test -- there was
// nothing in the httptest mocks enforcing GitHub's actual validation
// rules. Callers wanting both (spec section 12 asks for issues *and*
// PRs) call this twice; see scanner.go.
//
// since, if non-zero, restricts to items updated after that time
// (incremental scanning per leak_sources / leak_checker_runs bookkeeping).
func (c *Client) SearchIssues(ctx context.Context, query string, since time.Time, kind string) ([]IssueResult, SearchMeta, error) {
	if kind != "issue" && kind != "pr" {
		return nil, SearchMeta{}, fmt.Errorf("leakcheck: SearchIssues: kind must be \"issue\" or \"pr\", got %q", kind)
	}
	q := query + " is:" + kind
	if !since.IsZero() {
		q += " updated:>" + since.UTC().Format("2006-01-02T15:04:05Z")
	}
	path := "/search/issues?q=" + urlQueryEscape(q) + "&per_page=30&sort=updated&order=desc"
	body, rl, err := c.do(ctx, path, "application/vnd.github+json")
	if err != nil {
		return nil, SearchMeta{RateLimit: rl}, err
	}
	var parsed issueSearchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, SearchMeta{RateLimit: rl}, fmt.Errorf("leakcheck: decoding issue search response: %w", err)
	}
	results := make([]IssueResult, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		updated, _ := time.Parse(time.RFC3339, item.UpdatedAt)
		results = append(results, IssueResult{
			HTMLURL:   item.HTMLURL,
			Title:     item.Title,
			Body:      item.Body,
			UpdatedAt: updated,
		})
	}
	return results, SearchMeta{RateLimit: rl, Incomplete: parsed.IncompleteResults}, nil
}

// BuildAnchorQuery returns an exact-phrase GitHub search query for a
// stream's public URL. Quoting makes GitHub search for the phrase as a
// unit rather than OR-ing the tokens.
func BuildAnchorQuery(anchor string) string {
	return `"` + anchor + `"`
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
