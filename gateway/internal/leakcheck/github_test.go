package leakcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// No test in this package calls the real api.github.com -- BaseURL is
// always pointed at a local httptest server.

func TestSearchCodeParsesFragmentsAndAuth(t *testing.T) {
	var gotAuth, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		if !strings.Contains(r.URL.RawQuery, "q=") {
			t.Errorf("expected a q= query param, got %s", r.URL.RawQuery)
		}
		w.Header().Set("X-RateLimit-Remaining", "29")
		w.Header().Set("X-RateLimit-Reset", "1999999999")
		w.WriteHeader(200)
		w.Write([]byte(`{"items":[{"html_url":"https://github.com/x/y/blob/main/f","path":"f","repository":{"full_name":"x/y"},"text_matches":[{"fragment":"see https://restream.example.com/live/nova"}]}]}`))
	}))
	defer srv.Close()

	c := NewClient("test-token")
	c.BaseURL = srv.URL
	results, meta, err := c.SearchCode(context.Background(), `"https://restream.example.com/live/nova"`)
	if err != nil {
		t.Fatalf("SearchCode: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("expected Bearer auth header, got %q", gotAuth)
	}
	if gotUA == "" {
		t.Fatal("expected a User-Agent header (GitHub requires one)")
	}
	if len(results) != 1 || results[0].RepoFullName != "x/y" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if !strings.Contains(results[0].Fragments[0], "restream.example.com") {
		t.Fatalf("expected fragment to contain the matched text, got %q", results[0].Fragments[0])
	}
	if meta.RateLimit.Remaining != 29 {
		t.Fatalf("expected rate limit remaining 29, got %d", meta.RateLimit.Remaining)
	}
}

func TestSearchCodeRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := NewClient("")
	c.BaseURL = srv.URL
	_, _, err := c.SearchCode(context.Background(), "x")
	if err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestSearchCodePropagatesIncompleteResults(t *testing.T) {
	// GitHub can return incomplete_results: true on a 200 with some items
	// when its own search timed out internally -- easy to miss since it
	// isn't an HTTP error. Caught in review; must not be silently dropped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "10")
		w.Write([]byte(`{"incomplete_results":true,"items":[]}`))
	}))
	defer srv.Close()

	c := NewClient("")
	c.BaseURL = srv.URL
	_, meta, err := c.SearchCode(context.Background(), "x")
	if err != nil {
		t.Fatalf("SearchCode: %v", err)
	}
	if !meta.Incomplete {
		t.Fatal("expected Incomplete=true to be propagated from incomplete_results")
	}
}

// Regression test for a leak caught across two review passes: the first
// fix removed the query from log.Printf's direct arguments in scanner.go,
// but missed that both the HTTP-error path (which embedded the raw
// request path, including q=...) and the network-error path (a *url.Error
// from http.Client.Do, whose Error() concatenates the full request URL)
// could still smuggle a path_is_secret anchor into an error's own text --
// and that text is what actually reaches the logs via a bare %v.
func TestErrorsNeverContainTheQuery(t *testing.T) {
	const secretQuery = `"https://restream.example.com/nova/6f8e1b3c9a72d4e0-do-not-log-me"`

	t.Run("HTTP 4xx response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "10")
			w.WriteHeader(http.StatusUnprocessableEntity)
			// Simulates GitHub echoing part of an invalid query back in a
			// validation error -- a real thing GitHub's search API does,
			// which is exactly why the response body isn't trusted either.
			w.Write([]byte(`{"message":"Validation Failed","errors":[{"message":"` + secretQuery + `"}]}`))
		}))
		defer srv.Close()

		c := NewClient("")
		c.BaseURL = srv.URL
		_, _, err := c.SearchCode(context.Background(), secretQuery)
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "6f8e1b3c9a72d4e0") {
			t.Fatalf("error must not contain the secret query, got: %v", err)
		}
	})

	t.Run("network failure", func(t *testing.T) {
		// A server that closes the connection immediately produces a
		// genuine *url.Error from http.Client.Do, the same shape a real
		// DNS failure or connection refusal would.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Skip("ResponseWriter does not support hijacking")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
		}))
		defer srv.Close()

		c := NewClient("")
		c.BaseURL = srv.URL
		_, _, err := c.SearchCode(context.Background(), secretQuery)
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "6f8e1b3c9a72d4e0") || strings.Contains(err.Error(), srv.URL) {
			t.Fatalf("network error must not contain the secret query or the request URL, got: %v", err)
		}
	})
}

// Regression test for a bug only the real GitHub API surfaced (no mock
// enforced this): /search/issues now rejects any query with neither
// `is:issue` nor `is:pr` with a 422, where it used to default to
// searching both. Found by running an actual end-to-end scan against a
// real GitHub issue, not by any test in this package.
func TestSearchIssuesRejectsInvalidKind(t *testing.T) {
	c := NewClient("")
	c.BaseURL = "http://unused.invalid" // must fail before any request is made
	if _, _, err := c.SearchIssues(context.Background(), "x", time.Time{}, "bogus"); err == nil {
		t.Fatal("expected an error for an invalid kind")
	}
}

func TestSearchIssuesPRKindSetsQualifier(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	c := NewClient("")
	c.BaseURL = srv.URL
	if _, _, err := c.SearchIssues(context.Background(), "x", time.Time{}, "pr"); err != nil {
		t.Fatalf("SearchIssues: %v", err)
	}
	if !strings.Contains(gotQuery, "is%3Apr") && !strings.Contains(gotQuery, "is:pr") {
		t.Fatalf("expected an is:pr qualifier, got %s", gotQuery)
	}
}

func TestSearchIssuesIncludesSinceFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(200)
		w.Write([]byte(`{"items":[{"html_url":"https://github.com/x/y/issues/1","title":"leak?","body":"see https://restream.example.com/live/nova/deadbeef","updated_at":"2026-01-01T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	c := NewClient("")
	c.BaseURL = srv.URL
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	results, _, err := c.SearchIssues(context.Background(), `"restream.example.com/live/nova"`, since, "issue")
	if err != nil {
		t.Fatalf("SearchIssues: %v", err)
	}
	if !strings.Contains(gotQuery, "updated%3A%3E2026-01-01") && !strings.Contains(gotQuery, "updated:>2026-01-01") {
		t.Fatalf("expected an updated:> filter in query, got %s", gotQuery)
	}
	if !strings.Contains(gotQuery, "is%3Aissue") && !strings.Contains(gotQuery, "is:issue") {
		t.Fatalf("expected an is:issue qualifier (GitHub rejects issue search without one), got %s", gotQuery)
	}
	if len(results) != 1 || !strings.Contains(results[0].Body, "deadbeef") {
		t.Fatalf("unexpected results: %+v", results)
	}
}
