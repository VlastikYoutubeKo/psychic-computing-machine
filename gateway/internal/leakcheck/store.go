package leakcheck

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"streamvault/gateway/internal/secretbox"
)

type Store struct {
	db *sql.DB
}

func OpenStore(dbPath string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("leakcheck: opening %s: %w", dbPath, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) setting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// GitHubToken decrypts settings.github_token_enc using the same
// secretbox envelope the PHP admin writes it with (sv_encrypt in
// admin/includes/secret_box.php). Returns ("", false, nil) if unset --
// distinguished from an error, since "not configured" is an expected,
// normal state (Leak Checker is optional).
func (s *Store) GitHubToken(key []byte) (string, bool, error) {
	enc, ok, err := s.setting("github_token_enc")
	if err != nil || !ok {
		return "", false, err
	}
	if key == nil {
		return "", false, fmt.Errorf("leakcheck: a GitHub token is configured but no encryption key is loaded")
	}
	plain, err := secretbox.Decrypt(key, enc)
	if err != nil {
		return "", false, fmt.Errorf("leakcheck: decrypting GitHub token: %w", err)
	}
	return string(plain), true, nil
}

func (s *Store) BaseURL() (string, error) {
	v, ok, err := s.setting("gateway_base_url")
	if err != nil {
		return "", err
	}
	if !ok || v == "" {
		return "", fmt.Errorf("leakcheck: no gateway_base_url configured in settings -- cannot build search anchors")
	}
	return v, nil
}

// ScanRequestedAt returns the raw value of settings.leak_scan_requested_at
// (a timestamp string the PHP admin writes on each "Scan now" click) and
// whether it's set at all.
func (s *Store) ScanRequestedAt() (string, bool, error) {
	return s.setting("leak_scan_requested_at")
}

// ClearScanRequestIfUnchanged deletes the request flag only if it still
// holds exactly the value the caller saw when it decided to run --
// otherwise a click that arrives *during* a run would set a new
// timestamp, and an unconditional clear afterward would silently drop
// that second request instead of it being picked up by the next run.
// Caught in review.
func (s *Store) ClearScanRequestIfUnchanged(seenValue string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key = 'leak_scan_requested_at' AND value = ?`, seenValue)
	return err
}

// LastRunStartedAt returns when the most recent run (successful or not)
// began, used to throttle how often a full scan actually happens -- see
// ShouldRun.
func (s *Store) LastRunStartedAt() (time.Time, bool, error) {
	var v sql.NullString
	err := s.db.QueryRow(`SELECT started_at FROM leak_checker_runs ORDER BY id DESC LIMIT 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) || !v.Valid {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", v.String)
	if err != nil {
		return time.Time{}, false, nil // malformed/legacy value -- treat as "no prior run" rather than fail the whole invocation
	}
	return t, true, nil
}

// ShouldRun decides whether this invocation should actually perform a scan:
// yes if a manual request is pending, or if minInterval has elapsed since
// the last run. A timer firing every minute (needed for "Scan now" to feel
// responsive) would otherwise burn through GitHub's search rate limit by
// doing a full scan every single minute -- caught in review before this
// was wired to any scheduler.
func (s *Store) ShouldRun(minInterval time.Duration) (run bool, requestedValue string, err error) {
	val, requested, err := s.ScanRequestedAt()
	if err != nil {
		return false, "", err
	}
	if requested {
		return true, val, nil
	}
	last, ok, err := s.LastRunStartedAt()
	if err != nil {
		return false, "", err
	}
	if !ok || time.Since(last) >= minInterval {
		return true, "", nil
	}
	return false, "", nil
}

// lockStaleAfter bounds how long a lock is honored if its holder never
// released it (e.g. the process was killed). Kept comfortably above the
// leakchecker binary's own 10-minute scan context timeout.
const lockStaleAfter = 15 * time.Minute

// AcquireLock prevents two scans from running concurrently (see
// migrations/0003_leak_checker_lock.sql for why this exists). It self-heals:
// a lock older than lockStaleAfter is assumed to belong to a crashed
// process and is taken over rather than blocking forever.
func (s *Store) AcquireLock() (bool, error) {
	if _, err := s.db.Exec(`INSERT INTO leak_checker_lock (id, acquired_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`); err == nil {
		return true, nil
	}
	// Insert failed, almost certainly because a lock row already exists
	// (id=1 PK conflict). Check whether it's stale enough to steal.
	var acquiredAt string
	err := s.db.QueryRow(`SELECT acquired_at FROM leak_checker_lock WHERE id = 1`).Scan(&acquiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Raced with a concurrent release between the failed INSERT and
		// this SELECT; try once more.
		if _, err := s.db.Exec(`INSERT INTO leak_checker_lock (id, acquired_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`); err == nil {
			return true, nil
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	t, perr := time.Parse("2006-01-02T15:04:05.000Z", acquiredAt)
	if perr == nil && time.Since(t) < lockStaleAfter {
		return false, nil // a genuinely active run holds the lock
	}
	res, err := s.db.Exec(`UPDATE leak_checker_lock SET acquired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1 AND acquired_at = ?`, acquiredAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) ReleaseLock() error {
	_, err := s.db.Exec(`DELETE FROM leak_checker_lock WHERE id = 1`)
	return err
}

// LeakSource is an explicitly watched GitHub repo or org (spec: "Umožni
// přidat konkrétní repozitáře, organizace a veřejné playlisty"). Global
// code search already covers all of public GitHub, so these exist to (a)
// give priority sources like iptv-org/iptv a dedicated, always-run query
// even if global search's ranking/pagination would otherwise miss a hit,
// and (b) scope a search to an org's private-to-them-but-public repos.
type LeakSource struct {
	ID         int64
	Provider   string
	Identifier string
}

func (s *Store) EnabledGitHubSources() ([]LeakSource, error) {
	rows, err := s.db.Query(`SELECT id, provider, identifier FROM leak_sources WHERE enabled = 1 AND provider IN ('github_repo','github_org')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LeakSource
	for rows.Next() {
		var ls LeakSource
		if err := rows.Scan(&ls.ID, &ls.Provider, &ls.Identifier); err != nil {
			return nil, err
		}
		out = append(out, ls)
	}
	return out, rows.Err()
}

func (s *Store) TouchLeakSource(id int64) error {
	_, err := s.db.Exec(`UPDATE leak_sources SET last_scanned_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, id)
	return err
}

// ActiveAccessPoints loads every access point worth scanning: belonging to
// an active stream, itself active (a revoked one can't leak anything new).
func (s *Store) ActiveAccessPoints() ([]AccessPointInfo, error) {
	rows, err := s.db.Query(`
		SELECT ap.id, ap.stream_id, ap.public_path, ap.visibility, ap.path_is_secret
		FROM access_points ap
		JOIN streams st ON st.id = ap.stream_id
		WHERE ap.status = 'active' AND st.status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aps []AccessPointInfo
	for rows.Next() {
		var ap AccessPointInfo
		var pathIsSecret int
		if err := rows.Scan(&ap.ID, &ap.StreamID, &ap.PublicPath, &ap.Visibility, &pathIsSecret); err != nil {
			return nil, err
		}
		ap.PathIsSecret = pathIsSecret != 0
		aps = append(aps, ap)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range aps {
		toks, err := s.tokensFor(aps[i].ID)
		if err != nil {
			return nil, err
		}
		aps[i].Tokens = toks
	}
	return aps, nil
}

func (s *Store) tokensFor(accessPointID int64) ([]TokenInfo, error) {
	rows, err := s.db.Query(`
		SELECT id, token_hash, revoked_at IS NOT NULL, expires_at IS NOT NULL AND expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')
		FROM access_tokens WHERE access_point_id = ?`, accessPointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var toks []TokenInfo
	for rows.Next() {
		var t TokenInfo
		if err := rows.Scan(&t.ID, &t.Hash, &t.Revoked, &t.Expired); err != nil {
			return nil, err
		}
		toks = append(toks, t)
	}
	return toks, rows.Err()
}

// RecordMatch inserts a leak_findings row (idempotent via dedupe_key) and,
// for anything stronger than a bare Mention, creates or attaches an
// incidents row. Automated findings never set an incident straight to
// "confirmed" -- that stays a deliberate human action (admin/incidents.php,
// Phase 7) regardless of how strong the automated evidence looks; see
// ARCHITECTURE.md "Leak Checker" for the full mapping and why.
func (s *Store) RecordMatch(m Match, source, sourceURL string) (created bool, err error) {
	dedupeKey := DedupeKey(source, sourceURL, m.MatchedValue)

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var incidentID *int64
	if m.Confidence != Mention {
		status := "new"
		if m.Confidence == Confirmed {
			status = "probable"
		}
		incidentID, err = findOrCreateIncident(tx, m, source, sourceURL, status)
		if err != nil {
			return false, err
		}
	}

	res, err := tx.Exec(`
		INSERT OR IGNORE INTO leak_findings
			(incident_id, source, source_url, matched_value, confidence, dedupe_key, access_point_id, access_token_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		incidentID, source, sourceURL, m.MatchedValue, string(m.Confidence), dedupeKey, m.AccessPointID, m.TokenID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// findOrCreateIncident groups findings the way the spec requires ("Pokud
// se stejná URL objeví na více místech, seskup nálezy pod odpovídající
// incident"): one open incident per (stream, token) pair, or per
// (stream, access_point) when no specific token was identified.
func findOrCreateIncident(tx *sql.Tx, m Match, source, sourceURL, defaultStatus string) (*int64, error) {
	var query string
	var args []any
	if m.TokenID != nil {
		query = `SELECT id FROM incidents WHERE stream_id = ? AND access_token_id = ? AND status IN ('new','probable','confirmed') LIMIT 1`
		args = []any{m.StreamID, *m.TokenID}
	} else {
		query = `SELECT id FROM incidents WHERE stream_id = ? AND access_token_id IS NULL AND status IN ('new','probable','confirmed') LIMIT 1`
		args = []any{m.StreamID}
	}
	var id int64
	err := tx.QueryRow(query, args...).Scan(&id)
	if err == nil {
		return &id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	res, err := tx.Exec(`
		INSERT INTO incidents (stream_id, access_token_id, source, source_url, status, actions_taken)
		VALUES (?, ?, ?, ?, ?, ?)`,
		m.StreamID, m.TokenID, source, sourceURL, defaultStatus,
		mustJSON([]map[string]string{{"at": time.Now().UTC().Format(time.RFC3339), "actor": "leakchecker", "to": defaultStatus}}))
	if err != nil {
		return nil, err
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &newID, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

type RunSummary struct {
	StreamsChecked  int
	QueriesMade     int
	FindingsCreated int
	Err             error
}

func (s *Store) StartRun(providers []string) (int64, error) {
	providersJSON := mustJSON(providers)
	res, err := s.db.Exec(`INSERT INTO leak_checker_runs (providers_run) VALUES (?)`, providersJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinishRun(runID int64, sum RunSummary) error {
	var errText *string
	if sum.Err != nil {
		msg := sum.Err.Error()
		errText = &msg
	}
	_, err := s.db.Exec(`
		UPDATE leak_checker_runs
		SET finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), streams_checked = ?, queries_made = ?, findings_created = ?, error = ?
		WHERE id = ?`,
		sum.StreamsChecked, sum.QueriesMade, sum.FindingsCreated, errText, runID)
	return err
}
