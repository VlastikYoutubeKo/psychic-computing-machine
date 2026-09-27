// Package store is the gateway's read path into the shared StreamVault
// SQLite database. The admin UI (PHP) owns writes; the gateway only reads
// access_points/streams/access_tokens and performs the narrow best-effort
// writes needed for token bookkeeping (last_used_at).
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("store: not found")

type Store struct {
	db   *sql.DB
	path string
}

// Open opens the shared SQLite database in WAL mode. It does not run
// migrations -- the admin app owns schema creation (see migrations/) so the
// gateway never has write-DDL privileges it doesn't need.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4) // gateway is read-mostly; SQLite serializes writers anyway
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error    { return s.db.Close() }
func (s *Store) DataDir() string { return filepath.Dir(s.path) }

// SlateAudioSettings reads only the few operator-controlled values used at
// session startup. The manager validates the filename/URL independently.
func (s *Store) SlateAudioSettings() (file, streamURL string, volume int, err error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings WHERE key IN ('slate_audio_file','slate_audio_url','slate_audio_volume')`)
	if err != nil {
		return "", "", 0, err
	}
	defer rows.Close()
	volume = 0
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			return "", "", 0, err
		}
		switch key {
		case "slate_audio_file":
			file = value
		case "slate_audio_url":
			streamURL = value
		case "slate_audio_volume":
			if _, err = fmt.Sscanf(value, "%d", &volume); err != nil {
				return "", "", 0, err
			}
		}
	}
	return file, streamURL, volume, rows.Err()
}

func (s *Store) SlateText(reason string) (title, subtitle string, err error) {
	err = s.db.QueryRow(`SELECT title, subtitle FROM slate_texts WHERE reason = ?`, reason).Scan(&title, &subtitle)
	return title, subtitle, err
}

// Stream is the subset of streams columns the gateway needs to fetch and
// authenticate to the source.
type Stream struct {
	ID                 int64
	Name               string
	SourceType         string
	SourceURL          string
	SourceUsername     sql.NullString
	SourcePasswordEnc  sql.NullString
	Status             string
	DisabledAt         sql.NullString
	ReplacementReason  string
	ReplacementMessage sql.NullString
	AllowRemux         bool
}

// AccessPoint is a resolved public_path -> stream mapping.
type AccessPoint struct {
	ID           int64
	StreamID     int64
	PublicPath   string
	Visibility   string // public|private
	OutputFormat string
	Status       string // active|revoked
	RevokedAt    sql.NullString
	Stream       Stream
}

// ResolveAccessPoint looks up an access point by its exact public_path,
// joined with its parent stream. Callers must check Status/Stream.Status
// themselves: a revoked-but-existing row must produce replacement content
// (410), not a plain 404, so the two cases are deliberately not collapsed
// here.
func (s *Store) ResolveAccessPoint(publicPath string) (*AccessPoint, error) {
	row := s.db.QueryRow(`
		SELECT ap.id, ap.stream_id, ap.public_path, ap.visibility, ap.output_format, ap.status, ap.revoked_at,
		       st.id, st.name, st.source_type, st.source_url, st.source_username,
		       st.source_password_enc, st.status, st.disabled_at, st.replacement_reason, st.replacement_message,
		       CASE WHEN owner.role = 'user' THEN owner.allow_remux ELSE 1 END
		FROM access_points ap
		JOIN streams st ON st.id = ap.stream_id
		LEFT JOIN operators owner ON owner.id = st.owner_id
		WHERE ap.public_path = ?`, publicPath)

	var ap AccessPoint
	var allowRemux int
	if err := row.Scan(
		&ap.ID, &ap.StreamID, &ap.PublicPath, &ap.Visibility, &ap.OutputFormat, &ap.Status, &ap.RevokedAt,
		&ap.Stream.ID, &ap.Stream.Name, &ap.Stream.SourceType, &ap.Stream.SourceURL,
		&ap.Stream.SourceUsername, &ap.Stream.SourcePasswordEnc, &ap.Stream.Status, &ap.Stream.DisabledAt,
		&ap.Stream.ReplacementReason, &ap.Stream.ReplacementMessage, &allowRemux,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	ap.Stream.AllowRemux = allowRemux != 0
	return &ap, nil
}

// TokenStatus is the outcome of validating a raw bearer token against an
// access point's token list.
type TokenStatus int

const (
	TokenInvalid TokenStatus = iota
	TokenValid
	TokenRevoked
	TokenExpired
)

type TokenInfo struct {
	ID        int64
	Status    TokenStatus
	RevokedAt sql.NullString
	ExpiresAt sql.NullString
}

// ValidateToken hashes rawToken and checks it against access_tokens for the
// given access point. A token that exists but is revoked or past its
// expiry is distinguished from one that never existed, so the caller can
// serve a specific "revoked" replacement rather than a generic 404 --
// without ever having to store or compare the raw token itself.
func (s *Store) ValidateToken(accessPointID int64, rawToken string) (TokenInfo, error) {
	sum := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(sum[:])

	var id int64
	var revokedAt, expiresAt sql.NullString
	err := s.db.QueryRow(`
		SELECT id, revoked_at, expires_at FROM access_tokens
		WHERE access_point_id = ? AND token_hash = ?`, accessPointID, hash).
		Scan(&id, &revokedAt, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenInfo{Status: TokenInvalid}, nil
		}
		return TokenInfo{}, err
	}
	if revokedAt.Valid {
		return TokenInfo{ID: id, Status: TokenRevoked, RevokedAt: revokedAt, ExpiresAt: expiresAt}, nil
	}
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, expiresAt.String); err == nil && time.Now().After(t) {
			return TokenInfo{ID: id, Status: TokenExpired, ExpiresAt: expiresAt}, nil
		}
	}
	return TokenInfo{ID: id, Status: TokenValid}, nil
}

// TouchToken best-effort updates last_used_at. Failures are not fatal to the
// request being served -- this is bookkeeping, not an access decision.
func (s *Store) TouchToken(tokenID int64) {
	_, _ = s.db.Exec(`UPDATE access_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, tokenID)
}

// AlwaysOnStreams returns active streams flagged always_on whose owner may
// run a 24/7 relay (admins and ownerless streams always; users need both
// allow_always_on and allow_remux, since a relay is a pinned remux session).
func (s *Store) AlwaysOnStreams() ([]Stream, error) {
	rows, err := s.db.Query(`
		SELECT st.id, st.name, st.source_type, st.source_url, st.source_username,
		       st.source_password_enc, st.status, st.disabled_at, st.replacement_reason, st.replacement_message
		FROM streams st
		LEFT JOIN operators owner ON owner.id = st.owner_id
		WHERE st.always_on = 1 AND st.status = 'active'
		  AND (owner.id IS NULL OR owner.role = 'admin'
		       OR (owner.status = 'active' AND owner.allow_always_on = 1 AND owner.allow_remux = 1))
		ORDER BY st.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stream
	for rows.Next() {
		var st Stream
		if err := rows.Scan(&st.ID, &st.Name, &st.SourceType, &st.SourceURL, &st.SourceUsername,
			&st.SourcePasswordEnc, &st.Status, &st.DisabledAt, &st.ReplacementReason, &st.ReplacementMessage); err != nil {
			return nil, err
		}
		st.AllowRemux = true
		out = append(out, st)
	}
	return out, rows.Err()
}

// SetRuntime records the always-on relay state shown in the admin.
func (s *Store) SetRuntime(streamID int64, state, detail string) error {
	_, err := s.db.Exec(`INSERT INTO stream_runtime (stream_id, state, detail, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(stream_id) DO UPDATE SET state = excluded.state, detail = excluded.detail, updated_at = excluded.updated_at`,
		streamID, state, detail)
	return err
}

// ClearRuntime removes relay state for streams that are no longer always-on.
func (s *Store) ClearRuntime(keep []int64) error {
	if len(keep) == 0 {
		_, err := s.db.Exec(`DELETE FROM stream_runtime`)
		return err
	}
	args := make([]any, len(keep))
	ph := make([]string, len(keep))
	for i, id := range keep {
		args[i], ph[i] = id, "?"
	}
	_, err := s.db.Exec(`DELETE FROM stream_runtime WHERE stream_id NOT IN (`+strings.Join(ph, ",")+`)`, args...)
	return err
}
