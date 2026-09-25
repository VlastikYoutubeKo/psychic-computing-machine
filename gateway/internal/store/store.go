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
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("store: not found")

type Store struct {
	db *sql.DB
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
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

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
	ReplacementReason  string
	ReplacementMessage sql.NullString
}

// AccessPoint is a resolved public_path -> stream mapping.
type AccessPoint struct {
	ID           int64
	StreamID     int64
	PublicPath   string
	Visibility   string // public|private
	OutputFormat string
	Status       string // active|revoked
	Stream       Stream
}

// ResolveAccessPoint looks up an access point by its exact public_path,
// joined with its parent stream. Callers must check Status/Stream.Status
// themselves: a revoked-but-existing row must produce replacement content
// (410), not a plain 404, so the two cases are deliberately not collapsed
// here.
func (s *Store) ResolveAccessPoint(publicPath string) (*AccessPoint, error) {
	row := s.db.QueryRow(`
		SELECT ap.id, ap.stream_id, ap.public_path, ap.visibility, ap.output_format, ap.status,
		       st.id, st.name, st.source_type, st.source_url, st.source_username,
		       st.source_password_enc, st.status, st.replacement_reason, st.replacement_message
		FROM access_points ap
		JOIN streams st ON st.id = ap.stream_id
		WHERE ap.public_path = ?`, publicPath)

	var ap AccessPoint
	if err := row.Scan(
		&ap.ID, &ap.StreamID, &ap.PublicPath, &ap.Visibility, &ap.OutputFormat, &ap.Status,
		&ap.Stream.ID, &ap.Stream.Name, &ap.Stream.SourceType, &ap.Stream.SourceURL,
		&ap.Stream.SourceUsername, &ap.Stream.SourcePasswordEnc, &ap.Stream.Status,
		&ap.Stream.ReplacementReason, &ap.Stream.ReplacementMessage,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
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
	ID     int64
	Status TokenStatus
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
		return TokenInfo{ID: id, Status: TokenRevoked}, nil
	}
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, expiresAt.String); err == nil && time.Now().After(t) {
			return TokenInfo{ID: id, Status: TokenExpired}, nil
		}
	}
	return TokenInfo{ID: id, Status: TokenValid}, nil
}

// TouchToken best-effort updates last_used_at. Failures are not fatal to the
// request being served -- this is bookkeeping, not an access decision.
func (s *Store) TouchToken(tokenID int64) {
	_, _ = s.db.Exec(`UPDATE access_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, tokenID)
}
