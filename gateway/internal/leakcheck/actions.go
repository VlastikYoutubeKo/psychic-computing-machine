package leakcheck

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RotationMode returns the stream's rotation_mode ("manual_approval" or
// "auto").
func (s *Store) RotationMode(streamID int64) (string, error) {
	var mode string
	err := s.db.QueryRow(`SELECT rotation_mode FROM streams WHERE id = ?`, streamID).Scan(&mode)
	return mode, err
}

// AutoRevoke is what "Rotate automatically on confirmed leak" does: for a
// Confirmed match on a stream in auto mode, revoke exactly the leaked
// credential -- the identified token for a private access point, or the
// access point itself for a public path_is_secret one -- mark the incident
// confirmed, and log the action on it. It never touches an incident the
// operator already dismissed or resolved.
//
// inactive reports whether the leaked target is revoked after the call
// (revoked now, or already before). revokedNow is true only if this call
// did it.
func (s *Store) AutoRevoke(m Match, incidentID int64) (target string, inactive, revokedNow bool, err error) {
	if m.Confidence != Confirmed {
		return "", false, false, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", false, false, err
	}
	defer tx.Rollback()

	var status string
	var actions sql.NullString
	if err := tx.QueryRow(`SELECT status, actions_taken FROM incidents WHERE id = ?`, incidentID).Scan(&status, &actions); err != nil {
		return "", false, false, err
	}
	if status != "new" && status != "probable" && status != "confirmed" {
		return "", false, false, nil
	}

	var res sql.Result
	if m.TokenID != nil {
		target = fmt.Sprintf("token:%d", *m.TokenID)
		res, err = tx.Exec(`UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
				revoked_reason = 'leak_detected' WHERE id = ? AND revoked_at IS NULL`, *m.TokenID)
	} else {
		target = fmt.Sprintf("access_point:%d", m.AccessPointID)
		res, err = tx.Exec(`UPDATE access_points SET status = 'revoked' WHERE id = ? AND status = 'active'`, m.AccessPointID)
	}
	if err != nil {
		return target, false, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return target, false, false, err
	}
	revokedNow = n > 0

	if revokedNow || status != "confirmed" {
		var history []map[string]string
		if actions.Valid && actions.String != "" {
			_ = json.Unmarshal([]byte(actions.String), &history)
		}
		entry := map[string]string{"at": time.Now().UTC().Format(time.RFC3339), "actor": "leakchecker", "to": "confirmed"}
		if revokedNow {
			entry["action"] = "auto_revoked"
			entry["target"] = target
		}
		history = append(history, entry)
		if _, err := tx.Exec(`UPDATE incidents SET status = 'confirmed', actions_taken = ? WHERE id = ?`, mustJSON(history), incidentID); err != nil {
			return target, false, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return target, false, false, err
	}
	return target, true, revokedNow, nil
}

// ReplyAllowlist returns the lower-cased "owner/repo" entries from the
// github_reply_allowlist setting (comma, space or newline separated).
// Only these repos get an automatic public reply; everything else needs
// an operator to click "Reply on GitHub" in the admin.
func (s *Store) ReplyAllowlist() (map[string]bool, error) {
	v, ok, err := s.setting("github_reply_allowlist")
	if err != nil || !ok {
		return map[string]bool{}, err
	}
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		out[strings.ToLower(strings.TrimSpace(f))] = true
	}
	return out, nil
}

// HasReply reports whether a reply was already posted to this issue/PR.
func (s *Store) HasReply(sourceURL string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM leak_replies WHERE source_url = ?`, sourceURL).Scan(&n)
	return n > 0, err
}

// RecordReply stores the posted reply (unique per source_url) and logs it
// on the incident.
func (s *Store) RecordReply(sourceURL string, incidentID int64, commentURL, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO leak_replies (source_url, incident_id, comment_url, actor) VALUES (?, ?, ?, ?)`,
		sourceURL, incidentID, commentURL, actor); err != nil {
		return err
	}
	var actions sql.NullString
	if err := tx.QueryRow(`SELECT actions_taken FROM incidents WHERE id = ?`, incidentID).Scan(&actions); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var history []map[string]string
	if actions.Valid && actions.String != "" {
		_ = json.Unmarshal([]byte(actions.String), &history)
	}
	history = append(history, map[string]string{"at": time.Now().UTC().Format(time.RFC3339), "actor": actor, "action": "github_reply", "target": commentURL})
	if _, err := tx.Exec(`UPDATE incidents SET actions_taken = ? WHERE id = ?`, mustJSON(history), incidentID); err != nil {
		return err
	}
	return tx.Commit()
}

var issueURLRe = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)/(issues|pull)/([0-9]+)$`)

// ParseIssueURL extracts owner/repo/number from an issue or PR html_url.
// Code search hits (blob URLs) don't match: there's nowhere to comment.
func ParseIssueURL(u string) (owner, repo string, number int, ok bool) {
	m := issueURLRe.FindStringSubmatch(u)
	if m == nil {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(m[4])
	if err != nil || n <= 0 {
		return "", "", 0, false
	}
	return m[1], m[2], n, true
}

// NoticeImagePath is served by the gateway (gatewayhttp) on the stream
// base URL, so the public comment never reveals the admin host.
const NoticeImagePath = "/_sv/notice.png"

// NoticeBody is the public comment text. Deliberately says nothing about
// which stream, token or source this was -- only that the link is dead.
func NoticeBody(baseURL string) string {
	img := strings.TrimRight(baseURL, "/") + NoticeImagePath
	if u, err := url.Parse(img); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		img = ""
	}
	body := "This stream link has been revoked by its owner and no longer works."
	if img != "" {
		body += "\n\n![Stream unavailable](" + img + ")"
	}
	return body + "\n\n<sub>Automated notice from StreamVault.</sub>"
}
