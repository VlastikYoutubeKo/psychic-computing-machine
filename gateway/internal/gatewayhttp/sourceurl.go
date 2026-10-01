package gatewayhttp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

// Credential placeholders in a stream's source_url. Some sources carry the
// credentials in the URL itself rather than in an Authorization header --
// Xtream Codes panels use http://host/live/<user>/<pass>/<id>.ts. Storing
// such a URL verbatim would put the password in the database, the admin UI
// and node configs in plaintext, so the stored URL keeps these placeholders
// and the gateway substitutes the decrypted credentials only at fetch time.
const (
	usernamePlaceholder = "{username}"
	passwordPlaceholder = "{password}"
)

func usesCredentialPlaceholders(rawURL string) bool {
	return strings.Contains(rawURL, usernamePlaceholder) || strings.Contains(rawURL, passwordPlaceholder)
}

// sourceEntryURL parses a stream's source URL, filling in credential
// placeholders. The returned URL may contain the source password: never log
// it or put it in an error message.
func (h *Handler) sourceEntryURL(s store.Stream) (*url.URL, error) {
	raw := s.SourceURL
	if usesCredentialPlaceholders(raw) {
		if !s.SourceUsername.Valid || !s.SourcePasswordEnc.Valid {
			return nil, errors.New("source URL uses credential placeholders but the stream has no credentials")
		}
		if h.Key == nil {
			return nil, fmt.Errorf("stream %d requires source credentials but no encryption key is loaded", s.ID)
		}
		pw, err := secretbox.Decrypt(h.Key, s.SourcePasswordEnc.String)
		if err != nil {
			return nil, errors.New("decrypting source credentials failed")
		}
		// Path and query need different escaping.
		path, query, hasQuery := strings.Cut(raw, "?")
		path = strings.NewReplacer(
			usernamePlaceholder, url.PathEscape(s.SourceUsername.String),
			passwordPlaceholder, url.PathEscape(string(pw)),
		).Replace(path)
		raw = path
		if hasQuery {
			raw += "?" + strings.NewReplacer(
				usernamePlaceholder, url.QueryEscape(s.SourceUsername.String),
				passwordPlaceholder, url.QueryEscape(string(pw)),
			).Replace(query)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("unparsable source URL") // never echo the URL: it may hold credentials
	}
	return u, nil
}

// redactURLError strips the request URL from a *url.Error in place (keeping
// the error chain intact), so a fetch failure that ends up in a log line
// can't carry credentials or a secret path embedded in the URL.
func redactURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if u, perr := url.Parse(uerr.URL); perr == nil && u.Host != "" {
			uerr.URL = u.Scheme + "://" + u.Host + "/…"
		} else {
			uerr.URL = "…"
		}
	}
	return err
}
