package gatewayhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"streamvault/gateway/internal/nodeproto"
	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

// Control-plane side of relay nodes (see internal/node for the node side).
//
//   GET  /_sv/node/install.sh  public install script (no secrets inside)
//   GET  /_sv/node/binary      this gateway executable        [node token]
//   GET  /_sv/node/config      streams + revocations           [node token]
//   POST /_sv/node/status      heartbeat and metrics           [node token]

const (
	nodePollSeconds   = 10
	nodeOnlineWindow  = 45 * time.Second // heartbeat age after which a node counts as offline
	nodeURLLifetime   = 12 * time.Hour   // signed viewer URLs; revocation is enforced by the lists
	maxNodeStatusBody = 64 << 10
)

func (h *Handler) serveNodeAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch path := strings.TrimPrefix(r.URL.Path, "/_sv/node/"); {
	case path == "install.sh" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		h.serveNodeInstallScript(w, r)
	case path == "binary" && r.Method == http.MethodGet:
		if _, _, ok := h.authNode(w, r); ok {
			h.serveNodeBinary(w, r)
		}
	case path == "config" && r.Method == http.MethodGet:
		if n, secret, ok := h.authNode(w, r); ok {
			h.serveNodeConfig(w, n, secret)
		}
	case path == "status" && r.Method == http.MethodPost:
		if n, _, ok := h.authNode(w, r); ok {
			h.acceptNodeStatus(w, r, n)
		}
	default:
		http.NotFound(w, r)
	}
}

// authNode validates "Authorization: Bearer svn_<id>_<secret>" and returns
// the node and its decrypted secret. Every failure is the same 401 so the
// endpoint doesn't reveal which node ids exist.
func (h *Handler) authNode(w http.ResponseWriter, r *http.Request) (*store.Node, string, bool) {
	deny := func() (*store.Node, string, bool) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, "", false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return deny()
	}
	id, secret, ok := nodeproto.ParseToken(strings.TrimPrefix(auth, "Bearer "))
	if !ok {
		return deny()
	}
	n, err := h.Store.NodeByID(id)
	if err != nil || n.Status == "disabled" || !nodeproto.HashMatches(secret, n.TokenHash) {
		return deny()
	}
	return n, secret, true
}

func (h *Handler) serveNodeConfig(w http.ResponseWriter, n *store.Node, secret string) {
	streams, err := h.Store.NodeStreams(n.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	aps, tokens, err := h.Store.NodeRevocations(n.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cfg := nodeproto.Config{NodeID: n.ID, ServerTime: time.Now().Unix(), PollSeconds: nodePollSeconds,
		Streams: []nodeproto.StreamConfig{}, RevokedAccessPoints: aps, RevokedTokens: tokens}
	cfgKey := nodeproto.ConfigKey(secret)
	for _, st := range streams {
		sc := nodeproto.StreamConfig{ID: st.ID, SourceType: st.SourceType, SourceURL: st.SourceURL}
		if st.SourceUsername.Valid && st.SourcePasswordEnc.Valid {
			if h.Key == nil {
				log.Printf("node %d: stream %d needs credentials but no key is loaded", n.ID, st.ID)
				continue
			}
			pw, err := secretbox.Decrypt(h.Key, st.SourcePasswordEnc.String)
			if err != nil {
				log.Printf("node %d: stream %d credentials unreadable", n.ID, st.ID)
				continue
			}
			enc, err := secretbox.Encrypt(cfgKey, pw)
			if err != nil {
				continue
			}
			sc.SourceUsername, sc.SourcePasswordEnc = st.SourceUsername.String, enc
		}
		cfg.Streams = append(cfg.Streams, sc)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (h *Handler) acceptNodeStatus(w http.ResponseWriter, r *http.Request, n *store.Node) {
	var st nodeproto.Status
	body, err := io.ReadAll(io.LimitReader(r.Body, maxNodeStatusBody+1))
	if err != nil || len(body) > maxNodeStatusBody || json.Unmarshal(body, &st) != nil {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	// Re-marshal the typed struct: only known fields reach the admin.
	clean, _ := json.Marshal(st)
	if err := h.Store.RecordNodeStatus(n.ID, string(clean)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveNodeBinary(w http.ResponseWriter, r *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		http.Error(w, "binary unavailable", http.StatusServiceUnavailable)
		return
	}
	f, err := os.Open(exe)
	if err != nil {
		http.Error(w, "binary unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "binary unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="streamvault-gateway"`)
	http.ServeContent(w, r, "streamvault-gateway", info.ModTime(), f)
}

// nodeOnline: active and heard from recently. Offline nodes are bypassed:
// the control gateway then serves the stream itself.
func nodeOnline(n *store.NodeRef, now time.Time) bool {
	if n == nil || n.Status != "active" || !n.LastSeenAt.Valid || n.PublicURL == "" {
		return false
	}
	seen, err := time.Parse("2006-01-02T15:04:05.000Z", n.LastSeenAt.String)
	if err != nil {
		return false
	}
	return now.Sub(seen) <= nodeOnlineWindow
}

// redirectToNode sends an entry request to the stream's relay node with a
// signed URL, if the node is online. False means "serve locally".
func (h *Handler) redirectToNode(w http.ResponseWriter, r *http.Request, ap *store.AccessPoint, token store.TokenInfo) bool {
	n := ap.Stream.Node
	if !nodeOnline(n, time.Now()) || h.Key == nil {
		return false
	}
	secret, err := secretbox.Decrypt(h.Key, n.SecretEnc)
	if err != nil {
		log.Printf("node %d: secret unreadable, serving stream %d locally", n.ID, ap.Stream.ID)
		return false
	}
	target, err := nodeViewerURL(n.PublicURL, string(secret), ap.Stream.ID, ap.ID, token.ID, time.Now().Add(nodeURLLifetime).Unix())
	if err != nil {
		log.Printf("node %d: bad public URL, serving stream %d locally", n.ID, ap.Stream.ID)
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
	return true
}

func nodeViewerURL(publicURL, secret string, streamID, apID, tokenID, exp int64) (string, error) {
	base, err := url.Parse(strings.TrimRight(publicURL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return "", errors.New("invalid node public URL")
	}
	q := url.Values{}
	q.Set("ap", fmt.Sprint(apID))
	q.Set("tok", fmt.Sprint(tokenID))
	q.Set("exp", fmt.Sprint(exp))
	q.Set("sig", nodeproto.Sign(secret, streamID, apID, tokenID, exp))
	return fmt.Sprintf("%s/n/%d/index.m3u8?%s", base.String(), streamID, q.Encode()), nil
}

func (h *Handler) serveNodeInstallScript(w http.ResponseWriter, r *http.Request) {
	scheme := "https"
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	control := scheme + "://" + r.Host
	if !validHost(r.Host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = io.WriteString(w, strings.ReplaceAll(nodeInstallScript, "@CONTROL_URL@", control))
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

// nodeInstallScript installs a node as a systemd service. It contains no
// secrets: the node token comes from the environment of the one-liner shown
// once in the admin, and is written to a root-only env file.
const nodeInstallScript = `#!/bin/sh
# StreamVault relay node installer. Usage (from the admin's Nodes page):
#   curl -fsSL @CONTROL_URL@/_sv/node/install.sh | sudo STREAMVAULT_NODE_TOKEN=svn_... sh
set -eu
CONTROL="${STREAMVAULT_CONTROL_URL:-@CONTROL_URL@}"
TOKEN="${STREAMVAULT_NODE_TOKEN:?set STREAMVAULT_NODE_TOKEN (shown once in the admin)}"
LISTEN="${STREAMVAULT_LISTEN:-0.0.0.0:8090}"
case "$TOKEN" in svn_*) ;; *) echo "invalid node token" >&2; exit 1;; esac
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo "only x86_64 (amd64) nodes are supported" >&2; exit 1; }

if ! command -v ffmpeg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ffmpeg
  elif command -v dnf >/dev/null; then dnf install -y ffmpeg
  elif command -v apk >/dev/null; then apk add --no-cache ffmpeg
  else echo "install ffmpeg first" >&2; exit 1; fi
fi

install -d -m 0755 /opt/streamvault-node
curl -fsS -H "Authorization: Bearer $TOKEN" -o /opt/streamvault-node/streamvault-gateway.new "$CONTROL/_sv/node/binary"
chmod 0755 /opt/streamvault-node/streamvault-gateway.new
mv /opt/streamvault-node/streamvault-gateway.new /opt/streamvault-node/streamvault-gateway
id streamvault-node >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin streamvault-node

umask 077
cat > /etc/streamvault-node.env <<EOF
STREAMVAULT_MODE=node
STREAMVAULT_CONTROL_URL=$CONTROL
STREAMVAULT_NODE_TOKEN=$TOKEN
STREAMVAULT_LISTEN=$LISTEN
EOF
umask 022

cat > /etc/systemd/system/streamvault-node.service <<'EOF'
[Unit]
Description=StreamVault relay node
Wants=network-online.target
After=network-online.target

[Service]
EnvironmentFile=/etc/streamvault-node.env
ExecStart=/opt/streamvault-node/streamvault-gateway
User=streamvault-node
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now streamvault-node
systemctl restart streamvault-node
echo "StreamVault node installed and started (listening on $LISTEN)."
echo "It should show as online in the admin within ~15 seconds."
`
