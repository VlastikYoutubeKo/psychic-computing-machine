# StreamVault

Stream URL Manager & Leak Protection for self-hosted IPTV/HLS streaming
(datarhei Restreamer, Tvheadend, generic HLS). Lets you publish a stream at
a URL you choose, hides the real source, issues per-recipient revocable
access tokens, and (once the later phases land) watches for leaked URLs on
GitHub/GitLab and rotates access automatically.

**Status: early, but the core is real and tested.** See [ROADMAP.md](ROADMAP.md)
for exactly what works today vs. what's still a stub. Don't take "the admin
UI has a page for X" as "X works" -- pages that aren't wired to real logic
say so explicitly, in the UI itself.

## What exists right now

- **Stream gateway** (`gateway/`, Go): a single always-on process that Caddy
  points at. Resolves `public_path[/token]` to a source stream, proxies HLS
  manifests and rewrites every reference (segments, keys, init segments,
  alt audio, absolute or relative) so the source URL never reaches a
  client. Revoking a token blocks it immediately, for the manifest *and*
  every segment URL already handed out. No Caddy reload needed to add,
  edit, or rotate a stream -- it's all reads from SQLite.
- **MPEG-TS input**: the same gateway detects an MPEG-TS entry source and
  remuxes it to HLS with FFmpeg (`-c copy`, no transcoding). FFmpeg must be
  installed where the gateway runs. Sessions are shared per stream and
  limited to two on this host; a live Tvheadend feed still needs a real
  deployment test before that integration can be called complete.
- **Admin UI** (`admin/`, PHP 8.2): real login, stream CRUD, access point
  management (public/private), per-recipient token issue/revoke, GitHub
  monitoring settings and actual scan-run status, audit log.
  Server-rendered, no JS framework.
- **Shared SQLite schema** (`migrations/`), including incidents, monitored
  sources, scan runs and deduplicated findings.
- **Manual incident triage** (`admin/incidents.php`): record evidence for a
  stream, then confirm, dismiss, or resolve the incident with an audit trail.
  These actions do not revoke tokens or rotate source credentials.
- **GitHub Leak Checker code** (`gateway/cmd/leakchecker/`): a one-shot scan
  over active access points, with extra queries for enabled repositories and
  organizations. Local tests use a mock API. A systemd timer is prepared in
  `deploy/systemd/`, but has not been installed; no live GitHub scan has
  been verified.

## What's explicitly NOT implemented yet

Deployed/verified GitHub Leak Checker scans, GitLab/IPTV playlist scanning, automatic rotation,
Discord bot, replacement HLS video generation (only a static HTML page
today), M3U export, EPG, Tvheadend channel import, bandwidth stats. See
ROADMAP.md.

## Quick start (local/dev)

```bash
cd streamvault
export STREAMVAULT_DB="$PWD/data/streamvault.sqlite"
export STREAMVAULT_KEY_FILE="$PWD/data/secret.key"

# 1. Create the first admin account (also creates the DB + runs migrations)
echo 'your-password-here' | php admin/cli/create_operator.php admin

# 2. Serve the admin UI (dev only -- see DEPLOYMENT.md for php-fpm+Caddy)
php -S 127.0.0.1:8091 -t admin

# 3. Build and run the gateway, pointed at the same DB/key
cd gateway && go build -o /tmp/streamvault-gateway ./cmd/gateway
STREAMVAULT_DB="$STREAMVAULT_DB" STREAMVAULT_KEY_FILE="$STREAMVAULT_KEY_FILE" \
  STREAMVAULT_LISTEN=127.0.0.1:8090 /tmp/streamvault-gateway
```

Then open http://127.0.0.1:8091, log in, add a stream, add a public or
private access point, and fetch it from the gateway at
`http://127.0.0.1:8090/<public_path>[.m3u8|/<token>.m3u8]`.

## Tests

```bash
cd gateway && go test ./...              # unit tests (playlist rewriting, token lifecycle, crypto)
tests/e2e_gateway.sh                     # gateway alone against a real ffmpeg-generated HLS source
tests/e2e_admin_flow.sh                  # admin UI (real HTTP forms) + gateway, same DB, full lifecycle
tests/crypto_interop.sh                  # PHP <-> Go source-credential encryption format cross-check
tests/e2e_incidents.sh                   # manual incident creation, CSRF, triage and audit over HTTP
tests/e2e_leak_admin.sh                  # GitHub token/source settings, scan queue and run status (no GitHub API)
```

The PHP admin and Go checker tests pass locally; see ROADMAP.md for deployment
status. Tests run on Debian 13 with Go 1.24 and
PHP 8.4 CLI / 8.2-fpm.

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) -- design decisions and why
- [SECURITY.md](SECURITY.md) -- threat model, what's actually enforced today
- [DEPLOYMENT.md](DEPLOYMENT.md) -- current integration and pending production cutover/timer
- [ROADMAP.md](ROADMAP.md) -- phase-by-phase status
- [CHANGELOG.md](CHANGELOG.md)
- [AGENTS.md](AGENTS.md) -- context handoff for whoever (human or AI) picks this up next
