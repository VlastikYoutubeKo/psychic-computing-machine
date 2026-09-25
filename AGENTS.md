# AGENTS.md -- context handoff

You're picking up StreamVault, a stream URL manager + leak protection
project living inside `/root/caddy-setup` (a shared Caddy reverse-proxy
setup with ~15 other small apps). Read this before doing anything else;
it'll save you from re-deriving decisions already made and, more
importantly, from breaking things that already work.

## Read these first, in order

1. `ROADMAP.md` -- what's actually done vs. stubbed. Trust this over
   assumptions from the spec or from file/directory names.
2. `ARCHITECTURE.md` -- why the gateway is a separate Go process, the
   routing convention, the SSRF boundary. Don't redesign this without
   understanding why the alternatives were rejected (notably: this repo
   already has a real incident, `sktv.mxnticek.eu`, from using PHP-FPM as
   a video segment proxy -- see the `docker-compose.yml` comment dated
   2026-09-03 -- which is why the gateway is Go, not PHP).
3. `SECURITY.md` -- especially "Existing exposure found during research":
   `restream.mxnticek.eu` currently proxies straight to the real backend
   with no auth. That's the reason this project exists. It has NOT been
   fixed yet (would require a production Caddyfile edit).

## Ground rules that still apply to you

- **Never edit `/root/caddy-setup/caddy/conf/Caddyfile` without explicit
  user approval.** It serves ~15 other production sites. If a Caddy
  reload is needed after an approved edit, note that a `caddy reload`
  alone has not reliably picked up Caddyfile changes on this host before
  -- the `caddy` container may need recreating (`docker compose up -d
  --force-recreate caddy` or similar), which is itself worth confirming
  with the user first since it's a brief interruption to every site Caddy
  serves, not just this one.
- **This host is memory-constrained.** At last check: 7.8 GiB RAM, 138 MiB
  free, 2.2 GiB swap in use. Don't add a new always-on process without
  thinking about its RSS. This is why the gateway is a compiled Go binary
  and not, say, a Node service.
- **Don't fake functionality.** If you're asked to "finish" a section that
  ROADMAP.md marks not-started, actually implement it, or say clearly that
  you didn't get to it. The admin UI's own convention (see `settings.php`,
  `incidents.php`, `index.php`) is to state outright in the page when a
  feature isn't wired up yet, rather than showing an empty state that
  could be misread as "nothing found = safe."
- **Run the tests before claiming something works**:
  `gateway && go test ./...`, then `tests/e2e_gateway.sh`,
  `tests/e2e_admin_flow.sh`, `tests/crypto_interop.sh`, and
  `tests/e2e_incidents.sh` for incident UI changes, and
  `tests/e2e_leak_admin.sh` for GitHub configuration and coverage UI. If you change the routing
  convention, the manifest rewriter, or the crypto wire format, these are
  exactly the tests that will tell you if you broke something real
  (they're written against actual ffmpeg-generated HLS and a real HTTP
  round trip through the PHP dev server, not mocks).
- **Get an independent review of anything security-critical before calling
  it done, and actually act on what it finds.** The first version of the
  gateway passed its entire test suite (including a hand-written SSRF
  check) and still shipped three real bugs: a reversible "opaque" link, an
  unchecked redirect that could walk the client off the allowlisted host,
  and a missing leading slash that would have broken playback in any real
  player. All three existed because the tests were written by the same
  author with the same blind spots -- see ARCHITECTURE.md "How this was
  actually verified" and CHANGELOG.md's "Security review fixes" entry for
  specifics. Don't skip this step because your own tests are green.
- **Update ROADMAP.md, CHANGELOG.md, and this file** as you go, not just
  at the end -- if your session gets cut off, the next person (human or
  AI) should be able to tell what's actually true from these files alone,
  per the project's own instruction not to rely on re-explaining context
  from scratch.

## Where things live

```
  streamvault/
  migrations/0001_init.sql        -- schema, source of truth (both PHP and Go read this file directly in tests)
  gateway/                        -- Go module `streamvault/gateway`
    cmd/gateway/main.go           -- entrypoint, reads STREAMVAULT_DB / STREAMVAULT_KEY_FILE / STREAMVAULT_LISTEN
    internal/store/               -- SQLite read path (token validation, access point resolution)
    internal/hls/                 -- playlist parsing/rewriting (pure functions, easy to unit test)
    internal/blobcodec/           -- encrypts the source URL inside /r/ links (ephemeral, in-memory key -- see ARCHITECTURE.md)
    internal/secretbox/           -- AES-256-GCM envelope, mirrored in PHP (durable, for source credentials)
    internal/gatewayhttp/         -- the actual HTTP handler / routing logic
    internal/remux/               -- bounded FFmpeg MPEG-TS to HLS sessions
  admin/                          -- PHP 8.2, server-rendered, no framework
    includes/                     -- config, db (+ migration runner), auth, csrf, secret_box (PHP mirror), helpers
    cli/create_operator.php       -- CLI-only bootstrap, deliberately not an HTTP endpoint
  tests/                          -- bash-driven integration tests, see README.md "Tests"
    e2e_incidents.sh               -- manual incident creation/triage through the real PHP admin
    e2e_leak_admin.sh              -- GitHub token/source settings and scan request, no external API calls
  discord-bot/                    -- empty, Phase 9, not started
```

## Naming / branding

"StreamVault" was chosen (not specified by the user) to communicate the
core value prop: managing stream URLs *and* protecting them from leaking.
Feel free to revisit if the user has a different preference -- this
wasn't treated as load-bearing anywhere beyond doc titles and the login
page heading.
