# Changelog

## 2026-09-25 -- Manual incident triage

- Added authenticated, CSRF-protected incident creation in the PHP admin,
  tied to an existing stream, with validated optional evidence URL and
  escaped notes.
- Added explicit state transitions (`new/probable -> confirmed/dismissed`,
  `confirmed -> resolved`) with an append-only action history in the
  incident row and a matching audit event. Rejected transitions leave the
  incident unchanged. No token is revoked and no source credential is
  rotated by these actions.
- Added `tests/e2e_incidents.sh`, exercising login, CSRF, incident creation,
  HTML escaping, allowed and rejected transitions, action history and audit
  rows through the actual PHP admin over HTTP and a temporary SQLite DB.

## 2026-09-25 (later) -- Independent review of the remux work + deployment prep

Reviewed Codex's Phase 4 work above rather than taking the green test suite
at face value (see AGENTS.md's own advice on this). Findings:

- **Dead code in `cmd/gateway/main.go`**: a duplicate `if err != nil`
  check after `defer h.Remux.Close()` was unreachable (the same `err` had
  already been checked and would have exited via `log.Fatalf` above it).
  Removed.
- **Missing `ffmpeg` in the gateway's Docker image**: `gateway/Dockerfile`
  (written in this session, before Phase 4 existed) shipped an
  `alpine:3.20` runtime with no `ffmpeg` -- the image would build and
  start fine and only fail, confusingly, the first time a stream turned
  out to be MPEG-TS. Added `apk add ffmpeg`; rebuilt and confirmed
  `ffmpeg -version` runs as UID 33 inside the container. Image grew from
  ~23 MB to 151 MB as a result (ffmpeg's dependency chain) -- noted in
  DEPLOYMENT.md, not hidden.
- Everything else in the remux design held up under review: segment path
  resolution is validated against a strict filename pattern (no path
  traversal even though the blob is already authenticated), revocation
  still applies to remuxed segments (they go through the same token
  re-validation as any other resource), and the synthetic `sv-remux://`
  scheme trick cleanly reuses the existing playlist-rewriting machinery
  instead of forking a parallel code path.
- One non-blocking robustness note added to ROADMAP.md: `remux.Manager`
  holds one mutex across session lookup/start/segment-serving, so starting
  a new session (bounded to ~10s worst case by the shared Transport's
  timeouts, not unbounded) briefly stalls unrelated already-running
  sessions too. Not fixed now -- flagged for before this carries real
  concurrent load, consistent with not letting a known gap go
  undocumented just because it isn't urgent.
- Re-ran the full test suite independently after the above fixes: `go
  test ./...` (all packages, including the new `remux` and MPEG-TS
  handler tests), and all three `tests/e2e_*.sh` -- all pass.
- Deployment prep for the already-approved `help.iptvlookup.com` (admin UI
  only): wrote and build-tested `gateway/Dockerfile`, and documented the
  exact `docker-compose.yml`/Caddyfile diff in DEPLOYMENT.md. Confirmed
  `help.iptvlookup.com` already resolves (existing Cloudflare-proxied
  `iptvlookup.com` zone), so no DNS change is needed. Nothing applied to
  the live `docker-compose.yml` or Caddyfile yet.

## 2026-09-25 -- MPEG-TS remux and second-pass hardening

- Added MPEG-TS sync-byte detection on the existing gateway entry route.
  MPEG-TS sources start a shared FFmpeg `-c copy` remux session that writes a
  bounded HLS window. Segments remain behind the existing encrypted `/r/`
  route and per-request token validation. At most two sessions run, and idle
  sessions expire after 90 seconds; gateway shutdown stops FFmpeg processes.
- Bound encrypted resource blobs to their access point ID as AES-GCM
  associated data, checked nonce generation errors, and resolved relative
  HLS references against the actual URL after a same-origin redirect.
  Added a real redirecting-source test and a cross-origin redirect rejection
  test. Removed source URLs from new gateway error logs.
- Added an integration test using FFmpeg-generated MPEG-TS served by a real
  local HTTP server; it checks remuxed HLS, segment bytes, and revocation.
  `go test ./...`, `tests/e2e_gateway.sh`, `tests/e2e_admin_flow.sh`, and
  `tests/crypto_interop.sh` all pass. Production Tvheadend has not been
  exercised and no production service or Caddyfile was changed.

## 2026-09-25 (later same day) -- Security review fixes

An independent review (Codex, using the `vibe-security` checklist) of the
vertical slice below found four real issues before it was considered
production-ready. All four are fixed here, each with a new regression
test that would have caught it:

- **Reversible `/r/` resource links.** They were plain base64 of the
  absolute source URL -- anyone holding a link could decode it themselves,
  defeating the "hide the source" goal. Replaced with AES-256-GCM
  authenticated encryption under a key generated fresh in the gateway
  process's memory on startup (`gateway/internal/blobcodec`, new). A
  tampered or hand-crafted blob now fails closed as 404. Tests:
  `blobcodec_test.go`, `handler_test.go`
  (`TestHandCraftedBlobIsRejected`, `TestCrossOriginBlobRejectedEvenWhenValidlyEncoded`).
- **Redirects bypassed the source-host allowlist.** The outbound HTTP
  client followed redirects without re-checking origin; a source that
  issued (or was tricked into issuing) a redirect could walk the gateway
  off its allowlisted host. Fixed with a per-request `CheckRedirect` that
  re-validates every hop (`gateway/internal/gatewayhttp/handler.go`
  `fetch()`). Logic-reviewed; no automated redirecting-source test yet
  (tracked as a gap in SECURITY.md, not silently assumed fixed).
- **Missing leading slash in rewritten links.** `hls.Proxify` (now
  `EncodeFunc`) emitted a bare relative path; a real player resolves that
  against the manifest's own directory, silently double-nesting the path
  for any manifest not served at the site root -- the original E2E test
  didn't catch this because it string-concatenated the segment path onto
  the gateway root instead of resolving it the way a player actually does.
  Fixed (leading `/` now always present) and the test fixed to use real
  URL resolution (`url.ResolveReference` / Python's `urljoin`). Tests:
  `TestRewritePlaylistProducesAbsolutePathReferences`,
  `tests/e2e_gateway.sh` step 6.
- **Admin IDOR on token actions.** `add_token` and `revoke_token` in
  `stream_view.php` didn't verify the target access point/token actually
  belonged to the stream whose page you were on -- a crafted form field
  could act on a different stream's token. Fixed with an ownership check
  before every write.
- Also fixed, smaller: unbounded playlist body read (now capped at 4 MiB,
  relevant given this host's tight RAM); admin session cookie now sets
  `Secure` when served over HTTPS (via `X-Forwarded-Proto`, since Caddy
  terminates TLS before php-fpm sees the request).
- Documented, not fixed here (out of StreamVault's scope): a live Discord
  bot token was found hardcoded in this repo's `docker-compose.yml`
  (`euroklic-bot` service), committed to git. Flagged to the repo owner
  directly -- needs rotation in the Discord Developer Portal.
- Also documented in ARCHITECTURE.md: absolute cross-host URIs in a
  manifest (e.g. a separate key server) are rewritten but then rejected at
  fetch time by the same-origin check -- the original text implied this
  was fully supported, which wasn't true even before today's fixes.

A second review pass (same reviewer, same session) on the just-fixed code
found two more issues before either was allowed to stand as "fixed":

- **Encrypted blobs weren't bound to a specific access point.** Layer 1 of
  the SSRF fix above (AEAD-authenticated blobs) proved a blob was minted
  by this gateway, but not *for which access point* -- a blob issued while
  serving one access point's manifest could be replayed against a
  different access point whose stream resolves to the same source host.
  Fixed by using the access point's ID as GCM associated data
  (`blobcodec.Encode`/`Decode` now take a bind parameter). Test:
  `TestBlobCannotBeReplayedUnderAnotherAccessPoint`.
- **Relative URIs after a redirect resolved against the wrong base URL.**
  Once redirects were being followed (constrained to the same host), a
  manifest fetched via a redirect needed its relative references resolved
  against the *actual* final URL, not the originally requested one.
  `gatewayhttp` now passes `resp.Request.URL` (Go's `http.Response`
  exposes the final request after following redirects) into
  `hls.RewritePlaylist` instead of the pre-fetch target.

Both fixes were implemented directly by the reviewing agent (Codex) in
this same working tree; verified by re-running the full test suite
(`go test ./...`, all three `tests/e2e_*.sh`) afterward -- all green.

## 2026-09-25 -- Initial vertical slice

- Researched actual host environment (Debian 13.6, Caddy v2.11.4, PHP-FPM
  8.2, 4 vCPU / 7.8 GiB RAM with tight headroom, no Go/FFmpeg present) and
  the existing production Caddyfile before designing anything.
- Found and documented an existing unauthenticated exposure:
  `restream.mxnticek.eu` / `tvh.cyn.cz` reverse-proxy straight to the real
  Restreamer/Tvheadend backend with no access control (see SECURITY.md).
  Not fixed yet -- requires a production Caddyfile change, gated on
  approval per DEPLOYMENT.md.
- Installed Go 1.24.4 and FFmpeg 7.1.5 via apt (previously absent).
- Designed and implemented the SQLite schema (`migrations/0001_init.sql`)
  covering streams, access points, per-recipient tokens, incidents/leak
  findings (schema-ready, unused), audit log, settings.
- Implemented the Go stream gateway: routing, HLS manifest rewriting
  (master/media playlists, keys, init segments, alt renditions, absolute
  and relative URIs), per-request token re-validation (including for
  segment fetches, not just the manifest), SSRF host-allowlisting on the
  proxy path, streamed (non-buffered) segment delivery, AES-256-GCM source
  credential decryption.
- Implemented the PHP admin UI: login/session/CSRF, stream CRUD (with
  automatic extraction of `user:pass@host` credentials into encrypted
  storage), access point management, token issue (shown once) / revoke,
  audit logging, settings page, honest "not implemented yet" messaging for
  unbuilt sections instead of fake data.
- Added and ran real tests, not just unit tests: `tests/e2e_gateway.sh`
  (gateway against a real ffmpeg-generated HLS source, including a
  wrong-token check, an SSRF-forgery check, and a revocation check),
  `tests/e2e_admin_flow.sh` (drives the actual PHP admin over HTTP to
  create a stream/access points/token, then confirms the Go gateway
  serves and revokes correctly from the same database), and
  `tests/crypto_interop.sh` (cross-checks the PHP and Go AES-GCM
  implementations actually produce/consume the same wire format).
- Left untouched, deliberately: production Caddyfile, any existing
  service, firewall/network config. Nothing in this entry required
  destructive or production-affecting action.
