# Changelog

## 2026-09-27 -- Admin v3 and editable slate text

- Reorganized the admin around Dashboard, Streams, Leaks, Error screen and
  system Settings. Existing actions and CSRF handling remain; login markup
  and password-manager flow are untouched.
- Added migration 0006 for per-reason slate text and operator AI generation
  quota. Browser error pages and player slates use the same edited text.
- Re-rendered both slate loops without title/subtitle. A shared committed
  DejaVu font is used in the renderer and the runtime; FFmpeg reads text from
  0600 files and enforces a six-process total cap. Text and audio edits
  refresh running slates on the 30-second maintenance tick.
- Added encrypted write-only OpenRouter key, editable model and a local-mock
  tested suggestion flow. Suggestions fill the form and require a separate
  Save. Quotas are ten attempts/minute and 100/day per operator.

## 2026-09-26 -- Slate in 1080p with larger text; Opus/FLAC audio

- Slate loops are now rendered at 1920x1080 (same 854x480 CSS layout at
  deviceScaleFactor 2.25) with larger title/subtitle/icon, and the live
  clock/cut-off overlays scaled to match. Measured in the production image
  per session: 480p 3.4%, 720p 5.0%, 1080p 8.5% of one core (~400 kbit/s per
  viewer), so the worst case of 5 concurrent sessions stays under half a core.
- Slate audio accepts .opus (Opus in Ogg) and .flac.
- Changing slate audio in the admin now restarts running slate sessions
  within ~30 s (reaper tick compares each session's configured audio with
  the current settings); before, only newly started sessions used it.

## 2026-09-26 -- Leak response is automatic: revoke + GitHub notice

The admin offered "Rotate automatically on confirmed leak" (and
"monitor only"), but nothing implemented either -- the stream form's own help
text admitted it -- and a public access point's link found on GitHub was only
ever a "mention" unless the operator had also flipped a separate "path is
secret" switch. Confirming or resolving an incident changed a status and
nothing else. In practice a real leak (the owner's own test issue) did nothing.

- Any public access point link found publicly is now a confirmed leak (the
  URL is the credential). Private access points still need the token itself
  to match for "confirmed". The "path is secret" switch is gone.
- Response is always automatic (the per-stream choice is removed; migration
  0005 sets existing streams to auto): the leak checker revokes exactly the
  leaked token or access point, marks the incident confirmed and logs it.
- On a GitHub issue/PR in an allowlisted repo (Settings -> Automatic GitHub
  replies), it posts one public comment with the "Stream unavailable" image
  (`/_sv/notice.png`, served by the gateway on the stream domain, so the
  admin host never appears). Other repos: "Reply on GitHub" button on the
  incident, with the comment shown in the confirm dialog. One reply per
  issue/PR ever (`leak_replies`, unique source_url).
- Confirm on an incident now revokes the leaked link; flash messages say what
  actually happened.
- Existing findings upgrade in place when they classify stronger; re-seeing
  an already-recorded finding no longer opens a new, finding-less incident
  after the previous one was dismissed or resolved.
- Needs a classic GitHub token with `public_repo` to comment (fine-grained
  tokens can only write to their own account's repos).

## 2026-09-26 -- Shared HLS unavailable slate and admin presentation

- Added a lazy, shared FFmpeg slate with silent AAC, a rolling HLS window,
  idle cleanup and a strict global `/_sv/slate/` route. Player-style revoked
  entry requests receive an HLS master playlist; HTML requests keep 410,
  and invalid private tokens remain 404. Added routing and FFmpeg tests.
- Reserved `_sv` as a first public-path segment in the admin validator.
  Redesigned the server-rendered admin shell, responsive layouts, forms,
  tables, badges and login card without changing form names or auth logic.
- Documented the 200-status monitoring tradeoff.
- Review fixes before deploy (verified by building the real Alpine image
  and running the slate manager in it as UID 33):
  - The Alpine font path was wrong (`/usr/share/fonts/dejavu/`, not
    `ttf-dejavu/`), so every slate would have failed with "slate font
    unavailable" in production.
  - The lavfi inputs had no `-re`: ffmpeg generated video as fast as the CPU
    allowed (360 segments, ~12 min of "live" video, in 8 s of wall time),
    pinning a core and running the playlist far ahead of real time. Now
    real-time at ~0% CPU.
  - Upstream failures on a player entry request now get the shared
    "temporarily unavailable" slate (browsers still get 502); before, that
    variant existed and was publicly startable but never used.
  - Failed or short-lived encoders back off 10 s before restarting, so a
    broken ffmpeg can't be respawned on every public request.
  - Slate frame redesigned to match the admin palette: accent bar, bold
    title, muted subtitle, STREAMVAULT footer.

## 2026-09-26 -- Leak Checker timer installed (every 5 minutes)

The Leak Checker had only ever run when started by hand, so "Scan now"
requests from the admin UI sat queued forever (e.g. one queued at
11:39Z never ran). Installed `deploy/systemd/streamvault-leakchecker.{service,timer}`
into /etc/systemd/system and enabled the timer. The cadence was changed from
1 to 5 minutes at the owner's request: a check every 5 minutes, a real
GitHub scan only on a pending "Scan now" or every `minScanInterval`
(20 min), so detection is automatic and a manual request lands within ~5 min.

## 2026-09-25 (yet even later) -- Fixed a double-fetch that triggered the source's own rate limiting

After the SSRF redirect fix below, `rest.iptvlookup.com/metvtoons.m3u8`
still 502'd, now with `upstream returned status 429` from the remux path.
Manually reproducing the exact fetch (same Transport config, standalone)
against the real source succeeded every time, which ruled out the
redirect/TLS/header logic -- the difference had to be in *how many*
requests the gateway actually made.

It was two. `serveEntry` fetches the entry point once to sniff whether
it's HLS or MPEG-TS; when it turned out to be MPEG-TS, the *sniffed*
response was discarded and `serveRemuxEntry` opened a **second**,
independent fetch to feed FFmpeg. For an ordinary source that's just one
extra request. For this one -- and many similar low-quality/free IPTV
aggregators -- the entry point 302s to a single-use, token-bearing CDN77
URL per request, and two requests to the *entry point* in quick
succession get the second one 429'd by the origin itself. Confirmed by
watching `docker exec ... wget` succeed cleanly seconds apart while the
gateway's own two-fetch sequence kept failing.

Fixed by not re-fetching: the sniffed response's body (already-read sniff
bytes prepended via a new `prefixedReadCloser`, then the rest of the
original body) is now handed directly to the remux session instead of
being discarded. This required decoupling the entry fetch from the
triggering request's context and its 20s timeout (`gateway/internal/gatewayhttp/handler.go`
`serveEntry`'s doc comment has the full reasoning and the accepted
trade-off: a source that responds but drips bytes arbitrarily slowly can
now hang the request with no deadline -- accepted because the source is
admin-configured, not attacker-supplied, same trust boundary as
elsewhere in this project). New regression test in
`TestMPEGTSIsRemuxedToHLSAndTokenRevocationStillApplies` asserts exactly
one request reaches the source for the entry fetch.

After this fix and a rebuild/redeploy, `rest.iptvlookup.com/metvtoons.m3u8`
served a real HLS manifest (200) and a real ~770 KB video segment (200)
end to end against the live source -- StreamVault's first stream actually
serving real video through the gateway in production.

## 2026-09-25 (even later) -- Fixed SSRF redirect policy against a real stream

The project owner set up a real production stream (`rest.iptvlookup.com`,
routed through a new Caddy site block to `streamvault-gateway`) and hit
`525`/`502` errors: first because the Caddy site block didn't exist yet
(added, then a `caddy reload` didn't pick it up -- confirmed the known
project quirk that Caddyfile changes need the container recreated, not
just reloaded), then because the gateway's own SSRF redirect check
rejected the stream's source. The source
(`http://cynessa.ottb.xyz/live/.../13566.ts`) 302-redirects its entry
point to a fresh, single-use CDN77 edge URL *on a different host* on
every request -- an entirely ordinary CDN pattern, and exactly what the
gateway's same-host-only redirect policy was written to reject.

That policy was too strict for real-world sources by design, not by
accident of a missed edge case: rewrote it in
`gateway/internal/gatewayhttp/ssrf.go` (new file) around the actual risk
(a source redirecting the gateway into *this host's own private
network* -- cloud metadata, other containers, localhost) rather than "any
different host at all". A redirect/resource-fetch target is now allowed
if it resolves to a public address, regardless of host, matching what a
browser would do; a private/reserved target is allowed only when the
stream's own configured source is itself private (a LAN Tvheadend box,
or another container on this project's own Docker network -- both real,
intended use cases, not exceptions). `Handler.Resolve` makes the
IP-classification step injectable so tests don't depend on real DNS or
on httptest's own loopback binding (every httptest server uses
`127.0.0.1`, which real resolution correctly calls private -- without
injection, every test's "source" would look like a trusted LAN box and
silently disable the checks meant to exercise the opposite case). Cached
per-stream for 5 minutes so this doesn't cost a DNS lookup on every
segment request. New tests in `ssrf_test.go` and additions to
`handler_test.go` cover: private target rejected under a public source,
private target allowed under a private source, and a different-but-public
redirect host now succeeding (the actual regression for this bug).

After the fix and a rebuild/redeploy of `streamvault-gateway`, the
redirect chain resolved correctly against the real source (confirmed via
`docker exec ... wget` following the exact same 302 chain manually); the
stream then hit the *source's own* rate limit (429) from the repeated
testing during this session, which is a real, external, and unrelated
constraint, not a StreamVault bug.

## 2026-09-25 (later) -- First real end-to-end verification against live GitHub

The project owner configured a real GitHub PAT (dedicated account) and
asked for an actual test: a real stream/access point/token was created in
the live `help.iptvlookup.com` admin, a fictional leaked URL for it was
posted in a real GitHub issue
(github.com/VlastikYoutubeKo/psychic-computing-machine/issues/1), and the
checker was run against the live GitHub API for the first time.

**It found a real bug no mocked test had caught**: GitHub's
`/search/issues` endpoint now rejects any query with neither `is:issue`
nor `is:pr` (HTTP 422 `"Query must include 'is:issue' or
'is:pull-request'"`) -- it used to default to searching both. Every
`httptest`-mocked test in this repo happily returned whatever the mock
was told to return, so nothing caught that the real endpoint's validation
rules had changed underneath the client. Fixed: `Client.SearchIssues` now
takes a required `kind` ("issue" or "pr") and always sets the matching
`is:` qualifier; `Scanner` calls it twice per query (spec section 12 asks
for both issues and PRs covered), tripling per-access-point query count
from 2 to 3. New tests: `TestSearchIssuesRejectsInvalidKind`,
`TestSearchIssuesPRKindSetsQualifier`.

After the fix, the full pipeline worked correctly end to end against the
real issue: a `Confirmed`-confidence finding was recorded with the raw
token properly redacted (verified afterward by grepping the live SQLite
file's raw bytes for the token string -- zero matches), linked to the
correct stream/access point/token, and opened an incident at `probable`
(not auto-confirmed, as designed). `gateway_base_url` was also updated to
`https://rest.iptvlookup.com` per the owner's stated plan for where actual
stream traffic will live (distinct from `help.iptvlookup.com`, which
stays admin-only). The test stream, access point, token, incident, and
finding were deleted afterward; the GitHub issue was left open (the
configured PAT lacks permission to close/comment on issues) for the owner
to close manually. `leak_checker_runs` history includes both the failing
(pre-fix) and succeeding (post-fix) live runs, kept rather than scrubbed.

## 2026-09-25 -- Prepared GitHub checker timer

- Added a Dockerfile build step for the one-shot
  `streamvault-leakchecker` binary in the existing gateway image and
  added systemd service/timer files under
  `deploy/systemd/`. The timer invokes a temporary Compose container
  about a minute after each completion; the checker itself scans only for queued requests or when
  its 20-minute interval is due.
- Documented installation and verification without touching the live
  Compose/Caddy configuration or enabling a production service. A live
  GitHub scan still awaits the dedicated PAT.

## 2026-09-25 -- Phase 6 PHP configuration and coverage UI

- Added GitHub PAT entry in Settings, encrypted with the existing shared
  `secret_box` key and never rendered back into HTML. Added add, enable,
  disable and delete actions for watched GitHub repositories and
  organizations in the new `leak_sources` table.
- Added a `path_is_secret` control for public access points, so the checker
  can treat disclosure of a random public path as a confirmed leak.
- Dashboard, Incidents and Settings now show real `leak_checker_runs` data,
  including last successful run, error or partial coverage, query counts,
  and queued manual requests. The Settings “Scan now” action only writes a
  request timestamp; a separate once-per-minute timer and one-shot checker
  must process it. No web shell or Docker socket access was added.
- Added `tests/e2e_leak_admin.sh`, exercising token encryption and secrecy,
  source management, scan request, secret-path flag and status display over
  real HTTP/PHP/SQLite without contacting GitHub. No production timer or
  real GitHub scan was deployed in this step.

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
## 2026-09-26 -- Slate v2 (review branch)

- Added deterministic HTML/CSS/JS artwork and committed looping MP4s for
  unavailable and temporary variants.
- Added live Prague clock, timestamped personal slates with a three-session
  cap and opaque HMAC routes, and additive transition timestamps.
- Added admin audio upload/radio URL/volume controls with magic-byte and
  gateway-side URL checks. Failed radio sessions restart muted and defer
  radio retries for five minutes.
- No production container, Caddyfile or Compose changes.
