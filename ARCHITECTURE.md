# Architecture

## Environment this was designed against

Verified directly on the target host on 2026-09-25 (not assumed):

- Debian 13.6 (trixie), kernel 6.12
- Caddy v2.11.4, running in Docker (`caddy:latest` image), Caddyfile at
  `caddy/conf/Caddyfile` in the parent repo
- Caddy Admin API: listens on `0.0.0.0:2019` *inside* the container, but the
  host only publishes it on `127.0.0.1:2019` (docker-compose.yml). Any
  container on the `caddy-net` bridge network can still reach it at
  `http://caddy:2019` -- that's the intended internal control channel.
- PHP-FPM 8.2 (custom image, `Dockerfile.php`), extended timeouts
  (`request_terminate_timeout=3600`), shared by several small apps
- Docker 26.1.5 / Compose 2.26.1
- 4 vCPU, 7.8 GiB RAM. **At research time, 138 MiB was free and 2.2 GiB of
  swap was in use** -- this host is memory-constrained under normal
  operation, before StreamVault adds anything. This drove several choices
  below (Go over Node for the gateway, streaming instead of buffering,
  no per-request process spawn).
- Go and FFmpeg were **not installed** prior to this project; both were
  added via `apt-get install golang-go ffmpeg` (Go 1.24.4, FFmpeg 7.1.5).
- `restream.mxnticek.eu` and `tvh.cyn.cz` already exist in the production
  Caddyfile as **unauthenticated `reverse_proxy` blocks straight to the
  real Restreamer/Tvheadend backend** (`38.242.156.120:18080` /
  `:9981`). This is exactly the exposure this project exists to fix -- see
  SECURITY.md "Existing exposure found during research".

## Why a separate Go gateway, not PHP, not a generated Caddyfile

Section 9 of the spec asked for a comparison of: generating Caddyfile
per-stream, driving the Caddy Admin API, static Caddy + dynamic auth
backend, a separate gateway, or a mix.

**Chosen: a separate always-on gateway process, with exactly one static
Caddy route pointing at it.** Reasoning:

- **Generating Caddyfile per stream** means a reload (or Admin API push) on
  every add/edit/rotate. The spec explicitly asks to avoid that, and a
  config error on a shared Caddyfile risks the *other* ~15 sites it serves
  (euroklic, bazar, radios, ...). Rejected.
- **Driving the Admin API directly, one route per stream**: same
  blast-radius problem, plus the Admin API operates on the *whole* running
  config -- a bug in our code could corrupt unrelated site blocks. Rejected
  as the primary mechanism (still useful later for the *initial* one-time
  route registration, see DEPLOYMENT.md).
- **`forward_auth` to a PHP authorizer + static reverse_proxy to source**:
  this was seriously considered, since the repo already leans on PHP
  everywhere. Rejected because (a) `forward_auth` alone can't rewrite HLS
  manifest bodies -- something still has to do that -- and (b) this exact
  repo has already been burned once by PHP-FPM-as-video-proxy: the
  `sktv.mxnticek.eu` incident (see `docker-compose.yml` comment,
  2026-09-03) where video segment requests held PHP-FPM workers long
  enough to starve the *shared* pool and take down unrelated sites,
  requiring a dedicated `php-fpm-sktv` container as a fix. A stream
  gateway sitting in the request path of every video segment, for
  potentially several streams and viewers, is the same shape of risk.
  Given the host's RAM is already under pressure, a compiled Go binary
  (~10-20 MB RSS, no per-request worker pool to exhaust) was chosen
  instead of adding *another* isolated PHP-FPM pool.
- **A single static Caddy route to the gateway**: Caddy's job becomes just
  TLS termination + one `reverse_proxy stream-gateway:8090` (or a
  host-mapped port during development). All per-stream logic --
  resolving `public_path`, validating tokens, rewriting manifests,
  proxying segments -- lives in the gateway, reading SQLite on every
  request. Adding, editing, disabling or rotating a stream is a database
  write; Caddy never needs to know.

The admin UI stays PHP (matches the rest of this repo, low request volume,
no long-held connections) and talks to the *same* SQLite file. The gateway
never receives writes from the admin directly; both just look at the DB.

## Routing convention

- Public access: `GET /<public_path>.m3u8` or `GET /<public_path>` -- no
  token. `public_path` is looked up as a literal string (can contain
  slashes, e.g. `tv/nova`).
- Private access: `GET /<public_path>/<token>.m3u8`. The last path segment
  is always the token; everything before it must match a stored
  `public_path` whose `visibility = 'private'`.
- Any other resource a manifest references (variant playlist, segment,
  key, init segment, alt audio/subtitle) is rewritten to an **opaque,
  encrypted** `/<prefix>/r/<blob><ext>` path (leading slash always
  present, see below), where `<prefix>` is exactly the public_path[/token]
  that was already validated for this request, and `<blob>` is
  `blobcodec.Encode(absolute source URL)` -- AES-256-GCM under a key that
  exists only in the gateway process's memory (`gateway/internal/blobcodec`),
  not a reversible encoding. See `gateway/internal/hls/rewrite.go` for the
  rewriting itself.
- **The leading `/` is load-bearing, not cosmetic.** An early version
  emitted a bare relative path here (`live/nova/r/...`, no leading slash);
  a real player resolves a relative reference against the *manifest's own
  directory*, so a manifest served at `/live/nova/token.m3u8` would
  resolve that into `/live/nova/live/nova/token/r/...` -- silently broken
  for any manifest not served at the site root. Caught in security review,
  not by the original test suite (see "How this was actually verified"
  below). `hls.EncodeFunc`'s doc comment now states the absolute-path
  requirement explicitly, and `TestRewritePlaylistProducesAbsolutePathReferences`
  guards it.
- A public_path segment may never equal `r` (reserved; enforced both in
  the PHP admin's `sv_validate_public_path()` and implicitly by the
  gateway's routing, which would otherwise misparse it). This is the
  "collision / reserved endpoint" protection required by spec section 5.

This means: relative or absolute URIs in the source manifest are resolved
uniformly, and the client never sees or can derive the real source URL --
only ever an encrypted pointer scoped to a request that has already proven
it holds a valid token for that specific stream. **Absolute URIs pointing
at a different host than the stream's configured source (e.g. a separate
key server) are currently rewritten but then rejected at fetch time** by
the same-origin check below -- multi-host manifests are not yet actually
supported end to end, only single-origin ones. If a real stream needs a
second trusted host, that needs an explicit per-stream allowlist, not yet
built (see ROADMAP.md).

## SSRF boundary

Four independent layers, not one:

1. **The blob is authenticated, not just encoded.** `blobcodec` uses
   AES-256-GCM: decoding a blob that wasn't produced by this same gateway
   process (tampered, hand-crafted, or encoded under a different key)
   fails closed. A client cannot construct a valid blob pointing anywhere
   they choose -- unlike an earlier version, which just base64-encoded the
   URL and was fully reversible by anyone holding the link (a security
   review caught this before it reached production; see CHANGELOG.md).
2. **The blob is bound to the specific access point it was issued for**,
   via the access point's ID as GCM associated data (`Codec.Encode(url,
   accessPointID)` / `Decode(blob, accessPointID)`). Without this, a blob
   minted while serving one access point's manifest could be replayed
   against a *different* access point whose stream happens to resolve to
   the same source host -- passing the authentication check (it's a real
   blob from this gateway) but for the wrong context. Caught in a second
   review pass, after the first fix; verified in
   `TestBlobCannotBeReplayedUnderAnotherAccessPoint`.
3. **`checkFetchTarget` (`gateway/internal/gatewayhttp/ssrf.go`) as defense
   in depth against the real risk, not against "a different host".** Even
   a successfully decoded target is checked before the gateway will fetch
   it -- and so is every redirect hop the entry fetch follows (same
   function, same policy). The *first* version of this required the
   target to be the exact same host as the stream's `source_url`. That
   shipped, passed its own tests, and then broke on this project's first
   real production stream: many legitimate sources (this one included)
   302 their entry point to a *different* host per request -- a fresh CDN
   edge node with a signed, single-use URL -- which a same-host rule
   can't tell apart from an actual redirect-based attack. The real risk is
   narrower than "a different host": a source (compromised, malicious, or
   just misconfigured) redirecting the gateway into *this host's own
   private network* -- cloud metadata, other containers, localhost. So
   the rule is now: any *public* target is allowed regardless of host,
   exactly as a browser would follow the same redirect; a *private/reserved*
   target is allowed only when the stream's own configured source is
   itself private (a LAN Tvheadend/Restreamer box per spec section 7, or
   another container on this project's own Docker network -- both real,
   intended cases, not exceptions). `Handler.Resolve` makes the
   IP-classification step injectable, cached 5 minutes per stream so it
   doesn't cost a DNS lookup on every segment request. See
   `ssrf_test.go` and CHANGELOG.md for the fix and how it was verified
   (including against the real stream that exposed the bug).
4. **Every redirect hop is checked, not just the initial request.** The
   outbound HTTP client's `CheckRedirect` runs `checkFetchTarget` on every
   hop -- the default `http.Client` follows redirects with no re-check at
   all, so a source that issues (or is tricked into issuing) a redirect
   could otherwise walk the gateway anywhere. A related, non-security
   correctness bug fixed alongside the first version of this: relative
   URIs in a manifest fetched via a redirect must resolve against the
   *final* post-redirect URL, not the originally requested one -- the
   handler uses `resp.Request.URL` (Go's `http.Response` exposes the
   actual last request after following redirects) as the base for
   `hls.RewritePlaylist`, not the pre-fetch target.

## How this was actually verified

Beyond the automated test suite (`gateway/internal/*/*_test.go`,
`tests/e2e_*.sh`), an independent second-pass security review was run
against this exact code before considering it done, using the
methodology from the `vibe-security` skill checklist. That review
is what actually found the reversible-blob issue, the missing-leading-slash
bug, and the redirect gap above -- all three shipped in the *first* version
of this gateway and passed its own test suite, because the tests were
written by the same author with the same blind spots (e.g. the original
E2E test manually concatenated the gateway root with the extracted segment
path instead of resolving it the way a real player would, which is exactly
why it didn't catch the missing leading slash). Take this as a concrete
argument for getting an independent review on the actual security-critical
path before trusting your own tests, not just as a historical note.

## Segment-level revocation

Revoking a token (or an access point) is a single DB write
(`access_tokens.revoked_at`). The *next* request for that token --
manifest or segment -- is checked against the DB again and rejected, even
if the client already has a manifest full of `/r/...` links from before
the revocation (those links re-validate the same token on every fetch).
What's *not* possible, and the spec acknowledges this (section 10): a
segment a client has already fully downloaded before revocation can't be
un-downloaded. Verified in `tests/e2e_gateway.sh` step 9.

## MPEG-TS entry sources

The existing public entry route probes the source body. If it is HLS, the
manifest is rewritten as before. If it has MPEG-TS packet sync bytes, the
gateway starts a shared FFmpeg session for that stream and remuxes with
`-c copy` into a rotating HLS window. No video or audio transcoding is done.
The resulting manifest is rewritten with the same encrypted `/r/` links;
each segment request still resolves the access point and validates its token.

At most two remux sessions run on this memory-constrained host. Sessions
expire after 90 seconds without a manifest or segment request and are also
stopped on gateway shutdown. FFmpeg output lives in a private temporary
directory and old segments are deleted as the live window advances. A
completed finite source's files remain available until idle expiry.
Starting a session may take up to 15 seconds to produce the first segment;
a source that never yields one returns 502. FFmpeg must be installed on the
gateway host. MPEG-TS codecs are copied unchanged, so player codec support
still depends on the original channel. This path has been tested with a real
FFmpeg-generated TS feed, and, since, against a real production stream
(see CHANGELOG.md "Fixed a double-fetch...").

**The sniffing fetch is reused for the remux session, never re-fetched.**
Detecting MPEG-TS requires reading the first bytes of the entry response
*before* knowing whether it'll be handed to FFmpeg or rewritten as HLS
text. An earlier version discarded that sniffed response and opened a
second, independent fetch once MPEG-TS was confirmed -- an extra request
that a real source (a free/low-quality IPTV aggregator whose entry point
302s to a single-use, token-bearing CDN URL per request) rate-limited
outright, since two hits to the entry point in quick succession isn't a
pattern its own anti-abuse logic tolerates. `serveEntry` now fetches
without a deadline or the triggering request's context (accepting, in
exchange, that a source which responds but then drips bytes arbitrarily
slowly can hang the request -- judged acceptable since the source is
admin-configured, not attacker-supplied), and `sniffAndServe` hands the
already-open body (sniffed bytes prepended via `prefixedReadCloser`)
directly to the remux session instead of signaling "start a new fetch".

## Secrets

Source credentials (Tvheadend/Restreamer basic auth) are stored as
AES-256-GCM ciphertext (`streams.source_password_enc`), under a 32-byte
key kept in a separate file (`STREAMVAULT_KEY_FILE`), **not** in the
database. Losing the DB file alone (a backup, a copy, a leak) does not
expose source passwords. The PHP admin (`admin/includes/secret_box.php`)
and the Go gateway (`gateway/internal/secretbox`) implement the identical
wire format independently; `tests/crypto_interop.sh` cross-checks both
directions actually interoperate, since a silent mismatch here would only
surface in production as "Tvheadend auth mysteriously fails".

Access tokens themselves are never stored raw -- only
`sha256(token)`. The raw value is shown exactly once, at creation, in the
admin UI response (not via a redirect/URL parameter, so it can't end up in
browser history or a referer header).

This is a *different* key from the `blobcodec` one used to encrypt
`/r/<blob>` resource links (see "SSRF boundary" above): the secretbox key
is durable, shared between PHP and Go, and protects data at rest across
restarts; the blobcodec key is generated fresh in the gateway's memory on
every process start and never leaves it. A restart invalidates already
issued resource links; clients must refresh their manifest, and some players
may briefly stall until they do.

## Leak Checker

`gateway/internal/leakcheck` (Go) + `admin/settings.php` (PHP) implement
Phase 6 for GitHub only (GitLab and public-playlist scanning are not
implemented -- see ROADMAP.md).

**The matching algorithm exists because of a constraint the rest of this
project already committed to**: `access_tokens` stores only
`sha256(token)`, never the raw value (see "Secrets" above). The leak
checker therefore cannot search external sources for "our secret URL"
directly -- there is no secret on file to search for. Instead:

1. It searches GitHub: one code search, plus *two* issue searches (issues
   and pull requests are separate queries -- GitHub's `/search/issues`
   rejects a query with neither `is:issue` nor `is:pr` outright, a
   validation rule change only discovered by running against the real
   API; see the "first real end-to-end verification" entry in
   CHANGELOG.md) for an exact-phrase anchor:
   `base_url + "/" + access_point.public_path`. This is safe to
   send in a search query because `public_path` is not itself a secret
   for an ordinary stream (only the token that follows it is) -- except
   for the "long random path IS the secret" pattern from spec section 1,
   which `access_points.path_is_secret` flags explicitly (see below).
2. If a result contains the anchor followed by a 48-hex-character string
   (matching `sv_generate_raw_token`'s length), that candidate is hashed
   and compared against the access point's stored token hashes --
   *never* the other way around. A match against an active token is
   `Confirmed`; against a revoked/expired one, still `Confirmed` as
   evidence but not urgent (it already doesn't work); no match at all is
   `Probable` (the pattern looks right but we don't recognize it -- could
   be stale, garbled, or unrelated).
3. A bare anchor with no trailing token, on a normal public access point,
   is just a `Mention` -- expected, not actionable. On a
   `path_is_secret` public access point, any appearance of the exact path
   is `Confirmed` outright, since there the path itself is what must stay
   unguessable.
4. **The raw candidate token is never persisted.** `leak_findings.matched_value`
   stores the anchor plus a 12-character hash prefix
   (`.../live/nova/<redacted token, hash 3f9a1c...>`), not the token
   itself -- storing a working bearer credential in the findings table
   would silently reintroduce exactly what hashing `access_tokens` was
   meant to prevent. Caught in review before this ever ran a real scan.
5. **The same discipline applies to error paths, not just successful
   matches -- and took two review passes to get right.** The first fix
   only removed the search query from `log.Printf`'s direct arguments in
   `scanner.go`. That missed two places the query (which can be a
   `path_is_secret` anchor) was still reachable through an error's own
   `Error()` text, which scanner.go logs via a bare `%v`: a non-2xx
   GitHub response's error included the raw request path (`?q=...`), and
   a transport-level failure surfaces as a `*url.Error`, whose `Error()`
   method concatenates the *full request URL* regardless of what
   generated it. `gateway/internal/leakcheck/github.go`'s `do()` now
   builds every returned error from only an endpoint name
   (`endpointOnly`, everything before `?`) and a status code or coarse
   failure kind -- never the query, the full URL, or the response body
   (GitHub's search API validation errors can echo back part of an
   invalid query, so "the body is just a fixed error shape" wasn't a safe
   assumption to build a secrecy guarantee on either).
   `TestErrorsNeverContainTheQuery` exercises both the HTTP-error and
   network-failure paths directly against a planted secret string.

**Automated findings never auto-confirm an incident.** A `Confirmed`
match opens (or attaches to) an incident at status `probable`; a
`Probable` match opens one at `new`. Either way, moving it to `confirmed`
or `dismissed` stays a deliberate human action through the existing
Phase 7 UI (`admin/incidents.php`) -- the checker's own confidence in the
evidence is not the same thing as the operator having acted on it.
Findings are grouped into one incident per `(stream, token)` pair (or per
`(stream, access_point)` when no specific token was identified), per spec
section 13's "don't let one leak spam duplicate incidents", and
`leak_findings.dedupe_key` (a hash of source + source URL + matched
value) means re-scanning unchanged content creates zero new rows, not
just zero new incidents.

**Why a one-shot binary on a timer, not a long-running daemon**:
consistent with the rest of this project's stance on this
memory-constrained host (see "Why a separate Go gateway" above), a
process that only exists while it's actually doing work beats one sitting
idle in memory between scans. `cmd/leakchecker` is designed to be invoked
every minute by a timer (not deployed yet), but only
performs a real scan when either a manual "Scan now" request is pending
(`settings.leak_scan_requested_at`, written by `admin/settings.php`) or
`minScanInterval` (20 minutes by default) has elapsed since the last run;
otherwise it's a fast no-op DB check. This is what makes "Scan now" feel
responsive without a full GitHub search sweep running every single
minute and exhausting the search rate limit in a few minutes flat.

Two concurrency issues in this design were caught by review, not written
correctly the first time:

- **A pending request landing mid-scan must not be lost.** A scan can
  take several minutes; if a second "Scan now" click writes a new
  `leak_scan_requested_at` while one is already running, the finishing
  run must not blindly clear that newer value. `Store.ClearScanRequestIfUnchanged`
  captures the exact value seen at start and only deletes it if it's
  still the same value afterward (compare-and-delete).
- **Two scans must not run at once.** With a 1-minute timer and up to a
  10-minute scan, a manual request arriving mid-scan would otherwise
  start a second, overlapping run. `leak_checker_lock`
  (`migrations/0003_leak_checker_lock.sql` -- a separate migration from
  0002 because 0002 was already applied to this host's live database and
  to various tests by the time this was found, so editing its contents
  wouldn't have reached anything that already recorded it as done) is a
  single-row table acquired with a plain `INSERT` (fails on the second
  attempt via the primary key) and released with a `DELETE`. A lock older
  than 15 minutes is assumed to belong to a crashed process and is
  stolen rather than blocking forever.

**Explicitly watched sources** (`leak_sources`, managed from Settings):
global GitHub code/issue search already covers all of public GitHub, so
these exist for spec section 12's "Umožni přidat konkrétní repozitáře,
organizace" -- e.g. giving `iptv-org/iptv` (which the spec calls out by
name) a dedicated, always-run `repo:iptv-org/iptv`-scoped query in
addition to the global one, so a specific priority source isn't at the
mercy of global search's ranking or pagination limits. Each enabled
source gets its own query per access point; disabled ones are skipped;
`last_scanned_at` is updated after use.

Each GitHub search currently reads only the first page (30 results).
The run status does not measure matches beyond that page, so a clean run
does not imply exhaustive GitHub coverage.

**Verification status**: the matching/scanning/locking pipeline is covered
by tests against an `httptest` mock GitHub server (31 test functions in
`gateway/internal/leakcheck`, including three dedicated to proving a
secret path never reaches an error or a log line, and two proving the
`is:issue`/`is:pr` requirement is enforced) and the PHP admin side has its
own HTTP end-to-end test (`tests/e2e_leak_admin.sh`). Those never call
`api.github.com`, and mocks only enforce what they're told to -- which is
exactly how the `is:issue`/`is:pr` requirement above went unnoticed until
a real run against the live API surfaced it as an outright 422.

**A real, live end-to-end run has since been observed and worked
correctly** (see CHANGELOG.md's "First real end-to-end verification"
entry): a genuine GitHub issue containing a fictional leaked URL for a
real (test) stream/token was created, scanned with a real GitHub PAT, and
correctly produced a `Confirmed` finding with the token properly redacted
and an incident opened at `probable`, all verified directly against the
live database and admin UI, not just a test assertion. What that single
run does *not* establish: GitLab (not implemented), the systemd timer
running unattended over time, behavior against a large result set instead
of a hand-crafted one, or rate-limit exhaustion under real load.

## What was deliberately deferred

See ROADMAP.md for the full phase list. Notably: no Caddy config has been
touched (production `restream.mxnticek.eu`/`tvh.cyn.cz` cutover requires
explicit approval per the project's own autonomy rules -- see
DEPLOYMENT.md), and nothing here talks to GitHub/GitLab/Discord yet.
