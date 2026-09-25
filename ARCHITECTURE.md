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
3. **A per-stream host allowlist as defense in depth.** Even a
   successfully decoded target must match the stream's own configured
   `source_url` scheme+host (`gatewayhttp.sameOrigin`) before the gateway
   will fetch it. This layer is what's actually exercised by
   `tests/e2e_gateway.sh`'s forged-blob-style check, and remains useful in
   case of a future bug in the encode/decode path.
4. **Redirects are constrained too.** The outbound HTTP client's
   `CheckRedirect` re-validates *every* hop against the same origin, not
   just the initial request -- the default `http.Client` follows redirects
   without re-checking, so a source that issues (or is tricked into
   issuing) a redirect could otherwise walk the gateway off its
   allowlisted host entirely. Also caught in security review. A related,
   non-security correctness bug fixed alongside it: relative URIs in a
   manifest fetched via a redirect must resolve against the *final*
   post-redirect URL, not the originally requested one -- the handler now
   uses `resp.Request.URL` (Go's `http.Response` exposes the actual last
   request after following redirects) as the base for `hls.RewritePlaylist`,
   not the pre-fetch target.

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
FFmpeg-generated TS feed, not yet against the production Tvheadend server.

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

## What was deliberately deferred

See ROADMAP.md for the full phase list. Notably: no Caddy config has been
touched (production `restream.mxnticek.eu`/`tvh.cyn.cz` cutover requires
explicit approval per the project's own autonomy rules -- see
DEPLOYMENT.md), and nothing here talks to GitHub/GitLab/Discord yet.
