# Security

## Independent review before production cutover (2026-09-25)

Before treating the gateway/admin vertical slice as done, an independent
review (Codex, via the project's multi-agent setup, using the
`vibe-security` checklist) was run against the actual code -- not just the
author's own test suite. It found four real issues, all now fixed and
covered by new tests (see CHANGELOG.md for the full list; summary: the
`/r/` resource links were reversible base64 instead of encrypted, HTTP
redirects from the source weren't re-checked against the host allowlist, a
missing leading slash in rewritten links would have broken playback on any
manifest not served at the site root, and the admin UI's token
issue/revoke actions didn't verify the token belonged to the currently
open stream). The "SSRF via a forged /r/ blob" and "source URL hidden"
rows below describe the *current*, fixed state.

It also surfaced one finding entirely unrelated to StreamVault: a live
Discord bot token committed in plaintext in this repo's
`docker-compose.yml` (tracked in git history, not just the working tree).
That's a live-credential exposure for the *existing* `euroklic-bot`
service, not something StreamVault introduced or can fix by itself --
flagged to the repo owner directly; rotate the token in the Discord
Developer Portal and move it to an untracked `.env` file.

## Existing exposure found during research (2026-09-25)

While researching Caddy integration options (see ARCHITECTURE.md), the
production Caddyfile (`caddy/conf/Caddyfile`) was read to understand the
current setup. Two site blocks are directly relevant and, as configured
today, expose the underlying streaming backends with no access control
beyond a single-IP blocklist (`blocked_ips` snippet):

```
restream.mxnticek.eu {
	import blocked_ips
	reverse_proxy 38.242.156.120:18080
}
...
tvh.cyn.cz {
	import blocked_ips
	reverse_proxy 38.242.156.120:9981
	...
}
```

Anyone who can reach these hostnames can currently hit the real Restreamer
/ Tvheadend backend directly -- this is precisely the problem StreamVault
is meant to solve (hide the source, require a token, allow revocation).
The admin-only `help.iptvlookup.com` block was added later; these two
stream-facing blocks remain unchanged. Cutting `restream.mxnticek.eu`
(or a new subdomain) over to point at the StreamVault gateway instead is a
production Caddy change and requires explicit approval before it happens
-- see DEPLOYMENT.md "Production cutover (not yet applied)". Flagging it
here now because it's a real, currently-live exposure, independent of
whether/when the cutover happens.

## Threat model / what's actually enforced today

| Concern | Status |
|---|---|
| Source URL hidden from clients | Enforced. Every manifest reference is rewritten to an AES-256-GCM-encrypted `/r/<blob>` path under a key that lives only in the gateway process's memory (`gateway/internal/blobcodec`) -- not reversible by whoever holds the link. Verified in `gateway/internal/gatewayhttp/handler_test.go` (`TestPublicEntryHidesSourceAndRewritesAbsolute`) and `tests/e2e_gateway.sh`. An earlier version used plain reversible base64 here; caught by review, see CHANGELOG.md. |
| Revoked token stops working immediately, including for segments | Enforced (re-validated on every request, not just the top-level manifest). Verified in `tests/e2e_gateway.sh` step 9 and `handler_test.go` (`TestPrivateAccessTokenLifecycleOverHTTP`). Cannot retroactively un-download data a client already fetched before revocation -- inherent to HTTP, called out in spec section 10 too. |
| One recipient's leaked token doesn't affect others on the same stream | Enforced -- tokens are independent rows scoped to one access point. Verified in `gateway/internal/store/store_test.go` (`TestTwoTokensOnSameAccessPointAreIndependent`). |
| SSRF via a forged `/r/` blob | Enforced, three layers: (1) the blob must decrypt/authenticate under the gateway's own in-memory key -- a hand-crafted or tampered blob fails closed as 404, verified in `tests/e2e_gateway.sh` step 8 and `blobcodec_test.go`; (2) the blob is bound to the specific access point it was issued for (access point ID as AEAD associated data), so a valid blob from one access point can't be replayed against another, verified in `TestBlobCannotBeReplayedUnderAnotherAccessPoint`; (3) even a validly-encrypted, correctly-bound blob's target must resolve to a public address, unless the stream's own source is itself private (`checkFetchTarget`), verified in `TestCrossOriginBlobToPrivateAddressRejectedEvenWhenValidlyEncoded` / `TestCrossOriginBlobToPublicHostIsAllowed`. Layer 3 was originally a same-host allowlist; it broke this project's first real production stream (a source that legitimately 302s to a different CDN host per request) and was rewritten around actual private-address risk instead -- see ARCHITECTURE.md "SSRF boundary" and CHANGELOG.md. |
| Redirects from the source can't be used to reach this host's private network | Enforced -- `CheckRedirect` runs `checkFetchTarget` on every hop, not just the first request. `TestRedirectToPrivateAddressIsNeverFetched` / `TestRedirectAllowedWhenSourceItselfIsPrivate` / `TestRedirectToDifferentPublicHostIsFetched` cover: a private redirect target is rejected when the source is public, allowed when the source is itself private (a LAN Tvheadend box or another container on this project's own Docker network), and a different-but-public redirect host is followed. `TestSameOriginRedirectResolvesSegmentsFromFinalPlaylistURL` verifies relative URI resolution after an allowed redirect. DNS rebinding (a hostname resolving differently between this check and the actual connection) remains a separate, accepted gap below. |
| MPEG-TS remux access | Generated HLS segments use the same encrypted resource route, access-point binding and token validation as ordinary HLS segments. `TestMPEGTSIsRemuxedToHLSAndTokenRevocationStillApplies` uses FFmpeg-generated TS and verifies that a revoked token receives 410 for a previously issued segment link. |
| Shared unavailable slate | Entry requests without `Accept: text/html` for revoked/disabled access receive a 200 HLS master pointing at the public `/_sv/slate/unavailable/` stream (or `temporarily-unavailable/` when the source fails; browsers then keep 502). Invalid private tokens remain 404, including when the stream is disabled. The global route validates variant and filename strictly; no source URL, bearer token or stream-specific reason is written into slate media. HTTP-status-only player monitoring can no longer distinguish revoked from live. HTML requests and protected resource URLs retain 410. |
| Source credentials at rest | AES-256-GCM, key held outside the DB. Verified interoperable between the PHP writer and Go reader in `tests/crypto_interop.sh`. Not yet implemented: key rotation, or protecting the key file itself beyond filesystem permissions (see "Deferred hardening" below). |
| Access tokens at rest | SHA-256 hash only; raw value never persisted, shown once at creation. |
| CSRF on all admin state changes | Enforced (`sv_csrf_check()` on every POST handler). |
| Admin can't act on another stream's access point/token via a crafted form field (IDOR) | Enforced -- `add_token` and `revoke_token` in `stream_view.php` verify the target row's `stream_id` matches the currently open stream before writing. Caught by review; not yet covered by an automated test (single-operator system today, so lower severity, but still a real authorization gap prior to the fix -- see CHANGELOG.md). |
| Admin session cookie | `HttpOnly` + `SameSite=Lax` always; `Secure` set when the request arrived over HTTPS (checked via `$_SERVER['HTTPS']` or `X-Forwarded-Proto`, since Caddy terminates TLS before php-fpm sees the request). Caught by review -- an earlier version never set `Secure` at all. |
| SQL injection | All admin queries use PDO prepared statements; the gateway uses parameterized `database/sql` queries. No string-concatenated SQL exists in either. |
| XSS in admin UI | All dynamic output passed through `h()` (`htmlspecialchars`). |
| Caddy Admin API exposure | Not newly relevant -- already bound to `127.0.0.1:2019` on the host per an existing 2026-09-23 fix noted in `docker-compose.yml`; reachable internally at `http://caddy:2019` by containers on `caddy-net` only. StreamVault does not currently call the Admin API at all (see ARCHITECTURE.md -- the gateway needs no Caddy config changes per stream). |
| Rate limiting on login | Minimal: a fixed 300ms delay per attempt (`sv_login()`), attempts audited. **No lockout or IP-based throttling yet** -- see "Deferred hardening". |
| Leak detection, auto-rotation, Discord permissions | GitHub checker code exists and has local API tests; production scheduling and live API verification are pending. GitLab/public playlist scanning, automatic response and Discord permissions are not implemented. |
| Manual incident triage | Authenticated operators can record incidents and apply only the allowed status transitions. Every POST requires CSRF validation; stream IDs are checked server-side; evidence and notes are escaped on output. These status changes do not revoke tokens or rotate credentials. Verified by `tests/e2e_incidents.sh`. |
| GitHub API token in admin settings | Stored as `settings.github_token_enc` via the same AES-256-GCM `secret_box` envelope as source passwords. The raw token is never rendered back to the browser or written to the audit event; a CSRF-protected operator form can replace or remove it. Verified by `tests/e2e_leak_admin.sh`. The Go checker must load the same key file to decrypt it. |
| Scan request from admin | `Scan now` writes a timestamp to SQLite. The web process does not execute a shell command or access the Docker socket. A separate timer/one-shot checker is required; pending state and run errors are displayed from the DB so a queued request is not shown as a completed scan. |
| Discord bot token hardcoded in `docker-compose.yml` | **Not a StreamVault issue, but live and unresolved as of this writing** -- see "Independent review before production cutover" above. Rotate and move to `.env`. |

## Slate v2 boundary

Slate v2 personal routes use a process-local HMAC key; the URL does not
expose IDs or timestamps but acts as a bearer URL while valid. Music uploads
use extension and magic-byte validation, a 25 MiB cap, randomized names,
and 0640 files outside the web root. Radio URLs must be HTTP(S), resolve to
public addresses at session start, and use zero redirects plus FFmpeg's
protocol whitelist. FFmpeg resolves the hostname again when opening it,
leaving DNS rebinding as a residual risk for operator-entered URLs. Public
broadcast music requires appropriate rights.

## Admin v3: editable error text and AI suggestions

Migration 0006 stores public slate text, plus an operator-scoped generation
quota log. The OpenRouter API key is AES-256-GCM encrypted with the existing
key file, write-only in the admin and absent from audit records. The server
calls OpenRouter over HTTPS with a 20-second timeout and a 16 KiB response
limit. API failures shown to operators contain status codes only; response
bodies, credentials and cURL diagnostics are never logged or displayed.
Generation is charged before sending to enforce ten/minute and 100/day even
for concurrent clicks. Suggestions are validated and never auto-saved.

Text is written to 0600 files, rather than interpolated into FFmpeg filter
arguments. The gateway strips control characters and enforces length limits
again when reading the database. Every reason-specific route is an allowlisted
reason and opaque personal HMAC keys remain bound to the reason. At the hard
cap of six FFmpeg sessions, viewers share an existing generic slate; this may
show a different reason until capacity becomes free. Player requests still
return HTTP 200 for revoked URLs, while invalid tokens stay 404.

## Deferred hardening (known gaps, not yet addressed)

- **Login rate limiting / lockout**: production deployment should add a
  Caddy-level `rate_limit` (or equivalent) on `/login.php` in addition to
  the in-app delay. Not yet configured anywhere.
- **Key file protection**: `STREAMVAULT_KEY_FILE` should be `chmod 600`,
  owned by whichever user runs both the gateway and php-fpm for this app.
  The bootstrap script sets 0600 on creation; this hasn't been verified
  under the actual production deployment user/group yet (that's a
  DEPLOYMENT.md task, not done).
- **Host-only SSRF allowlist**: the `/r/` check is host-exact, not
  IP-range-aware. If a stream's configured source hostname itself later
  resolves to something unexpected (DNS rebinding against the *source*,
  not the client-forged path), that's not separately defended. Low
  priority since the source host is admin-configured, not attacker
  -controlled, but noted for completeness (spec section 26 raises DNS
  rebinding explicitly).
- **No network-level isolation of the actual Restreamer/Tvheadend
  backends** (spec section 10, "Ochrana zdrojových URL") -- that requires
  firewall changes on `38.242.156.120` or wherever those backends run,
  which is out of scope for this repo and requires the server owner's
  explicit action (also an "ask before doing" item per the project's own
  autonomy rules: firewall/network changes).
- **Discord bot permission model, GitHub/GitLab comment automation**: not
  implemented, so not yet a security surface -- noted here so it isn't
  forgotten when Phase 9/16 start (per-guild/per-role allowlists,
  backend-side permission re-checks, ephemeral responses, confirmation
  dialogs bound to the invoking user and a short TTL, as specified).

## Reporting

This is a personal single-operator project; there's no external disclosure
process yet. If you're a future maintainer (human or AI) reading this:
check ROADMAP.md before assuming any of the "not yet implemented" items
above have since shipped -- update this file the moment they do.

## Automatic leak response (2026-09-26)

- A confirmed leak revokes only the specific leaked token or access point,
  never the stream or other recipients' tokens. Anyone who can post the
  link publicly can therefore get that link revoked -- intended: a public
  link is compromised the moment it is posted.
- Public comments go out automatically only for repos on the operator's
  allowlist; elsewhere an operator must click. At most one comment per
  issue/PR. The comment names no stream, path or token -- only that the
  link was revoked -- and embeds an image from the stream domain.
- GitHub API errors are reported by status code only; response bodies are
  never logged or shown.

## Security review 2026-09-27 (vibe-security checklist)

No critical findings. Secrets were never committed (data/ ignored, keys
encrypted at rest); CSRF on every POST; every page requires login; SQL is
parameterized; output is escaped; uploads are content-checked and stored
outside the web root; AI quota and output validation are server-side.

Fixed:
- **High -- login brute force.** Only a 300 ms delay protected the public
  admin. Now at most 5 failures per client IP and 30 per username per 15
  minutes (`login_attempts`, HTTP 429 + Retry-After). The client IP is taken
  from CF-Connecting-IP only when the TCP peer is inside Cloudflare's
  published ranges: the origin is reachable directly, where the header is
  attacker-controlled. Update `SV_CLOUDFLARE_RANGES` if Cloudflare changes
  them (https://www.cloudflare.com/ips/).
- **Medium -- error disclosure.** php-fpm has display_errors on (shared pool);
  opening admin/includes/*.php directly printed stack traces with paths.
  admin/.user.ini now turns display_errors off (logs instead) for every
  script under admin/.
- **Medium -- clickjacking.** Admin pages send X-Frame-Options: DENY and
  CSP frame-ancestors 'none' (+ base-uri/form-action 'self', nosniff,
  Referrer-Policy) and drop X-Powered-By.
- **Low -- session fixation hardening:** session.use_strict_mode=1.
- **Low -- logout CSRF:** logout is POST + CSRF only.

Accepted / open:
- Anonymous requests to /_sv/slate/<variant>/<reason>/index.m3u8 can start
  generic slate processes. Bounded by the 4-process cap (~36% of a core,
  ~530 MiB); beyond it requests share a running slate.
- Caddy still serves admin/includes/, admin/cli/ (403 only for cli) and
  dotfiles such as admin/.user.ini (harmless content). Recommended Caddy
  hardening for help.iptvlookup.com: respond 404 for /includes/*, /cli/* and
  /.* -- pending owner approval (shared production Caddy).
- Radio URL DNS rebinding (admin-entered only; documented above).

## Multi-user accounts (2026-09-27)

- Authorization is server-side on every request: the session operator is
  re-read with status='active' each time (disabling = immediate logout), and
  every stream/access point/token/incident/leak-source id is checked against
  the operator's ownership (admins bypass). tests/e2e_accounts.sh covers all
  pages and actions with another user's ids.
- Invites: 64-hex token, SHA-256 at rest, 72 h expiry, single use via an
  atomic UPDATE, Referrer-Policy no-referrer, token moved out of the URL,
  guessing counted in login_attempts.
- Quotas are DB triggers, so concurrent requests cannot exceed them.
- Remux permission is enforced in the gateway, not only the admin UI.
- Users' own GitHub tokens are encrypted like the global one and only used
  to scan that user's access points; they never post public replies.
- Admin-only: accounts, error screen (texts/AI/audio -- the OpenRouter key
  is money-limited), global settings, GitHub replies.

## Relay nodes (2026-09-27)

- A node token (svn_<id>_<256-bit secret>) is shown once. The control plane
  stores SHA-256(secret) for authentication (constant-time compare; one
  generic 401 for every failure) and the secret encrypted with the main key,
  which it needs to sign viewer URLs and to encrypt credentials for that node.
- A node receives source credentials ONLY for streams assigned to it,
  encrypted under a key derived from its own secret. A compromised node leaks
  those credentials: assign carefully, and use "New token" / Disable / Delete
  to cut it off (the old token stops working immediately).
- Viewers never talk to nodes: the control gateway checks the viewer's
  token, then fetches from the node with a control grant (HMAC-SHA256 over
  stream, access point 0, token 0 and a 1 h expiry, embedded only inside the
  encrypted /r/ references) and proxies it. Revoking a token therefore takes
  effect on the control gateway immediately. The node still enforces the
  signature and its revocation lists for any direct access, and a disabled
  or stale node is not used. Firewall the node port to the control server.
- The node serves only its own relay files (strict segment names); it is not
  a proxy. /healthz is the only unauthenticated path.
- The node binary download requires the node token; install.sh is public and
  contains no secrets.
- Known limits: control<->node traffic is plain HTTP unless the node address
  is HTTPS or a private/VPN link; it carries stream data and signed grants,
  not viewer tokens. The node address is trusted by the control gateway (no
  public-IP SSRF rule applies to it), so only admins can set it.
  Pre-existing: source Basic-auth credentials are sent with every segment
  fetch, including to other hosts a source redirects/points to.
