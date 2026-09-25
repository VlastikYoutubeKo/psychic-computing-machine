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
**No change has been made to this file.** Cutting `restream.mxnticek.eu`
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
| SSRF via a forged `/r/` blob | Enforced, three layers: (1) the blob must decrypt/authenticate under the gateway's own in-memory key -- a hand-crafted or tampered blob fails closed as 404, verified in `tests/e2e_gateway.sh` step 8 and `blobcodec_test.go`; (2) the blob is bound to the specific access point it was issued for (access point ID as AEAD associated data), so a valid blob from one access point can't be replayed against another sharing the same source host, verified in `TestBlobCannotBeReplayedUnderAnotherAccessPoint`; (3) even a validly-encrypted, correctly-bound blob must still match the stream's configured source host, verified in `handler_test.go` (`TestCrossOriginBlobRejectedEvenWhenValidlyEncoded`). |
| Redirects from the source can't be used to leave the allowlisted host | Enforced -- `CheckRedirect` re-validates every hop's scheme+host. `TestRedirectToDifferentOriginIsNeverFetched` verifies this with two real local HTTP servers; `TestSameOriginRedirectResolvesSegmentsFromFinalPlaylistURL` verifies relative URI resolution after an allowed redirect. DNS rebinding of an admin-configured hostname remains a separate gap below. |
| MPEG-TS remux access | Generated HLS segments use the same encrypted resource route, access-point binding and token validation as ordinary HLS segments. `TestMPEGTSIsRemuxedToHLSAndTokenRevocationStillApplies` uses FFmpeg-generated TS and verifies that a revoked token receives 410 for a previously issued segment link. |
| Source credentials at rest | AES-256-GCM, key held outside the DB. Verified interoperable between the PHP writer and Go reader in `tests/crypto_interop.sh`. Not yet implemented: key rotation, or protecting the key file itself beyond filesystem permissions (see "Deferred hardening" below). |
| Access tokens at rest | SHA-256 hash only; raw value never persisted, shown once at creation. |
| CSRF on all admin state changes | Enforced (`sv_csrf_check()` on every POST handler). |
| Admin can't act on another stream's access point/token via a crafted form field (IDOR) | Enforced -- `add_token` and `revoke_token` in `stream_view.php` verify the target row's `stream_id` matches the currently open stream before writing. Caught by review; not yet covered by an automated test (single-operator system today, so lower severity, but still a real authorization gap prior to the fix -- see CHANGELOG.md). |
| Admin session cookie | `HttpOnly` + `SameSite=Lax` always; `Secure` set when the request arrived over HTTPS (checked via `$_SERVER['HTTPS']` or `X-Forwarded-Proto`, since Caddy terminates TLS before php-fpm sees the request). Caught by review -- an earlier version never set `Secure` at all. |
| SQL injection | All admin queries use PDO prepared statements; the gateway uses parameterized `database/sql` queries. No string-concatenated SQL exists in either. |
| XSS in admin UI | All dynamic output passed through `h()` (`htmlspecialchars`). |
| Caddy Admin API exposure | Not newly relevant -- already bound to `127.0.0.1:2019` on the host per an existing 2026-09-23 fix noted in `docker-compose.yml`; reachable internally at `http://caddy:2019` by containers on `caddy-net` only. StreamVault does not currently call the Admin API at all (see ARCHITECTURE.md -- the gateway needs no Caddy config changes per stream). |
| Rate limiting on login | Minimal: a fixed 300ms delay per attempt (`sv_login()`), attempts audited. **No lockout or IP-based throttling yet** -- see "Deferred hardening". |
| Leak detection, auto-rotation, Discord permissions | Not implemented. The incident UI states that manual triage is available but automated detection and response are not. |
| Manual incident triage | Authenticated operators can record incidents and apply only the allowed status transitions. Every POST requires CSRF validation; stream IDs are checked server-side; evidence and notes are escaped on output. These status changes do not revoke tokens or rotate credentials. Verified by `tests/e2e_incidents.sh`. |
| Discord bot token hardcoded in `docker-compose.yml` | **Not a StreamVault issue, but live and unresolved as of this writing** -- see "Independent review before production cutover" above. Rotate and move to `.env`. |

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
