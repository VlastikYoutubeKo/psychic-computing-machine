# Roadmap

Phases follow the spec's own numbering (section 31) with status against
what actually exists in this repo, not what's planned. "Tested" means an
automated test in `tests/` or `gateway/internal/*/*_test.go` actually
exercises it -- not just "the code compiles."

| Phase | Status | Notes |
|---|---|---|
| 1. Research & Architecture | **Done** | Real environment checked (not assumed) -- see ARCHITECTURE.md "Environment this was designed against". Caddy integration approach decided and documented with rejected alternatives. |
| 2. Core Backend | **Done (MVP)** | SQLite schema (`migrations/0001_init.sql`), stream CRUD, access points, per-recipient tokens, audit log. Tested: `gateway/internal/store/store_test.go`, `tests/e2e_admin_flow.sh`. |
| 3. Stream Gateway | **Done (MVP)** | Go gateway: routing, HLS manifest rewriting (master + media playlists, keys, init segments, absolute + relative URIs), segment-level token re-validation, SSRF host allowlist, streamed (non-buffered) segment proxying. Tested: `gateway/internal/hls/rewrite_test.go`, `tests/e2e_gateway.sh`. **Not done**: MPEG-TS-native output path (see Phase 4), backup/failover sources, bandwidth limiting. |
| 4. Tvheadend & Restreamer | **Partial** | Generic HTTP(S) source + Basic Auth works. The gateway now detects MPEG-TS from sync bytes on the entry response and starts a shared, bounded FFmpeg copy-only remux session that exposes HLS through the same token-validated route. A real FFmpeg/HTTP/SQLite integration test covers playlist, segment and revocation. **Not done**: Tvheadend channel-list API import, profile selection, transcoding, native MPEG-TS output. |
| 5. Administration UI | **Partial** | Stream CRUD, access points and tokens, manual incident triage, GitHub token/source settings, and scan coverage display. Audit log is written but not yet surfaced in the UI. **Not done**: stream search/filter/sort, in-admin playback test, themable replacement-page editor. |
| 6. Leak Checker | **In progress** | Additive migrations `0002_leak_checker.sql` and `0003_leak_checker_lock.sql`; PHP admin saves an encrypted GitHub token, manages watched GitHub repos/orgs, marks a public path as secret, queues scan requests, and displays run status. The Go one-shot checker searches globally and runs extra queries for enabled sources, with a SQLite lock and local API tests. `tests/e2e_leak_admin.sh` covers the admin flow without GitHub API calls. No timer or live GitHub scan has been deployed or verified; GitLab and public playlist scanning remain unimplemented. |
| 7. Incident Management | **Partial** | Admin can record an incident against an existing stream and move `new/probable -> confirmed/dismissed` or `confirmed -> resolved`. Every transition writes an action history and audit row; auth, CSRF, validation, and escaping are covered by `tests/e2e_incidents.sh`. No automated detection or token/source rotation is triggered. |
| 8. Replacement Streams | **Partial** | A static HTML "stream unavailable" page (with the configured reason) is served on revoked/disabled access, over HTTP 410. **Not done**: replacement HLS video generation, themable colors/logo, bilingual (CZ/EN) message templates -- currently English only. |
| 9. Discord Bot | **Not started** | `discord-bot/` directory scaffolded, empty. |
| 10. Advanced Features | **Not started** | M3U export, EPG, bandwidth stats/limits, backup sources. |
| 11. Security & Reliability | **Ongoing** | See SECURITY.md for the current threat-model table and explicit deferred-hardening list. |
| 12. Deployment & Documentation | **Partial** | This document set exists and is kept honest; native-install steps are written (DEPLOYMENT.md). Docker Compose variant now written and build-tested (`gateway/Dockerfile`, 151 MB image incl. ffmpeg, confirmed to build/start/run ffmpeg as UID 33) with the exact `docker-compose.yml`/Caddyfile diff documented for joining this host's existing stack -- **approved for `help.iptvlookup.com` (admin UI only) but not yet applied**; production Caddy cutover for actual stream traffic (`restream.mxnticek.eu`) remains separately gated on approval (see DEPLOYMENT.md). |

## Suggested next steps (not started, in rough priority order)

1. Exercise the MPEG-TS remux against a real Tvheadend channel and selected
   profile before calling Tvheadend integration complete; the automated test
   uses a real FFmpeg-generated TS source, not a live Tvheadend instance.
2. Link manual incidents to specific access tokens where identifiable, then
   add an explicit operator-approved response action. Current triage changes
   the incident status only; it never revokes or rotates access automatically.
3. Finish reviewing the GitHub one-shot checker, then deploy a timer that
   checks queued manual requests without running a full GitHub scan every
   minute. Keep detection read-only before connecting rotation actions.
4. ~~Docker Compose packaging~~ -- done for this host (see DEPLOYMENT.md);
   a fully standalone compose file for a from-scratch host is still open
   if this ever needs to run somewhere else.
5. Apply the approved `help.iptvlookup.com` admin-UI deployment
   (DEPLOYMENT.md) once the current review round is signed off.
6. A known robustness gap worth a closer look before relying on the remux
   path under real load: `remux.Manager` holds a single mutex across
   session lookup, start, and segment path resolution. Starting a new
   session blocks on network I/O (bounded to roughly the shared
   Transport's dial/TLS/response-header timeouts, ~10s worst case, not
   unbounded) while holding that lock, which briefly stalls segment
   serving for *other*, already-running remux sessions too. Not a
   correctness bug and bounded in time, but worth revisiting (e.g.
   per-stream locking, or starting the session outside the global lock)
   before this carries real concurrent viewers.
