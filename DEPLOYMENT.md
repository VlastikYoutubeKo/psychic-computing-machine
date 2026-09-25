# Deployment

## Status: not yet deployed to production

Everything below the "Native Debian install" section has been **written
and reasoned through, but not applied to this server**, and several steps
are explicitly gated on your approval per the project's own autonomy
rules (production Caddyfile changes, anything that could disrupt an
existing service). Treat this file as a plan to execute together, not a
record of what's already live.

## Native Debian install (this host)

Already verified present on this host during Phase 1 research
(2026-09-25): Debian 13.6, Go 1.24.4, FFmpeg 7.1.5, SQLite CLI 3.46,
PHP 8.4 (CLI) / 8.2-fpm (in the existing `php-fpm` container). Go and
FFmpeg were installed via `apt-get install golang-go ffmpeg` as part of
this work (not present before).

1. **Build the gateway binary:**
   ```bash
   cd streamvault/gateway
   go build -o /usr/local/bin/streamvault-gateway ./cmd/gateway
   ```
2. **Create the data directory and key:**
   ```bash
   mkdir -p /etc/streamvault
   chown www-data:www-data /etc/streamvault   # match whichever user runs php-fpm for this app
   chmod 750 /etc/streamvault
   ```
   The key file is created automatically on first admin write that needs
   it (`sv_ensure_key_file()`), or generate one explicitly:
   ```bash
   php -r 'require "streamvault/admin/includes/secret_box.php"; echo sv_generate_key(), "\n";' > /etc/streamvault/secret.key
   chmod 600 /etc/streamvault/secret.key
   ```
3. **Bootstrap the database + first operator:**
   ```bash
   export STREAMVAULT_DB=/etc/streamvault/streamvault.sqlite
   export STREAMVAULT_KEY_FILE=/etc/streamvault/secret.key
   php streamvault/admin/cli/create_operator.php admin
   ```
4. **systemd unit for the gateway** (not yet installed -- example, needs a
   real path once you decide where the binary/repo lives permanently):
   ```ini
   # /etc/systemd/system/streamvault-gateway.service
   [Unit]
   Description=StreamVault stream gateway
   After=network.target

   [Service]
   ExecStart=/usr/local/bin/streamvault-gateway
   Environment=STREAMVAULT_DB=/etc/streamvault/streamvault.sqlite
   Environment=STREAMVAULT_KEY_FILE=/etc/streamvault/secret.key
   Environment=STREAMVAULT_LISTEN=127.0.0.1:8090
   Restart=on-failure
   RestartSec=2
   User=www-data
   # Given this host's tight memory headroom (138 MiB free / 2.2 GiB swap
   # in use at research time), consider a hard cap so a bug here can't
   # starve the other ~15 sites this box serves:
   MemoryMax=256M

   [Install]
   WantedBy=multi-user.target
   ```
5. **Admin UI**: serve `streamvault/admin/` through the existing shared
   `php-fpm` container the same way `karty.cyn.cz` or `epg.mxnticek.eu` do
   (mount the directory, add a `php_fastcgi php-fpm:9000` block) --
   **not** through `php-fpm-sktv`, since the admin UI does no long-held
   video proxying and doesn't need an isolated pool the way sktv's video
   endpoints did.

## Docker Compose variant -- joining the existing stack (validated, not yet applied)

Decided: since StreamVault runs on this exact host, plugging into the
*existing* `docker-compose.yml` / `caddy-net` (option (a) from the earlier
draft of this section) beats a separate standalone compose file -- it's
how every other app here works, and it's what lets the gateway reach
`php-fpm` and be reached by `caddy` by service name with no published
ports of its own. A fully standalone `streamvault/docker-compose.yml` for
a from-scratch host is still a reasonable ask for later (ROADMAP.md), just
not what this section is about.

**`streamvault/gateway/Dockerfile`** (written and build-tested on this
host): multi-stage, `golang:1.25-alpine` builder (matches `go.mod`'s `go
1.25.0` directive -- the host's own `golang-go` apt package is 1.24, which
is fine for local `go build`/`go test`, but the container build needs a
toolchain that satisfies go.mod) -> `alpine:3.20` runtime. `CGO_ENABLED=0`
because `modernc.org/sqlite` is pure Go, so the final image needs no libc
SQLite bindings. As of Phase 4 (MPEG-TS remux, `gateway/internal/remux`)
the runtime image also installs `apk add ffmpeg` -- the gateway shells out
to it, so without this the image builds and starts fine and only fails,
confusingly, the first time a stream turns out to be MPEG-TS. That pulls
in ffmpeg's dependency chain (codec/audio libs), so the image is
**151 MB**, not the ~23 MB it was pre-Phase-4 -- still confirmed to build,
start, and run `ffmpeg -version` correctly as UID 33 in this session.
Runs as **UID 33** (numeric, no `/etc/passwd` entry needed)
-- deliberately the same UID as `www-data` in the project's existing
`php-fpm` image (`Dockerfile.php`, based on Debian's official
`php:8.2-fpm`), because both processes read/write the *same* SQLite file
on a shared bind mount, and a UID mismatch there is exactly how a
previous incident happened (project memory: euroklic's `.sqlite`
directory wasn't `www-data`-writable, and a `.backup` call stripped
`-wal`/`-shm` and 500'd the site until `chmod`'d). One
`chown -R 33:33 streamvault/data` on the host satisfies both containers
instead of juggling ACLs.

**`docker-compose.yml` changes needed** (not yet applied -- this is the
exact diff to review before it lands):

```yaml
  caddy:
    volumes:
      # ...existing mounts...
      - ./streamvault:/srv/streamvault   # admin UI + migrations, read by both caddy (file_server) and php-fpm

  php-fpm:
    volumes:
      # ...existing mounts...
      - ./streamvault:/srv/streamvault
    environment:
      # ...existing PHP_FPM_REQUEST_TERMINATE_TIMEOUT...
      - STREAMVAULT_DB=/srv/streamvault/data/streamvault.sqlite
      - STREAMVAULT_KEY_FILE=/srv/streamvault/data/secret.key

  streamvault-gateway:
    build:
      context: ./streamvault/gateway
    container_name: streamvault-gateway
    restart: unless-stopped
    volumes:
      - ./streamvault/data:/data
    environment:
      - STREAMVAULT_DB=/data/streamvault.sqlite
      - STREAMVAULT_KEY_FILE=/data/secret.key
      - STREAMVAULT_LISTEN=0.0.0.0:8090
    networks:
      - caddy-net
```

Mounting the *whole* `./streamvault` directory (not just `admin/`) into
`caddy`/`php-fpm` matches this repo's existing convention (e.g.
`./euroklic:/srv/euroklic` mounts bot.py and docs alongside the web root
too) and, more importantly, keeps `admin/`, `migrations/`, and `data/` as
siblings on disk the way `admin/includes/config.php` assumes
(`SV_ROOT = dirname(admin dir)`). The gateway container only gets
`./streamvault/data`, since its binary is already built into the image.

**Caddyfile addition** (not yet applied): see "Production cutover" below
for `help.iptvlookup.com` specifically -- it's an *additive* new site
block, not a change to any existing one, so it doesn't carry the same
risk as the `restream.mxnticek.eu` cutover, but recreating the `caddy` and
`php-fpm` containers to pick up the new volumes/env still briefly affects
every other site they serve (confirmed as an acceptable brief blip, not
silently assumed).

**What this does *not* do yet**: no stream-facing hostname is wired to
`streamvault-gateway`. Per the split agreed with the project owner,
`help.iptvlookup.com` is the admin UI *only* -- actual stream URLs will
live on separate domains added later, each needing just one more
`reverse_proxy streamvault-gateway:8090` block, no further gateway
changes.

## Admin UI on help.iptvlookup.com (approved by the project owner in chat, 2026-09-25 -- applied once Codex's review of the current changes is done)

Unlike the `restream.mxnticek.eu` cutover below, this one has explicit
sign-off already: `help.iptvlookup.com` hosts the StreamVault **admin UI
only**; actual stream URLs will get their own, separate domain(s) added
later, each just needing a `reverse_proxy streamvault-gateway:8090` block.
DNS is already in place -- `help.iptvlookup.com` resolves today through
the same Cloudflare-proxied zone as the rest of `iptvlookup.com` (checked
via `getent hosts`, matches `de03.iptvlookup.com`'s resolution), so no
registrar/Cloudflare change is needed, only the origin-side Caddy block.

Caddyfile addition:

```caddyfile
# ==========================================
# StreamVault Admin
# ==========================================
help.iptvlookup.com {
	import blocked_ips
	root * /srv/streamvault/admin
	encode gzip
	php_fastcgi php-fpm:9000
	file_server
}
```

This mirrors the existing `karty.cyn.cz` block exactly (same shared
`php-fpm`, same `root`+`php_fastcgi`+`file_server` shape) -- nothing novel
in the Caddy config itself, just a new hostname.

Steps to actually go live, in order:

1. `mkdir -p streamvault/data && chown -R 33:33 streamvault/data` on the
   host (see "Docker Compose variant" above for why UID 33).
2. Apply the `docker-compose.yml` diff above (new `streamvault-gateway`
   service, volume + env additions to `caddy` and `php-fpm`).
3. Append the Caddyfile block above.
4. `docker compose up -d --build` -- this recreates `caddy` and `php-fpm`
   (briefly affecting every other site they serve, on the order of
   seconds) and builds+starts the new `streamvault-gateway` container.
   Confirm timing with the project owner right before this specific step
   even though the feature itself is pre-approved, since it's the one
   moment other live sites are touched at all.
5. Bootstrap the first operator account:
   ```bash
   docker compose exec php-fpm php /srv/streamvault/admin/cli/create_operator.php admin
   ```
6. Verify: `https://help.iptvlookup.com/login.php` loads, log in, create a
   test stream, confirm the dashboard renders. Do **not** consider this
   step done just because the container started -- check the actual page.

## Production cutover (not yet applied -- requires your approval)

To actually protect `restream.mxnticek.eu` for real (see SECURITY.md
"Existing exposure found during research"), the production Caddyfile
needs a new block routing to the gateway instead of straight to the
source. Sketch of the change (**not applied**):

```caddyfile
# Replaces the current unauthenticated reverse_proxy block.
restream.mxnticek.eu {
	import blocked_ips
	reverse_proxy 127.0.0.1:8090   # or gateway:8090 if containerized on caddy-net
}
```

Before this happens, per the project's autonomy rules, the following need
your explicit sign-off (each is either a production Caddyfile edit or
touches an existing live stream):

1. Confirming which existing stream(s) currently served raw via
   `restream.mxnticek.eu` should be modeled as StreamVault streams first,
   and under what public_path(s) -- this determines whether any
   currently-shared raw URL breaks on cutover (it will, by design: the
   old raw memfs URL stops being reachable once Caddy stops proxying to
   it directly).
2. The actual Caddyfile edit + `docker compose restart caddy` (per the
   existing project memory: a Caddy reload alone doesn't always pick up
   Caddyfile changes -- the container needs recreating).
3. Whether/how to also restrict direct network access to the real
   Restreamer/Tvheadend backend (`38.242.156.120`) so the gateway is the
   *only* path in -- this is a firewall change on infrastructure outside
   this repo and explicitly listed as an ask-first item in the project
   spec.

Until that happens, StreamVault can be fully built, tested, and used on
a *new*, not-yet-linked hostname/path without touching the existing
`restream.mxnticek.eu` traffic at all.

## Backup / restore

Not yet built. The whole of StreamVault's state is one SQLite file plus
one key file; a correct backup is "copy both, consistently" (SQLite WAL
mode means a naive `cp` of just the `.sqlite` file while it's live can
miss unflushed data in `-wal` -- use `sqlite3 streamvault.sqlite ".backup
backup.sqlite"` instead, and see the project memory about `.backup`
requiring the directory to actually be writable by whichever user runs
it). A documented restore drill is a ROADMAP Phase 12 item.
