#!/usr/bin/env bash
# Real HTTP/PHP/SQLite test for Phase 6 admin configuration. No GitHub API call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT=18326
COOKIES="$WORK/cookies.txt"
export STREAMVAULT_DB="$WORK/streamvault.sqlite"
export STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup() { kill "${ADMIN_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

printf '%s\n' 'supersecretpassword123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
sqlite3 "$STREAMVAULT_DB" "INSERT INTO streams (name, source_type, source_url) VALUES ('Leak Test', 'hls', 'https://source.test/index.m3u8');"
STREAM_ID="$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM streams WHERE name='Leak Test';")"
(cd "$ROOT" && exec php -S "127.0.0.1:$PORT" -t admin) >"$WORK/admin.log" 2>&1 &
ADMIN_PID=$!
sleep 1

csrf() {
  curl -fsS -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$PORT/$1" |
    grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'
}

LOGIN_CSRF="$(csrf login.php)"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$LOGIN_CSRF" --data-urlencode 'username=admin' \
  --data-urlencode 'password=supersecretpassword123' "http://127.0.0.1:$PORT/login.php"
CSRF="$(csrf settings.php)"

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=save_display' \
  --data-urlencode 'gateway_base_url=https://streams.example.test/' \
  "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='gateway_base_url';")" = 'https://streams.example.test'

# The token-setting endpoint must require the authenticated session and CSRF.
BAD_CODE="$(curl -sS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w '%{http_code}' \
  --data-urlencode 'csrf=bad' --data-urlencode 'action=save_github_token' \
  --data-urlencode 'github_token=should-not-save' "http://127.0.0.1:$PORT/settings.php")"
test "$BAD_CODE" = 400
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM settings WHERE key='github_token_enc';")" = 0

TOKEN='github_pat_test_only_secret'
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=save_github_token' \
  --data-urlencode "github_token=$TOKEN" "http://127.0.0.1:$PORT/settings.php"
STORED="$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='github_token_enc';")"
test -n "$STORED"
test "$STORED" != "$TOKEN"
DECRYPTED="$(php -r 'require $argv[1]; echo sv_decrypt(sv_load_key(getenv("STREAMVAULT_KEY_FILE")), $argv[2]);' "$ROOT/admin/includes/secret_box.php" "$STORED")"
test "$DECRYPTED" = "$TOKEN"
PAGE="$(curl -fsS -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$PORT/settings.php")"
if echo "$PAGE" | grep -q "$TOKEN"; then echo 'FAIL: token exposed in HTML'; exit 1; fi
echo "$PAGE" | grep -q 'Token: <strong>configured</strong>'

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=add_leak_source' \
  --data-urlencode 'provider=github_repo' --data-urlencode 'identifier=IPTV-Org/IPTV' \
  "http://127.0.0.1:$PORT/settings.php"
SOURCE_ID="$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM leak_sources WHERE provider='github_repo' AND identifier='iptv-org/iptv';")"
test -n "$SOURCE_ID"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=toggle_leak_source' \
  --data-urlencode "source_id=$SOURCE_ID" "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT enabled FROM leak_sources WHERE id=$SOURCE_ID;")" = 0

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=request_leak_scan' \
  "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM settings WHERE key='leak_scan_requested_at';")" = 1

CSRF="$(csrf "stream_view.php?id=$STREAM_ID")"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=add_access_point' \
  --data-urlencode 'public_path=secret/random-path' --data-urlencode 'visibility=public' \
  --data-urlencode 'path_is_secret=1' "http://127.0.0.1:$PORT/stream_view.php?id=$STREAM_ID"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT path_is_secret FROM access_points WHERE public_path='secret/random-path';")" = 1

sqlite3 "$STREAMVAULT_DB" "INSERT INTO leak_checker_runs (providers_run, streams_checked, queries_made, findings_created, error, finished_at) VALUES ('[\"github\"]', 1, 3, 0, 'rate limit reached', strftime('%Y-%m-%dT%H:%M:%fZ','now'));"
DASH="$(curl -fsS -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$PORT/index.php")"
echo "$DASH" | grep -q 'rate limit reached'
echo "$DASH" | grep -q 'Providers reported: github'

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=delete_leak_source' \
  --data-urlencode "source_id=$SOURCE_ID" "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM leak_sources WHERE id=$SOURCE_ID;")" = 0

echo 'ALL LEAK CHECKER ADMIN E2E CHECKS PASSED'
