#!/usr/bin/env bash
# Drives the actual PHP admin UI over HTTP (login -> create stream -> add a
# public access point -> add a private access point + token), then starts
# the Go gateway against the SAME database the admin just wrote to and
# fetches the resulting URLs -- proving the two halves of the app actually
# interoperate, not just each in isolation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
ADMIN_PORT=8091
GATEWAY_PORT=18323
SOURCE_PORT=18324
FAIL=0
COOKIES="$WORK/cookies.txt"

export STREAMVAULT_DB="$WORK/streamvault.sqlite"
export STREAMVAULT_KEY_FILE="$WORK/secret.key"

cleanup() {
  kill "${ADMIN_PID:-}" "${GATEWAY_PID:-}" "${SOURCE_PID:-}" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then echo "PASS: $desc"; else echo "FAIL: $desc (expected $expected, got $actual)"; FAIL=1; fi
}

echo "== 0. Prepare a real HLS source and an operator account =="
mkdir -p "$WORK/source"
ffmpeg -loglevel error -f lavfi -i "testsrc=size=320x240:rate=10" -t 4 -pix_fmt yuv420p \
  -c:v libx264 -hls_time 2 -hls_playlist_type vod -hls_segment_filename "$WORK/source/seg%d.ts" "$WORK/source/index.m3u8"
(cd "$WORK/source" && exec python3 -m http.server "$SOURCE_PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SOURCE_PID=$!

echo "supersecretpassword123" | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null

echo "== 1. Start the PHP admin (built-in server, same as a php-fpm-backed setup would serve) =="
(cd "$ROOT" && exec php -S "127.0.0.1:$ADMIN_PORT" -t admin) >"$WORK/admin.log" 2>&1 &
ADMIN_PID=$!
sleep 1

get_csrf() {
  curl -s -c "$COOKIES" -b "$COOKIES" "$1" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'
}

echo "== 2. Log in =="
CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/login.php")
LOGIN_CODE=$(curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -w "%{http_code}" \
  -d "csrf=$CSRF" -d "username=admin" -d "password=supersecretpassword123" \
  "http://127.0.0.1:$ADMIN_PORT/login.php")
check "login redirect status" "302" "$LOGIN_CODE"
DASH=$(curl -s -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$ADMIN_PORT/index.php")
if echo "$DASH" | grep -q "Dashboard"; then echo "PASS: reached dashboard after login"; else echo "FAIL: did not reach dashboard"; FAIL=1; fi

echo "== 3. Create a stream via the real form =="
CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/stream_form.php")
curl -s -c "$COOKIES" -b "$COOKIES" -o "$WORK/create_stream.html" \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode "name=E2E Admin Nova" \
  --data-urlencode "description=created by e2e_admin_flow.sh" \
  --data-urlencode "source_type=hls" \
  --data-urlencode "source_url=http://127.0.0.1:$SOURCE_PORT/index.m3u8" \
  --data-urlencode "source_username=" \
  --data-urlencode "source_password=" \
  --data-urlencode "rotation_mode=manual_approval" \
  --data-urlencode "replacement_reason=unauthorized_redistribution" \
  "http://127.0.0.1:$ADMIN_PORT/stream_form.php"
STREAM_ID=$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM streams WHERE name='E2E Admin Nova';")
if [ -n "$STREAM_ID" ]; then echo "PASS: stream created via form, id=$STREAM_ID"; else echo "FAIL: stream not found after form submit"; FAIL=1; fi

echo "== 4. Add a public access point via the real form =="
CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID")
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=add_access_point" \
  --data-urlencode "public_path=live/e2eadmin" --data-urlencode "visibility=public" \
  "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID"
AP_COUNT=$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM access_points WHERE public_path='live/e2eadmin';")
check "public access point created" "1" "$AP_COUNT"

echo "== 5. Add a private access point + issue a token via the real forms =="
CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID")
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=add_access_point" \
  --data-urlencode "public_path=live/e2eadmin-priv" --data-urlencode "visibility=private" \
  "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID"
PRIV_AP_ID=$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM access_points WHERE public_path='live/e2eadmin-priv';")

CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID")
REVEAL_HTML=$(curl -s -c "$COOKIES" -b "$COOKIES" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=add_token" \
  --data-urlencode "access_point_id=$PRIV_AP_ID" --data-urlencode "label=E2E recipient" \
  "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID")
RAW_TOKEN=$(echo "$REVEAL_HTML" | grep -o "live/e2eadmin-priv/[0-9a-f]\{48\}" | head -1 | sed 's#.*/##')
if [ -n "$RAW_TOKEN" ]; then echo "PASS: token issued and revealed once in the response, token=${RAW_TOKEN:0:8}..."; else echo "FAIL: could not find issued token in page"; FAIL=1; fi

echo "== 6. Start the gateway against the SAME db the admin just wrote =="
(cd "$ROOT/gateway" && go build -o "$WORK/gateway-bin" ./cmd/gateway)
STREAMVAULT_DB="$STREAMVAULT_DB" STREAMVAULT_KEY_FILE="$STREAMVAULT_KEY_FILE" STREAMVAULT_LISTEN="127.0.0.1:$GATEWAY_PORT" \
  "$WORK/gateway-bin" >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
sleep 1

echo "== 7. Fetch the public URL the admin created, through the gateway =="
CODE=$(curl -s -o "$WORK/pub.m3u8" -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2eadmin.m3u8")
check "public entry status" "200" "$CODE"
grep -q "/r/" "$WORK/pub.m3u8" && echo "PASS: public manifest rewritten" || { echo "FAIL: public manifest not rewritten"; FAIL=1; }

echo "== 8. Fetch the private URL with the token the admin's UI revealed =="
CODE=$(curl -s -o "$WORK/priv.m3u8" -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2eadmin-priv/$RAW_TOKEN.m3u8")
check "private entry status with admin-issued token" "200" "$CODE"

echo "== 9. Revoke that token from the admin UI, then confirm the gateway rejects it immediately =="
CSRF=$(get_csrf "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID")
TOKEN_ID=$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM access_tokens WHERE access_point_id=$PRIV_AP_ID;")
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode "action=revoke_token" \
  --data-urlencode "token_id=$TOKEN_ID" --data-urlencode "reason=manual" \
  "http://127.0.0.1:$ADMIN_PORT/stream_view.php?id=$STREAM_ID"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2eadmin-priv/$RAW_TOKEN.m3u8")
check "gateway rejects admin-revoked token" "410" "$CODE"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ALL ADMIN+GATEWAY INTEGRATION CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
  echo "--- admin.log ---"; tail -30 "$WORK/admin.log"
  echo "--- gateway.log ---"; tail -30 "$WORK/gateway.log"
  exit 1
fi
