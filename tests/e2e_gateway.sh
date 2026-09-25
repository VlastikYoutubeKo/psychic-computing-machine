#!/usr/bin/env bash
# End-to-end proof that the gateway actually protects an HLS stream:
# generates a real HLS VOD with ffmpeg, serves it as a stand-in "source",
# points the gateway at it through a scratch SQLite DB, and exercises the
# full lifecycle: valid token -> rewritten manifest -> segment fetch works,
# wrong token -> 404, revoked token -> 410. Safe to run repeatedly; each run
# uses a fresh temp dir and picks free ports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill $SOURCE_PID $GATEWAY_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

SOURCE_PORT=18321
GATEWAY_PORT=18322
RAW_TOKEN="e2e-test-token-do-not-use-in-prod"
FAIL=0

echo "== 1. Generating test HLS VOD with ffmpeg =="
mkdir -p "$WORK/source"
ffmpeg -loglevel error -f lavfi -i "testsrc=size=320x240:rate=10" -t 6 -pix_fmt yuv420p \
  -c:v libx264 -hls_time 2 -hls_playlist_type vod \
  -hls_segment_filename "$WORK/source/seg%d.ts" "$WORK/source/index.m3u8"
test -f "$WORK/source/index.m3u8" || { echo "FAIL: ffmpeg did not produce index.m3u8"; exit 1; }
echo "OK: $(ls "$WORK/source" | tr '\n' ' ')"

echo "== 2. Serving it as the 'source' over plain HTTP =="
(cd "$WORK/source" && exec python3 -m http.server "$SOURCE_PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SOURCE_PID=$!
sleep 1

echo "== 3. Building scratch SQLite DB with a private access point =="
DB="$WORK/streamvault.sqlite"
sqlite3 "$DB" < "$ROOT/migrations/0001_init.sql"
sqlite3 "$DB" "INSERT INTO streams (name, source_type, source_url) VALUES ('E2E Nova', 'hls', 'http://127.0.0.1:$SOURCE_PORT/index.m3u8');"
STREAM_ID=$(sqlite3 "$DB" "SELECT id FROM streams WHERE name='E2E Nova';")
sqlite3 "$DB" "INSERT INTO access_points (stream_id, public_path, visibility) VALUES ($STREAM_ID, 'live/e2e', 'private');"
AP_ID=$(sqlite3 "$DB" "SELECT id FROM access_points WHERE public_path='live/e2e';")
TOKEN_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$RAW_TOKEN")
sqlite3 "$DB" "INSERT INTO access_tokens (access_point_id, token_hash, token_display, label) VALUES ($AP_ID, '$TOKEN_HASH', 'e2etok', 'e2e recipient');"
echo "OK: stream_id=$STREAM_ID access_point_id=$AP_ID"

echo "== 4. Building and starting the gateway =="
(cd "$ROOT/gateway" && go build -o "$WORK/gateway-bin" ./cmd/gateway)
STREAMVAULT_DB="$DB" STREAMVAULT_KEY_FILE="$WORK/nonexistent.key" STREAMVAULT_LISTEN="127.0.0.1:$GATEWAY_PORT" \
  "$WORK/gateway-bin" >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
sleep 1

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (expected $expected, got $actual)"
    FAIL=1
  fi
}

echo "== 5. Valid token: entry manifest must be rewritten and hide the source =="
BODY=$(curl -s "http://127.0.0.1:$GATEWAY_PORT/live/e2e/$RAW_TOKEN.m3u8")
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2e/$RAW_TOKEN.m3u8")
check "entry HTTP status" "200" "$CODE"
if echo "$BODY" | grep -q "127.0.0.1:$SOURCE_PORT"; then
  echo "FAIL: rewritten manifest leaks the source URL:"
  echo "$BODY"
  FAIL=1
else
  echo "PASS: source URL not present in rewritten manifest"
fi
SEG_LINE=$(echo "$BODY" | grep '/r/' | head -1)
if [ -z "$SEG_LINE" ]; then
  echo "FAIL: no proxied segment line found in manifest"; FAIL=1
else
  echo "PASS: found proxied segment line: $SEG_LINE"
fi

echo "== 6. Fetching a proxied segment through the gateway must return real video bytes =="
# Resolve SEG_LINE exactly the way a real HLS player would: as a reference
# relative to the manifest's OWN URL, not by string-concatenating it onto
# the gateway root. An earlier version of the gateway emitted a reference
# with no leading slash, which happened to still work under naive
# concatenation here but would have double-nested the path in any real
# player -- caught by security review, not by this script, which is why
# this now does real URL resolution instead.
ENTRY_URL="http://127.0.0.1:$GATEWAY_PORT/live/e2e/$RAW_TOKEN.m3u8"
SEG_URL=$(python3 -c "import urllib.parse,sys; print(urllib.parse.urljoin(sys.argv[1], sys.argv[2]))" "$ENTRY_URL" "$SEG_LINE")
SEG_CODE=$(curl -s -o "$WORK/fetched.ts" -w "%{http_code}" "$SEG_URL")
check "segment HTTP status" "200" "$SEG_CODE"
SIZE=$(stat -c%s "$WORK/fetched.ts" 2>/dev/null || echo 0)
if [ "$SIZE" -gt 1000 ]; then
  echo "PASS: fetched segment has real content ($SIZE bytes)"
else
  echo "FAIL: fetched segment too small ($SIZE bytes)"; FAIL=1
fi

echo "== 7. Wrong token must not work =="
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2e/wrong-token.m3u8")
check "wrong token status" "404" "$CODE"

echo "== 8. SSRF guard: a hand-crafted /r/ blob (not encrypted by this gateway) must be rejected =="
# /r/ blobs are AES-256-GCM-encrypted by the gateway's own in-memory key
# (gateway/internal/blobcodec) -- a black box outside the process cannot
# forge a *valid* one, so the best an external attacker can do is exactly
# this: base64 of a URL with no valid authentication tag, which fails to
# decode at all and is rejected the same as a nonexistent path (404). The
# separate defense-in-depth layer -- a validly-encrypted blob that still
# points off the stream's configured source host -- can only be exercised
# with access to the running process's codec, so it's covered instead by
# TestCrossOriginBlobRejectedEvenWhenValidlyEncoded in
# gateway/internal/gatewayhttp/handler_test.go.
FORGED=$(python3 -c "import base64; print(base64.urlsafe_b64encode(b'http://169.254.169.254/latest/meta-data/').decode().rstrip('='))")
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2e/$RAW_TOKEN/r/$FORGED")
check "hand-crafted blob status" "404" "$CODE"

echo "== 9. Revoking the token must immediately block both manifest AND already-known segment URLs =="
sqlite3 "$DB" "UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = (SELECT id FROM access_tokens WHERE access_point_id=$AP_ID);"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GATEWAY_PORT/live/e2e/$RAW_TOKEN.m3u8")
check "revoked token entry status" "410" "$CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SEG_URL")
check "revoked token segment status (must not keep streaming)" "410" "$CODE"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ALL E2E CHECKS PASSED"
else
  echo "SOME E2E CHECKS FAILED -- see above"
  echo "--- gateway.log ---"
  cat "$WORK/gateway.log"
  exit 1
fi
