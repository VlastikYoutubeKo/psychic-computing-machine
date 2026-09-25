#!/usr/bin/env bash
# Exercises the real admin login, CSRF checks, manual incident creation,
# state transitions, audit history and HTML escaping over HTTP.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT=18325
COOKIES="$WORK/cookies.txt"
export STREAMVAULT_DB="$WORK/streamvault.sqlite"
export STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup() { kill "${ADMIN_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

printf '%s\n' 'supersecretpassword123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
sqlite3 "$STREAMVAULT_DB" "INSERT INTO streams (name, source_type, source_url) VALUES ('Incident Test', 'hls', 'https://source.test/index.m3u8');"
STREAM_ID="$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM streams WHERE name='Incident Test';")"
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
CSRF="$(csrf incidents.php)"

# Neither an anonymous request nor a logged-in request with a bad CSRF token
# may create an incident.
curl -sS -o /dev/null --data-urlencode 'action=create' --data-urlencode "stream_id=$STREAM_ID" \
  "http://127.0.0.1:$PORT/incidents.php"
BAD_CODE="$(curl -sS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w '%{http_code}' \
  --data-urlencode 'csrf=bad' --data-urlencode 'action=create' --data-urlencode "stream_id=$STREAM_ID" \
  "http://127.0.0.1:$PORT/incidents.php")"
test "$BAD_CODE" = 400
test "$(sqlite3 "$STREAMVAULT_DB" 'SELECT COUNT(*) FROM incidents;')" = 0

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=create' \
  --data-urlencode "stream_id=$STREAM_ID" \
  --data-urlencode 'source_url=https://example.test/leak?x=1&y=2' \
  --data-urlencode 'notes=<script>alert(1)</script>' \
  "http://127.0.0.1:$PORT/incidents.php"
ID="$(sqlite3 "$STREAMVAULT_DB" "SELECT id FROM incidents WHERE stream_id=$STREAM_ID;")"
test -n "$ID"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT source || ':' || status FROM incidents WHERE id=$ID;")" = 'manual:new'
PAGE="$(curl -fsS -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$PORT/incidents.php")"
if echo "$PAGE" | grep -q '<script>alert(1)</script>'; then
  echo 'FAIL: evidence notes rendered as executable HTML'; exit 1
fi
echo "$PAGE" | grep -q '&lt;script&gt;alert(1)&lt;/script&gt;'

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=confirm' \
  --data-urlencode "incident_id=$ID" "http://127.0.0.1:$PORT/incidents.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT status FROM incidents WHERE id=$ID;")" = confirmed

# Confirmed incidents cannot be dismissed through a forged form submission.
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=dismiss' \
  --data-urlencode "incident_id=$ID" "http://127.0.0.1:$PORT/incidents.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT status FROM incidents WHERE id=$ID;")" = confirmed

curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null \
  --data-urlencode "csrf=$CSRF" --data-urlencode 'action=resolve' \
  --data-urlencode "incident_id=$ID" "http://127.0.0.1:$PORT/incidents.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT status FROM incidents WHERE id=$ID;")" = resolved
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT json_array_length(actions_taken) FROM incidents WHERE id=$ID;")" = 2
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM audit_log WHERE target='incident:$ID' AND action IN ('incident_created','incident_confirm','incident_resolve');")" = 3
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT status FROM streams WHERE id=$STREAM_ID;")" = active

echo 'ALL INCIDENT ADMIN E2E CHECKS PASSED'
