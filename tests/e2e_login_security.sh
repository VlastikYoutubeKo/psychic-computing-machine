#!/usr/bin/env bash
# Login throttling, spoofed CF-Connecting-IP, security headers, POST-only logout.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; PORT=18341; FAIL=0
export STREAMVAULT_DB="$WORK/sv.sqlite" STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup(){ kill "${PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
check(){ if [ "$2" = "$3" ]; then echo "PASS: $1"; else echo "FAIL: $1 (expected $2, got $3)"; FAIL=1; fi; }
printf '%s\n' 'correct-horse-battery' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
php -S "127.0.0.1:$PORT" -t "$ROOT/admin" >"$WORK/php.log" 2>&1 & PID=$!
sleep 1
B="http://127.0.0.1:$PORT"; J="$WORK/c"
tok(){ curl -s -c "$J" -b "$J" "$B/login.php" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
login(){ curl -s -c "$J" -b "$J" -o /dev/null -w "%{http_code}" ${2:-} --data-urlencode "csrf=$(tok)" --data-urlencode username=admin --data-urlencode "password=$1" "$B/login.php"; }

H=$(curl -sI "$B/login.php")
echo "$H" | grep -qi '^x-frame-options: DENY' && echo "PASS: X-Frame-Options" || { echo "FAIL: X-Frame-Options"; FAIL=1; }
echo "$H" | grep -qi "frame-ancestors 'none'" && echo "PASS: CSP frame-ancestors" || { echo "FAIL: CSP"; FAIL=1; }
echo "$H" | grep -qi '^x-content-type-options: nosniff' && echo "PASS: nosniff" || { echo "FAIL: nosniff"; FAIL=1; }
echo "$H" | grep -qi '^x-powered-by' && { echo "FAIL: X-Powered-By still sent"; FAIL=1; } || echo "PASS: no X-Powered-By"

for i in 1 2 3 4 5; do login wrong >/dev/null; done
check "6th attempt throttled even with correct password" 429 "$(login correct-horse-battery)"
# Spoofed CF-Connecting-IP from a non-Cloudflare peer must not reset the IP bucket.
check "spoofed CF-Connecting-IP ignored" 429 "$(login correct-horse-battery "-H CF-Connecting-IP:9.9.9.9")"
JSON=$(curl -s -c "$J" -b "$J" -H 'X-SV-Login: 1' --data-urlencode "csrf=$(tok)" --data-urlencode username=admin --data-urlencode password=correct-horse-battery "$B/login.php")
echo "$JSON" | grep -q 'Too many failed attempts' && echo "PASS: JSON login reports throttling" || { echo "FAIL: JSON throttle message: $JSON"; FAIL=1; }

# Lift the throttle (simulate window expiry) and log in for real.
sqlite3 "$STREAMVAULT_DB" "UPDATE login_attempts SET created_at = '2000-01-01T00:00:00.000Z'"
check "correct login after window" 302 "$(login correct-horse-battery)"
check "dashboard reachable" 200 "$(curl -s -c "$J" -b "$J" -o /dev/null -w '%{http_code}' "$B/index.php")"
curl -s -c "$J" -b "$J" -o /dev/null "$B/logout.php"
check "GET logout does not log out" 200 "$(curl -s -c "$J" -b "$J" -o /dev/null -w '%{http_code}' "$B/index.php")"
CSRF=$(curl -s -c "$J" -b "$J" "$B/index.php" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/')
check "POST logout without CSRF rejected" 400 "$(curl -s -c "$J" -b "$J" -o /dev/null -w '%{http_code}' -X POST "$B/logout.php")"
curl -s -c "$J" -b "$J" -o /dev/null --data-urlencode "csrf=$CSRF" "$B/logout.php"
check "POST logout with CSRF logs out" 302 "$(curl -s -c "$J" -b "$J" -o /dev/null -w '%{http_code}' "$B/index.php")"
check "successful login cleared IP failures" 0 "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM login_attempts WHERE created_at > '2001-01-01'")"

# --- persistent login: 3 days since the last request, own session directory -------
J2="$WORK/c2"
t2=$(curl -s -c "$J2" -b "$J2" "$B/login.php" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/')
curl -s -c "$J2" -b "$J2" -o /dev/null --data-urlencode "csrf=$t2" --data-urlencode username=admin --data-urlencode password=correct-horse-battery "$B/login.php"
check "logged in" 200 "$(curl -s -c "$J2" -b "$J2" -o /dev/null -w '%{http_code}' "$B/index.php")"
EXP=$(awk '$6=="streamvault_admin"{print $5}' "$J2"); NOW=$(date +%s)
[ -n "$EXP" ] && [ "$EXP" -gt $((NOW + 3*86400 - 300)) ] && [ "$EXP" -le $((NOW + 3*86400 + 300)) ] \
  && echo "PASS: session cookie persists ~3 days (survives closing the browser)" || { echo "FAIL: session cookie expiry is '$EXP' (now $NOW)"; FAIL=1; }
SIDV=$(awk '$6=="streamvault_admin"{print $7}' "$J2")
[ -f "$WORK/sessions/sess_$SIDV" ] && echo "PASS: session stored in the app's own directory, not shared /tmp" || { echo "FAIL: session file not in $WORK/sessions"; FAIL=1; }
check "session directory is private" 700 "$(stat -c %a "$WORK/sessions")"
# Two days idle: still logged in.
sed -i -E "s/last_seen\|i:[0-9]+;/last_seen|i:$((NOW - 2*86400));/" "$WORK/sessions/sess_$SIDV"
check "still logged in after 2 idle days" 200 "$(curl -s -c "$J2" -b "$J2" -o /dev/null -w '%{http_code}' "$B/index.php")"
# Four days idle: logged out server-side even though the browser still sends the cookie.
SIDV=$(awk '$6=="streamvault_admin"{print $7}' "$J2")
sed -i -E "s/last_seen\|i:[0-9]+;/last_seen|i:$((NOW - 4*86400));/" "$WORK/sessions/sess_$SIDV"
check "logged out after 4 idle days" 302 "$(curl -s -c "$J2" -b "$J2" -o /dev/null -w '%{http_code}' "$B/index.php")"

[ "$FAIL" -eq 0 ] && echo "ALL LOGIN SECURITY E2E CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
