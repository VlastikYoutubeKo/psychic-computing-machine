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

[ "$FAIL" -eq 0 ] && echo "ALL LOGIN SECURITY E2E CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
