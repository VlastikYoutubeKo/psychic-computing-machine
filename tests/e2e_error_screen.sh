#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
ADMIN_PORT=8096
MOCK_PORT=18916
export STREAMVAULT_DB="$WORK/streamvault.sqlite"
export STREAMVAULT_KEY_FILE="$WORK/secret.key"
COOKIES="$WORK/cookies"
cleanup() { kill "${ADMIN_PID:-}" "${MOCK_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

cat >"$WORK/mock.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

class Mock(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert self.headers['Authorization'] == 'Bearer local-test-key'
        assert body['model'] == 'z-ai/glm-5.3-flash'
        if 'force401' in body['messages'][1]['content']:
            data = b'echo local-test-key secret response'
            self.send_response(401)
        else:
            data = json.dumps({'choices':[{'message':{'content':json.dumps({'title':'Generated title','subtitle':'Generated subtitle.'})}}]}).encode()
            self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)

HTTPServer(('127.0.0.1', int(os.environ['MOCK_PORT'])), Mock).serve_forever()
PY
MOCK_PORT="$MOCK_PORT" python3 "$WORK/mock.py" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
echo 'supersecretpassword123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null
STREAMVAULT_OPENROUTER_URL="http://127.0.0.1:$MOCK_PORT/ai" php -S "127.0.0.1:$ADMIN_PORT" -t "$ROOT/admin" >"$WORK/admin.log" 2>&1 &
ADMIN_PID=$!
sleep 1
csrf() { curl -s -c "$COOKIES" -b "$COOKIES" "$1" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
base="http://127.0.0.1:$ADMIN_PORT"
token="$(csrf "$base/login.php")"
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -d "csrf=$token" -d 'username=admin' -d 'password=supersecretpassword123' "$base/login.php"
token="$(csrf "$base/settings.php")"
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -d "csrf=$token" -d 'action=save_openrouter_key' -d 'openrouter_key=local-test-key' "$base/settings.php"
if grep -aq 'local-test-key' "$STREAMVAULT_DB"; then echo 'FAIL: plaintext key in SQLite'; exit 1; fi
token="$(csrf "$base/error_screen.php")"
curl -s -c "$COOKIES" -b "$COOKIES" -o "$WORK/suggestion.html" -d "csrf=$token" -d 'action=generate_slate_text' -d 'reason=limited_bandwidth' -d 'language=en' -d 'instruction=calm' "$base/error_screen.php"
grep -q 'Generated title' "$WORK/suggestion.html" || { echo 'FAIL: suggestion absent'; exit 1; }
saved="$(sqlite3 "$STREAMVAULT_DB" "SELECT title FROM slate_texts WHERE reason='limited_bandwidth'")"
[ "$saved" = 'Capacity limit reached' ] || { echo 'FAIL: AI autosaved'; exit 1; }
token="$(csrf "$base/error_screen.php")"
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -d "csrf=$token" -d 'action=save_slate_text' -d 'reason=limited_bandwidth' --data-urlencode 'title=Generated title' --data-urlencode 'subtitle=Generated subtitle.' "$base/error_screen.php"
saved="$(sqlite3 "$STREAMVAULT_DB" "SELECT title FROM slate_texts WHERE reason='limited_bandwidth'")"
[ "$saved" = 'Generated title' ] || { echo 'FAIL: approved text was not saved'; exit 1; }
curl -s -c "$COOKIES" -b "$COOKIES" -o "$WORK/error.html" -d "csrf=$token" -d 'action=generate_slate_text' -d 'reason=limited_bandwidth' -d 'language=cs' -d 'instruction=force401' "$base/error_screen.php"
grep -q 'HTTP 401' "$WORK/error.html" || { echo 'FAIL: status not reported'; exit 1; }
if grep -q 'local-test-key\|secret response' "$WORK/error.html"; then echo 'FAIL: key or raw response leaked'; exit 1; fi
for _ in $(seq 1 8); do
  curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -d "csrf=$token" -d 'action=generate_slate_text' -d 'reason=limited_bandwidth' -d 'language=en' "$base/error_screen.php"
done
curl -s -c "$COOKIES" -b "$COOKIES" -o "$WORK/limit.html" -d "csrf=$token" -d 'action=generate_slate_text' -d 'reason=limited_bandwidth' -d 'language=en' "$base/error_screen.php"
grep -q 'AI generation limit reached' "$WORK/limit.html" || { echo 'FAIL: per-operator rate limit'; exit 1; }
old_hash="$(sqlite3 "$STREAMVAULT_DB" "SELECT password_hash FROM operators WHERE username='admin'")"
token="$(csrf "$base/settings.php")"
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -d "csrf=$token" -d 'action=change_password' -d 'current_password=supersecretpassword123' -d 'new_password=changedpassword123' -d 'new_password_confirm=changedpassword123' "$base/settings.php"
new_hash="$(sqlite3 "$STREAMVAULT_DB" "SELECT password_hash FROM operators WHERE username='admin'")"
[ "$old_hash" != "$new_hash" ] || { echo 'FAIL: own-password change'; exit 1; }
curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null "$base/logout.php"
token="$(csrf "$base/login.php")"
code="$(curl -s -c "$COOKIES" -b "$COOKIES" -o /dev/null -w '%{http_code}' -d "csrf=$token" -d 'username=admin' -d 'password=changedpassword123' "$base/login.php")"
[ "$code" = 302 ] || { echo 'FAIL: login after own-password change'; exit 1; }
echo 'ALL ERROR SCREEN + OPENROUTER MOCK E2E CHECKS PASSED'
