#!/usr/bin/env bash
# Xtream Codes import across the real stack: a mock panel (player_api.php +
# /live/<user>/<pass>/<id>.m3u8), the PHP admin's import page, and the Go
# gateway playing an imported stream. Proves the password is stored only
# encrypted, never shown, and substituted into the URL path at fetch time
# (PHP-encrypted -> Go-decrypted, with characters that need escaping).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; ADMIN_PORT=18371; GW_PORT=18372; XT_PORT=18373; FAIL=0
export STREAMVAULT_DB="$WORK/sv.sqlite" STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup(){ kill ${PIDS:-} 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
ok(){ echo "PASS: $1"; }
bad(){ echo "FAIL: $1"; FAIL=1; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $2, got $3)"; fi; }
q(){ sqlite3 "$STREAMVAULT_DB" "$1"; }
PIDS=""
XUSER='line user'; XPASS='p@ss w/rd&1'

# --- mock Xtream panel ------------------------------------------------------
cat > "$WORK/panel.py" <<'PY'
import json, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
USER, PASS, LOG = sys.argv[2], sys.argv[3], sys.argv[4]
LIVE = "/live/%s/%s/" % (USER, PASS)  # compared after percent-decoding, like a real web server
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        with open(LOG, "a") as f:
            f.write("%s auth=%s\n" % (self.path, "yes" if self.headers.get("Authorization") else "no"))
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/player_api.php":
            qs = urllib.parse.parse_qs(u.query)
            good = qs.get("username") == [USER] and qs.get("password") == [PASS]
            action = qs.get("action", [None])[0]
            if not good:
                return self.send(200, json.dumps({"user_info": {"auth": 0}}))
            if action is None:
                return self.send(200, json.dumps({"user_info": {"auth": 1, "status": "Active", "exp_date": "1893456000", "max_connections": "2", "active_cons": "0"}, "server_info": {}}))
            if action == "get_live_categories":
                return self.send(200, json.dumps([{"category_id": "1", "category_name": "News"}, {"category_id": "2", "category_name": "Kids <b>"}]))
            if action == "get_live_streams":
                return self.send(200, json.dumps([
                    {"stream_id": 101, "name": "Alpha News", "category_id": "1"},
                    {"stream_id": 102, "name": "Beta Kids", "category_id": "2"},
                    {"stream_id": 103, "name": "<script>alert(1)</script>", "category_id": "1"},
                    {"stream_id": "bogus", "name": "ignored"}]))
            return self.send(200, "[]")
        path = urllib.parse.unquote(self.path)
        if path == LIVE + "102.m3u8":
            return self.send(200, "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nseg1.ts\n", "application/vnd.apple.mpegurl")
        if path == LIVE + "seg1.ts":
            return self.send(200, b"xtream-segment-bytes", "video/mp2t")
        self.send(404, "not found", "text/plain")
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/panel.py" "$XT_PORT" "$XUSER" "$XPASS" "$WORK/panel.log" & PIDS="$PIDS $!"
X="http://127.0.0.1:$XT_PORT"

printf '%s\n' 'admin-password-123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
php -S "127.0.0.1:$ADMIN_PORT" -t "$ROOT/admin" >"$WORK/php.log" 2>&1 & PIDS="$PIDS $!"
(cd "$ROOT/gateway" && go build -o "$WORK/gw" ./cmd/gateway) || { echo "build failed"; exit 1; }
sleep 1
A="http://127.0.0.1:$ADMIN_PORT"; G="http://127.0.0.1:$GW_PORT"
jar(){ echo "$WORK/$1.jar"; }
csrf(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" "$A/$2" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
post(){ local u=$1 page=$2; shift 2; local t; t=$(csrf "$u" index.php); local args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -c "$(jar "$u")" -b "$(jar "$u")" -o "$WORK/last.html" -w '%{http_code}' --data-urlencode "csrf=$t" "${args[@]}" "$A/$page"; }
get(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o "$WORK/last.html" -w '%{http_code}' "$A/$2"; }
login(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$(csrf "$1" login.php)" --data-urlencode "username=$1" --data-urlencode "password=$2" "$A/login.php"; }

check "admin login" 302 "$(login admin admin-password-123)"
check "import page requires login" 302 "$(curl -s -o /dev/null -w '%{http_code}' "$A/xtream_import.php")"
get admin streams.php >/dev/null; grep -q 'href="xtream_import.php"' "$WORK/last.html" && ok "streams page links to the import" || bad "no import link on streams page"

# --- connect ---------------------------------------------------------------
post admin xtream_import.php action=connect "server=$X" "username=$XUSER" password=wrong format=m3u8 >/dev/null
grep -q "rejected the username or password" "$WORK/last.html" && ok "wrong password is reported" || bad "wrong password not reported"
post admin xtream_import.php action=connect "server=ftp://x" "username=$XUSER" "password=$XPASS" >/dev/null
grep -q "Enter the server address" "$WORK/last.html" && ok "non-http server address rejected" || bad "bad server address accepted"

check "connect redirects to the channel list" 302 "$(post admin xtream_import.php action=connect "server=$X/get.php?x=1" "username=$XUSER" "password=$XPASS" format=m3u8)"
check "channel list loads" 200 "$(get admin xtream_import.php)"
grep -q "Alpha News" "$WORK/last.html" && grep -q "Beta Kids" "$WORK/last.html" && ok "channels listed" || bad "channels missing"
grep -q "2 allowed" "$WORK/last.html" && ok "connection limit shown" || bad "connection limit missing"
grep -q "<script>alert(1)</script>" "$WORK/last.html" && bad "panel-supplied name rendered unescaped (XSS)" || ok "panel-supplied names are escaped"
grep -q "&lt;script&gt;alert(1)&lt;/script&gt;" "$WORK/last.html" && ok "escaped name is present" || bad "escaped name missing"
grep -qF "$XPASS" "$WORK/last.html" || grep -q "p@ss" "$WORK/last.html" && bad "password appears in the page" || ok "password never rendered"

# --- import ----------------------------------------------------------------
post admin xtream_import.php action=import >/dev/null
grep -q "Select at least one channel" "$WORK/last.html" && ok "empty selection rejected" || bad "empty selection accepted"
check "import redirects to streams" 302 "$(post admin xtream_import.php action=import 'ids[]=101' 'ids[]=102' 'ids[]=999')"
check "two streams created (unknown id ignored)" 2 "$(q "SELECT COUNT(*) FROM streams")"
check "stored URL keeps placeholders" "$X/live/{username}/{password}/102.m3u8" "$(q "SELECT source_url FROM streams WHERE name='Beta Kids'")"
check "source type follows the format" hls "$(q "SELECT source_type FROM streams WHERE name='Beta Kids'")"
check "username stored" "$XUSER" "$(q "SELECT source_username FROM streams WHERE name='Beta Kids'")"
check "category kept in description" "Xtream Codes · Kids <b>" "$(q "SELECT description FROM streams WHERE name='Beta Kids'")"
sqlite3 "$STREAMVAULT_DB" .dump | grep -qF "$XPASS" && bad "plaintext password in the database" || ok "no plaintext password in the database"
check "each stream has an encrypted password" 2 "$(q "SELECT COUNT(*) FROM streams WHERE length(source_password_enc) > 20")"
OLDENC=$(q "SELECT source_password_enc FROM streams WHERE name='Alpha News'")
post admin xtream_import.php action=import 'ids[]=101' >/dev/null
check "re-import skips existing streams" 2 "$(q "SELECT COUNT(*) FROM streams")"
[ "$OLDENC" != "$(q "SELECT source_password_enc FROM streams WHERE name='Alpha News'")" ] && ok "re-import refreshes the stored password" || bad "re-import did not refresh the password"
get admin xtream_import.php >/dev/null; grep -q "already added" "$WORK/last.html" && ok "imported channels are marked" || bad "imported channels not marked"
SID=$(q "SELECT id FROM streams WHERE name='Beta Kids'")
get admin "stream_view.php?id=$SID" >/dev/null
grep -q "{username}/{password}/102.m3u8" "$WORK/last.html" && ! grep -q "p@ss" "$WORK/last.html" && ok "stream page shows placeholders, not the password" || bad "stream page leaks or lacks the source URL"

# --- gateway plays the imported stream ----------------------------------------
post admin "stream_view.php?id=$SID" action=add_access_point public_path=kids visibility=public >/dev/null
check "access point created" 1 "$(q "SELECT COUNT(*) FROM access_points WHERE public_path='kids'")"
: > "$WORK/panel.log"
STREAMVAULT_LISTEN="127.0.0.1:$GW_PORT" "$WORK/gw" >"$WORK/gw.log" 2>&1 & PIDS="$PIDS $!"
sleep 1
check "gateway serves the playlist" 200 "$(curl -s -o "$WORK/pl.m3u8" -w '%{http_code}' "$G/kids.m3u8")"
grep -q "p@ss\|p%40ss\|line%20user" "$WORK/pl.m3u8" && bad "credentials leaked to the viewer playlist" || ok "viewer playlist has no credentials"
SEG=$(grep -v '^#' "$WORK/pl.m3u8" | head -1)
check "gateway serves the segment" "xtream-segment-bytes" "$(curl -s "$G$SEG")"
grep -qF "/live/line%20user/p@ss%20w%2Frd&1/102.m3u8 auth=no" "$WORK/panel.log" && ok "panel got escaped credentials in the path, no Basic auth" || bad "unexpected panel request: $(cat "$WORK/panel.log")"
grep -q "p@ss\|p%40ss" "$WORK/gw.log" && bad "password in the gateway log" || ok "gateway log has no password"

# --- regular accounts can't point the admin server at private addresses -----------
post admin accounts.php action=create username=bob max_streams=1 max_access_points=3 >/dev/null
INV=$(grep -oE 'accept_invite\.php\?token=[0-9a-f]{64}' "$WORK/last.html" | head -1)
curl -s -c "$(jar bob)" -b "$(jar bob)" -o /dev/null "$A/$INV"
t=$(csrf bob accept_invite.php); curl -s -c "$(jar bob)" -b "$(jar bob)" -o /dev/null --data-urlencode "csrf=$t" --data-urlencode password=bob-password-123 --data-urlencode password_confirm=bob-password-123 "$A/accept_invite.php"
login bob bob-password-123 >/dev/null
: > "$WORK/panel.log"
post bob xtream_import.php action=connect "server=$X" "username=$XUSER" "password=$XPASS" >/dev/null
grep -q "must be a public address" "$WORK/last.html" && ok "non-admin cannot connect to a private address" || bad "non-admin private connect not rejected"
check "no request was sent for the rejected connect" 0 "$(wc -l < "$WORK/panel.log" | tr -d ' ')"
# PHP 8.2's filter_var calls IPv4-mapped IPv6 "public"; it must still be refused.
post bob xtream_import.php action=connect "server=http://[::ffff:127.0.0.1]:$XT_PORT" "username=$XUSER" "password=$XPASS" >/dev/null
grep -q "must be a public address" "$WORK/last.html" && ok "non-admin cannot use an IPv4-mapped IPv6 literal" || bad "IPv4-mapped literal not rejected"
check "no request was sent for the IPv4-mapped literal" 0 "$(wc -l < "$WORK/panel.log" | tr -d ' ')"
check "bob has no session connection (import refused)" 302 "$(post bob xtream_import.php action=import 'ids[]=103')"
check "bob created nothing" 0 "$(q "SELECT COUNT(*) FROM streams WHERE owner_id=(SELECT id FROM operators WHERE username='bob')")"
check "bob cannot see admin's imported stream" 404 "$(get bob "stream_view.php?id=$SID")"

# The remembered connection belongs to the operator who made it: another
# account logging in within the same browser session must not inherit it.
q "UPDATE operators SET status='disabled' WHERE username='admin'"
get admin index.php >/dev/null   # admin's session loses operator_id but keeps the rest
q "UPDATE operators SET status='active' WHERE username='admin'"
curl -s -c "$(jar admin)" -b "$(jar admin)" -o /dev/null --data-urlencode "csrf=$(csrf admin login.php)" --data-urlencode username=bob --data-urlencode password=bob-password-123 "$A/login.php"
get admin xtream_import.php >/dev/null
grep -q 'name="password"' "$WORK/last.html" && ! grep -q "Alpha News" "$WORK/last.html" && ok "another operator in the same session does not inherit the connection" || bad "Xtream connection leaked to another operator"
check "bob (no remux) is not offered MPEG-TS" 0 "$(grep -c 'value="ts"' "$WORK/last.html")"
login admin admin-password-123 >/dev/null
post admin xtream_import.php action=connect "server=$X" "username=$XUSER" "password=$XPASS" format=m3u8 >/dev/null

post admin xtream_import.php action=disconnect >/dev/null
get admin xtream_import.php >/dev/null; grep -q 'name="password"' "$WORK/last.html" && ok "disconnect returns to the connect form" || bad "disconnect did not clear the connection"

[ "$FAIL" = 0 ] && echo "ALL XTREAM E2E CHECKS PASSED" || { echo "SOME XTREAM E2E CHECKS FAILED"; exit 1; }
