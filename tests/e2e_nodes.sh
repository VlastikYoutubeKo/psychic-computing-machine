#!/usr/bin/env bash
# Nodes across the real stack: the PHP admin creates a node (PHP-encrypted
# secret), the Go control gateway authenticates it and signs viewer
# redirects with that secret, and a real node process (same binary,
# STREAMVAULT_MODE=node) fetches its config, heartbeats and verifies the
# signature. Also: admin-only access, token reissue/disable, stream
# assignment via the stream form.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; ADMIN_PORT=18361; CTL_PORT=18362; NODE_PORT=18363; FAIL=0
export STREAMVAULT_DB="$WORK/sv.sqlite" STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup(){ kill ${PIDS:-} 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
ok(){ echo "PASS: $1"; }
bad(){ echo "FAIL: $1"; FAIL=1; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $2, got $3)"; fi; }
q(){ sqlite3 "$STREAMVAULT_DB" "$1"; }
PIDS=""

printf '%s\n' 'admin-password-123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
php -S "127.0.0.1:$ADMIN_PORT" -t "$ROOT/admin" >"$WORK/php.log" 2>&1 & PIDS="$PIDS $!"
(cd "$ROOT/gateway" && go build -o "$WORK/gw" ./cmd/gateway) || { echo "build failed"; exit 1; }
sleep 1
A="http://127.0.0.1:$ADMIN_PORT"; C="http://127.0.0.1:$CTL_PORT"
jar(){ echo "$WORK/$1.jar"; }
csrf(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" "$A/$2" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
post(){ local u=$1 page=$2; shift 2; local t; t=$(csrf "$u" index.php); local args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -c "$(jar "$u")" -b "$(jar "$u")" -o "$WORK/last.html" -w '%{http_code}' --data-urlencode "csrf=$t" "${args[@]}" "$A/$page"; }
get(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o "$WORK/last.html" -w '%{http_code}' "$A/$2"; }
login(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$(csrf "$1" login.php)" --data-urlencode "username=$1" --data-urlencode "password=$2" "$A/login.php"; }

check "admin login" 302 "$(login admin admin-password-123)"
post admin settings.php action=save_display "gateway_base_url=$C" >/dev/null
[ "$(q "SELECT value FROM settings WHERE key='gateway_base_url'")" = "$C" ] || q "INSERT OR REPLACE INTO settings (key, value) VALUES ('gateway_base_url', '$C')"

# --- create node in the admin ------------------------------------------------
post admin nodes.php action=create name=node-a "public_url=http://127.0.0.1:$NODE_PORT" >/dev/null
TOKEN=$(grep -oE 'svn_[0-9]+_[0-9a-f]{64}' "$WORK/last.html" | head -1)
[ -n "$TOKEN" ] && ok "install command with token shown once" || bad "no token in create response"
grep -q "_sv/node/install.sh | sudo STREAMVAULT_NODE_TOKEN=" "$WORK/last.html" && ok "install one-liner rendered" || bad "install one-liner missing"
get admin nodes.php >/dev/null; grep -q "$TOKEN" "$WORK/last.html" && bad "token visible again after reload" || ok "token not shown again"
NODE_ID=$(q "SELECT id FROM nodes WHERE name='node-a'")
check "only the secret hash is stored" 0 "$(q "SELECT COUNT(*) FROM nodes WHERE token_hash LIKE '%${TOKEN#svn_*_}%' OR secret_enc LIKE '%${TOKEN#svn_*_}%'")"

# --- a stream assigned to the node via the stream form --------------------------
post admin stream_form.php name=relayed source_type=hls "source_url=http://127.0.0.1:9/live.m3u8" replacement_reason=unauthorized_redistribution "node_id=$NODE_ID" >/dev/null
SID=$(q "SELECT id FROM streams WHERE name='relayed'")
check "stream assigned to node" "$NODE_ID" "$(q "SELECT node_id FROM streams WHERE id=$SID")"
post admin "stream_view.php?id=$SID" action=add_access_point public_path=relayed visibility=public >/dev/null

# --- control gateway + node process ------------------------------------------------
STREAMVAULT_LISTEN="127.0.0.1:$CTL_PORT" "$WORK/gw" >"$WORK/ctl.log" 2>&1 & PIDS="$PIDS $!"
sleep 1
check "install.sh is public" 200 "$(curl -s -o "$WORK/install.sh" -w '%{http_code}' "$C/_sv/node/install.sh")"
grep -q "STREAMVAULT_NODE_TOKEN" "$WORK/install.sh" && ! grep -q "svn_[0-9]" "$WORK/install.sh" && ok "install.sh carries no token" || bad "install.sh content"
check "binary requires token" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$C/_sv/node/binary")"
check "binary downloads with token" 200 "$(curl -s -o "$WORK/node-bin" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$C/_sv/node/binary")"
cmp -s "$WORK/node-bin" "$WORK/gw" && ok "downloaded binary is the gateway executable" || bad "downloaded binary differs"
check "config with PHP-created token (PHP->Go crypto)" 200 "$(curl -s -o "$WORK/cfg.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$C/_sv/node/config")"
grep -q "\"id\":$SID" "$WORK/cfg.json" && ok "config lists the assigned stream" || bad "assigned stream missing from config"

chmod +x "$WORK/node-bin"
STREAMVAULT_MODE=node STREAMVAULT_CONTROL_URL="$C" STREAMVAULT_NODE_TOKEN="$TOKEN" STREAMVAULT_LISTEN="127.0.0.1:$NODE_PORT" \
  "$WORK/node-bin" >"$WORK/node.log" 2>&1 & PIDS="$PIDS $!"
for i in $(seq 1 40); do [ "$(q "SELECT status FROM nodes WHERE id=$NODE_ID")" = active ] && break; sleep 1; done
check "node heartbeat marks it active (downloaded binary in node mode)" active "$(q "SELECT status FROM nodes WHERE id=$NODE_ID")"
get admin nodes.php >/dev/null; grep -q ">online<" "$WORK/last.html" && ok "admin shows node online" || bad "admin does not show node online"
# Always-on state of a node-assigned stream comes from the node heartbeat, not stream_runtime.
q "UPDATE streams SET always_on=1 WHERE id=$SID"
q "UPDATE nodes SET last_status_json='{\"streams\":[{\"id\":$SID,\"state\":\"backoff\",\"detail\":\"probe-detail\"}]}' WHERE id=$NODE_ID"
get admin "stream_view.php?id=$SID" >/dev/null
grep -q ">backoff<" "$WORK/last.html" && grep -q "on node node-a: probe-detail" "$WORK/last.html" && ok "stream view shows node-reported always-on state" || bad "stream view ignores node-reported state"
q "UPDATE streams SET always_on=0 WHERE id=$SID"
check "node health endpoint" 200 "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NODE_PORT/healthz")"

# Viewer: the control gateway proxies from the node (single domain). The
# source is down, so the node's relay isn't ready and answers 503, which
# makes the control fall back to the source; its log proves the node
# ACCEPTED the control-signed request (a bad signature would log 403).
curl -s -o "$WORK/viewer.out" -w '%{http_code} %{redirect_url}\n' "$C/relayed.m3u8" > "$WORK/viewer.code"
grep -q "^[0-9]* $" "$WORK/viewer.code" && ok "viewer is not redirected (single domain)" || bad "viewer redirected: $(cat "$WORK/viewer.code")"
sleep 1
grep -q "node $NODE_ID returned HTTP 503 for stream $SID, serving locally" "$WORK/ctl.log" && ok "node accepted the control-signed request (PHP->Go secret)" || bad "control did not reach the node with a valid signature: $(grep -i node "$WORK/ctl.log" | tail -3)"
check "node rejects an unsigned request" 403 "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NODE_PORT/n/$SID/index.m3u8?ap=0&tok=0&exp=9999999999&sig=00")"

# --- access control and token lifecycle -----------------------------------------------
post admin accounts.php action=create username=bob max_streams=2 max_access_points=3 >/dev/null
INV=$(grep -oE 'accept_invite\.php\?token=[0-9a-f]{64}' "$WORK/last.html" | head -1)
curl -s -c "$(jar bob)" -b "$(jar bob)" -o /dev/null "$A/$INV"
t=$(csrf bob accept_invite.php); curl -s -c "$(jar bob)" -b "$(jar bob)" -o /dev/null --data-urlencode "csrf=$t" --data-urlencode password=bob-password-123 --data-urlencode password_confirm=bob-password-123 "$A/accept_invite.php"
login bob bob-password-123 >/dev/null
check "non-admin gets 403 on nodes.php" 403 "$(get bob nodes.php)"
post bob stream_form.php name=bobs source_type=hls source_url=https://1.1.1.1/b.m3u8 replacement_reason=unauthorized_redistribution "node_id=$NODE_ID" >/dev/null
check "non-admin cannot assign a node (forged POST)" "" "$(q "SELECT IFNULL(node_id,'') FROM streams WHERE name='bobs'")"

post admin nodes.php action=reissue "node_id=$NODE_ID" >/dev/null
NEW=$(grep -oE 'svn_[0-9]+_[0-9a-f]{64}' "$WORK/last.html" | head -1)
check "old token rejected after reissue" 401 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$C/_sv/node/config")"
check "new token works" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $NEW" "$C/_sv/node/config")"
post admin nodes.php action=toggle "node_id=$NODE_ID" >/dev/null
check "disabled node rejected" 401 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $NEW" "$C/_sv/node/config")"
before=$(grep -c "node $NODE_ID returned" "$WORK/ctl.log")
curl -s -o /dev/null "$C/relayed.m3u8"; sleep 1
check "disabled node is not used for viewers" "$before" "$(grep -c "node $NODE_ID returned" "$WORK/ctl.log")"
post admin nodes.php action=delete "node_id=$NODE_ID" >/dev/null
check "deleting a node returns its streams to this server" "" "$(q "SELECT IFNULL(node_id,'') FROM streams WHERE id=$SID")"

if [ "$FAIL" -eq 0 ]; then echo "ALL NODES E2E CHECKS PASSED"; else echo "--- ctl.log"; tail -15 "$WORK/ctl.log"; echo "--- node.log"; tail -15 "$WORK/node.log"; echo "SOME NODES CHECKS FAILED"; exit 1; fi
