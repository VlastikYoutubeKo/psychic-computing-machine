#!/usr/bin/env bash
# Multi-user isolation (IDOR), invites, limits, admin-only pages, disabling.
# Two users (alice, bob) + admin against a scratch DB and php -S.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; PORT=18352; FAIL=0
export STREAMVAULT_DB="$WORK/sv.sqlite" STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup(){ kill "${PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
B="http://127.0.0.1:$PORT"
ok(){ echo "PASS: $1"; }
bad(){ echo "FAIL: $1"; FAIL=1; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $2, got $3)"; fi; }
q(){ sqlite3 "$STREAMVAULT_DB" "$1"; }

printf '%s\n' 'admin-password-123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
php -S "127.0.0.1:$PORT" -t "$ROOT/admin" >"$WORK/php.log" 2>&1 & PID=$!
sleep 1

jar(){ echo "$WORK/$1.jar"; }
csrf(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" "$B/$2" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
post(){ # post USER PAGE field=value...  -> prints HTTP code
  local u=$1 page=$2; shift 2
  # CSRF token from the dashboard (session-wide), NOT from $page: a 404 page
  # has no token, and a CSRF rejection would make IDOR checks pass vacuously.
  local t; t=$(csrf "$u" index.php)
  [ -n "$t" ] || { echo "no CSRF token for $u" >&2; }
  local args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -c "$(jar "$u")" -b "$(jar "$u")" -o "$WORK/last.html" -w '%{http_code}' --data-urlencode "csrf=$t" "${args[@]}" "$B/$page"
}
get(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o "$WORK/last.html" -w '%{http_code}' "$B/$2"; }
login(){ curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$(csrf "$1" login.php)" --data-urlencode "username=$1" --data-urlencode "password=$2" "$B/login.php"; }

check "admin login" 302 "$(login admin admin-password-123)"

# --- invites ------------------------------------------------------------
invite_for(){ # create user via admin, echo invite URL
  post admin accounts.php action=create "username=$1" max_streams=2 max_access_points=3 allow_remux=0 >/dev/null
  grep -oE 'accept_invite\.php\?token=[0-9a-f]{64}' "$WORK/last.html" | head -1
}
accept(){ # accept USER INVITEPATH PASSWORD -> HTTP code of the password POST
  curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o /dev/null "$B/$2"
  local t; t=$(csrf "$1" accept_invite.php)
  curl -s -c "$(jar "$1")" -b "$(jar "$1")" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" --data-urlencode "password=$3" --data-urlencode "password_confirm=$3" "$B/accept_invite.php"
}
A_INV=$(invite_for alice); B_INV=$(invite_for bob)
[ -n "$A_INV" ] && [ -n "$B_INV" ] && ok "invite links shown once to admin" || bad "invite link missing"
check "alice accepts invite" 302 "$(accept alice "$A_INV" alice-password-1234)"
check "bob accepts invite" 302 "$(accept bob "$B_INV" bob-password-12345)"
check "alice status active" active "$(q "SELECT status FROM operators WHERE username='alice'")"
rm -f "$(jar mallory)"
curl -s -c "$(jar mallory)" -b "$(jar mallory)" -o /dev/null "$B/$A_INV"
check "invite is single-use" 404 "$(get mallory accept_invite.php)"
C_INV=$(invite_for carol); q "UPDATE operators SET invite_expires_at='2000-01-01T00:00:00.000Z' WHERE username='carol'"
curl -s -c "$(jar carol)" -b "$(jar carol)" -o /dev/null "$B/$C_INV"
check "expired invite rejected" 404 "$(get carol accept_invite.php)"

check "alice login" 302 "$(login alice alice-password-1234)"
check "bob login" 302 "$(login bob bob-password-12345)"

# --- each user creates a stream, access point and token -----------------
mkstream(){ post "$1" stream_form.php "name=$2" source_type=hls "source_url=https://src.example/$2.m3u8" replacement_reason=unauthorized_redistribution >/dev/null; q "SELECT id FROM streams WHERE name='$2'"; }
A_S=$(mkstream alice alice-stream); B_S=$(mkstream bob bob-stream)
[ -n "$A_S" ] && [ -n "$B_S" ] && ok "users created streams" || bad "stream creation"
check "alice owns her stream" "$(q "SELECT id FROM operators WHERE username='alice'")" "$(q "SELECT owner_id FROM streams WHERE id=$A_S")"
post alice "stream_view.php?id=$A_S" action=add_access_point public_path=alice-priv visibility=private >/dev/null
A_AP=$(q "SELECT id FROM access_points WHERE public_path='alice-priv'")
post alice "stream_view.php?id=$A_S" action=add_token "access_point_id=$A_AP" label=t1 expires_days= >/dev/null
A_TOK=$(q "SELECT id FROM access_tokens WHERE access_point_id=$A_AP")
post bob "stream_view.php?id=$B_S" action=add_access_point public_path=bob-pub visibility=public >/dev/null
[ -n "$A_AP" ] && [ -n "$A_TOK" ] && ok "alice has access point + token" || bad "alice ap/token setup"

# --- IDOR: bob against alice's resources --------------------------------
for page in "stream_view.php?id=$A_S" "stream_form.php?id=$A_S"; do
  code=$(get bob "$page")
  if [ "$code" = 200 ] && grep -q "alice-stream\|alice-priv" "$WORK/last.html"; then bad "bob can read $page"; else ok "bob cannot read $page ($code)"; fi
done
get bob streams.php >/dev/null; grep -q "alice-stream" "$WORK/last.html" && bad "streams list leaks alice's stream" || ok "streams list scoped"
get bob index.php >/dev/null; grep -q "alice-stream" "$WORK/last.html" && bad "dashboard leaks alice's stream" || ok "dashboard scoped"

before=$(q "SELECT status||name FROM streams WHERE id=$A_S")
post bob "stream_view.php?id=$A_S" action=toggle_status >/dev/null
post bob "stream_form.php?id=$A_S" name=pwned source_type=hls source_url=https://evil.example/x.m3u8 replacement_reason=unauthorized_redistribution >/dev/null
post bob "stream_view.php?id=$A_S" action=delete_stream >/dev/null
check "bob cannot toggle/edit/delete alice's stream" "$before" "$(q "SELECT status||name FROM streams WHERE id=$A_S")"
post bob "stream_view.php?id=$A_S" action=add_access_point public_path=bob-into-alice visibility=public >/dev/null
check "bob cannot add access point to alice's stream" 0 "$(q "SELECT COUNT(*) FROM access_points WHERE public_path='bob-into-alice'")"
post bob "stream_view.php?id=$A_S" action=add_token "access_point_id=$A_AP" label=evil expires_days= >/dev/null
post bob "stream_view.php?id=$B_S" action=add_token "access_point_id=$A_AP" label=evil2 expires_days= >/dev/null
check "bob cannot mint tokens on alice's access point" 1 "$(q "SELECT COUNT(*) FROM access_tokens WHERE access_point_id=$A_AP")"
post bob "stream_view.php?id=$A_S" action=revoke_token "token_id=$A_TOK" reason=x >/dev/null
post bob "stream_view.php?id=$B_S" action=revoke_token "token_id=$A_TOK" reason=x >/dev/null
check "bob cannot revoke alice's token (own or foreign stream id)" "" "$(q "SELECT IFNULL(revoked_at,'') FROM access_tokens WHERE id=$A_TOK")"
post bob "stream_view.php?id=$A_S" action=revoke_access_point "access_point_id=$A_AP" >/dev/null
post bob "stream_view.php?id=$B_S" action=revoke_access_point "access_point_id=$A_AP" >/dev/null
check "bob cannot revoke alice's access point" active "$(q "SELECT status FROM access_points WHERE id=$A_AP")"

# Sanity: the same POST helper DOES work on bob's own stream (so the denials
# above are ownership checks, not CSRF failures).
post bob "stream_view.php?id=$B_S" action=toggle_status >/dev/null
check "bob can toggle his own stream (helper is live)" disabled "$(q "SELECT status FROM streams WHERE id=$B_S")"
post bob "stream_view.php?id=$B_S" action=toggle_status >/dev/null

# incidents
post bob incidents.php action=create "stream_id=$A_S" notes=evil >/dev/null
check "bob cannot record incidents on alice's stream" 0 "$(q "SELECT COUNT(*) FROM incidents WHERE stream_id=$A_S")"
post alice incidents.php action=create "stream_id=$A_S" notes=alice-incident >/dev/null
A_INC=$(q "SELECT id FROM incidents WHERE stream_id=$A_S")
[ -n "$A_INC" ] && ok "alice records incident" || bad "alice incident"
get bob incidents.php >/dev/null; grep -q "alice-incident" "$WORK/last.html" && bad "incident list leaks alice's incident" || ok "incident list scoped"
post bob incidents.php action=dismiss "incident_id=$A_INC" >/dev/null
post bob incidents.php action=confirm "incident_id=$A_INC" >/dev/null
check "bob cannot change alice's incident" new "$(q "SELECT status FROM incidents WHERE id=$A_INC")"
check "bob cannot post GitHub replies (admin-only)" 403 "$(post bob incidents.php action=github_reply "incident_id=$A_INC")"

# --- admin-only pages -----------------------------------------------------
for page in accounts.php error_screen.php settings.php; do check "bob gets 403 on $page" 403 "$(get bob "$page")"; done
check "bob cannot create accounts" 403 "$(post bob accounts.php action=create username=eve max_streams=9 max_access_points=9)"
check "no account created by bob" 0 "$(q "SELECT COUNT(*) FROM operators WHERE username='eve'")"

# --- limits -----------------------------------------------------------------
mkstream alice alice-2 >/dev/null; mkstream alice alice-3 >/dev/null
check "stream limit (2) enforced" 2 "$(q "SELECT COUNT(*) FROM streams WHERE owner_id=(SELECT id FROM operators WHERE username='alice')")"
for p in a2 a3 a4; do post alice "stream_view.php?id=$A_S" action=add_access_point "public_path=alice-$p" visibility=public >/dev/null; done
check "access point limit (3) enforced" 3 "$(q "SELECT COUNT(*) FROM access_points ap JOIN streams s ON s.id=ap.stream_id WHERE s.owner_id=(SELECT id FROM operators WHERE username='alice')")"

# --- own leak sources are private -------------------------------------------
post bob my_account.php action=add_leak_source provider=github_repo identifier=bob/repo >/dev/null
BOB_SRC=$(q "SELECT id FROM leak_sources WHERE identifier='bob/repo'")
post alice my_account.php action=toggle_leak_source "source_id=$BOB_SRC" >/dev/null
check "alice cannot toggle bob's leak source" 1 "$(q "SELECT enabled FROM leak_sources WHERE id=$BOB_SRC")"

# --- admin view, disabling, last admin ----------------------------------------
get admin streams.php >/dev/null
grep -q "alice-stream" "$WORK/last.html" && grep -q "bob-stream" "$WORK/last.html" && ok "admin sees all streams" || bad "admin stream view"
BOB_ID=$(q "SELECT id FROM operators WHERE username='bob'")
post admin accounts.php action=status "account_id=$BOB_ID" >/dev/null
check "bob disabled" disabled "$(q "SELECT status FROM operators WHERE id=$BOB_ID")"
check "disabled bob's session is dropped" 302 "$(get bob index.php)"
check "disabled bob cannot log in" 200 "$(login bob bob-password-12345)"
ADMIN_ID=$(q "SELECT id FROM operators WHERE username='admin'")
post admin accounts.php action=status "account_id=$ADMIN_ID" >/dev/null
check "last active admin cannot be disabled" active "$(q "SELECT status FROM operators WHERE id=$ADMIN_ID")"

[ "$FAIL" -eq 0 ] && echo "ALL ACCOUNTS E2E CHECKS PASSED" || { echo "SOME ACCOUNTS CHECKS FAILED"; exit 1; }
