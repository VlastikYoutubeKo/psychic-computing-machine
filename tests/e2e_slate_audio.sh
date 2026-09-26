#!/usr/bin/env bash
# Isolated HTTP/PHP/SQLite exercise of slate audio settings and upload checks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; PORT=18329; COOKIES="$WORK/cookies"
export STREAMVAULT_DB="$WORK/streamvault.sqlite" STREAMVAULT_KEY_FILE="$WORK/secret.key"
cleanup(){ kill "${ADMIN_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
printf '%s\n' 'supersecretpassword123' | php "$ROOT/admin/cli/create_operator.php" admin >/dev/null 2>&1
php -S "127.0.0.1:$PORT" -t "$ROOT/admin" >"$WORK/php.log" 2>&1 & ADMIN_PID=$!
sleep 1
csrf(){ curl -fsS -c "$COOKIES" -b "$COOKIES" "http://127.0.0.1:$PORT/$1" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)"/\1/'; }
TOKEN="$(csrf login.php)"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null --data-urlencode "csrf=$TOKEN" --data-urlencode username=admin --data-urlencode password=supersecretpassword123 "http://127.0.0.1:$PORT/login.php"
TOKEN="$(csrf settings.php)"
ffmpeg -hide_banner -loglevel error -f lavfi -i 'sine=frequency=330:duration=1' -c:a libmp3lame "$WORK/music.mp3"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -F "csrf=$TOKEN" -F action=save_slate_audio -F slate_audio_volume=40 -F "slate_audio_file=@$WORK/music.mp3" "http://127.0.0.1:$PORT/settings.php"
NAME="$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_file'")"
test -n "$NAME"; test -f "$WORK/slate-audio/$NAME"; test "$(stat -c %a "$WORK/slate-audio/$NAME")" = 640
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_volume'")" = 40
# .opus (Opus in Ogg) must be accepted too, then switch back to the mp3.
ffmpeg -hide_banner -loglevel error -f lavfi -i 'sine=frequency=440:duration=1' -c:a libopus "$WORK/music.opus"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -F "csrf=$TOKEN" -F action=save_slate_audio -F slate_audio_volume=40 -F "slate_audio_file=@$WORK/music.opus" "http://127.0.0.1:$PORT/settings.php"
OPUS="$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_file'")"
case "$OPUS" in *.opus) ;; *) echo "FAIL: .opus upload rejected ($OPUS)"; exit 1;; esac
test ! -e "$WORK/slate-audio/$NAME"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -F "csrf=$TOKEN" -F action=save_slate_audio -F slate_audio_volume=40 -F "slate_audio_file=@$WORK/music.mp3" "http://127.0.0.1:$PORT/settings.php"
NAME="$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_file'")"
printf 'not audio' > "$WORK/bad.mp3"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null -F "csrf=$TOKEN" -F action=save_slate_audio -F slate_audio_volume=40 -F "slate_audio_file=@$WORK/bad.mp3" "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_file'")" = "$NAME"
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null --data-urlencode "csrf=$TOKEN" --data-urlencode action=save_slate_audio --data-urlencode slate_audio_volume=55 --data-urlencode slate_audio_url=file:///etc/passwd "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM settings WHERE key='slate_audio_url'")" = 0
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null --data-urlencode "csrf=$TOKEN" --data-urlencode action=save_slate_audio --data-urlencode slate_audio_volume=55 --data-urlencode slate_audio_url=https://example.org/radio.mp3 "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT value FROM settings WHERE key='slate_audio_url'")" = https://example.org/radio.mp3
test ! -e "$WORK/slate-audio/$NAME"
BAD="$(curl -sS -c "$COOKIES" -b "$COOKIES" -o /dev/null -w '%{http_code}' --data-urlencode csrf=bad --data-urlencode action=disable_slate_audio "http://127.0.0.1:$PORT/settings.php")"
test "$BAD" = 400
curl -fsS -c "$COOKIES" -b "$COOKIES" -o /dev/null --data-urlencode "csrf=$TOKEN" --data-urlencode action=disable_slate_audio "http://127.0.0.1:$PORT/settings.php"
test "$(sqlite3 "$STREAMVAULT_DB" "SELECT COUNT(*) FROM settings WHERE key LIKE 'slate_audio_%'")" = 0
echo 'ALL SLATE AUDIO ADMIN E2E CHECKS PASSED'
