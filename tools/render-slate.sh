#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d);cid=''
cleanup(){ [ -z "$cid" ] || docker rm -f "$cid" >/dev/null 2>&1 || :; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM
# zenika/alpine-chrome works here; chromedp/headless-shell:latest hangs.
cid=$(docker run -d --rm --network bridge -p 127.0.0.1:9229:9222 -v "$PWD:/work:ro" --entrypoint chromium-browser zenika/alpine-chrome:latest --headless --no-sandbox --disable-gpu --disable-dev-shm-usage --remote-allow-origins='*' --remote-debugging-address=0.0.0.0 --remote-debugging-port=9222 about:blank)
for i in $(seq 1 60); do if curl -fsS http://127.0.0.1:9229/json >/dev/null 2>&1; then break; fi; sleep 1; done
for variant in unavailable temporarily-unavailable; do
 mkdir "$tmp/$variant"
 node tools/render-slate.js 9229 "$variant" "$tmp/$variant"
 ffmpeg -hide_banner -loglevel error -y -framerate 10 -i "$tmp/$variant/frame%04d.png" -vf "scale=1920:1080:flags=lanczos" -c:v libx264 -preset slow -crf 29 -pix_fmt yuv420p -r 10 -g 20 -keyint_min 20 -sc_threshold 0 -movflags +faststart "gateway/assets/slate/$variant.mp4"
done
