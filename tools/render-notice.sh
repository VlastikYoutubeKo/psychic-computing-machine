#!/bin/sh
# Renders gateway/internal/gatewayhttp/notice.html -> notice.png (2400x800,
# i.e. 1200x400 at 2x) in a throwaway container. Render-time only; the
# gateway just embeds the PNG. zenika/alpine-chrome works on this host,
# chromedp/headless-shell:latest hangs.
set -eu
DIR=$(cd "$(dirname "$0")/../gateway/internal/gatewayhttp" && pwd)
docker run --rm -u 0 -v "$DIR:/work" --entrypoint chromium-browser zenika/alpine-chrome:latest \
  --headless --no-sandbox --disable-gpu --disable-dev-shm-usage --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1200,400 --default-background-color=00000000 \
  --screenshot=/work/notice.png file:///work/notice.html
# Palettize (~840 KB -> ~250 KB, visually identical, keeps transparent corners).
docker run --rm -u 0 -v "$DIR:/work" --entrypoint ffmpeg caddy-setup-streamvault-gateway -loglevel error -y \
  -i /work/notice.png -vf "split[a][b];[a]palettegen=max_colors=192:reserve_transparent=1:stats_mode=full[p];[b][p]paletteuse=dither=sierra2_4a:alpha_threshold=128" /work/notice.q.png
mv "$DIR/notice.q.png" "$DIR/notice.png"
echo "wrote $DIR/notice.png"
