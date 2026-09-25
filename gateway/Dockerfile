# Multi-stage build: compiles a static Go binary, then ships it in a tiny
# runtime image. No CGO (modernc.org/sqlite is pure Go), so this cross-builds
# and runs on a minimal base without needing libc/sqlite3 shared libs -- a
# meaningful win on a host this memory-constrained (see ARCHITECTURE.md).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/streamvault-gateway ./cmd/gateway
RUN CGO_ENABLED=0 go build -o /out/streamvault-leakchecker ./cmd/leakchecker

FROM alpine:3.20
# ffmpeg is a hard runtime dependency as of Phase 4 (MPEG-TS -> HLS remux,
# gateway/internal/remux): the gateway shells out to it. Without this the
# image builds and starts fine but silently fails only when a stream turns
# out to be MPEG-TS -- caught by rebuilding and smoke-testing this image
# specifically, not just running `go build` locally.
RUN apk add --no-cache ffmpeg
COPY --from=build /out/streamvault-gateway /usr/local/bin/streamvault-gateway
COPY --from=build /out/streamvault-leakchecker /usr/local/bin/streamvault-leakchecker
# UID 33 matches www-data in the project's existing php-fpm image (Dockerfile.php,
# based on the official Debian php:8.2-fpm), which also reads/writes the shared
# SQLite file under ./streamvault/data on the host. Running as the same UID here
# means one `chown -R 33:33 streamvault/data` on the host satisfies both
# containers, instead of juggling ACLs across mismatched users -- see
# DEPLOYMENT.md and the project memory about a prior SQLite/WAL permissions
# incident (euroklic) caused by exactly this kind of mismatch.
USER 33:33
ENV STREAMVAULT_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/streamvault-gateway"]
