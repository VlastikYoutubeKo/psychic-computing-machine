// Command gateway is the StreamVault stream gateway: the single always-on
// process that Caddy points at for every stream path. It never reloads and
// never needs Caddy config changes when streams are added, removed, or
// rotated -- all of that is data in SQLite, read on every request. See
// docs/ARCHITECTURE.md section "Caddy integration" for why this shape was
// chosen over generating Caddyfile snippets or driving the Admin API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"streamvault/gateway/internal/gatewayhttp"
	"streamvault/gateway/internal/secretbox"
	"streamvault/gateway/internal/store"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	dbPath := getenv("STREAMVAULT_DB", "../data/streamvault.sqlite")
	keyPath := getenv("STREAMVAULT_KEY_FILE", "../data/secret.key")
	listen := getenv("STREAMVAULT_LISTEN", "127.0.0.1:8090")

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("opening database %s: %v", dbPath, err)
	}
	defer st.Close()

	var key []byte
	if k, err := secretbox.LoadKey(keyPath); err != nil {
		log.Printf("warning: no secret key loaded from %s (%v) -- streams with source credentials will fail", keyPath, err)
	} else {
		key = k
	}

	h, err := gatewayhttp.New(st, key)
	if err != nil {
		log.Fatalf("creating gateway handler: %v", err)
	}
	defer h.Remux.Close()
	srv := &http.Server{
		Addr:              listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("streamvault-gateway listening on %s (db=%s)", listen, dbPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("gateway server error: %v", err)
	}
}
