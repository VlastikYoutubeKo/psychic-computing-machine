<?php
declare(strict_types=1);

// Same env var names as the Go gateway (see gateway/cmd/gateway/main.go) so
// both processes point at one database and one key file without needing
// separate configuration.
define('SV_ADMIN_ROOT', dirname(__DIR__));
define('SV_ROOT', dirname(SV_ADMIN_ROOT));
define('SV_DB_PATH', getenv('STREAMVAULT_DB') ?: SV_ROOT . '/data/streamvault.sqlite');
define('SV_KEY_FILE', getenv('STREAMVAULT_KEY_FILE') ?: SV_ROOT . '/data/secret.key');
define('SV_MIGRATIONS_DIR', SV_ROOT . '/migrations');

// Reserved path segment used internally by the gateway to mark proxied
// resource URLs (".../<public_path>/<token>/r/<blob>"). No public_path may
// contain a segment equal to this, or it could collide with that routing
// marker. Keep this in sync with gateway/internal/gatewayhttp/handler.go.
define('SV_RESERVED_SEGMENT', 'r');

session_name('streamvault_admin');
if (session_status() === PHP_SESSION_NONE) {
    // Behind Caddy, TLS is terminated before php-fpm ever sees the request,
    // so $_SERVER['HTTPS'] alone won't reflect it -- trust the standard
    // X-Forwarded-Proto header Caddy sets on proxied requests too. Falls
    // back to plain HTTP (secure=false) for local dev servers (php -S),
    // which refuse to send a Secure cookie over HTTP at all.
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => $isHttps]);
    session_start();
}
