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
// The gateway handles /_sv/... before access-point lookup. Reserve only
// the first segment; nested "_sv" in a public path has no route conflict.
define('SV_RESERVED_ROOT_SEGMENT', '_sv');

// Every admin page includes this file: send baseline security headers here.
// Clickjacking: the admin has one-click destructive forms (revoke, reply on
// GitHub), so it must never render inside a frame.
if (PHP_SAPI !== 'cli' && !headers_sent()) {
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header_remove('X-Powered-By');
}

// Logged out after this long without any request (3 days).
const SV_SESSION_LIFETIME = 3 * 86400;

session_name('streamvault_admin');
ini_set('session.use_strict_mode', '1');
if (session_status() === PHP_SESSION_NONE) {
    // Behind Caddy, TLS is terminated before php-fpm ever sees the request,
    // so $_SERVER['HTTPS'] alone won't reflect it -- trust the standard
    // X-Forwarded-Proto header Caddy sets on proxied requests too. Falls
    // back to plain HTTP (secure=false) for local dev servers (php -S),
    // which refuse to send a Secure cookie over HTTP at all.
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    // Stay logged in for SV_SESSION_LIFETIME since the last request, across
    // browser restarts. Two things used to log people out within minutes:
    // the cookie was a browser-session cookie, and session files lived in
    // the shared /tmp, where any other PHP site's session GC deletes files
    // idle for its own (24 min default) lifetime. So: a persistent cookie,
    // and a private session directory next to the database.
    $sessionDir = dirname(SV_DB_PATH) . '/sessions';
    if (!is_dir($sessionDir)) {
        @mkdir($sessionDir, 0700, true);
    }
    if (is_dir($sessionDir) && is_writable($sessionDir)) {
        ini_set('session.save_path', $sessionDir);
    }
    ini_set('session.gc_maxlifetime', (string) SV_SESSION_LIFETIME);
    $sessionCookie = ['lifetime' => SV_SESSION_LIFETIME, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => $isHttps];
    session_set_cookie_params($sessionCookie);
    // PHP's default session cache limiter ("nocache") sends
    // Cache-Control: no-store on every response, including the login POST's
    // response. Chromium (and Brave) silently refuse to offer to save a
    // password when that response carries no-store -- the label/autocomplete
    // fixes alone don't help. But no max-age either: "private_no_expire" sent
    // max-age=10800, so browsers cached logged-out redirects (streams.php ->
    // login.php -> index.php) for 3h. "no-cache" = store but always revalidate.
    session_cache_limiter('');
    session_start();
    header('Cache-Control: private, no-cache, must-revalidate');

    // Idle timeout, enforced server-side (the cookie's own expiry is only a
    // hint to the browser), and a sliding cookie: re-issued at most hourly
    // so activity keeps extending it.
    if (!empty($_SESSION['operator_id'])) {
        $now = time();
        if ((int) ($_SESSION['last_seen'] ?? $now) < $now - SV_SESSION_LIFETIME) {
            $_SESSION = [];
            session_regenerate_id(true);
        } else {
            $_SESSION['last_seen'] = $now;
            if ((int) ($_SESSION['cookie_at'] ?? 0) < $now - 3600) {
                $_SESSION['cookie_at'] = $now;
                unset($sessionCookie['lifetime']);
                setcookie(session_name(), session_id(), ['expires' => $now + SV_SESSION_LIFETIME] + $sessionCookie);
            }
        }
    }
}
