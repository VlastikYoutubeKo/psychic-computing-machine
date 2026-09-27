<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

function sv_current_operator(): ?array
{
    if (empty($_SESSION['operator_id'])) {
        return null;
    }
    $stmt = sv_db()->prepare('SELECT id, username FROM operators WHERE id = ?');
    $stmt->execute([$_SESSION['operator_id']]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function sv_require_login(): array
{
    $op = sv_current_operator();
    if ($op === null) {
        sv_redirect('login.php');
    }
    return $op;
}

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips/).
// CF-Connecting-IP is only trusted when the TCP peer is one of these: the
// origin is also reachable directly, where anyone can set that header.
const SV_CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32',
];
const SV_LOGIN_WINDOW = 900;          // seconds
const SV_LOGIN_MAX_PER_IP = 5;
const SV_LOGIN_MAX_PER_USER = 30;     // backstop against distributed guessing

function sv_ip_in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    $ipBin = @inet_pton($ip);
    $netBin = @inet_pton($net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }
    $bits = (int) $bits;
    $bytes = intdiv($bits, 8);
    if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
}

function sv_client_ip(): string
{
    $peer = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $cf = (string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '');
    if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) {
        foreach (SV_CLOUDFLARE_RANGES as $range) {
            if (sv_ip_in_cidr($peer, $range)) {
                return $cf;
            }
        }
    }
    return $peer;
}

/** Seconds until another login attempt is allowed; 0 if allowed now. */
function sv_login_retry_after(string $username): int
{
    $db = sv_db();
    $since = gmdate('Y-m-d\TH:i:s', time() - SV_LOGIN_WINDOW) . '.000Z';
    $worst = 0;
    foreach ([['ip', sv_client_ip(), SV_LOGIN_MAX_PER_IP], ['username', strtolower($username), SV_LOGIN_MAX_PER_USER]] as [$col, $val, $max]) {
        $stmt = $db->prepare("SELECT created_at FROM login_attempts WHERE $col = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 1 OFFSET " . ($max - 1));
        $stmt->execute([$val, $since]);
        $nth = $stmt->fetchColumn();
        if ($nth !== false) {
            $worst = max($worst, strtotime((string) $nth) + SV_LOGIN_WINDOW - time());
        }
    }
    return max(0, $worst);
}

/**
 * A fixed-cost delay on every attempt plus per-IP / per-username failure
 * throttling (sv_login_retry_after, checked by login.php before this).
 */
function sv_login(string $username, string $password): bool
{
    usleep(300_000);
    $stmt = sv_db()->prepare('SELECT id, password_hash FROM operators WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    $ok = $row !== false && password_verify($password, $row['password_hash']);
    sv_audit($ok ? 'login_success' : 'login_failure', $username);
    $db = sv_db();
    if (!$ok) {
        $db->prepare('INSERT INTO login_attempts (ip, username) VALUES (?, ?)')->execute([sv_client_ip(), strtolower($username)]);
        $db->prepare('DELETE FROM login_attempts WHERE created_at < ?')->execute([gmdate('Y-m-d\TH:i:s', time() - 86400) . '.000Z']);
        return false;
    }
    $db->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([sv_client_ip()]);
    session_regenerate_id(true);
    $_SESSION['operator_id'] = $row['id'];
    sv_db()->prepare('UPDATE operators SET last_login_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE id = ?')
        ->execute([$row['id']]);
    return true;
}

function sv_logout(): void
{
    $_SESSION = [];
    session_destroy();
}

function sv_audit(string $action, ?string $target = null, array $details = []): void
{
    $actor = $_SESSION['operator_id'] ?? null;
    $actorLabel = $actor ? "operator:$actor" : 'anonymous';
    sv_db()->prepare('INSERT INTO audit_log (actor, action, target, details) VALUES (?, ?, ?, ?)')
        ->execute([$actorLabel, $action, $target, $details ? json_encode($details) : null]);
}
