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

/**
 * A fixed-cost delay on every attempt (not just failures) blunts naive
 * password-guessing scripts. This is a floor, not a full defense -- see
 * SECURITY.md for the recommendation to also rate-limit /login.php at the
 * Caddy layer in production.
 */
function sv_login(string $username, string $password): bool
{
    usleep(300_000);
    $stmt = sv_db()->prepare('SELECT id, password_hash FROM operators WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    $ok = $row !== false && password_verify($password, $row['password_hash']);
    sv_audit($ok ? 'login_success' : 'login_failure', $username);
    if (!$ok) {
        return false;
    }
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
