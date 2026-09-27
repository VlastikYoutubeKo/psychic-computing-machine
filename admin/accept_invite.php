<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
$db = sv_db();
$error = '';
$token = (string) ($_GET['token'] ?? '');
if ($token !== '') {
    unset($_SESSION['invite_token']);
    $retry = sv_login_retry_after('invite');
    if ($retry > 0) { http_response_code(429); exit('Too many attempts. Try again later.'); }
    $valid = preg_match('/^[0-9a-f]{64}$/D', $token);
    $stmt = $db->prepare("SELECT id FROM operators WHERE role='user' AND status='invited' AND invite_token_hash=? AND invite_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')");
    $stmt->execute([$valid ? hash('sha256', $token) : '']);
    if ($stmt->fetchColumn()) {
        $_SESSION['invite_token'] = $token;
        sv_redirect('accept_invite.php'); // Remove the bearer token from the address bar.
    }
    usleep(300_000);
    $db->prepare('INSERT INTO login_attempts(ip,username) VALUES(?,?)')->execute([sv_client_ip(), 'invite']);
    $error = 'Invitation invalid or expired.';
}
$sessionToken = (string) ($_SESSION['invite_token'] ?? '');
$hash = preg_match('/^[0-9a-f]{64}$/D', $sessionToken) ? hash('sha256', $sessionToken) : '';
$stmt = $db->prepare("SELECT id,username FROM operators WHERE role='user' AND status='invited' AND invite_token_hash=? AND invite_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')");
$stmt->execute([$hash]);
$invite = $stmt->fetch();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $retry = sv_login_retry_after('invite');
    if ($retry > 0) { http_response_code(429); $error = 'Too many attempts. Try again later.'; }
    elseif (!$invite) $error = 'Invitation invalid or expired.';
    else {
        $password = (string) ($_POST['password'] ?? '');
        if (strlen($password) < 12 || strlen($password) > 1024 || $password !== (string) ($_POST['password_confirm'] ?? '')) {
            $error = 'Enter matching passwords of at least 12 characters.';
        } else {
            $updated = $db->prepare("UPDATE operators SET password_hash=?,status='active',invite_token_hash=NULL,invite_expires_at=NULL WHERE id=? AND status='invited' AND invite_token_hash=? AND invite_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')");
            $updated->execute([password_hash($password, PASSWORD_DEFAULT), $invite['id'], $hash]);
            unset($_SESSION['invite_token']);
            if ($updated->rowCount() !== 1) $error = 'Invitation invalid or expired.';
            else { sv_audit('account_invite_accepted', 'operator:' . $invite['id']); sv_flash('ok', 'Password set. Sign in now.'); sv_redirect('login.php'); }
        }
    }
}
if (!$invite) http_response_code(404);
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Accept invitation · StreamVault</title><link rel="stylesheet" href="assets/style.css"></head><body class="sv-login-body"><div class="sv-panel sv-login-card"><div class="sv-brand"><span class="dot"></span> StreamVault</div><h1>Accept invitation</h1>
<?php if ($error): ?><div class="sv-flash err"><?= h($error) ?></div><?php endif; ?>
<?php if ($invite): ?><p>Set a password for <strong><?= h($invite['username']) ?></strong>. This invitation can be used once.</p><form method="post" action="accept_invite.php"><?= sv_csrf_field() ?><label for="invite-password">Password (at least 12 characters)</label><input type="password" id="invite-password" name="password" autocomplete="new-password" minlength="12" required><label for="invite-confirm">Confirm password</label><input type="password" id="invite-confirm" name="password_confirm" autocomplete="new-password" minlength="12" required><button class="btn-primary" type="submit">Set password</button></form>
<?php else: ?><p>This invitation is invalid or has expired. Ask an administrator for a new link.</p><?php endif; ?>
</div></body></html>
