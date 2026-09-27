<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_admin();
$db = sv_db();
$inviteUrl = null;
$error = '';

function sv_account_limits(): ?array
{
    $streams = filter_var($_POST['max_streams'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 1000]]);
    $points = filter_var($_POST['max_access_points'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 10000]]);
    if ($streams === false || $points === false || $streams === null || $points === null) return null;
    return [$streams, $points, isset($_POST['allow_remux']) ? 1 : 0, isset($_POST['allow_always_on']) ? 1 : 0];
}

function sv_issue_invite(PDO $db, int $id): string
{
    $raw = bin2hex(random_bytes(32));
    $db->prepare("UPDATE operators SET status='invited', invite_token_hash=?, invite_expires_at=? WHERE id=? AND role='user'")
        ->execute([hash('sha256', $raw), gmdate('Y-m-d\TH:i:s.000\Z', time() + 72 * 3600), $id]);
    sv_audit('account_invite_issued', "operator:$id");
    $origin = rtrim(getenv('STREAMVAULT_ADMIN_BASE_URL') ?: 'https://help.iptvlookup.com', '/');
    return $origin . '/accept_invite.php?token=' . $raw;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    $id = filter_var($_POST['account_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    try {
        if ($action === 'create') {
            $username = strtolower(trim((string) ($_POST['username'] ?? '')));
            $limits = sv_account_limits();
            if (!preg_match('/^[a-z0-9][a-z0-9_.-]{2,63}$/D', $username) || !$limits) {
                $error = 'Enter a valid username (3–64 characters) and limits.';
            } else {
                $placeholder = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
                $db->prepare("INSERT INTO operators(username,password_hash,role,status,max_streams,max_access_points,allow_remux,allow_always_on) VALUES(?,?,'user','invited',?,?,?,?)")
                    ->execute([$username, $placeholder, ...$limits]);
                $id = (int) $db->lastInsertId();
                sv_audit('account_created', "operator:$id", ['username' => $username, 'limits' => $limits]);
                $inviteUrl = sv_issue_invite($db, $id);
            }
        } elseif ($id === false || $id === null) {
            $error = 'Account not found.';
        } else {
            $stmt = $db->prepare('SELECT id, role, status FROM operators WHERE id=?');
            $stmt->execute([$id]);
            $target = $stmt->fetch();
            if (!$target) {
                $error = 'Account not found.';
            } elseif ($action === 'invite') {
                $inviteUrl = $target['role'] === 'user' ? sv_issue_invite($db, $id) : null;
                if ($inviteUrl === null) $error = 'Admin accounts use the CLI bootstrap.';
            } elseif ($action === 'limits') {
                $limits = sv_account_limits();
                if ($target['role'] !== 'user' || !$limits) $error = 'Invalid account or limits.';
                else {
                    $db->prepare('UPDATE operators SET max_streams=?,max_access_points=?,allow_remux=?,allow_always_on=? WHERE id=? AND role=\'user\'')->execute([...$limits, $id]);
                    sv_audit('account_limits_changed', "operator:$id", ['limits' => $limits]);
                    sv_flash('ok', 'Limits saved.');
                    sv_redirect('accounts.php');
                }
            } elseif ($action === 'status') {
                $db->beginTransaction();
                $stmt = $db->prepare('SELECT role,status,invite_token_hash,invite_expires_at FROM operators WHERE id=?');
                $stmt->execute([$id]);
                $target = $stmt->fetch();
                if (!$target) throw new RuntimeException('Account not found.');
                if ($target['status'] === 'disabled') {
                    $validInvite = $target['invite_token_hash'] && $target['invite_expires_at'] > gmdate('Y-m-d\TH:i:s.000\Z');
                    $next = $validInvite ? 'invited' : 'active';
                } else {
                    if ($target['role'] === 'admin' && (int) $db->query("SELECT COUNT(*) FROM operators WHERE role='admin' AND status='active'")->fetchColumn() <= 1) {
                        throw new RuntimeException('The last active admin cannot be disabled.');
                    }
                    $next = 'disabled';
                }
                $db->prepare('UPDATE operators SET status=? WHERE id=?')->execute([$next, $id]);
                $db->commit();
                sv_audit('account_status_changed', "operator:$id", ['status' => $next]);
                sv_flash('ok', "Account set to $next.");
                sv_redirect('accounts.php');
            } else $error = 'Unknown account action.';
        }
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        $error = str_contains($e->getMessage(), 'last active admin') ? 'The last active admin cannot be disabled.' : 'Account action failed. Username may already exist.';
    }
}

$accounts = $db->query("SELECT o.id,o.username,o.role,o.status,o.max_streams,o.max_access_points,o.allow_remux,o.allow_always_on,o.invite_expires_at,
 (SELECT COUNT(*) FROM streams s WHERE s.owner_id=o.id) AS streams_used,
 (SELECT COUNT(*) FROM access_points ap JOIN streams s ON s.id=ap.stream_id WHERE s.owner_id=o.id) AS points_used
 FROM operators o ORDER BY o.role,o.username COLLATE NOCASE")->fetchAll();
$pageTitle = 'Accounts'; $activeNav = 'accounts';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Accounts</h1><p class="sv-help">Create invitations and set resource limits. New accounts cannot sign in until they choose a password.</p></div></div>
<?php if ($error): ?><div class="sv-flash err"><?= h($error) ?></div><?php endif; ?>
<?php if ($inviteUrl): ?><div class="sv-flash ok"><strong>Copy this invitation now; it will not be shown again.</strong><div class="sv-url-box"><span class="mono"><?= h($inviteUrl) ?></span><button type="button" data-copy="<?= h($inviteUrl) ?>">Copy</button></div><p>Expires in 72 hours and works once.</p></div><?php endif; ?>
<div class="sv-panel"><h2>Create account</h2><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="create"><label>Username</label><input name="username" maxlength="64" required><label>Max streams</label><input type="number" name="max_streams" min="0" max="1000" value="3" required><label>Max access points (total)</label><input type="number" name="max_access_points" min="0" max="10000" value="10" required><label><input type="checkbox" name="allow_remux" value="1"> Allow MPEG-TS remux (shared server-wide slots)</label><label><input type="checkbox" name="allow_always_on" value="1"> Allow always-on (24/7) relays (needs remux; each holds a slot permanently)</label><button class="btn-primary" type="submit">Create and issue invite</button></form></div>
<div class="sv-panel"><h2>Accounts and usage</h2><table><tr><th>Account</th><th>Status</th><th>Streams</th><th>Access points</th><th>Remux</th><th>Actions</th></tr>
<?php foreach ($accounts as $a): ?><tr><td><?= h($a['username']) ?> <span class="badge"><?= h($a['role']) ?></span></td><td><?= h($a['status']) ?></td><td><?= (int)$a['streams_used'] ?> / <?= $a['role']==='admin' ? '∞' : (int)$a['max_streams'] ?></td><td><?= (int)$a['points_used'] ?> / <?= $a['role']==='admin' ? '∞' : (int)$a['max_access_points'] ?></td><td><?= $a['allow_remux'] ? 'yes' : 'no' ?><?= $a['allow_always_on'] ? ' · 24/7' : '' ?></td><td>
<?php if ($a['role']==='user'): ?><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="limits"><input type="hidden" name="account_id" value="<?= (int)$a['id'] ?>"><input type="number" name="max_streams" min="0" max="1000" value="<?= (int)$a['max_streams'] ?>" aria-label="Max streams for <?= h($a['username']) ?>"><input type="number" name="max_access_points" min="0" max="10000" value="<?= (int)$a['max_access_points'] ?>" aria-label="Max access points for <?= h($a['username']) ?>"><label><input type="checkbox" name="allow_remux" value="1" <?= $a['allow_remux'] ? 'checked' : '' ?>> Remux</label><label><input type="checkbox" name="allow_always_on" value="1" <?= $a['allow_always_on'] ? 'checked' : '' ?>> 24/7</label><button type="submit">Save limits</button></form><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="invite"><input type="hidden" name="account_id" value="<?= (int)$a['id'] ?>"><button type="submit">Re-issue invite</button></form><?php endif; ?>
<form method="post" data-confirm="Change this account's access immediately?"><?= sv_csrf_field() ?><input type="hidden" name="action" value="status"><input type="hidden" name="account_id" value="<?= (int)$a['id'] ?>"><button type="submit" class="<?= $a['status']==='disabled' ? '' : 'btn-danger' ?>"><?= $a['status']==='disabled' ? 'Enable' : 'Disable' ?></button></form>
</td></tr><?php endforeach; ?></table></div>
<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
