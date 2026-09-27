<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
require_once __DIR__ . '/includes/leak_status.php';
$operator = sv_require_login();
$db = sv_db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    if ($action === 'change_password') {
        $old = (string) ($_POST['current_password'] ?? '');
        $new = (string) ($_POST['new_password'] ?? '');
        $again = (string) ($_POST['new_password_confirm'] ?? '');
        $stmt = $db->prepare('SELECT password_hash FROM operators WHERE id=?'); $stmt->execute([$operator['id']]);
        if (!password_verify($old, (string) $stmt->fetchColumn()) || strlen($new) < 12 || strlen($new) > 1024 || $new !== $again) sv_flash('err', 'Check your current password and enter matching new passwords of at least 12 characters.');
        else {
            $db->prepare('UPDATE operators SET password_hash=? WHERE id=?')->execute([password_hash($new, PASSWORD_DEFAULT), $operator['id']]);
            session_regenerate_id(true); sv_audit('operator_password_changed'); sv_flash('ok', 'Password changed.');
        }
    } elseif ($action === 'save_github_token') {
        $token = trim((string) ($_POST['github_token'] ?? ''));
        if ($token === '' || strlen($token) > 512) sv_flash('err', 'Enter a GitHub token up to 512 bytes.');
        else {
            $db->prepare('UPDATE operators SET github_token_enc=? WHERE id=?')->execute([sv_encrypt(sv_ensure_key_file(SV_KEY_FILE), $token), $operator['id']]);
            sv_audit('own_github_token_updated'); sv_flash('ok', 'Your GitHub token was saved encrypted and will not be shown again.');
        }
    } elseif ($action === 'clear_github_token') {
        $db->prepare('UPDATE operators SET github_token_enc=NULL WHERE id=?')->execute([$operator['id']]);
        sv_audit('own_github_token_cleared'); sv_flash('ok', 'Your GitHub token was removed.');
    } elseif ($action === 'request_leak_scan') {
        $stmt = $db->prepare('SELECT github_token_enc FROM operators WHERE id=?'); $stmt->execute([$operator['id']]);
        if (!$stmt->fetchColumn()) sv_flash('err', 'Add your GitHub token first.');
        else {
            $db->prepare("UPDATE operators SET leak_scan_requested_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?")->execute([$operator['id']]);
            sv_audit('own_leak_scan_requested'); sv_flash('ok', 'Your scan was queued for the checker timer.');
        }
    } elseif ($action === 'add_leak_source') {
        $provider = (string) ($_POST['provider'] ?? '');
        $identifier = strtolower(trim((string) ($_POST['identifier'] ?? '')));
        $valid = $provider === 'github_repo' ? (bool) preg_match('/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/D', $identifier) : ($provider === 'github_org' && (bool) preg_match('/^[a-z0-9-]+$/D', $identifier));
        if (!$valid || strlen($identifier) > 200 || str_contains($identifier, '..')) sv_flash('err', 'Enter a valid GitHub repository or organization.');
        else {
            try {
                $db->prepare('INSERT INTO leak_sources(provider,identifier,owner_id) VALUES(?,?,?)')->execute([$provider,$identifier,$operator['id']]);
                sv_audit('own_leak_source_created', 'leak_source:' . $db->lastInsertId()); sv_flash('ok', 'Watched source added.');
            } catch (PDOException $e) { sv_flash('err', 'Source unavailable or already on your list.'); }
        }
    } elseif (in_array($action, ['toggle_leak_source','delete_leak_source'], true)) {
        $id = filter_var($_POST['source_id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        if (!$id) sv_flash('err', 'Source not found.');
        else {
            $stmt = $db->prepare('SELECT 1 FROM leak_sources WHERE id=? AND owner_id=?'); $stmt->execute([$id,$operator['id']]);
            if (!$stmt->fetchColumn()) sv_flash('err', 'Source not found.');
            else {
                if ($action === 'toggle_leak_source') $db->prepare('UPDATE leak_sources SET enabled=1-enabled WHERE id=? AND owner_id=?')->execute([$id,$operator['id']]);
                else $db->prepare('DELETE FROM leak_sources WHERE id=? AND owner_id=?')->execute([$id,$operator['id']]);
                sv_audit('own_leak_source_' . ($action === 'toggle_leak_source' ? 'toggled' : 'deleted'), "leak_source:$id");
                sv_flash('ok', 'Source updated.');
            }
        }
    } else sv_flash('err', 'Unknown action.');
    sv_redirect('my_account.php');
}

$stmt = $db->prepare('SELECT github_token_enc FROM operators WHERE id=?'); $stmt->execute([$operator['id']]); $tokenSet = (bool) $stmt->fetchColumn();
$stmt = $db->prepare('SELECT id,provider,identifier,enabled,last_scanned_at FROM leak_sources WHERE owner_id=? ORDER BY provider,identifier'); $stmt->execute([$operator['id']]); $sources = $stmt->fetchAll();
$pageTitle = 'My account'; $activeNav = 'my_account'; require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>My account</h1><p class="sv-help">Password, personal GitHub scanning and resource limits.</p></div></div>
<div class="sv-grid"><div class="sv-stat"><div class="num"><?= $operator['role']==='admin' ? '∞' : (int)$operator['max_streams'] ?></div><div class="label">Max streams</div></div><div class="sv-stat"><div class="num"><?= $operator['role']==='admin' ? '∞' : (int)$operator['max_access_points'] ?></div><div class="label">Max access points</div></div><div class="sv-stat"><div class="num"><?= $operator['allow_remux'] ? 'Yes' : 'No' ?></div><div class="label">MPEG-TS remux</div></div></div>
<div class="sv-panel"><h2>Change password</h2><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="change_password"><label>Current password</label><input type="password" name="current_password" autocomplete="current-password" required><label>New password</label><input type="password" name="new_password" autocomplete="new-password" minlength="12" required><label>Confirm new password</label><input type="password" name="new_password_confirm" autocomplete="new-password" minlength="12" required><button type="submit">Change password</button></form></div>
<div class="sv-panel"><h2>Your GitHub token</h2><p class="sv-help">The admin's global token already scans all active streams. Your optional token runs an additional scan of only your access points and sources. It is write-only and stored encrypted.</p><p>Status: <?= $tokenSet ? 'configured' : 'not configured' ?></p><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="save_github_token"><label>New token</label><input type="password" name="github_token" autocomplete="off" required><button type="submit">Save token</button></form><form method="post" data-confirm="Remove your GitHub token?"><?= sv_csrf_field() ?><input type="hidden" name="action" value="clear_github_token"><button type="submit" class="btn-danger">Remove token</button></form></div>
<?php sv_render_leak_status($db, $operator); ?>
<?php if ($operator['role'] === 'user'): ?><div class="sv-panel"><h2>Scan your streams</h2><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="request_leak_scan"><button type="submit" <?= $tokenSet ? '' : 'disabled' ?>>Scan now</button></form></div><?php endif; ?>
<div class="sv-panel"><h2>Your watched GitHub sources</h2><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="add_leak_source"><label>Type</label><select name="provider"><option value="github_repo">Repository</option><option value="github_org">Organization</option></select><label>Owner/repository or organization</label><input name="identifier" maxlength="200" required><button type="submit">Add source</button></form><table><tr><th>Source</th><th>Enabled</th><th>Last attempted</th><th>Actions</th></tr><?php foreach ($sources as $s): ?><tr><td><?= h($s['provider'] . ': ' . $s['identifier']) ?></td><td><?= $s['enabled'] ? 'yes' : 'no' ?></td><td><?= h($s['last_scanned_at'] ?: 'never') ?></td><td><form method="post"><?= sv_csrf_field() ?><input type="hidden" name="action" value="toggle_leak_source"><input type="hidden" name="source_id" value="<?= (int)$s['id'] ?>"><button type="submit">Toggle</button></form><form method="post" data-confirm="Delete this source?"><?= sv_csrf_field() ?><input type="hidden" name="action" value="delete_leak_source"><input type="hidden" name="source_id" value="<?= (int)$s['id'] ?>"><button type="submit">Delete</button></form></td></tr><?php endforeach; ?></table></div>
<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
