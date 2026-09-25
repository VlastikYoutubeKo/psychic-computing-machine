<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_login();
$db = sv_db();

$id = (int) ($_GET['id'] ?? 0);
$stmt = $db->prepare('SELECT * FROM streams WHERE id = ?');
$stmt->execute([$id]);
$stream = $stmt->fetch();
if (!$stream) {
    sv_flash('err', 'Stream not found.');
    sv_redirect('streams.php');
}

$revealToken = null; // ['raw' => ..., 'access_point_id' => ..., 'label' => ...] shown exactly once

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = $_POST['action'] ?? '';

    if ($action === 'toggle_status') {
        $newStatus = $stream['status'] === 'active' ? 'disabled' : 'active';
        $db->prepare('UPDATE streams SET status = ? WHERE id = ?')->execute([$newStatus, $id]);
        sv_audit('stream_status_changed', "stream:$id", ['status' => $newStatus]);
        sv_flash('ok', "Stream set to $newStatus.");
        sv_redirect("stream_view.php?id=$id");
    }

    if ($action === 'delete_stream') {
        $db->prepare('DELETE FROM streams WHERE id = ?')->execute([$id]);
        sv_audit('stream_deleted', "stream:$id");
        sv_flash('ok', 'Stream and all its access points/tokens deleted.');
        sv_redirect('streams.php');
    }

    if ($action === 'add_access_point') {
        $path = trim((string) ($_POST['public_path'] ?? ''), '/');
        $visibility = ($_POST['visibility'] ?? '') === 'private' ? 'private' : 'public';
        $err = sv_validate_public_path($path);
        if ($err) {
            sv_flash('err', $err);
        } else {
            try {
                $db->prepare('INSERT INTO access_points (stream_id, public_path, visibility) VALUES (?, ?, ?)')
                    ->execute([$id, $path, $visibility]);
                sv_audit('access_point_created', "stream:$id", ['public_path' => $path, 'visibility' => $visibility]);
                sv_flash('ok', "Access point \"$path\" created.");
            } catch (PDOException $e) {
                sv_flash('err', str_contains($e->getMessage(), 'UNIQUE')
                    ? "The path \"$path\" is already in use by another access point."
                    : 'Could not create access point: ' . $e->getMessage());
            }
        }
        sv_redirect("stream_view.php?id=$id");
    }

    if ($action === 'revoke_access_point') {
        $apId = (int) $_POST['access_point_id'];
        $db->prepare('UPDATE access_points SET status = "revoked" WHERE id = ? AND stream_id = ?')->execute([$apId, $id]);
        sv_audit('access_point_revoked', "access_point:$apId");
        sv_flash('ok', 'Access point revoked. Its URL now shows the revoked-stream page.');
        sv_redirect("stream_view.php?id=$id");
    }

    if ($action === 'add_token') {
        $apId = (int) $_POST['access_point_id'];
        $owns = $db->prepare('SELECT 1 FROM access_points WHERE id = ? AND stream_id = ?');
        $owns->execute([$apId, $id]);
        if (!$owns->fetchColumn()) {
            sv_flash('err', 'That access point does not belong to this stream.');
            sv_redirect("stream_view.php?id=$id");
        }
        $label = trim((string) ($_POST['label'] ?? ''));
        $expiresIn = trim((string) ($_POST['expires_days'] ?? ''));
        $expiresAt = null;
        if ($expiresIn !== '' && ctype_digit($expiresIn) && (int) $expiresIn > 0) {
            $expiresAt = gmdate('Y-m-d\TH:i:s.000\Z', time() + ((int) $expiresIn * 86400));
        }
        $raw = sv_generate_raw_token();
        $db->prepare('INSERT INTO access_tokens (access_point_id, token_hash, token_display, label, expires_at) VALUES (?,?,?,?,?)')
            ->execute([$apId, sv_hash_token($raw), sv_token_display($raw), $label, $expiresAt]);
        sv_audit('token_created', "access_point:$apId", ['label' => $label]);
        $revealToken = ['raw' => $raw, 'access_point_id' => $apId];
    }

    if ($action === 'revoke_token') {
        $tokenId = (int) $_POST['token_id'];
        $stmt = $db->prepare('UPDATE access_tokens SET revoked_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'), revoked_reason = ?
            WHERE id = ? AND access_point_id IN (SELECT id FROM access_points WHERE stream_id = ?)');
        $stmt->execute([$_POST['reason'] ?? 'manual', $tokenId, $id]);
        if ($stmt->rowCount() === 0) {
            sv_flash('err', 'That token does not belong to this stream.');
            sv_redirect("stream_view.php?id=$id");
        }
        sv_audit('token_revoked', "token:$tokenId");
        sv_flash('ok', 'Token revoked. It stops working immediately, including for segments already in flight to a player that hasn\'t buffered them yet.');
        sv_redirect("stream_view.php?id=$id");
    }
}

// Reload access points + tokens fresh (also picks up the just-added token/AP above).
$aps = $db->prepare('SELECT * FROM access_points WHERE stream_id = ? ORDER BY created_at');
$aps->execute([$id]);
$accessPoints = $aps->fetchAll();
foreach ($accessPoints as &$ap) {
    $tstmt = $db->prepare('SELECT * FROM access_tokens WHERE access_point_id = ? ORDER BY created_at DESC');
    $tstmt->execute([$ap['id']]);
    $ap['tokens'] = $tstmt->fetchAll();
}
unset($ap);

$baseUrlStmt = $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'");
$baseUrl = $baseUrlStmt->fetchColumn() ?: null;

$pageTitle = $stream['name'];
$activeNav = 'streams';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>
  <?= h($stream['name']) ?>
  <span class="badge <?= h($stream['status']) ?>"><?= h($stream['status']) ?></span>
  <a href="stream_form.php?id=<?= $id ?>" class="btn btn-sm" style="float:right;">Edit</a>
</h1>

<?php if (!$baseUrl): ?>
  <div class="sv-flash err">
    No public base URL configured yet -- <a href="settings.php">set one in Settings</a> so the URLs below are shown
    as full links instead of just paths. This does not affect how the gateway works, only how links are displayed here.
  </div>
<?php endif; ?>

<div class="sv-panel">
  <p><?= h($stream['description']) ?: '<span class="sv-help">No description.</span>' ?></p>
  <table>
    <tr><th>Source type</th><td class="mono"><?= h($stream['source_type']) ?></td></tr>
    <tr><th>Source URL</th><td class="mono"><?= h($stream['source_url']) ?></td></tr>
    <tr><th>Source credentials</th><td><?= $stream['source_username'] ? 'Set (' . h($stream['source_username']) . ' / ••••••••)' : 'None' ?></td></tr>
    <tr><th>Rotation mode</th><td class="mono"><?= h($stream['rotation_mode']) ?></td></tr>
  </table>
  <form method="post" style="margin-top:1rem;display:inline;">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="toggle_status">
    <button type="submit"><?= $stream['status'] === 'active' ? 'Disable stream' : 'Enable stream' ?></button>
  </form>
  <form method="post" style="margin-top:1rem;display:inline;" data-confirm="Delete this stream and ALL its access points and tokens? This cannot be undone.">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="delete_stream">
    <button type="submit" class="btn-danger">Delete stream</button>
  </form>
</div>

<h2>Access points</h2>

<?php foreach ($accessPoints as $ap): $fullPath = $ap['public_path']; ?>
  <div class="sv-panel">
    <div class="sv-topbar" style="margin-bottom:0.5rem;">
      <div>
        <span class="badge <?= h($ap['visibility']) ?>"><?= h($ap['visibility']) ?></span>
        <span class="badge <?= h($ap['status']) ?>"><?= h($ap['status']) ?></span>
        <code><?= h($fullPath) ?></code>
      </div>
      <?php if ($ap['status'] === 'active'): ?>
        <form method="post" data-confirm="Revoke this access point? Its URL will show the revoked-stream page instead of the stream.">
          <?= sv_csrf_field() ?>
          <input type="hidden" name="action" value="revoke_access_point">
          <input type="hidden" name="access_point_id" value="<?= $ap['id'] ?>">
          <button type="submit" class="btn-sm btn-danger">Revoke</button>
        </form>
      <?php endif; ?>
    </div>

    <?php if ($ap['visibility'] === 'public'): ?>
      <div class="sv-url-box">
        <span class="mono"><?= h(($baseUrl ?: '') . '/' . $fullPath . '.m3u8') ?></span>
        <button type="button" data-copy="<?= h(($baseUrl ?: '') . '/' . $fullPath . '.m3u8') ?>" class="btn-sm">Copy</button>
      </div>
    <?php else: ?>
      <table>
        <tr><th>Label</th><th>Token</th><th>Status</th><th>Expires</th><th>Last used</th><th></th></tr>
        <?php if (!$ap['tokens']): ?>
          <tr><td colspan="6" class="sv-help">No tokens yet -- this private access point has no working URL until you add one.</td></tr>
        <?php endif; ?>
        <?php foreach ($ap['tokens'] as $tok): ?>
          <tr>
            <td><?= h($tok['label'] ?: '—') ?></td>
            <td class="mono"><?= h($tok['token_display']) ?>…</td>
            <td>
              <?php if ($tok['revoked_at']): ?><span class="badge revoked">revoked</span>
              <?php elseif ($tok['expires_at'] && $tok['expires_at'] < gmdate('Y-m-d\TH:i:s.000\Z')): ?><span class="badge revoked">expired</span>
              <?php else: ?><span class="badge active">active</span><?php endif; ?>
            </td>
            <td class="mono"><?= h($tok['expires_at'] ? substr($tok['expires_at'], 0, 10) : 'never') ?></td>
            <td class="mono"><?= h($tok['last_used_at'] ? substr($tok['last_used_at'], 0, 19) : 'never') ?></td>
            <td>
              <?php if (!$tok['revoked_at']): ?>
                <form method="post" data-confirm="Revoke this token? It stops working immediately for whoever has this link.">
                  <?= sv_csrf_field() ?>
                  <input type="hidden" name="action" value="revoke_token">
                  <input type="hidden" name="token_id" value="<?= $tok['id'] ?>">
                  <input type="hidden" name="reason" value="manual">
                  <button type="submit" class="btn-sm btn-danger">Revoke</button>
                </form>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>

      <?php if ($revealToken && $revealToken['access_point_id'] == $ap['id']): ?>
        <div class="sv-flash ok">
          <strong>New token created -- copy it now, it will not be shown again:</strong>
          <div class="sv-url-box" style="margin-top:0.5rem;">
            <span class="mono"><?= h(($baseUrl ?: '') . '/' . $fullPath . '/' . $revealToken['raw'] . '.m3u8') ?></span>
            <button type="button" data-copy="<?= h(($baseUrl ?: '') . '/' . $fullPath . '/' . $revealToken['raw'] . '.m3u8') ?>" class="btn-sm">Copy</button>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($ap['status'] === 'active'): ?>
        <form method="post" style="margin-top:0.75rem;display:flex;gap:0.5rem;align-items:end;">
          <?= sv_csrf_field() ?>
          <input type="hidden" name="action" value="add_token">
          <input type="hidden" name="access_point_id" value="<?= $ap['id'] ?>">
          <div style="flex:1;"><label style="margin-top:0;">Recipient / label</label><input type="text" name="label" placeholder="e.g. Alice's TV box"></div>
          <div style="width:10rem;"><label style="margin-top:0;">Expires (days, blank = never)</label><input type="text" name="expires_days" placeholder="e.g. 30"></div>
          <button type="submit" class="btn-primary">Issue token</button>
        </form>
      <?php endif; ?>
    <?php endif; ?>
  </div>
<?php endforeach; ?>

<div class="sv-panel">
  <h2 style="margin-top:0;">Add access point</h2>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="add_access_point">
    <label>Public path (no leading/trailing slash)</label>
    <input type="text" name="public_path" placeholder="live/nova" required>
    <label>Visibility</label>
    <select name="visibility">
      <option value="public">Public (no token required)</option>
      <option value="private">Private (requires a bearer token per recipient)</option>
    </select>
    <button type="submit" class="btn-primary" style="margin-top:1rem;">Add</button>
  </form>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
