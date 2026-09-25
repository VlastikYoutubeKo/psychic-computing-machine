<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
$operator = sv_require_login();
$db = sv_db();

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
$stream = null;
if ($id) {
    $stmt = $db->prepare('SELECT * FROM streams WHERE id = ?');
    $stmt->execute([$id]);
    $stream = $stmt->fetch();
    if (!$stream) {
        sv_flash('err', 'Stream not found.');
        sv_redirect('streams.php');
    }
}

$errors = [];
$form = [
    'name' => $stream['name'] ?? '',
    'description' => $stream['description'] ?? '',
    'source_type' => $stream['source_type'] ?? 'hls',
    'source_url' => $stream['source_url'] ?? '',
    'source_username' => $stream['source_username'] ?? '',
    'rotation_mode' => $stream['rotation_mode'] ?? 'manual_approval',
    'replacement_reason' => $stream['replacement_reason'] ?? 'unauthorized_redistribution',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    foreach (array_keys($form) as $key) {
        $form[$key] = trim((string) ($_POST[$key] ?? ''));
    }
    $sourcePassword = (string) ($_POST['source_password'] ?? '');

    if ($form['name'] === '') {
        $errors[] = 'Name is required.';
    }
    if ($form['source_url'] === '') {
        $errors[] = 'Source URL is required.';
    }
    $validTypes = ['restreamer', 'tvheadend', 'hls', 'mpegts', 'generic'];
    if (!in_array($form['source_type'], $validTypes, true)) {
        $errors[] = 'Invalid source type.';
    }

    // If the URL itself carries user:pass@host, extract it so the raw URL
    // stored (and ever logged) never contains credentials -- the whole
    // point of this app is to stop that leaking, so we don't get to do it
    // ourselves either (spec section 7).
    $cleanUrl = $form['source_url'];
    $embeddedUser = $embeddedPass = null;
    $parsed = parse_url($form['source_url']);
    if ($parsed !== false && isset($parsed['user'])) {
        $embeddedUser = $parsed['user'];
        $embeddedPass = $parsed['pass'] ?? '';
        $cleanUrl = sprintf(
            '%s://%s%s%s',
            $parsed['scheme'] ?? 'http',
            $parsed['host'] ?? '',
            isset($parsed['port']) ? ':' . $parsed['port'] : '',
            $parsed['path'] ?? ''
        );
        if (isset($parsed['query'])) {
            $cleanUrl .= '?' . $parsed['query'];
        }
    }

    $finalUsername = $form['source_username'] !== '' ? $form['source_username'] : $embeddedUser;
    $finalPassword = $sourcePassword !== '' ? $sourcePassword : $embeddedPass;

    if (!$errors) {
        $encryptedPassword = null;
        if ($finalUsername !== null && $finalUsername !== '') {
            if ($finalPassword === null || $finalPassword === '') {
                // Editing an existing stream without changing the password:
                // keep whatever is already stored.
                $encryptedPassword = $stream['source_password_enc'] ?? null;
            } else {
                $key = sv_ensure_key_file(SV_KEY_FILE);
                $encryptedPassword = sv_encrypt($key, $finalPassword);
            }
        }

        if ($stream) {
            $db->prepare('UPDATE streams SET name=?, description=?, source_type=?, source_url=?, source_username=?,
                source_password_enc=?, rotation_mode=?, replacement_reason=?, updated_at=strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\')
                WHERE id=?')
                ->execute([$form['name'], $form['description'], $form['source_type'], $cleanUrl,
                    $finalUsername ?: null, $encryptedPassword, $form['rotation_mode'], $form['replacement_reason'], $id]);
            sv_audit('stream_updated', "stream:$id");
            sv_flash('ok', 'Stream updated.');
            sv_redirect('stream_view.php?id=' . $id);
        } else {
            $db->prepare('INSERT INTO streams (name, description, source_type, source_url, source_username,
                source_password_enc, rotation_mode, replacement_reason) VALUES (?,?,?,?,?,?,?,?)')
                ->execute([$form['name'], $form['description'], $form['source_type'], $cleanUrl,
                    $finalUsername ?: null, $encryptedPassword, $form['rotation_mode'], $form['replacement_reason']]);
            $newId = (int) $db->lastInsertId();
            sv_audit('stream_created', "stream:$newId");
            sv_flash('ok', 'Stream created. Now add a public or private access point to it.');
            sv_redirect('stream_view.php?id=' . $newId);
        }
    }
}

$pageTitle = $stream ? 'Edit stream' : 'Add stream';
$activeNav = 'streams';
require __DIR__ . '/includes/layout_top.php';
?>
<h1><?= $stream ? 'Edit stream' : 'Add stream' ?></h1>

<?php foreach ($errors as $e): ?><div class="sv-flash err"><?= h($e) ?></div><?php endforeach; ?>

<div class="sv-panel">
  <form method="post">
    <?= sv_csrf_field() ?>
    <label>Name</label>
    <input type="text" name="name" value="<?= h($form['name']) ?>" required>

    <label>Description</label>
    <textarea name="description"><?= h($form['description']) ?></textarea>

    <label>Source type</label>
    <select name="source_type">
      <?php foreach (['restreamer' => 'datarhei Restreamer', 'tvheadend' => 'Tvheadend', 'hls' => 'Generic HLS', 'mpegts' => 'MPEG-TS over HTTP', 'generic' => 'Generic'] as $val => $label): ?>
        <option value="<?= h($val) ?>" <?= $form['source_type'] === $val ? 'selected' : '' ?>><?= h($label) ?></option>
      <?php endforeach; ?>
    </select>

    <label>Source URL</label>
    <input type="text" name="source_url" value="<?= h($form['source_url']) ?>" placeholder="https://restream.mxnticek.eu/memfs/xxxxx.m3u8 or http://user:pass@tvheadend:9981/stream/channel/123" required>
    <div class="sv-help">If the URL contains <code>user:pass@</code>, credentials are extracted automatically and stored encrypted, separately from the URL. They are never shown again after saving.</div>

    <label>Source username (optional, overrides URL)</label>
    <input type="text" name="source_username" value="<?= h($form['source_username']) ?>" autocomplete="off">

    <label>Source password <?= $stream && $stream['source_password_enc'] ? '(leave blank to keep the current one)' : '' ?></label>
    <input type="password" name="source_password" autocomplete="new-password">

    <label>Rotation mode</label>
    <select name="rotation_mode">
      <option value="manual_approval" <?= $form['rotation_mode'] === 'manual_approval' ? 'selected' : '' ?>>Rotate after admin approval</option>
      <option value="auto" <?= $form['rotation_mode'] === 'auto' ? 'selected' : '' ?>>Rotate automatically on confirmed leak</option>
      <option value="monitor_only" <?= $form['rotation_mode'] === 'monitor_only' ? 'selected' : '' ?>>Monitor only, never auto-act</option>
    </select>
    <div class="sv-help">"auto" and "monitor_only" are recorded now but not yet acted on by anything -- the leak checker that would trigger a rotation isn't implemented yet (ROADMAP.md Phase 6-7).</div>

    <label>Replacement reason shown if revoked</label>
    <select name="replacement_reason">
      <?php $reasons = [
          'limited_bandwidth' => 'Limited bandwidth',
          'not_intended_for_public' => 'Not intended for public distribution',
          'unauthorized_redistribution' => 'Unauthorized redistribution',
          'access_revoked_by_owner' => 'Access revoked by the stream owner',
          'stream_permanently_discontinued' => 'Stream permanently discontinued',
      ]; ?>
      <?php foreach ($reasons as $val => $label): ?>
        <option value="<?= h($val) ?>" <?= $form['replacement_reason'] === $val ? 'selected' : '' ?>><?= h($label) ?></option>
      <?php endforeach; ?>
    </select>

    <button type="submit" class="btn-primary" style="margin-top:1.5rem;"><?= $stream ? 'Save changes' : 'Create stream' ?></button>
    <a href="streams.php" class="btn" style="margin-top:1.5rem;">Cancel</a>
  </form>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
