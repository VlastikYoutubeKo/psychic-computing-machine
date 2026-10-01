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
    $stream = sv_stream_for_operator($db, $operator, $id);
    if (!$stream) {
        http_response_code(404); exit('Stream not found.');
    }
}

$errors = [];
$form = [
    'name' => $stream['name'] ?? '',
    'description' => $stream['description'] ?? '',
    'source_type' => $stream['source_type'] ?? 'hls',
    'source_url' => $stream['source_url'] ?? '',
    'source_username' => $stream['source_username'] ?? '',
    'rotation_mode' => 'auto',
    'always_on' => (string) (int) ($stream['always_on'] ?? 0),
    'node_id' => (string) (int) ($stream['node_id'] ?? 0),
    'replacement_reason' => $stream['replacement_reason'] ?? 'unauthorized_redistribution',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    foreach (array_keys($form) as $key) {
        $form[$key] = trim((string) ($_POST[$key] ?? ''));
    }
    $form['rotation_mode'] = 'auto'; // no longer a user choice, see the help text
    // Only accounts allowed to pin a relay may switch always-on on; if the
    // permission was withdrawn, saving turns it off.
    $form['always_on'] = sv_can_always_on($operator) && isset($_POST['always_on']) ? '1' : '0';
    // Node assignment is admin-only; others keep whatever the admin set.
    if (sv_is_admin($operator)) {
        $nid = (int) ($_POST['node_id'] ?? 0);
        $exists = $db->prepare('SELECT 1 FROM nodes WHERE id = ?');
        $exists->execute([$nid]);
        $form['node_id'] = ($nid > 0 && $exists->fetchColumn()) ? (string) $nid : '0';
    } else {
        $form['node_id'] = (string) (int) ($stream['node_id'] ?? 0);
    }
    $sourcePassword = (string) ($_POST['source_password'] ?? '');

    if ($form['name'] === '') {
        $errors[] = 'Name is required.';
    }
    if ($form['source_url'] === '') {
        $errors[] = 'Source URL is required.';
    }
    // Regular accounts may only use public sources: the gateway enforces this
    // at connect time too, but reject it here with a clear message.
    if ($form['source_url'] !== '' && !sv_is_admin($operator)) {
        $srcErr = sv_public_source_error($form['source_url']);
        if ($srcErr !== null) $errors[] = $srcErr;
    }
    $validTypes = ['restreamer', 'tvheadend', 'hls', 'mpegts', 'generic'];
    if (!in_array($form['source_type'], $validTypes, true)) {
        $errors[] = 'Invalid source type.';
    }
    if (!$stream && !sv_is_admin($operator)) {
        $count = $db->prepare('SELECT COUNT(*) FROM streams WHERE owner_id=?');
        $count->execute([$operator['id']]);
        if ((int) $count->fetchColumn() >= (int) $operator['max_streams']) $errors[] = 'Stream limit reached.';
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
            $db->prepare('UPDATE streams SET always_on = ?, node_id = ? WHERE id = ?')->execute([(int) $form['always_on'], (int) $form['node_id'] ?: null, $id]);
            sv_audit('stream_updated', "stream:$id", ['always_on' => (int) $form['always_on']]);
            sv_flash('ok', 'Stream updated.');
            sv_redirect('stream_view.php?id=' . $id);
        } else {
            $db->prepare('INSERT INTO streams (name, description, source_type, source_url, source_username,
                source_password_enc, rotation_mode, replacement_reason, owner_id) VALUES (?,?,?,?,?,?,?,?,?)')
                ->execute([$form['name'], $form['description'], $form['source_type'], $cleanUrl,
                    $finalUsername ?: null, $encryptedPassword, $form['rotation_mode'], $form['replacement_reason'], $operator['id']]);
            $newId = (int) $db->lastInsertId();
            $db->prepare('UPDATE streams SET always_on = ?, node_id = ? WHERE id = ?')->execute([(int) $form['always_on'], (int) $form['node_id'] ?: null, $newId]);
            sv_audit('stream_created', "stream:$newId", ['always_on' => (int) $form['always_on']]);
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
    <div class="sv-help">If the URL contains <code>user:pass@</code>, credentials are extracted automatically and stored encrypted, separately from the URL. They are never shown again after saving. For sources that want the credentials inside the URL path (Xtream Codes), write <code>{username}</code> and <code>{password}</code> in the URL and fill in the fields below, or use <a href="xtream_import.php">Import from Xtream Codes</a>.</div>

    <label>Source username (optional, overrides URL)</label>
    <input type="text" name="source_username" value="<?= h($form['source_username']) ?>" autocomplete="off">

    <label>Source password <?= $stream && $stream['source_password_enc'] ? '(leave blank to keep the current one)' : '' ?></label>
    <input type="password" name="source_password" autocomplete="new-password">

    <div class="sv-help">Leak response is automatic: when the Leak Checker finds one of this stream's links posted publicly on GitHub, that link is revoked right away (players get the "Stream unavailable" screen) and the incident is logged.</div>

    <?php if (sv_can_always_on($operator)): ?>
      <label><input type="checkbox" name="always_on" value="1" <?= $form['always_on'] === '1' ? 'checked' : '' ?>> Always on (24/7 relay)</label>
      <div class="sv-help">The gateway keeps this stream running permanently: the first viewer starts instantly and the source sees one connection instead of one per viewer. Uses one relay slot all the time.</div>
    <?php endif; ?>

    <?php if (sv_is_admin($operator)): $nodeOptions = $db->query('SELECT id, name, status FROM nodes ORDER BY name COLLATE NOCASE')->fetchAll(); ?>
      <label for="node-select">Relay node</label>
      <select id="node-select" name="node_id">
        <option value="0">This server</option>
        <?php foreach ($nodeOptions as $no): ?><option value="<?= (int) $no['id'] ?>" <?= $form['node_id'] === (string) $no['id'] ? 'selected' : '' ?>><?= h($no['name']) ?><?= $no['status'] === 'disabled' ? ' (disabled)' : '' ?></option><?php endforeach; ?>
      </select>
      <div class="sv-help">The node pulls this stream from its source and relays it 24/7; viewers still use this domain and this server fetches the stream from the node. If the node is offline, this server serves the stream straight from the source. Manage nodes on the Nodes page.</div>
    <?php endif; ?>

    <label>Replacement reason shown if revoked</label>
    <div class="sv-help">The administrator maintains the video and browser text for each reason.</div>
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
