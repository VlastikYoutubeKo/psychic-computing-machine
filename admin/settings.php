<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
require_once __DIR__ . '/includes/leak_status.php';
$operator = sv_require_login();
$db = sv_db();

function sv_put_setting(PDO $db, string $key, string $value): void
{
    $db->prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        ->execute([$key, $value]);
}

function sv_slate_audio_extension(string $path, string $name): ?string
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!in_array($ext, ['mp3', 'ogg', 'aac', 'm4a', 'wav'], true)) return null;
    $head = file_get_contents($path, false, null, 0, 16);
    if ($head === false || strlen($head) < 12) return null;
    $valid = match ($ext) {
        'mp3' => str_starts_with($head, 'ID3') || (ord($head[0]) === 0xff && (ord($head[1]) & 0xe0) === 0xe0),
        'ogg' => str_starts_with($head, 'OggS'),
        'aac' => ord($head[0]) === 0xff && (ord($head[1]) & 0xf0) === 0xf0,
        'm4a' => substr($head, 4, 4) === 'ftyp',
        'wav' => str_starts_with($head, 'RIFF') && substr($head, 8, 4) === 'WAVE',
    };
    return $valid ? $ext : null;
}

function sv_slate_audio_url_valid(string $raw): bool
{
    if (strlen($raw) > 2048 || preg_match('/[\x00-\x20\x7f]/', $raw)) return false;
    $parts = parse_url($raw);
    return is_array($parts) && in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
        && !empty($parts['host']) && !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['fragment']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = $_POST['action'] ?? 'save_display';
    if (!is_string($action)) {
        $action = '';
    }
    if ($action === 'save_slate_audio' || $action === 'disable_slate_audio') {
        $oldFile = $db->query("SELECT value FROM settings WHERE key = 'slate_audio_file'")->fetchColumn() ?: '';
        $volume = filter_var($_POST['slate_audio_volume'] ?? null, FILTER_VALIDATE_INT);
        if ($action === 'disable_slate_audio') {
            $db->exec("DELETE FROM settings WHERE key IN ('slate_audio_file','slate_audio_url','slate_audio_volume')");
            if ($oldFile !== '' && preg_match('/^[0-9a-f]{32}\.(mp3|ogg|aac|m4a|wav)$/D', $oldFile)) {
                @unlink(dirname(SV_DB_PATH) . '/slate-audio/' . $oldFile);
            }
            sv_audit('slate_audio_disabled');
            sv_flash('ok', 'Slate audio disabled. Running sessions will finish when idle.');
        } elseif ($volume === false || $volume < 0 || $volume > 100) {
            sv_flash('err', 'Volume must be 0–100.');
        } else {
            $upload = $_FILES['slate_audio_file'] ?? null;
            $hasUpload = is_array($upload) && ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE;
            $url = trim((string) ($_POST['slate_audio_url'] ?? ''));
            if ($hasUpload && $url !== '') {
                sv_flash('err', 'Choose an upload or a URL, not both.');
            } elseif ($hasUpload) {
                $tmp = (string) ($upload['tmp_name'] ?? '');
                $size = (int) ($upload['size'] ?? 0);
                $ext = ($upload['error'] ?? null) === UPLOAD_ERR_OK && is_uploaded_file($tmp) && $size > 0 && $size <= 25 * 1024 * 1024
                    ? sv_slate_audio_extension($tmp, (string) ($upload['name'] ?? '')) : null;
                if ($ext === null) {
                    sv_flash('err', 'Upload a valid MP3, OGG, AAC, M4A or WAV file up to 25 MB.');
                } else {
                    $dir = dirname(SV_DB_PATH) . '/slate-audio';
                    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) throw new RuntimeException('Cannot create slate audio directory');
                    chmod($dir, 0770);
                    $name = bin2hex(random_bytes(16)) . '.' . $ext;
                    if (!move_uploaded_file($tmp, $dir . '/' . $name)) throw new RuntimeException('Cannot store slate audio');
                    chmod($dir . '/' . $name, 0640);
                    sv_put_setting($db, 'slate_audio_file', $name);
                    $db->prepare("DELETE FROM settings WHERE key = 'slate_audio_url'")->execute();
                    sv_put_setting($db, 'slate_audio_volume', (string) $volume);
                    if ($oldFile !== '' && preg_match('/^[0-9a-f]{32}\.(mp3|ogg|aac|m4a|wav)$/D', $oldFile)) @unlink($dir . '/' . $oldFile);
                    sv_audit('slate_audio_uploaded');
                    sv_flash('ok', 'Slate audio saved. New sessions will use it.');
                }
            } elseif ($url !== '') {
                if (!sv_slate_audio_url_valid($url)) {
                    sv_flash('err', 'Enter a valid HTTP(S) radio URL without credentials or fragment.');
                } else {
                    sv_put_setting($db, 'slate_audio_url', $url);
                    $db->prepare("DELETE FROM settings WHERE key = 'slate_audio_file'")->execute();
                    sv_put_setting($db, 'slate_audio_volume', (string) $volume);
                    if ($oldFile !== '' && preg_match('/^[0-9a-f]{32}\.(mp3|ogg|aac|m4a|wav)$/D', $oldFile)) @unlink(dirname(SV_DB_PATH) . '/slate-audio/' . $oldFile);
                    sv_audit('slate_audio_url_updated');
                    sv_flash('ok', 'Radio URL saved. New sessions will use it.');
                }
            } else {
                sv_flash('err', 'Choose an audio file or a radio URL.');
            }
        }
    } elseif ($action === 'save_display') {
        $baseUrl = rtrim(trim((string) ($_POST['gateway_base_url'] ?? '')), '/');
        $parts = $baseUrl !== '' ? parse_url($baseUrl) : [];
        if ($baseUrl !== '' && (!filter_var($baseUrl, FILTER_VALIDATE_URL) || !is_array($parts)
            || !in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || (isset($parts['path']) && $parts['path'] !== ''))) {
            sv_flash('err', 'Enter a bare HTTP(S) stream base URL without path, credentials, query or fragment.');
        } else {
            sv_put_setting($db, 'gateway_base_url', $baseUrl);
            sv_audit('settings_updated', 'gateway_base_url');
            sv_flash('ok', 'Stream base URL saved.');
        }
    } elseif ($action === 'save_github_token') {
        $token = trim((string) ($_POST['github_token'] ?? ''));
        if ($token === '' || strlen($token) > 512) {
            sv_flash('err', 'Enter a GitHub token up to 512 bytes.');
        } else {
            $key = sv_ensure_key_file(SV_KEY_FILE);
            sv_put_setting($db, 'github_token_enc', sv_encrypt($key, $token));
            sv_audit('github_token_updated');
            sv_flash('ok', 'GitHub token saved encrypted. Its value will not be shown again.');
        }
    } elseif ($action === 'clear_github_token') {
        $db->prepare("DELETE FROM settings WHERE key = 'github_token_enc'")->execute();
        sv_audit('github_token_cleared');
        sv_flash('ok', 'GitHub token removed.');
    } elseif ($action === 'save_reply_allowlist') {
        $entries = preg_split('/[\s,]+/', strtolower(trim((string) ($_POST['reply_allowlist'] ?? ''))), -1, PREG_SPLIT_NO_EMPTY);
        $bad = array_filter($entries, fn ($e) => !preg_match('/^[a-z0-9-]+\/[a-z0-9_.-]+$/D', $e) || str_contains($e, '..'));
        if ($bad || count($entries) > 50) {
            sv_flash('err', 'Enter owner/repository entries only (max 50), one per line.');
        } else {
            sv_put_setting($db, 'github_reply_allowlist', implode("\n", array_unique($entries)));
            sv_audit('settings_updated', 'github_reply_allowlist', ['count' => count($entries)]);
            sv_flash('ok', 'Automatic reply allowlist saved.');
        }
    } elseif ($action === 'request_leak_scan') {
        if (!$db->query("SELECT 1 FROM settings WHERE key = 'github_token_enc'")->fetchColumn()) {
            sv_flash('err', 'Configure a GitHub token before requesting a scan.');
        } elseif (!$db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn()) {
            sv_flash('err', 'Configure the stream base URL before requesting a scan.');
        } else {
            $db->exec("INSERT INTO settings (key, value) VALUES ('leak_scan_requested_at', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            sv_audit('leak_scan_requested');
            sv_flash('ok', 'Scan requested. The checker timer picks it up within about 5 minutes.');
        }
    } elseif ($action === 'add_leak_source') {
        $provider = $_POST['provider'] ?? '';
        $identifier = strtolower(trim((string) ($_POST['identifier'] ?? '')));
        $valid = $provider === 'github_repo'
            ? (bool) preg_match('/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/D', $identifier)
            : ($provider === 'github_org' && (bool) preg_match('/^[a-z0-9-]+$/D', $identifier));
        if (!$valid || strlen($identifier) > 200 || str_contains($identifier, '..')) {
            sv_flash('err', 'Enter a valid GitHub owner/repository or organization name.');
        } else {
            try {
                $db->prepare('INSERT INTO leak_sources (provider, identifier) VALUES (?, ?)')->execute([$provider, $identifier]);
                sv_audit('leak_source_created', "leak_source:" . $db->lastInsertId(), ['provider' => $provider, 'identifier' => $identifier]);
                sv_flash('ok', 'Watched GitHub source added.');
            } catch (PDOException $e) {
                sv_flash('err', 'Could not add source. It may already exist.');
            }
        }
    } elseif ($action === 'toggle_leak_source' || $action === 'delete_leak_source') {
        $id = filter_var($_POST['source_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false || $id === null) {
            sv_flash('err', 'Invalid source ID.');
        } else {
            $stmt = $db->prepare("SELECT provider FROM leak_sources WHERE id = ? AND provider IN ('github_repo','github_org')");
            $stmt->execute([$id]);
            if (!$stmt->fetchColumn()) {
                sv_flash('err', 'GitHub source not found.');
            } elseif ($action === 'toggle_leak_source') {
                $db->prepare('UPDATE leak_sources SET enabled = 1 - enabled WHERE id = ?')->execute([$id]);
                sv_audit('leak_source_toggled', "leak_source:$id");
                sv_flash('ok', 'Source enabled state updated.');
            } else {
                $db->prepare('DELETE FROM leak_sources WHERE id = ?')->execute([$id]);
                sv_audit('leak_source_deleted', "leak_source:$id");
                sv_flash('ok', 'Watched source removed.');
            }
        }
    } else {
        sv_flash('err', 'Unknown settings action.');
    }
    sv_redirect('settings.php');
}

$baseUrl = $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: '';
$githubTokenSet = (bool) $db->query("SELECT 1 FROM settings WHERE key = 'github_token_enc'")->fetchColumn();
$replyAllowlist = (string) ($db->query("SELECT value FROM settings WHERE key = 'github_reply_allowlist'")->fetchColumn() ?: '');
$slateAudio = $db->query("SELECT key, value FROM settings WHERE key IN ('slate_audio_file','slate_audio_url','slate_audio_volume')")->fetchAll(PDO::FETCH_KEY_PAIR);
$sources = $db->query('SELECT id, provider, identifier, enabled, last_scanned_at FROM leak_sources ORDER BY provider, identifier')->fetchAll();

$pageTitle = 'Settings';
$activeNav = 'settings';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Settings</h1>

<div class="sv-panel">
  <h2>Slate audio</h2>
  <p class="sv-help">Current source: <?= isset($slateAudio['slate_audio_file']) ? 'uploaded file' : (isset($slateAudio['slate_audio_url']) ? 'radio URL' : 'silence') ?>. Changes apply when a new slate session starts. Public broadcasts require music rights.</p>
  <form method="post" enctype="multipart/form-data">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="save_slate_audio">
    <label for="slate-file">Upload audio (MP3, OGG, AAC, M4A, WAV; max 25 MB)</label>
    <input id="slate-file" type="file" name="slate_audio_file" accept=".mp3,.ogg,.aac,.m4a,.wav,audio/*">
    <label for="slate-url">Or radio stream URL</label>
    <input id="slate-url" type="url" name="slate_audio_url" maxlength="2048" value="<?= h($slateAudio['slate_audio_url'] ?? '') ?>" placeholder="https://example.org/radio.mp3">
    <label for="slate-volume">Volume (0–100)</label>
    <input id="slate-volume" type="number" name="slate_audio_volume" min="0" max="100" value="<?= h($slateAudio['slate_audio_volume'] ?? '50') ?>" required>
    <button type="submit" class="btn-primary" style="margin-top:1rem">Save audio</button>
  </form>
  <form method="post" data-confirm="Disable slate audio?" style="margin-top:1rem">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="disable_slate_audio">
    <button type="submit" class="btn-danger">Disable and remove audio</button>
  </form>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Display</h2>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="save_display">
    <label>Stream base URL (used to display links and build exact Leak Checker search anchors)</label>
    <input type="text" name="gateway_base_url" value="<?= h($baseUrl) ?>" placeholder="https://restream.mxnticek.eu">
    <div class="sv-help">Use the actual public stream hostname. Only this base URL is covered by the current GitHub checker; additional stream domains require a future configuration change.</div>
    <button type="submit" class="btn-primary" style="margin-top:1rem;">Save</button>
  </form>
</div>

<?php sv_render_leak_status($db); ?>

<div class="sv-panel">
  <h2 style="margin-top:0;">Request a scan</h2>
  <p class="sv-help">The checker is a separate one-shot process. This queues a request for its once-per-minute timer; it does not run a command inside the web container. Check the run status above to see when it actually starts and whether it succeeds.</p>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="request_leak_scan">
    <button type="submit" class="btn-primary" <?= $githubTokenSet && $baseUrl !== '' ? '' : 'disabled' ?>>Scan now</button>
  </form>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">GitHub access</h2>
  <p>Token: <strong><?= $githubTokenSet ? 'configured' : 'not configured' ?></strong>. It is encrypted at rest using the StreamVault key and never shown here after saving.</p>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="save_github_token">
    <label>GitHub personal access token</label>
    <input type="password" name="github_token" autocomplete="new-password" required>
    <button type="submit" class="btn-primary" style="margin-top:1rem;">Save token</button>
  </form>
  <?php if ($githubTokenSet): ?>
    <form method="post" data-confirm="Remove the stored GitHub token? Scheduled scans will fail until another is configured.">
      <?= sv_csrf_field() ?>
      <input type="hidden" name="action" value="clear_github_token">
      <button type="submit" class="btn-danger" style="margin-top:0.75rem;">Remove token</button>
    </form>
  <?php endif; ?>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Automatic GitHub replies</h2>
  <p class="sv-help">When a stream is set to "Revoke automatically on confirmed leak", the checker revokes the leaked link and, only for issues/PRs in these repositories, posts a public comment with the "Stream unavailable" image. Everywhere else, reply from the incident page after reviewing. The GitHub token needs the <code>public_repo</code> scope (classic token) to comment.</p>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="save_reply_allowlist">
    <label for="reply_allowlist">Repositories (owner/repo, one per line)</label>
    <textarea id="reply_allowlist" name="reply_allowlist" rows="3" placeholder="owner/repo"><?= h($replyAllowlist) ?></textarea>
    <button type="submit" class="btn btn-primary">Save allowlist</button>
  </form>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Configured GitHub sources</h2>
  <p class="sv-help">Enabled repositories and organizations receive additional scoped queries during a scan. The “Last attempted” column records when the checker tried each source; check the run status above for errors or partial coverage. Global GitHub search does not need a row. GitLab and public playlist scanning are not implemented yet.</p>
  <form method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="add_leak_source">
    <label>Type</label>
    <select name="provider"><option value="github_repo">GitHub repository</option><option value="github_org">GitHub organization</option></select>
    <label>Owner/repository or organization</label>
    <input type="text" name="identifier" maxlength="200" placeholder="iptv-org/iptv" required>
    <button type="submit" class="btn-primary" style="margin-top:1rem;">Add source</button>
  </form>
  <?php if ($sources): ?>
    <table style="margin-top:1rem;">
      <tr><th>Provider</th><th>Identifier</th><th>Enabled</th><th>Last attempted</th><th>Actions</th></tr>
      <?php foreach ($sources as $source): ?>
        <tr>
          <td><?= h($source['provider']) ?></td>
          <td class="mono"><?= h($source['identifier']) ?></td>
          <td><?= $source['enabled'] ? 'yes' : 'no' ?></td>
          <td class="mono"><?= h($source['last_scanned_at'] ?? 'never') ?></td>
          <td>
            <?php if (in_array($source['provider'], ['github_repo', 'github_org'], true)): ?>
              <form method="post" style="display:inline;">
                <?= sv_csrf_field() ?><input type="hidden" name="action" value="toggle_leak_source"><input type="hidden" name="source_id" value="<?= (int) $source['id'] ?>">
                <button type="submit" class="btn-sm"><?= $source['enabled'] ? 'Disable' : 'Enable' ?></button>
              </form>
              <form method="post" style="display:inline;" data-confirm="Delete this watched source?">
                <?= sv_csrf_field() ?><input type="hidden" name="action" value="delete_leak_source"><input type="hidden" name="source_id" value="<?= (int) $source['id'] ?>">
                <button type="submit" class="btn-sm btn-danger">Delete</button>
              </form>
            <?php else: ?>
              <span class="sv-help">Not managed here yet</span>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Not yet implemented</h2>
  <ul class="sv-help">
    <li>GitLab and public playlist monitoring</li>
    <li>Discord bot configuration</li>
    <li>Automatic or approval-gated token rotation</li>
    <li>Replacement HLS video, M3U export and EPG import</li>
  </ul>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
