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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = $_POST['action'] ?? 'save_display';
    if (!is_string($action)) {
        $action = '';
    }
    if ($action === 'save_display') {
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
    } elseif ($action === 'request_leak_scan') {
        if (!$db->query("SELECT 1 FROM settings WHERE key = 'github_token_enc'")->fetchColumn()) {
            sv_flash('err', 'Configure a GitHub token before requesting a scan.');
        } elseif (!$db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn()) {
            sv_flash('err', 'Configure the stream base URL before requesting a scan.');
        } else {
            $db->exec("INSERT INTO settings (key, value) VALUES ('leak_scan_requested_at', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            sv_audit('leak_scan_requested');
            sv_flash('ok', 'Scan requested. The checker timer will pick it up within about a minute if running.');
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
$sources = $db->query('SELECT id, provider, identifier, enabled, last_scanned_at FROM leak_sources ORDER BY provider, identifier')->fetchAll();

$pageTitle = 'Settings';
$activeNav = 'settings';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Settings</h1>

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
