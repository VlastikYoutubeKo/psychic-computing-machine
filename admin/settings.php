<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_login();
$db = sv_db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $baseUrl = rtrim(trim((string) ($_POST['gateway_base_url'] ?? '')), '/');
    $db->prepare('INSERT INTO settings (key, value) VALUES (\'gateway_base_url\', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value')->execute([$baseUrl]);
    sv_audit('settings_updated', 'gateway_base_url');
    sv_flash('ok', 'Settings saved.');
    sv_redirect('settings.php');
}

$baseUrl = $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: '';

$pageTitle = 'Settings';
$activeNav = 'settings';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Settings</h1>

<div class="sv-panel">
  <h2 style="margin-top:0;">Display</h2>
  <form method="post">
    <?= sv_csrf_field() ?>
    <label>Public base URL (display only -- this does not change routing, it's just used to build the full links shown in this admin UI)</label>
    <input type="text" name="gateway_base_url" value="<?= h($baseUrl) ?>" placeholder="https://restream.mxnticek.eu">
    <button type="submit" class="btn-primary" style="margin-top:1rem;">Save</button>
  </form>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Not yet implemented</h2>
  <p class="sv-help">
    The following sections from the project spec have a data model ready (see migrations/0001_init.sql)
    but no working logic yet -- listed here instead of shown as working so this page never implies more
    than what actually runs. See ROADMAP.md for planned order.
  </p>
  <ul class="sv-help">
    <li>GitHub / GitLab leak monitoring configuration</li>
    <li>Discord bot configuration</li>
    <li>Automatic/approval-gated token rotation on confirmed leaks</li>
    <li>Replacement HLS video generation (currently only a static HTML "stream unavailable" page)</li>
    <li>M3U playlist export, EPG import</li>
  </ul>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
