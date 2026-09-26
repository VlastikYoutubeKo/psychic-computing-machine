<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/leak_status.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_login();
$db = sv_db();

$streamCount = (int) $db->query('SELECT COUNT(*) FROM streams')->fetchColumn();
$activeStreamCount = (int) $db->query("SELECT COUNT(*) FROM streams WHERE status='active'")->fetchColumn();
$privateAccessCount = (int) $db->query("SELECT COUNT(*) FROM access_points WHERE status='active'")->fetchColumn();
$openIncidentCount = (int) $db->query("SELECT COUNT(*) FROM incidents WHERE status IN ('new','probable','confirmed')")->fetchColumn();

$recentStreams = $db->query('SELECT id, name, status, created_at FROM streams ORDER BY created_at DESC LIMIT 5')->fetchAll();

$pageTitle = 'Dashboard';
$activeNav = 'dashboard';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Dashboard</h1><p class="sv-help">Your streams and leak response at a glance.</p></div><a href="stream_form.php" class="btn btn-primary">+ Add stream</a></div>

<div class="sv-grid">
  <div class="sv-stat"><div class="num"><?= $streamCount ?></div><div class="label">Total streams</div></div>
  <div class="sv-stat"><div class="num"><?= $activeStreamCount ?></div><div class="label">Active streams</div></div>
  <div class="sv-stat"><div class="num"><?= $privateAccessCount ?></div><div class="label">Active access points</div></div>
  <div class="sv-stat"><div class="num"><?= $openIncidentCount ?></div><div class="label">Open incidents</div></div>
</div>

<div class="sv-panel"><h2>Quick actions</h2><div class="sv-section-nav">
  <a href="stream_form.php">Add stream</a><a href="incidents.php">Review leaks</a><a href="error_screen.php">Edit error screen</a>
  <form method="post" action="settings.php"><?= sv_csrf_field() ?><input type="hidden" name="action" value="request_leak_scan"><button class="btn-primary" type="submit">Scan now</button></form>
</div></div>

<h2>Recently added streams</h2>
<div class="sv-panel">
  <?php if (!$recentStreams): ?>
    <p class="sv-help">No streams yet. <a href="stream_form.php">Add your first stream</a>.</p>
  <?php else: ?>
    <table>
      <tr><th>Name</th><th>Status</th><th>Created</th><th></th></tr>
      <?php foreach ($recentStreams as $s): ?>
        <tr>
          <td><?= h($s['name']) ?></td>
          <td><span class="badge <?= h($s['status']) ?>"><?= h($s['status']) ?></span></td>
          <td class="mono"><?= h($s['created_at']) ?></td>
          <td><a href="stream_view.php?id=<?= (int) $s['id'] ?>">View</a></td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<?php sv_render_leak_status($db); ?>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
