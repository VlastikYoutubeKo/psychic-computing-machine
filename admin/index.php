<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$operator = sv_require_login();
$db = sv_db();

$streamCount = (int) $db->query('SELECT COUNT(*) FROM streams')->fetchColumn();
$activeStreamCount = (int) $db->query("SELECT COUNT(*) FROM streams WHERE status='active'")->fetchColumn();
$privateAccessCount = (int) $db->query("SELECT COUNT(*) FROM access_points WHERE visibility='private' AND status='active'")->fetchColumn();
$openIncidentCount = (int) $db->query("SELECT COUNT(*) FROM incidents WHERE status IN ('new','probable','confirmed')")->fetchColumn();

$recentStreams = $db->query('SELECT id, name, status, created_at FROM streams ORDER BY created_at DESC LIMIT 5')->fetchAll();

$pageTitle = 'Dashboard';
$activeNav = 'dashboard';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Dashboard</h1>

<div class="sv-grid">
  <div class="sv-stat"><div class="num"><?= $streamCount ?></div><div class="label">Total streams</div></div>
  <div class="sv-stat"><div class="num"><?= $activeStreamCount ?></div><div class="label">Active streams</div></div>
  <div class="sv-stat"><div class="num"><?= $privateAccessCount ?></div><div class="label">Active private access points</div></div>
  <div class="sv-stat"><div class="num"><?= $openIncidentCount ?></div><div class="label">Open incidents</div></div>
</div>

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

<div class="sv-panel">
  <strong>Leak Checker:</strong> not yet implemented (see ROADMAP.md Phase 6) — no automated GitHub/GitLab
  scanning is running. Do not treat the absence of incidents above as confirmation that no leak exists.
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
