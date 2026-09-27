<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/leak_status.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_login();
$db = sv_db();

$count = static function (string $sql) use ($db, $operator): int {
    $stmt = $db->prepare($sql); $stmt->execute([$operator['role'], $operator['id']]); return (int) $stmt->fetchColumn();
};
$streamCount = $count("SELECT COUNT(*) FROM streams s WHERE (?='admin' OR s.owner_id=?)");
$activeStreamCount = $count("SELECT COUNT(*) FROM streams s WHERE s.status='active' AND (?='admin' OR s.owner_id=?)");
$privateAccessCount = $count("SELECT COUNT(*) FROM access_points ap JOIN streams s ON s.id=ap.stream_id WHERE ap.status='active' AND (?='admin' OR s.owner_id=?)");
$openIncidentCount = $count("SELECT COUNT(*) FROM incidents i JOIN streams s ON s.id=i.stream_id WHERE i.status IN ('new','probable','confirmed') AND (?='admin' OR s.owner_id=?)");
$recentStmt = $db->prepare("SELECT s.id,s.name,s.status,s.created_at FROM streams s WHERE (?='admin' OR s.owner_id=?) ORDER BY s.created_at DESC LIMIT 5");
$recentStmt->execute([$operator['role'], $operator['id']]);
$recentStreams = $recentStmt->fetchAll();

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
  <a href="stream_form.php">Add stream</a><a href="incidents.php">Review leaks</a>
  <?php if (sv_is_admin($operator)): ?><a href="error_screen.php">Edit error screen</a><form method="post" action="settings.php"><?= sv_csrf_field() ?><input type="hidden" name="action" value="request_leak_scan"><button class="btn-primary" type="submit">Scan now</button></form><?php else: ?><a href="my_account.php">My scan settings</a><?php endif; ?>
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

<?php sv_render_leak_status($db, $operator); ?>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
