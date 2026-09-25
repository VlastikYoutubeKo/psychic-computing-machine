<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$operator = sv_require_login();
$db = sv_db();

$streams = $db->query('
    SELECT s.*,
           (SELECT COUNT(*) FROM access_points ap WHERE ap.stream_id = s.id AND ap.status = "active") AS access_count,
           (SELECT COUNT(*) FROM incidents i WHERE i.stream_id = s.id AND i.status IN ("new","probable","confirmed")) AS incident_count
    FROM streams s
    ORDER BY s.name COLLATE NOCASE
')->fetchAll();

$pageTitle = 'Streams';
$activeNav = 'streams';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Streams <a href="stream_form.php" class="btn btn-primary btn-sm" style="float:right;">+ Add stream</a></h1>

<div class="sv-panel">
  <?php if (!$streams): ?>
    <p class="sv-help">No streams yet. <a href="stream_form.php">Add your first stream</a>.</p>
  <?php else: ?>
    <table>
      <tr><th>Name</th><th>Source type</th><th>Status</th><th>Access points</th><th>Open incidents</th><th></th></tr>
      <?php foreach ($streams as $s): ?>
        <tr>
          <td><?= h($s['name']) ?></td>
          <td class="mono"><?= h($s['source_type']) ?></td>
          <td><span class="badge <?= h($s['status']) ?>"><?= h($s['status']) ?></span></td>
          <td><?= (int) $s['access_count'] ?></td>
          <td><?= (int) $s['incident_count'] ?></td>
          <td><a href="stream_view.php?id=<?= (int) $s['id'] ?>">Manage</a></td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
