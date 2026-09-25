<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
$operator = sv_require_login();
$db = sv_db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = $_POST['action'] ?? '';
    if (!is_string($action)) {
        $action = '';
    }

    if ($action === 'create') {
        $streamId = filter_var($_POST['stream_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $sourceUrl = trim((string) ($_POST['source_url'] ?? ''));
        $notes = trim((string) ($_POST['notes'] ?? ''));
        $scheme = strtolower((string) parse_url($sourceUrl, PHP_URL_SCHEME));
        $host = parse_url($sourceUrl, PHP_URL_HOST);
        $streamExists = false;
        if ($streamId !== false && $streamId !== null) {
            $stmt = $db->prepare('SELECT 1 FROM streams WHERE id = ?');
            $stmt->execute([$streamId]);
            $streamExists = (bool) $stmt->fetchColumn();
        }
        if (!$streamExists) {
            sv_flash('err', 'Select an existing stream.');
        } elseif ($sourceUrl !== '' && (strlen($sourceUrl) > 2048 || !in_array($scheme, ['http', 'https'], true) || !$host || !filter_var($sourceUrl, FILTER_VALIDATE_URL))) {
            sv_flash('err', 'Evidence URL must be an HTTP(S) URL up to 2048 bytes.');
        } elseif (strlen($notes) > 4000) {
            sv_flash('err', 'Notes must be at most 4000 bytes.');
        } else {
            $db->prepare('INSERT INTO incidents (stream_id, source, source_url, notes) VALUES (?, ?, ?, ?)')
                ->execute([$streamId, 'manual', $sourceUrl ?: null, $notes ?: null]);
            $id = (int) $db->lastInsertId();
            sv_audit('incident_created', "incident:$id", ['stream_id' => $streamId]);
            sv_flash('ok', "Incident #$id recorded. No token was revoked or rotated.");
        }
        sv_redirect('incidents.php');
    }

    $transitions = [
        'confirm' => ['to' => 'confirmed', 'from' => ['new', 'probable']],
        'dismiss' => ['to' => 'dismissed', 'from' => ['new', 'probable']],
        'resolve' => ['to' => 'resolved', 'from' => ['confirmed']],
    ];
    if (isset($transitions[$action])) {
        $id = filter_var($_POST['incident_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false || $id === null) {
            sv_flash('err', 'Invalid incident ID.');
            sv_redirect('incidents.php');
        }
        $db->beginTransaction();
        try {
            $stmt = $db->prepare('SELECT status, actions_taken FROM incidents WHERE id = ?');
            $stmt->execute([$id]);
            $incident = $stmt->fetch();
            $transition = $transitions[$action];
            if (!$incident || !in_array($incident['status'], $transition['from'], true)) {
                $db->rollBack();
                sv_flash('err', 'Incident was not found or this state change is not allowed.');
                sv_redirect('incidents.php');
            }
            $history = json_decode($incident['actions_taken'] ?? '[]', true);
            if (!is_array($history)) {
                $history = [];
            }
            $history[] = [
                'at' => gmdate('Y-m-d\TH:i:s\Z'),
                'actor' => 'operator:' . $operator['id'],
                'from' => $incident['status'],
                'to' => $transition['to'],
            ];
            $stmt = $db->prepare('UPDATE incidents SET status = ?, actions_taken = ? WHERE id = ? AND status = ?');
            $stmt->execute([$transition['to'], json_encode($history, JSON_THROW_ON_ERROR), $id, $incident['status']]);
            if ($stmt->rowCount() !== 1) {
                throw new RuntimeException('Incident changed concurrently.');
            }
            sv_audit('incident_' . $action, "incident:$id", ['from' => $incident['status'], 'to' => $transition['to']]);
            $db->commit();
            sv_flash('ok', "Incident #$id is now {$transition['to']}. No token was revoked or rotated.");
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            error_log('StreamVault incident state change failed: ' . $e->getMessage());
            sv_flash('err', 'Could not update incident. Please try again.');
        }
        sv_redirect('incidents.php');
    }

    sv_flash('err', 'Unknown incident action.');
    sv_redirect('incidents.php');
}

$streams = $db->query('SELECT id, name FROM streams ORDER BY name COLLATE NOCASE')->fetchAll();
$incidents = $db->query('SELECT i.*, s.name AS stream_name FROM incidents i LEFT JOIN streams s ON s.id = i.stream_id ORDER BY i.detected_at DESC, i.id DESC')->fetchAll();

$pageTitle = 'Incidents';
$activeNav = 'incidents';
require __DIR__ . '/includes/layout_top.php';
?>
<h1>Incidents</h1>

<div class="sv-panel">
  <strong>Leak Checker is not implemented yet.</strong> You can record and triage incidents manually here.
  Confirming an incident does <strong>not</strong> revoke a token, rotate source credentials, or change the stream.
  An empty list does not mean that no leak exists.
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Record an incident</h2>
  <?php if (!$streams): ?>
    <p class="sv-help">Create a stream before recording an incident.</p>
  <?php else: ?>
    <form method="post">
      <?= sv_csrf_field() ?>
      <input type="hidden" name="action" value="create">
      <label>Stream</label>
      <select name="stream_id" required>
        <?php foreach ($streams as $stream): ?>
          <option value="<?= (int) $stream['id'] ?>"><?= h($stream['name']) ?></option>
        <?php endforeach; ?>
      </select>
      <label>Evidence URL (optional)</label>
      <input type="url" name="source_url" maxlength="2048" placeholder="https://example.com/leaked-playlist">
      <label>Notes (optional)</label>
      <textarea name="notes" maxlength="4000" placeholder="What was found and where?"></textarea>
      <button type="submit" class="btn-primary" style="margin-top:1rem;">Record incident</button>
    </form>
  <?php endif; ?>
</div>

<div class="sv-panel">
  <?php if (!$incidents): ?>
    <p class="sv-help">No incidents recorded.</p>
  <?php else: ?>
    <table>
      <tr><th>ID</th><th>Stream</th><th>Source</th><th>Status</th><th>Detected</th><th>Evidence / notes</th><th>Actions</th></tr>
      <?php foreach ($incidents as $i): ?>
        <tr>
          <td>#<?= (int) $i['id'] ?></td>
          <td><?= h($i['stream_name'] ?? 'Deleted stream') ?></td>
          <td class="mono"><?= h($i['source']) ?></td>
          <td><span class="badge <?= $i['status'] === 'confirmed' ? 'revoked' : 'private' ?>"><?= h($i['status']) ?></span></td>
          <td class="mono"><?= h($i['detected_at']) ?></td>
          <td>
            <?php if ($i['source_url']): ?><div class="mono"><?= h($i['source_url']) ?></div><?php endif; ?>
            <?php if ($i['notes']): ?><div><?= nl2br(h($i['notes'])) ?></div><?php endif; ?>
          </td>
          <td>
            <?php $allowed = in_array($i['status'], ['new', 'probable'], true) ? ['confirm' => 'Confirm', 'dismiss' => 'Dismiss'] : ($i['status'] === 'confirmed' ? ['resolve' => 'Resolve'] : []); ?>
            <?php foreach ($allowed as $value => $label): ?>
              <form method="post" style="display:inline;">
                <?= sv_csrf_field() ?>
                <input type="hidden" name="action" value="<?= h($value) ?>">
                <input type="hidden" name="incident_id" value="<?= (int) $i['id'] ?>">
                <button type="submit" class="btn-sm"><?= h($label) ?></button>
              </form>
            <?php endforeach; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
