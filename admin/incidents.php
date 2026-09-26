<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/leak_status.php';
require_once __DIR__ . '/includes/github_reply.php';
require_once __DIR__ . '/includes/secret_box.php';
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
            sv_flash('ok', "Incident #$id recorded. Click Confirm to revoke the leaked link.");
        }
        sv_redirect('incidents.php');
    }

    if ($action === 'github_reply') {
        $id = filter_var($_POST['incident_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $stmt = $db->prepare('SELECT id, source_url, actions_taken FROM incidents WHERE id = ?');
        $stmt->execute([$id ?: 0]);
        $incident = $stmt->fetch();
        $parsed = $incident ? sv_parse_issue_url((string) $incident['source_url']) : null;
        $encToken = $db->query("SELECT value FROM settings WHERE key = 'github_token_enc'")->fetchColumn();
        $baseUrl = (string) $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn();
        if (!$parsed) {
            sv_flash('err', 'This incident has no GitHub issue or pull request to reply to.');
        } elseif (!$encToken || $baseUrl === '') {
            sv_flash('err', 'Configure the GitHub token and stream base URL first.');
        } else {
            $dup = $db->prepare('SELECT 1 FROM leak_replies WHERE source_url = ?');
            $dup->execute([$incident['source_url']]);
            if ($dup->fetchColumn()) {
                sv_flash('err', 'A reply was already posted to this issue.');
            } else {
                $token = sv_decrypt(sv_load_key(SV_KEY_FILE), (string) $encToken);
                [$ok, $result] = sv_post_github_comment($token, $parsed[0], $parsed[1], $parsed[2], sv_notice_body($baseUrl));
                if (!$ok) {
                    sv_flash('err', 'Reply failed: ' . $result . '.');
                } else {
                    $db->beginTransaction();
                    $db->prepare('INSERT OR IGNORE INTO leak_replies (source_url, incident_id, comment_url, actor) VALUES (?, ?, ?, ?)')
                        ->execute([$incident['source_url'], $incident['id'], $result, 'operator:' . $operator['id']]);
                    $history = json_decode($incident['actions_taken'] ?? '[]', true);
                    $history = is_array($history) ? $history : [];
                    $history[] = ['at' => gmdate('c'), 'actor' => 'operator:' . $operator['id'], 'action' => 'github_reply', 'target' => $result];
                    $db->prepare('UPDATE incidents SET actions_taken = ? WHERE id = ?')->execute([json_encode($history), $incident['id']]);
                    $db->commit();
                    sv_audit('incident_github_reply', 'incident:' . $incident['id'], ['comment' => $result]);
                    sv_flash('ok', 'Reply posted on GitHub.');
                }
            }
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
            $stmt = $db->prepare('SELECT status, actions_taken, access_token_id, stream_id FROM incidents WHERE id = ?');
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
            // Confirming a leak revokes exactly the leaked link: the token the
            // checker identified, else the access point its findings point at.
            // A manual incident without either has nothing specific to revoke.
            $revoked = null;
            if ($action === 'confirm') {
                if ($incident['access_token_id']) {
                    $r = $db->prepare("UPDATE access_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_reason = 'leak_confirmed' WHERE id = ? AND revoked_at IS NULL");
                    $r->execute([$incident['access_token_id']]);
                    $revoked = $r->rowCount() ? 'token:' . $incident['access_token_id'] : null;
                } else {
                    $f = $db->prepare('SELECT access_point_id FROM leak_findings WHERE incident_id = ? AND access_point_id IS NOT NULL ORDER BY id DESC LIMIT 1');
                    $f->execute([$id]);
                    $apId = $f->fetchColumn();
                    if ($apId) {
                        $r = $db->prepare("UPDATE access_points SET status = 'revoked', revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = ? AND status = 'active'");
                        $r->execute([$apId]);
                        $revoked = $r->rowCount() ? 'access_point:' . $apId : null;
                    }
                }
                if ($revoked) {
                    $history[count($history) - 1]['action'] = 'revoked';
                    $history[count($history) - 1]['target'] = $revoked;
                }
            }
            $stmt = $db->prepare('UPDATE incidents SET status = ?, actions_taken = ? WHERE id = ? AND status = ?');
            $stmt->execute([$transition['to'], json_encode($history, JSON_THROW_ON_ERROR), $id, $incident['status']]);
            if ($stmt->rowCount() !== 1) {
                throw new RuntimeException('Incident changed concurrently.');
            }
            sv_audit('incident_' . $action, "incident:$id", ['from' => $incident['status'], 'to' => $transition['to'], 'revoked' => $revoked ?? null]);
            $db->commit();
            if ($action === 'confirm') {
                sv_flash('ok', $revoked
                    ? "Incident #$id confirmed and the leaked link ($revoked) was revoked. Players now get the \"Stream unavailable\" screen."
                    : "Incident #$id confirmed. There was no specific active link to revoke (already revoked, or a manual incident without one); revoke it from the stream page if needed.");
            } else {
                sv_flash('ok', "Incident #$id is now {$transition['to']}.");
            }
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
$incidents = $db->query('SELECT i.*, s.name AS stream_name, r.comment_url AS reply_url FROM incidents i LEFT JOIN streams s ON s.id = i.stream_id LEFT JOIN leak_replies r ON r.source_url = i.source_url ORDER BY i.detected_at DESC, i.id DESC')->fetchAll();
$replyBase = (string) ($db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: '');

$pageTitle = 'Leaks';
$activeNav = 'incidents';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Leaks</h1><p class="sv-help">Incidents, scan coverage, watched sources and automatic replies.</p></div><a class="btn" href="#checker">Checker controls</a></div>
<div class="sv-panel">You can record and triage incidents manually here. Confirming an incident will
  revoke the leaked link (the identified token, or the access point that was found). Links the Leak Checker
  finds on GitHub are revoked automatically, and a notice is posted on issues in allowlisted repositories.</div>

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
        <tr id="incident-<?= (int) $i['id'] ?>">
          <td>#<?= (int) $i['id'] ?></td>
          <td><?= h($i['stream_name'] ?? 'Deleted stream') ?></td>
          <td class="mono"><?= h($i['source']) ?></td>
          <td><span class="badge <?= $i['status'] === 'confirmed' ? 'revoked' : 'private' ?>"><?= h($i['status']) ?></span></td>
          <td class="mono"><?= h($i['detected_at']) ?></td>
          <td>
            <?php if ($i['source_url']): ?><div class="mono"><?= h($i['source_url']) ?></div><?php endif; ?>
            <?php if ($i['notes']): ?><div><?= nl2br(h($i['notes'])) ?></div><?php endif; ?>
            <?php foreach ((json_decode($i['actions_taken'] ?? '[]', true) ?: []) as $act): ?>
              <?php if (is_array($act) && ($act['action'] ?? '') === 'auto_revoked'): ?><div class="sv-help">Auto-revoked <?= h($act['target'] ?? '') ?> at <?= h($act['at'] ?? '') ?></div><?php endif; ?>
            <?php endforeach; ?>
            <?php if (!empty($i['reply_url'])): ?><div><a href="<?= h($i['reply_url']) ?>" target="_blank" rel="noopener noreferrer">GitHub reply posted</a></div><?php endif; ?>
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
            <?php if (empty($i['reply_url']) && sv_parse_issue_url((string) $i['source_url']) && $replyBase !== ''): ?>
              <form method="post" style="display:inline;" data-confirm="<?= h("Post this public comment on GitHub?\n\n" . sv_notice_body($replyBase)) ?>">
                <?= sv_csrf_field() ?>
                <input type="hidden" name="action" value="github_reply">
                <input type="hidden" name="incident_id" value="<?= (int) $i['id'] ?>">
                <button type="submit" class="btn-sm">Reply on GitHub</button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<?php require __DIR__ . '/includes/leak_panels.php'; ?>
<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
