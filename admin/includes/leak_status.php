<?php
declare(strict_types=1);

/** @return array{latest: ?array, last_success: ?array, requested_at: ?string} */
function sv_leak_status(PDO $db, ?array $operator = null): array
{
    $owner = $operator && $operator['role'] === 'user' ? (int) $operator['id'] : null;
    $where = $owner === null ? 'owner_id IS NULL' : 'owner_id = ?';
    $latestStmt = $db->prepare("SELECT * FROM leak_checker_runs WHERE $where ORDER BY id DESC LIMIT 1");
    $successStmt = $db->prepare("SELECT * FROM leak_checker_runs WHERE $where AND finished_at IS NOT NULL AND error IS NULL ORDER BY id DESC LIMIT 1");
    $latestStmt->execute($owner === null ? [] : [$owner]);
    $successStmt->execute($owner === null ? [] : [$owner]);
    $latest = $latestStmt->fetch() ?: null;
    $lastSuccess = $successStmt->fetch() ?: null;
    if ($owner === null) $requested = $db->query("SELECT value FROM settings WHERE key = 'leak_scan_requested_at'")->fetchColumn();
    else { $stmt = $db->prepare('SELECT leak_scan_requested_at FROM operators WHERE id=?'); $stmt->execute([$owner]); $requested = $stmt->fetchColumn(); }
    return ['latest' => $latest, 'last_success' => $lastSuccess, 'requested_at' => $requested ?: null];
}

function sv_render_leak_status(PDO $db, ?array $operator = null): void
{
    $status = sv_leak_status($db, $operator);
    $latest = $status['latest'];
    $success = $status['last_success'];
    $requested = $status['requested_at'];
    $baseUrl = $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: '';
    $providers = $latest ? json_decode($latest['providers_run'], true) : [];
    $providers = is_array($providers) ? array_filter($providers, 'is_string') : [];
    ?>
    <div class="sv-panel">
      <strong><?= $operator && $operator['role'] === 'user' ? 'Your GitHub token coverage' : 'Global Leak Checker coverage' ?></strong>
      <p class="sv-help">Only GitHub scanning is supported in this phase. GitLab and public playlist scanning are not implemented. No scan proves that a stream is safe.</p>
      <p class="sv-help">Configured stream base URL: <?= $baseUrl ? h($baseUrl) : 'not configured — no search anchors can be built' ?>.</p>
      <?php if (!$latest): ?>
        <p>No scan has run yet. There is no automated coverage result.</p>
      <?php else: ?>
        <p>Latest run #<?= (int) $latest['id'] ?>:
          started <?= h($latest['started_at']) ?>;
          <?= $latest['finished_at'] ? 'finished ' . h($latest['finished_at']) : 'still running or interrupted' ?>.
          Streams checked: <?= (int) $latest['streams_checked'] ?>;
          queries: <?= (int) $latest['queries_made'] ?>;
          new findings: <?= (int) $latest['findings_created'] ?>.
        </p>
        <p class="sv-help">Providers reported: <?= h($providers ? implode(', ', $providers) : 'none') ?>.</p>
        <?php if ($latest['error']): ?><p class="sv-flash err">Last run error or partial coverage: <?= h($latest['error']) ?></p><?php endif; ?>
        <?php if ($success): ?><p class="sv-help">Last successful run: <?= h($success['finished_at']) ?>.</p><?php else: ?><p class="sv-help">No successful run recorded.</p><?php endif; ?>
      <?php endif; ?>
      <?php if ($requested && (!$latest || strcmp($requested, (string) $latest['started_at']) > 0)): ?>
        <p class="sv-help">A manual scan request is queued since <?= h($requested) ?>; it has not started yet.</p>
      <?php endif; ?>
    </div>
    <?php
}
