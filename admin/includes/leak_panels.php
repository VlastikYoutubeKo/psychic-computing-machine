<?php
$baseUrl = $db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: '';
$githubTokenSet = (bool) $db->query("SELECT 1 FROM settings WHERE key = 'github_token_enc'")->fetchColumn();
$replyAllowlist = (string) ($db->query("SELECT value FROM settings WHERE key = 'github_reply_allowlist'")->fetchColumn() ?: '');
$sources = $db->query('SELECT id, provider, identifier, enabled, last_scanned_at FROM leak_sources ORDER BY provider, identifier')->fetchAll();
sv_render_leak_status($db);
?>
<div id="checker"></div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Request a scan</h2>
  <p class="sv-help">The checker is a separate one-shot process. This queues a request; the timer checks every 5 minutes, so a scan starts within about 5 minutes; it does not run a command inside the web container. Check the run status above to see when it actually starts and whether it succeeds.</p>
  <form action="settings.php" method="post">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="request_leak_scan">
    <button type="submit" class="btn-primary" <?= $githubTokenSet && $baseUrl !== '' ? '' : 'disabled' ?>>Scan now</button>
  </form>
</div>

<div class="sv-panel">
  <h2 style="margin-top:0;">Automatic GitHub replies</h2>
  <p class="sv-help">When the checker finds a link, it revokes it automatically and, only for issues/PRs in these repositories, posts a public comment with the "Stream unavailable" image. Everywhere else, reply from the incident page after reviewing. The GitHub token needs the <code>public_repo</code> scope (classic token) to comment.</p>
  <form action="settings.php" method="post">
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
  <form action="settings.php" method="post">
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
              <form action="settings.php" method="post" style="display:inline;">
                <?= sv_csrf_field() ?><input type="hidden" name="action" value="toggle_leak_source"><input type="hidden" name="source_id" value="<?= (int) $source['id'] ?>">
                <button type="submit" class="btn-sm"><?= $source['enabled'] ? 'Disable' : 'Enable' ?></button>
              </form>
              <form action="settings.php" method="post" style="display:inline;" data-confirm="Delete this watched source?">
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
