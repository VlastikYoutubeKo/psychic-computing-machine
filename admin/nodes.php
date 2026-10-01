<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
$operator = sv_require_admin();
$db = sv_db();
$install = null; // ['name' => ..., 'token' => ...] shown exactly once
$error = '';

const SV_NODE_ONLINE_SECONDS = 45; // keep in sync with gateway nodeOnlineWindow

function sv_node_public_url_valid(string $u): bool
{
    if ($u === '' || strlen($u) > 255 || preg_match('/[\x00-\x20\x7f]/', $u)) return false;
    $p = parse_url($u);
    return is_array($p) && in_array(strtolower((string) ($p['scheme'] ?? '')), ['http', 'https'], true)
        && !empty($p['host']) && !isset($p['user']) && !isset($p['pass']) && !isset($p['query']) && !isset($p['fragment'])
        && (($p['path'] ?? '') === '' || ($p['path'] ?? '') === '/');
}

/** New secret: returns the one-time token; stores only its hash + encrypted copy. */
function sv_node_issue_secret(PDO $db, int $id): string
{
    $secret = bin2hex(random_bytes(32));
    $enc = sv_encrypt(sv_ensure_key_file(SV_KEY_FILE), $secret);
    $db->prepare('UPDATE nodes SET token_hash = ?, secret_enc = ? WHERE id = ?')->execute([hash('sha256', $secret), $enc, $id]);
    return 'svn_' . $id . '_' . $secret;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = (string) ($_POST['action'] ?? '');
    $id = filter_var($_POST['node_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    try {
        if ($action === 'create') {
            $name = trim((string) ($_POST['name'] ?? ''));
            $url = rtrim(trim((string) ($_POST['public_url'] ?? '')), '/');
            if ($name === '' || mb_strlen($name) > 64 || !sv_node_public_url_valid($url)) {
                $error = 'Enter a name (max 64 characters) and the node address like http://203.0.113.10:8090 (no path).';
            } else {
                // Placeholder credentials are replaced by sv_node_issue_secret right away.
                $db->prepare("INSERT INTO nodes (name, public_url, token_hash, secret_enc) VALUES (?, ?, 'pending', 'pending')")->execute([$name, $url]);
                $newId = (int) $db->lastInsertId();
                $install = ['name' => $name, 'token' => sv_node_issue_secret($db, $newId)];
                sv_audit('node_created', "node:$newId", ['name' => $name, 'public_url' => $url]);
            }
        } elseif ($id && $action === 'reissue') {
            $row = $db->prepare('SELECT name FROM nodes WHERE id = ?'); $row->execute([$id]);
            if ($name = $row->fetchColumn()) {
                $install = ['name' => (string) $name, 'token' => sv_node_issue_secret($db, $id)];
                sv_audit('node_token_reissued', "node:$id");
            }
        } elseif ($id && $action === 'toggle') {
            $db->prepare("UPDATE nodes SET status = CASE WHEN status = 'disabled' THEN 'pending' ELSE 'disabled' END WHERE id = ?")->execute([$id]);
            sv_audit('node_status_toggled', "node:$id");
            sv_flash('ok', 'Node status updated. Disabled nodes are refused immediately and get no viewers.');
            sv_redirect('nodes.php');
        } elseif ($id && $action === 'update_url') {
            $url = rtrim(trim((string) ($_POST['public_url'] ?? '')), '/');
            if (!sv_node_public_url_valid($url)) {
                $error = 'Invalid public URL.';
            } else {
                $db->prepare('UPDATE nodes SET public_url = ? WHERE id = ?')->execute([$url, $id]);
                sv_audit('node_url_updated', "node:$id", ['public_url' => $url]);
                sv_flash('ok', 'Public URL updated.');
                sv_redirect('nodes.php');
            }
        } elseif ($id && $action === 'delete') {
            $db->prepare('DELETE FROM nodes WHERE id = ?')->execute([$id]);
            sv_audit('node_deleted', "node:$id");
            sv_flash('ok', 'Node deleted. Its streams are served by this server again.');
            sv_redirect('nodes.php');
        }
    } catch (Throwable $e) {
        error_log('StreamVault node action failed: ' . $e->getMessage());
        $error = 'Node action failed.';
    }
}

$base = rtrim((string) ($db->query("SELECT value FROM settings WHERE key = 'gateway_base_url'")->fetchColumn() ?: ''), '/');
$nodes = $db->query("SELECT n.*, (SELECT COUNT(*) FROM streams s WHERE s.node_id = n.id) AS stream_count FROM nodes n ORDER BY n.name COLLATE NOCASE")->fetchAll();
$streamNames = [];
foreach ($db->query('SELECT id, name FROM streams') as $s) $streamNames[(int) $s['id']] = $s['name'];

function sv_fmt_bytes(float $b): string
{
    foreach (['B', 'KB', 'MB', 'GB', 'TB'] as $u) { if ($b < 1024) return sprintf($u === 'B' ? '%d %s' : '%.1f %s', $b, $u); $b /= 1024; }
    return sprintf('%.1f PB', $b);
}

$pageTitle = 'Nodes';
$activeNav = 'nodes';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Nodes</h1><p class="sv-help">Other servers that pull streams from their sources and relay them 24/7. Viewers keep using the same links on this domain: while a node is online this server fetches the stream from it and serves it; otherwise it serves the stream straight from the source. Viewer traffic always flows through this server; a node saves the source connection and can sit close to the source.</p></div></div>
<?php if ($error): ?><div class="sv-flash err"><?= h($error) ?></div><?php endif; ?>

<?php if ($install): ?>
<div class="sv-panel">
  <h2>Install “<?= h($install['name']) ?>”</h2>
  <p><strong>Shown only once.</strong> Run this on the new server (Debian/Ubuntu/Fedora/Alpine, x86_64). It installs ffmpeg, downloads the node binary from this server and starts it as a systemd service.</p>
  <?php $cmd = 'curl -fsSL ' . ($base ?: 'https://YOUR-STREAM-DOMAIN') . '/_sv/node/install.sh | sudo STREAMVAULT_NODE_TOKEN=' . $install['token'] . ' sh'; ?>
  <div class="sv-url-box"><span class="mono"><?= h($cmd) ?></span><button type="button" data-copy="<?= h($cmd) ?>" class="btn-sm">Copy</button></div>
  <p class="sv-help">The node listens on port 8090 (set STREAMVAULT_LISTEN before sh to change it). Only this server needs to reach it: allow port 8090 from this server's IP and block it for everyone else (a VPN/private address works too). Keep the token secret: it grants this node's streams, including source credentials. Lost it? Use “New token” below (the old one stops working immediately).</p>
  <?php if (!$base): ?><div class="sv-flash err">Set the stream base URL in Settings first; the install command needs it.</div><?php endif; ?>
</div>
<?php endif; ?>

<?php $gatewayBuild = (string) ($db->query("SELECT value FROM settings WHERE key = 'gateway_binary_sha256'")->fetchColumn() ?: ''); ?>
<div class="sv-panel">
  <h2>Add a node</h2>
  <form method="post">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="create">
    <label for="node-name">Name</label><input id="node-name" name="name" maxlength="64" placeholder="contabo-1" required>
    <label for="node-url">Address this server uses to reach the node</label><input id="node-url" name="public_url" maxlength="255" placeholder="http://203.0.113.10:8090 (or a VPN/private address)" required>
    <button class="btn-primary" type="submit">Create node and show install command</button>
  </form>
  <p class="sv-help">After it's online, assign streams to it in each stream's settings (“Relay node”).</p>
</div>

<div class="sv-panel">
  <?php if (!$nodes): ?><p class="sv-help">No nodes yet.</p><?php else: ?>
  <table>
    <tr><th>Node</th><th>State</th><th>Load / memory</th><th>Traffic (since start)</th><th>Streams</th><th></th></tr>
    <?php foreach ($nodes as $n):
      $st = json_decode((string) ($n['last_status_json'] ?? ''), true) ?: [];
      $seen = $n['last_seen_at'] ? strtotime($n['last_seen_at']) : 0;
      $online = $n['status'] === 'active' && $seen && time() - $seen <= SV_NODE_ONLINE_SECONDS;
      $state = $n['status'] === 'disabled' ? 'disabled' : ($online ? 'online' : ($n['status'] === 'pending' ? 'waiting for first contact' : 'offline'));
      $badge = $online ? 'active' : ($n['status'] === 'disabled' ? 'revoked' : 'private'); ?>
      <tr>
        <td><strong><?= h($n['name']) ?></strong><div class="mono sv-help"><?= h($n['public_url']) ?></div><?php if (!empty($st['version'])): ?><div class="sv-help">v<?= h((string) $st['version']) ?><?php if (!empty($st['binary_sha256'])): ?> · build <span class="mono"><?= h(substr((string) $st['binary_sha256'], 0, 8)) ?></span><?php endif; ?></div><?php endif; ?>
          <?php if ($gatewayBuild !== '' && $online): ?>
            <?php if (($st['binary_sha256'] ?? '') === $gatewayBuild): ?><span class="badge active">up to date</span>
            <?php elseif (!empty($st['binary_sha256'])): ?><span class="badge private">updating</span><div class="sv-help">picks up this server's build within ~5 minutes</div>
            <?php else: ?><span class="badge revoked">no auto-update</span><div class="sv-help">run the install command on the node once more</div><?php endif; ?>
          <?php endif; ?></td>
        <td><span class="badge <?= h($badge) ?>"><?= h($state) ?></span><?php if ($seen): ?><div class="sv-help">last seen <?= h($n['last_seen_at']) ?></div><?php endif; ?></td>
        <td><?php if ($st): ?>load <?= h(number_format((float) ($st['load1'] ?? 0), 2)) ?> / <?= (int) ($st['cpus'] ?? 0) ?> CPU<br>
          <?php $tot = (int) ($st['mem_total_kb'] ?? 0); $av = (int) ($st['mem_available_kb'] ?? 0); if ($tot > 0): ?>RAM <?= h(sv_fmt_bytes(($tot - $av) * 1024)) ?> / <?= h(sv_fmt_bytes($tot * 1024)) ?><?php endif; ?><?php else: ?><span class="sv-help">—</span><?php endif; ?></td>
        <td><?php if ($st): ?>↓ <?= h(sv_fmt_bytes((float) ($st['net_rx_bytes'] ?? 0))) ?><br>↑ <?= h(sv_fmt_bytes((float) ($st['net_tx_bytes'] ?? 0))) ?><?php else: ?><span class="sv-help">—</span><?php endif; ?></td>
        <td><?= (int) $n['stream_count'] ?> assigned
          <?php foreach (($st['streams'] ?? []) as $rs): if (!is_array($rs)) continue; ?>
            <div class="sv-help"><?= h($streamNames[(int) ($rs['id'] ?? 0)] ?? ('#' . (int) ($rs['id'] ?? 0))) ?>: <?= h((string) ($rs['state'] ?? '?')) ?>, <?= (int) ($rs['viewers'] ?? 0) ?> viewers<?php if (!empty($rs['detail'])): ?> — <?= h((string) $rs['detail']) ?><?php endif; ?></div>
          <?php endforeach; ?></td>
        <td>
          <form method="post" style="display:inline;"><?= sv_csrf_field() ?><input type="hidden" name="action" value="toggle"><input type="hidden" name="node_id" value="<?= (int) $n['id'] ?>"><button type="submit" class="btn-sm"><?= $n['status'] === 'disabled' ? 'Enable' : 'Disable' ?></button></form>
          <form method="post" style="display:inline;" data-confirm="Issue a new token? The node stops working until you reinstall it with the new command."><?= sv_csrf_field() ?><input type="hidden" name="action" value="reissue"><input type="hidden" name="node_id" value="<?= (int) $n['id'] ?>"><button type="submit" class="btn-sm">New token</button></form>
          <form method="post" style="display:inline;" data-confirm="Delete this node? Its streams go back to this server."><?= sv_csrf_field() ?><input type="hidden" name="action" value="delete"><input type="hidden" name="node_id" value="<?= (int) $n['id'] ?>"><button type="submit" class="btn-sm btn-danger">Delete</button></form>
          <form method="post" style="margin-top:.4rem;"><?= sv_csrf_field() ?><input type="hidden" name="action" value="update_url"><input type="hidden" name="node_id" value="<?= (int) $n['id'] ?>"><input name="public_url" value="<?= h($n['public_url']) ?>" aria-label="Public URL of <?= h($n['name']) ?>" maxlength="255"><button type="submit" class="btn-sm">Save URL</button></form>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>
  <?php endif; ?>
</div>
<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
