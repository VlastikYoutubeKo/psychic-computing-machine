<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
require_once __DIR__ . '/includes/xtream.php';
$operator = sv_require_login();
$db = sv_db();
$isAdmin = sv_is_admin($operator);

// Importing thousands of channels' worth of JSON takes a while and some memory.
@set_time_limit(180);
@ini_set('memory_limit', '768M');

const SV_XTREAM_SESSION_TTL = 1800;

// The connection is remembered in the session (password encrypted with the
// app key) so choosing channels doesn't need the password sent back and forth.
$conn = $_SESSION['sv_xtream'] ?? null;
// It belongs to the operator who made it: a different account logging in
// within the same browser session must not inherit provider credentials.
if (!is_array($conn) || (int) ($conn['at'] ?? 0) < time() - SV_XTREAM_SESSION_TTL
    || (int) ($conn['operator_id'] ?? 0) !== (int) $operator['id']) {
    $conn = null;
    unset($_SESSION['sv_xtream']);
}

// The gateway only plays MPEG-TS sources for accounts allowed to remux;
// everyone else can use the panel's HLS output.
$canTs = $isAdmin || !empty($operator['allow_remux']);

$errors = [];
$form = ['server' => '', 'username' => '', 'format' => $canTs ? 'ts' : 'm3u8'];
$account = null;
$channels = null;

$connPassword = function (array $conn): string {
    return sv_decrypt(sv_ensure_key_file(SV_KEY_FILE), (string) $conn['password_enc']);
};

// Current view of the channel list: search text, category ('*' = all) and page.
$view = static function (array $src): array {
    $q = trim((string) ($src['q'] ?? ''));
    $cat = array_key_exists('cat', $src) ? (string) $src['cat'] : '*';
    return ['q' => mb_substr($q, 0, 100, 'UTF-8'), 'cat' => mb_substr($cat, 0, 80, 'UTF-8'), 'page' => max(1, (int) ($src['page'] ?? 1))];
};
$viewUrl = static function (array $v): string {
    $params = [];
    if ($v['q'] !== '') $params['q'] = $v['q'];
    if ($v['cat'] !== '*') $params['cat'] = $v['cat'];
    if ($v['page'] > 1) $params['page'] = $v['page'];
    return 'xtream_import.php' . ($params ? '?' . http_build_query($params) : '');
};
$cur = $view($_GET);
$forceRefresh = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'disconnect') {
        if ($conn) {
            sv_xtream_cache_clear((int) $operator['id'], $conn['base'], $conn['username']);
        }
        unset($_SESSION['sv_xtream']);
        sv_redirect('xtream_import.php');
    }

    if ($action === 'refresh' && $conn) {
        $forceRefresh = true; // re-fetch the channel list from the panel below
    }
    if ($action === 'import') {
        $cur = $view($_POST); // come back to the same search/category/page
    }

    if ($action === 'connect') {
        $form['server'] = trim((string) ($_POST['server'] ?? ''));
        $form['username'] = trim((string) ($_POST['username'] ?? ''));
        $form['format'] = ($_POST['format'] ?? '') === 'ts' && $canTs ? 'ts' : 'm3u8';
        $password = (string) ($_POST['password'] ?? '');
        $base = sv_xtream_base($form['server']);
        if ($base === null) {
            $errors[] = 'Enter the server address as http://host:port.';
        }
        if ($form['username'] === '' || $password === '') {
            $errors[] = 'Username and password are required.';
        }
        if (!$errors) {
            try {
                $account = sv_xtream_account($base, $form['username'], $password, $isAdmin);
                $conn = [
                    'base' => $base,
                    'username' => $form['username'],
                    'password_enc' => sv_encrypt(sv_ensure_key_file(SV_KEY_FILE), $password),
                    'format' => $form['format'],
                    'account' => $account,
                    'operator_id' => (int) $operator['id'],
                    'at' => time(),
                ];
                $_SESSION['sv_xtream'] = $conn;
                sv_audit('xtream_connected', null, ['server' => $base]);
                sv_redirect('xtream_import.php');
            } catch (RuntimeException $e) {
                $errors[] = $e->getMessage();
            }
        }
    }

    if ($action === 'import') {
        if (!$conn) {
            sv_flash('err', 'The Xtream connection expired. Connect again.');
            sv_redirect('xtream_import.php');
        }
        $ids = array_values(array_unique(array_filter(array_map('intval', (array) ($_POST['ids'] ?? [])), fn ($i) => $i > 0)));
        if (!$ids) {
            $errors[] = 'Select at least one channel.';
        } elseif (count($ids) > SV_XTREAM_MAX_IMPORT) {
            $errors[] = 'Import at most ' . SV_XTREAM_MAX_IMPORT . ' channels at a time.';
        }
        // Regular accounts may only use public sources (the gateway enforces
        // this at connect time as well).
        if (!$errors && !$isAdmin && ($srcErr = sv_public_source_error($conn['base'])) !== null) {
            $errors[] = $srcErr;
        }
        if (!$errors && $conn['format'] === 'ts' && !$canTs) {
            $errors[] = 'Your account cannot play MPEG-TS sources. Connect again and choose HLS.';
        }
        if (!$errors) {
            try {
                $password = $connPassword($conn);
                // Names come from the server-side channel list, not from the submitted form.
                $all = sv_xtream_channels_cached((int) $operator['id'], $conn['base'], $conn['username'], $password, $isAdmin)['channels'];
                $key = sv_ensure_key_file(SV_KEY_FILE);
                $sourceType = $conn['format'] === 'm3u8' ? 'hls' : 'mpegts';
                // A channel is "already added" only for the same panel account;
                // importing it again refreshes the stored password (rotated line).
                $exists = $db->prepare('SELECT id FROM streams WHERE source_url = ? AND owner_id IS ? AND source_username IS ?');
                $refresh = $db->prepare('UPDATE streams SET source_password_enc = ? WHERE id = ?');
                $count = $db->prepare('SELECT COUNT(*) FROM streams WHERE owner_id = ?');
                $insert = $db->prepare('INSERT INTO streams (name, description, source_type, source_url, source_username,
                    source_password_enc, rotation_mode, replacement_reason, owner_id) VALUES (?,?,?,?,?,?,?,?,?)');
                $created = $skipped = $unknown = 0;
                $limitHit = false;
                foreach ($ids as $sid) {
                    if (!isset($all[$sid])) {
                        $unknown++;
                        continue;
                    }
                    $url = sv_xtream_source_url($conn['base'], $sid, $conn['format']);
                    $exists->execute([$url, $operator['id'], $conn['username']]);
                    $existingIds = $exists->fetchAll(PDO::FETCH_COLUMN);
                    if ($existingIds) {
                        foreach ($existingIds as $eid) {
                            $refresh->execute([sv_encrypt($key, $password), (int) $eid]);
                        }
                        $skipped++;
                        continue;
                    }
                    if (!$isAdmin) {
                        $count->execute([$operator['id']]);
                        if ((int) $count->fetchColumn() >= (int) $operator['max_streams']) {
                            $limitHit = true;
                            break;
                        }
                    }
                    $ch = $all[$sid];
                    $desc = 'Xtream Codes' . ($ch['category'] !== '' ? ' · ' . $ch['category'] : '');
                    try {
                        $insert->execute([$ch['name'], $desc, $sourceType, $url, $conn['username'],
                            sv_encrypt($key, $password), 'auto', 'unauthorized_redistribution', $operator['id']]);
                    } catch (PDOException $e) {
                        $limitHit = true; // quota trigger
                        break;
                    }
                    $created++;
                }
                sv_audit('xtream_imported', null, ['server' => $conn['base'], 'created' => $created, 'skipped' => $skipped]);
                $msg = "Imported $created stream" . ($created === 1 ? '' : 's') . '.';
                if ($skipped) $msg .= " $skipped already existed (password refreshed).";
                if ($unknown) $msg .= " $unknown no longer offered by the server.";
                if ($limitHit) $msg .= ' Stopped: your stream limit is reached.';
                if ($created) $msg .= ' Add an access point to each stream you want to share (Streams page).';
                sv_flash($created || !$limitHit ? 'ok' : 'err', $msg);
                sv_redirect($viewUrl($cur));
            } catch (RuntimeException $e) {
                $errors[] = $e->getMessage();
            }
        }
    }
}

$fetchedAt = null;
$categories = [];   // name => channel count
$rows = [];         // the page of channels to render
$matches = 0;
$pages = 1;
if ($conn && $channels === null) {
    $account = $conn['account'] ?? null;
    try {
        $list = sv_xtream_channels_cached((int) $operator['id'], $conn['base'], $conn['username'], $connPassword($conn), $isAdmin, $forceRefresh);
        $channels = $list['channels'];
        $fetchedAt = $list['fetched_at'];
    } catch (RuntimeException $e) {
        $errors[] = $e->getMessage();
        $channels = [];
    }
    // Filter and page on the server: the browser gets SV_XTREAM_PAGE_SIZE rows,
    // never the whole list (56 000 table rows freeze a phone).
    $needle = mb_strtolower($cur['q'], 'UTF-8');
    $first = ($cur['page'] - 1) * SV_XTREAM_PAGE_SIZE;
    foreach ($channels as $sid => $ch) {
        $categories[$ch['category']] = ($categories[$ch['category']] ?? 0) + 1;
        if ($cur['cat'] !== '*' && $ch['category'] !== $cur['cat']) {
            continue;
        }
        if ($needle !== '' && mb_stripos($ch['name'], $needle, 0, 'UTF-8') === false) {
            continue;
        }
        if ($matches >= $first && count($rows) < SV_XTREAM_PAGE_SIZE) {
            $rows[$sid] = $ch;
        }
        $matches++;
    }
    $pages = max(1, (int) ceil($matches / SV_XTREAM_PAGE_SIZE));
    if ($cur['page'] > $pages) { // e.g. a stale page number after narrowing the search
        sv_redirect($viewUrl(['page' => $pages] + $cur));
    }
    uksort($categories, fn ($a, $b) => strnatcasecmp((string) $a, (string) $b));
}

$existing = [];
if ($conn) {
    $st = $db->prepare('SELECT source_url FROM streams WHERE owner_id IS ? AND source_username IS ? AND source_url LIKE ?');
    $st->execute([$operator['id'], $conn['username'], $conn['base'] . '/live/{username}/{password}/%']);
    $existing = array_flip($st->fetchAll(PDO::FETCH_COLUMN));
}

$pageTitle = 'Import from Xtream Codes';
$activeNav = 'streams';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Import from Xtream Codes</h1><p class="sv-help">Pick live channels from an Xtream Codes server you have an account on. Each channel becomes a stream.</p></div><a href="streams.php" class="btn">Back to streams</a></div>

<?php foreach ($errors as $e): ?><div class="sv-flash err"><?= h($e) ?></div><?php endforeach; ?>

<?php if (!$conn): ?>
<div class="sv-panel">
  <form method="post" autocomplete="off">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="connect">
    <label for="xt-server">Server</label>
    <input id="xt-server" type="text" name="server" value="<?= h($form['server']) ?>" placeholder="http://example.com:8080" required>
    <div class="sv-help">The address from your provider, with the port. No <code>/get.php</code> or <code>/player_api.php</code> needed.</div>

    <label for="xt-username">Username</label>
    <input id="xt-username" type="text" name="username" value="<?= h($form['username']) ?>" autocomplete="off" required>

    <label for="xt-password">Password</label>
    <input id="xt-password" type="password" name="password" autocomplete="new-password" required>
    <div class="sv-help">Stored encrypted with each imported stream. It is never shown again and never appears in a stream's source URL.</div>

    <label for="xt-format">Stream format</label>
    <select id="xt-format" name="format">
      <?php if ($canTs): ?><option value="ts" <?= $form['format'] === 'ts' ? 'selected' : '' ?>>MPEG-TS (.ts) – works with every Xtream server</option><?php endif; ?>
      <option value="m3u8" <?= $form['format'] === 'm3u8' ? 'selected' : '' ?>>HLS (.m3u8) – only if the server offers it</option>
    </select>
    <?php if (!$canTs): ?><div class="sv-help">MPEG-TS sources need the remux permission, which your account does not have. Ask the administrator if the server has no HLS output.</div><?php endif; ?>

    <button type="submit" class="btn-primary" style="margin-top:1.5rem;">Connect and list channels</button>
  </form>
</div>
<?php else: ?>
<div class="sv-panel">
  <table>
    <tr><th>Server</th><td class="mono"><?= h($conn['base']) ?></td></tr>
    <tr><th>Username</th><td class="mono"><?= h($conn['username']) ?></td></tr>
    <tr><th>Account</th><td><?= h($account['status'] ?? 'unknown') ?><?= !empty($account['expires']) ? ', expires ' . h($account['expires']) : '' ?></td></tr>
    <tr><th>Connections</th><td><?php if (($account['max_connections'] ?? null) !== null): ?>
        <?= (int) $account['max_connections'] ?> allowed<?= ($account['active_connections'] ?? null) !== null ? ', ' . (int) $account['active_connections'] . ' in use now' : '' ?>
        <div class="sv-help">Every stream that is playing uses one connection, however many viewers it has. Importing more channels than this is fine; playing more of them at once is not.</div>
      <?php else: ?>not reported by the server<?php endif; ?></td></tr>
    <tr><th>Format</th><td class="mono"><?= $conn['format'] === 'm3u8' ? 'HLS (.m3u8)' : 'MPEG-TS (.ts)' ?></td></tr>
  </table>
  <form method="post" style="margin-top:1rem;">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="disconnect">
    <button type="submit" class="btn">Use a different account</button>
  </form>
  <form method="post" style="margin-top:.5rem;">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="refresh">
    <button type="submit" class="btn">Reload channel list from the server</button>
  </form>
</div>

<div class="sv-panel">
  <?php if (!$channels): ?>
    <p class="sv-help">The server lists no live channels for this account.</p>
  <?php else: ?>
  <form method="get" action="xtream_import.php" style="display:flex;gap:.75rem;flex-wrap:wrap;align-items:end;">
    <div style="flex:2 1 14rem;"><label for="xt-filter">Search</label><input id="xt-filter" type="search" name="q" value="<?= h($cur['q']) ?>" placeholder="Channel name" autocomplete="off"></div>
    <div style="flex:1 1 12rem;"><label for="xt-cat">Category</label>
      <select id="xt-cat" name="cat">
        <option value="*">All categories (<?= count($channels) ?> channels)</option>
        <?php foreach ($categories as $c => $n): ?><option value="<?= h((string) $c) ?>" <?= $cur['cat'] === (string) $c ? 'selected' : '' ?>><?= h((string) $c === '' ? '(no category)' : (string) $c) ?> (<?= (int) $n ?>)</option><?php endforeach; ?>
      </select></div>
    <div><button type="submit" class="btn-primary">Show</button> <?php if ($cur['q'] !== '' || $cur['cat'] !== '*'): ?><a class="btn" href="xtream_import.php">Reset</a><?php endif; ?></div>
  </form>
  <p class="sv-help" aria-live="polite">
    <?php if ($matches === 0): ?>No channels match.<?php else: ?>
      Showing <?= ($cur['page'] - 1) * SV_XTREAM_PAGE_SIZE + 1 ?>–<?= ($cur['page'] - 1) * SV_XTREAM_PAGE_SIZE + count($rows) ?> of <?= (int) $matches ?> matching channel<?= $matches === 1 ? '' : 's' ?>.
    <?php endif; ?>
    <?php if ($fetchedAt): ?>List loaded from the server <?= h(gmdate('H:i', $fetchedAt)) ?> UTC.<?php endif; ?>
  </p>

  <?php if ($rows): ?>
  <form method="post" id="xt-import">
    <?= sv_csrf_field() ?>
    <input type="hidden" name="action" value="import">
    <input type="hidden" name="q" value="<?= h($cur['q']) ?>">
    <?php if ($cur['cat'] !== '*'): ?><input type="hidden" name="cat" value="<?= h($cur['cat']) ?>"><?php endif; ?>
    <input type="hidden" name="page" value="<?= (int) $cur['page'] ?>">
    <p><button type="button" class="btn" id="xt-all">Select all on this page</button> <button type="button" class="btn" id="xt-none">Clear</button> <span class="sv-help" id="xt-count"></span></p>
    <table id="xt-table">
      <tr><th style="width:2.5rem;"></th><th>Channel</th><th>Category</th></tr>
      <?php foreach ($rows as $sid => $ch):
          $have = isset($existing[sv_xtream_source_url($conn['base'], (int) $sid, $conn['format'])]); ?>
        <tr>
          <td><input type="checkbox" name="ids[]" value="<?= (int) $sid ?>" id="xt-<?= (int) $sid ?>" <?= $have ? 'disabled' : '' ?>></td>
          <td><label for="xt-<?= (int) $sid ?>" style="margin:0;font-weight:inherit;"><?= h($ch['name']) ?></label><?= $have ? ' <span class="badge resolved">already added</span>' : '' ?></td>
          <td><?= h($ch['category']) ?></td>
        </tr>
      <?php endforeach; ?>
    </table>
    <button type="submit" class="btn-primary" style="margin-top:1rem;" id="xt-submit">Import selected</button>
    <span class="sv-help">Imports the channels ticked on this page; search or change page for more.</span>
  </form>
  <?php if ($pages > 1): ?>
  <p style="margin-top:1rem;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap;">
    <?php if ($cur['page'] > 1): ?><a class="btn" href="<?= h($viewUrl(['page' => $cur['page'] - 1] + $cur)) ?>">← Previous</a><?php endif; ?>
    <span class="sv-help">Page <?= (int) $cur['page'] ?> of <?= (int) $pages ?></span>
    <?php if ($cur['page'] < $pages): ?><a class="btn" href="<?= h($viewUrl(['page' => $cur['page'] + 1] + $cur)) ?>">Next →</a><?php endif; ?>
  </p>
  <?php endif; ?>
  <script>
  (function () {
    var boxes = Array.prototype.slice.call(document.querySelectorAll('#xt-table input[type=checkbox]'));
    var count = document.getElementById('xt-count'), submit = document.getElementById('xt-submit');
    function update() {
      var picked = boxes.filter(function (b) { return b.checked; }).length;
      count.textContent = picked + ' selected';
      submit.disabled = picked === 0;
    }
    document.getElementById('xt-table').addEventListener('change', update);
    document.getElementById('xt-all').addEventListener('click', function () {
      boxes.forEach(function (b) { if (!b.disabled) b.checked = true; }); update();
    });
    document.getElementById('xt-none').addEventListener('click', function () {
      boxes.forEach(function (b) { b.checked = false; }); update();
    });
    update();
  })();
  </script>
  <?php endif; ?>
  <?php endif; ?>
</div>
<?php endif; ?>

<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
