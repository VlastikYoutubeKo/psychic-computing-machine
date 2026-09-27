<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';

$wantsJson = ($_SERVER['HTTP_X_SV_LOGIN'] ?? '') === '1';

if (sv_current_operator() !== null) {
    if ($wantsJson) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true]);
        exit;
    }
    sv_redirect('index.php');
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $retry = sv_login_retry_after($username);
    $ok = $retry === 0 && sv_login($username, $password);
    $message = $retry > 0
        ? 'Too many failed attempts. Try again in ' . max(1, (int) ceil($retry / 60)) . ' min.'
        : 'Invalid username or password.';
    if ($wantsJson) {
        if (!$ok && $retry > 0) {
            http_response_code(429);
            header('Retry-After: ' . $retry);
        }
        header('Content-Type: application/json');
        echo json_encode($ok ? ['ok' => true] : ['ok' => false, 'error' => $message]);
        exit;
    }
    if ($ok) {
        sv_redirect('index.php');
    }
    if ($retry > 0) {
        http_response_code(429);
        header('Retry-After: ' . $retry);
    }
    $error = $message;
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · StreamVault</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body class="sv-login-body">
  <div class="sv-panel sv-login-card">
    <div class="sv-brand"><span class="dot"></span> StreamVault</div>
    <h1 class="sv-login-title">Welcome back</h1>
    <p class="sv-login-subtitle">Sign in to manage your streams and incident response.</p>
    <div id="sv-login-error" class="sv-flash err"<?= $error ? '' : ' hidden' ?>><?= h($error) ?></div>
    <form id="sv-login" name="login" method="post" action="login.php" autocomplete="on">
      <?= sv_csrf_field() ?>
      <label for="sv-username">Username</label>
      <input type="text" id="sv-username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
      <label for="sv-password">Password</label>
      <input type="password" id="sv-password" name="password" autocomplete="current-password" required>
      <button type="submit" class="btn-primary" style="width:100%;margin-top:1.25rem;">Sign in</button>
    </form>
  </div>
<script>
// Chromium/Brave heuristics for "was this a successful login?" are unreliable
// for a plain POST+302, so log in via fetch and then explicitly hand the
// credential to the browser's password manager. Without JS the form still
// submits normally.
(function () {
  const form = document.getElementById('sv-login');
  const errBox = document.getElementById('sv-login-error');
  if (!window.fetch) return;
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const btn = form.querySelector('button[type=submit]');
    btn.disabled = true;
    errBox.hidden = true;
    try {
      const res = await fetch('login.php', {
        method: 'POST',
        body: new FormData(form),
        headers: { 'X-SV-Login': '1' },
        credentials: 'same-origin',
      });
      const data = await res.json().catch(function () { return { ok: false, error: 'Unexpected server response (' + res.status + ').' }; });
      if (!data.ok) {
        errBox.textContent = data.error || 'Login failed.';
        errBox.hidden = false;
        btn.disabled = false;
        return;
      }
      if ('PasswordCredential' in window && navigator.credentials) {
        try {
          await navigator.credentials.store(new PasswordCredential({
            id: form.username.value,
            password: form.password.value,
            name: form.username.value,
          }));
        } catch (_) { /* user dismissed or unsupported -- still log in */ }
      }
      window.location.href = 'index.php';
    } catch (_) {
      form.submit();
    }
  });
})();
</script>
</body>
</html>
