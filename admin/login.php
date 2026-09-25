<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';

if (sv_current_operator() !== null) {
    sv_redirect('index.php');
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    if (sv_login($username, $password)) {
        sv_redirect('index.php');
    }
    $error = 'Invalid username or password.';
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · StreamVault</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body style="display:flex;align-items:center;justify-content:center;height:100vh;">
  <div class="sv-panel" style="width:22rem;">
    <div class="sv-brand" style="margin-bottom:1.25rem;"><span class="dot"></span> StreamVault</div>
    <?php if ($error): ?><div class="sv-flash err"><?= h($error) ?></div><?php endif; ?>
    <form method="post" action="login.php">
      <?= sv_csrf_field() ?>
      <label for="sv-username">Username</label>
      <input type="text" id="sv-username" name="username" autocomplete="username" required autofocus>
      <label for="sv-password">Password</label>
      <input type="password" id="sv-password" name="password" autocomplete="current-password" required>
      <button type="submit" class="btn-primary" style="width:100%;margin-top:1.25rem;">Sign in</button>
    </form>
  </div>
</body>
</html>
