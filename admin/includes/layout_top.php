<?php
declare(strict_types=1);
/** @var string $pageTitle */
/** @var array|null $operator */
$pageTitle ??= 'StreamVault';
$activeNav ??= '';
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($pageTitle) ?> · StreamVault</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="sv-shell">
  <nav class="sv-nav">
    <div class="sv-brand"><span class="dot"></span> StreamVault</div>
    <a href="index.php" class="<?= $activeNav === 'dashboard' ? 'active' : '' ?>">Dashboard</a>
    <a href="streams.php" class="<?= $activeNav === 'streams' ? 'active' : '' ?>">Streams</a>
    <a href="incidents.php" class="<?= $activeNav === 'incidents' ? 'active' : '' ?>">Incidents</a>
    <a href="settings.php" class="<?= $activeNav === 'settings' ? 'active' : '' ?>">Settings</a>
  </nav>
  <main class="sv-main">
    <div class="sv-topbar">
      <div></div>
      <?php if (!empty($operator)): ?>
        <div class="user"><?= h($operator['username']) ?> · <a href="logout.php">Log out</a></div>
      <?php endif; ?>
    </div>
    <?php if (!empty($_SESSION['flash'])): $f = $_SESSION['flash']; unset($_SESSION['flash']); ?>
      <div class="sv-flash <?= h($f['type']) ?>"><?= h($f['message']) ?></div>
    <?php endif; ?>
