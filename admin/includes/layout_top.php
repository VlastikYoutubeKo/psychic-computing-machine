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
  <nav class="sv-nav" aria-label="Main navigation">
    <div class="sv-brand"><span class="dot"></span> StreamVault</div>
    <div class="sv-nav-label">Workspace</div>
    <a href="index.php" class="<?= $activeNav === 'dashboard' ? 'active' : '' ?>" <?= $activeNav === 'dashboard' ? 'aria-current="page"' : '' ?>><span class="sv-nav-icon" aria-hidden="true">◫</span>Dashboard</a>
    <a href="streams.php" class="<?= $activeNav === 'streams' ? 'active' : '' ?>" <?= $activeNav === 'streams' ? 'aria-current="page"' : '' ?>><span class="sv-nav-icon" aria-hidden="true">▶</span>Streams</a>
    <a href="incidents.php" class="<?= $activeNav === 'incidents' ? 'active' : '' ?>" <?= $activeNav === 'incidents' ? 'aria-current="page"' : '' ?>><span class="sv-nav-icon" aria-hidden="true">◇</span>Incidents</a>
    <a href="settings.php" class="<?= $activeNav === 'settings' ? 'active' : '' ?>" <?= $activeNav === 'settings' ? 'aria-current="page"' : '' ?>><span class="sv-nav-icon" aria-hidden="true">⚙</span>Settings</a>
    <div class="sv-nav-foot">STREAMVAULT · CONTROL PANEL</div>
  </nav>
  <main class="sv-main">
    <div class="sv-topbar">
      <div class="sv-location">Workspace / <?= h($pageTitle) ?></div>
      <?php if (!empty($operator)): ?>
        <div class="user"><strong><?= h($operator['username']) ?></strong><a href="logout.php">Log out</a></div>
      <?php endif; ?>
    </div>
    <?php if (!empty($_SESSION['flash'])): $f = $_SESSION['flash']; unset($_SESSION['flash']); ?>
      <div class="sv-flash <?= h($f['type']) ?>"><?= h($f['message']) ?></div>
    <?php endif; ?>
