<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
sv_logout();
sv_redirect('login.php');
