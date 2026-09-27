<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';

// POST + CSRF only, so another site can't log the operator out via a link.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sv_redirect(sv_current_operator() ? 'index.php' : 'login.php');
}
sv_csrf_check();
sv_logout();
sv_redirect('login.php');
