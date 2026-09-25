<?php
declare(strict_types=1);

function sv_csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function sv_csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . h(sv_csrf_token()) . '">';
}

function sv_csrf_check(): void
{
    $sent = $_POST['csrf'] ?? '';
    $expected = $_SESSION['csrf'] ?? '';
    if ($expected === '' || !hash_equals($expected, $sent)) {
        http_response_code(400);
        die('Invalid or expired form token. Go back and try again.');
    }
}
