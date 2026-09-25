<?php
declare(strict_types=1);

// CLI-only bootstrap for the first (or an additional) admin operator.
// Deliberately not exposed over HTTP: letting anyone create an admin
// account by hitting a URL before one exists is a real foot-gun, so this
// requires shell access to the box instead.
//
// Usage: php create_operator.php <username>
// (prompts for the password so it never lands in shell history)

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die("This script is CLI-only.\n");
}

require_once __DIR__ . '/../includes/db.php';

$username = $argv[1] ?? null;
if (!$username) {
    fwrite(STDERR, "Usage: php create_operator.php <username>\n");
    exit(1);
}

fwrite(STDOUT, "Password for $username: ");
system('stty -echo');
$password = trim((string) fgets(STDIN));
system('stty echo');
fwrite(STDOUT, "\n");

if (strlen($password) < 12) {
    fwrite(STDERR, "Password must be at least 12 characters.\n");
    exit(1);
}

$hash = password_hash($password, PASSWORD_DEFAULT);
$pdo = sv_db();
$stmt = $pdo->prepare('INSERT INTO operators (username, password_hash) VALUES (?, ?)
    ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash');
$stmt->execute([$username, $hash]);

fwrite(STDOUT, "Operator '$username' created/updated.\n");
