<?php
declare(strict_types=1);

function h(?string $s): string
{
    return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}

function sv_redirect(string $to): void
{
    header('Location: ' . $to);
    exit;
}

function sv_flash(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

/**
 * Validates a public_path: non-empty slash-separated segments of
 * [a-zA-Z0-9_-], no leading/trailing slash, no empty segments, and no
 * segment equal to the reserved "r" marker the gateway uses internally
 * (see config.php SV_RESERVED_SEGMENT / ARCHITECTURE.md). Returns an error
 * string, or null if the path is valid.
 */
function sv_validate_public_path(string $path): ?string
{
    if ($path === '' || $path !== trim($path, '/')) {
        return 'Path must not be empty and must not start or end with a slash.';
    }
    $segments = explode('/', $path);
    foreach ($segments as $seg) {
        if ($seg === '' || !preg_match('/^[a-zA-Z0-9_-]+$/', $seg)) {
            return "Invalid path segment \"$seg\": only letters, digits, - and _ are allowed.";
        }
        if (strcasecmp($seg, SV_RESERVED_SEGMENT) === 0) {
            return 'The path segment "' . SV_RESERVED_SEGMENT . '" is reserved by the gateway and cannot be used.';
        }
    }
    return null;
}

function sv_generate_raw_token(): string
{
    return bin2hex(random_bytes(24)); // 48 hex chars, not derived from anything predictable
}

function sv_hash_token(string $raw): string
{
    return hash('sha256', $raw);
}

function sv_token_display(string $raw): string
{
    return substr($raw, 0, 8);
}
