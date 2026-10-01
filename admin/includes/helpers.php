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
 * segment equal to the reserved "r" marker the gateway uses internally,
 * and no leading "_sv" segment (the global slate route)
 * (see config.php SV_RESERVED_SEGMENT / ARCHITECTURE.md). Returns an error
 * string, or null if the path is valid.
 */
function sv_validate_public_path(string $path): ?string
{
    if ($path === '' || $path !== trim($path, '/')) {
        return 'Path must not be empty and must not start or end with a slash.';
    }
    $segments = explode('/', $path);
    foreach ($segments as $index => $seg) {
        if ($seg === '' || !preg_match('/^[a-zA-Z0-9_-]+$/', $seg)) {
            return "Invalid path segment \"$seg\": only letters, digits, - and _ are allowed.";
        }
        if (strcasecmp($seg, SV_RESERVED_SEGMENT) === 0) {
            return 'The path segment "' . SV_RESERVED_SEGMENT . '" is reserved by the gateway and cannot be used.';
        }
        if ($index === 0 && $seg === SV_RESERVED_ROOT_SEGMENT) {
            return 'The path segment "' . SV_RESERVED_ROOT_SEGMENT . '" is reserved by the gateway and cannot be used.';
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

/**
 * For streams of regular accounts: the source must be http(s) and resolve
 * only to public addresses. Returns an error message or null. (Admins may
 * point streams at private/LAN sources.) The gateway re-checks the address it
 * actually connects to, so DNS changes after saving don't bypass this.
 */
/**
 * True only for globally routable addresses. filter_var's NO_PRIV/NO_RES
 * flags alone are not enough: PHP 8.2 calls IPv4-mapped IPv6 such as
 * ::ffff:127.0.0.1 or ::ffff:169.254.169.254 public, and never looks inside
 * the other IPv6 forms that embed an IPv4 address. Those are unwrapped and
 * judged as the IPv4 address they reach; forms with no legitimate use as a
 * stream source are refused.
 */
function sv_ip_is_public(string $ip): bool
{
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return false;
    }
    if (strlen($bin) === 16) {
        $embedded = null;
        if (substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff"      // ::ffff:a.b.c.d  IPv4-mapped
            || substr($bin, 0, 12) === str_repeat("\0", 12)                 // ::a.b.c.d       IPv4-compatible (and ::, ::1)
            || substr($bin, 0, 12) === "\x00\x64\xff\x9b" . str_repeat("\0", 8)) { // 64:ff9b::/96 NAT64
            $embedded = substr($bin, 12);
        } elseif (substr($bin, 0, 2) === "\x20\x02") {                      // 2002::/16       6to4
            $embedded = substr($bin, 2, 4);
        } elseif (substr($bin, 0, 4) === "\x20\x01\x00\x00") {             // 2001::/32       Teredo
            return false;
        }
        if ($embedded !== null) {
            return sv_ip_is_public((string) inet_ntop($embedded));
        }
        if ($bin[0] === "\xff") {                                           // ff00::/8        multicast
            return false;
        }
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }
    $o = array_map('intval', explode('.', (string) inet_ntop($bin)));
    return !($o[0] === 100 && $o[1] >= 64 && $o[1] <= 127)   // 100.64/10 carrier-grade NAT
        && !($o[0] === 192 && $o[1] === 0 && $o[2] === 0)     // 192.0.0.0/24 protocol assignments
        && !($o[0] === 198 && ($o[1] === 18 || $o[1] === 19)) // 198.18/15 benchmarking
        && $o[0] < 224;                                       // multicast and above
}

function sv_public_source_error(string $url): ?string
{
    $p = parse_url($url);
    $scheme = strtolower((string) ($p['scheme'] ?? ''));
    $host = trim((string) ($p['host'] ?? ''), '[]');
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        return 'Source URL must be an http(s) URL.';
    }
    $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : array_merge(
        gethostbynamel($host) ?: [],
        array_column(@dns_get_record($host, DNS_AAAA) ?: [], 'ipv6')
    );
    if (!$ips) {
        return 'Source host could not be resolved.';
    }
    foreach ($ips as $ip) {
        if (!sv_ip_is_public($ip)) {
            return 'Source must be a public address; private, local and internal addresses are only allowed for admins.';
        }
    }
    return null;
}
