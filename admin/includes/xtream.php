<?php
declare(strict_types=1);

// Xtream Codes source support: talk to a panel's player_api.php to list its
// live channels, and build source URLs for the chosen ones.
//
// Xtream puts the credentials in the URL path, so the URL stored for a stream
// keeps {username}/{password} placeholders; the gateway fills them in from the
// stream's encrypted credentials at fetch time (gateway/internal/gatewayhttp/
// sourceurl.go). The password therefore never appears in the admin UI, the
// database or logs in plaintext.

require_once __DIR__ . '/helpers.php';

const SV_XTREAM_MAX_RESPONSE = 48 * 1024 * 1024; // big panels list tens of thousands of channels
const SV_XTREAM_MAX_IMPORT = 500;

/**
 * Normalises what the operator typed (http://host:port, optionally with a
 * path such as /player_api.php or /get.php?...) to scheme://host[:port].
 * Returns null when it isn't a usable http(s) server address.
 */
function sv_xtream_base(string $input): ?string
{
    $input = trim($input);
    if ($input !== '' && !preg_match('#^[a-z][a-z0-9+.-]*://#i', $input)) {
        $input = 'http://' . $input;
    }
    $p = parse_url($input);
    if ($p === false || empty($p['host']) || isset($p['user']) || isset($p['pass'])) {
        return null;
    }
    $scheme = strtolower((string) ($p['scheme'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return null;
    }
    $host = strtolower($p['host']);
    if (!preg_match('/^(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)$/', $host)) {
        return null;
    }
    $port = isset($p['port']) ? ':' . (int) $p['port'] : '';
    return $scheme . '://' . $host . $port;
}

/** Source URL stored for one channel. $format is 'ts' or 'm3u8'. */
function sv_xtream_source_url(string $base, int $streamId, string $format): string
{
    return $base . '/live/{username}/{password}/' . $streamId . ($format === 'm3u8' ? '.m3u8' : '.ts');
}

/**
 * Calls player_api.php and returns the decoded JSON.
 *
 * $allowPrivate is true only for admins. For everyone else the host must
 * resolve to public addresses and the connection is pinned to the address
 * that was checked, so a DNS answer that changes between the check and the
 * request can't point this server at an internal service. Redirects are
 * never followed. Error messages never contain the URL (it holds the
 * password).
 *
 * @throws RuntimeException with a message that is safe to show
 */
function sv_xtream_call(string $base, string $username, string $password, ?string $action, bool $allowPrivate): array
{
    $p = parse_url($base);
    $host = trim((string) ($p['host'] ?? ''), '[]');
    $scheme = (string) ($p['scheme'] ?? '');
    $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
    if ($host === '') {
        throw new RuntimeException('Invalid server address.');
    }

    $query = ['username' => $username, 'password' => $password];
    if ($action !== null) {
        $query['action'] = $action;
    }
    $ch = curl_init($base . '/player_api.php?' . http_build_query($query));
    $body = '';
    $tooBig = false;
    $opts = [
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 45,
        CURLOPT_USERAGENT => 'StreamVault',
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$body, &$tooBig): int {
            if (strlen($body) + strlen($chunk) > SV_XTREAM_MAX_RESPONSE) {
                $tooBig = true;
                return 0; // aborts the transfer
            }
            $body .= $chunk;
            return strlen($chunk);
        },
    ];
    if (!$allowPrivate) {
        $err = sv_public_source_error($base);
        if ($err !== null) {
            throw new RuntimeException($err);
        }
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = gethostbynamel($host) ?: [];
            $public = array_values(array_filter($ips, fn ($ip) => sv_public_source_error('http://' . $ip . '/') === null));
            if (!$public) {
                throw new RuntimeException('Server host could not be resolved to a public IPv4 address.');
            }
            $opts[CURLOPT_RESOLVE] = [$host . ':' . $port . ':' . $public[0]];
        }
    }
    curl_setopt_array($ch, $opts);
    $ok = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($tooBig) {
        throw new RuntimeException('The server\'s channel list is too large to import.');
    }
    if ($ok === false || $errno !== 0) {
        throw new RuntimeException($errno === CURLE_OPERATION_TIMEDOUT
            ? 'The Xtream server did not answer in time.'
            : 'Could not connect to the Xtream server.');
    }
    if ($status >= 300 && $status < 400) {
        throw new RuntimeException('The Xtream server answered with a redirect; enter the address it redirects to.');
    }
    if ($status === 401 || $status === 403) {
        throw new RuntimeException('The Xtream server rejected the username or password.');
    }
    if ($status !== 200) {
        throw new RuntimeException('The Xtream server answered with HTTP ' . $status . '.');
    }
    $data = json_decode($body, true);
    if (!is_array($data)) {
        throw new RuntimeException('The server did not answer like an Xtream Codes API (no JSON).');
    }
    return $data;
}

/**
 * Logs in and returns the account summary shown to the operator.
 *
 * @throws RuntimeException
 */
function sv_xtream_account(string $base, string $username, string $password, bool $allowPrivate): array
{
    $data = sv_xtream_call($base, $username, $password, null, $allowPrivate);
    $info = is_array($data['user_info'] ?? null) ? $data['user_info'] : [];
    if ((int) ($info['auth'] ?? 0) !== 1) {
        throw new RuntimeException('The Xtream server rejected the username or password.');
    }
    $exp = $info['exp_date'] ?? null;
    return [
        'status' => (string) ($info['status'] ?? 'unknown'),
        'expires' => is_numeric($exp) && (int) $exp > 0 ? gmdate('Y-m-d', (int) $exp) : null,
        'max_connections' => is_numeric($info['max_connections'] ?? null) ? (int) $info['max_connections'] : null,
        'active_connections' => is_numeric($info['active_cons'] ?? null) ? (int) $info['active_cons'] : null,
    ];
}

/**
 * Live channels as [stream_id => ['name' => ..., 'category' => ...]],
 * sorted by category then name.
 *
 * @throws RuntimeException
 */
function sv_xtream_channels(string $base, string $username, string $password, bool $allowPrivate): array
{
    $categories = [];
    foreach (sv_xtream_call($base, $username, $password, 'get_live_categories', $allowPrivate) as $c) {
        if (is_array($c) && isset($c['category_id'])) {
            $categories[(string) $c['category_id']] = sv_xtream_text($c['category_name'] ?? '', 80);
        }
    }
    $channels = [];
    foreach (sv_xtream_call($base, $username, $password, 'get_live_streams', $allowPrivate) as $s) {
        if (!is_array($s) || !is_numeric($s['stream_id'] ?? null) || (int) $s['stream_id'] <= 0) {
            continue;
        }
        $id = (int) $s['stream_id'];
        $name = sv_xtream_text($s['name'] ?? '', 120);
        $channels[$id] = [
            'name' => $name !== '' ? $name : 'Channel ' . $id,
            'category' => $categories[(string) ($s['category_id'] ?? '')] ?? '',
        ];
    }
    uasort($channels, fn ($a, $b) => [$a['category'], $a['name']] <=> [$b['category'], $b['name']]);
    return $channels;
}

/** Panel-supplied text: single line, valid UTF-8, bounded length. */
function sv_xtream_text(mixed $value, int $max): string
{
    $s = is_scalar($value) ? (string) $value : '';
    $s = mb_scrub($s, 'UTF-8');
    $s = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s));
    return mb_substr($s, 0, $max, 'UTF-8');
}
