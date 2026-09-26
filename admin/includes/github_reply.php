<?php
declare(strict_types=1);

// PHP twin of gateway/internal/leakcheck/actions.go (ParseIssueURL,
// NoticeBody, PostIssueComment) for the operator-initiated reply button.
// Keep the regex and comment text in sync with the Go side.

/** @return array{0:string,1:string,2:int}|null */
function sv_parse_issue_url(string $url): ?array
{
    if (!preg_match('#^https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)/(issues|pull)/([0-9]+)$#D', $url, $m)) {
        return null;
    }
    $n = (int) $m[4];
    return $n > 0 ? [$m[1], $m[2], $n] : null;
}

function sv_notice_body(string $baseUrl): string
{
    $img = rtrim($baseUrl, '/') . '/_sv/notice.png';
    $body = 'This stream link has been revoked by its owner and no longer works.';
    if (preg_match('#^https?://#', $img)) {
        $body .= "\n\n![Stream unavailable](" . $img . ')';
    }
    return $body . "\n\n<sub>Automated notice from StreamVault.</sub>";
}

/** @return array{0:bool,1:string} [ok, comment html_url or error text] */
function sv_post_github_comment(string $token, string $owner, string $repo, int $number, string $body): array
{
    $ch = curl_init(sprintf('https://api.github.com/repos/%s/%s/issues/%d/comments', rawurlencode($owner), rawurlencode($repo), $number));
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['body' => $body]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $token,
            'Accept: application/vnd.github+json',
            'Content-Type: application/json',
            'User-Agent: streamvault-admin',
        ],
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false) {
        return [false, 'network error'];
    }
    if ($code !== 201) {
        // Status only; never echo GitHub's response body into the UI/logs.
        $hint = $code === 403 || $code === 404 ? ' (token needs the public_repo scope, or the issue is locked/private)' : '';
        return [false, "GitHub returned status $code$hint"];
    }
    $data = json_decode((string) $resp, true);
    return [true, is_array($data) && is_string($data['html_url'] ?? null) ? $data['html_url'] : ''];
}
