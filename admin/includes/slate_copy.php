<?php
declare(strict_types=1);

const SV_SLATE_REASONS = [
    'limited_bandwidth' => 'Limited bandwidth',
    'not_intended_for_public' => 'Not intended for public distribution',
    'unauthorized_redistribution' => 'Unauthorized redistribution',
    'access_revoked_by_owner' => 'Access revoked by owner',
    'stream_permanently_discontinued' => 'Stream permanently discontinued',
    'temporarily_unavailable' => 'Temporarily unavailable (source failure)',
];

function sv_slate_copy_valid(string $title, string $subtitle): ?array
{
    $clean = static function (string $value, bool $allowBreak): string {
        $value = str_replace(["\r\n", "\r"], "\n", $value);
        $value = preg_replace('/[\x00-\x09\x0B-\x1F\x7F\p{Cf}]/u', ' ', $value) ?? '';
        if (!$allowBreak) $value = str_replace("\n", ' ', $value);
        return trim($value);
    };
    $title = $clean($title, false);
    $subtitle = $clean($subtitle, true);
    if ($title === '' || $subtitle === '' || mb_strlen($title) > 32 || mb_strlen($subtitle) > 90 || substr_count($subtitle, "\n") > 1) return null;
    if (preg_match('~https?://|www\.|[\x{1F300}-\x{1FAFF}]~iu', $title . ' ' . $subtitle)) return null;
    return ['title' => $title, 'subtitle' => $subtitle];
}

function sv_ai_reserve(PDO $db, int $operatorId): bool
{
    $db->exec('BEGIN IMMEDIATE');
    try {
        $minute = gmdate('Y-m-d\TH:i:s', time() - 60) . '.000Z';
        $day = gmdate('Y-m-d') . 'T00:00:00.000Z';
        $stmt = $db->prepare('SELECT COUNT(*) FROM ai_generation_log WHERE operator_id = ? AND created_at >= ?');
        $stmt->execute([$operatorId, $minute]);
        $recent = (int) $stmt->fetchColumn();
        $stmt->execute([$operatorId, $day]);
        $daily = (int) $stmt->fetchColumn();
        if ($recent >= 10 || $daily >= 100) { $db->commit(); return false; }
        $db->prepare('INSERT INTO ai_generation_log(operator_id) VALUES (?)')->execute([$operatorId]);
        $db->commit();
        return true;
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        throw $e;
    }
}

/** @return array{copy?:array,error?:string} */
function sv_ai_generate(PDO $db, int $operatorId, string $reason, string $language, string $instruction): array
{
    if (!mb_check_encoding($instruction, 'UTF-8')) return ['error' => 'Invalid generation request.'];
    $instruction = trim(preg_replace('/[\x00-\x1F\x7F\p{Cf}]/u', ' ', $instruction) ?? '');
    if (!isset(SV_SLATE_REASONS[$reason]) || !in_array($language, ['en', 'cs'], true) || mb_strlen($instruction) > 200) return ['error' => 'Invalid generation request.'];
    $encrypted = $db->query("SELECT value FROM settings WHERE key = 'openrouter_key_enc'")->fetchColumn();
    if (!$encrypted) return ['error' => 'Configure an OpenRouter key in Settings first.'];
    if (!sv_ai_reserve($db, $operatorId)) return ['error' => 'AI generation limit reached (10 per minute, 100 per day).'];
    try {
        $key = sv_decrypt((string) sv_load_key(SV_KEY_FILE), (string) $encrypted);
    } catch (Throwable $e) { return ['error' => 'OpenRouter key could not be read.']; }
    $model = $db->query("SELECT value FROM settings WHERE key = 'openrouter_model'")->fetchColumn() ?: 'z-ai/glm-5.3-flash';
    $endpoint = getenv('STREAMVAULT_OPENROUTER_URL') ?: 'https://openrouter.ai/api/v1/chat/completions';
    $payload = json_encode([
        'model' => $model, 'temperature' => 0.7, 'max_tokens' => 150,
        'messages' => [
            ['role' => 'system', 'content' => 'Write neutral, professional IPTV unavailability notices. Return only strict JSON with exactly title and subtitle string fields. Title max 32 Unicode characters; subtitle max 90 Unicode characters and at most two short lines. No URLs, emojis, markdown or blame.'],
            ['role' => 'user', 'content' => 'Reason: ' . SV_SLATE_REASONS[$reason] . '. Language: ' . ($language === 'cs' ? 'Czech' : 'English') . '. Additional operator guidance: ' . trim($instruction)],
        ],
    ], JSON_THROW_ON_ERROR);
    $response = '';
    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST => true, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $key, 'Content-Type: application/json'],
        CURLOPT_POSTFIELDS => $payload, CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response): int {
            if (strlen($response) + strlen($chunk) > 16384) return 0;
            $response .= $chunk; return strlen($chunk);
        },
    ]);
    $ok = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    unset($key, $encrypted);
    if ($ok === false) return ['error' => 'OpenRouter request failed or timed out.'];
    if ($status !== 200) return ['error' => match ($status) {401 => 'OpenRouter rejected the key (HTTP 401).', 402 => 'OpenRouter reports insufficient credit (HTTP 402).', 429 => 'OpenRouter rate limit reached (HTTP 429).', default => 'OpenRouter returned HTTP ' . $status . '.'}];
    $body = json_decode($response, true);
    $content = $body['choices'][0]['message']['content'] ?? null;
    if (!is_string($content)) return ['error' => 'OpenRouter returned an unexpected response.'];
    // Many models wrap JSON in a ```json fence despite instructions; strip it.
    $content = preg_replace('/^\s*```(?:json)?\s*|\s*```\s*$/i', '', $content) ?? $content;
    $suggestion = json_decode($content, true);
    if (!is_array($suggestion) || count($suggestion) !== 2 || !isset($suggestion['title'], $suggestion['subtitle']) || !is_string($suggestion['title']) || !is_string($suggestion['subtitle'])) return ['error' => 'AI response was not valid title/subtitle JSON.'];
    $copy = sv_slate_copy_valid($suggestion['title'], $suggestion['subtitle']);
    return $copy ? ['copy' => $copy] : ['error' => 'AI suggestion exceeded limits or contained disallowed content.'];
}
