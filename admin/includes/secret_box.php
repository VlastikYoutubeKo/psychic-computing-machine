<?php
declare(strict_types=1);

/**
 * PHP mirror of gateway/internal/secretbox/secretbox.go. Wire format:
 * base64( nonce[12] || ciphertext || tag[16] ). Both sides must agree on
 * this exactly, or the admin UI will encrypt source passwords the gateway
 * can never decrypt. tests/crypto_interop.sh cross-checks both directions.
 */

function sv_load_key(string $path): ?string
{
    if (!is_file($path)) {
        return null;
    }
    $raw = (string) file_get_contents($path);
    if (strlen($raw) === 32) {
        return $raw;
    }
    $decoded = base64_decode(trim($raw), true);
    if ($decoded !== false && strlen($decoded) === 32) {
        return $decoded;
    }
    return null;
}

function sv_generate_key(): string
{
    return base64_encode(random_bytes(32));
}

function sv_ensure_key_file(string $path): string
{
    $key = sv_load_key($path);
    if ($key !== null) {
        return $key;
    }
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0770, true);
    }
    $encoded = sv_generate_key();
    file_put_contents($path, $encoded, LOCK_EX);
    chmod($path, 0600);
    return base64_decode($encoded);
}

function sv_encrypt(string $key, string $plaintext): string
{
    $nonce = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ciphertext === false) {
        throw new RuntimeException('secret_box: encryption failed');
    }
    return base64_encode($nonce . $ciphertext . $tag);
}

function sv_decrypt(string $key, string $encoded): string
{
    $raw = base64_decode($encoded, true);
    if ($raw === false || strlen($raw) < 12 + 16) {
        throw new RuntimeException('secret_box: invalid ciphertext');
    }
    $nonce = substr($raw, 0, 12);
    $tag = substr($raw, -16);
    $ciphertext = substr($raw, 12, -16);
    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($plaintext === false) {
        throw new RuntimeException('secret_box: decryption failed (wrong key or tampered data)');
    }
    return $plaintext;
}
