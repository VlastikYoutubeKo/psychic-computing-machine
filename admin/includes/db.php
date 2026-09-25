<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function sv_db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dataDir = dirname(SV_DB_PATH);
    if (!is_dir($dataDir)) {
        mkdir($dataDir, 0770, true);
    }
    $pdo = new PDO('sqlite:' . SV_DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    // WAL + a real busy_timeout: the gateway (Go) reads this same file
    // concurrently. Without this, admin writes and gateway reads can hit
    // SQLITE_BUSY under load (see memory: SQLite WAL dir perms incident).
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    sv_migrate($pdo);
    return $pdo;
}

function sv_migrate(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))
    )');
    $applied = $pdo->query('SELECT version FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
    $files = glob(SV_MIGRATIONS_DIR . '/*.sql');
    sort($files);
    foreach ($files as $file) {
        $version = basename($file, '.sql');
        if (in_array($version, $applied, true)) {
            continue;
        }
        $sql = file_get_contents($file);
        if ($sql === false) {
            throw new RuntimeException("cannot read migration $file");
        }
        $pdo->exec($sql);
    }
}
