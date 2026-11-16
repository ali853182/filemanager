<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\Audit\Adapters;

use Filegator\Services\Audit\AuditAction;
use Filegator\Services\Audit\AuditLoggerInterface;
use Filegator\Services\FileProfile\Adapters\Sqlite\SchemaInstaller;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteConnection;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Service;
use Monolog\Logger;

/**
 * Append-only JSONL audit ledger plus a rebuildable SQLite query index.
 *
 * The JSON Lines file at private/logs/audit.log is the source of truth. Every
 * event is appended as a single JSON object per line and mirrored into the
 * SQLite audit_events table. The mirror is best-effort: a failure there is
 * reported to the application logger and never rethrown, so a file operation
 * is never aborted by the audit subsystem (spec.md 8, 13, 14; FR10, FR11).
 *
 * When audit.enabled is false the logger is a strict no-op and writes nothing.
 */
class MonoAuditLogger implements Service, AuditLoggerInterface
{
    protected const RESULT_SUCCESS = 'success';

    protected const RESULT_FAILURE = 'failure';

    protected const RESULT_DENIED = 'denied';

    /**
     * Keys whose values must never reach the ledger or the index.
     */
    protected const FORBIDDEN_KEY_PATTERN = '/(pass(word|wd)?|pwd|token|csrf|session|ldap|bind|secret|authorization|cookie|credential|api[_-]?key|body|content|contents|payload)/i';

    protected $connection;

    protected $schemaInstaller;

    protected $logger;

    protected $enabled = false;

    protected $logPath;

    protected $maxFiles = 90;

    protected $maxPathLength = 4096;

    protected $maxMetaLength = 8192;

    protected $schemaReady = false;

    public function __construct(SqliteConnection $connection, SchemaInstaller $schemaInstaller, LoggerInterface $logger)
    {
        $this->connection = $connection;
        $this->schemaInstaller = $schemaInstaller;
        $this->logger = $logger;
        $this->logPath = dirname(__DIR__, 4).'/private/logs/audit.log';
    }

    public function init(array $config = [])
    {
        $this->enabled = (bool) ($config['enabled'] ?? false);

        if (isset($config['path']) && is_string($config['path']) && $config['path'] !== '') {
            $this->logPath = $config['path'];
        }

        if (isset($config['max_files'])) {
            $this->maxFiles = max(1, (int) $config['max_files']);
        }

        if (isset($config['max_path_length'])) {
            $this->maxPathLength = max(64, (int) $config['max_path_length']);
        }

        if (isset($config['max_meta_length'])) {
            $this->maxMetaLength = max(256, (int) $config['max_meta_length']);
        }
    }

    public function record(array $event): void
    {
        if (! $this->enabled) {
            return;
        }

        try {
            $normalized = $this->normalizeEvent($event);
        } catch (\Throwable $exception) {
            $this->report('Audit event rejected: '.$exception->getMessage());

            return;
        }

        if ($normalized === null) {
            return;
        }

        try {
            $this->appendLedger($normalized);
        } catch (\Throwable $exception) {
            $this->report('Audit ledger write failed: '.$exception->getMessage());

            return;
        }

        try {
            $this->indexEvent($normalized);
        } catch (\Throwable $exception) {
            $this->report('Audit index write failed: '.$exception->getMessage());
        }
    }

    /**
     * Validate, coerce and sanitize an incoming event.
     *
     * Unknown actions are rejected (null). Invalid results are coerced to
     * "failure". Missing required values are filled with safe defaults. No
     * exception is allowed to escape to the caller.
     */
    protected function normalizeEvent(array $event): ?array
    {
        $action = $this->sanitizeString($event['action'] ?? '', 64);

        if (! AuditAction::isValid($action)) {
            $this->report('Audit event rejected: unknown action "'.$action.'".');

            return null;
        }

        $result = strtolower(trim($this->sanitizeString($event['result'] ?? '', 16)));

        if (! in_array($result, [self::RESULT_SUCCESS, self::RESULT_FAILURE, self::RESULT_DENIED], true)) {
            $this->report('Audit event coerced: invalid result "'.$result.'" -> failure.');
            $result = self::RESULT_FAILURE;
        }

        [$path, $pathKey] = $this->sanitizePath($event['path'] ?? '/');

        $destination = null;
        if (isset($event['destination']) && $this->scalarString($event['destination']) !== '') {
            [$destination] = $this->sanitizePath($event['destination']);
        }

        $fileId = null;
        if (isset($event['file_id'])) {
            $candidate = $this->sanitizeString($event['file_id'], 64);
            $fileId = $candidate === '' ? null : $candidate;
        }

        $eventId = $this->sanitizeString($event['event_id'] ?? '', 64);
        if (! $this->isUuid($eventId)) {
            $eventId = $this->uuid();
        }

        $timestamp = $this->sanitizeString($event['ts'] ?? '', 40);
        if ($timestamp === '') {
            $timestamp = $this->now();
        }

        $user = $this->sanitizeString($event['user'] ?? '', 255);
        if ($user === '') {
            $user = 'guest';
        }

        $role = $this->sanitizeString($event['role'] ?? '', 32);
        if ($role === '') {
            $role = 'guest';
        }

        $ip = $this->sanitizeString($event['ip'] ?? '', 64);
        if ($ip === '') {
            $ip = 'unknown';
        }

        return [
            'event_id' => $eventId,
            'ts' => $timestamp,
            'user' => $user,
            'role' => $role,
            'ip' => $ip,
            'action' => $action,
            'file_id' => $fileId,
            'path' => $path,
            'path_key' => $pathKey,
            'destination' => $destination,
            'result' => $result,
            'meta' => $this->sanitizeMeta($event['meta'] ?? null),
        ];
    }

    /**
     * Append exactly one JSON object per line to the ledger.
     */
    protected function appendLedger(array $event): void
    {
        $directory = dirname($this->logPath);

        if (! is_dir($directory)) {
            if (! @mkdir($directory, 0775, true) && ! is_dir($directory)) {
                throw new \RuntimeException('Unable to create audit log directory.');
            }
        }

        $this->rotateIfNeeded($directory);

        $ledger = [
            'event_id' => $event['event_id'],
            'ts' => $event['ts'],
            'user' => $event['user'],
            'role' => $event['role'],
            'ip' => $event['ip'],
            'action' => $event['action'],
        ];

        if ($event['file_id'] !== null) {
            $ledger['file_id'] = $event['file_id'];
        }

        $ledger['path'] = $event['path'];

        if ($event['destination'] !== null) {
            $ledger['destination'] = $event['destination'];
        }

        $ledger['result'] = $event['result'];

        if ($event['meta'] !== null) {
            $ledger['meta'] = $event['meta'];
        }

        $line = json_encode($ledger, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            throw new \RuntimeException('Unable to encode audit event as JSON.');
        }

        $handle = @fopen($this->logPath, 'ab');
        if ($handle === false) {
            throw new \RuntimeException('Unable to open audit ledger for append.');
        }

        try {
            if (@flock($handle, LOCK_EX)) {
                @fwrite($handle, $line."\n");
                @fflush($handle);
                @flock($handle, LOCK_UN);
            } else {
                @fwrite($handle, $line."\n");
            }
        } finally {
            @fclose($handle);
        }
    }

    /**
     * Rotate the active ledger to a dated file when the day changes and prune
     * rotated files so at most audit.max_files remain.
     */
    protected function rotateIfNeeded(string $directory): void
    {
        if (is_file($this->logPath)) {
            $modified = @filemtime($this->logPath);

            if ($modified !== false) {
                $fileDate = gmdate('Y-m-d', $modified);
                $today = gmdate('Y-m-d');

                if ($fileDate !== $today) {
                    $target = $directory.'/audit-'.$fileDate.'.log';

                    if (is_file($target)) {
                        $target = $directory.'/audit-'.$fileDate.'-'.gmdate('His').'.log';
                    }

                    @rename($this->logPath, $target);
                }
            }
        }

        $this->pruneRotated($directory);
    }

    protected function pruneRotated(string $directory): void
    {
        $files = glob($directory.'/audit-*.log');

        if ($files === false || count($files) <= $this->maxFiles) {
            return;
        }

        sort($files, SORT_STRING);

        $excess = count($files) - $this->maxFiles;

        for ($index = 0; $index < $excess; $index++) {
            @unlink($files[$index]);
        }
    }

    /**
     * Mirror the event into the SQLite audit_events query index.
     */
    protected function indexEvent(array $event): void
    {
        if (! $this->schemaReady) {
            $this->schemaInstaller->install();
            $this->schemaReady = true;
        }

        $metaJson = null;
        if ($event['meta'] !== null) {
            $metaJson = json_encode($event['meta'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

            if ($metaJson === false || strlen($metaJson) > $this->maxMetaLength) {
                $metaJson = json_encode(['truncated' => true]);
            }
        }

        $database = $this->connection->connection();
        $statement = $database->prepare(
            'INSERT OR REPLACE INTO audit_events
                (event_id, ts, user, role, ip, action, file_id, path, path_key, destination, result, meta_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );

        if ($statement === false) {
            throw new \RuntimeException('Unable to prepare audit index statement.');
        }

        $values = [
            $event['event_id'],
            $event['ts'],
            $event['user'],
            $event['role'],
            $event['ip'],
            $event['action'],
            $event['file_id'],
            $event['path'],
            $event['path_key'],
            $event['destination'],
            $event['result'],
            $metaJson,
        ];

        $index = 1;
        foreach ($values as $value) {
            if ($value === null) {
                $statement->bindValue($index, null, SQLITE3_NULL);
            } else {
                $statement->bindValue($index, (string) $value, SQLITE3_TEXT);
            }

            $index++;
        }

        $statement->execute();
        $statement->close();
    }

    /**
     * Recursively redact forbidden keys and sanitize meta values.
     */
    protected function sanitizeMeta($meta): ?array
    {
        if (! is_array($meta)) {
            return null;
        }

        $clean = $this->sanitizeValue($meta, 0);

        return is_array($clean) ? $clean : null;
    }

    protected function sanitizeValue($value, int $depth)
    {
        if ($depth > 4) {
            return '[truncated]';
        }

        if (is_array($value)) {
            $clean = [];
            $count = 0;

            foreach ($value as $key => $item) {
                if ($count >= 50) {
                    $clean['truncated'] = true;
                    break;
                }

                $safeKey = $this->sanitizeString($key, 128);

                if ($safeKey === '') {
                    $safeKey = 'key';
                }

                if (preg_match(self::FORBIDDEN_KEY_PATTERN, $safeKey) === 1) {
                    $clean[$safeKey] = '[redacted]';
                } else {
                    $clean[$safeKey] = $this->sanitizeValue($item, $depth + 1);
                }

                $count++;
            }

            return $clean;
        }

        if (is_bool($value) || is_int($value) || is_float($value) || $value === null) {
            return $value;
        }

        return $this->sanitizeString($value, 1024);
    }

    /**
     * Normalize a path without throwing; strips ".." segments and control
     * characters, collapses slashes and caps the length.
     *
     * @return array{0: string, 1: string} Normalized path and lowercase path_key.
     */
    protected function sanitizePath($value): array
    {
        $path = $this->sanitizeString($this->scalarString($value), $this->maxPathLength);
        $path = str_replace('\\', '/', $path);

        $collapsed = preg_replace('#/+#', '/', $path);
        if ($collapsed === null) {
            $collapsed = '/';
        }

        $segments = [];
        foreach (explode('/', $collapsed) as $segment) {
            if ($segment === '..') {
                continue;
            }

            $segments[] = $segment;
        }

        $collapsed = implode('/', $segments);

        if ($collapsed === '' || $collapsed[0] !== '/') {
            $collapsed = '/'.ltrim($collapsed, '/');
        }

        if (strlen($collapsed) > 1) {
            $collapsed = rtrim($collapsed, '/');
        }

        if ($collapsed === '') {
            $collapsed = '/';
        }

        $pathKey = function_exists('mb_strtolower')
            ? mb_strtolower($collapsed, 'UTF-8')
            : strtolower($collapsed);

        return [$collapsed, $pathKey];
    }

    protected function sanitizeString($value, int $maxLength): string
    {
        $value = $this->scalarString($value);

        $stripped = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value);
        if ($stripped === null) {
            $stripped = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
        }

        if ($stripped === null) {
            $stripped = '';
        }

        if (function_exists('mb_substr')) {
            return mb_substr($stripped, 0, $maxLength, 'UTF-8');
        }

        return substr($stripped, 0, $maxLength);
    }

    protected function scalarString($value): string
    {
        if (is_string($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        return '';
    }

    protected function isUuid(string $value): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1;
    }

    protected function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    protected function now(): string
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

        return $now->format('Y-m-d\TH:i:s.v\Z');
    }

    /**
     * Report a failure without leaking secrets and without ever throwing.
     */
    protected function report(string $message): void
    {
        try {
            $this->logger->log($message, Logger::WARNING);
        } catch (\Throwable $exception) {
            // Logging must never break the caller.
        }
    }
}
