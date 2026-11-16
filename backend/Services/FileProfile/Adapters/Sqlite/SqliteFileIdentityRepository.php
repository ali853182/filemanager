<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile\Adapters\Sqlite;

use Filegator\Services\FileProfile\FileIdentity;
use Filegator\Services\FileProfile\FileIdentityRepositoryInterface;
use Filegator\Services\Service;

/**
 * SQLite-backed implementation of the stable file identity store.
 *
 * Identity rules implemented here (spec.md 9):
 *   create/upload new/zip/unzip/re-create -> ensureFile() inserts a new id
 *   upload overwrite/save/chmod           -> ensureFile() keeps the active id
 *   rename/move                           -> rename()/move() keep the id
 *   copy                                  -> copy() links copied_from_file_id
 *   delete                                -> softDelete() sets deleted_at
 *
 * Paths are normalised (trim, "\" to "/", collapse "//", leading "/", reject
 * "..") and path_key is the lowercased path for Windows lookups. Every query
 * uses prepared statements with bound values; no value is interpolated into
 * SQL.
 */
class SqliteFileIdentityRepository implements FileIdentityRepositoryInterface, Service
{
    protected const COLUMNS = 'file_id, path, path_key, type, created_at, updated_at, deleted_at, copied_from_file_id';

    protected $connection;

    protected $schemaReady = false;

    public function __construct(SqliteConnection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * Service bootstrap has no configuration of its own; the connection is
     * configured by SqliteConnection.
     */
    public function init(array $config = [])
    {
    }

    public function ensureFile(string $path, string $type): array
    {
        [$normalizedPath, $pathKey] = $this->normalizePath($path);
        $this->assertType($type);

        $existing = $this->findActiveByPathKey($pathKey);
        if ($existing !== null) {
            return $existing;
        }

        $now = $this->now();
        $fileId = $this->uuid();

        try {
            $this->execute(
                'INSERT INTO files
                    (file_id, path, path_key, type, created_at, updated_at, deleted_at, copied_from_file_id)
                 VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)',
                [$fileId, $normalizedPath, $pathKey, $type, $now, $now]
            );
        } catch (\Exception $exception) {
            // A concurrent writer may have created the active identity first;
            // the unique active-path index is the source of truth.
            $existing = $this->findActiveByPathKey($pathKey);
            if ($existing !== null) {
                return $existing;
            }

            throw new \RuntimeException('Unable to create file identity.', 0, $exception);
        }

        $identity = $this->findById($fileId);
        if ($identity === null) {
            throw new \RuntimeException('File identity was not persisted.');
        }

        return $identity;
    }

    public function findByPath(string $path): ?array
    {
        [, $pathKey] = $this->normalizePath($path);

        return $this->findActiveByPathKey($pathKey);
    }

    public function findById(string $fileId): ?array
    {
        if ($fileId === '') {
            return null;
        }

        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM files WHERE file_id = ? LIMIT 1',
            [$fileId]
        );

        return $row === null ? null : FileIdentity::fromArray($row)->toArray();
    }

    public function findByPathIncludingDeleted(string $path): ?array
    {
        [, $pathKey] = $this->normalizePath($path);

        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM files
             WHERE path_key = ?
             ORDER BY updated_at DESC, created_at DESC
             LIMIT 1',
            [$pathKey]
        );

        return $row === null ? null : FileIdentity::fromArray($row)->toArray();
    }

    public function rename(string $fileId, string $newPath): array
    {
        return $this->relocate($fileId, $newPath);
    }

    public function move(string $fileId, string $newPath): array
    {
        return $this->relocate($fileId, $newPath);
    }

    public function copy(string $sourceFileId, string $newPath): array
    {
        $source = $this->findById($sourceFileId);
        if ($source === null) {
            throw new \RuntimeException('Source file identity does not exist.');
        }

        [$normalizedPath, $pathKey] = $this->normalizePath($newPath);

        if ($this->findActiveByPathKey($pathKey) !== null) {
            throw new \RuntimeException('Destination path already has an active identity.');
        }

        $now = $this->now();
        $fileId = $this->uuid();

        $this->execute(
            'INSERT INTO files
                (file_id, path, path_key, type, created_at, updated_at, deleted_at, copied_from_file_id)
             VALUES (?, ?, ?, ?, ?, ?, NULL, ?)',
            [$fileId, $normalizedPath, $pathKey, $source['type'], $now, $now, $sourceFileId]
        );

        $identity = $this->findById($fileId);
        if ($identity === null) {
            throw new \RuntimeException('Copied file identity was not persisted.');
        }

        return $identity;
    }

    public function softDelete(string $fileId): bool
    {
        if ($fileId === '') {
            return false;
        }

        $now = $this->now();

        $changed = $this->execute(
            'UPDATE files SET deleted_at = ?, updated_at = ? WHERE file_id = ? AND deleted_at IS NULL',
            [$now, $now, $fileId]
        );

        return $changed > 0;
    }

    /**
     * Rename and move share the same identity rule: keep file_id, rewrite the
     * path, and refuse to collide with another active identity.
     */
    protected function relocate(string $fileId, string $newPath): array
    {
        if ($fileId === '') {
            throw new \InvalidArgumentException('A file_id is required.');
        }

        [$normalizedPath, $pathKey] = $this->normalizePath($newPath);

        $current = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM files WHERE file_id = ? AND deleted_at IS NULL LIMIT 1',
            [$fileId]
        );

        if ($current === null) {
            throw new \RuntimeException('File identity was not found or is already deleted.');
        }

        $conflict = $this->fetchOne(
            'SELECT file_id FROM files WHERE path_key = ? AND deleted_at IS NULL AND file_id <> ? LIMIT 1',
            [$pathKey, $fileId]
        );

        if ($conflict !== null) {
            throw new \RuntimeException('Destination path already has an active identity.');
        }

        $this->execute(
            'UPDATE files SET path = ?, path_key = ?, updated_at = ? WHERE file_id = ? AND deleted_at IS NULL',
            [$normalizedPath, $pathKey, $this->now(), $fileId]
        );

        $identity = $this->findById($fileId);
        if ($identity === null) {
            throw new \RuntimeException('Renamed file identity could not be reloaded.');
        }

        return $identity;
    }

    protected function findActiveByPathKey(string $pathKey): ?array
    {
        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM files WHERE path_key = ? AND deleted_at IS NULL LIMIT 1',
            [$pathKey]
        );

        return $row === null ? null : FileIdentity::fromArray($row)->toArray();
    }

    /**
     * @return array{0: string, 1: string} Normalised path and lowercase path_key.
     */
    protected function normalizePath(string $path): array
    {
        $path = trim($path);
        $path = str_replace('\\', '/', $path);

        foreach (explode('/', $path) as $segment) {
            if ($segment === '..') {
                throw new \InvalidArgumentException('A path must not contain a ".." segment.');
            }
        }

        $collapsed = preg_replace('#/+#', '/', $path);
        if ($collapsed === null || $collapsed === '') {
            $collapsed = '/';
        }

        if ($collapsed[0] !== '/') {
            $collapsed = '/'.$collapsed;
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

    protected function assertType(string $type): void
    {
        if (! in_array($type, ['file', 'dir'], true)) {
            throw new \InvalidArgumentException('File identity type must be "file" or "dir".');
        }
    }

    protected function database(): \SQLite3
    {
        $database = $this->connection->connection();

        // The schema is installed lazily by the first consumer (see
        // SchemaInstaller). Without this, the very first identity write after a
        // fresh database would fail before the audit logger has provisioned the
        // schema. install() is idempotent (IF NOT EXISTS) and only runs once per
        // repository instance.
        if (! $this->schemaReady) {
            (new SchemaInstaller($this->connection))->install();
            $this->schemaReady = true;
        }

        return $database;
    }

    protected function fetchOne(string $sql, array $params = []): ?array
    {
        $statement = $this->database()->prepare($sql);
        $this->bindValues($statement, $params);

        $result = $statement->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        $result->finalize();
        $statement->close();

        return $row === false ? null : $row;
    }

    protected function execute(string $sql, array $params = []): int
    {
        $database = $this->database();
        $statement = $database->prepare($sql);
        $this->bindValues($statement, $params);

        $statement->execute();
        $changed = $database->changes();

        $statement->close();

        return $changed;
    }

    protected function bindValues(\SQLite3Stmt $statement, array $params): void
    {
        $index = 1;

        foreach ($params as $value) {
            if ($value === null) {
                $statement->bindValue($index, null, SQLITE3_NULL);
            } elseif (is_int($value)) {
                $statement->bindValue($index, $value, SQLITE3_INTEGER);
            } else {
                $statement->bindValue($index, (string) $value, SQLITE3_TEXT);
            }

            $index++;
        }
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
}
