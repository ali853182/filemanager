<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile\Adapters\Sqlite;

use Filegator\Services\FileProfile\AuditEventRepositoryInterface;
use Filegator\Services\Service;

/**
 * SQLite-backed read model for the audit_events query index.
 *
 * Every statement uses prepared statements with bound values and explicit
 * columns (no SELECT *). Filter column names are chosen from a fixed, trusted
 * map; user values are always bound. meta_json is decoded into a plain array
 * and the raw column is never returned, so report output cannot leak the
 * serialized form.
 */
class SqliteAuditEventRepository implements AuditEventRepositoryInterface, Service
{
    protected const COLUMNS = 'event_id, ts, user, role, ip, action, file_id, path, destination, result, meta_json';

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

    public function listByFileId(string $fileId, int $limit, int $offset): array
    {
        if ($fileId === '') {
            return [];
        }

        [$limit, $offset] = $this->clamp($limit, $offset);

        $rows = $this->fetchAll(
            'SELECT '.self::COLUMNS.' FROM audit_events
             WHERE file_id = ?
             ORDER BY ts DESC, event_id DESC
             LIMIT ? OFFSET ?',
            [$fileId, $limit, $offset]
        );

        return $this->shapeRows($rows);
    }

    public function countByFileId(string $fileId): int
    {
        if ($fileId === '') {
            return 0;
        }

        $row = $this->fetchOne(
            'SELECT COUNT(event_id) AS total FROM audit_events WHERE file_id = ?',
            [$fileId]
        );

        return $row === null ? 0 : (int) $row['total'];
    }

    public function firstByFileId(string $fileId): ?array
    {
        if ($fileId === '') {
            return null;
        }

        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM audit_events
             WHERE file_id = ?
             ORDER BY ts ASC, event_id ASC
             LIMIT 1',
            [$fileId]
        );

        return $row === null ? null : $this->shapeRow($row);
    }

    public function latestByFileId(string $fileId): ?array
    {
        if ($fileId === '') {
            return null;
        }

        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM audit_events
             WHERE file_id = ?
             ORDER BY ts DESC, event_id DESC
             LIMIT 1',
            [$fileId]
        );

        return $row === null ? null : $this->shapeRow($row);
    }

    public function search(array $filters, int $limit, int $offset): array
    {
        [$limit, $offset] = $this->clamp($limit, $offset);
        [$where, $params] = $this->buildWhere($filters);

        $params[] = $limit;
        $params[] = $offset;

        $rows = $this->fetchAll(
            'SELECT '.self::COLUMNS.' FROM audit_events'
            .$where
            .' ORDER BY ts DESC, event_id DESC LIMIT ? OFFSET ?',
            $params
        );

        return $this->shapeRows($rows);
    }

    public function countSearch(array $filters): int
    {
        [$where, $params] = $this->buildWhere($filters);

        $row = $this->fetchOne(
            'SELECT COUNT(event_id) AS total FROM audit_events'.$where,
            $params
        );

        return $row === null ? 0 : (int) $row['total'];
    }

    /**
     * Build a WHERE clause from a fixed set of trusted column names. Only the
     * column names are taken from this map; every value is bound.
     *
     * @param array<string, string|null> $filters
     *
     * @return array{0: string, 1: array<int, string>}
     */
    protected function buildWhere(array $filters): array
    {
        $clauses = [];
        $params = [];

        $from = $this->stringFilter($filters, 'from');
        if ($from !== null) {
            $clauses[] = 'ts >= ?';
            $params[] = $from;
        }

        $to = $this->stringFilter($filters, 'to');
        if ($to !== null) {
            $clauses[] = 'ts <= ?';
            $params[] = $to;
        }

        $user = $this->stringFilter($filters, 'user');
        if ($user !== null) {
            $clauses[] = 'user = ?';
            $params[] = $user;
        }

        $action = $this->stringFilter($filters, 'action');
        if ($action !== null) {
            $clauses[] = 'action = ?';
            $params[] = $action;
        }

        $path = $this->stringFilter($filters, 'path');
        if ($path !== null) {
            $clauses[] = 'path_key = ?';
            $params[] = $this->pathKey($path);
        }

        $fileId = $this->stringFilter($filters, 'file_id');
        if ($fileId !== null) {
            $clauses[] = 'file_id = ?';
            $params[] = $fileId;
        }

        $result = $this->stringFilter($filters, 'result');
        if ($result !== null) {
            $clauses[] = 'result = ?';
            $params[] = $result;
        }

        return [$clauses === [] ? '' : ' WHERE '.implode(' AND ', $clauses), $params];
    }

    /**
     * @param array<string, string|null> $filters
     */
    protected function stringFilter(array $filters, string $key): ?string
    {
        if (! isset($filters[$key])) {
            return null;
        }

        $value = trim((string) $filters[$key]);

        return $value === '' ? null : $value;
    }

    protected function pathKey(string $path): string
    {
        $path = trim($path);
        $path = str_replace('\\', '/', $path);
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

        return function_exists('mb_strtolower')
            ? mb_strtolower($collapsed, 'UTF-8')
            : strtolower($collapsed);
    }

    /**
     * @return array{0: int, 1: int}
     */
    protected function clamp(int $limit, int $offset): array
    {
        if ($limit < 1) {
            $limit = 100;
        }

        if ($limit > 1000) {
            $limit = 1000;
        }

        if ($offset < 0) {
            $offset = 0;
        }

        return [$limit, $offset];
    }

    /**
     * @param array<int, array> $rows
     *
     * @return array<int, array>
     */
    protected function shapeRows(array $rows): array
    {
        $events = [];
        foreach ($rows as $row) {
            $events[] = $this->shapeRow($row);
        }

        return $events;
    }

    /**
     * @param array<string, mixed> $row
     *
     * @return array<string, mixed>
     */
    protected function shapeRow(array $row): array
    {
        $meta = null;
        if (isset($row['meta_json']) && $row['meta_json'] !== null && $row['meta_json'] !== '') {
            $decoded = json_decode((string) $row['meta_json'], true);
            if (is_array($decoded)) {
                $meta = $decoded;
            }
        }

        return [
            'event_id' => (string) $row['event_id'],
            'ts' => (string) $row['ts'],
            'user' => (string) $row['user'],
            'role' => (string) $row['role'],
            'ip' => (string) $row['ip'],
            'action' => (string) $row['action'],
            'file_id' => isset($row['file_id']) ? (string) $row['file_id'] : null,
            'path' => (string) $row['path'],
            'destination' => isset($row['destination']) ? (string) $row['destination'] : null,
            'result' => (string) $row['result'],
            'meta' => $meta,
        ];
    }

    protected function database(): \SQLite3
    {
        $database = $this->connection->connection();

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

    /**
     * @return array<int, array>
     */
    protected function fetchAll(string $sql, array $params = []): array
    {
        $statement = $this->database()->prepare($sql);
        $this->bindValues($statement, $params);

        $result = $statement->execute();

        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }

        $result->finalize();
        $statement->close();

        return $rows;
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
}
