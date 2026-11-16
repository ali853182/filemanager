<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile\Adapters\Sqlite;

use Filegator\Services\FileProfile\Comment;
use Filegator\Services\FileProfile\CommentRepositoryInterface;
use Filegator\Services\Service;

/**
 * SQLite-backed implementation of the flat comment store (spec.md 7.2, 7.3, 10).
 *
 * Storage only: validation, moderation and ACL checks are the caller's
 * responsibility (see CommentService). Every statement uses prepared
 * statements with bound values and explicit columns (no SELECT *); comment
 * bodies are never logged.
 *
 * Search uses the FTS5 comments_fts index (unicode61 remove_diacritics 2).
 * Terms of two or more characters become prefix queries ("term"*); a
 * one-character query or an FTS syntax error falls back to an escaped LIKE
 * query. The result rows are NOT ACL-filtered here; CommentService drops
 * results whose current path the user cannot read.
 */
class SqliteCommentRepository implements CommentRepositoryInterface, Service
{
    protected const COLUMNS = 'comment_id, file_id, user, role, body, created_at, updated_at, deleted_at';

    protected const HIT_COLUMNS = 'c.comment_id, c.file_id, c.user, c.role, c.body, c.created_at, f.path';

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

    public function addComment(string $fileId, string $user, string $role, string $body): int
    {
        $this->execute(
            'INSERT INTO comments (file_id, user, role, body, created_at, updated_at, deleted_at)
             VALUES (?, ?, ?, ?, ?, NULL, NULL)',
            [$fileId, $user, $role, $body, $this->now()]
        );

        return (int) $this->database()->lastInsertRowID();
    }

    public function findCommentById(int $commentId): ?array
    {
        if ($commentId <= 0) {
            return null;
        }

        $row = $this->fetchOne(
            'SELECT '.self::COLUMNS.' FROM comments WHERE comment_id = ? LIMIT 1',
            [$commentId]
        );

        return $row === null ? null : Comment::fromArray($row)->toArray();
    }

    public function listComments(string $fileId, int $limit, int $offset): array
    {
        $limit = $this->clampLimit($limit);
        $offset = $offset < 0 ? 0 : $offset;

        $rows = $this->fetchAll(
            'SELECT '.self::COLUMNS.' FROM comments
             WHERE file_id = ? AND deleted_at IS NULL
             ORDER BY created_at DESC, comment_id DESC
             LIMIT ? OFFSET ?',
            [$fileId, $limit, $offset]
        );

        $comments = [];
        foreach ($rows as $row) {
            $comments[] = Comment::fromArray($row)->toArray();
        }

        return $comments;
    }

    public function countComments(string $fileId): int
    {
        $row = $this->fetchOne(
            'SELECT COUNT(comment_id) AS total FROM comments WHERE file_id = ? AND deleted_at IS NULL',
            [$fileId]
        );

        return $row === null ? 0 : (int) $row['total'];
    }

    public function softDeleteComment(int $commentId, string $actor, bool $isAdmin): bool
    {
        if ($commentId <= 0) {
            return false;
        }

        $changed = $this->execute(
            'UPDATE comments SET deleted_at = ?
             WHERE comment_id = ? AND deleted_at IS NULL AND (user = ? OR ? = 1)',
            [$this->now(), $commentId, $actor, $isAdmin ? 1 : 0]
        );

        return $changed > 0;
    }

    public function searchComments(string $query, int $limit, int $offset): array
    {
        $limit = $this->clampLimit($limit);
        $offset = $offset < 0 ? 0 : $offset;

        $query = trim($query);
        if ($query === '') {
            return [];
        }

        $terms = $this->tokenize($query);

        // A query with no token of two or more characters (for example a
        // single character) cannot use prefix matching meaningfully, so use
        // the LIKE fallback. An empty FTS expression also falls back.
        $ftsTerms = [];
        foreach ($terms as $term) {
            if ($this->length($term) >= 2) {
                $ftsTerms[] = $term;
            }
        }

        if ($ftsTerms === []) {
            return $this->searchLike($query, $terms, $limit, $offset);
        }

        try {
            $rows = $this->fetchAll(
                'SELECT '.self::HIT_COLUMNS.'
                 FROM comments_fts
                 JOIN comments c ON c.comment_id = comments_fts.rowid
                 JOIN files f ON f.file_id = c.file_id
                 WHERE comments_fts MATCH ? AND c.deleted_at IS NULL
                 ORDER BY c.created_at DESC, c.comment_id DESC
                 LIMIT ? OFFSET ?',
                [$this->buildFtsExpression($ftsTerms), $limit, $offset]
            );
        } catch (\Throwable $exception) {
            // FTS syntax errors (or an unavailable index) degrade to LIKE so a
            // malformed query never breaks search.
            return $this->searchLike($query, $terms, $limit, $offset);
        }

        return $this->shapeHits($rows, $terms);
    }

    /**
     * Escaped LIKE fallback used for one-character queries and FTS failures.
     */
    protected function searchLike(string $query, array $terms, int $limit, int $offset): array
    {
        $pattern = '%'.$this->escapeLike($query).'%';

        $rows = $this->fetchAll(
            'SELECT '.self::HIT_COLUMNS.'
             FROM comments c
             JOIN files f ON f.file_id = c.file_id
             WHERE c.deleted_at IS NULL AND c.body LIKE ? ESCAPE \'\\\'
             ORDER BY c.created_at DESC, c.comment_id DESC
             LIMIT ? OFFSET ?',
            [$pattern, $limit, $offset]
        );

        return $this->shapeHits($rows, $terms);
    }

    /**
     * Build a safe FTS5 prefix expression: each term is quoted (internal
     * quotes doubled) and suffixed with "*" for prefix matching.
     *
     * @param string[] $terms
     */
    protected function buildFtsExpression(array $terms): string
    {
        $parts = [];
        foreach ($terms as $term) {
            $parts[] = '"'.str_replace('"', '""', $term).'"*';
        }

        return implode(' ', $parts);
    }

    /**
     * @param array<int, array> $rows
     * @param string[]          $terms
     *
     * @return array<int, array>
     */
    protected function shapeHits(array $rows, array $terms): array
    {
        $hits = [];
        foreach ($rows as $row) {
            $hits[] = [
                'comment_id' => (int) $row['comment_id'],
                'file_id' => (string) $row['file_id'],
                'path' => (string) $row['path'],
                'user' => (string) $row['user'],
                'role' => (string) $row['role'],
                'snippet' => $this->snippet((string) $row['body'], $terms),
                'created_at' => (string) $row['created_at'],
            ];
        }

        return $hits;
    }

    /**
     * Plain-text excerpt around the first matching term. Never returns HTML
     * and never returns a full file body.
     *
     * @param string[] $terms
     */
    protected function snippet(string $body, array $terms): string
    {
        $body = trim(preg_replace('/\s+/u', ' ', $body) ?? $body);

        $position = false;
        foreach ($terms as $term) {
            if ($term === '') {
                continue;
            }
            $found = $this->stripos($body, $term);
            if ($found !== false && ($position === false || $found < $position)) {
                $position = $found;
            }
        }

        if ($position === false) {
            return $this->slice($body, 0, 120);
        }

        $start = $position - 40;
        if ($start < 0) {
            $start = 0;
        }

        $excerpt = $this->slice($body, $start, 120);
        if ($start > 0) {
            $excerpt = '…'.$excerpt;
        }
        if ($start + 120 < $this->length($body)) {
            $excerpt .= '…';
        }

        return $excerpt;
    }

    /**
     * Split a query into Unicode word tokens, dropping punctuation so the
     * value can never inject FTS5 syntax.
     *
     * @return string[]
     */
    protected function tokenize(string $query): array
    {
        $parts = preg_split('/[^\p{L}\p{N}_]+/u', $query, -1, PREG_SPLIT_NO_EMPTY);

        if (! is_array($parts)) {
            return [];
        }

        $terms = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part !== '') {
                $terms[] = $part;
            }
        }

        return $terms;
    }

    protected function escapeLike(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $value);
    }

    protected function clampLimit(int $limit): int
    {
        if ($limit < 1) {
            return 1;
        }

        if ($limit > 200) {
            return 200;
        }

        return $limit;
    }

    protected function database(): \SQLite3
    {
        $database = $this->connection->connection();

        // Install the schema lazily on first use (idempotent IF NOT EXISTS),
        // matching SqliteFileIdentityRepository and SchemaInstaller.
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

    protected function length(string $value): int
    {
        return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
    }

    protected function slice(string $value, int $start, int $length): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($value, $start, $length, 'UTF-8');
        }

        return substr($value, $start, $length);
    }

    /**
     * @return int|false
     */
    protected function stripos(string $haystack, string $needle)
    {
        if (function_exists('mb_stripos')) {
            return mb_stripos($haystack, $needle, 0, 'UTF-8');
        }

        return stripos($haystack, $needle);
    }

    protected function now(): string
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

        return $now->format('Y-m-d\TH:i:s.v\Z');
    }
}
