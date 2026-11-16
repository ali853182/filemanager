<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile\Adapters\Sqlite;

use Filegator\Services\Service;

/**
 * Creates the file profile query store schema.
 *
 * The installer is idempotent: every statement uses IF NOT EXISTS so it can be
 * executed on every request/bootstrap without touching existing data. It
 * provisions the files identity table, the comments table, the FTS5 comment
 * index (with synchronisation triggers) and the audit_events query index from
 * spec.md 7.
 */
class SchemaInstaller implements Service
{
    protected $connection;

    public function __construct(SqliteConnection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * Service bootstrap is intentionally a no-op: the schema is installed
     * lazily by the first consumer so an unavailable database never breaks
     * application bootstrap.
     */
    public function init(array $config = [])
    {
    }

    public function install(): void
    {
        $database = $this->connection->connection();

        $database->exec(
            'CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                path_key TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT NULL,
                copied_from_file_id TEXT NULL
            )'
        );

        $database->exec(
            'CREATE UNIQUE INDEX IF NOT EXISTS files_path_active
                ON files(path_key) WHERE deleted_at IS NULL'
        );

        $database->exec('CREATE INDEX IF NOT EXISTS files_file_id ON files(file_id)');

        $database->exec(
            'CREATE TABLE IF NOT EXISTS comments (
                comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                user TEXT NOT NULL,
                role TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NULL,
                deleted_at TEXT NULL,
                FOREIGN KEY(file_id) REFERENCES files(file_id)
            )'
        );

        $database->exec('CREATE INDEX IF NOT EXISTS comments_file_id ON comments(file_id)');
        $database->exec('CREATE INDEX IF NOT EXISTS comments_created_at ON comments(created_at)');

        $database->exec(
            "CREATE VIRTUAL TABLE IF NOT EXISTS comments_fts USING fts5(
                body,
                user,
                file_id UNINDEXED,
                content='comments',
                content_rowid='comment_id',
                tokenize='unicode61 remove_diacritics 2'
            )"
        );

        $database->exec(
            'CREATE TRIGGER IF NOT EXISTS comments_ai AFTER INSERT ON comments BEGIN
                INSERT INTO comments_fts(rowid, body, user, file_id)
                VALUES (new.comment_id, new.body, new.user, new.file_id);
            END'
        );

        $database->exec(
            "CREATE TRIGGER IF NOT EXISTS comments_ad AFTER DELETE ON comments BEGIN
                INSERT INTO comments_fts(comments_fts, rowid, body, user, file_id)
                VALUES ('delete', old.comment_id, old.body, old.user, old.file_id);
            END"
        );

        $database->exec(
            "CREATE TRIGGER IF NOT EXISTS comments_au AFTER UPDATE ON comments BEGIN
                INSERT INTO comments_fts(comments_fts, rowid, body, user, file_id)
                VALUES ('delete', old.comment_id, old.body, old.user, old.file_id);
                INSERT INTO comments_fts(rowid, body, user, file_id)
                VALUES (new.comment_id, new.body, new.user, new.file_id);
            END"
        );

        $database->exec(
            'CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                user TEXT NOT NULL,
                role TEXT NOT NULL,
                ip TEXT NOT NULL,
                action TEXT NOT NULL,
                file_id TEXT NULL,
                path TEXT NOT NULL,
                path_key TEXT NOT NULL,
                destination TEXT NULL,
                result TEXT NOT NULL,
                meta_json TEXT NULL
            )'
        );

        $database->exec('CREATE INDEX IF NOT EXISTS audit_events_file_id ON audit_events(file_id)');
        $database->exec('CREATE INDEX IF NOT EXISTS audit_events_path_key ON audit_events(path_key)');
        $database->exec('CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events(ts)');
    }
}
