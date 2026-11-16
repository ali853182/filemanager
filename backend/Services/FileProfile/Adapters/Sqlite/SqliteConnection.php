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
 * Owns the single SQLite3 handle used by the file profile query store.
 *
 * The database is opened lazily on the first connection() call so that a
 * misconfigured or unavailable path never breaks application bootstrap. The
 * handle is configured with WAL journaling, foreign keys and a busy timeout so
 * concurrent readers and the audit writer do not fail with "database is
 * locked" under normal load.
 */
class SqliteConnection implements Service
{
    protected $databasePath;

    protected $connection;

    public function __construct(?string $databasePath = null)
    {
        $this->databasePath = $databasePath;
    }

    public function init(array $config = [])
    {
        if (isset($config['path']) && is_string($config['path']) && $config['path'] !== '') {
            $this->databasePath = $config['path'];
        }
    }

    public function getDatabasePath(): string
    {
        if ($this->databasePath === null || $this->databasePath === '') {
            throw new \RuntimeException('SQLite database path is not configured.');
        }

        return $this->databasePath;
    }

    /**
     * Open (or create) the database and return the shared SQLite3 handle.
     */
    public function connection(): \SQLite3
    {
        if ($this->connection instanceof \SQLite3) {
            return $this->connection;
        }

        $path = $this->getDatabasePath();
        $directory = dirname($path);

        if (! is_dir($directory)) {
            if (! @mkdir($directory, 0775, true) && ! is_dir($directory)) {
                throw new \RuntimeException('Unable to create SQLite directory: '.$directory);
            }
        }

        $database = new \SQLite3($path);
        $database->enableExceptions(true);

        $database->querySingle('PRAGMA journal_mode = WAL');
        $database->exec('PRAGMA foreign_keys = ON');
        $database->exec('PRAGMA busy_timeout = 5000');

        $this->connection = $database;

        return $this->connection;
    }

    public function close(): void
    {
        if ($this->connection instanceof \SQLite3) {
            $this->connection->close();
            $this->connection = null;
        }
    }
}
