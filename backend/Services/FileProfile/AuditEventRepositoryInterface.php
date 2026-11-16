<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile;

/**
 * Read-only query contract for the SQLite audit_events query index.
 *
 * The JSONL ledger at private/logs/audit.log remains the append-only source of
 * truth (see AuditLoggerInterface). This repository only reads the rebuildable
 * index that MonoAuditLogger mirrors into SQLite. It never writes, never
 * returns file contents or secrets, and uses prepared statements with bound
 * values and explicit columns only.
 *
 * Row shape returned by every method:
 *   event_id, ts, user, role, ip, action, file_id, path, destination, result,
 *   meta (decoded meta_json object or null)
 *
 * Ordering is newest first (ts DESC, event_id DESC) unless documented
 * otherwise. Callers must still apply their own authorization decisions; the
 * file identity card and the CLI tools are admin-facing readers.
 */
interface AuditEventRepositoryInterface
{
    /**
     * Page through the audit events of one file identity, newest first.
     *
     * @return array<int, array>
     */
    public function listByFileId(string $fileId, int $limit, int $offset): array;

    /**
     * Total number of audit events for one file identity.
     */
    public function countByFileId(string $fileId): int;

    /**
     * Oldest audit event for one file identity (used for summary.created_at).
     */
    public function firstByFileId(string $fileId): ?array;

    /**
     * Newest audit event for one file identity (used for summary.last_modified_at).
     */
    public function latestByFileId(string $fileId): ?array;

    /**
     * Filtered, paginated event search for reports and the admin endpoint.
     *
     * Supported filters (all optional, empty values ignored):
     *   from, to      ISO-8601 timestamp bounds (inclusive)
     *   user          exact username
     *   action        exact action name
     *   path          exact normalized path (case-insensitive via path_key)
     *   file_id       exact file identity
     *   result        success|failure|denied
     *
     * @param array<string, string|null> $filters
     *
     * @return array<int, array>
     */
    public function search(array $filters, int $limit, int $offset): array;

    /**
     * Total number of events matching the same filters as search().
     *
     * @param array<string, string|null> $filters
     */
    public function countSearch(array $filters): int;
}
