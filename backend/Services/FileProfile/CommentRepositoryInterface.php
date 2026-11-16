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
 * Storage contract for flat, plain-text comments attached to a file identity.
 *
 * Stored fields (comments table): comment_id, file_id, user, role, body,
 * created_at, updated_at, deleted_at.
 *
 * Rules (spec.md 10):
 *   - body is trimmed, plain text, 1-5000 characters; never HTML.
 *   - comments are listed newest first and soft-deleted comments are hidden.
 *   - soft delete only; the author or an admin may delete.
 *   - comment bodies never enter the audit ledger.
 *
 * The repository is storage only: it does not know about User objects and
 * therefore does not enforce ACLs. The calling service MUST pass every path
 * through PathAccessPolicy::canRead before adding, listing, deleting or
 * returning a comment, and MUST drop search results whose current path is not
 * readable. Implementations must use prepared statements with bound values
 * and must never log comment bodies.
 */
interface CommentRepositoryInterface
{
    /**
     * Insert a comment and return its comment_id.
     *
     * The repository stamps created_at itself. Validation and ACL checks are
     * the caller's responsibility.
     */
    public function addComment(string $fileId, string $user, string $role, string $body): int;

    /**
     * Find a comment by comment_id, including soft-deleted comments.
     *
     * The moderation service needs the author before deciding whether the
     * acting user may delete it. Returns null when the comment is unknown.
     */
    public function findCommentById(int $commentId): ?array;

    /**
     * List active comments for a file identity, newest first.
     *
     * @param int $limit  Maximum rows to return.
     * @param int $offset Rows to skip.
     *
     * @return array<int, array> Comment rows shaped by Comment::toArray().
     */
    public function listComments(string $fileId, int $limit, int $offset): array;

    /**
     * Count active comments for a file identity.
     *
     * Used by the file identity card summary.
     */
    public function countComments(string $fileId): int;

    /**
     * Soft-delete a comment when the actor is its author or an admin.
     *
     * Sets deleted_at instead of removing the row. Returns false when the
     * comment is unknown, already deleted, or the actor is not allowed to
     * delete it.
     */
    public function softDeleteComment(int $commentId, string $actor, bool $isAdmin): bool;

    /**
     * Search active comments using FTS5, with a LIKE fallback for short terms.
     *
     * Results are NOT ACL-filtered by the repository. The caller must check
     * PathAccessPolicy::canRead for each result's current path and drop
     * unreadable rows before pagination is finalized.
     *
     * @return array<int, array> Hits shaped as:
     *                           comment_id, file_id, path, user, role,
     *                           snippet, created_at
     */
    public function searchComments(string $query, int $limit, int $offset): array;
}
