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
 * Storage contract for stable file identities (the file identity card key).
 *
 * Identity rules (spec.md 9)
 * --------------------------
 *   create file/dir       new file_id
 *   upload new file       new file_id
 *   upload overwrite      keep the existing active file_id for that path
 *   save content          keep the existing file_id
 *   rename                keep the same file_id, update path and path_key
 *   move                  keep the same file_id, update path and path_key
 *   copy                  new file_id; copied_from_file_id = source file_id
 *   zip                   new file_id for the archive; sources unchanged
 *   unzip                 new file_id per extracted entry; archive unchanged
 *   chmod                 keep the same file_id
 *   delete                soft-delete (deleted_at); keep comments and history
 *   re-create same path   new file_id; the old identity stays deleted
 *
 * Canonical mapping for callers:
 *   create/upload new/zip/unzip/re-create  -> create via ensureFile()
 *   upload overwrite/save/chmod            -> ensureFile() keeps the active id
 *   rename/move                            -> rename()/move() keep the same id
 *   copy                                   -> copy() creates a linked identity
 *   delete                                 -> softDelete() sets deleted_at
 *
 * Path normalization (shared with AuditLoggerInterface and PathAccessPolicy):
 * trim, convert "\" to "/", collapse duplicate "/", ensure a leading "/",
 * reject any ".." segment, and store path_key as the lowercased path so
 * Windows lookups are case-insensitive.
 *
 * Every method returns an identity array shaped by FileIdentity::toArray():
 *   file_id, path, path_key, type, created_at, updated_at,
 *   deleted_at, copied_from_file_id
 *
 * Implementations must use prepared statements with bound values and must not
 * echo or log file contents, credentials, tokens or session ids.
 */
interface FileIdentityRepositoryInterface
{
    /**
     * Return the active identity for a path, creating a new file_id when the
     * path has no active identity.
     *
     * Used by create, upload-new, upload-overwrite, save, chmod, zip and
     * unzip. When an active identity already exists it is returned unchanged,
     * which is what "keep the same file_id" means for overwrite/save/chmod.
     * A soft-deleted identity on the same path is ignored, so re-creating the
     * path yields a new file_id.
     *
     * @param string $path Normalized storage path.
     * @param string $type "file" or "dir".
     *
     * @throws \InvalidArgumentException for an unsupported type or a path
     *                                   containing a ".." segment.
     */
    public function ensureFile(string $path, string $type): array;

    /**
     * Find the active identity for a path (case-insensitive via path_key).
     *
     * Returns null when the path has no active identity, including when the
     * only known identity has been soft-deleted.
     */
    public function findByPath(string $path): ?array;

    /**
     * Find an identity by file_id, including soft-deleted identities.
     *
     * This is the lookup used by the file identity card, which must keep
     * showing the history of deleted files while path ACLs still allow it.
     */
    public function findById(string $fileId): ?array;

    /**
     * Find the most recently updated identity for a path, including a
     * soft-deleted identity.
     *
     * The file identity card uses this to keep showing the retained history
     * and comments of a deleted file. Because a path may be re-created after a
     * delete, the newest row (updated_at DESC) is returned; callers must check
     * deleted_at before treating it as the active identity.
     */
    public function findByPathIncludingDeleted(string $path): ?array;

    /**
     * Update the path of an existing identity for a rename.
     *
     * The file_id is preserved; path and path_key are rewritten. Only active
     * identities can be renamed.
     *
     * @throws \RuntimeException when the identity is missing/deleted or the
     *                           destination path already has an active identity.
     */
    public function rename(string $fileId, string $newPath): array;

    /**
     * Update the path of an existing identity for a move.
     *
     * Same identity rule as rename(): the file_id is preserved and only
     * path/path_key change. A move into another directory is not a copy.
     *
     * @throws \RuntimeException when the identity is missing/deleted or the
     *                           destination path already has an active identity.
     */
    public function move(string $fileId, string $newPath): array;

    /**
     * Create a new identity for a copied item.
     *
     * The destination receives a new file_id and copied_from_file_id is set
     * to the source identity. Source comments and history stay attached to
     * the source id.
     *
     * @throws \RuntimeException when the source is missing or the destination
     *                           path already has an active identity.
     */
    public function copy(string $sourceFileId, string $newPath): array;

    /**
     * Soft-delete an identity by setting deleted_at.
     *
     * Comments and audit history are retained. The path may be re-used later
     * with a new file_id.
     *
     * @return bool true when an active identity was soft-deleted; false when
     *              the identity is unknown or already deleted.
     */
    public function softDelete(string $fileId): bool;
}
