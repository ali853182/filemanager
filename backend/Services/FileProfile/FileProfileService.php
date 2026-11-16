<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile;

use Filegator\Config\Config;
use Filegator\Services\Access\PathAccessPolicy;
use Filegator\Services\Auth\User;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Service;
use Filegator\Services\Storage\Filesystem;
use Monolog\Logger;

/**
 * Aggregates the file identity card (spec.md 11, FR8).
 *
 * The card combines:
 *   - current file metadata from Filesystem (size, modified_at, permissions,
 *     exists, type);
 *   - the stable file_id from FileIdentityRepositoryInterface;
 *   - a summary built from the first/latest audit events and the comment count;
 *   - the audit timeline (newest first, paginated);
 *   - the active comments (newest first, paginated).
 *
 * ACL: the caller's PathAccessPolicy::canRead is checked before any storage or
 * query store access. A deleted identity is shown only to an admin (spec.md 11,
 * Q9); other users receive 404 so the existence of a deleted file is not
 * leaked. When file_profile.enabled is false the method is a no-op that
 * returns 404 and touches no storage (spec.md 15).
 *
 * Non-blocking (FR10): metadata, audit and comment failures are caught and
 * reported to the logger; they degrade the card to empty sections and never
 * throw to the controller.
 */
class FileProfileService implements Service
{
    public const STATUS_OK = 200;

    public const STATUS_BAD_REQUEST = 400;

    public const STATUS_FORBIDDEN = 403;

    public const STATUS_NOT_FOUND = 404;

    public const STATUS_ERROR = 500;

    protected const DEFAULT_LIMIT = 50;

    protected const MAX_LIMIT = 200;

    protected $config;

    protected $identities;

    protected $comments;

    protected $auditEvents;

    protected $accessPolicy;

    protected $filesystem;

    protected $logger;

    public function __construct(
        Config $config,
        FileIdentityRepositoryInterface $identities,
        CommentRepositoryInterface $comments,
        AuditEventRepositoryInterface $auditEvents,
        PathAccessPolicy $accessPolicy,
        Filesystem $filesystem,
        LoggerInterface $logger = null
    ) {
        $this->config = $config;
        $this->identities = $identities;
        $this->comments = $comments;
        $this->auditEvents = $auditEvents;
        $this->accessPolicy = $accessPolicy;
        $this->filesystem = $filesystem;
        $this->logger = $logger;
    }

    /**
     * Service bootstrap has no configuration of its own; settings are read
     * from Config on demand.
     */
    public function init(array $config = [])
    {
    }

    public function isEnabled(): bool
    {
        return (bool) $this->config->get('file_profile.enabled', false);
    }

    /**
     * Build the file identity card for a path.
     *
     * @return array{status: int, data: mixed}
     */
    public function getProfile(
        User $user,
        string $path,
        int $historyLimit = 0,
        int $commentsLimit = 0,
        int $historyOffset = 0,
        int $commentsOffset = 0
    ): array {
        if (! $this->isEnabled()) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        if ($user->isGuest()) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $normalized = $this->normalizePath($path);
        if ($normalized === null) {
            return $this->result(self::STATUS_BAD_REQUEST, 'Invalid path');
        }

        if (! $this->accessPolicy->canRead($user, $normalized)) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $identity = $this->resolveIdentity($normalized);
        if ($identity !== null && $identity['deleted_at'] !== null && ! $user->isAdmin()) {
            // A deleted file is only visible to an admin/auditor. 404 avoids
            // leaking its existence to ordinary readers.
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        $fileId = $identity !== null ? (string) $identity['file_id'] : null;

        $historyLimit = $this->clampLimit($historyLimit, 'file_profile.history_limit');
        $commentsLimit = $this->clampLimit($commentsLimit, 'file_profile.comments_limit');
        $historyOffset = $historyOffset < 0 ? 0 : $historyOffset;
        $commentsOffset = $commentsOffset < 0 ? 0 : $commentsOffset;

        $metadata = $this->metadata($normalized, $identity);

        $history = [];
        if ($fileId !== null) {
            try {
                $history = $this->auditEvents->listByFileId($fileId, $historyLimit, $historyOffset);
            } catch (\Throwable $exception) {
                $this->report('File profile history failed: '.$exception->getMessage());
                $history = [];
            }
        }

        // IP addresses are personal data (spec.md 14). Only admins see the
        // full audit event; ordinary readers get the timeline without the IP.
        if (! $user->isAdmin()) {
            foreach ($history as $index => $event) {
                unset($history[$index]['ip']);
            }
        }

        $comments = [];
        $commentCount = 0;
        if ($fileId !== null && (bool) $this->config->get('comments.enabled', false)) {
            try {
                $comments = $this->comments->listComments($fileId, $commentsLimit, $commentsOffset);
                $commentCount = $this->comments->countComments($fileId);
            } catch (\Throwable $exception) {
                $this->report('File profile comments failed: '.$exception->getMessage());
                $comments = [];
                $commentCount = 0;
            }
        }

        $summary = $this->summary($fileId, $commentCount);

        return $this->result(self::STATUS_OK, [
            'file' => $metadata,
            'summary' => $summary,
            'history' => $history,
            'comments' => $comments,
        ]);
    }

    /**
     * Resolve the active identity, then fall back to the newest identity
     * (including a soft-deleted one) for the deleted-file card.
     */
    protected function resolveIdentity(string $path): ?array
    {
        try {
            $identity = $this->identities->findByPath($path);
            if ($identity !== null) {
                return $identity;
            }

            return $this->identities->findByPathIncludingDeleted($path);
        } catch (\Throwable $exception) {
            $this->report('File profile identity lookup failed: '.$exception->getMessage());

            return null;
        }
    }

    /**
     * Current metadata from the storage adapter. Any storage failure degrades
     * to exists=false rather than throwing.
     */
    protected function metadata(string $path, ?array $identity): array
    {
        $type = $identity !== null ? (string) $identity['type'] : 'file';
        $exists = false;
        $isDir = false;

        try {
            $exists = (bool) $this->filesystem->fileExists($path);
            if ($exists) {
                $isDir = (bool) $this->filesystem->isDir($path);
            }
        } catch (\Throwable $exception) {
            $this->report('File profile metadata failed: '.$exception->getMessage());
            $exists = false;
            $isDir = false;
        }

        $size = null;
        $modifiedAt = null;
        $permissions = null;

        if ($exists) {
            try {
                $entry = $this->findDirectoryEntry($path);
                if ($entry !== null) {
                    $size = isset($entry['size']) ? (int) $entry['size'] : null;

                    $timestamp = isset($entry['time']) ? (int) $entry['time'] : 0;
                    if ($timestamp > 0) {
                        $modifiedAt = gmdate('Y-m-d\TH:i:s\Z', $timestamp);
                    }

                    $permissionValue = $entry['permissions'] ?? -1;
                    if (is_int($permissionValue) && $permissionValue >= 0) {
                        $permissions = (string) $permissionValue;
                    }
                }
            } catch (\Throwable $exception) {
                $this->report('File profile metadata listing failed: '.$exception->getMessage());
            }
        }

        return [
            'file_id' => $identity !== null ? (string) $identity['file_id'] : null,
            'path' => $identity !== null ? (string) $identity['path'] : $path,
            'type' => $isDir ? 'dir' : $type,
            'size' => $size,
            'modified_at' => $modifiedAt,
            'permissions' => $permissions,
            'exists' => $exists,
            'deleted_at' => $identity !== null && $identity['deleted_at'] !== null
                ? (string) $identity['deleted_at']
                : null,
        ];
    }

    /**
     * Find the storage entry for a path by listing its parent directory. This
     * uses only the existing Filesystem public API (no adapter-specific code).
     */
    protected function findDirectoryEntry(string $path): ?array
    {
        $collection = $this->filesystem->getDirectoryCollection($this->parentPath($path), false);
        $data = $collection->jsonSerialize();

        foreach (($data['files'] ?? []) as $entry) {
            if (isset($entry['path']) && $entry['path'] === $path) {
                return $entry;
            }
        }

        return null;
    }

    protected function summary(?string $fileId, int $commentCount): array
    {
        $first = null;
        $latest = null;
        $eventCount = 0;

        if ($fileId !== null) {
            try {
                $first = $this->auditEvents->firstByFileId($fileId);
            } catch (\Throwable $exception) {
                $this->report('File profile first event failed: '.$exception->getMessage());
            }

            try {
                $latest = $this->auditEvents->latestByFileId($fileId);
            } catch (\Throwable $exception) {
                $this->report('File profile latest event failed: '.$exception->getMessage());
            }

            try {
                $eventCount = $this->auditEvents->countByFileId($fileId);
            } catch (\Throwable $exception) {
                $this->report('File profile event count failed: '.$exception->getMessage());
                $eventCount = 0;
            }
        }

        return ProfileSummary::fromArray([
            'created_at' => $first['ts'] ?? null,
            'created_by' => $first['user'] ?? null,
            'last_modified_at' => $latest['ts'] ?? null,
            'last_modified_by' => $latest['user'] ?? null,
            'event_count' => $eventCount,
            'comment_count' => $commentCount,
        ])->toArray();
    }

    protected function clampLimit(int $limit, string $configKey): int
    {
        if ($limit < 1) {
            $limit = (int) $this->config->get($configKey, self::DEFAULT_LIMIT);
        }

        if ($limit < 1) {
            $limit = self::DEFAULT_LIMIT;
        }

        return $limit > self::MAX_LIMIT ? self::MAX_LIMIT : $limit;
    }

    /**
     * Normalize and validate a path without throwing. Returns null for an
     * empty path or a ".." segment.
     */
    protected function normalizePath(string $path): ?string
    {
        $path = trim($path);
        $path = str_replace('\\', '/', $path);

        foreach (explode('/', $path) as $segment) {
            if ($segment === '..') {
                return null;
            }
        }

        $collapsed = preg_replace('#/+#', '/', $path);
        if ($collapsed === null || $collapsed === '') {
            return null;
        }

        if ($collapsed[0] !== '/') {
            $collapsed = '/'.$collapsed;
        }

        if (strlen($collapsed) > 1) {
            $collapsed = rtrim($collapsed, '/');
        }

        return $collapsed === '' ? '/' : $collapsed;
    }

    protected function parentPath(string $path): string
    {
        if ($path === '/' || $path === '') {
            return '/';
        }

        $position = strrpos($path, '/');
        if ($position === false || $position === 0) {
            return '/';
        }

        return substr($path, 0, $position);
    }

    protected function result(int $status, $data): array
    {
        return ['status' => $status, 'data' => $data];
    }

    protected function report(string $message): void
    {
        if (! $this->logger) {
            return;
        }

        try {
            $this->logger->log($message, Logger::WARNING);
        } catch (\Throwable $exception) {
            // Logging must never break the caller.
        }
    }
}
