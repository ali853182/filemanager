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
use Filegator\Services\Audit\AuditAction;
use Filegator\Services\Audit\AuditLoggerInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Service;
use Monolog\Logger;

/**
 * Application service for file comments (spec.md 10, 11.1, 12, 14).
 *
 * Responsibilities:
 *   - validation: trim, 1..comments.max_length characters, plain text only;
 *   - ACL: every add/list/delete/search result passes PathAccessPolicy::canRead;
 *   - moderation: the author or an admin may soft-delete; other users get 403;
 *   - audit: comment.create / comment.delete carry only comment_id, file_id and
 *     path in meta, never the comment body;
 *   - non-blocking audit: an audit failure never changes the response.
 *
 * Every method returns a structured result:
 *   ['status' => int, 'data' => mixed]
 * so the controller maps it directly to the HTTP response. When
 * comments.enabled is false every method is a no-op that returns 404 and
 * touches no storage and writes no audit event (spec.md 15).
 */
class CommentService implements Service
{
    public const STATUS_OK = 200;

    public const STATUS_FORBIDDEN = 403;

    public const STATUS_NOT_FOUND = 404;

    public const STATUS_UNPROCESSABLE = 422;

    public const STATUS_ERROR = 500;

    protected const DEFAULT_MAX_LENGTH = 5000;

    protected const DEFAULT_LIMIT = 50;

    protected $config;

    protected $comments;

    protected $identities;

    protected $accessPolicy;

    protected $auditLogger;

    protected $logger;

    public function __construct(
        Config $config,
        CommentRepositoryInterface $comments,
        FileIdentityRepositoryInterface $identities,
        PathAccessPolicy $accessPolicy,
        AuditLoggerInterface $auditLogger = null,
        LoggerInterface $logger = null
    ) {
        $this->config = $config;
        $this->comments = $comments;
        $this->identities = $identities;
        $this->accessPolicy = $accessPolicy;
        $this->auditLogger = $auditLogger;
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
        return (bool) $this->config->get('comments.enabled', false);
    }

    /**
     * List the active comments for a file the user can read.
     */
    public function listComments(User $user, string $path, int $limit = self::DEFAULT_LIMIT, int $offset = 0): array
    {
        if (! $this->isEnabled()) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        if ($user->isGuest()) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        if (! $this->accessPolicy->canRead($user, $path)) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $limit = $this->clampLimit($limit);
        $offset = $offset < 0 ? 0 : $offset;

        try {
            $identity = $this->identities->findByPath($path);
            if ($identity === null) {
                return $this->result(self::STATUS_OK, [
                    'file_id' => null,
                    'total' => 0,
                    'comments' => [],
                ]);
            }

            $fileId = (string) $identity['file_id'];

            return $this->result(self::STATUS_OK, [
                'file_id' => $fileId,
                'total' => $this->comments->countComments($fileId),
                'comments' => $this->comments->listComments($fileId, $limit, $offset),
            ]);
        } catch (\Throwable $exception) {
            $this->report('Comment list failed: '.$exception->getMessage());

            return $this->result(self::STATUS_ERROR, 'Internal Server Error');
        }
    }

    /**
     * Add a comment to a file the user can read.
     */
    public function addComment(User $user, string $path, string $body, string $ip = 'cli', string $type = 'file'): array
    {
        if (! $this->isEnabled()) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        if ($user->isGuest()) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $body = $this->normalizeBody($body);
        $validationError = $this->validateBody($body);
        if ($validationError !== null) {
            return $this->result(self::STATUS_UNPROCESSABLE, $validationError);
        }

        if (! $this->accessPolicy->canRead($user, $path)) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $type = $type === 'dir' ? 'dir' : 'file';

        try {
            $identity = $this->identities->findByPath($path);
            if ($identity === null) {
                $identity = $this->identities->ensureFile($path, $type);
            }

            $fileId = (string) $identity['file_id'];
            $commentId = $this->comments->addComment($fileId, $user->getUsername(), $user->getRole(), $body);
        } catch (\Throwable $exception) {
            $this->report('Comment create failed: '.$exception->getMessage());

            return $this->result(self::STATUS_ERROR, 'Internal Server Error');
        }

        $this->recordAudit($user, $ip, AuditAction::COMMENT_CREATE, $path, $fileId, $commentId);

        $comment = null;
        try {
            $stored = $this->comments->findCommentById($commentId);
            if ($stored !== null) {
                $comment = Comment::fromArray($stored)->toArray();
            }
        } catch (\Throwable $exception) {
            $comment = null;
        }

        return $this->result(self::STATUS_OK, [
            'comment_id' => $commentId,
            'file_id' => $fileId,
            'comment' => $comment,
        ]);
    }

    /**
     * Soft-delete a comment. The author or an admin may delete; other users
     * receive 403 and the comment stays visible.
     */
    public function deleteComment(User $user, int $commentId, string $ip = 'cli'): array
    {
        if (! $this->isEnabled()) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        if ($user->isGuest()) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        try {
            $comment = $this->comments->findCommentById($commentId);
        } catch (\Throwable $exception) {
            $this->report('Comment lookup failed: '.$exception->getMessage());

            return $this->result(self::STATUS_ERROR, 'Internal Server Error');
        }

        if ($comment === null || $comment['deleted_at'] !== null) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        $fileId = (string) $comment['file_id'];

        try {
            $identity = $this->identities->findById($fileId);
        } catch (\Throwable $exception) {
            $identity = null;
        }

        $path = $identity !== null ? (string) $identity['path'] : null;

        // Never act on a comment whose current path cannot be resolved and
        // read by the caller (no leaking of unreadable content).
        if ($path === null || ! $this->accessPolicy->canRead($user, $path)) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $isAdmin = $user->isAdmin();
        if ($comment['user'] !== $user->getUsername() && ! $isAdmin) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        try {
            $deleted = $this->comments->softDeleteComment($commentId, $user->getUsername(), $isAdmin);
        } catch (\Throwable $exception) {
            $this->report('Comment delete failed: '.$exception->getMessage());

            return $this->result(self::STATUS_ERROR, 'Internal Server Error');
        }

        if (! $deleted) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        $this->recordAudit($user, $ip, AuditAction::COMMENT_DELETE, $path, $fileId, $commentId);

        return $this->result(self::STATUS_OK, [
            'comment_id' => $commentId,
            'file_id' => $fileId,
            'deleted' => true,
        ]);
    }

    /**
     * Search comments and drop every result whose current path the user
     * cannot read (spec.md 10, 12; Story 5).
     */
    public function searchComments(User $user, string $query, int $limit = self::DEFAULT_LIMIT, int $offset = 0): array
    {
        if (! $this->isEnabled()) {
            return $this->result(self::STATUS_NOT_FOUND, 'Not Found');
        }

        if ($user->isGuest()) {
            return $this->result(self::STATUS_FORBIDDEN, 'Forbidden');
        }

        $query = trim($query);
        if ($query === '') {
            return $this->result(self::STATUS_OK, [
                'query' => '',
                'count' => 0,
                'results' => [],
            ]);
        }

        $limit = $this->clampLimit($limit);
        $offset = $offset < 0 ? 0 : $offset;

        try {
            $hits = $this->comments->searchComments($query, $limit, $offset);
        } catch (\Throwable $exception) {
            $this->report('Comment search failed: '.$exception->getMessage());

            return $this->result(self::STATUS_ERROR, 'Internal Server Error');
        }

        $results = [];
        foreach ($hits as $hit) {
            $path = (string) ($hit['path'] ?? '');
            if ($path === '' || ! $this->accessPolicy->canRead($user, $path)) {
                continue;
            }
            $results[] = $hit;
        }

        return $this->result(self::STATUS_OK, [
            'query' => $query,
            'count' => count($results),
            'results' => $results,
        ]);
    }

    /**
     * Trim and strip control characters (except tab/newline/carriage return)
     * so the stored value is plain text. HTML is never rendered or stripped
     * here; it is stored verbatim as text and escaped by the frontend.
     */
    protected function normalizeBody(string $body): string
    {
        $body = trim($body);

        $stripped = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $body);
        if ($stripped === null) {
            $stripped = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $body);
        }

        return $stripped === null ? $body : $stripped;
    }

    /**
     * Return an error message when the body is invalid, or null when valid.
     */
    protected function validateBody(string $body): ?string
    {
        if ($body === '') {
            return 'Comment must not be empty';
        }

        $max = (int) $this->config->get('comments.max_length', self::DEFAULT_MAX_LENGTH);
        if ($max < 1) {
            $max = self::DEFAULT_MAX_LENGTH;
        }

        $length = function_exists('mb_strlen') ? mb_strlen($body, 'UTF-8') : strlen($body);
        if ($length > $max) {
            return 'Comment must not exceed '.$max.' characters';
        }

        return null;
    }

    /**
     * Record a comment audit event. Only comment_id, file_id and path are
     * stored in meta; the comment body is never passed. The write is gated by
     * audit.enabled and isolated so it can never change the response (FR10).
     */
    protected function recordAudit(User $user, string $ip, string $action, string $path, string $fileId, int $commentId): void
    {
        if (! $this->auditLogger || ! $this->config->get('audit.enabled', false)) {
            return;
        }

        $meta = ['comment_id' => $commentId];
        if ($fileId !== '') {
            $meta['file_id'] = $fileId;
        }
        $meta['path'] = $path;

        try {
            $this->auditLogger->record([
                'user' => $user->getUsername(),
                'role' => $user->getRole(),
                'ip' => $ip !== '' ? $ip : 'unknown',
                'action' => $action,
                'path' => $path,
                'result' => 'success',
                'meta' => $meta,
            ]);
        } catch (\Throwable $exception) {
            // Audit must never break the comment operation.
        }
    }

    protected function clampLimit(int $limit): int
    {
        $configured = (int) $this->config->get('comments.search_limit', self::DEFAULT_LIMIT);
        if ($configured < 1) {
            $configured = self::DEFAULT_LIMIT;
        }

        if ($limit < 1) {
            return $configured;
        }

        return $limit > 200 ? 200 : $limit;
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
