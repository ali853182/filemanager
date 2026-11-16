<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Controllers\Concerns;

use Filegator\Kernel\Request;
use Filegator\Kernel\Response;
use Filegator\Services\Audit\AuditAction;

/**
 * Shared, defensive instrumentation helpers for the file audit / file identity
 * feature (spec.md 8, 9; FR10, FR11).
 *
 * Every helper is a strict no-op unless the feature is enabled:
 *   - audit events require audit.enabled
 *   - file identity writes require audit.enabled OR file_profile.enabled
 *
 * When the flags are off no ledger is written, no SQLite database is opened and
 * no identity row is created, so file operations behave exactly as before
 * (Story 8, spec.md 15). Every call is wrapped so a failing audit or identity
 * write can never change the HTTP response or abort the operation (FR10).
 *
 * The consuming controller must expose $config (Config), $user (User),
 * $auditLogger (AuditLoggerInterface|null) and $fileIdentity
 * (FileIdentityRepositoryInterface|null).
 */
trait AuditContext
{
    /**
     * Whether audit events may be written.
     */
    protected function auditEnabled(): bool
    {
        return (bool) $this->config->get('audit.enabled', false);
    }

    /**
     * Whether file identities may be read or written. Identities back both the
     * audit file_id and the file identity card, so either flag enables them.
     */
    protected function identityEnabled(): bool
    {
        return $this->auditEnabled() || (bool) $this->config->get('file_profile.enabled', false);
    }

    /**
     * Whether successful downloads should be audited (audit.log_downloads).
     */
    protected function downloadAuditEnabled(): bool
    {
        return $this->auditEnabled() && (bool) $this->config->get('audit.log_downloads', false);
    }

    /**
     * Record one audit event, filling the actor context from the current user
     * and request. Never throws.
     */
    protected function recordAudit(
        Request $request,
        string $action,
        string $path,
        string $result,
        ?string $fileId = null,
        ?string $destination = null,
        array $meta = []
    ): void {
        if (! $this->auditEnabled() || ! $this->auditLogger) {
            return;
        }

        $event = [
            'user' => $this->user ? $this->user->getUsername() : 'guest',
            'role' => $this->user ? $this->user->getRole() : 'guest',
            'ip' => $this->clientIp($request),
            'action' => $action,
            'path' => $path,
            'result' => $result,
        ];

        if ($fileId !== null && $fileId !== '') {
            $event['file_id'] = $fileId;
        }

        if ($destination !== null && $destination !== '') {
            $event['destination'] = $destination;
        }

        if ($meta !== []) {
            $event['meta'] = $meta;
        }

        try {
            $this->auditLogger->record($event);
        } catch (\Throwable $exception) {
            // Audit must never break the file operation.
        }
    }

    /**
     * Record an access-denied event for a rejected operation. The attempted
     * action is carried in meta; the event action is access.denied so the
     * catalog stays closed. Never throws.
     */
    protected function recordAccessDenied(Request $request, string $attemptedAction, string $path): void
    {
        $this->recordAudit(
            $request,
            AuditAction::ACCESS_DENIED,
            $path,
            'denied',
            null,
            null,
            ['attempted_action' => $attemptedAction]
        );
    }

    /**
     * Record an access-denied event (when enabled) and return the standard 403
     * JSON response.
     */
    protected function denyResponse(Request $request, Response $response, string $attemptedAction, string $path)
    {
        $this->recordAccessDenied($request, $attemptedAction, $path);

        return $response->json('Forbidden', 403);
    }

    /**
     * Return the active identity for a path, creating one when the path has no
     * active identity. Returns null when identity storage is disabled or fails.
     */
    protected function identityEnsure(string $path, string $type): ?array
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return null;
        }

        try {
            return $this->fileIdentity->ensureFile($path, $type);
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Return the active identity for a path, or null when unknown/disabled.
     */
    protected function identityFind(string $path): ?array
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return null;
        }

        try {
            return $this->fileIdentity->findByPath($path);
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Rename an identity, keeping its file_id. Returns null on failure.
     */
    protected function identityRename(string $fileId, string $newPath): ?array
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return null;
        }

        try {
            return $this->fileIdentity->rename($fileId, $newPath);
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Move an identity, keeping its file_id. Returns null on failure.
     */
    protected function identityMove(string $fileId, string $newPath): ?array
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return null;
        }

        try {
            return $this->fileIdentity->move($fileId, $newPath);
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Create a linked copy identity (new file_id, copied_from_file_id set).
     * Returns null on failure.
     */
    protected function identityCopy(string $sourceFileId, string $newPath): ?array
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return null;
        }

        try {
            return $this->fileIdentity->copy($sourceFileId, $newPath);
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Soft-delete an identity. Never throws.
     */
    protected function identitySoftDelete(string $fileId): void
    {
        if (! $this->identityEnabled() || ! $this->fileIdentity) {
            return;
        }

        try {
            $this->fileIdentity->softDelete($fileId);
        } catch (\Throwable $exception) {
            // Identity storage must never break the delete.
        }
    }

    /**
     * Resolve the client IP without ever throwing.
     */
    protected function clientIp(Request $request): string
    {
        try {
            $ip = $request->getClientIp();
        } catch (\Throwable $exception) {
            return 'unknown';
        }

        return is_string($ip) && $ip !== '' ? $ip : 'unknown';
    }
}
