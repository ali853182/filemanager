<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\Audit\Adapters;

use Filegator\Services\Audit\AuditLoggerInterface;
use Filegator\Services\Service;

/**
 * Disabled audit path.
 *
 * This adapter satisfies AuditLoggerInterface while writing nothing. It exists
 * so the audit service can be wired explicitly to a no-op implementation when
 * audit.enabled is false, guaranteeing that no ledger or index write happens
 * and that file operations behave exactly as before (spec.md 15; Story 8).
 */
class NullAuditLogger implements Service, AuditLoggerInterface
{
    public function init(array $config = [])
    {
    }

    public function record(array $event): void
    {
    }
}
