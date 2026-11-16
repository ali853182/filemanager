<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\Audit;

/**
 * Contract for the append-only file audit ledger.
 *
 * Every call to record() represents exactly one audit event. Implementations
 * append one JSON object per line to
 * private/logs/audit.log (the source of truth) and mirror the event into the
 * SQLite audit_events query index. A failing index must never throw back into
 * the caller and must never abort a file operation.
 *
 * Event schema
 * ------------
 *
 * {
 *   "event_id":    "6f1c2f7e-7d1a-4f2b-9c3e-2a1b0c9d8e7f",
 *   "ts":          "2026-11-15T08:30:00.123Z",
 *   "user":        "a.rahimi",
 *   "role":        "admin",
 *   "ip":          "192.168.1.35",
 *   "action":      "file.rename",
 *   "file_id":     "0b7d5a2e-3c4f-4a1b-8e9d-1f2a3b4c5d6e",
 *   "path":        "/اطلاعات خرید/a.txt",
 *   "destination": "/اطلاعات خرید/b.txt",
 *   "result":      "success",
 *   "meta":        {"type": "file"}
 * }
 *
 * Required keys (the adapter must reject or coerce a missing value):
 *   - event_id  UUID v4, unique per event.
 *   - ts        ISO-8601 UTC timestamp with milliseconds, suffix "Z".
 *   - user      Authenticated username; "guest" for unauthenticated attempts.
 *   - role      FileGator role: guest, user or admin.
 *   - ip        Client IP address; "cli" for command line tools.
 *   - action    One of the constants declared in AuditAction.
 *   - path      Normalized path of the affected item (see path rules below).
 *   - result    One of the result values below.
 *
 * Optional keys (omit when not applicable; never send an empty placeholder):
 *   - file_id      Stable file identity the event belongs to, if known.
 *   - destination  Normalized destination path for copy/move/rename.
 *   - meta         JSON object with small scalars only. Comment events store
 *                  comment_id, file_id and path, never the comment body.
 *
 * Result values:
 *   - success  The operation completed.
 *   - failure  Storage or validation failed.
 *   - denied   Authorization/ACL rejected the operation.
 *
 * Forbidden content (must never appear in any key or meta value):
 *   - Passwords, LDAP bind credentials, tokens, CSRF values, session ids.
 *   - File contents, uploaded bytes, comment bodies and archive payloads.
 *   - Any request body, cookie, header or credential material.
 *
 * Path rules (shared with FileIdentityRepositoryInterface):
 *   trim, convert "\" to "/", collapse duplicate "/", ensure a leading "/",
 *   reject any ".." segment, and derive the lowercase path_key for lookups.
 */
interface AuditLoggerInterface
{
    /**
     * Record a single audit event.
     *
     * The array must follow the schema documented above. Implementations must
     * redact forbidden keys and control characters, cap path length, and stay
     * non-blocking: a ledger or index failure is logged through the
     * application logger and swallowed, never rethrown to the caller.
     */
    public function record(array $event): void;
}
