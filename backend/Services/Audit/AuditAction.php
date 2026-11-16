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
 * Canonical audit action catalog.
 *
 * These values are the only accepted values for the "action" key of an audit
 * event. Keep them in sync with spec.md 8.1; instrumentation must use these
 * constants instead of literal strings.
 */
class AuditAction
{
    public const FILE_CREATE = 'file.create';

    public const FILE_COPY = 'file.copy';

    public const FILE_MOVE = 'file.move';

    public const FILE_ZIP = 'file.zip';

    public const FILE_UNZIP = 'file.unzip';

    public const FILE_CHMOD = 'file.chmod';

    public const FILE_RENAME = 'file.rename';

    public const FILE_DELETE = 'file.delete';

    public const FILE_SAVE = 'file.save';

    public const FILE_UPLOAD = 'file.upload';

    public const FILE_DOWNLOAD = 'file.download';

    public const FILE_BATCH_DOWNLOAD = 'file.batch_download';

    public const ACCESS_DENIED = 'access.denied';

    public const COMMENT_CREATE = 'comment.create';

    public const COMMENT_DELETE = 'comment.delete';

    /**
     * All catalogued actions in specification order.
     *
     * @return string[]
     */
    public static function all(): array
    {
        return [
            self::FILE_CREATE,
            self::FILE_COPY,
            self::FILE_MOVE,
            self::FILE_ZIP,
            self::FILE_UNZIP,
            self::FILE_CHMOD,
            self::FILE_RENAME,
            self::FILE_DELETE,
            self::FILE_SAVE,
            self::FILE_UPLOAD,
            self::FILE_DOWNLOAD,
            self::FILE_BATCH_DOWNLOAD,
            self::ACCESS_DENIED,
            self::COMMENT_CREATE,
            self::COMMENT_DELETE,
        ];
    }

    /**
     * Whether the value belongs to the catalog.
     */
    public static function isValid(string $action): bool
    {
        return in_array($action, self::all(), true);
    }
}
