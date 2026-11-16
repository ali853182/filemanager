<?php

// Test storage for the audit ledger and SQLite query store. TEST_TMP_PATH is
// defined by Tests\TestCase before this file is required.
$auditBase = defined('TEST_TMP_PATH') ? TEST_TMP_PATH : sys_get_temp_dir() . '/filegator-test/';
$sqlitePath = $auditBase . 'audit/filegator.sqlite';

$audit = [
    'enabled' => false,
    'path' => $auditBase . 'audit/audit.log',
    'max_files' => 90,
    'max_path_length' => 4096,
    'max_meta_length' => 8192,
    'log_downloads' => false,
    'database_path' => $sqlitePath,
];

$comments = [
    'enabled' => false,
    'max_length' => 5000,
    'max_per_10_minutes' => 30,
    'search_limit' => 50,
];

$fileProfile = [
    'enabled' => false,
    'history_limit' => 50,
    'comments_limit' => 50,
];

return [
    'public_path' => '',
    'public_dir' => __DIR__ . '/../../dist',
    'overwrite_on_upload' => false,
    'timezone' => 'UTC', // https://www.php.net/manual/en/timezones.php
    'download_inline' => ['pdf'],

    // Path authorization stays disabled in tests so the historical behaviour
    // of the existing suite is preserved.
    'authorization' => [
        'enabled' => false,
        'default' => 'deny',
        'admin_groups' => [],
        'group_paths' => [],
    ],

    'audit' => $audit,
    'comments' => $comments,
    'file_profile' => $fileProfile,

    'frontend_config' => [
        'app_name' => 'FileGator',
        'language' => 'english',
        'logo' => 'https://via.placeholder.com/263x55.png',
        'upload_max_size' => 2 * 1024 * 1024,
        'upload_chunk_size' => 1 * 1024 * 1024,
        'upload_simultaneous' => 3,
        'default_archive_name' => 'archive.zip',
        'editable' => ['.txt', '.css', '.js', '.ts', '.html', '.php', '.json', '.md'],
        'date_format' => 'YY/MM/DD hh:mm:ss',
        'guest_redirection' => '', // useful for external auth adapters
    ],

    'services' => [
        'Filegator\Services\Logger\LoggerInterface' => [
            'handler' => '\Filegator\Services\Logger\Adapters\MonoLogger',
            'config' => [
                'monolog_handlers' => [
                    function () {
                        return new \Monolog\Handler\NullHandler();
                    },
                ],
            ],
        ],
        'Filegator\Services\Session\SessionStorageInterface' => [
            'handler' => '\Filegator\Services\Session\Adapters\SessionStorage',
            'config' => [
                'handler' => function () {
                    return new \Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage();
                },
            ],
        ],
        'Filegator\Services\Tmpfs\TmpfsInterface' => [
            'handler' => '\Filegator\Services\Tmpfs\Adapters\Tmpfs',
            'config' => [
                'path' => TEST_TMP_PATH,
                'gc_probability_perc' => 10,
                'gc_older_than' => 60 * 60 * 24 * 2, // 2 days
            ],
        ],
        'Filegator\Services\View\ViewInterface' => [
            'handler' => '\Filegator\Services\View\Adapters\Vuejs',
            'config' => [
                'add_to_head' => '',
                'add_to_body' => '',
            ],
        ],
        'Filegator\Services\Storage\Filesystem' => [
            'handler' => '\Filegator\Services\Storage\Filesystem',
            'config' => [
                'separator' => '/',
                'adapter' => function () {
                    return new \League\Flysystem\Adapter\Local(
                        TEST_REPOSITORY
                    );
                },
            ],
        ],
        'Filegator\Services\Auth\AuthInterface' => [
            'handler' => '\Tests\MockUsers',
        ],
        'Filegator\Services\Archiver\ArchiverInterface' => [
            'handler' => '\Filegator\Services\Archiver\Adapters\ZipArchiver',
            'config' => [],
        ],
        'Filegator\Services\Access\PathAccessPolicy' => [
            'handler' => '\Filegator\Services\Access\PathAccessPolicy',
            'config' => [
                'enabled' => false,
                'default' => 'deny',
                'admin_groups' => [],
                'group_paths' => [],
            ],
        ],
        // Audit and file profile query store, disabled by default in tests.
        'Filegator\Services\FileProfile\Adapters\Sqlite\SqliteConnection' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteConnection',
            'config' => [
                'path' => $sqlitePath,
            ],
        ],

        'Filegator\Services\FileProfile\Adapters\Sqlite\SchemaInstaller' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SchemaInstaller',
            'config' => [],
        ],

        'Filegator\Services\FileProfile\Adapters\Sqlite\SqliteFileIdentityRepository' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteFileIdentityRepository',
            'config' => [],
        ],

        // Controllers type-hint the identity repository interface; bind it to
        // the concrete SQLite implementation registered above (same instance).
        'Filegator\Services\FileProfile\FileIdentityRepositoryInterface' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteFileIdentityRepository',
            'config' => [],
        ],

        'Filegator\Services\Audit\AuditLoggerInterface' => [
            'handler' => '\Filegator\Services\Audit\Adapters\MonoAuditLogger',
            'config' => $audit,
        ],

        // Comment store and application service (filegator-audit-log G7-G9).
        'Filegator\Services\FileProfile\Adapters\Sqlite\SqliteCommentRepository' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteCommentRepository',
            'config' => [],
        ],

        'Filegator\Services\FileProfile\CommentRepositoryInterface' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteCommentRepository',
            'config' => [],
        ],

        'Filegator\Services\FileProfile\CommentService' => [
            'handler' => '\Filegator\Services\FileProfile\CommentService',
            'config' => [],
        ],

        // Read-only audit_events query model and the file identity card
        // service (filegator-audit-log G10).
        'Filegator\Services\FileProfile\Adapters\Sqlite\SqliteAuditEventRepository' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteAuditEventRepository',
            'config' => [],
        ],

        'Filegator\Services\FileProfile\AuditEventRepositoryInterface' => [
            'handler' => '\Filegator\Services\FileProfile\Adapters\Sqlite\SqliteAuditEventRepository',
            'config' => [],
        ],

        'Filegator\Services\FileProfile\FileProfileService' => [
            'handler' => '\Filegator\Services\FileProfile\FileProfileService',
            'config' => [],
        ],

        // The router MUST be registered last (see configuration.php): its
        // init() dispatches the request and resolves the controller, so all
        // controller dependencies must already be bound in the container.
        'Filegator\Services\Router\Router' => [
            'handler' => '\Filegator\Services\Router\Router',
            'config' => [
                'query_param' => 'r',
                'routes_file' => __DIR__ . '/../../backend/Controllers/routes.php',
            ],
        ],
    ],
];
