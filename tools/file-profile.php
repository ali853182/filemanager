<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

/**
 * CLI file identity card export (filegator-audit-log G11, T22, FR12).
 *
 * Builds the file identity card through FileProfileService (metadata, summary,
 * audit timeline, comments) and optionally runs an ACL-filtered comment search
 * through CommentService. Output is JSON or a plain-text table.
 *
 * The tool runs as a synthetic admin user ("cli") so PathAccessPolicy keeps
 * its admin bypass; it never prints session ids, credentials or file contents.
 * When the configured SQLite database is absent it uses an in-memory database
 * so a report never creates a production database as a side effect. The tool
 * respects file_profile.enabled and comments.enabled from the loaded config;
 * point --config at a configuration with those flags enabled to export while
 * the web endpoint is disabled.
 *
 * Usage:
 *   php tools/file-profile.php --path=/data/a.txt [options]
 *
 * Options:
 *   --path=PATH             file path (required)
 *   --history-limit=N       audit history page size (default from config)
 *   --comments-limit=N      comment page size (default from config)
 *   --history-offset=N      audit history offset
 *   --comments-offset=N     comment offset
 *   --search=QUERY          ACL-filtered comment search to include
 *   --search-limit=N        comment search page size (default 50)
 *   --format=json|table     output format (default json)
 *   --config=PATH           alternate configuration file
 *   --db=PATH               override the SQLite database path
 *   --repository=PATH       override the storage root (local adapter)
 *   --help                  show this help
 */

use Filegator\Config\Config;
use Filegator\Container\Container;
use Filegator\Services\Access\PathAccessPolicy;
use Filegator\Services\Audit\AuditLoggerInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\FileProfile\Adapters\Sqlite\SchemaInstaller;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteAuditEventRepository;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteCommentRepository;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteConnection;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteFileIdentityRepository;
use Filegator\Services\FileProfile\AuditEventRepositoryInterface;
use Filegator\Services\FileProfile\CommentRepositoryInterface;
use Filegator\Services\FileProfile\CommentService;
use Filegator\Services\FileProfile\FileIdentityRepositoryInterface;
use Filegator\Services\FileProfile\FileProfileService;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Storage\Filesystem;

error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);

$root = dirname(__DIR__);

require $root.'/vendor/autoload.php';

if (! defined('APP_ENV')) {
    define('APP_ENV', 'production');
}
if (! defined('APP_PUBLIC_PATH')) {
    define('APP_PUBLIC_PATH', '');
}
if (! defined('APP_PUBLIC_DIR')) {
    define('APP_PUBLIC_DIR', $root.'/dist');
}
if (! defined('APP_VERSION')) {
    define('APP_VERSION', 'cli');
}

/**
 * @return array<string, string>
 */
function file_profile_options(array $argv): array
{
    $options = [];

    foreach (array_slice($argv, 1) as $argument) {
        if ($argument === '--help' || $argument === '-h') {
            $options['help'] = '1';
            continue;
        }

        if (strpos($argument, '--') === 0) {
            $parts = explode('=', substr($argument, 2), 2);
            $options[$parts[0]] = $parts[1] ?? '1';
        }
    }

    return $options;
}

function file_profile_fail(string $message, int $code = 1): void
{
    fwrite(STDERR, $message."\n");
    exit($code);
}

function file_profile_int(array $options, string $key, int $default): int
{
    if (! isset($options[$key]) || ! is_numeric($options[$key])) {
        return $default;
    }

    return (int) $options[$key];
}

$options = file_profile_options($argv);

if (isset($options['help'])) {
    echo "Usage: php tools/file-profile.php --path=/data/a.txt [--history-limit=] [--comments-limit=] [--history-offset=] [--comments-offset=] [--search=] [--search-limit=] [--format=json|table] [--config=] [--db=] [--repository=]\n";
    exit(0);
}

$path = $options['path'] ?? '';
if (! is_string($path) || trim($path) === '') {
    file_profile_fail('Missing required option: --path=PATH', 2);
}

$configFile = $options['config'] ?? ($root.'/configuration.php');
if (! is_file($configFile)) {
    file_profile_fail('Configuration file not found: '.$configFile, 2);
}

$configArray = require $configFile;
if (! is_array($configArray)) {
    file_profile_fail('Configuration file did not return an array: '.$configFile, 2);
}

if (isset($options['repository']) && is_string($options['repository']) && $options['repository'] !== '') {
    $repositoryPath = $options['repository'];
    $configArray['services'][Filesystem::class]['config']['adapter'] = function () use ($repositoryPath) {
        return new \League\Flysystem\Adapter\Local($repositoryPath);
    };
}

$dbPath = $options['db'] ?? ($configArray['audit']['database_path'] ?? null);
if (! is_string($dbPath) || $dbPath === '') {
    $dbPath = $configArray['services'][SqliteConnection::class]['config']['path'] ?? null;
}

if (! is_string($dbPath) || $dbPath === '') {
    file_profile_fail('No SQLite database path is configured.', 2);
}

if (! is_file($dbPath)) {
    $dbPath = ':memory:';
}

$configArray['audit']['database_path'] = $dbPath;
$configArray['services'][SqliteConnection::class]['config']['path'] = $dbPath;

$config = new Config($configArray);
$container = new Container();
$container->set(Config::class, $config);
$container->set(Container::class, $container);

$order = [
    LoggerInterface::class,
    Filesystem::class,
    PathAccessPolicy::class,
    SqliteConnection::class,
    SchemaInstaller::class,
    SqliteFileIdentityRepository::class,
    FileIdentityRepositoryInterface::class,
    AuditLoggerInterface::class,
    SqliteCommentRepository::class,
    CommentRepositoryInterface::class,
    SqliteAuditEventRepository::class,
    AuditEventRepositoryInterface::class,
    FileProfileService::class,
    CommentService::class,
];

foreach ($order as $key) {
    $definition = $configArray['services'][$key] ?? null;
    if (! is_array($definition)) {
        file_profile_fail('Service is not configured: '.$key, 2);
    }

    try {
        $service = $container->get($definition['handler']);
        $service->init($definition['config'] ?? []);
        $container->set($key, $service);
    } catch (\Throwable $exception) {
        file_profile_fail('Unable to resolve '.$key.': '.$exception->getMessage(), 2);
    }
}

$user = new User();
$user->setUsername('cli');
$user->setRole('admin');
$user->setHomedir('/');
$user->setGroups([]);
$user->setPermissions(['read', 'write', 'upload', 'download', 'batchdownload', 'zip', 'chmod']);

$profiles = $container->get(FileProfileService::class);
$comments = $container->get(CommentService::class);

$result = $profiles->getProfile(
    $user,
    $path,
    file_profile_int($options, 'history-limit', 0),
    file_profile_int($options, 'comments-limit', 0),
    file_profile_int($options, 'history-offset', 0),
    file_profile_int($options, 'comments-offset', 0)
);

$format = $options['format'] ?? 'json';

if ($result['status'] !== 200) {
    if ($format === 'json') {
        echo json_encode([
            'status' => $result['status'],
            'error' => $result['data'],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)."\n";
    } else {
        fwrite(STDERR, 'Profile unavailable (status '.$result['status'].'): '.(is_string($result['data']) ? $result['data'] : 'error')."\n");
    }

    exit(1);
}

$profile = $result['data'];

if (isset($options['search']) && is_string($options['search']) && trim($options['search']) !== '') {
    $searchLimit = file_profile_int($options, 'search-limit', 50);
    $profile['comment_search'] = $comments->searchComments($user, $options['search'], $searchLimit, 0);
}

if ($format === 'json') {
    echo json_encode($profile, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)."\n";
    exit(0);
}

$file = $profile['file'] ?? [];
$summary = $profile['summary'] ?? [];

echo "file:\n";
foreach (['file_id', 'path', 'type', 'size', 'modified_at', 'permissions', 'exists', 'deleted_at'] as $key) {
    $value = $file[$key] ?? null;
    if (is_bool($value)) {
        $value = $value ? 'true' : 'false';
    }
    echo '  '.$key.': '.($value === null ? '' : (string) $value)."\n";
}

echo "summary:\n";
foreach (['created_at', 'created_by', 'last_modified_at', 'last_modified_by', 'event_count', 'comment_count'] as $key) {
    $value = $summary[$key] ?? null;
    echo '  '.$key.': '.($value === null ? '' : (string) $value)."\n";
}

$history = $profile['history'] ?? [];
echo 'history ('.count($history)."):\n";
echo '  '.implode("\t", ['ts', 'user', 'action', 'result', 'path'])."\n";
foreach ($history as $event) {
    echo '  '.implode("\t", [
        (string) ($event['ts'] ?? ''),
        (string) ($event['user'] ?? ''),
        (string) ($event['action'] ?? ''),
        (string) ($event['result'] ?? ''),
        (string) ($event['path'] ?? ''),
    ])."\n";
}

$commentList = $profile['comments'] ?? [];
echo 'comments ('.count($commentList)."):\n";
echo '  '.implode("\t", ['comment_id', 'user', 'created_at', 'body'])."\n";
foreach ($commentList as $comment) {
    echo '  '.implode("\t", [
        (string) ($comment['comment_id'] ?? ''),
        (string) ($comment['user'] ?? ''),
        (string) ($comment['created_at'] ?? ''),
        (string) ($comment['body'] ?? ''),
    ])."\n";
}

if (isset($profile['comment_search'])) {
    $search = $profile['comment_search'];
    $hits = is_array($search['data']['results'] ?? null) ? $search['data']['results'] : [];
    echo 'comment_search ('.count($hits)."):\n";
    echo '  '.implode("\t", ['comment_id', 'path', 'user', 'created_at', 'snippet'])."\n";
    foreach ($hits as $hit) {
        echo '  '.implode("\t", [
            (string) ($hit['comment_id'] ?? ''),
            (string) ($hit['path'] ?? ''),
            (string) ($hit['user'] ?? ''),
            (string) ($hit['created_at'] ?? ''),
            (string) ($hit['snippet'] ?? ''),
        ])."\n";
    }
}

exit(0);
