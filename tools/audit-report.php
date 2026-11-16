<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

/**
 * CLI audit report (filegator-audit-log G11, T21, FR12).
 *
 * Reads the SQLite audit_events query index through
 * AuditEventRepositoryInterface and prints a filtered, paginated report as a
 * table or JSON. It never writes to the database, never prints file contents
 * or secrets, and opens the configured database read-only by using an
 * in-memory database when the configured file does not exist.
 *
 * Usage:
 *   php tools/audit-report.php [options]
 *
 * Options:
 *   --from=YYYY-MM-DD|ISO   lower timestamp bound (inclusive)
 *   --to=YYYY-MM-DD|ISO     upper timestamp bound (inclusive)
 *   --user=USERNAME         exact username
 *   --action=ACTION         exact action (e.g. file.rename)
 *   --path=PATH             exact path (case-insensitive)
 *   --file-id=UUID          exact file identity
 *   --result=RESULT         success|failure|denied
 *   --limit=N               page size (default 100, max 1000)
 *   --offset=N              rows to skip (default 0)
 *   --format=table|json     output format (default table)
 *   --config=PATH           alternate configuration file
 *   --db=PATH               override the SQLite database path
 *   --help                  show this help
 */

use Filegator\Config\Config;
use Filegator\Container\Container;
use Filegator\Services\FileProfile\Adapters\Sqlite\SqliteConnection;
use Filegator\Services\FileProfile\AuditEventRepositoryInterface;

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
function audit_report_options(array $argv): array
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

function audit_report_fail(string $message, int $code = 1): void
{
    fwrite(STDERR, $message."\n");
    exit($code);
}

function audit_report_from(?string $value): ?string
{
    if ($value === null || trim($value) === '') {
        return null;
    }

    $value = trim($value);
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) === 1) {
        return $value.'T00:00:00.000Z';
    }

    return $value;
}

function audit_report_to(?string $value): ?string
{
    if ($value === null || trim($value) === '') {
        return null;
    }

    $value = trim($value);
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) === 1) {
        return $value.'T23:59:59.999Z';
    }

    return $value;
}

$options = audit_report_options($argv);

if (isset($options['help'])) {
    echo "Usage: php tools/audit-report.php [--from=] [--to=] [--user=] [--action=] [--path=] [--file-id=] [--result=] [--limit=] [--offset=] [--format=table|json] [--config=] [--db=]\n";
    exit(0);
}

$configFile = $options['config'] ?? ($root.'/configuration.php');
if (! is_file($configFile)) {
    audit_report_fail('Configuration file not found: '.$configFile, 2);
}

$configArray = require $configFile;
if (! is_array($configArray)) {
    audit_report_fail('Configuration file did not return an array: '.$configFile, 2);
}

$dbPath = $options['db'] ?? ($configArray['audit']['database_path'] ?? null);
if (! is_string($dbPath) || $dbPath === '') {
    $dbPath = $configArray['services'][SqliteConnection::class]['config']['path'] ?? null;
}

if (! is_string($dbPath) || $dbPath === '') {
    audit_report_fail('No SQLite database path is configured.', 2);
}

// A report must never create a production database as a side effect. When the
// configured file is absent, use an in-memory database (empty result).
if (! is_file($dbPath)) {
    $dbPath = ':memory:';
}

$configArray['audit']['database_path'] = $dbPath;
$configArray['services'][SqliteConnection::class]['config']['path'] = $dbPath;

$config = new Config($configArray);
$container = new Container();
$container->set(Config::class, $config);
$container->set(Container::class, $container);

$connectionDefinition = $configArray['services'][SqliteConnection::class] ?? null;
if (! is_array($connectionDefinition)) {
    audit_report_fail('SqliteConnection is not configured.', 2);
}

$connection = $container->get($connectionDefinition['handler']);
$connection->init($connectionDefinition['config'] ?? []);
$container->set(SqliteConnection::class, $connection);

$repositoryDefinition = $configArray['services'][AuditEventRepositoryInterface::class] ?? null;
if (! is_array($repositoryDefinition)) {
    audit_report_fail('AuditEventRepositoryInterface is not configured.', 2);
}

$repository = $container->get($repositoryDefinition['handler']);
$repository->init($repositoryDefinition['config'] ?? []);
$container->set(AuditEventRepositoryInterface::class, $repository);

$filters = [
    'from' => audit_report_from($options['from'] ?? null),
    'to' => audit_report_to($options['to'] ?? null),
    'user' => $options['user'] ?? null,
    'action' => $options['action'] ?? null,
    'path' => $options['path'] ?? null,
    'file_id' => $options['file-id'] ?? ($options['file_id'] ?? null),
    'result' => $options['result'] ?? null,
];

$limit = isset($options['limit']) && is_numeric($options['limit']) ? (int) $options['limit'] : 100;
$offset = isset($options['offset']) && is_numeric($options['offset']) ? (int) $options['offset'] : 0;

try {
    $events = $repository->search($filters, $limit, $offset);
    $total = $repository->countSearch($filters);
} catch (\Throwable $exception) {
    audit_report_fail('Audit report failed: '.$exception->getMessage(), 3);
}

$format = $options['format'] ?? 'table';

if ($format === 'json') {
    echo json_encode([
        'total' => $total,
        'limit' => $limit,
        'offset' => $offset,
        'events' => $events,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)."\n";
    exit(0);
}

echo 'total: '.$total."\n";
echo implode("\t", ['ts', 'user', 'action', 'result', 'path', 'file_id', 'destination'])."\n";

foreach ($events as $event) {
    echo implode("\t", [
        (string) ($event['ts'] ?? ''),
        (string) ($event['user'] ?? ''),
        (string) ($event['action'] ?? ''),
        (string) ($event['result'] ?? ''),
        (string) ($event['path'] ?? ''),
        (string) ($event['file_id'] ?? ''),
        (string) ($event['destination'] ?? ''),
    ])."\n";
}

exit(0);
