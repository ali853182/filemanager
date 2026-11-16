<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Controllers;

use Filegator\Config\Config;
use Filegator\Controllers\Concerns\AuditContext;
use Filegator\Kernel\Request;
use Filegator\Kernel\Response;
use Filegator\Services\Access\PathAccessPolicy;
use Filegator\Services\Archiver\ArchiverInterface;
use Filegator\Services\Audit\AuditAction;
use Filegator\Services\Audit\AuditLoggerInterface;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\FileProfile\FileIdentityRepositoryInterface;
use Filegator\Services\Session\SessionStorageInterface as Session;
use Filegator\Services\Storage\DirectoryCollection;
use Filegator\Services\Storage\Filesystem;

class FileController
{
    use AuditContext;

    public const SESSION_CWD = 'current_path';

    protected $session;

    protected $auth;

    protected $config;

    protected $storage;

    protected $separator;

    protected $accessPolicy;

    protected $user;

    protected $auditLogger;

    protected $fileIdentity;

    public function __construct(Config $config, Session $session, AuthInterface $auth, Filesystem $storage, PathAccessPolicy $accessPolicy, AuditLoggerInterface $auditLogger = null, FileIdentityRepositoryInterface $fileIdentity = null)
    {
        $this->session = $session;
        $this->config = $config;
        $this->auth = $auth;

        $user = $this->auth->user() ?: $this->auth->getGuest();
        $this->user = $user;

        $this->storage = $storage;
        $this->storage->setPathPrefix($user->getHomeDir());

        $this->separator = $this->storage->getSeparator();
        $this->accessPolicy = $accessPolicy;

        $this->auditLogger = $auditLogger;
        $this->fileIdentity = $fileIdentity;
    }

    public function changeDirectory(Request $request, Response $response)
    {
        $path = $request->input('to', $this->separator);

        if (! $this->accessPolicy->canRead($this->user, (string) $path)) {
            return $this->deny($request, $response, 'read', (string) $path);
        }

        $this->session->set(self::SESSION_CWD, $path);

        $content = $this->storage->getDirectoryCollection($path);

        return $response->json($this->filterCollection($content, (string) $path));
    }

    public function getDirectory(Request $request, Response $response)
    {
        $path = $request->input('dir', $this->session->get(self::SESSION_CWD, $this->separator));

        if (! $this->accessPolicy->canRead($this->user, (string) $path)) {
            return $this->deny($request, $response, 'read', (string) $path);
        }

        $content = $this->storage->getDirectoryCollection($path);

        return $response->json($this->filterCollection($content, (string) $path));
    }

    public function createNew(Request $request, Response $response)
    {
        $type = $request->input('type', 'file');
        $name = $request->input('name');
        $path = $this->session->get(self::SESSION_CWD, $this->separator);

        if (! $this->accessPolicy->canWrite($this->user, (string) $path)) {
            return $this->deny($request, $response, AuditAction::FILE_CREATE, (string) $path);
        }

        $success = true;
        if ($type == 'dir') {
            if (!$this->storage->createDir($path, $request->input('name'))) {
                $success = false;
            }
        }
        if ($type == 'file') {
            if (!$this->storage->createFile($path, $request->input('name'))) {
                $success = false;
            }
        }

        $identityType = $type == 'dir' ? 'dir' : 'file';
        $createdPath = $this->joinPath((string) $path, (string) $name);

        // Determine the real outcome for audit/identity. The legacy response
        // expression below is kept unchanged; createFile() returns null, so the
        // response for a file create stays "Failed" as before.
        $created = $success;
        if ($this->auditEnabled() || $this->identityEnabled()) {
            try {
                $created = $identityType === 'dir'
                    ? $this->storage->isDir($createdPath)
                    : $this->storage->fileExists($createdPath);
            } catch (\Throwable $exception) {
                $created = $success;
            }
        }

        $fileId = null;
        if ($created) {
            $identity = $this->identityEnsure($createdPath, $identityType);
            $fileId = $identity['file_id'] ?? null;
        }

        $this->recordAudit(
            $request,
            AuditAction::FILE_CREATE,
            $createdPath,
            $created ? 'success' : 'failure',
            $fileId,
            null,
            ['type' => $identityType]
        );

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function copyItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);
        $destination = $request->input('destination', $this->separator);

        if (! $this->accessPolicy->canWrite($this->user, (string) $destination)) {
            return $this->deny($request, $response, AuditAction::FILE_COPY, (string) $destination);
        }

        $success = true;
        foreach ($items as $item) {
            if (! $this->accessPolicy->canRead($this->user, (string) $item->path)) {
                return $this->deny($request, $response, AuditAction::FILE_COPY, (string) $item->path);
            }

            $itemSuccess = true;
            if ($item->type == 'dir') {
                if (!$this->storage->copyDir($item->path, $destination)) {
                    $itemSuccess = false;
                }
            }
            if ($item->type == 'file') {
                if (!$this->storage->copyFile($item->path, $destination)) {
                    $itemSuccess = false;
                }
            }
            if (! $itemSuccess) {
                $success = false;
            }

            $itemType = isset($item->type) ? (string) $item->type : 'file';
            // copyFile() stores under the source basename, so the copied path is
            // destination + basename(source), not the client-supplied name.
            $sourceName = basename((string) $item->path);
            $copiedPath = $this->joinPath((string) $destination, $sourceName);

            $fileId = null;
            if ($itemSuccess) {
                $source = $this->identityFind((string) $item->path);
                if ($source === null) {
                    $source = $this->identityEnsure((string) $item->path, $itemType);
                }
                if ($source !== null) {
                    $copied = $this->identityCopy((string) $source['file_id'], $copiedPath);
                    $fileId = $copied['file_id'] ?? null;
                }
            }

            $this->recordAudit(
                $request,
                AuditAction::FILE_COPY,
                (string) $item->path,
                $itemSuccess ? 'success' : 'failure',
                $fileId,
                $copiedPath,
                ['type' => $itemType]
            );
        }

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function moveItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);
        $destination = $request->input('destination', $this->separator);

        if (! $this->accessPolicy->canWrite($this->user, (string) $destination)) {
            return $this->deny($request, $response, AuditAction::FILE_MOVE, (string) $destination);
        }

        $success = true;
        foreach ($items as $item) {
            if (! $this->accessPolicy->canRead($this->user, (string) $item->path)) {
                return $this->deny($request, $response, AuditAction::FILE_MOVE, (string) $item->path);
            }
            $full_destination = trim($destination, $this->separator)
                    . $this->separator
                    . ltrim($item->name, $this->separator);

            $itemSuccess = true;
            if (!$this->storage->move($item->path, $full_destination)) {
                $itemSuccess = false;
                $success = false;
            }

            $itemType = isset($item->type) ? (string) $item->type : 'file';

            $fileId = null;
            if ($itemSuccess) {
                $source = $this->identityFind((string) $item->path);
                if ($source !== null) {
                    $moved = $this->identityMove((string) $source['file_id'], $full_destination);
                    $fileId = $moved['file_id'] ?? (string) $source['file_id'];
                } else {
                    $created = $this->identityEnsure($full_destination, $itemType);
                    $fileId = $created['file_id'] ?? null;
                }
            }

            $this->recordAudit(
                $request,
                AuditAction::FILE_MOVE,
                (string) $item->path,
                $itemSuccess ? 'success' : 'failure',
                $fileId,
                $full_destination,
                ['type' => $itemType]
            );
        }

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function zipItems(Request $request, Response $response, ArchiverInterface $archiver)
    {
        $items = $request->input('items', []);
        $destination = $request->input('destination', $this->separator);
        $name = $request->input('name', $this->config->get('frontend_config.default_archive_name'));

        if (! $this->accessPolicy->canWrite($this->user, (string) $destination)) {
            return $this->deny($request, $response, AuditAction::FILE_ZIP, (string) $destination);
        }

        foreach ($items as $item) {
            if (! $this->accessPolicy->canRead($this->user, (string) $item->path)) {
                return $this->deny($request, $response, AuditAction::FILE_ZIP, (string) $item->path);
            }
        }

        $archiver->createArchive($this->storage);

        $success = true;
        foreach ($items as $item) {
            if ($item->type == 'dir') {
                if (!$archiver->addDirectoryFromStorage($item->path)) {
                    $success = false;
                }
            }
            if ($item->type == 'file') {
                if (!$archiver->addFileFromStorage($item->path)) {
                    $success = false;
                }
            }
        }

        if (!$archiver->storeArchive($destination, $name)) {
            $success = false;
        }

        // The archive is a new item; the source identities are left untouched.
        // storeArchive() returns null, so the legacy response stays "Failed";
        // derive the real outcome from the stored archive for audit/identity.
        $archivePath = $this->joinPath((string) $destination, (string) $name);
        $archived = $success;
        if ($this->auditEnabled() || $this->identityEnabled()) {
            try {
                $archived = $this->storage->fileExists($archivePath);
            } catch (\Throwable $exception) {
                $archived = $success;
            }
        }

        $fileId = null;
        if ($archived) {
            $identity = $this->identityEnsure($archivePath, 'file');
            $fileId = $identity['file_id'] ?? null;
        }

        $this->recordAudit(
            $request,
            AuditAction::FILE_ZIP,
            $archivePath,
            $archived ? 'success' : 'failure',
            $fileId,
            (string) $destination,
            ['type' => 'file', 'sources' => count($items)]
        );

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function unzipItem(Request $request, Response $response, ArchiverInterface $archiver)
    {
        $source = $request->input('item');
        $destination = $request->input('destination', $this->separator);

        if (! $this->accessPolicy->canWrite($this->user, (string) $destination)) {
            return $this->deny($request, $response, AuditAction::FILE_UNZIP, (string) $destination);
        }

        $sourcePath = (string) $source;
        $before = $this->identityEnabled() ? $this->collectPathTypes((string) $destination) : [];

        $operationOk = true;
        try {
            $success = $archiver->uncompress($source, $destination, $this->storage);
        } catch (\Throwable $exception) {
            $operationOk = false;
            $this->recordAudit(
                $request,
                AuditAction::FILE_UNZIP,
                $sourcePath,
                'failure',
                null,
                (string) $destination,
                ['type' => 'file']
            );

            throw $exception;
        }

        $archiveId = null;
        if ($this->identityEnabled()) {
            // The archive keeps its own identity; each extracted entry gets a
            // new identity (spec.md 9).
            $archive = $this->identityFind($sourcePath);
            if ($archive === null) {
                $archive = $this->identityEnsure($sourcePath, 'file');
            }
            $archiveId = $archive['file_id'] ?? null;

            $after = $this->collectPathTypes((string) $destination);
            foreach ($after as $entryPath => $entryType) {
                if (! array_key_exists($entryPath, $before)) {
                    $this->identityEnsure($entryPath, $entryType);
                }
            }
        }

        $this->recordAudit(
            $request,
            AuditAction::FILE_UNZIP,
            $sourcePath,
            $operationOk ? 'success' : 'failure',
            $archiveId,
            (string) $destination,
            ['type' => 'file']
        );

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function chmodItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);
        $permissions = $request->input('permissions', 0);
        /** @var null|'all'|'folders'|'files' */
        $recursive = $request->input('recursive', null);

        $success = true;
        foreach ($items as $item) {
            if (! $this->accessPolicy->canWrite($this->user, (string) $item->path)) {
                return $this->deny($request, $response, AuditAction::FILE_CHMOD, (string) $item->path);
            }

            $itemSuccess = true;
            if (!$this->storage->chmod($item->path, $permissions, $recursive)) {
                $itemSuccess = false;
                $success = false;
            }

            $itemType = isset($item->type) ? (string) $item->type : 'file';

            // chmod keeps the existing file_id (ensureFile keeps the active id).
            $fileId = null;
            if ($itemSuccess) {
                $identity = $this->identityEnsure((string) $item->path, $itemType);
                $fileId = $identity['file_id'] ?? null;
            }

            $this->recordAudit(
                $request,
                AuditAction::FILE_CHMOD,
                (string) $item->path,
                $itemSuccess ? 'success' : 'failure',
                $fileId,
                null,
                ['type' => $itemType, 'permissions' => (int) $permissions]
            );
        }

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function renameItem(Request $request, Response $response)
    {
        $destination = $request->input('destination', $this->separator);
        $from = $request->input('from');
        $to = $request->input('to');

        $source_path = rtrim((string) $destination, $this->separator)
            . $this->separator
            . ltrim((string) $from, $this->separator);

        if (! $this->accessPolicy->canWrite($this->user, $source_path)) {
            return $this->deny($request, $response, AuditAction::FILE_RENAME, $source_path);
        }

        $success = true;
        if (!$this->storage->rename($destination, $from, $to)) {
            $success = false;
        }

        $renamedPath = $this->joinPath((string) $destination, (string) $to);

        // Rename keeps the same file_id and only rewrites path/path_key.
        $fileId = null;
        if ($success) {
            $existing = $this->identityFind($source_path);
            if ($existing !== null) {
                $renamed = $this->identityRename((string) $existing['file_id'], $renamedPath);
                $fileId = $renamed['file_id'] ?? (string) $existing['file_id'];
            }
        }

        $this->recordAudit(
            $request,
            AuditAction::FILE_RENAME,
            $source_path,
            $success ? 'success' : 'failure',
            $fileId,
            $renamedPath,
            []
        );

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function deleteItems(Request $request, Response $response)
    {
        $items = $request->input('items', []);

        $success = true;
        foreach ($items as $item) {
            if (! $this->accessPolicy->canWrite($this->user, (string) $item->path)) {
                return $this->deny($request, $response, AuditAction::FILE_DELETE, (string) $item->path);
            }

            $itemSuccess = true;
            if ($item->type == 'dir') {
                if (!$this->storage->deleteDir($item->path)) {
                    $itemSuccess = false;
                }
            }
            if ($item->type == 'file') {
                if (!$this->storage->deleteFile($item->path)) {
                    $itemSuccess = false;
                }
            }
            if (! $itemSuccess) {
                $success = false;
            }

            $itemType = isset($item->type) ? (string) $item->type : 'file';

            // Delete soft-deletes the identity; comments and history are kept.
            $fileId = null;
            if ($itemSuccess) {
                $existing = $this->identityFind((string) $item->path);
                if ($existing !== null) {
                    $this->identitySoftDelete((string) $existing['file_id']);
                    $fileId = (string) $existing['file_id'];
                }
            }

            $this->recordAudit(
                $request,
                AuditAction::FILE_DELETE,
                (string) $item->path,
                $itemSuccess ? 'success' : 'failure',
                $fileId,
                null,
                ['type' => $itemType]
            );
        }

        return $response->json($success ? 'Done' : 'Failed');
    }

    public function saveContent(Request $request, Response $response)
    {
        $path = $request->input('dir', $this->session->get(self::SESSION_CWD, $this->separator));

        if (! $this->accessPolicy->canWrite($this->user, (string) $path)) {
            return $this->deny($request, $response, AuditAction::FILE_SAVE, (string) $path);
        }

        $name = $request->input('name');
        $content = $request->input('content');

        $stream = tmpfile();
        fwrite($stream, $content);
        rewind($stream);

        $this->storage->deleteFile($path . $this->separator . $name);
        $success = $this->storage->store($path, $name, $stream);

        if (is_resource($stream)) {
            fclose($stream);
        }

        $savedPath = $this->joinPath((string) $path, (string) $name);

        // Save keeps the existing file_id (ensureFile keeps the active id).
        // The file content is deliberately never sent to the audit logger.
        $fileId = null;
        if ($success) {
            $identity = $this->identityEnsure($savedPath, 'file');
            $fileId = $identity['file_id'] ?? null;
        }

        $this->recordAudit(
            $request,
            AuditAction::FILE_SAVE,
            $savedPath,
            $success ? 'success' : 'failure',
            $fileId,
            null,
            ['type' => 'file']
        );

        return $response->json($success ? 'Done' : 'Failed');
    }

    protected function forbidden(Response $response)
    {
        return $response->json('Forbidden', 403);
    }

    /**
     * Record an access-denied audit event (when enabled) and return the 403
     * response. The attempted action and path are recorded without secrets.
     */
    protected function deny(Request $request, Response $response, string $attemptedAction, string $path)
    {
        $this->recordAccessDenied($request, $attemptedAction, $path);

        return $this->forbidden($response);
    }

    /**
     * Join a directory and a child name into a normalized storage path.
     */
    protected function joinPath(string $directory, string $name): string
    {
        $directory = rtrim($directory, $this->separator);
        $name = ltrim($name, $this->separator);

        if ($directory === '') {
            return $this->separator.$name;
        }

        return $directory.$this->separator.$name;
    }

    /**
     * Map every item under a directory (recursively) to its type. Used to find
     * the entries newly created by an unzip so each gets its own identity.
     *
     * @return array<string, string> path => "file"|"dir"
     */
    protected function collectPathTypes(string $directory): array
    {
        $paths = [];

        try {
            $collection = $this->storage->getDirectoryCollection($directory, true);
        } catch (\Throwable $exception) {
            return $paths;
        }

        foreach ($collection->all() as $item) {
            $type = (string) ($item['type'] ?? '');
            if ($type === 'back') {
                continue;
            }

            $paths[(string) $item['path']] = $type === 'dir' ? 'dir' : 'file';
        }

        return $paths;
    }

    /**
     * Drop entries the current user cannot read. The synthetic "back" entry is
     * kept only when its parent path is readable.
     */
    protected function filterCollection(DirectoryCollection $collection, string $path): DirectoryCollection
    {
        $filtered = new DirectoryCollection($path);

        foreach ($collection->all() as $item) {
            if (! $this->accessPolicy->canRead($this->user, (string) $item['path'])) {
                continue;
            }
            $filtered->add($item);
        }

        return $filtered;
    }
}
