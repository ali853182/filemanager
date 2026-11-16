<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\Access;

use Filegator\Services\Auth\User;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Service;
use Monolog\Logger;

/**
 * Folder-level authorization driven by the FileGator configuration instead of
 * the underlying filesystem/NTFS permissions.
 *
 * The policy maps AD/LDAP groups to storage paths with the rights "read" and
 * "write". It only makes decisions when authorization.enabled is true; when it
 * is false every path is allowed so the historical behaviour is preserved.
 */
class PathAccessPolicy implements Service
{
    public const RIGHT_READ = 'read';
    public const RIGHT_WRITE = 'write';

    protected $logger;

    protected $config = [];

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    public function init(array $config = [])
    {
        $this->config = $config;
    }

    public function isEnabled(): bool
    {
        return !empty($this->config['enabled']);
    }

    public function canRead(User $user, string $path): bool
    {
        return in_array(self::RIGHT_READ, $this->allowedRights($user, $path), true);
    }

    public function canWrite(User $user, string $path): bool
    {
        return in_array(self::RIGHT_WRITE, $this->allowedRights($user, $path), true);
    }

    /**
     * Rights granted to the user for a single path. An empty array means deny.
     */
    public function allowedRights(User $user, string $path): array
    {
        // Backward compatibility: no path checks while the feature is off.
        if (! $this->isEnabled()) {
            return [self::RIGHT_READ, self::RIGHT_WRITE];
        }

        if ($user->isAdmin() || $this->isConfiguredAdmin($user)) {
            return [self::RIGHT_READ, self::RIGHT_WRITE];
        }

        $normalized = $this->normalizePath($path);
        if ($normalized === null) {
            $this->warn('Denied a path containing parent traversal');
            return [];
        }

        $groups = $user->getGroups();
        if (empty($groups)) {
            return [];
        }

        $rules = $this->rules();
        if ($rules === null) {
            return [];
        }

        $best_length = -1;
        $rights = [];

        foreach ($groups as $group) {
            if (! is_string($group) || $group === '') {
                continue;
            }

            foreach ($rules as $configured_group => $paths) {
                if (! $this->groupMatches($group, (string) $configured_group)) {
                    continue;
                }
                if (! is_array($paths)) {
                    continue;
                }

                foreach ($paths as $rule_path => $rule_rights) {
                    $normalized_rule = $this->normalizePath((string) $rule_path);
                    if ($normalized_rule === null) {
                        continue;
                    }
                    if (! $this->pathMatches($normalized, $normalized_rule)) {
                        continue;
                    }

                    $length = strlen($normalized_rule);
                    $parsed = $this->parseRights($rule_rights);

                    if ($length > $best_length) {
                        $best_length = $length;
                        $rights = $parsed;
                    } elseif ($length === $best_length) {
                        $rights = array_values(array_unique(array_merge($rights, $parsed)));
                    }
                }
            }
        }

        if (empty($rights)) {
            $this->warn('Access denied for user "'.$user->getUsername().'" on path "'.$normalized.'"');
        }

        return $rights;
    }

    /**
     * Global (Router-level) permissions implied by the user's path rights.
     *
     * "read" unlocks read/download/batchdownload routes; "write" unlocks
     * write/upload/zip/chmod routes. The controllers still enforce the actual
     * per-path decision.
     */
    public function globalPermissionsFor(User $user): array
    {
        if (! $this->isEnabled()) {
            return $this->allPermissions();
        }

        if ($user->isAdmin() || $this->isConfiguredAdmin($user)) {
            return $this->allPermissions();
        }

        $rules = $this->rules();
        if ($rules === null) {
            return [];
        }

        $rights = [];
        foreach ($user->getGroups() as $group) {
            if (! is_string($group) || $group === '') {
                continue;
            }

            foreach ($rules as $configured_group => $paths) {
                if (! $this->groupMatches($group, (string) $configured_group)) {
                    continue;
                }
                if (! is_array($paths)) {
                    continue;
                }

                foreach ($paths as $rule_rights) {
                    foreach ($this->parseRights($rule_rights) as $right) {
                        $rights[$right] = true;
                    }
                }
            }
        }

        $permissions = [];
        if (isset($rights[self::RIGHT_READ])) {
            $permissions[] = 'read';
            $permissions[] = 'download';
            $permissions[] = 'batchdownload';
        }
        if (isset($rights[self::RIGHT_WRITE])) {
            $permissions[] = 'write';
            $permissions[] = 'upload';
            $permissions[] = 'zip';
            $permissions[] = 'chmod';
        }

        return array_values(array_unique($permissions));
    }

    protected function rules(): ?array
    {
        $rules = $this->config['group_paths'] ?? null;

        if (! is_array($rules)) {
            $this->warn('authorization.group_paths is not an array, denying all paths');

            return null;
        }

        return $rules;
    }

    protected function isConfiguredAdmin(User $user): bool
    {
        $admin_groups = $this->config['admin_groups'] ?? [];
        if (! is_array($admin_groups) || empty($admin_groups)) {
            return false;
        }

        foreach ($user->getGroups() as $group) {
            if (! is_string($group) || $group === '') {
                continue;
            }
            foreach ($admin_groups as $admin_group) {
                if ($this->groupMatches($group, (string) $admin_group)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function allPermissions(): array
    {
        return ['read', 'write', 'upload', 'download', 'batchdownload', 'zip', 'chmod'];
    }

    /**
     * Normalize a path for comparison. Returns null when the path contains a
     * ".." segment, which is always denied before any I/O happens.
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

        if ($path === '') {
            $path = '/';
        }

        $path = preg_replace('#/+#', '/', $path);
        if ($path === '' || $path === null) {
            $path = '/';
        }

        if ($path[0] !== '/') {
            $path = '/'.$path;
        }

        if (strlen($path) > 1) {
            $path = rtrim($path, '/');
        }

        if ($path === '') {
            $path = '/';
        }

        return $this->lower($path);
    }

    /**
     * Segment-aware prefix match. "/year 1403" must not match "/year 14030".
     */
    protected function pathMatches(string $candidate, string $rule): bool
    {
        if ($rule === '/') {
            return true;
        }

        return $candidate === $rule || strpos($candidate, $rule.'/') === 0;
    }

    protected function groupMatches(string $user_group, string $configured_group): bool
    {
        $user_group = $this->lower(trim($user_group));
        $configured_group = $this->lower(trim($configured_group));

        if ($configured_group === '') {
            return false;
        }

        if ($user_group === $configured_group) {
            return true;
        }

        // A key without "=" is treated as a bare CN and matched against the CN
        // of the memberOf DN. Full DNs are compared exactly (case-insensitive).
        if (strpos($configured_group, '=') === false) {
            return $this->lower($this->extractCn($user_group)) === $configured_group;
        }

        return false;
    }

    protected function extractCn(string $dn): string
    {
        foreach (explode(',', $dn) as $part) {
            $part = trim($part);
            if (strpos($part, 'cn=') === 0) {
                return substr($part, 3);
            }
        }

        return '';
    }

    protected function parseRights($rights): array
    {
        if (is_array($rights)) {
            $items = $rights;
        } else {
            $items = explode('|', (string) $rights);
        }

        $parsed = [];
        foreach ($items as $item) {
            if (! is_string($item)) {
                continue;
            }
            $item = $this->lower(trim($item));
            if ($item === self::RIGHT_READ || $item === self::RIGHT_WRITE) {
                $parsed[] = $item;
            }
        }

        return array_values(array_unique($parsed));
    }

    protected function lower(string $value): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
    }

    protected function warn(string $message)
    {
        if ($this->logger) {
            $this->logger->log('PathAccessPolicy: '.$message, Logger::WARNING);
        }
    }
}
