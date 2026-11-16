<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Adriano Hänggli <https://github.com/ahaenggli>
 *
 */

namespace Filegator\Services\Auth\Adapters;

use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\Auth\UsersCollection;
use Filegator\Services\Service;
use Filegator\Services\Session\SessionStorageInterface as Session;
use Filegator\Services\Logger\LoggerInterface;
use Monolog\Logger;

/**
 * @codeCoverageIgnore
 */
class LDAP implements Service, AuthInterface
{
    public const SESSION_KEY = 'LDAP_auth';
    public const SESSION_HASH = 'LDAP_auth_hash';
    public const SESSION_LOOKUP = 'LDAP_auth_lookup';
    public const GUEST_USERNAME = 'guest';

    protected $session;

    protected $resolved_user;
    protected $private_repos = false;
    protected $ldap_server;
    protected $ldap_bindDN;
    protected $ldap_bindPass;
    protected $ldap_baseDN;
    protected $ldap_filter;
    protected $ldap_attributes;
    protected $ldap_userFieldMapping;
    protected $authorization = [];
    protected $logger;

    public function __construct(Session $session, LoggerInterface $logger)
    {
        $this->session = $session;
        $this->logger = $logger;
    }

    public function init(array $config = [])
    {
        if (!isset($config['ldap_server']) || empty($config['ldap_server'])) {
            throw new \Exception('config ldap_server missing');
        }

        if (!extension_loaded('ldap')) {
            throw new \Exception('ldap extension missing');
        }

        if ($connect = ldap_connect($config['ldap_server'])) {
            @ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            @ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

            $this->private_repos = $config['private_repos'];
            $this->ldap_server = $config['ldap_server'];
            $this->ldap_bindDN = $config['ldap_bindDN'];
            $this->ldap_bindPass = $config['ldap_bindPass'];
            $this->ldap_baseDN = $config['ldap_baseDN'];
            $this->ldap_filter = $config['ldap_filter'];
            $this->ldap_attributes = $config['ldap_attributes'] ?? ['*'];
            $this->ldap_userFieldMapping = $config['ldap_userFieldMapping'];
            $this->authorization = $config['authorization'] ?? [];
        } else {
            @ldap_close($connect);
            throw new \Exception('could not connect to domain');
        }

        @ldap_close($connect);
    }

    public function user(): ?User
    {
        if (! $this->session) {
            return null;
        }

        // revalidation hits the directory, and both the Router and the resolved
        // controller ask for the user within the same request; resolve once
        if ($this->resolved_user !== null) {
            return $this->resolved_user ?: null;
        }

        $user = $this->session->get(self::SESSION_KEY, null);
        $hash = $this->session->get(self::SESSION_HASH, null);

        if (! $user) {
            return null;
        }

        // re-read the account from the directory on every request so that a
        // disabled or downgraded LDAP user does not keep a stale session,
        // mirroring the Database and JsonFile adapters. Replay the exact search
        // key used at login (SESSION_LOOKUP) so AddDomain/RemoveDomains setups
        // resolve to the same directory entry.
        $lookup = $this->session->get(self::SESSION_LOOKUP, $user->getUsername());

        try {
            foreach ($this->getUsers($lookup) as $u) {
                if (strtolower($u['username']) == strtolower($user->getUsername())
                    && $hash === $this->userHash($u)) {
                    return $this->resolved_user = $user;
                }
            }
        } catch (\Exception $e) {
            // a transient directory outage is not an authorization decision;
            // keep the existing session rather than logging everyone out or 500
            $this->logger->log('LDAP revalidation failed: '.$e->getMessage(), Logger::WARNING);
            return $this->resolved_user = $user;
        }

        $this->resolved_user = false;
        return null;
    }

    public function authenticate($username, $password): bool
    {
        // prevent anonymous binding
        if (!isset($password) || empty($password)) {
            return false;
        }
        if (!isset($username) || empty($username)) {
            return false;
        }

        // remove (optional) domains from the username
        if (!empty($this->ldap_userFieldMapping['username_RemoveDomains']) && is_array($this->ldap_userFieldMapping['username_RemoveDomains'])) {
            $username = str_replace($this->ldap_userFieldMapping['username_RemoveDomains'], '', $username);
        }

        $search_username = $username;
        $all_users = $this->getUsers($search_username);

        // add the domain to the username
        if (!empty($this->ldap_userFieldMapping['username_AddDomain'])) {
            if (strpos($username, $this->ldap_userFieldMapping['username_AddDomain']) === false) {
                $username .= $this->ldap_userFieldMapping['username_AddDomain'];
            }
        }

        foreach ($all_users as &$u) {
            if (strtolower($u['username']) == strtolower($username) && $this->verifyPassword($u['userDN'], $password)) {
                $user = $this->mapToUserObject($u);
                $this->store($user);
                $this->session->set(self::SESSION_HASH, $this->userHash($u));
                $this->session->set(self::SESSION_LOOKUP, $search_username);
                // regenerate the session id on login to prevent session fixation,
                // mirroring the Database and JsonFile adapters
                $this->session->migrate(true);
                return true;
            }
        }

        return false;
    }

    public function forget()
    {
        $this->resolved_user = null;

        return $this->session->invalidate();
    }

    public function store(User $user)
    {
        $this->resolved_user = null;

        return $this->session->set(self::SESSION_KEY, $user);
    }

    public function update($username, User $user, $password = ''): User
    {
        return new User(); // not used
    }

    public function add(User $user, $password): User
    {
        return new User(); // not used
    }

    public function delete(User $user)
    {
        return true; // not used
    }

    public function find($username): ?User
    {
        foreach ($this->getUsers($username) as $user) {
            if (strtolower($user['username']) == strtolower($username)) {
                return $this->mapToUserObject($user);
            }
        }

        return null;
    }

    public function getGuest(): User
    {
        $guest = $this->find(self::GUEST_USERNAME);

        if (!$guest || !$guest->isGuest()) {
            $guest = new User();
            $guest->setUsername('guest');
            $guest->setName('Guest');
            $guest->setRole('guest');
            $guest->setHomedir('/');
            $guest->setPermissions([]);
            return $guest;
        }

        return $guest;
    }

    public function allUsers(): UsersCollection
    {
        $users = new UsersCollection();

        foreach ($this->getUsers() as $user) {
            $users->addUser($this->mapToUserObject($user));
        }

        return $users;
    }

    protected function mapToUserObject(array $user): User
    {
        $new = new User();
        $new->setUsername($user['username']);
        $new->setName($user['name']);
        $new->setRole($user['role']);
        $new->setHomedir($user['homedir']);
        $new->setGroups(isset($user['groups']) && is_array($user['groups']) ? $user['groups'] : []);
        try {
            if ($user['permissions'] === '' || $user['permissions'] === []) {
                $new->setPermissions([]);
            } else {
                $new->setPermissions($user['permissions'], true);
            }
        } catch (\Exception $e) {
            // fail closed: an invalid permission name (e.g. a typo in
            // group_permissions) must never grant access or break login
            $this->logger->log('Invalid LDAP permissions for user '.$user['username'].': '.$e->getMessage(), Logger::WARNING);
            $new->setPermissions([]);
        }
        return $new;
    }

    protected function getUsers(string $username = null): array
    {
        $ldapConn = @ldap_connect($this->ldap_server);
        if (!$ldapConn) {
            throw new \Exception('Cannot Connect to LDAP server');
        }
        @ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        @ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);

        $ldapBind = @ldap_bind($ldapConn, $this->ldap_bindDN, $this->ldap_bindPass);
        if (!$ldapBind) {
            throw new \Exception('Cannot Bind to LDAP server: Wrong credentials?');
        }

        // search the LDAP server for users
        $filter = $this->buildUserFilter($username);

        $attributes = $this->ldap_attributes;
        $group_attribute = $this->getGroupAttribute();
        if ($group_attribute !== null) {
            $requested = array_map('strtolower', array_filter($attributes, 'is_string'));
            if (!in_array($group_attribute, $requested, true)) {
                $attributes[] = $group_attribute;
            }
        }

        $ldapSearch = @ldap_search($ldapConn, $this->ldap_baseDN, $filter, $attributes);

        if (!$ldapSearch) {
            $this->logger->log($filter);
            throw new \Exception('Cannot search LDAP server: Wrong filter?');
        }

        $ldapResults = @ldap_get_entries($ldapConn, $ldapSearch);
        @ldap_close($ldapConn);

        $users = [];

        for ($item = 0; $item < $ldapResults['count']; $item++) {

            $missingAttributes = [];

            // Check if all required attributes are present
            foreach (['username', 'name', 'userDN'] as $attribute) {
                if (!isset($ldapResults[$item][$this->ldap_userFieldMapping[$attribute]])) {
                    $missingAttributes[] = '`' . $this->ldap_userFieldMapping[$attribute] . '` as `' . $attribute . '`';
                }
            }
            // if any required attribute is missing, log an info message
            if (!empty($missingAttributes)) {
                $this->logger->log('Missing LDAP attribues: ' . implode(', ', $missingAttributes) . '. Please check the spelling (including upper or lower case).', Logger::WARNING);
            } else {
                $user = $this->mapEntryToUser($ldapResults[$item]);

                if (is_array($user) && !empty($user)) {
                    $users[] = $user;
                }
            }
        }
        // print_r($users); // uncomment this line to see all available ldap-login-users
        return is_array($users) ? $users : [];
    }

    /**
     * Build the LDAP search filter for a login lookup. The username is escaped
     * for filter context (RFC 4515) so it cannot inject filter syntax.
     */
    protected function buildUserFilter(string $username = null): string
    {
        $filter = $this->ldap_filter;
        if (!empty($username)) {
            $safe_username = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
            $filter = '(&' . $filter . '(' . $this->ldap_userFieldMapping['username'] . '=' . $safe_username . '))';
        }

        return $filter;
    }

    /**
     * Map a single ldap_get_entries() row to the internal user array.
     *
     * Group-based authorization is opt-in: it is active only when
     * ldap_userFieldMapping.group_permissions is a non-empty array. When it is
     * not configured the historical default_permissions/admin_usernames
     * behaviour is preserved unchanged.
     */
    protected function mapEntryToUser(array $entry): array
    {
        $user = [];
        $user['username'] = $entry[$this->ldap_userFieldMapping['username']][0];
        $user['name'] = $entry[$this->ldap_userFieldMapping['name']][0];
        $user['role'] = 'user';
        $user['homedir'] = '/';
        $user['permissions'] = (string) ($this->ldap_userFieldMapping['default_permissions'] ?? '');
        $user['userDN'] = $entry[$this->ldap_userFieldMapping['userDN']] ?? '';

        if (!empty($this->ldap_userFieldMapping['username_AddDomain'])) {
            if (strpos($user['username'], $this->ldap_userFieldMapping['username_AddDomain']) === false) {
                $user['username'] .= $this->ldap_userFieldMapping['username_AddDomain'];
            }
        }

        $member_of = $this->memberOfFromEntry($entry);
        $user['groups'] = $member_of;

        if ($this->isAuthorizationEnabled()) {
            // Path-based authorization is the source of truth: global
            // permissions are the union of the rights granted on the user's
            // allowed paths, and admins come only from authorization.admin_groups.
            $user['permissions'] = $this->resolveAuthorizationPermissions($member_of);

            if ($this->isAuthorizationAdmin($member_of)) {
                $user['role'] = 'admin';
            }
        } else {
            $group_mapping = $this->ldap_userFieldMapping['group_permissions'] ?? [];
            $group_mode = is_array($group_mapping) && !empty($group_mapping);

            if ($group_mode) {
                $user['permissions'] = $this->resolveGroupPermissions($member_of);

                // Admin is granted only by explicit admin_groups membership, never
                // by a general/indirect group or by the legacy username list.
                if ($this->isAdminGroupMember($member_of)) {
                    $user['role'] = 'admin';
                }
            } else {
                if (is_array($this->ldap_userFieldMapping['admin_usernames'] ?? null)) {
                    if (in_array($user['username'], $this->ldap_userFieldMapping['admin_usernames'])) {
                        $user['role'] = 'admin';
                    }
                }
            }
        }

        // private repositories for each user?
        if ($this->private_repos) {
            $user['homedir'] = '/' . $user['username'];
        }

        // ...but not for admins
        if ($user['role'] == 'admin') {
            $user['homedir'] = '/';
            $user['permissions'] = 'read|write|upload|download|batchdownload|zip|chmod';
        }

        return $user;
    }

    /**
     * LDAP attribute that carries the user's group DNs. Returns null when
     * group-based authorization is not configured.
     */
    protected function getGroupAttribute(): ?string
    {
        $mapping = $this->ldap_userFieldMapping['group_permissions'] ?? [];
        $group_mode = is_array($mapping) && !empty($mapping);

        // memberOf is also needed when path-based authorization is enabled,
        // even if the legacy group_permissions map is empty.
        if (!$group_mode && !$this->isAuthorizationEnabled()) {
            return null;
        }

        $attribute = $this->ldap_userFieldMapping['group_attribute'] ?? 'memberof';

        return strtolower((string) $attribute);
    }

    /**
     * Extract the memberOf values from a single ldap_get_entries() row.
     * Returns an empty array when the attribute is absent (fail-closed: the
     * caller then treats the user as belonging to no configured group).
     */
    protected function memberOfFromEntry(array $entry): array
    {
        $attribute = $this->getGroupAttribute();
        if ($attribute === null || !isset($entry[$attribute]) || !is_array($entry[$attribute])) {
            return [];
        }

        $groups = [];
        $count = (int) ($entry[$attribute]['count'] ?? 0);
        for ($i = 0; $i < $count; $i++) {
            if (isset($entry[$attribute][$i]) && is_string($entry[$attribute][$i])) {
                $groups[] = $entry[$attribute][$i];
            }
        }

        return $groups;
    }

    /**
     * Resolve a user's permissions from the configured group map.
     *
     * Policy: union of every matched group's permissions. A user that matches
     * no configured group receives ldap_userFieldMapping.unmapped_permissions
     * (empty string by default, i.e. no access).
     */
    protected function resolveGroupPermissions(array $member_of): string
    {
        $mapping = $this->ldap_userFieldMapping['group_permissions'] ?? [];
        $granted = [];
        $matched = false;

        $policy = $this->ldap_userFieldMapping['permission_policy'] ?? 'union';
        if ($policy !== 'union') {
            // only union is implemented; unknown policies fall back to union
            // and are logged instead of silently granting something else
            $this->logger->log('Unsupported LDAP permission_policy "'.$policy.'", using union', Logger::WARNING);
        }

        foreach ($mapping as $group_key => $permissions) {
            if ($this->matchesGroup($member_of, (string) $group_key)) {
                $matched = true;
                foreach ($this->parsePermissions($permissions) as $permission) {
                    $granted[$permission] = true;
                }
            }
        }

        if (!$matched) {
            return $this->encodePermissions($this->parsePermissions($this->ldap_userFieldMapping['unmapped_permissions'] ?? ''));
        }

        return $this->encodePermissions(array_keys($granted));
    }

    /**
     * True only when the user's direct memberOf values contain one of the
     * configured admin group keys. Nested group expansion is intentionally not
     * performed; see the project report.
     */
    protected function isAdminGroupMember(array $member_of): bool
    {
        $admin_groups = $this->ldap_userFieldMapping['admin_groups'] ?? [];
        if (!is_array($admin_groups) || empty($admin_groups)) {
            return false;
        }

        foreach ($admin_groups as $group_key) {
            if ($this->matchesGroup($member_of, (string) $group_key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * True when the new folder-level authorization layer is enabled.
     */
    protected function isAuthorizationEnabled(): bool
    {
        return !empty($this->authorization['enabled']);
    }

    /**
     * Admin role for path-based authorization comes only from
     * authorization.admin_groups, never from admin_usernames.
     */
    protected function isAuthorizationAdmin(array $member_of): bool
    {
        $admin_groups = $this->authorization['admin_groups'] ?? [];
        if (!is_array($admin_groups) || empty($admin_groups)) {
            return false;
        }

        foreach ($admin_groups as $group_key) {
            if ($this->matchesGroup($member_of, (string) $group_key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Global permissions implied by the union of the rights granted on every
     * path the user's groups can reach. A user matching no rule gets nothing
     * (fail-closed).
     */
    protected function resolveAuthorizationPermissions(array $member_of): string
    {
        $group_paths = $this->authorization['group_paths'] ?? [];
        if (!is_array($group_paths)) {
            $this->logger->log('Invalid authorization.group_paths, denying all permissions', Logger::WARNING);
            return '';
        }

        $rights = [];

        foreach ($group_paths as $group_key => $paths) {
            if (!$this->matchesGroup($member_of, (string) $group_key)) {
                continue;
            }
            if (!is_array($paths)) {
                continue;
            }

            foreach ($paths as $permissions) {
                foreach ($this->parsePermissions($permissions) as $permission) {
                    $permission = strtolower($permission);
                    if ($permission === 'read' || $permission === 'write') {
                        $rights[$permission] = true;
                    }
                }
            }
        }

        $permissions = [];
        if (isset($rights['read'])) {
            $permissions[] = 'read';
            $permissions[] = 'download';
            $permissions[] = 'batchdownload';
        }
        if (isset($rights['write'])) {
            $permissions[] = 'write';
            $permissions[] = 'upload';
            $permissions[] = 'zip';
            $permissions[] = 'chmod';
        }

        return $this->encodePermissions($permissions);
    }

    /**
     * Exact (case-insensitive) group match. A configured key containing "=" is
     * treated as a full DN; otherwise it is treated as a bare CN and compared
     * against the CN of each memberOf DN. Substring matching is never used.
     */
    protected function matchesGroup(array $member_of, string $group_key): bool
    {
        $normalized_key = $this->normalizeGroupKey($group_key);
        if ($normalized_key === '') {
            return false;
        }

        $key_is_dn = strpos($group_key, '=') !== false;

        foreach ($member_of as $dn) {
            if (!is_string($dn) || $dn === '') {
                continue;
            }

            if ($this->normalizeGroupKey($dn) === $normalized_key) {
                return true;
            }

            if (!$key_is_dn && $this->normalizeGroupKey($this->extractCn($dn)) === $normalized_key) {
                return true;
            }
        }

        return false;
    }

    protected function normalizeGroupKey(string $value): string
    {
        return strtolower(trim($value));
    }

    protected function extractCn(string $dn): string
    {
        foreach (explode(',', $dn) as $part) {
            $part = trim($part);
            if (stripos($part, 'CN=') === 0) {
                return substr($part, 3);
            }
        }

        return '';
    }

    /**
     * Accept either a "read|download" string or an array of permission names.
     * Unknown/empty entries are dropped here; User::setPermissions() remains
     * the final validator.
     */
    protected function parsePermissions($permissions): array
    {
        if (is_array($permissions)) {
            $items = $permissions;
        } else {
            $items = explode('|', (string) $permissions);
        }

        $parsed = [];
        foreach ($items as $item) {
            if (!is_string($item)) {
                continue;
            }
            $item = trim($item);
            if ($item !== '') {
                $parsed[] = $item;
            }
        }

        return array_values(array_unique($parsed));
    }

    protected function encodePermissions(array $permissions): string
    {
        return implode('|', $permissions);
    }

    // signature of the security-relevant account fields, compared on each
    // request to invalidate a session whose LDAP account was changed; plain
    // concatenation mirrors the Database and JsonFile adapters
    private function userHash(array $u): string
    {
        return ($u['role'] ?? '').($u['homedir'] ?? '').($u['permissions'] ?? '')
            .implode('|', (array) ($u['groups'] ?? []));
    }

    protected function verifyPassword($auth_user, $password)
    {
        if (!isset($this->ldap_server) || empty($this->ldap_server)) {
            return false;
        }
        if (!extension_loaded('ldap')) {
            return false;
        }
        $connect = @ldap_connect($this->ldap_server);
        if ($connect) {
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
            $bind = @ldap_bind($connect, $auth_user, $password);
            if ($bind) {
                @ldap_close($connect);
                return true;
            } else {
                @ldap_close($connect);
                return false;
            }
        }

        @ldap_close($connect);
        return false;
    }
}
