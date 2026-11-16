<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Tests\Unit\Auth;

use Exception;
use Filegator\Kernel\Request;
use Filegator\Services\Auth\Adapters\LDAP;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Session\Adapters\SessionStorage;
use Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage;
use Tests\TestCase;

/**
 * Group-based authorization tests for the LDAP adapter.
 *
 * The adapter is exercised through its pure mapping seam (mapEntryToUser) and
 * the filter builder, so no LDAP server or real credentials are needed. The
 * directory-dependent getUsers()/verifyPassword() methods are replaced with
 * in-memory fixtures.
 *
 * @internal
 */
class LdapGroupPermissionsTest extends TestCase
{
    private const READERS = 'CN=FileGator-Readers,OU=FileGator,OU=Groups,DC=CHEKAD,DC=LOCAL';

    private const UPLOADERS = 'CN=FileGator-Uploaders,OU=FileGator,OU=Groups,DC=CHEKAD,DC=LOCAL';

    private const ADMINS = 'CN=FileGator-Admins,OU=FileGator,OU=Groups,DC=CHEKAD,DC=LOCAL';

    private function mapping(array $overrides = []): array
    {
        return array_merge([
            'username' => 'samaccountname',
            'name' => 'cn',
            'userDN' => 'dn',
            'default_permissions' => 'read|download',
            'admin_usernames' => ['legacyadmin'],
            'group_attribute' => 'memberof',
            'permission_policy' => 'union',
            'group_permissions' => [
                self::READERS => 'read|download',
                self::UPLOADERS => 'read|download|write|upload',
                self::ADMINS => 'read|write|upload|download|batchdownload|zip|chmod',
            ],
            'admin_groups' => [self::ADMINS],
            'unmapped_permissions' => '',
        ], $overrides);
    }

    private function makeAuth(array $mapping, array $directory = []): LDAP
    {
        $request = new Request();
        $session = new SessionStorage($request);
        $session->init([
            'handler' => function () {
                return new MockFileSessionStorage();
            },
        ]);

        $logger = new class implements LoggerInterface {
            public $messages = [];

            public function log(string $message, int $level)
            {
                $this->messages[] = $message;
            }
        };

        return new class($session, $logger, $mapping, $directory) extends LDAP {
            public $fail = false;

            private $mapping;

            private $directory;

            public function __construct($session, $logger, array $mapping, array $directory)
            {
                parent::__construct($session, $logger);
                $this->mapping = $mapping;
                $this->directory = $directory;
                $this->ldap_userFieldMapping = $mapping;
                $this->ldap_filter = '(&(objectClass=user)(sAMAccountName=*))';
            }

            public function map(array $entry): array
            {
                return $this->mapEntryToUser($entry);
            }

            public function toUser(array $user): \Filegator\Services\Auth\User
            {
                return $this->mapToUserObject($user);
            }

            public function buildFilter(string $username = null): string
            {
                return $this->buildUserFilter($username);
            }

            protected function getUsers(string $username = null): array
            {
                if ($this->fail) {
                    throw new Exception('Cannot search LDAP server: Wrong filter?');
                }

                return $this->directory;
            }

            protected function verifyPassword($auth_user, $password)
            {
                return $password === 'correct-horse';
            }
        };
    }

    private function entry(array $groups = null, array $overrides = []): array
    {
        $entry = array_merge([
            'samaccountname' => ['alice'],
            'cn' => ['Alice'],
            'dn' => 'CN=Alice,OU=Users,DC=CHEKAD,DC=LOCAL',
        ], $overrides);

        if ($groups !== null) {
            $entry['memberof'] = $groups;
            $entry['memberof']['count'] = count($groups);
        }

        return $entry;
    }

    private function permissionsOf(array $user): array
    {
        $permissions = $user['permissions'] === '' ? [] : explode('|', $user['permissions']);
        sort($permissions);

        return $permissions;
    }

    public function testReadersGroupGetsReadAndDownload()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry([self::READERS]));

        $this->assertEquals('user', $user['role']);
        $this->assertEquals(['download', 'read'], $this->permissionsOf($user));
    }

    public function testUploadersGroupGetsUploadPermissions()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry([self::UPLOADERS]));

        $this->assertEquals('user', $user['role']);
        $this->assertEquals(['download', 'read', 'upload', 'write'], $this->permissionsOf($user));
    }

    public function testMultipleGroupsAreUnioned()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry([self::READERS, self::UPLOADERS]));

        $this->assertEquals(['download', 'read', 'upload', 'write'], $this->permissionsOf($user));
    }

    public function testUserInNoConfiguredGroupGetsNoPermissions()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry(['CN=SomeOtherGroup,OU=Groups,DC=CHEKAD,DC=LOCAL']));

        $this->assertEquals('user', $user['role']);
        $this->assertEquals([], $this->permissionsOf($user));
    }

    public function testUnmappedPermissionsCanBeConfigured()
    {
        $auth = $this->makeAuth($this->mapping(['unmapped_permissions' => 'read']));

        $user = $auth->map($this->entry(['CN=SomeOtherGroup,OU=Groups,DC=CHEKAD,DC=LOCAL']));

        $this->assertEquals(['read'], $this->permissionsOf($user));
    }

    public function testMissingMemberOfFailsClosed()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry(null));

        $this->assertEquals([], $this->permissionsOf($user));
        $this->assertEquals('user', $user['role']);
    }

    public function testAdminRoleComesOnlyFromExplicitAdminGroup()
    {
        $auth = $this->makeAuth($this->mapping());

        $reader = $auth->map($this->entry([self::READERS]));
        $this->assertEquals('user', $reader['role']);

        $admin = $auth->map($this->entry([self::ADMINS]));
        $this->assertEquals('admin', $admin['role']);
        $this->assertEquals('/', $admin['homedir']);
        $this->assertEquals(
            ['batchdownload', 'chmod', 'download', 'read', 'upload', 'write', 'zip'],
            $this->permissionsOf($admin)
        );
    }

    public function testLegacyAdminUsernameIsIgnoredInGroupMode()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry([self::READERS], ['samaccountname' => ['legacyadmin']]));

        $this->assertEquals('user', $user['role']);
        $this->assertEquals(['download', 'read'], $this->permissionsOf($user));
    }

    public function testGroupModeDisabledKeepsLegacyBehaviour()
    {
        $mapping = $this->mapping();
        unset($mapping['group_permissions']);

        $auth = $this->makeAuth($mapping);

        $user = $auth->map($this->entry(null));
        $this->assertEquals(['download', 'read'], $this->permissionsOf($user));

        $legacy_admin = $auth->map($this->entry(null, ['samaccountname' => ['legacyadmin']]));
        $this->assertEquals('admin', $legacy_admin['role']);
    }

    public function testGroupDnMatchIsCaseInsensitive()
    {
        $auth = $this->makeAuth($this->mapping());

        $user = $auth->map($this->entry([strtolower(self::READERS)]));

        $this->assertEquals(['download', 'read'], $this->permissionsOf($user));
    }

    public function testBareCnKeyMatchesGroupDn()
    {
        $mapping = $this->mapping([
            'group_permissions' => ['FileGator-Readers' => 'read|download'],
            'admin_groups' => [],
        ]);

        $auth = $this->makeAuth($mapping);

        $user = $auth->map($this->entry([self::READERS]));

        $this->assertEquals(['download', 'read'], $this->permissionsOf($user));
    }

    public function testUsernameIsEscapedInLdapFilter()
    {
        $auth = $this->makeAuth($this->mapping());

        $filter = $auth->buildFilter('*)(uid=*');

        $this->assertStringContainsString('\2a', $filter);
        $this->assertStringNotContainsString('*)(uid=*', $filter);
    }

    public function testDirectoryFailureAbortsLogin()
    {
        $auth = $this->makeAuth($this->mapping());
        $auth->fail = true;

        $this->expectException(Exception::class);

        $auth->authenticate('alice', 'correct-horse');
    }

    public function testGuestHasNoPermissionsWhenNoGuestAccountExists()
    {
        $auth = $this->makeAuth($this->mapping(), []);

        $guest = $auth->getGuest();

        $this->assertEquals('guest', $guest->getRole());
        $this->assertEquals([], $guest->getPermissions());
    }

    public function testInvalidConfiguredPermissionFailsClosed()
    {
        $mapping = $this->mapping([
            'group_permissions' => [self::READERS => 'read|not-a-real-permission'],
            'admin_groups' => [],
        ]);

        $auth = $this->makeAuth($mapping);
        $mapped = $auth->map($this->entry([self::READERS]));

        $user = $auth->toUser($mapped);

        $this->assertEquals([], $user->getPermissions());
    }
}
