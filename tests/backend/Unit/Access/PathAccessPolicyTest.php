<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Tests\Unit\Access;

use Filegator\Services\Access\PathAccessPolicy;
use Filegator\Services\Auth\User;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
class PathAccessPolicyTest extends TestCase
{
    private const BUY = 'CN=Buy,OU=Group,OU=chekad,DC=chekad,DC=local';

    private const SALES = 'CN=Sales,OU=Group,OU=chekad,DC=chekad,DC=local';

    private const COMMERCIAL = 'CN=Commercial,OU=Group,OU=chekad,DC=chekad,DC=local';

    private const ADM = 'CN=ADM,OU=Group,OU=chekad,DC=chekad,DC=local';

    private const DOMAIN_USERS = 'CN=Domain Users,CN=Users,DC=chekad,DC=local';

    private function policy(array $overrides = []): PathAccessPolicy
    {
        $config = array_merge([
            'enabled' => true,
            'default' => 'deny',
            'admin_groups' => [self::ADM],
            'group_paths' => [
                self::BUY => [
                    '/اطلاعات خرید' => 'read|write',
                    '/اطلاعات فروش' => 'read',
                ],
                self::SALES => [
                    '/اطلاعات فروش' => 'read|write',
                ],
                self::COMMERCIAL => [
                    '/اطلاعات فروش' => 'read',
                ],
                self::DOMAIN_USERS => [
                    '/سال 1403' => 'read',
                ],
            ],
        ], $overrides);

        $policy = new PathAccessPolicy();
        $policy->init($config);

        return $policy;
    }

    private function user(array $groups, string $role = 'user'): User
    {
        $user = new User();
        $user->setUsername('test-user');
        $user->setRole($role);
        $user->setGroups($groups);

        return $user;
    }

    public function testReadOnAllowedPath()
    {
        $policy = $this->policy();

        $this->assertTrue($policy->canRead($this->user([self::BUY]), '/اطلاعات خرید'));
    }

    public function testWriteOnAllowedPath()
    {
        $policy = $this->policy();

        $this->assertTrue($policy->canWrite($this->user([self::BUY]), '/اطلاعات خرید'));
    }

    public function testDenyOnUnauthorizedPath()
    {
        $policy = $this->policy();

        $user = $this->user([self::BUY]);

        $this->assertFalse($policy->canRead($user, '/سال 1404'));
        $this->assertFalse($policy->canWrite($user, '/سال 1404'));
    }

    public function testUserWithoutGroupsIsDenied()
    {
        $policy = $this->policy();

        $this->assertFalse($policy->canRead($this->user([]), '/اطلاعات خرید'));
        $this->assertFalse($policy->canWrite($this->user([]), '/اطلاعات خرید'));
    }

    public function testMultipleGroupsAreUnioned()
    {
        $policy = $this->policy();

        // Buy grants read on sales, Sales grants read|write: union is read|write.
        $user = $this->user([self::BUY, self::SALES]);

        $this->assertTrue($policy->canRead($user, '/اطلاعات فروش'));
        $this->assertTrue($policy->canWrite($user, '/اطلاعات فروش'));
    }

    public function testLongestPrefixWins()
    {
        $policy = $this->policy([
            'group_paths' => [
                self::BUY => [
                    '/data' => 'read',
                    '/data/secret' => 'write',
                ],
            ],
        ]);

        $user = $this->user([self::BUY]);

        // The longest matching rule is "/data/secret" (write only), so the
        // broader read grant on "/data" must not leak through.
        $this->assertFalse($policy->canRead($user, '/data/secret/file.txt'));
        $this->assertTrue($policy->canWrite($user, '/data/secret/file.txt'));
    }

    public function testPrefixMatchIsCaseInsensitive()
    {
        $policy = $this->policy([
            'group_paths' => [
                self::BUY => [
                    '/Data/Reports' => 'read',
                ],
            ],
        ]);

        $this->assertTrue($policy->canRead($this->user([self::BUY]), '/data/reports/Q1.TXT'));
    }

    public function testPrefixMatchIsSegmentAware()
    {
        $policy = $this->policy();

        $user = $this->user([self::DOMAIN_USERS]);

        $this->assertTrue($policy->canRead($user, '/سال 1403/گزارش.txt'));
        $this->assertFalse($policy->canRead($user, '/سال 14030'));
    }

    public function testParentTraversalIsDenied()
    {
        $policy = $this->policy();

        $user = $this->user([self::DOMAIN_USERS]);

        $this->assertFalse($policy->canRead($user, '/سال 1403/../secret'));
        $this->assertFalse($policy->canWrite($user, '\\سال 1403\\..\\secret'));
    }

    public function testAdminRoleBypassesPathRules()
    {
        $policy = $this->policy();

        $admin = $this->user([], 'admin');

        $this->assertTrue($policy->canRead($admin, '/anything/at/all'));
        $this->assertTrue($policy->canWrite($admin, '/anything/at/all'));
    }

    public function testAdminGroupBypassesPathRules()
    {
        $policy = $this->policy();

        $user = $this->user([self::ADM]);

        $this->assertTrue($policy->canRead($user, '/anything/at/all'));
        $this->assertTrue($policy->canWrite($user, '/anything/at/all'));
    }

    public function testDisabledPolicyAllowsEverything()
    {
        $policy = $this->policy(['enabled' => false]);

        $user = $this->user([]);

        $this->assertTrue($policy->canRead($user, '/anything'));
        $this->assertTrue($policy->canWrite($user, '/anything'));
    }

    public function testPathsWithSpacesAndPersianCharacters()
    {
        $policy = $this->policy([
            'group_paths' => [
                self::BUY => [
                    '/اطلاعات خرید' => 'read|write',
                ],
            ],
        ]);

        $user = $this->user([self::BUY]);

        $this->assertTrue($policy->canRead($user, '/اطلاعات خرید/فایل من.txt'));
        $this->assertTrue($policy->canWrite($user, '/اطلاعات خرید/فایل من.txt'));
    }

    public function testBareGroupNameMatchesDn()
    {
        $policy = $this->policy([
            'group_paths' => [
                'Buy' => [
                    '/اطلاعات خرید' => 'read',
                ],
            ],
        ]);

        $this->assertTrue($policy->canRead($this->user([self::BUY]), '/اطلاعات خرید'));
    }

    public function testGlobalPermissionsAreDerivedFromPathRights()
    {
        $policy = $this->policy();

        $reader = $policy->globalPermissionsFor($this->user([self::COMMERCIAL]));
        sort($reader);
        $this->assertEquals(['batchdownload', 'download', 'read'], $reader);

        $writer = $policy->globalPermissionsFor($this->user([self::SALES]));
        sort($writer);
        $this->assertEquals(
            ['batchdownload', 'chmod', 'download', 'read', 'upload', 'write', 'zip'],
            $writer
        );
    }

    public function testGlobalPermissionsAreEmptyWithoutRules()
    {
        $policy = $this->policy();

        $this->assertEquals([], $policy->globalPermissionsFor($this->user([])));
    }
}
