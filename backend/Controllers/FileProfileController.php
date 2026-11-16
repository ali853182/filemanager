<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Controllers;

use Filegator\Kernel\Request;
use Filegator\Kernel\Response;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\FileProfile\FileProfileService;

/**
 * HTTP endpoint for the file identity card (spec.md 11, FR8/FR9).
 *
 * Role ("user"/"admin") and the "read" permission are enforced by the router
 * (routes.php) before this controller runs. The controller additionally
 * enforces PathAccessPolicy::canRead per path through FileProfileService.
 *
 * When file_profile.enabled is false FileProfileService answers 404 and
 * touches no storage, so the endpoint is a no-op (spec.md 15).
 */
class FileProfileController
{
    protected $auth;

    protected $profiles;

    public function __construct(AuthInterface $auth, FileProfileService $profiles)
    {
        $this->auth = $auth;
        $this->profiles = $profiles;
    }

    public function getProfile(Request $request, Response $response)
    {
        $user = $this->auth->user() ?: $this->auth->getGuest();

        $result = $this->profiles->getProfile(
            $user,
            (string) $request->input('path', ''),
            $this->intInput($request, 'history_limit', 0),
            $this->intInput($request, 'comments_limit', 0),
            $this->intInput($request, 'history_offset', 0),
            $this->intInput($request, 'comments_offset', 0)
        );

        return $response->json($result['data'], $result['status']);
    }

    protected function intInput(Request $request, string $key, int $default): int
    {
        $value = $request->input($key, $default);

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && is_numeric($value)) {
            return (int) $value;
        }

        return $default;
    }
}
