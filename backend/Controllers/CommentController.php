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
use Filegator\Services\FileProfile\CommentService;

/**
 * HTTP endpoints for file comments (spec.md 11.1).
 *
 * Role ("user"/"admin") and the "read" permission are enforced by the router
 * (routes.php) before this controller runs; CSRF for POST is enforced by the
 * existing Security service. The controller additionally enforces
 * PathAccessPolicy::canRead per path through CommentService.
 *
 * When comments.enabled is false CommentService answers 404 and touches no
 * storage, so the endpoints are a no-op (spec.md 15).
 */
class CommentController
{
    protected $auth;

    protected $comments;

    public function __construct(AuthInterface $auth, CommentService $comments)
    {
        $this->auth = $auth;
        $this->comments = $comments;
    }

    public function listComments(Request $request, Response $response)
    {
        $user = $this->auth->user() ?: $this->auth->getGuest();

        $result = $this->comments->listComments(
            $user,
            (string) $request->input('path', ''),
            $this->intInput($request, 'limit', 50),
            $this->intInput($request, 'offset', 0)
        );

        return $response->json($result['data'], $result['status']);
    }

    public function addComment(Request $request, Response $response)
    {
        $user = $this->auth->user() ?: $this->auth->getGuest();

        $result = $this->comments->addComment(
            $user,
            (string) $request->input('path', ''),
            (string) $request->input('text', $request->input('body', '')),
            $this->clientIp($request),
            (string) $request->input('type', 'file')
        );

        return $response->json($result['data'], $result['status']);
    }

    public function deleteComment(Request $request, Response $response)
    {
        $user = $this->auth->user() ?: $this->auth->getGuest();

        $result = $this->comments->deleteComment(
            $user,
            $this->intInput($request, 'comment_id', 0),
            $this->clientIp($request)
        );

        return $response->json($result['data'], $result['status']);
    }

    public function searchComments(Request $request, Response $response)
    {
        $user = $this->auth->user() ?: $this->auth->getGuest();

        $result = $this->comments->searchComments(
            $user,
            (string) $request->input('q', ''),
            $this->intInput($request, 'limit', 50),
            $this->intInput($request, 'offset', 0)
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

    protected function clientIp(Request $request): string
    {
        try {
            $ip = $request->getClientIp();
        } catch (\Throwable $exception) {
            return 'unknown';
        }

        return is_string($ip) && $ip !== '' ? $ip : 'unknown';
    }
}
