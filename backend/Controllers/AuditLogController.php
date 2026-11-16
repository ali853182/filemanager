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
use Filegator\Kernel\Request;
use Filegator\Kernel\Response;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\FileProfile\AuditEventRepositoryInterface;

/**
 * Optional admin-only audit log endpoint (spec.md 18, G12).
 *
 * The route is registered for role "admin" only. The controller repeats the
 * admin check so a direct invocation cannot bypass the router. The endpoint is
 * gated by audit.enabled: when audit is off it returns 404 and touches no
 * storage. Filters and pagination are delegated to the read-only
 * AuditEventRepositoryInterface (prepared statements, explicit columns).
 */
class AuditLogController
{
    protected $auth;

    protected $config;

    protected $events;

    public function __construct(AuthInterface $auth, Config $config, AuditEventRepositoryInterface $events)
    {
        $this->auth = $auth;
        $this->config = $config;
        $this->events = $events;
    }

    public function getAuditLog(Request $request, Response $response)
    {
        if (! $this->config->get('audit.enabled', false)) {
            return $response->json('Not Found', 404);
        }

        $user = $this->auth->user() ?: $this->auth->getGuest();
        if (! $user->isAdmin()) {
            return $response->json('Forbidden', 403);
        }

        $limit = $this->clampLimit($this->intInput($request, 'limit', 100));
        $offset = $this->intInput($request, 'offset', 0);
        $offset = $offset < 0 ? 0 : $offset;

        $filters = [
            'from' => $this->stringInput($request, 'from'),
            'to' => $this->stringInput($request, 'to'),
            'user' => $this->stringInput($request, 'user'),
            'action' => $this->stringInput($request, 'action'),
            'path' => $this->stringInput($request, 'path'),
            'file_id' => $this->stringInput($request, 'file_id'),
            'result' => $this->stringInput($request, 'result'),
        ];

        try {
            $events = $this->events->search($filters, $limit, $offset);
            $total = $this->events->countSearch($filters);
        } catch (\Throwable $exception) {
            return $response->json('Internal Server Error', 500);
        }

        return $response->json([
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset,
            'events' => $events,
        ], 200);
    }

    protected function clampLimit(int $limit): int
    {
        if ($limit < 1) {
            return 100;
        }

        return $limit > 1000 ? 1000 : $limit;
    }

    protected function stringInput(Request $request, string $key): ?string
    {
        $value = $request->input($key, null);

        if ($value === null) {
            return null;
        }

        if (is_string($value)) {
            return $value;
        }

        return null;
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
