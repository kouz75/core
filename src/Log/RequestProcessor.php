<?php

declare(strict_types=1);

namespace Bolt\Log;

use Bolt\Entity\User;
use Monolog\LogRecord;
use Symfony\Component\Filesystem\Path;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Security;

class RequestProcessor
{
    private RequestStack $request;
    private Security $security;
    private string $projectDir;

    public function __construct(RequestStack $request, Security $security, KernelInterface $kernel)
    {
        $this->request = $request;
        $this->security = $security;
        $this->projectDir = $kernel->getProjectDir();
    }

    public function processRecord(LogRecord $record): LogRecord
    {
        $request = $this->request->getCurrentRequest();
        $user = $this->security->getUser();
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 7);

        $extra = $record->extra;

        if ($request !== null) {
            $extra['client_ip'] = $request->getClientIp();
            $extra['client_port'] = $request->getPort();
            $extra['uri'] = $request->getUri();
            $extra['query_string'] = $request->getQueryString();
            $extra['method'] = $request->getMethod();
        }

        if ($user instanceof User) {
            $extra['user'] = [
                'id' => $user->getId(),
                'username' => $user->getUsername(),
                'roles' => $user->getRoles(),
            ];
        }

        $extra['location'] = [
            'file' => isset($trace[5]['file']) ? '…/' . Path::makeRelative($trace[5]['file'], $this->projectDir) : null,
            'line' => $trace[5]['line'] ?? null,
            'class' => $trace[6]['class'] ?? null,
            'type' => $trace[6]['type'] ?? null,
            'function' => $trace[6]['function'] ?? null,
        ];

        return $record->with(extra: $extra);
    }
}
