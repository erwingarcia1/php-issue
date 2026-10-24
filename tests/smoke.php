<?php
declare(strict_types=1);

$base = rtrim($argv[1] ?? 'http://127.0.0.1:8000', '/');
$checks = [
    ['/', 200, 'Your PHP app is running.', 'text/html'],
    ['/health', 200, '{"status":"ok"}', 'application/json'],
    ['/missing', 404, 'Not found', 'text/html'],
];

foreach ($checks as [$path, $expectedStatus, $expectedBody, $contentType]) {
    $context = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 5]]);
    $body = file_get_contents($base . $path, false, $context);
    $headers = $http_response_header ?? [];
    $statusLine = $headers[0] ?? '';
    if ($body === false || !preg_match('/^HTTP\/\S+ ' . $expectedStatus . '\b/', $statusLine)
        || !str_contains($body, $expectedBody)
        || !str_contains(strtolower(implode("\n", $headers)), 'content-type: ' . $contentType)) {
        fwrite(STDERR, "FAIL $path: unexpected response ($statusLine)\n");
        exit(1);
    }
    echo "PASS $path ($expectedStatus)\n";
}
