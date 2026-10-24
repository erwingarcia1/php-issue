<?php
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/health') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'ok'], JSON_THROW_ON_ERROR);
    return;
}

header('Content-Type: text/html; charset=utf-8');
if ($path !== '/') {
    http_response_code(404);
    echo '<!doctype html><html lang="en"><title>Not found</title><h1>Not found</h1></html>';
    return;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP starter</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 12vh auto; padding: 1.5rem; line-height: 1.6; color: #202b3a; background: #f7f9fc; }
        main { background: white; padding: 2rem; border-radius: 1rem; }
        a { color: #4056b5; }
    </style>
</head>
<body>
    <main>
        <h1>Your PHP app is running.</h1>
        <p>A small starting point for your next project.</p>
        <p><a href="/health">Check application health</a></p>
    </main>
</body>
</html>
