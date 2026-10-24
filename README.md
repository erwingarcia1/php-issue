# PHP starter

A dependency-free PHP 8.4 application with a landing page, JSON health endpoint,
and an HTTP smoke test. No database, Composer packages, or credentials are needed.

## Run with PHP

From the repository root:

```sh
php -S 127.0.0.1:8000 -t public public/index.php
```

In another terminal:

```sh
php tests/smoke.php
```

## Run with Docker

If PHP is unavailable locally:

```sh
docker run --rm --name php-issue-dev -p 127.0.0.1:8000:8000 \
  -v "$PWD:/app:ro" -w /app php:8.4-cli \
  php -S 0.0.0.0:8000 -t public public/index.php
```

In another terminal, run all three smoke checks:

```sh
docker exec php-issue-dev php tests/smoke.php
```

The development server is intended for local development. Stop it with Ctrl-C.

## Routes

| Route | Response |
| --- | --- |
| `/` | HTML landing page |
| `/health` | JSON `{"status":"ok"}` |
| Any other path | HTTP 404 |
