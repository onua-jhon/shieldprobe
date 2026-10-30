"""Scan a *simulated* vulnerable website (no real network traffic) and write sample reports.

Run from the repository root:

    python examples/demo.py

This is how ``examples/sample-report.html`` and ``examples/sample-report.json`` are produced,
and it is a safe way to see ShieldProbe's output without touching any real system.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from shieldprobe import scan
from shieldprobe.report import render_html, render_json, render_text

HERE = Path(__file__).parent
TARGET = "https://vulnerable-demo.test"

HOME_PAGE = """<!doctype html>
<html><head><title>Demo Shop</title>
<meta name="generator" content="WordPress 5.8.1"></head>
<body><h1>Welcome</h1></body></html>"""

# Mirrors PHP's real html_errors output, where labels, paths and line numbers are in <b> tags.
PHP_ERROR_PAGE = (
    "<br />\n<b>Fatal error</b>:  Uncaught Exception: not found in "
    "<b>/var/www/html/index.php</b> on line <b>42</b><br />"
)

STATIC_ROUTES: dict[str, tuple[int, str]] = {
    "/.git/HEAD": (200, "ref: refs/heads/main\n"),
    "/.env": (200, "APP_ENV=production\nDB_PASSWORD=not-a-real-secret\n"),
    "/phpinfo.php": (200, "<html><title>phpinfo()</title>PHP Version 7.2.24</html>"),
    "/backup.sql": (200, "-- demo dump\nCREATE TABLE users (id INT, email TEXT);\n"),
}


def handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/":
        headers = [
            ("content-type", "text/html"),
            ("server", "Apache/2.4.29 (Ubuntu)"),
            ("x-powered-by", "PHP/7.2.24"),
            ("set-cookie", "PHPSESSID=demo123; path=/"),
            ("set-cookie", "theme=dark; path=/"),
        ]
        origin = request.headers.get("origin")
        if origin:
            headers += [
                ("access-control-allow-origin", origin),
                ("access-control-allow-credentials", "true"),
            ]
        return httpx.Response(200, headers=headers, content=HOME_PAGE)
    if path in STATIC_ROUTES:
        status, body = STATIC_ROUTES[path]
        return httpx.Response(status, content=body)
    return httpx.Response(404, content=PHP_ERROR_PAGE)


async def main() -> None:
    # "tls" is skipped: it opens real sockets, and this demo site does not exist.
    checks = ["headers", "cookies", "cors", "disclosure", "exposed-files"]
    result = await scan(TARGET, checks=checks, transport=httpx.MockTransport(handler))

    (HERE / "sample-report.html").write_text(render_html(result), encoding="utf-8")
    (HERE / "sample-report.json").write_text(render_json(result) + "\n", encoding="utf-8")
    print(render_text(result))


if __name__ == "__main__":
    asyncio.run(main())
