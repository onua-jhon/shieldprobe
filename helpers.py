"""Test helpers: a tiny fake website built on httpx.MockTransport (no real network)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx

from shieldprobe import ScanResult, scan

Headers = dict[str, str] | list[tuple[str, str]]
Route = tuple[int, Headers, str | bytes]

HARDENED_HEADERS: dict[str, str] = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def make_site(
    routes: dict[str, Route] | None = None,
    *,
    default: Route = (404, {}, "not found"),
) -> httpx.MockTransport:
    routes = routes or {}

    def handler(request: httpx.Request) -> httpx.Response:
        status, headers, body = routes.get(request.url.path, default)
        return httpx.Response(status, headers=headers, content=body)

    return httpx.MockTransport(handler)


def run_scan(
    transport: httpx.MockTransport,
    checks: list[str],
    target: str = "https://site.test",
    **kwargs: Any,
) -> ScanResult:
    return asyncio.run(scan(target, checks=checks, transport=transport, **kwargs))


def ids(result: ScanResult) -> set[str]:
    return {f.check_id for f in result.findings}


def handler_site(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)
