"""Shared state handed to every check."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class ScanContext:
    """Per-scan state: the HTTP client, the base page, and politeness controls.

    All requests made by checks go through :meth:`request` / :meth:`peek` so that the
    concurrency limit and inter-request delay are always honoured.
    """

    base_url: httpx.URL  # origin (scheme://host[:port]/) the scan is scoped to
    client: httpx.AsyncClient
    response: httpx.Response  # the already-fetched base page
    semaphore: asyncio.Semaphore
    delay: float = 0.0
    timeout: float = 10.0
    verify_tls: bool = True

    @property
    def scheme(self) -> str:
        return self.base_url.scheme

    @property
    def host(self) -> str:
        return self.base_url.host

    @property
    def port(self) -> int:
        if self.base_url.port is not None:
            return self.base_url.port
        return 443 if self.scheme == "https" else 80

    def url_for(self, path: str) -> str:
        """Absolute URL for ``path`` on the scan origin."""
        return str(self.base_url.join(path))

    async def _pause(self) -> None:
        if self.delay > 0:
            await asyncio.sleep(self.delay)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            await self._pause()
            return await self.client.request(method, url, **kwargs)

    async def peek(self, path: str, limit: int = 4096) -> tuple[httpx.Response, bytes]:
        """GET ``path`` but read at most ``limit`` bytes of the body.

        Keeps probes cheap even if a path unexpectedly serves a huge file.
        """
        url = self.url_for(path)
        async with self.semaphore:
            await self._pause()
            async with self.client.stream("GET", url, follow_redirects=False) as response:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= limit:
                        break
                return response, b"".join(chunks)[:limit]
