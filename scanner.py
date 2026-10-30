"""Scan orchestration: fetch the base page, enforce scope, run checks concurrently."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import datetime, timezone

import httpx

from . import __version__
from .checks import REGISTRY, CheckFn
from .context import ScanContext
from .models import Finding, ScanResult

USER_AGENT = f"ShieldProbe/{__version__} (authorized security assessment)"


class ScanError(Exception):
    """Base class for errors that stop a scan before any check runs."""


class TargetUnreachableError(ScanError):
    """The base page could not be fetched."""


class ScopeError(ScanError):
    """The target redirected somewhere outside the authorized scope."""


def normalize_target(raw: str) -> str:
    """Turn user input into an absolute http(s) URL, defaulting to https."""
    raw = raw.strip()
    if not raw:
        raise ValueError("target must not be empty")
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        url = httpx.URL(raw)
    except httpx.InvalidURL as exc:
        raise ValueError(f"invalid target {raw!r}: {exc}") from exc
    if url.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme {url.scheme!r}; use http or https")
    if not url.host:
        raise ValueError(f"target {raw!r} has no hostname")
    return str(url)


def _strip_www(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def same_site(a: str, b: str) -> bool:
    """True if two hostnames are the same, differ only by ``www.``, or are parent/child."""
    a, b = _strip_www(a), _strip_www(b)
    return a == b or a.endswith(f".{b}") or b.endswith(f".{a}")


def resolve_checks(selected: Iterable[str] | None) -> list[str]:
    """Validate requested check names; ``None`` means all checks."""
    if selected is None:
        return list(REGISTRY)
    names = list(dict.fromkeys(selected))
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        raise ValueError(
            f"unknown check(s): {', '.join(unknown)}. Available: {', '.join(REGISTRY)}"
        )
    return names


async def _run_check(
    name: str, check: CheckFn, ctx: ScanContext
) -> tuple[list[Finding], str | None]:
    try:
        return await check(ctx), None
    except Exception as exc:  # a failing check must never abort the whole scan
        return [], f"{name}: {type(exc).__name__}: {exc}"


async def scan(
    target: str,
    *,
    checks: Iterable[str] | None = None,
    timeout: float = 10.0,
    concurrency: int = 5,
    delay: float = 0.0,
    verify_tls: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanResult:
    """Run the selected checks against ``target`` and return the results.

    ``transport`` lets tests inject an ``httpx.MockTransport`` so no network is used.
    """
    url = normalize_target(target)
    names = resolve_checks(checks)
    started = datetime.now(timezone.utc)

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        verify=verify_tls,
        max_redirects=5,
        transport=transport,
    ) as client:
        try:
            response = await client.get(url, follow_redirects=True)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise TargetUnreachableError(f"could not reach {url}: {exc}") from exc

        original_host = httpx.URL(url).host
        if not same_site(original_host, response.url.host):
            raise ScopeError(
                f"{url} redirected to {response.url.host}, which is outside the scanned scope; "
                "re-run against that host explicitly if you are authorized to test it"
            )

        origin = f"{response.url.scheme}://{response.url.netloc.decode('ascii')}/"
        ctx = ScanContext(
            base_url=httpx.URL(origin),
            client=client,
            response=response,
            semaphore=asyncio.Semaphore(max(1, concurrency)),
            delay=max(0.0, delay),
            timeout=timeout,
            verify_tls=verify_tls,
        )
        outcomes = await asyncio.gather(*(_run_check(n, REGISTRY[n], ctx) for n in names))

    findings: list[Finding] = []
    errors: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for found, error in outcomes:
        if error:
            errors.append(error)
        for finding in found:
            key = (finding.check_id, finding.url, finding.title)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    findings.sort(key=lambda f: (-f.severity, f.check_id, f.url))

    return ScanResult(
        target=str(response.url),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        findings=findings,
        errors=errors,
        checks_run=names,
    )
