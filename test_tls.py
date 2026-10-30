import asyncio

import httpx
import pytest

from shieldprobe.checks import tls
from shieldprobe.context import ScanContext
from shieldprobe.models import Severity


def _context(handler, base: str = "https://site.test/") -> tuple[ScanContext, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = httpx.Response(200, request=httpx.Request("GET", base))
    ctx = ScanContext(
        base_url=httpx.URL(base),
        client=client,
        response=response,
        semaphore=asyncio.Semaphore(2),
    )
    return ctx, client


def _run(handler, base: str = "https://site.test/"):
    async def go():
        ctx, client = _context(handler, base)
        try:
            return await tls._check_http_redirect(ctx)
        finally:
            await client.aclose()

    return asyncio.run(go())


def test_http_served_without_redirect_flagged():
    findings = _run(lambda request: httpx.Response(200, content="hello"))
    assert [f.check_id for f in findings] == ["TLS-NO-REDIRECT"]
    assert findings[0].severity is Severity.MEDIUM


def test_proper_redirect_is_clean():
    handler = lambda request: httpx.Response(301, headers={"location": "https://site.test/"})  # noqa: E731
    assert _run(handler) == []


def test_redirect_to_http_is_not_good_enough():
    handler = lambda request: httpx.Response(301, headers={"location": "http://other.test/"})  # noqa: E731
    assert _run(handler) == []  # not a plain 200, so not reported as unredirected


def test_closed_port_80_is_fine():
    def handler(request):
        raise httpx.ConnectError("refused")

    assert _run(handler) == []


def test_non_standard_port_skipped():
    assert _run(lambda r: httpx.Response(200), base="https://site.test:8443/") == []


def test_plain_http_target_is_high_severity():
    async def go():
        ctx, client = _context(lambda r: httpx.Response(200), base="http://site.test/")
        try:
            return await tls.run(ctx)
        finally:
            await client.aclose()

    findings = asyncio.run(go())
    assert [(f.check_id, f.severity) for f in findings] == [("TLS-NO-HTTPS", Severity.HIGH)]


@pytest.mark.parametrize(
    ("not_after", "expected"),
    [("Jan  1 00:00:00 2030 GMT", 365)],
)
def test_days_until(not_after: str, expected: int):
    import ssl

    start = ssl.cert_time_to_seconds("Jan  1 00:00:00 2029 GMT")
    assert tls.days_until(not_after, now=start) == pytest.approx(expected, abs=1)
