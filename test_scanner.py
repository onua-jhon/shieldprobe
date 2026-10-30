import asyncio

import httpx
import pytest

from helpers import handler_site, make_site, run_scan
from shieldprobe import ScopeError, TargetUnreachableError, scan
from shieldprobe.scanner import normalize_target, resolve_checks, same_site


def test_normalize_target_defaults_to_https():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target(" http://example.com/app ") == "http://example.com/app"


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "https://"])
def test_normalize_target_rejects_bad_input(bad: str):
    with pytest.raises(ValueError):
        normalize_target(bad)


def test_same_site_rules():
    assert same_site("example.com", "www.example.com")
    assert same_site("api.example.com", "example.com")
    assert not same_site("example.com", "evil-example.com")
    assert not same_site("example.com", "example.org")
    assert not same_site("a.example.com", "b.example.com")


def test_resolve_checks():
    assert resolve_checks(["headers", "headers", "cors"]) == ["headers", "cors"]
    assert "tls" in resolve_checks(None)
    with pytest.raises(ValueError, match="unknown check"):
        resolve_checks(["headers", "nope"])


def test_redirect_to_unrelated_domain_aborts_scan():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "site.test":
            return httpx.Response(302, headers={"location": "https://third-party.test/"})
        return httpx.Response(200, content="should never be scanned")

    with pytest.raises(ScopeError, match="outside the scanned scope"):
        run_scan(handler_site(handler), ["headers"])


def test_redirect_within_site_is_followed_and_scoped_to_final_host():
    seen_hosts: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.add(request.url.host)
        if request.url.host == "site.test":
            return httpx.Response(301, headers={"location": "https://www.site.test/"})
        return httpx.Response(200, headers={"content-type": "text/html"}, content="hi")

    result = run_scan(handler_site(handler), ["headers", "exposed-files"])
    assert result.target == "https://www.site.test/"
    assert seen_hosts == {"site.test", "www.site.test"}


def test_unreachable_target_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with pytest.raises(TargetUnreachableError):
        run_scan(handler_site(handler), ["headers"])


def test_failing_check_is_reported_not_fatal(monkeypatch):
    from shieldprobe import scanner

    async def broken(ctx):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(scanner.REGISTRY, "headers", broken)
    site = make_site({"/": (200, {"content-type": "text/html"}, "hi")})
    result = run_scan(site, ["headers", "cookies"])
    assert result.errors == ["headers: RuntimeError: kaboom"]
    assert result.checks_run == ["headers", "cookies"]


def test_findings_sorted_by_severity_and_deduplicated():
    site = make_site(
        {
            "/": (200, {"content-type": "text/html"}, "hi"),
            "/.git/HEAD": (200, {}, "ref: refs/heads/main"),
        }
    )
    result = run_scan(site, ["headers", "exposed-files"])
    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, reverse=True)
    keys = [(f.check_id, f.url, f.title) for f in result.findings]
    assert len(keys) == len(set(keys))


def test_concurrency_limit_is_respected():
    active = 0
    peak = 0

    async def run() -> None:
        nonlocal active, peak

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return httpx.Response(404, content="nf")

        class Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return await handler(request)

        await scan(
            "https://site.test", checks=["exposed-files"], concurrency=3, transport=Transport()
        )

    asyncio.run(run())
    assert 1 <= peak <= 3 + 1  # base-page fetch happens before the checks start
