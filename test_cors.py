import httpx

from helpers import handler_site, ids, run_scan
from shieldprobe import Severity


def _site(*, reflect: bool = False, credentials: bool = False, wildcard: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": "text/html"}
        origin = request.headers.get("origin")
        if origin and reflect:
            headers["access-control-allow-origin"] = origin
        elif origin and wildcard:
            headers["access-control-allow-origin"] = "*"
        if origin and credentials:
            headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, headers=headers, content="hi")

    return handler_site(handler)


def test_reflected_origin_with_credentials_is_high():
    result = run_scan(_site(reflect=True, credentials=True), ["cors"])
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["CORS-REFLECT-ORIGIN"].severity is Severity.HIGH
    assert by_id["CORS-NULL-ORIGIN"].severity is Severity.HIGH


def test_reflected_origin_without_credentials_is_medium():
    result = run_scan(_site(reflect=True), ["cors"])
    assert {f.severity for f in result.findings} == {Severity.MEDIUM}


def test_wildcard_is_informational_and_reported_once():
    result = run_scan(_site(wildcard=True), ["cors"])
    assert [f.check_id for f in result.findings] == ["CORS-WILDCARD"]
    assert result.findings[0].severity is Severity.INFO


def test_no_cors_headers_no_findings():
    assert ids(run_scan(_site(), ["cors"])) == set()
