from helpers import HARDENED_HEADERS, ids, make_site, run_scan
from shieldprobe import Severity
from shieldprobe.checks.headers import parse_csp


def test_bare_site_reports_missing_headers():
    result = run_scan(make_site({"/": (200, {"content-type": "text/html"}, "hi")}), ["headers"])
    assert ids(result) >= {
        "HDR-HSTS-MISSING",
        "HDR-CSP-MISSING",
        "HDR-FRAME-MISSING",
        "HDR-XCTO-MISSING",
        "HDR-REFERRER-MISSING",
        "HDR-PERMISSIONS-MISSING",
    }


def test_hardened_site_is_clean():
    result = run_scan(make_site({"/": (200, HARDENED_HEADERS, "hi")}), ["headers"])
    assert result.findings == []
    assert result.score == 100


def test_hsts_not_required_over_plain_http():
    result = run_scan(make_site({"/": (200, {}, "hi")}), ["headers"], target="http://site.test")
    assert "HDR-HSTS-MISSING" not in ids(result)


def test_weak_hsts_max_age():
    headers = {**HARDENED_HEADERS, "strict-transport-security": "max-age=300"}
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["headers"])
    assert ids(result) == {"HDR-HSTS-WEAK"}


def test_csp_unsafe_inline_flagged_but_nonce_allowed():
    unsafe = {
        **HARDENED_HEADERS,
        "content-security-policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    }
    result = run_scan(make_site({"/": (200, unsafe, "hi")}), ["headers"])
    assert "HDR-CSP-UNSAFE-INLINE" in ids(result)

    nonce = {
        **HARDENED_HEADERS,
        "content-security-policy": (
            "script-src 'unsafe-inline' 'nonce-abc123'; frame-ancestors 'none'"
        ),
    }
    result = run_scan(make_site({"/": (200, nonce, "hi")}), ["headers"])
    assert "HDR-CSP-UNSAFE-INLINE" not in ids(result)


def test_csp_wildcard_and_eval():
    policy = "script-src * 'unsafe-eval'; frame-ancestors 'self'"
    headers = {**HARDENED_HEADERS, "content-security-policy": policy}
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["headers"])
    assert {"HDR-CSP-BROAD-SOURCE", "HDR-CSP-UNSAFE-EVAL"} <= ids(result)


def test_frame_ancestors_satisfies_clickjacking_check():
    headers = {k: v for k, v in HARDENED_HEADERS.items() if k != "x-frame-options"}
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["headers"])
    assert "HDR-FRAME-MISSING" not in ids(result)


def test_x_frame_options_alone_satisfies_clickjacking_check():
    headers = {**HARDENED_HEADERS, "content-security-policy": "default-src 'self'"}
    headers["x-frame-options"] = "DENY"
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["headers"])
    assert "HDR-FRAME-MISSING" not in ids(result)


def test_severities_are_sensible():
    result = run_scan(make_site({"/": (200, {}, "hi")}), ["headers"])
    by_id = {f.check_id: f.severity for f in result.findings}
    assert by_id["HDR-CSP-MISSING"] is Severity.MEDIUM
    assert by_id["HDR-PERMISSIONS-MISSING"] is Severity.INFO


def test_parse_csp():
    parsed = parse_csp("default-src 'self'; img-src * data:; ; upgrade-insecure-requests")
    assert parsed["default-src"] == ["'self'"]
    assert parsed["img-src"] == ["*", "data:"]
    assert parsed["upgrade-insecure-requests"] == []
