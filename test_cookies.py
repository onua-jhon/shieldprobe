from helpers import ids, make_site, run_scan
from shieldprobe import Severity
from shieldprobe.checks.cookies import parse_set_cookie


def _site(*cookies: str):
    headers = [("content-type", "text/html"), *[("set-cookie", c) for c in cookies]]
    return make_site({"/": (200, headers, "hi")})


def test_insecure_session_cookie_flagged_medium():
    result = run_scan(_site("PHPSESSID=abc; path=/"), ["cookies"])
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["CKIE-SECURE-MISSING"].severity is Severity.MEDIUM
    assert by_id["CKIE-HTTPONLY-MISSING"].severity is Severity.MEDIUM
    assert "CKIE-SAMESITE-MISSING" in by_id


def test_non_session_cookie_is_low_severity():
    result = run_scan(_site("theme=dark; path=/"), ["cookies"])
    assert {f.severity for f in result.findings} == {Severity.LOW}


def test_secure_cookie_is_clean():
    result = run_scan(_site("sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"), ["cookies"])
    assert result.findings == []


def test_evidence_lists_names_but_never_values():
    result = run_scan(_site("sid=SUPER-SECRET-VALUE; path=/"), ["cookies"])
    assert result.findings
    for finding in result.findings:
        assert "SUPER-SECRET-VALUE" not in finding.evidence
        assert "sid" in finding.evidence


def test_samesite_none_requires_secure():
    result = run_scan(_site("x=1; SameSite=None; HttpOnly"), ["cookies"])
    assert "CKIE-SAMESITE-NONE-INSECURE" in ids(result)


def test_csrf_cookie_not_required_to_be_httponly():
    result = run_scan(_site("csrftoken=abc; Secure; SameSite=Lax"), ["cookies"])
    assert "CKIE-HTTPONLY-MISSING" not in ids(result)


def test_no_cookies_no_findings():
    assert run_scan(make_site({"/": (200, {}, "hi")}), ["cookies"]).findings == []


def test_secure_flag_not_demanded_on_plain_http():
    result = run_scan(
        _site("sid=abc; HttpOnly; SameSite=Lax"), ["cookies"], target="http://site.test"
    )
    assert "CKIE-SECURE-MISSING" not in ids(result)


def test_parse_set_cookie():
    name, attrs = parse_set_cookie(
        "id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; SameSite=Lax"
    )
    assert name == "id"
    assert attrs["secure"] == ""
    assert attrs["samesite"] == "Lax"
    assert "expires" in attrs
