import json
from datetime import datetime, timezone

from shieldprobe import Finding, ScanResult, Severity
from shieldprobe.report import render_html, render_json, render_text, sanitize


def _result(*findings: Finding, errors: list[str] | None = None) -> ScanResult:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    return ScanResult(
        "https://site.test/", now, now, list(findings), errors or [], ["headers", "cookies"]
    )


def _finding(**overrides) -> Finding:
    base = {
        "check_id": "T-1",
        "title": "Test finding",
        "severity": Severity.HIGH,
        "description": "Something is wrong.",
        "remediation": "Fix it.",
        "url": "https://site.test/x",
        "evidence": "header: value",
        "references": ("https://example.org/ref",),
    }
    return Finding(**{**base, **overrides})


def test_json_report_roundtrips():
    data = json.loads(render_json(_result(_finding())))
    assert data["tool"]["name"] == "shieldprobe"
    assert data["score"] == 85
    assert data["findings"][0]["check_id"] == "T-1"
    assert data["findings"][0]["severity"] == "high"
    assert data["summary"]["high"] == 1


def test_text_report_contents():
    text = render_text(_result(_finding()))
    assert "[HIGH] Test finding (T-1)" in text
    assert "Score    : 85/100 (grade B)" in text
    assert "Fix       Fix it." in text
    assert "\x1b[" not in text  # no color unless asked


def test_text_report_color_is_opt_in():
    assert "\x1b[" in render_text(_result(_finding()), color=True)


def test_text_report_empty_and_errors():
    text = render_text(_result(errors=["tls: OSError: nope"]))
    assert "No findings" in text
    assert "tls: OSError: nope" in text


def test_terminal_escape_sequences_are_neutralised():
    evil = _finding(evidence="Server: \x1b]0;pwned\x07\x1b[31mred")
    text = render_text(_result(evil))
    assert "\x1b" not in text
    assert "\x07" not in text
    assert sanitize("a\x00b\x9bc") == "a?b?c"


def test_html_report_escapes_target_controlled_data():
    evil = _finding(
        title="<script>alert(1)</script>",
        evidence='"><img src=x onerror=alert(1)>',
        url="https://site.test/<b>",
    )
    html = render_html(_result(evil))
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_html_report_has_strict_csp_and_no_external_resources():
    html = render_html(_result(_finding()))
    assert "default-src 'none'" in html
    assert "<script" not in html
    assert 'src="http' not in html
    assert "Test finding" in html
    assert 'rel="noopener noreferrer"' in html


def test_html_report_empty():
    assert "No findings" in render_html(_result())
