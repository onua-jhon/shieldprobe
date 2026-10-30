from helpers import ids, make_site, run_scan


def test_version_banners_flagged():
    headers = {
        "content-type": "text/html",
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/7.4.3",
    }
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["disclosure"])
    assert {"INFO-SERVER-VERSION", "INFO-X-POWERED-BY"} <= ids(result)


def test_generic_server_header_is_fine():
    headers = {"content-type": "text/html", "server": "nginx"}
    result = run_scan(make_site({"/": (200, headers, "hi")}), ["disclosure"])
    assert "INFO-SERVER-VERSION" not in ids(result)


def test_generator_meta_with_version():
    body = '<html><head><meta name="generator" content="WordPress 6.1.1"></head></html>'
    result = run_scan(make_site({"/": (200, {"content-type": "text/html"}, body)}), ["disclosure"])
    assert "INFO-GENERATOR-VERSION" in ids(result)


def test_generator_meta_attribute_order_reversed():
    body = '<meta content="Drupal 9.4" name="generator">'
    result = run_scan(make_site({"/": (200, {"content-type": "text/html"}, body)}), ["disclosure"])
    assert "INFO-GENERATOR-VERSION" in ids(result)


def test_stack_trace_on_404_detected_without_storing_body():
    trace = (
        "Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 3, in <module>\n'
        "SECRET-DETAIL"
    )
    site = make_site({"/": (200, {}, "hi")}, default=(500, {}, trace))
    result = run_scan(site, ["disclosure"])
    finding = next(f for f in result.findings if f.check_id == "INFO-VERBOSE-ERRORS")
    assert "Python traceback" in finding.evidence
    assert "SECRET-DETAIL" not in finding.evidence


def test_php_html_error_format_detected():
    page = (
        "<br />\n<b>Warning</b>:  include(x.php): failed to open stream in "
        "<b>/var/www/html/index.php</b> on line <b>7</b><br />"
    )
    site = make_site({"/": (200, {}, "hi")}, default=(200, {}, page))
    finding = next(f for f in run_scan(site, ["disclosure"]).findings if "VERBOSE" in f.check_id)
    assert "PHP error message" in finding.evidence
    assert "/var/www" not in finding.evidence


def test_clean_404_page_is_fine():
    site = make_site({"/": (200, {}, "hi")}, default=(404, {}, "Not found"))
    assert "INFO-VERBOSE-ERRORS" not in ids(run_scan(site, ["disclosure"]))
