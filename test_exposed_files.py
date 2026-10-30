from helpers import ids, make_site, run_scan
from shieldprobe import Severity


def _site(extra, **kwargs):
    return make_site(
        {"/": (200, {"content-type": "text/html"}, "<html>home</html>"), **extra}, **kwargs
    )


def test_git_head_detected():
    result = run_scan(_site({"/.git/HEAD": (200, {}, "ref: refs/heads/main\n")}), ["exposed-files"])
    finding = next(f for f in result.findings if f.check_id == "EXP-GIT")
    assert finding.severity is Severity.HIGH
    assert finding.url == "https://site.test/.git/HEAD"


def test_env_file_detected_and_secret_never_leaked():
    body = "APP_ENV=production\nDB_PASSWORD=hunter2-very-secret\n"
    result = run_scan(_site({"/.env": (200, {}, body)}), ["exposed-files"])
    finding = next(f for f in result.findings if f.check_id == "EXP-ENV")
    assert finding.severity is Severity.CRITICAL
    assert "hunter2" not in finding.evidence
    assert "hunter2" not in str(finding.to_dict())


def test_soft_404_site_produces_no_false_positives():
    page = (
        "<html><body>Sorry, page not found. "
        "Welcome to phpMyAdmin PHP Version CREATE TABLE</body></html>"
    )
    site = make_site({"/": (200, {}, page)}, default=(200, {}, page))
    result = run_scan(site, ["exposed-files"])
    assert [f.check_id for f in result.findings] == ["EXP-NO-SECURITY-TXT"]


def test_html_page_at_env_path_is_not_an_env_file():
    html = "<!doctype html><html><body>API_KEY=nope</body></html>"
    result = run_scan(_site({"/.env": (200, {}, html)}), ["exposed-files"])
    assert "EXP-ENV" not in ids(result)


def test_zip_archive_detected_by_magic_bytes():
    result = run_scan(
        _site({"/backup.zip": (200, {}, b"PK\x03\x04" + b"\x00" * 64)}), ["exposed-files"]
    )
    finding = next(f for f in result.findings if f.check_id == "EXP-ARCHIVE")
    assert finding.severity is Severity.HIGH


def test_non_matching_content_ignored():
    result = run_scan(_site({"/backup.zip": (200, {}, b"not a zip")}), ["exposed-files"])
    assert "EXP-ARCHIVE" not in ids(result)


def test_non_200_ignored():
    result = run_scan(_site({"/.git/HEAD": (403, {}, "ref: refs/heads/main")}), ["exposed-files"])
    assert "EXP-GIT" not in ids(result)


def test_sql_dump_and_phpinfo():
    routes = {
        "/dump.sql": (200, {}, "-- dump\nCREATE TABLE users (id int);"),
        "/phpinfo.php": (200, {}, "<title>phpinfo()</title>"),
    }
    assert {"EXP-SQL-DUMP", "EXP-PHPINFO"} <= ids(run_scan(_site(routes), ["exposed-files"]))


def test_security_txt_present_suppresses_info_finding():
    txt = "Contact: mailto:security@site.test\nExpires: 2027-01-01T00:00:00Z\n"
    result = run_scan(_site({"/.well-known/security.txt": (200, {}, txt)}), ["exposed-files"])
    assert "EXP-NO-SECURITY-TXT" not in ids(result)


def test_security_txt_missing_is_info_only():
    result = run_scan(_site({}), ["exposed-files"])
    assert [(f.check_id, f.severity) for f in result.findings] == [
        ("EXP-NO-SECURITY-TXT", Severity.INFO)
    ]
    assert result.score == 100


def test_large_files_are_read_only_partially():
    seen: list[int] = []

    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/backup.sql":
            payload = b"CREATE TABLE t (id int);\n" + b"x" * 5_000_000
            seen.append(len(payload))
            return httpx.Response(200, content=payload)
        return httpx.Response(404, content="nf")

    from helpers import handler_site

    result = run_scan(handler_site(handler), ["exposed-files"])
    finding = next(f for f in result.findings if f.check_id == "EXP-SQL-DUMP")
    assert seen  # served, but the scanner only keeps a small prefix
    assert "5000" not in finding.evidence
