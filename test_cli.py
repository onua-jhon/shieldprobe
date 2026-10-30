import json
from datetime import datetime, timezone

import pytest

from shieldprobe import Finding, ScanResult, Severity, TargetUnreachableError, cli


def _fake_scan(*severities: Severity):
    async def fake(target, **kwargs):
        now = datetime.now(timezone.utc)
        findings = [
            Finding(f"F-{i}", f"Finding {i}", s, "d", "r") for i, s in enumerate(severities)
        ]
        fake.kwargs = kwargs
        return ScanResult(target, now, now, findings, [], kwargs["checks"])

    return fake


def test_list_checks(capsys):
    assert cli.main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "exposed-files" in out
    assert "headers" in out


def test_refuses_without_authorization_in_non_interactive_mode(capsys, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["https://site.test"]) == 2
    assert "authorization not confirmed" in capsys.readouterr().err


def test_interactive_confirmation(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "scan", _fake_scan())
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert cli.main(["https://site.test"]) == 2
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert cli.main(["https://site.test"]) == 0


def test_unknown_check_is_a_usage_error(capsys):
    assert cli.main(["https://site.test", "--checks", "nope", "--yes-i-am-authorized"]) == 2
    assert "unknown check" in capsys.readouterr().err


def test_checks_and_skip_are_combined(monkeypatch):
    fake = _fake_scan()
    monkeypatch.setattr(cli, "scan", fake)
    args = ["https://site.test", "--yes-i-am-authorized", "--skip", "tls,cors"]
    assert cli.main(args) == 0
    assert "tls" not in fake.kwargs["checks"]
    assert "cors" not in fake.kwargs["checks"]
    assert "headers" in fake.kwargs["checks"]


def test_fail_on_threshold(monkeypatch):
    monkeypatch.setattr(cli, "scan", _fake_scan(Severity.MEDIUM))
    base = ["https://site.test", "--yes-i-am-authorized"]
    assert cli.main([*base, "--fail-on", "high"]) == 0
    assert cli.main([*base, "--fail-on", "medium"]) == 1
    assert cli.main([*base]) == 0


def test_min_severity_filters_output_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", _fake_scan(Severity.LOW, Severity.HIGH))
    code = cli.main(
        [
            "https://site.test",
            "--yes-i-am-authorized",
            "-f",
            "json",
            "--min-severity",
            "high",
            "--fail-on",
            "low",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert [f["severity"] for f in data["findings"]] == ["high"]
    assert code == 1


def test_writes_report_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "scan", _fake_scan(Severity.LOW))
    out = tmp_path / "report.html"
    assert (
        cli.main(["https://site.test", "--yes-i-am-authorized", "-f", "html", "-o", str(out)]) == 0
    )
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_scan_errors_exit_2(monkeypatch, capsys):
    async def boom(target, **kwargs):
        raise TargetUnreachableError("could not reach https://site.test")

    monkeypatch.setattr(cli, "scan", boom)
    assert cli.main(["https://site.test", "--yes-i-am-authorized"]) == 2
    assert "could not reach" in capsys.readouterr().err


def test_missing_target_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "shieldprobe 0.1.0" in capsys.readouterr().out
