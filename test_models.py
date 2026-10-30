from datetime import datetime, timezone

import pytest

from shieldprobe import Finding, ScanResult, Severity


def _finding(severity: Severity, check_id: str = "X") -> Finding:
    return Finding(check_id, "title", severity, "desc", "fix")


def _result(*severities: Severity) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult("https://x.test/", now, now, [_finding(s) for s in severities])


def test_severity_ordering_and_parse():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.parse(" High ") is Severity.HIGH


def test_severity_parse_rejects_unknown():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


def test_score_and_grade():
    assert _result().score == 100
    assert _result().grade == "A"
    assert _result(Severity.HIGH).score == 85
    assert _result(Severity.HIGH).grade == "B"
    assert _result(Severity.INFO, Severity.INFO).score == 100


def test_score_never_negative():
    result = _result(*[Severity.CRITICAL] * 10)
    assert result.score == 0
    assert result.grade == "F"


def test_counts_and_max_severity():
    result = _result(Severity.LOW, Severity.LOW, Severity.HIGH)
    assert result.counts() == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}
    assert result.max_severity() is Severity.HIGH
    assert _result().max_severity() is None


def test_to_dict_is_json_friendly():
    data = _result(Severity.MEDIUM).to_dict()
    assert data["findings"][0]["severity"] == "medium"
    assert data["summary"]["medium"] == 1
