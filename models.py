"""Core data models shared by the scanner, checks and reporters."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity, ordered so that comparisons and sorting work naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {valid})") from None


# Points deducted from a 100-point score for each finding of a given severity.
SCORE_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class Finding:
    """A single security observation."""

    check_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    url: str = ""
    evidence: str = ""
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "description": self.description,
            "remediation": self.remediation,
            "url": self.url,
            "evidence": self.evidence,
            "references": list(self.references),
        }


@dataclass
class ScanResult:
    """Everything produced by one scan."""

    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {s.name.lower(): 0 for s in sorted(Severity, reverse=True)}
        for finding in self.findings:
            counts[finding.severity.name.lower()] += 1
        return counts

    @property
    def score(self) -> int:
        penalty = sum(SCORE_PENALTY[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if score >= threshold:
                return letter
        return "F"

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "checks_run": list(self.checks_run),
            "score": self.score,
            "grade": self.grade,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }
