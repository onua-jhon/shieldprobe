"""Report renderers: JSON, plain text (terminal) and self-contained HTML."""

from __future__ import annotations

import json
import re
import textwrap
from html import escape

from . import __version__
from .models import Finding, ScanResult, Severity

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

_ANSI = {
    Severity.CRITICAL: "\x1b[1;97;41m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_RESET = "\x1b[0m"


def sanitize(text: str) -> str:
    """Neutralise terminal control characters (target-controlled data may contain them)."""
    return _CONTROL_CHARS.sub("?", text)


# --- JSON ---------------------------------------------------------------------------------


def render_json(result: ScanResult) -> str:
    payload = {"tool": {"name": "shieldprobe", "version": __version__}, **result.to_dict()}
    return json.dumps(payload, indent=2, ensure_ascii=False)


# --- Text ---------------------------------------------------------------------------------


def render_text(result: ScanResult, *, color: bool = False) -> str:
    def paint(severity: Severity, text: str) -> str:
        return f"{_ANSI[severity]}{text}{_RESET}" if color else text

    def field(label: str, value: str) -> str:
        indent = " " * 4
        return textwrap.fill(
            sanitize(value),
            width=96,
            initial_indent=f"{indent}{label:<10}",
            subsequent_indent=indent + " " * 10,
            break_long_words=False,
            break_on_hyphens=False,
        )

    counts = ", ".join(f"{n} {name}" for name, n in result.counts().items() if n)
    lines = [
        f"ShieldProbe {__version__} report",
        f"Target   : {sanitize(result.target)}",
        f"Scanned  : {result.started_at:%Y-%m-%d %H:%M:%S} UTC "
        f"({(result.finished_at - result.started_at).total_seconds():.1f}s)",
        f"Checks   : {', '.join(result.checks_run)}",
        f"Score    : {result.score}/100 (grade {result.grade})",
        f"Findings : {counts or 'none'}",
        "",
    ]

    if not result.findings:
        lines.append("No findings. The selected checks did not detect any issues.")
    for finding in result.findings:
        tag = paint(finding.severity, f"[{finding.severity.name}]")
        lines.append(f"{tag} {sanitize(finding.title)} ({finding.check_id})")
        if finding.url:
            lines.append(field("URL", finding.url))
        if finding.evidence:
            lines.append(field("Evidence", finding.evidence))
        lines.append(field("Why", finding.description))
        lines.append(field("Fix", finding.remediation))
        lines.append("")

    if result.errors:
        lines.append("Errors (these checks did not complete):")
        lines.extend(f"  - {sanitize(e)}" for e in result.errors)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --- HTML ---------------------------------------------------------------------------------

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6672;--border:#dde1e6;
--critical:#7f1d1d;--high:#c0392b;--medium:#b9770e;--low:#1f7a8c;--info:#6b7785}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--text:#e6e9ed;
--muted:#97a3b0;--border:#2a323c;--critical:#e05a5a;--high:#ef6b5b;--medium:#e0a33a;
--low:#4fb3c6;--info:#8995a3}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}
h1{margin:0 0 4px;font-size:1.6rem} .sub{color:var(--muted);margin:0 0 24px;word-break:break-all}
.top{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.score{background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:16px 24px;text-align:center;min-width:140px}
.score .big{font-size:2.4rem;font-weight:700;line-height:1} .score small{color:var(--muted)}
.counts{display:flex;gap:8px;flex-wrap:wrap;flex:1;align-items:stretch}
.count{flex:1;min-width:84px;background:var(--card);border:1px solid var(--border);
border-radius:12px;padding:12px;text-align:center;border-top:4px solid var(--info)}
.count b{display:block;font-size:1.5rem}
.count.critical{border-top-color:var(--critical)} .count.high{border-top-color:var(--high)}
.count.medium{border-top-color:var(--medium)} .count.low{border-top-color:var(--low)}
.finding{background:var(--card);border:1px solid var(--border);border-left-width:5px;
border-radius:10px;padding:16px 18px;margin:0 0 14px}
.finding.critical{border-left-color:var(--critical)} .finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)} .finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.finding h3{margin:0 0 6px;font-size:1.05rem}
.badge{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.04em;
text-transform:uppercase;color:#fff;border-radius:6px;padding:2px 8px;margin-right:8px;
vertical-align:middle;background:var(--info)}
.badge.critical{background:var(--critical)} .badge.high{background:var(--high)}
.badge.medium{background:var(--medium)} .badge.low{background:var(--low)}
.cid{color:var(--muted);font-size:.8rem;font-family:ui-monospace,Menlo,Consolas,monospace}
dl{margin:10px 0 0;display:grid;grid-template-columns:90px 1fr;gap:6px 12px}
dt{color:var(--muted)} dd{margin:0;overflow-wrap:anywhere}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem;
background:var(--bg);padding:1px 5px;border-radius:4px}
ul.refs{margin:0;padding-left:18px} a{color:var(--low)}
.errors{background:var(--card);border:1px solid var(--medium);border-radius:10px;padding:12px 18px}
footer{color:var(--muted);font-size:.85rem;margin-top:32px}
@media (max-width:560px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
"""


def _finding_html(finding: Finding) -> str:
    sev = finding.severity.name.lower()
    rows = []
    if finding.url:
        rows.append(f"<dt>URL</dt><dd><code>{escape(finding.url)}</code></dd>")
    if finding.evidence:
        rows.append(f"<dt>Evidence</dt><dd><code>{escape(finding.evidence)}</code></dd>")
    rows.append(f"<dt>Why it matters</dt><dd>{escape(finding.description)}</dd>")
    rows.append(f"<dt>Fix</dt><dd>{escape(finding.remediation)}</dd>")
    if finding.references:
        links = "".join(
            f'<li><a href="{escape(u, quote=True)}" rel="noopener noreferrer">{escape(u)}</a></li>'
            for u in finding.references
        )
        rows.append(f'<dt>References</dt><dd><ul class="refs">{links}</ul></dd>')
    return (
        f'<article class="finding {sev}">'
        f'<h3><span class="badge {sev}">{sev}</span>{escape(finding.title)} '
        f'<span class="cid">{escape(finding.check_id)}</span></h3>'
        f"<dl>{''.join(rows)}</dl></article>"
    )


def render_html(result: ScanResult) -> str:
    counts = "".join(
        f'<div class="count {name}"><b>{n}</b>{name.title()}</div>'
        for name, n in result.counts().items()
    )
    findings = "".join(_finding_html(f) for f in result.findings) or (
        "<p>No findings. The selected checks did not detect any issues.</p>"
    )
    errors = ""
    if result.errors:
        items = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
        errors = (
            '<section class="errors"><strong>Checks that did not complete</strong>'
            f"<ul>{items}</ul></section>"
        )
    duration = (result.finished_at - result.started_at).total_seconds()
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ShieldProbe report - {escape(result.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>ShieldProbe report</h1>
<p class="sub">{escape(result.target)}</p>
<div class="top">
<div class="score">
<div class="big">{result.score}</div>
<small>/ 100 &middot; grade {result.grade}</small>
</div>
<div class="counts">{counts}</div>
</div>
{errors}
<h2>Findings ({len(result.findings)})</h2>
{findings}
<footer>Generated by ShieldProbe {escape(__version__)} on {result.started_at:%Y-%m-%d %H:%M} UTC
in {duration:.1f}s &middot; checks: {escape(", ".join(result.checks_run))}.
Automated results can include false positives; verify findings before acting.</footer>
</main>
</body>
</html>
"""


RENDERERS = {"json": render_json, "html": render_html}
