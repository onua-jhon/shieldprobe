# ShieldProbe

[![CI](https://github.com/YOUR-USERNAME/shieldprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/shieldprobe/actions/workflows/ci.yml)
[![CodeQL](https://github.com/YOUR-USERNAME/shieldprobe/actions/workflows/codeql.yml/badge.svg)](https://github.com/YOUR-USERNAME/shieldprobe/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A passive, non-exploitative web security scanner.** ShieldProbe checks a website for common
misconfigurations (missing security headers, weak cookies, CORS mistakes, exposed secrets,
TLS problems) and produces a scored report in text, JSON or self-contained HTML.

It is built for the first pass of an authorized assessment: fast, safe to run, and explicit
about *why* each finding matters and *how* to fix it.

> **Only scan systems you own or have written permission to test.** See
> [Responsible use](#responsible-use).

## Features

| Check | What it looks for |
|---|---|
| `headers` | HSTS (missing / weak max-age), CSP (missing, `unsafe-inline`, `unsafe-eval`, wildcards), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy |
| `cookies` | Missing `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` without `Secure`. Severity is raised for session-looking cookies |
| `cors` | Reflected `Origin`, trusted `null` origin, credentialed CORS, wildcard origins |
| `disclosure` | Version banners (`Server`, `X-Powered-By`, generator meta tag) and verbose error pages (stack traces, PHP/SQL errors) |
| `exposed-files` | `.git`, `.env`, SQL dumps, backup archives, `wp-config` backups, private keys, `.htpasswd`, `phpinfo`, Spring Actuator, Werkzeug console, phpMyAdmin, API docs, missing `security.txt` |
| `tls` | Certificate validity and expiry, deprecated TLS 1.0/1.1, HTTP not redirecting to HTTPS, plain-HTTP sites |

Design goals:

- **Low false positives.** Exposed-file probes must return content that *looks like the real
  file* (e.g. `ref: refs/heads/...` for `.git/HEAD`), and sites that answer `200` to every URL
  are detected and ignored.
- **Safe by construction.** Fixed, small request budget; no fuzzing, payloads, brute force or
  auth bypass; adjustable concurrency and delay; reads at most 4 KB of any probed file.
- **Secrets never leave the target.** If `.env` or a SQL dump is found, the report says it
  exists and what format it has. The contents are not stored.
- **Safe output.** HTML reports escape all target-controlled data and ship with a strict
  Content-Security-Policy. Text output strips terminal escape sequences.
- **Scope guard.** If the target redirects to an unrelated domain, the scan stops instead of
  following it.
- **CI-friendly.** `--fail-on high` returns a non-zero exit code; JSON output is stable.

## Install

```bash
git clone https://github.com/YOUR-USERNAME/shieldprobe.git
cd shieldprobe
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Or with Docker:

```bash
docker build -t shieldprobe .
docker run --rm shieldprobe --yes-i-am-authorized https://your-site.example
```

## Usage

```bash
# Interactive: asks you to confirm authorization first
shieldprobe https://your-site.example

# Non-interactive, HTML report
shieldprobe https://your-site.example --yes-i-am-authorized -f html -o report.html

# Only some checks, only medium+ findings, JSON, fail a CI job on high+
shieldprobe your-site.example --yes-i-am-authorized \
  --checks headers,cookies,tls --min-severity medium -f json --fail-on high

# Be gentle with a fragile server
shieldprobe https://your-site.example --yes-i-am-authorized --concurrency 2 --delay 0.5

shieldprobe --list-checks
```

| Option | Description |
|---|---|
| `--checks a,b` / `--skip a,b` | Choose which checks run |
| `-f text\|json\|html`, `-o FILE` | Report format and destination |
| `--min-severity LEVEL` | Hide findings below `info/low/medium/high/critical` |
| `--fail-on LEVEL` | Exit with status 1 if a finding is at or above this level |
| `--timeout`, `--concurrency`, `--delay` | Request politeness controls |
| `--insecure` | Skip TLS verification (also skips the certificate check) |
| `--yes-i-am-authorized` | Required for non-interactive runs |

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` usage or scan error.

## Try it without touching any real system

`examples/demo.py` scans a *simulated* vulnerable site entirely in memory and writes
[`examples/sample-report.html`](examples/sample-report.html) and
[`examples/sample-report.json`](examples/sample-report.json):

```bash
python examples/demo.py
```

```text
ShieldProbe 0.1.0 report
Target   : https://vulnerable-demo.test
Checks   : headers, cookies, cors, disclosure, exposed-files
Score    : 0/100 (grade F)
Findings : 1 critical, 4 high, 7 medium, 6 low, 2 info

[CRITICAL] Environment file exposed (EXP-ENV)
    URL       https://vulnerable-demo.test/.env
    Evidence  HTTP 200, Content-Type: unknown; expected format detected (contents
              intentionally not stored)
    Why       An environment file is downloadable. These routinely hold database passwords,
              API keys and signing secrets.
    Fix       Remove the file from the web root, block dotfiles, and rotate every secret it
              contained.

[HIGH] Git repository exposed (EXP-GIT)
    ...
```

## Scoring

Each site starts at 100. Findings subtract points by severity: critical 25, high 15,
medium 8, low 3, info 0 (floor of 0). Grades: A >= 90, B >= 80, C >= 70, D >= 60, else F.
Treat the score as a quick indicator, not a verdict: the findings are what matter.

## Use as a library

```python
import asyncio
from shieldprobe import scan
from shieldprobe.report import render_json

result = asyncio.run(scan("https://your-site.example", checks=["headers", "cookies"]))
print(result.score, result.grade)
for finding in result.findings:
    print(finding.severity.label, finding.title)
```

## Adding a check

A check is one async function that receives a `ScanContext` (HTTP client, base response,
concurrency limits) and returns `Finding`s:

```python
# src/shieldprobe/checks/robots.py
from ..context import ScanContext
from ..models import Finding, Severity


async def run(ctx: ScanContext) -> list[Finding]:
    response, body = await ctx.peek("/robots.txt")
    ...
    return []
```

Register it in `src/shieldprobe/checks/__init__.py`, add a test using `tests/helpers.py`
(`make_site` builds a fake website, so no network is needed), and you're done.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest
```

Tests run entirely against in-memory fake sites (`httpx.MockTransport`). The TLS socket
probes (certificate and legacy protocol handshakes) are the one area not covered by unit
tests, because they require a real TLS endpoint.

## Limitations

- It is a **first-pass** scanner, not a replacement for manual testing. It does not crawl,
  authenticate, test for injection flaws, or analyze application logic.
- Results can include false positives and false negatives; verify findings manually.
- Legacy-protocol detection depends on the local OpenSSL still being able to speak TLS 1.0/1.1;
  where it cannot, those protocols are reported as not supported rather than guessed.

## Roadmap

- [ ] Crawl same-origin pages and check forms (CSRF tokens, `autocomplete`, mixed content)
- [ ] Subresource Integrity and third-party script inventory
- [ ] DNS checks (SPF/DKIM/DMARC, dangling CNAMEs)
- [ ] SARIF output for GitHub code scanning
- [ ] Authenticated scanning via supplied cookies/headers
- [ ] Baseline files to track new vs. known findings between runs

## Responsible use

ShieldProbe sends roughly 40 ordinary HTTP(S) requests per scan. Scanning systems without
authorization may be illegal. The CLI asks you to confirm authorization before each
interactive run and requires `--yes-i-am-authorized` otherwise. You are responsible for how
you use this tool. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
