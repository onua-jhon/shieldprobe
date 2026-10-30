"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .checks import DESCRIPTIONS
from .models import Severity
from .report import render_html, render_json, render_text
from .scanner import ScanError, resolve_checks, scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shieldprobe",
        description="Passive web security scanner. Only scan systems you are authorized to test.",
    )
    parser.add_argument("target", nargs="?", help="URL or hostname to scan (https:// assumed)")
    parser.add_argument("--version", action="version", version=f"shieldprobe {__version__}")
    parser.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    parser.add_argument("--checks", help="comma-separated checks to run (default: all)")
    parser.add_argument("--skip", help="comma-separated checks to skip")
    parser.add_argument(
        "-f", "--format", choices=("text", "json", "html"), default="text", help="report format"
    )
    parser.add_argument("-o", "--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--min-severity",
        default="info",
        metavar="LEVEL",
        help="hide findings below this severity: info, low, medium, high, critical",
    )
    parser.add_argument(
        "--fail-on",
        default="none",
        metavar="LEVEL",
        help="exit with status 1 if any finding is at/above this severity "
        "(none, low, medium, high, critical) - useful in CI",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (seconds)")
    parser.add_argument("--concurrency", type=int, default=5, help="max simultaneous requests")
    parser.add_argument(
        "--delay", type=float, default=0.0, help="pause before each request (seconds)"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates (skips the certificate check)",
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )
    parser.add_argument("--no-color", action="store_true", help="disable colored text output")
    return parser


def _split(value: str | None) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()] if value else []


def _confirm_authorized(target: str, already_confirmed: bool) -> bool:
    if already_confirmed:
        return True
    if not sys.stdin.isatty():
        return False
    answer = input(f"Do you own {target} or have written permission to test it? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        width = max(len(name) for name in DESCRIPTIONS)
        for name, description in DESCRIPTIONS.items():
            print(f"{name:<{width}}  {description}")
        return EXIT_OK

    if not args.target:
        parser.error("a target is required (try: shieldprobe https://example.com)")

    try:
        min_severity = Severity.parse(args.min_severity)
        fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
        selected = _split(args.checks) or list(DESCRIPTIONS)
        skipped = set(_split(args.skip))
        resolve_checks(skipped)  # validates names
        checks = [c for c in resolve_checks(selected) if c not in skipped]
        if not checks:
            raise ValueError("no checks left to run after applying --skip")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not _confirm_authorized(args.target, args.yes_i_am_authorized):
        print(
            "error: authorization not confirmed. Only scan systems you own or have written "
            "permission to test. Re-run with --yes-i-am-authorized to confirm.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    print(
        f"ShieldProbe {__version__}: scanning {args.target} (passive checks only)...",
        file=sys.stderr,
    )
    try:
        result = asyncio.run(
            scan(
                args.target,
                checks=checks,
                timeout=args.timeout,
                concurrency=args.concurrency,
                delay=args.delay,
                verify_tls=not args.insecure,
            )
        )
    except (ScanError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result.findings = [f for f in result.findings if f.severity >= min_severity]

    use_color = (
        args.output is None
        and sys.stdout.isatty()
        and not args.no_color
        and "NO_COLOR" not in os.environ
    )
    if args.format == "json":
        report = render_json(result)
    elif args.format == "html":
        report = render_html(result)
    else:
        report = render_text(result, color=use_color)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
