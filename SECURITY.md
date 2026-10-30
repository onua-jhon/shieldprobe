# Security policy

## Reporting a vulnerability in ShieldProbe itself

Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability")
instead of a public issue. Include the version, a description, and reproduction steps.
You can expect an acknowledgement within a few days.

## Responsible use

ShieldProbe sends a small number of ordinary HTTP(S) requests to the target (about 40 by
default). It does not fuzz, inject payloads, brute-force, or attempt to bypass authentication.
Even so, scanning systems you do not own or lack written permission to test may be illegal in
your jurisdiction. Only scan targets you are authorized to assess.

The CLI enforces this with an authorization prompt (or the explicit
`--yes-i-am-authorized` flag in non-interactive use).

## Design choices that limit harm

- **Passive and bounded:** fixed, small probe list; configurable concurrency and delay.
- **Scope guard:** if the target redirects to an unrelated domain, the scan aborts instead of
  following it.
- **Secrets are never stored:** when a sensitive file is detected (for example `.env`), only
  its existence and format are reported, never its contents.
- **Safe reports:** HTML reports escape all target-controlled data and ship with a strict
  Content-Security-Policy; text output strips terminal control characters.
