# Security and responsible-use policy

This project is a **defensive** toolkit for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619): it helps operators validate exposure,
apply mitigations, and detect exploitation. It deliberately ships no weaponized
remote-code-execution exploit.

## Authorized use only

- Use the detection tools only against systems you own or are explicitly
  authorized in writing to assess.
- Do not point the remote/fleet checker at third-party hosts.
- The lab target is bound to localhost on an internet-isolated network. Keep it
  that way; do not expose it.

## Scope of the tools

- `exposure/check_php2shell.*` and `exposure/scan_fleet.py` perform version
  and configuration checks and header-only remote fingerprinting. They send no
  exploit payloads and never touch the vulnerable code path.
- `exposure/php2shell_scan.py` is active: it sends small multipart requests
  carrying the upload-progress field, and can write an inert text canary into a
  session file. It sends nothing that drives PHP out of memory or triggers
  either CVE, and runs only with `--authorized`.
- `mitigations/` and `hunting/` are configuration and monitoring guidance.
- `lab/` is a deliberately unpatched target for validating the defensive pieces,
  not an exploitation tutorial.

## Reporting

If you find a bug in this toolkit (for example, a detection that misjudges a
version, or a mitigation that breaks legitimate traffic), open an issue with
the PHP version, OS/packaging, and the exact output.

## Remember

The complete fix for PHP2Shell is upgrading PHP to a patched release
(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later). Everything here is support for
getting there safely.
