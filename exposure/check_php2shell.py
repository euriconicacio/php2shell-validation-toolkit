#!/usr/bin/env python3
"""
check_php2shell.py — Safe exposure checker for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

This tool does NOT exploit anything. It answers one question:
"Is this PHP install exposed to PHP2Shell?"

It does so by:
  1. Reading the local PHP version and comparing it to the fixed releases, and
     checking for memory_hard_limit_percent, an INI setting that only exists in
     builds carrying the fix (so distribution backports that keep an old
     version number are recognized as patched).
  2. Auditing the runtime configuration behind the known routes
     (session.upload_progress.enabled, fatal_error_backtraces, memory_limit).
  3. (Optional) Fingerprinting a remote host's advertised PHP version from
     response headers only — no payloads, no requests that touch the
     vulnerable code path.

Use it on systems you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass

# First patched release per supported branch. Anything below these on the
# same branch is vulnerable unless the build carries a backport of the fix.
# Branches <= 8.1 are end-of-life: no release (7.4-8.1 have source backports).
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

EOL_CEILING = (8, 1)  # 8.1.x and older: EOL, no release.

# INI directive added by the fix (php/php-src@31c0ea7d7). ini_get() returns
# False when the directive does not exist, i.e. on builds without the fix.
FIX_MARKER = "memory_hard_limit_percent"


@dataclass
class Verdict:
    status: str   # VULNERABLE | PATCHED | UNKNOWN
    detail: str


def parse_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def judge_version(ver: tuple[int, int, int]) -> Verdict:
    major, minor, patch = ver
    branch = (major, minor)

    if major < 8 or branch <= EOL_CEILING:
        advice = ("PHP published minimal source backports for 7.4-8.1: check "
                  "your distribution / LTS vendor, or upgrade to a supported, "
                  "patched branch."
                  if (major, minor) >= (7, 4) else
                  "No fix from PHP: upgrade to a supported, patched branch.")
        return Verdict(
            "VULNERABLE",
            f"PHP {major}.{minor}.{patch} is end-of-life with no release. {advice}",
        )
    if branch in FIXED:
        if ver < FIXED[branch]:
            fx = ".".join(map(str, FIXED[branch]))
            return Verdict(
                "VULNERABLE",
                f"PHP {major}.{minor}.{patch} is below the fixed release "
                f"{fx} for this branch. Update now.",
            )
        return Verdict(
            "PATCHED",
            f"PHP {major}.{minor}.{patch} is at or above the fixed release "
            f"for branch {major}.{minor}.",
        )
    # Future branch we don't have data for.
    return Verdict(
        "UNKNOWN",
        f"PHP {major}.{minor}.{patch}: no fixed-release data for this branch. "
        f"Check the official PHP advisory.",
    )


def local_php_version() -> tuple[int, int, int] | None:
    for cmd in (["php", "-r", "echo PHP_VERSION;"], ["php", "-v"]):
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, check=False
            ).stdout
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        ver = parse_version(out)
        if ver:
            return ver
    return None


def php_ini_value(name: str) -> str | None:
    """Return the CLI's value for an INI directive, "" when empty,
    "<missing>" when the directive does not exist, None without a PHP CLI."""
    try:
        out = subprocess.run(
            ["php", "-r",
             f"$v = ini_get({name!r}); echo $v === false ? '<missing>' : $v;"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return out


def has_fix_marker() -> bool | None:
    """True if the local build has the INI directive the fix introduced."""
    v = php_ini_value(FIX_MARKER)
    if v is None:
        return None
    return v != "<missing>"


def audit_config() -> list[str]:
    """Flag runtime settings relevant to the PHP2Shell paths."""
    notes: list[str] = []

    upload_progress = php_ini_value("session.upload_progress.enabled")
    if upload_progress is None:
        notes.append("Could not read session.upload_progress.enabled (no PHP CLI?).")
    elif upload_progress in ("1", "on", "On", "true"):
        notes.append(
            "session.upload_progress.enabled is ON (default). This is the "
            "session case of CVE-2026-109619. Interim stopgap: set it to 0 in "
            "php.ini / the FPM pool (NOT .user.ini, which is applied too late)."
        )
    else:
        notes.append("session.upload_progress.enabled is OFF (stopgap for the "
                     "CVE-2026-109619 session case in place).")

    backtraces = php_ini_value("fatal_error_backtraces")
    if backtraces not in (None, "<missing>"):
        if backtraces in ("1", "on", "On", "true"):
            notes.append(
                "fatal_error_backtraces is ON (PHP 8.5 default). This is the "
                "producer behind the confirmed CVE-2026-109619 RCE. Interim "
                "stopgap: set it to 0 administratively."
            )
        else:
            notes.append("fatal_error_backtraces is OFF (stopgap for the "
                         "CVE-2026-109619 backtrace case in place).")

    mem = php_ini_value("memory_limit")
    if mem is not None:
        if mem == "-1":
            notes.append(
                "memory_limit = -1 (PHP's stopgap for CVE-2026-109618 in place; "
                "not complete, and one request can now exhaust RAM: keep a "
                "container/cgroup limit and restore a finite limit after patching)."
            )
        else:
            notes.append(
                f"memory_limit = {mem}. A finite per-request limit is what the "
                f"confirmed CVE-2026-109618 exploit drives requests into. PHP's "
                f"stopgap is memory_limit = -1, with a DoS cost; see "
                f"mitigations/php.ini.hardening.ini."
            )
    notes.append(
        "These values come from the PHP CLI. PHP-FPM pools and Apache can load "
        "different settings: confirm them where they are defined."
    )
    return notes


def remote_fingerprint(url: str) -> Verdict:
    """
    Header-only PHP version fingerprint. Sends a single benign GET and reads
    Server / X-Powered-By. No payloads, nothing that touches the vulnerable
    code path. Many hardened hosts hide these headers, so UNKNOWN is common
    and is not a clean bill of health.
    """
    try:
        import urllib.request
    except ImportError:  # pragma: no cover
        return Verdict("UNKNOWN", "urllib unavailable.")

    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "php2shell-exposure-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:  # noqa: BLE001
        return Verdict("UNKNOWN", f"Request failed: {exc}")

    banner = " ".join(v for k, v in headers.items()
                      if k in ("x-powered-by", "server"))
    ver = parse_version(banner)
    if not ver:
        return Verdict(
            "UNKNOWN",
            "Host does not advertise a PHP version in headers. "
            "Check the version on the server itself.",
        )
    v = judge_version(ver)
    return Verdict(v.status, f"Advertised {'.'.join(map(str, ver))}. {v.detail}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Safe PHP2Shell (CVE-2026-109618/109619) exposure checker. "
                    "Does not exploit; reports whether PHP is exposed."
    )
    ap.add_argument("--url", help="Header-only remote fingerprint of a host you own/are authorized to assess.")
    ap.add_argument("--version", help="Judge a version string directly, e.g. 8.3.12.")
    args = ap.parse_args()

    print("PHP2Shell exposure check (CVE-2026-109618 / CVE-2026-109619)\n")

    if args.version:
        ver = parse_version(args.version)
        if not ver:
            print(f"Could not parse version: {args.version}")
            return 2
        v = judge_version(ver)
        print(f"[{v.status}] {v.detail}")
        return 0 if v.status == "PATCHED" else 1

    if args.url:
        v = remote_fingerprint(args.url)
        print(f"[{v.status}] {args.url}: {v.detail}")
        return 0 if v.status == "PATCHED" else 1

    # Default: audit the local install.
    ver = local_php_version()
    if not ver:
        print("[UNKNOWN] No local PHP CLI found. Pass --version or --url.")
        return 2
    v = judge_version(ver)
    marker = has_fix_marker()
    if marker and v.status == "VULNERABLE":
        v = Verdict(
            "PATCHED",
            f"PHP {'.'.join(map(str, ver))} carries the fix as a backport: "
            f"{FIX_MARKER} exists, and it only exists in fixed builds.",
        )
    elif marker is False and v.status == "PATCHED":
        v = Verdict(
            "UNKNOWN",
            f"{v.detail} But {FIX_MARKER} is missing, which fixed builds have. "
            f"Check how this PHP was built.",
        )
    print(f"[{v.status}] Local PHP: {v.detail}")
    if marker is not None:
        print(f"  Fix marker {FIX_MARKER}: {'present' if marker else 'absent'}")
    print()
    print("Configuration audit:")
    for note in audit_config():
        print(f"  - {note}")
    return 0 if v.status == "PATCHED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
