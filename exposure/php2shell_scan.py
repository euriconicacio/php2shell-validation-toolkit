#!/usr/bin/env python3
"""
php2shell_scan.py — active, non-destructive checks around PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Part of the PHP2Shell Validation & Defense Toolkit by Eurico Nicacio.

What this can and cannot tell you
---------------------------------
PHP2Shell is two memory-safety bugs in the PHP engine. Confirming them on a
live target means driving PHP out of memory or into a use-after-free, which is
exploitation. This tool never does that. Over HTTP, the only safe signal for
PHP2Shell itself is the PHP version a host advertises (check 1), and a version
can be misleading: distributions backport the fix without changing it. Confirm
on the server with check_php2shell.py, which also looks for the fix marker.

The other checks answer two practical questions:

  2. Edge rule  — does your WAF / web-server rule stop a multipart request that
                  carries the PHP_SESSION_UPLOAD_PROGRESS field before it
                  reaches PHP? (the mitigation in ../mitigations/)
  3. LFI chain  — the OLDER upload-progress technique, which is NOT PHP2Shell:
                  an attacker-chosen session id is accepted
                  (session.use_strict_mode=Off), the upload filename lands in
                  sess_<id>, and an application file-inclusion bug includes it.
                  Some public "PHP2Shell" exploits use this chain. It needs an
                  LFI in the application and session.upload_progress.cleanup=Off.
                  The optional confirmation (--file-read) writes an INERT random
                  canary (plain text, no PHP tags) and reads it back through a
                  file-read endpoint you already know exists. Nothing is run.

AUTHORIZED TESTING ONLY. Run this only against systems you own or have explicit
written permission to test. Pointing it at third-party sites is unauthorized
access. See ../SECURITY.md.

  python3 php2shell_scan.py --authorized --target http://host:port \\
      --session-path /index.php
  python3 php2shell_scan.py --authorized --target http://host:port \\
      --session-path /index.php \\
      --file-read 'http://host:port/view.php?page=FUZZ' \\
      --save-path /tmp/sessions

Note: the active probes (checks 2-3) use a raw HTTP socket and do not wrap TLS,
so they only run against http:// targets. Check 1 works over https.
"""
from __future__ import annotations

import argparse
import re
import secrets
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

# Fixed release per stable branch; anything earlier on that branch is
# vulnerable unless it carries a backport. Mirrors exposure/check_php2shell.py.
# Branches in EOL_VULNERABLE are end-of-life with no release.
BRANCH_FIX = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
EOL_VULNERABLE = {(8, 1), (8, 0), (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
                  (5, 6), (5, 5), (5, 4)}

# Status codes that mean "stopped before PHP" when a front end blocks a request.
BLOCKED = {403, 406, 501}

RESET = "\033[0m"


def c(txt: str, col: str) -> str:
    cols = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "grey": 90}
    return f"\033[{cols[col]}m{txt}{RESET}" if sys.stdout.isatty() else txt


def classify_version(ver: str | None) -> tuple[str, str]:
    """Return (verdict, note) for a dotted PHP version string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        return "unknown", "could not parse version"
    major, minor, patch = int(m[1]), int(m[2]), int(m[3])
    branch = (major, minor)
    if branch in BRANCH_FIX:
        fix = BRANCH_FIX[branch]
        if patch < fix:
            return "vulnerable", (f"{ver} < {major}.{minor}.{fix} (fixed); a "
                                  f"distribution backport keeps the old number, "
                                  f"so confirm on the server")
        return "patched", f"{ver} >= {major}.{minor}.{fix}"
    if branch in EOL_VULNERABLE:
        return "vulnerable", f"{major}.{minor}.x is end-of-life with no release"
    if major > 8 or (major == 8 and minor > 5):
        return "unknown", f"{ver} is newer than the advisory range"
    return "unknown", f"{ver} not in the advisory table"


# --- HTTP helpers -----------------------------------------------------------
def fingerprint(target: str, timeout: float):
    """GET the target root; return (status, headers dict, body bytes)."""
    req = urllib.request.Request(
        target, method="GET", headers={"User-Agent": "php2shell-scan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(65536)
    except Exception as e:  # noqa: BLE001
        return None, {"_error": str(e)}, b""


def raw_request(host, port, method, path, timeout, cookie=None, fields=None):
    """Send one request over a raw HTTP socket.

    fields: list of (name, value, filename-or-None) sent as multipart/form-data.
    Returns (status_code or None, status_line, set_cookie_header_values).
    """
    body = b""
    headers = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: php2shell-scan\r\n")
    if fields is not None:
        boundary = "SCAN" + secrets.token_hex(4)
        parts = []
        for name, value, filename in fields:
            disp = f'form-data; name="{name}"'
            if filename is not None:
                disp += f'; filename="{filename}"'
            parts.append(f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n{value}\r\n")
        body = ("".join(parts) + f"--{boundary}--\r\n").encode("latin-1")
        headers += (f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                    f"Content-Length: {len(body)}\r\n")
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    headers += "Connection: close\r\n\r\n"

    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(headers.encode() + body)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()

    status_line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
    code = int(m[1]) if m else None
    head = resp.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in resp else resp
    set_cookies = [x.decode("latin1", "replace").strip()
                   for x in re.findall(rb"(?im)^set-cookie:\s*(.*)$", head)]
    return code, status_line, set_cookies


def session_cookie(set_cookies: list[str]) -> str | None:
    """Return the PHPSESSID value a response sets, if any."""
    for sc in set_cookies:
        m = re.match(r"PHPSESSID=([^;]*)", sc)
        if m and m[1] and m[1] != "deleted":
            return m[1]
    return None


def file_read(template: str, file_path: str, timeout: float) -> bytes:
    """GET the file-read endpoint with FUZZ replaced by file_path."""
    url = template.replace("FUZZ", urllib.parse.quote(file_path, safe="/"))
    req = urllib.request.Request(url, headers={"User-Agent": "php2shell-scan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.read(262144)
    except urllib.error.HTTPError as e:
        return e.read(262144)
    except Exception:  # noqa: BLE001
        return b""


# --- Main -------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="http://host:port")
    ap.add_argument("--session-path", default="/",
                    help="path to an endpoint that calls session_start() (default '/')")
    ap.add_argument("--file-read", default=None,
                    help="known file-read endpoint with a FUZZ marker, e.g. "
                         "'http://h/view.php?page=FUZZ' — enables the LFI-chain "
                         "canary confirmation")
    ap.add_argument("--save-path", default=None,
                    help="session.save_path on the target; if omitted, a short "
                         "candidate list is tried for the canary read-back")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--authorized", action="store_true",
                    help="REQUIRED. Affirm you own or are explicitly authorized "
                         "in writing to test this target.")
    args = ap.parse_args()

    if not args.authorized:
        print(c("Refusing to run without --authorized.", "yellow"))
        print("This tool sends active probes. Scan only systems you own or have")
        print("explicit written permission to test. See ../SECURITY.md.")
        return 2

    u = urlparse(args.target)
    if not u.hostname:
        print(c("Invalid --target. Use http://host:port", "red"))
        return 2
    host, port = u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    active = u.scheme != "https"
    if not active:
        print(c("[!] Active probes (checks 2-3) use plain HTTP; https targets "
                "get check 1 only.", "yellow"))

    print(c("php2shell_scan — CVE-2026-109618 / CVE-2026-109619", "blue"))
    print(c("Authorized testing only.", "grey"))
    print(f"[*] Target: {args.target}\n")

    # Check 1: PHP2Shell by advertised version
    status, headers, body = fingerprint(args.target, args.timeout)
    if status is None:
        print(c(f"[1] PHP2Shell (version)  FAIL — unreachable ({headers.get('_error')})", "red"))
        return 2
    banner = headers.get("x-powered-by", "") or headers.get("server", "")
    vm = re.search(r"PHP/([\d.]+)", banner)
    version = vm.group(1) if vm else None
    verdict, note = classify_version(version)
    label = {"vulnerable": c("VULNERABLE (by version)", "red"),
             "patched": c("patched (by version)", "green"),
             "unknown": c("unknown", "yellow")}[verdict]
    print(f"[1] PHP2Shell (version)  PHP {version or '?'}  -> {label}")
    print(c(f"       {note}  (banner: {banner or 'none'})", "grey"))

    edge = "skipped"
    strict_off = None
    confirmed = False
    if active:
        # Check 2: is the upload-progress field stopped before PHP?
        path = args.session_path
        try:
            base_code, base_line, _ = raw_request(
                host, port, "POST", path, args.timeout,
                fields=[("probe", "x", None)])
            field_code, field_line, _ = raw_request(
                host, port, "POST", path, args.timeout,
                fields=[("PHP_SESSION_UPLOAD_PROGRESS", "scan", None),
                        ("f", "Z", "probe.txt")])
        except OSError as e:
            print(c(f"[2] Edge rule            FAIL — connection error: {e}", "red"))
            base_code = field_code = None
            base_line = field_line = "ERR"
        if field_code in BLOCKED and base_code in BLOCKED:
            edge = "multipart-blocked"
            msg = c("all multipart blocked before PHP", "green")
        elif field_code in BLOCKED:
            edge = "field-blocked"
            msg = c("upload-progress field blocked before PHP", "green")
        elif field_code is None:
            edge = "error"
            msg = c("no answer", "yellow")
        else:
            edge = "reaches-php"
            msg = c("upload-progress field reaches PHP (no edge rule seen)", "yellow")
        print(f"[2] Edge rule            {msg}")
        print(c(f"       plain multipart -> {base_line}; with field -> {field_line}", "grey"))

        # Check 3: the older upload-progress + LFI chain (not PHP2Shell)
        print("[3] LFI chain (separate, older technique — not PHP2Shell)")
        try:
            _, _, fresh = raw_request(host, port, "GET", path, args.timeout)
            starts_session = session_cookie(fresh) is not None
            chosen = "scan" + secrets.token_hex(12)
            _, _, reply = raw_request(host, port, "GET", path, args.timeout,
                                      cookie=f"PHPSESSID={chosen}")
            reissued = session_cookie(reply)
        except OSError as e:
            print(c(f"       strict mode       FAIL — connection error: {e}", "red"))
            starts_session, reissued = False, None
        if not starts_session:
            print(c("       strict mode       inconclusive — the endpoint did not "
                    "start a session (pass --session-path to one that does)", "yellow"))
        elif reissued and reissued != chosen:
            strict_off = False
            print(f"       strict mode       {c('ON', 'green')}  — a made-up session id "
                  f"was replaced (session.use_strict_mode=1)")
        else:
            strict_off = True
            print(f"       strict mode       {c('OFF', 'yellow')} — a made-up session id "
                  f"was accepted (session.use_strict_mode=0, the default)")

        if args.file_read:
            if edge in ("field-blocked", "multipart-blocked"):
                print(c("       canary            skipped — the edge rule blocks the "
                        "upload-progress field", "grey"))
            else:
                canary = "P2S_" + secrets.token_hex(12)   # inert text, no PHP tags
                sid = "scancan" + secrets.token_hex(10)
                try:
                    raw_request(host, port, "POST", path, args.timeout,
                                cookie=f"PHPSESSID={sid}",
                                fields=[("PHP_SESSION_UPLOAD_PROGRESS", "scan", None),
                                        ("f", "Z", canary)])
                except OSError as e:
                    print(c(f"       canary            FAIL — inject error: {e}", "red"))
                candidates = ([args.save_path] if args.save_path else
                              ["/tmp/sessions", "/var/lib/php/sessions",
                               "/var/lib/php/session", "/var/lib/php5", "/tmp"])
                hit_path = None
                for base in candidates:
                    data = file_read(args.file_read,
                                     f"{base.rstrip('/')}/sess_{sid}", args.timeout)
                    if canary.encode() in data:
                        hit_path = base
                        break
                confirmed = hit_path is not None
                if confirmed:
                    print(c(f"       canary            CONFIRMED — read back from "
                            f"{hit_path}/sess_{sid}", "red"))
                    print(c(f"       canary={canary}; no code was run", "grey"))
                else:
                    print("       canary            not read back (expected with "
                          "session.upload_progress.cleanup=On, the default; also: wrong "
                          "--save-path, no file read, or upload progress disabled)")
        else:
            print(c("       canary            skipped — pass --file-read to test the chain "
                    "end to end", "grey"))

    # Verdict
    print()
    p2s = {"vulnerable": c("VULNERABLE by advertised version", "red"),
           "patched": c("patched by advertised version", "green"),
           "unknown": c("UNKNOWN (no usable version)", "yellow")}[verdict]
    print(f"[=] PHP2Shell:  {p2s}")
    print(c("    The bugs cannot be confirmed over HTTP without exploiting them. "
            "Confirm on the server: check_php2shell.py.", "grey"))
    edge_txt = {"field-blocked": c("upload-progress field blocked", "green"),
                "multipart-blocked": c("multipart blocked", "green"),
                "reaches-php": c("no rule seen", "yellow"),
                "error": c("no answer", "yellow"),
                "skipped": c("not tested (https)", "grey")}[edge]
    print(f"[=] Edge rule:  {edge_txt}")
    if confirmed:
        chain = c("CONFIRMED (inert canary included through the file-read endpoint)", "red")
    elif strict_off:
        chain = c("precondition present (strict mode off); needs an LFI and cleanup=Off", "yellow")
    elif strict_off is False:
        chain = c("strict mode on: made-up session ids are refused", "green")
    else:
        chain = c("not tested / inconclusive", "grey")
    print(f"[=] LFI chain:  {chain}")
    print(c("    Fix PHP2Shell: upgrade PHP. LFI chain: fix the file inclusion; "
            "session.use_strict_mode=1; upload progress off.", "grey"))

    return 1 if (verdict != "patched" or confirmed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
