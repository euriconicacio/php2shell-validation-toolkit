#!/usr/bin/env python3
"""
php2shell_scan.py — active (non-destructive) validator for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Part of the PHP2Shell Validation & Defense Toolkit by Eurico Nicacio.

Unlike check_php2shell.py (which only reads version/config), this probes a
running target for the preconditions of the session.upload_progress injection
chain. It NEVER executes code on the target. The optional confirmation step
writes an INERT random canary (no PHP tags) into a session file via the
upload-progress filename and, only if you supply a file-read endpoint you
already know exists, reads it back to prove the inject+include primitive. The
canary is harmless text; nothing is ever run.

Checks:
  1. Fingerprint  — PHP version from Server / X-Powered-By, mapped to the
                    affected/fixed table (same table as check_php2shell.py).
  2. Fixation     — is a POST-body PHPSESSID honored (session.use_only_cookies
                    = Off), letting a caller choose the session id?
  3. upload_prog  — is the upload_progress multipart mechanism accepted (not
                    WAF-blocked / disabled)?
  4. Confirm      — (optional, needs --file-read) inject an inert canary and read
                    it back to prove injection+inclusion. No code execution.

AUTHORIZED TESTING ONLY. Run this only against systems you own or have explicit
written permission to test. Pointing it at third-party sites is unauthorized
access. See ../SECURITY.md.

  python3 php2shell_scan.py --authorized --target http://host:port
  python3 php2shell_scan.py --authorized --target http://host:port \
      --session-path /index.php \
      --file-read 'http://host:port/view.php?page=FUZZ' \
      --save-path /tmp/sessions

Note: the active probes (checks 2-4) use a raw HTTP socket and do not wrap TLS,
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
# vulnerable. Mirrors exposure/check_php2shell.py. Branches in EOL_VULNERABLE
# are end-of-life with no official fix.
BRANCH_FIX = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
EOL_VULNERABLE = {(8, 1), (8, 0), (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
                  (5, 6), (5, 5), (5, 4)}

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
            return "vulnerable", f"{ver} < {major}.{minor}.{fix} (fixed)"
        return "patched", f"{ver} >= {major}.{minor}.{fix}"
    if branch in EOL_VULNERABLE:
        return "vulnerable", f"{major}.{minor}.x is end-of-life, no official fix"
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


def upload_progress_post(host, port, path, sid, filename, send_cookie, timeout):
    """Send one upload_progress multipart POST over a raw HTTP socket.

    PHPSESSID is placed in the POST body (fixation probe); the cookie is sent
    only when send_cookie is True. Returns (status_line, body_bytes, set_cookie).
    Non-destructive: the fields carry only harmless probe text.
    """
    boundary = "SCAN" + secrets.token_hex(4)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-scan\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    if send_cookie:
        headers += f"Cookie: PHPSESSID={sid}\r\n"
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

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    head = resp.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in resp else resp
    body_out = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    m = re.search(rb"set-cookie:\s*(.*)", head, re.I)
    set_cookie = m.group(1).decode("latin1", "replace").strip() if m else ""
    return status, body_out, set_cookie


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
                         "'http://h/view.php?page=FUZZ' — enables canary confirmation")
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
    if u.scheme == "https":
        print(c("[!] Active probes (checks 2-4) use plain HTTP; https targets "
                "fingerprint only (check 1).", "yellow"))

    print(c("php2shell_scan — CVE-2026-109618 / CVE-2026-109619", "blue"))
    print(c("Authorized testing only.", "grey"))
    print(f"[*] Target: {args.target}\n")

    results: dict[str, object] = {}

    # Check 1: fingerprint
    status, headers, body = fingerprint(args.target, args.timeout)
    if status is None:
        print(c(f"[1] Fingerprint       FAIL — unreachable ({headers.get('_error')})", "red"))
        return 2
    banner = headers.get("x-powered-by", "") or headers.get("server", "")
    vm = (re.search(r"PHP/([\d.]+)", banner)
          or re.search(r"PHP ([\d.]+)", body.decode("latin1", "replace")))
    version = vm.group(1) if vm else None
    verdict, note = classify_version(version)
    results["version"] = verdict
    label = {"vulnerable": c("VULNERABLE", "red"),
             "patched": c("patched", "green"),
             "unknown": c("unknown", "yellow")}[verdict]
    print(f"[1] Fingerprint       PHP {version or '?'}  -> {label}")
    print(c(f"       {note}  (banner: {banner or 'none'})", "grey"))

    # Check 2: POST-body session fixation
    sid_fix = "scanfix" + secrets.token_hex(10)
    try:
        st, _, setck = upload_progress_post(
            host, port, args.session_path, sid_fix, "canary.txt",
            send_cookie=False, timeout=args.timeout)
    except OSError as e:
        print(c(f"[2] Fixation          FAIL — connection error: {e}", "red"))
        st, setck = "", ""
    issued_new = bool(re.search(r"PHPSESSID=([^;]+)", setck)) and sid_fix not in setck
    fixation_ok = st.startswith("HTTP") and not issued_new
    results["fixation"] = fixation_ok
    print(f"[2] Fixation          {'OK  ' if fixation_ok else 'no  '}"
          f"POST-body PHPSESSID {'honored' if fixation_ok else 'not honored'} "
          f"{c('(use_only_cookies=Off)', 'grey') if fixation_ok else ''}")
    if setck:
        print(c(f"       Set-Cookie: {setck}", "grey"))

    # Check 3: upload_progress mechanism accepted
    sid_up = "scanup" + secrets.token_hex(10)
    try:
        st3, _, _ = upload_progress_post(
            host, port, args.session_path, sid_up, "probe.txt",
            send_cookie=True, timeout=args.timeout)
    except OSError as e:
        st3 = f"ERR {e}"
    up_ok = st3.startswith("HTTP") and " 200" in st3
    results["upload_progress"] = up_ok
    print(f"[3] upload_progress   {'OK  ' if up_ok else 'no  '}"
          f"multipart probe -> {st3}")

    # Check 4: inert-canary confirmation (optional)
    confirmed = False
    if args.file_read:
        canary = "P2S_" + secrets.token_hex(12)   # inert text, no PHP tags
        sid_can = "scancan" + secrets.token_hex(10)
        try:
            upload_progress_post(host, port, args.session_path, sid_can,
                                 canary, send_cookie=True, timeout=args.timeout)
        except OSError as e:
            print(c(f"[4] Confirm           FAIL — inject error: {e}", "red"))
        candidates = ([args.save_path] if args.save_path else
                      ["/tmp/sessions", "/var/lib/php/sessions",
                       "/var/lib/php/session", "/var/lib/php5", "/tmp"])
        hit_path = None
        for base in candidates:
            data = file_read(args.file_read, f"{base.rstrip('/')}/sess_{sid_can}", args.timeout)
            if canary.encode() in data:
                hit_path = base
                break
        confirmed = hit_path is not None
        results["confirm"] = confirmed
        if confirmed:
            print(c(f"[4] Confirm           CONFIRMED — inert canary read back from "
                    f"{hit_path}/sess_{sid_can}", "red"))
            print(c("       injection+inclusion primitive proven; no code was run.", "grey"))
            print(c(f"       canary={canary}", "grey"))
        else:
            print("[4] Confirm           no  — canary not read back "
                  "(wrong --save-path, no file-read, or not injectable)")
    else:
        print(c("[4] Confirm           skipped — pass --file-read to confirm the primitive", "grey"))

    # Verdict
    print()
    if confirmed:
        v = c("VULNERABLE (confirmed)", "red")
        detail = "injection+inclusion primitive proven with an inert canary."
    elif results.get("version") == "vulnerable" and results.get("fixation") \
            and results.get("upload_progress"):
        v = c("LIKELY VULNERABLE", "red")
        detail = ("affected version + fixation + upload_progress all present; "
                  "add --file-read to confirm end-to-end.")
    elif results.get("version") == "patched":
        v = c("LIKELY PATCHED", "green")
        detail = "PHP version is at or above the fixed release for its branch."
    elif results.get("upload_progress") or results.get("fixation"):
        v = c("PRECONDITIONS PRESENT", "yellow")
        detail = "some preconditions hold, but not the full chain; review each check above."
    else:
        v = c("NOT DETECTED", "green")
        detail = "no preconditions observed over HTTP."
    print(f"[=] Verdict: {v}")
    print(c(f"    {detail}", "grey"))
    print(c("    Fix: patch PHP. Mitigate: session.upload_progress.enabled=Off; "
            "use_only_cookies=On.", "grey"))

    return 0 if confirmed or results.get("version") == "vulnerable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
