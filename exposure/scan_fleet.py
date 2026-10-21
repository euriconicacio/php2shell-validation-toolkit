#!/usr/bin/env python3
"""
scan_fleet.py — Safe fleet exposure scan for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Header-only. For each host you own or are authorized to assess, it sends one
benign GET and reads the advertised PHP version from response headers, then
judges it against the fixed releases. It NEVER sends exploit payloads and never
touches the vulnerable code path.

  python3 scan_fleet.py hosts.txt
  python3 scan_fleet.py --csv hosts.txt > report.csv

hosts.txt: one URL or host per line (http(s):// optional). Lines starting
with '#' are ignored.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import sys

# Reuse the single-host logic.
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from check_php2shell import remote_fingerprint  # noqa: E402


def normalize(line: str) -> str | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    return s


def scan(url: str) -> tuple[str, str, str]:
    v = remote_fingerprint(url)
    return url, v.status, v.detail


def main() -> int:
    ap = argparse.ArgumentParser(description="Safe header-only PHP2Shell fleet scan.")
    ap.add_argument("hosts", help="File with one host/URL per line.")
    ap.add_argument("--csv", action="store_true", help="CSV output.")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    with open(args.hosts, encoding="utf-8") as fh:
        urls = [u for u in (normalize(l) for l in fh) if u]

    if not urls:
        print("No hosts to scan.", file=sys.stderr)
        return 2

    results: list[tuple[str, str, str]] = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for r in pool.map(scan, urls):
            results.append(r)

    # Sort worst-first.
    order = {"VULNERABLE": 0, "UNKNOWN": 1, "PATCHED": 2}
    results.sort(key=lambda r: order.get(r[1], 1))

    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["url", "status", "detail"])
        w.writerows(results)
    else:
        vuln = sum(1 for _, s, _ in results if s == "VULNERABLE")
        unk = sum(1 for _, s, _ in results if s == "UNKNOWN")
        for url, status, detail in results:
            print(f"[{status:10}] {url}\n             {detail}")
        print(f"\nSummary: {len(results)} hosts  |  "
              f"VULNERABLE={vuln}  UNKNOWN={unk}  "
              f"PATCHED={len(results)-vuln-unk}")
        print("UNKNOWN means the host hides its version — verify on the host itself.")
    return 1 if any(s == "VULNERABLE" for _, s, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
