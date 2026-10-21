# exposure/ — checking if a target is vulnerable to PHP2Shell

CVE-2026-109618 / CVE-2026-109619. Three tools, from safest to most active.
All are for **authorized use only** — systems you own or have explicit written
permission to test. See [`../SECURITY.md`](../SECURITY.md).

| Tool | What it does | Touches target? |
| --- | --- | --- |
| `check_php2shell.py` / `.sh` | Local version + config audit; optional header-only remote fingerprint | No exploit traffic |
| `scan_fleet.py` | Header-only version sweep across many hosts | One benign GET per host |
| `php2shell_scan.py` | Active, non-destructive validator of the injection preconditions | Sends crafted probes |

## 1. Passive check (start here)

Judge an install by version and configuration. No requests to the vulnerable
path.

```bash
python3 check_php2shell.py                 # local PHP install
python3 check_php2shell.py --version 8.3.0 # judge a version string
python3 check_php2shell.py --url https://host-you-own.test   # header-only
python3 scan_fleet.py hosts.txt            # many hosts, header-only
```

## 2. Active validator — `php2shell_scan.py`

Probes a running target for the preconditions of the `session.upload_progress`
injection chain. It **never executes code**. The optional confirmation writes an
**inert random canary** (plain text, no PHP tags) into a session file and reads
it back only if you supply a file-read endpoint you already know exists — this
proves the inject+include primitive without running anything.

```bash
# Preconditions only (checks 1-3)
python3 php2shell_scan.py --authorized --target http://host:port \
    --session-path /index.php

# With end-to-end confirmation (check 4) when you know a file-read endpoint
python3 php2shell_scan.py --authorized --target http://host:port \
    --session-path /index.php \
    --file-read 'http://host:port/view.php?page=FUZZ' \
    --save-path /tmp/sessions
```

`--authorized` is mandatory; the tool refuses to run without it.

### Checks and verdicts

1. **Fingerprint** — PHP version vs the fixed releases.
2. **Fixation** — is a POST-body `PHPSESSID` honored (`use_only_cookies=Off`)?
3. **upload_progress** — is the multipart upload-progress mechanism accepted?
4. **Confirm** (optional) — inert canary injected and read back.

| Verdict | Meaning |
| --- | --- |
| `VULNERABLE (confirmed)` | Inert canary proved injection+inclusion. |
| `LIKELY VULNERABLE` | Affected version + fixation + upload_progress all present. |
| `PRECONDITIONS PRESENT` | Some conditions hold, not the full chain. |
| `LIKELY PATCHED` | PHP version at/above the fixed release. |
| `NOT DETECTED` | No preconditions observed over HTTP. |

Note: the active probes (checks 2-4) use a raw HTTP socket without TLS, so they
run against `http://` targets only. Check 1 works over `https`.

## Validate the scanner safely, in the lab

Do not point the scanner at anything you do not control. To see it work, use a
throwaway container on localhost:

```bash
docker run -d --name p2s-demo -p 127.0.0.1:8099:80 php:8.3.0-apache
docker exec p2s-demo sh -c 'printf "<?php session_start(); echo \"ok\"; ?>" > /var/www/html/index.php'

python3 php2shell_scan.py --authorized --target http://127.0.0.1:8099 --session-path /index.php

docker rm -f p2s-demo
```

Against that unpatched image, check 1 reports `VULNERABLE` (PHP 8.3.0 < 8.3.36).
See [`../lab/`](../lab/) for the full isolated lab.

## Authorization — read this

Scanning a site just because it runs PHP is **not** authorization. Pointing
these active probes at a third party's site is unauthorized access and may be
illegal. Keep it to your own systems, your lab, or targets covered by a signed
engagement.
