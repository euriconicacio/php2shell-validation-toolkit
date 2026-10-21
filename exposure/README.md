# exposure/ — checking if a target is vulnerable to PHP2Shell

CVE-2026-109618 / CVE-2026-109619. Three tools, from safest to most active.
All are for **authorized use only** — systems you own or have explicit written
permission to test. See [`../SECURITY.md`](../SECURITY.md).

| Tool | What it does | Touches target? |
| --- | --- | --- |
| `check_php2shell.py` / `.sh` | Local version, fix-marker and config audit; optional header-only remote fingerprint | No exploit traffic |
| `scan_fleet.py` | Header-only version sweep across many hosts | One benign GET per host |
| `php2shell_scan.py` | Remote version, edge-rule check, and the separate upload-progress + LFI chain | Sends small multipart probes |

## What can be confirmed, and where

PHP2Shell is two memory-safety bugs in the PHP engine. Confirming them on a
live target means driving PHP out of memory or into a use-after-free, which is
exploitation; none of these tools does that.

- **On the server** you can be definitive. The fix added an INI directive,
  `memory_hard_limit_percent`, that only exists in fixed builds. It is present
  at the `php-8.2.35`, `php-8.3.36`, `php-8.4.27` and `php-8.5.12` tags and absent
  before them; on the official Docker images, `ini_get()` returns `false` on
  8.3.35 / 8.5.11 and `''` on 8.3.36 / 8.5.12. `check_php2shell.*` uses it, so a
  distribution package that carries the fix under an old version number is
  reported as patched. Minimal source backports for EOL branches may not carry
  the directive.
- **Over HTTP** the advertised version is the only safe signal, and it is
  blind to backports and hidden by many hosts.

## 1. Passive check (start here)

```bash
python3 check_php2shell.py                 # local PHP install
python3 check_php2shell.py --version 8.3.0 # judge a version string
python3 check_php2shell.py --url https://host-you-own.test   # header-only
python3 scan_fleet.py hosts.txt            # many hosts, header-only
```

The local audit reads the PHP CLI's settings (`session.upload_progress.enabled`,
`fatal_error_backtraces`, `memory_limit`). PHP-FPM pools and Apache can load
different settings, so confirm them where they are defined.

## 2. Active checks — `php2shell_scan.py`

```bash
# Version, edge rule, and the LFI-chain precondition
python3 php2shell_scan.py --authorized --target http://host:port \
    --session-path /index.php

# Also test the LFI chain end to end, when you know a file-read endpoint
python3 php2shell_scan.py --authorized --target http://host:port \
    --session-path /index.php \
    --file-read 'http://host:port/view.php?page=FUZZ' \
    --save-path /tmp/sessions
```

`--authorized` is mandatory; the tool refuses to run without it. It never sends
anything that drives PHP out of memory or triggers either CVE.

### Checks

1. **PHP2Shell (version)** — the advertised PHP version against the fixed
   releases. This is the tool's only PHP2Shell verdict.
2. **Edge rule** — sends a plain multipart POST and one carrying the
   `PHP_SESSION_UPLOAD_PROGRESS` field, and reports whether your WAF or
   web-server rule (see `../mitigations/`) stops them before PHP.
3. **LFI chain** — the older upload-progress technique, **not PHP2Shell**.
   Some public "PHP2Shell" exploits use it. An attacker picks a session id,
   PHP accepts it (`session.use_strict_mode=0`, the default), the upload
   filename is stored in `sess_<id>`, and a file-inclusion bug in the
   application includes that file. It needs an LFI in the application and
   `session.upload_progress.cleanup=0` (the default `1` removes the data when
   the upload ends). The tool checks strict mode, and with `--file-read` writes
   an **inert random canary** (plain text, no PHP tags) and tries to read it
   back. Nothing is executed.

### Verdicts

| Line | Values |
| --- | --- |
| `PHP2Shell` | `VULNERABLE by advertised version`, `patched by advertised version`, `UNKNOWN` |
| `Edge rule` | `upload-progress field blocked`, `multipart blocked`, `no rule seen` |
| `LFI chain` | `CONFIRMED` (canary read back), `precondition present (strict mode off)`, `strict mode on`, `not tested` |

Exit status is `0` only when the version is patched and the LFI chain was not
confirmed.

Note: the active probes (checks 2-3) use a raw HTTP socket without TLS, so they
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

Against that unpatched image: check 1 reports `VULNERABLE by advertised
version` (8.3.0 < 8.3.36), check 2 reports that the field reaches PHP, and
check 3 reports strict mode off. With the toolkit's `apache/.htaccess` active
(mod_rewrite and `AllowOverride` enabled), check 2 reports `multipart blocked`.
See [`../lab/`](../lab/) for the full isolated lab.

## Authorization — read this

Scanning a site just because it runs PHP is **not** authorization. Pointing
these active probes at a third party's site is unauthorized access and may be
illegal. Keep it to your own systems, your lab, or targets covered by a signed
engagement.
