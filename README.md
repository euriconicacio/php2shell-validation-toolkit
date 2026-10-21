<p align="center">
  <img src="banner.png" alt="PHP2Shell Validation & Defense Toolkit" width="100%">
</p>

# PHP2Shell Validation & Defense Toolkit

**CVE-2026-109618 / CVE-2026-109619 — unauthenticated RCE in PHP core (CVSS 9.2)**

By **Eurico Nicacio**.

Tooling to let operators **check whether their PHP is exposed to PHP2Shell**,
apply interim mitigations across the whole stack, and detect exploitation —
without shipping a weaponized remote-code-execution exploit.

> **Scope.** For defenders and for authorized assessment of systems you own or
> have written permission to test. It contains no public RCE exploit by design.
> The complete fix is upgrading PHP. See [`SECURITY.md`](SECURITY.md).

## The vulnerabilities

Two critical, pre-authentication memory-safety flaws in **PHP core** (not in
WordPress/Drupal/Joomla — those were only demonstration targets). The identifiers
leaked on 20 October 2026; PHP published the advisories and fixed releases on
21 October. Cloudflare reported early attacks and watchTowr reported
exploitation attempts the same day.

| CVE | PHP advisory | What it is | Impact |
| --- | --- | --- | --- |
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | Out-of-memory corruption: an OOM bailout (`longjmp()`) leaves request memory half-initialized, and request shutdown then reads it | Unauthenticated RCE (validated on Apache mod_php with default limits) |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Stale global state: worker globals keep pointing into a freed request heap and the next request on that worker uses them. Confirmed cases: PHP 8.5 `fatal_error_backtraces`, and the session upload-progress lifecycle | Unauthenticated use-after-free, memory disclosure, RCE |

Both are CVSS v4.0 9.2. Both are fixed by the same upstream commit,
[`31c0ea7d7`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
("Avoid state corruption via bailout"). Full mechanism in
[`docs/TECHNICAL.md`](docs/TECHNICAL.md).

> Some write-ups published before PHP's advisories described the pair
> differently (for example, the upload-progress bug as CVE-2026-109618). This
> toolkit follows PHP's own advisories; PHP is the CNA for both identifiers.

### Affected and fixed ([`docs/affected-versions.md`](docs/affected-versions.md))

| Branch | First fixed release |
| --- | --- |
| 8.5.x | 8.5.12 |
| 8.4.x | 8.4.27 |
| 8.3.x | 8.3.36 |
| 8.2.x | 8.2.35 |
| 7.4 – 8.1 | End-of-life — no release; PHP published minimal source backports, distributions may ship them |
| ≤ 7.3 | End-of-life — no fix from PHP, upgrade the branch |

## What's here

```
exposure/      Checkers + scanners (see exposure/README.md):
   check_php2shell.py/.sh     passive version/config audit + header-only remote
   scan_fleet.py              header-only version sweep across many hosts
   php2shell_scan.py          active, non-destructive: edge-rule check + the separate
                              upload-progress + LFI chain (authorized only)
mitigations/   Interim hardening across the stack:
   php.ini.hardening.ini      the three official config stopgaps, with their costs
   quick-fix/run.sh           check / dry-run / apply / revert the config mitigation
   nginx-block.conf           multipart / body / read-only options
   apache/                    ModSecurity rule + .htaccess
   lighttpd/                  multipart deny
   frankenphp/                Caddyfile snippet
   cloudflare/                edge WAF rules (multipart + body inspection)
   patch/                     source-patching + EOL guidance (points to upstream)
hunting/     Host, log, IDS signals + PHP-worker process watcher
lab/           Isolated Docker target to validate the hunting/mitigation pieces
docs/          Technical summary, affected versions, FAQ
```

## Quick start

```bash
# Check the local PHP install (version + config audit)
python3 exposure/check_php2shell.py
#   or
bash exposure/check_php2shell.sh

# Judge a specific version string
python3 exposure/check_php2shell.py --version 8.3.12

# Header-only fingerprint of a host you are authorized to assess
python3 exposure/check_php2shell.py --url https://example-you-own.test

# Sweep many hosts (one per line; header-only, no payloads)
python3 exposure/scan_fleet.py hosts.txt
```

The checkers never send exploit payloads. The remote mode only reads the PHP
version a host advertises in headers; a hidden version returns `UNKNOWN`, which
is not a clean bill of health. The local audit reads the PHP CLI's
configuration; FPM pools and Apache can load different settings, so confirm
those where they are defined.

Over HTTP, the advertised version is the only signal for PHP2Shell itself: the
bugs cannot be confirmed remotely without exploiting them. `exposure/php2shell_scan.py`
adds two active, non-destructive checks (whether your edge rule blocks the
upload-progress field, and the older upload-progress + LFI chain, which is a
separate issue); see [`exposure/README.md`](exposure/README.md).

## Apply the mitigation fast

```bash
sudo mitigations/quick-fix/run.sh --check     # report current state
sudo mitigations/quick-fix/run.sh --dry-run   # preview changes
sudo mitigations/quick-fix/run.sh             # apply (session.upload_progress.enabled = 0)
sudo mitigations/quick-fix/run.sh --revert    # undo
```

The quick fix covers one of PHP's three configuration stopgaps. Set the other
two yourself, administratively, and restart every PHP worker:

| Setting | Removes | Cost |
| --- | --- | --- |
| `session.upload_progress.enabled = 0` (quick fix) | The session upload-progress case of CVE-2026-109619 | Upload progress bars |
| `fatal_error_backtraces = 0` (PHP 8.5 only) | The backtrace case of CVE-2026-109619 | Backtraces in fatal-error logs |
| `memory_limit = -1` | The controllable OOM behind CVE-2026-109618 | One request can use all RAM; put a container/cgroup limit in its place and restore the limit after patching |

None of these is a complete mitigation. Do not use `RLIMIT_AS`/`RLIMIT_DATA`
to cap memory: they make allocations fail and trigger the vulnerable
`longjmp()` path. Then add the WAF/edge rule for your front end from
`mitigations/` and reload.

## If you are exposed

1. **Patch PHP** to the fixed release for your branch — the only complete fix.
2. Until you can patch, apply `mitigations/` (the configuration stopgaps above
   in `php.ini`/the FPM pool, plus the WAF/edge rules). For exposed high-risk
   hosts, consider a read-only posture at the web server (reject anything but
   GET/HEAD); an application's own maintenance mode does not help, because the
   bugs trigger before application code runs.
3. Enable the `hunting/` signals and review logs for the disclosure-day window
   and for PHP workers spawning shells/interpreters.

## Validate the toolkit in a lab

See [`lab/`](lab/): an isolated, internet-blocked Docker target running an
unpatched PHP so you can confirm the checker reports `VULNERABLE`, your WAF rules
block the trigger, and your log/IDS signals fire — then flip the image to a
patched tag and watch it go `PATCHED`.

## Responsible use

Use only against systems you own or are explicitly authorized to test. Do not
point the remote/fleet checker at third-party hosts. See [`SECURITY.md`](SECURITY.md).

## References

- PHP security advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- CVE records: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618), [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- Upstream fix: [php/php-src@31c0ea7d7](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
- [Tenable — PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Sansec — PHP2Shell research](https://sansec.io/research/php2shell)
- Cloudflare, Wiz Research and Malwarebytes Labs coverage (2026-10-21)
- Write-up: [PHP2Shell in depth](https://euriconicacio.github.io/blog/php2shell-in-depth/)

## License

MIT © 2026 Eurico Nicacio. See [`LICENSE`](LICENSE).
