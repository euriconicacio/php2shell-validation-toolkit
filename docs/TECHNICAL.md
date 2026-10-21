# PHP2Shell — technical summary (CVE-2026-109618 / CVE-2026-109619)

Compiled from public advisories (Cloudflare, Wiz / php2shell.com, Sansec,
Malwarebytes) disclosed 2026-10-21. Root-cause details are still settling
across sources; treat specifics as provisional and defer to the official PHP
advisory. This document describes the mechanism for defenders. It contains no
exploit.

## At a glance

| | |
| --- | --- |
| Names | PHP2Shell |
| CVEs | CVE-2026-109618, CVE-2026-109619 |
| Class | Memory-safety (use-after-free) in PHP core |
| Severity | CVSS v4.0 9.2 (critical) |
| Auth | None (pre-authentication) |
| Impact | Remote code execution, worker-memory disclosure |
| Affected | PHP core; both mod_php and PHP-FPM; default configs |
| Disclosed | 2026-10-21 (early in-the-wild attacks reported same day) |

## Mechanism (as described publicly)

Both bugs are use-after-free conditions. A fatal error mid-request — commonly
an out-of-memory when a request exceeds `memory_limit` — can halt native code
before it finishes cleaning up. Memory that should have been released is later
referenced, by cleanup code or by a subsequent request handled by the same
reused worker, as if it were still valid.

- **CVE-2026-109618 — upload-progress unserializer UAF.** The rfc1867 upload
  handler in `ext/session` caches raw `zval *` pointers into a session hash
  table. A timed stall between multipart chunks can cause the session to be
  re-initialized and that table freed while the cached pointers still reference
  it. Consequences include remote memory disclosure (freed worker memory
  returned via the `PHPSESSID` cookie, potentially exposing passwords, session
  tokens, API keys, even TLS private keys) and code execution. Reported to be
  reachable even when the application never calls `session_start()`.
- **CVE-2026-109619 — fatal-error backtrace UAF + OPcache type confusion.**
  Freed memory referenced during fatal-error backtrace handling, combined with
  an OPcache type-confusion, enables code execution.

The public tool "PHP2Shell" is reported to chain both into a single
unauthenticated exploit.

## Trigger surface

- `multipart/form-data` requests are the known trigger surface.
- The upload-progress path is enabled by default
  (`session.upload_progress.enabled = On`).
- Memory pressure (requests near/over `memory_limit`) is part of the trigger.

## Why app-level fixes don't help

The bugs live in the PHP runtime, not in applications. Updating WordPress,
Drupal, plugins, or using a framework maintenance mode does not remove them.
Applications reported as exploitable in public testing span Magento, WordPress,
Drupal, Joomla, MediaWiki, Roundcube, phpMyAdmin, Nextcloud, Laravel, Symfony,
and WHMCS — i.e. the stack, not any single app.

## Remediation priority

1. Upgrade PHP to the fixed release for the branch (see `affected-versions.md`).
2. Until then: disable `session.upload_progress`, add WAF/edge rules, consider
   read-only/maintenance posture for exposed high-risk hosts.
3. Turn on the detection signals in `../hunting/` and review logs for the
   disclosure-day window.
