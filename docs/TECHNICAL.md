# PHP2Shell — technical summary (CVE-2026-109618 / CVE-2026-109619)

Compiled from PHP's own security advisories,
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
and the upstream fix
[`31c0ea7d7`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065).
PHP is the CNA for both identifiers. Some write-ups published around the
disclosure described the pair differently, or folded older upload-progress
techniques (session-file injection plus a local file inclusion) into the name;
where they disagree, this document follows PHP. It describes the mechanism for
defenders and contains no exploit.

## At a glance

| | |
| --- | --- |
| Name | PHP2Shell |
| CVEs | CVE-2026-109618, CVE-2026-109619 |
| Class | Memory safety in the PHP engine (CWE-416, CWE-824, CWE-755) |
| Severity | CVSS v4.0 9.2 (critical), `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H` |
| Auth | None (pre-authentication) |
| Impact | Remote code execution as the web worker; memory disclosure (CVE-2026-109619) |
| Fixed in | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Disclosed | 2026-10-21 (identifiers leaked 2026-10-20; early attacks and exploitation attempts reported the same day) |

## Background: three engine properties

- **Workers outlive requests.** mod_php, PHP-FPM and FrankenPHP reuse worker
  processes, so anything a worker keeps between requests is shared over time.
- **Request memory is released in bulk.** Each request allocates from a heap
  bounded by `memory_limit`; at the end of the request the heap is released
  wholesale. Anything still pointing into it is dangling.
- **Fatal errors do not unwind.** A fatal error, including running out of
  memory, "bails out" with `longjmp()` to the top of the request, skipping the
  cleanup of every function in progress.

## CVE-2026-109618 — out-of-memory corruption

Some code paths make request memory reachable before it is fully initialized.
If any allocation fails in that window (it does not have to be related), the
OOM bailout leaves the memory half-built, and request shutdown then reads or
branches on it.

Routes to a controllable OOM within PHP's apparent limits, per the advisory:

- a multipart request with no usable declared length passes the
  `post_max_size` check and keeps supplying body data;
- a multipart part can carry an unrestricted number of headers, which cost far
  more memory inside PHP than on the wire;
- empty file controls do not count toward `max_file_uploads` but still build
  the file metadata arrays, and nested field names multiply the work.

Application code that makes large allocations from attacker input can also
reach OOM.

## CVE-2026-109619 — stale global state

Worker globals (error, session, object and extension state) can point into the
current request's heap and must be reset before it is released. A fatal error
can skip the reset, and a late warning during shutdown can repopulate the
state after it was cleared. The heap is then released while a global still
refers to it, and the next request on the same worker reads it before normal
initialization. Exploitation needs a *producer* request and a *consumer*
request on the same worker.

Confirmed cases:

- **PHP 8.5 fatal-error backtraces.** With `fatal_error_backtraces` enabled
  (the 8.5 default), the stored backtrace is never reset during shutdown; a
  diagnostic on the next request reaches it first. Basis of the confirmed
  mod_php exploit.
- **Session upload progress.** The upload-progress handler runs session code
  during request startup, before the session module's normal initialization.
  A request interrupted after publishing session or decoder state (OOM is the
  demonstrated trigger) leaves it pointing into freed memory, and a later
  upload-progress request consumes it. Enabled by default; no `session_start()`
  needed. Validated on mod_php and FPM (on FPM it needs a suitable application
  operation).

Consumers before initialization also include warnings from INI settings
applied per request (`.htaccess` / Apache `php_value` under mod_php,
`PHP_VALUE` from the front end under FPM). The state is read before PHP decides
whether to report the warning, so `@`, `error_reporting`, `display_errors` and
`log_errors` do not protect.

## Exposure by SAPI

| SAPI | CVE-2026-109618 | CVE-2026-109619 |
| --- | --- | --- |
| Apache mod_php | Confirmed RCE with default limits, during body parsing, before application code runs (mod_php runs shutdown even when startup failed) | Confirmed (8.5 backtrace case and session case) |
| PHP-FPM | Susceptible after startup by source analysis; no complete exploit demonstrated. FPM exits a child whose startup fails | Session case validated, needs a suitable application operation; INI consumer only if the front end sends `PHP_VALUE` |
| FrankenPHP | Likely susceptible (runs shutdown unconditionally) | No early INI consumer established in the default setup; others may exist |
| LSAPI | Models FPM; application-specific exploits likely, unvalidated | Conditional candidate (early environment INI values) |

Multiple workers and recycling lower the success rate per request but do not
remove the condition.

## What the fix changed

One commit fixes both on the 8.5 branch:
[`31c0ea7d7`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065),
"Avoid state corruption via bailout" (Arnaud Le Blanc, with Ilija Tovilo, Jakub
Zelenka, Nora Dossche and Nicolas Grekas; 423 files, 306 of them tests).

- **No more OOM bailout.** Crossing `memory_limit` now queues a delayed OOM
  (`EG(delayed_oom)`) and interrupts the VM; the error is raised at the next
  safe point. Code outside the VM, such as `main/rfc1867.c`, checks
  `ZEND_HAS_OOM()` and backs out. Fallible allocators return `NULL`.
- **Hard limit.** New INI `memory_hard_limit_percent` (default `-1`: 200% of
  `memory_limit`, or `memory_limit` + 1 GB above 1 GB). Reaching it prints
  `Hard memory limit of … bytes exhausted …` to stderr and calls `_exit(137)`.
- **Globals cleared at the end of shutdown.** The last error, the
  superglobals and the modules-activated flag are reset after the request heap
  is released ("May be accessed before php_request_startup()"); the session
  module resets its upload-progress flag.
- **Upload-progress hardening.** While the upload-progress handler decodes a
  session during startup, objects stay `__PHP_Incomplete_Class`: no
  autoloading, no `__wakeup()` or `__unserialize()`.

### A local marker for the fix

`memory_hard_limit_percent` only exists in builds that carry the fix. It is in
`main/main.c` at the `php-8.2.35`, `php-8.3.36`, `php-8.4.27` and `php-8.5.12`
tags and absent at `php-8.5.11`. On the official `php` Docker images,
`ini_get("memory_hard_limit_percent")` returns `false` on 8.3.35 and 8.5.11 and
`''` on 8.3.36 and 8.5.12. `exposure/check_php2shell.py` uses this to recognize
a fixed build whose version number did not change, as with distribution
backports. Minimal source backports for EOL branches may not carry the INI, so
its absence there is not proof of exposure.

## Why application-level fixes don't help

The bugs live in the PHP runtime. Updating WordPress, Drupal, plugins or a
framework, or switching on an application's maintenance mode, does not remove
them; on mod_php, CVE-2026-109618 triggers before any application code runs.

## Remediation priority

1. Upgrade PHP to the fixed release for the branch (see `affected-versions.md`).
2. Until then: the configuration stopgaps in `../mitigations/php.ini.hardening.ini`
   (each removes one route; none is complete), the edge rules, and a read-only
   posture at the web server for exposed high-risk hosts.
3. Turn on the detection signals in `../hunting/`.
