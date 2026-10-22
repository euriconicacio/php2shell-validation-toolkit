# PHP2Shell — affected and fixed versions

CVE-2026-109618 / CVE-2026-109619. PHP's advisories bound these by supported
branch only — each with an upper (fixed) version and **no lower bound** — and say
nothing about end-of-life branches. The two CVEs do **not** share a lower bound,
and the widely repeated "PHP 5.4+" floor applies to only one of them. Read
"Where each CVE actually starts" below before judging an old build.

## Fixed releases

| Branch | Status | First fixed release |
| --- | --- | --- |
| 8.5.x | Supported | **8.5.12** |
| 8.4.x | Supported | **8.4.27** |
| 8.3.x | Supported | **8.3.36** |
| 8.2.x | Supported | **8.2.35** |
| 7.4.x – 8.1.x | End-of-life | No release. PHP's security team published minimal source backports for people who build PHP themselves; distributions and LTS vendors received the patches in advance |
| 7.0.x – 7.3.x | End-of-life | No fix and no backport — migrate the branch |

Run below the fixed release on a supported branch → **patch now**. Run an
end-of-life 7.x / 8.1 branch → treat as affected (no upstream fix); apply a vetted
backport where one exists, or migrate.

## Where each CVE actually starts (the lower bound the advisories omit)

**CVE-2026-109618 (OOM state corruption) — PHP 7.x.** The demonstrated corruption
primitive lives in the modern `zend_array` HashTable: `_zend_hash_str_add_or_update_i`
increments `nNumUsed` before `zend_string_init()`, and `zend_array_destroy()` then
walks `arData` up to `nNumUsed`, into the half-built bucket. Those fields are the
PHP 7.0 "phpng" rewrite; they do not exist in any PHP 5.x or 6, whose HashTable is
a linked list of separately allocated buckets with no `nNumUsed` / `arData`. Calif,
the source for the primitive, scopes this RCE to **PHP ≥ 7.3**. So **PHP ≤ 6.x is
not affected by the known 109618 vector.** (Caveat: this is the *demonstrated*
vector. The general OOM-bailout property — a fatal `longjmp()` that skips cleanup —
exists in older PHP too, but no public source has shown a pre-7.x path, and the
specific primitive above cannot be expressed before 7.0. "Not affected by the known
vector", not "proven immune".)

**CVE-2026-109619 (stale worker globals) — PHP 5.4+ for the upload-progress path.**
Its main pre-auth trigger, `session.upload_progress`, was introduced in PHP 5.4.0,
so it does not exist in 5.3 or earlier. The "5.4.0" floor Calif gives is for **this**
path — not for 109618. The 8.5 fatal-error-backtrace route is 8.5-only. Unlike
109618, the dangling-globals *condition* here is memory-model-agnostic: it is present
and structurally identical from `php-5.4.0` through 7.x (the upload-progress handler
decodes the session before `modules_activated`, an OOM fatal skips the session
RSHUTDOWN, and the next request consumes `PS(id)`/`PS(http_session_vars)` from the
freed heap). Turning that UAF into RCE, however, relies on PHP 7.x object/allocator/
`var_unserialize` internals and is not demonstrated on 5.x — so 5.4–5.6 carry the
condition (if `session.upload_progress` is enabled) but their RCE exposure is
uncertain. See `lab/reproduction-php-5.3.15/evidence/08-cve109619-floor-is-5.4.txt`.

**The widely cited "affects PHP 5.4+ / every PHP since 5.4" conflates the two.** It
is the 109619 upload-progress floor applied to the whole pair. For the headline RCE
(109618) the real floor is PHP 7.x; PHP 5.x is implicated only by the 109619
upload-progress path (5.4+), and not at all on 5.3.

**NVD caveat.** The NVD CPE configuration for CVE-2026-109618 lists its oldest range
as `cpe:…:php:php:*` up to `< 8.2.35` with **no lower bound** (`versionStartIncluding`
absent). A scanner reads that as "every PHP below 8.2.35" and sweeps in 7.x and 5.x.
That is a mechanical translation of the branch-only advisory, not a determination
that 5.x was tested or is affected — and it is the usual reason a scanner flags an
EOL PHP 5.x host for 109618. See `lab/reproduction-php-5.3.15/` for the source and
lab evidence that 5.3.15 does not carry the primitive.

## Distribution packages keep their version number

Distributions usually backport the fix without changing the upstream version
(for example, a `8.3.6-…ubuntu…` package). A version comparison then reports
VULNERABLE for a fixed build. `../exposure/check_php2shell.py` also checks for
`memory_hard_limit_percent`, an INI setting that only exists in builds carrying
the fix (see `TECHNICAL.md`), and reports such builds as patched. Verified on
Ubuntu 24.04: `php8.3-cli` `8.3.6-0ubuntu0.24.04.13` (changelog: "Avoid state
corruption via bailout", CVE-2026-109618/109619) reports `PHP_VERSION` 8.3.6,
which a version check flags, and has the directive. For remote hosts only the
advertised version is available, so confirm on the server.

## Notes

- Third-party RPM/DEB repositories may lag the upstream release. Confirm the
  package you install actually contains the fix; do not assume same-day parity.
- Default configuration is enough for the confirmed mod_php exploit of
  CVE-2026-109618 on an affected (7.x+) build. Exposure differs by SAPI (see
  `TECHNICAL.md`): on PHP-FPM no complete exploit of CVE-2026-109618 has been
  shown, and the validated FPM path of CVE-2026-109619 needs a suitable
  application operation. Patch regardless.
- Use `../exposure/check_php2shell.py` / `.sh` to judge a specific install, and
  `../exposure/scan_fleet.py` to sweep many hosts by advertised version. A version
  older than 7.0 is below the 109618 floor; the checker should not report it as
  affected by that CVE on version alone.
