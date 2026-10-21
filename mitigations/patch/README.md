# Source patching — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

For environments that build PHP from source or run an end-of-life branch
(8.1 and older) with no official package update.

> This directory intentionally does **not** ship a hand-written C patch.
> Shipping an unverified patch to a memory-safety bug can introduce new bugs.
> Use the upstream fix or a vetted backport, then rebuild and test.

## Preferred: upgrade to a fixed release

The complete, supported fix is a patched PHP build:

| Branch | First fixed release |
| --- | --- |
| 8.5.x | 8.5.12 |
| 8.4.x | 8.4.27 |
| 8.3.x | 8.3.36 |
| 8.2.x | 8.2.35 |

## Building from upstream source

1. Get `php-src` and check out the tag for the fixed release on your branch,
   or cherry-pick the official upstream commits referenced in the PHP
   release announcement for 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
2. The upstream change hardens the `ext/session` rfc1867 upload-progress
   handler so it no longer caches raw `zval *` pointers into the session hash
   table across request teardown (the root of CVE-2026-109618), and fixes the
   fatal-error backtrace / OPcache path behind CVE-2026-109619.
3. Rebuild, run the PHP test suite, then restart PHP-FPM / the web server.
4. Re-run `../../exposure/check_php2shell.sh` to confirm the version flips to
   `PATCHED`.

## End-of-life branches (PHP <= 8.1)

There is no official backport. Options, in order of preference:

1. Migrate to a supported, patched branch.
2. Apply the configuration and WAF mitigations in this repo and isolate the
   host from the internet until you can migrate.
3. If you must stay on an EOL branch, use a **vetted** third-party backport and
   review the diff yourself before building. Do not apply backports blindly.

Always diff and review any patch against the official upstream fix before
building a production binary.
