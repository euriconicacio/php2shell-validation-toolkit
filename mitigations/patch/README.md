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

1. Get `php-src` and check out the `php-X.Y.Z` tag of the fixed release on your
   branch. On the 8.5 branch the fix for both CVEs is a single commit,
   [`31c0ea7d7`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065),
   "Avoid state corruption via bailout".
2. What it changes: running out of memory no longer bails out with `longjmp()`
   (a delayed OOM is raised at the next VM safe point, with a hard limit,
   `memory_hard_limit_percent`, that ends the process); globals that the next
   request could read before initialization are cleared at the end of shutdown;
   and the session upload-progress handler no longer instantiates objects while
   decoding a session during startup. See `../../docs/TECHNICAL.md`.
3. Rebuild, run the PHP test suite, then restart PHP-FPM / the web server.
4. Re-run `../../exposure/check_php2shell.sh` and confirm it reports `PATCHED`
   (the fix marker `memory_hard_limit_percent` should now exist).

## End-of-life branches (PHP <= 8.1)

There is no release. Options, in order of preference:

1. Migrate to a supported, patched branch.
2. For 7.4 – 8.1, use your distribution's or LTS vendor's patched package, or
   PHP's minimal source backport for that branch, reviewed and rebuilt.
3. For 5.4 – 7.3 there is no fix from PHP. Apply the configuration and WAF
   mitigations in this repo and isolate the host until you can migrate.

Always diff and review any patch against the official upstream fix before
building a production binary.
