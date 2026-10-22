# PHP 5.3.15 — scope analysis for CVE-2026-109618 / CVE-2026-109619

Controlled-lab analysis that answers one question: **is PHP 5.3.15 exposed to the
PHP2Shell pair?** It does *not* contain or build an exploit. It combines a source
comparison across PHP versions with a runtime reachability check in a container.

Stack reproduced: PHP 5.3.15 built as `mod_php` on CentOS 6.10 — a typical legacy
deployment of that release — from the official php.net museum tarball.

## Verdict: PHP 5.3.15 is NOT affected by the RCE pair

| CVE | 5.3.15 | Basis |
| --- | --- | --- |
| **CVE-2026-109618** (OOM state corruption → RCE) | **Not affected** | The corruption primitive is PHP 7+ engine internals (see below); PHP 5.3's HashTable does not have it. The multipart OOM is *reachable* on 5.3.15, but on 5.3 that is a fatal error / DoS, not state corruption to RCE |
| **CVE-2026-109619** (stale worker globals → RCE) | **Not affected** | `session.upload_progress` (the pre-auth trigger) was introduced in PHP 5.4.0 and does not exist in 5.3.15 (0 occurrences); `fatal_error_backtraces` is 8.5-only |

This **reverses** an earlier working conclusion that treated 5.3.15 as affected by
CVE-2026-109618. That earlier reasoning stopped at "the OOM is reachable and the
vulnerable parser code is present"; it had not traced the actual corruption
primitive. Once traced, the primitive turns out to be PHP 7+ only. See below.

## Why 5.3.15 is not affected by CVE-2026-109618

The real corruption primitive (from Calif's write-up, calif.io/php2shell):
`_zend_hash_str_add_or_update_i` increments the array's `nNumUsed` /
`nNumOfElements` **before** `zend_string_init()`. If the allocation OOMs and the
engine bails out, the bucket is left half-built, and `zend_array_destroy()` later
walks up to `nNumUsed` and treats the dead bucket as a live value — that is the
corruption request shutdown consumes.

Every part of that primitive is a PHP 7+ construct:

- a **flat `arData` bucket array** with inline values,
- an **`nNumUsed`** high-water counter that destroy walks,
- **`zend_string`**,
- **`zend_array_destroy()`**.

PHP 5.3.15's HashTable (`Zend/zend_hash.h`) is a different design entirely: a
doubly-linked list (`pListHead`/`pListTail`) of **separately allocated** `Bucket`
nodes, with `nNumOfElements` but **no `nNumUsed`** and **no flat `arData`**. A
bucket is allocated in full and *then* linked, so an OOM during an add leaves
nothing walkable — `zend_hash_destroy()` traverses the list, not a used-count.
The "counter bumped before the value is set, destroy walks the dead slot"
primitive cannot arise there. See `evidence/04-primitive-is-php7.txt` for the two
struct definitions side by side.

## What the runtime reproduction does and does not show

**It shows (empirically, not just by code reading):** an unauthenticated HTTP
multipart request drives PHP 5.3.15's body parser to an out-of-memory fault
**before any application code runs** (`Allowed memory size … exhausted … in
Unknown on line 0`; the receiving script never executes). On EOL PHP 5.3 that is
a resource-exhaustion / denial-of-service surface, nothing more.

**It does NOT show, and must not be read as, RCE.** The OOM being reachable is not
the vulnerability; the vulnerability is the state corruption that follows, and
that corruption does not occur on 5.3's memory model. Note also that the same
request returns the same HTTP 500 on the *fixed* 8.3.36 build — the runtime test
proves reachability, never the corruption, on any build.

## External scope signals (all consistent with "5.3 out")

- The official GitHub advisories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp) give
  **no lower bound** — only upper bounds for the supported 8.2–8.5 branches — and
  say nothing about PHP 5.x. PHP, the CNA, has made no claim that 5.x is affected.
- Calif states "the earliest affected path **we found** dates to PHP 5.4.0" — a
  research boundary, not a structural claim — and never mentions 5.3. Calif's own
  text is inconsistent elsewhere (">= 7.3" in one passage).
- The main 109619 pre-auth trigger, `session.upload_progress`, was **introduced in
  PHP 5.4.0** (RFC: wiki.php.net/rfc/session_upload_progress) — a plausible reason
  the floor is quoted as 5.4.
- No independent reproduction reaches below PHP 7.4.33 (devploit/php2shell).
- The only claim of "PHP 5 onward" (watchTowr) is explicitly flagged by its author
  as *not confirmed by any vendor advisory*.

## Evidence

- `evidence/01-source-provenance.txt` — the 5.3.15 tarball (SHA-256) matches the
  `php-5.3.15` git tag byte-for-byte in the five files that matter.
- `evidence/02-code-findings.txt` — the parser OOM routes and the mod_php
  shutdown-after-bailout flow (these establish the *trigger/reachability*, which
  does hold on 5.3; they are not sufficient for the corruption).
- `evidence/03-runtime-evidence.txt` — marker/SAPI probe, the memory_limit→fatal
  demonstration, and the three-build differential (all three OOM identically).
- `evidence/04-primitive-is-php7.txt` — the decisive one: the HashTable struct in
  5.3.15 vs the `_zend_array` struct in 8.3.36, showing the primitive is PHP 7+.
- `evidence/06-primitive-floor-is-php7.0.txt` — the struct across every PHP 5
  release (5.3.15 … 5.6.40) vs 7.0.0: `nNumUsed`/`arData`/`zend_array_destroy`
  first appear at **7.0.0**, so the *whole* PHP 5 branch lacks the substrate, not
  just 5.3.
- `evidence/07-nvd-and-calif-firsthand.txt` — primary sources: Calif scopes the
  hash-table RCE to **PHP ≥ 7.3** (the "5.4.0" everyone repeats is their floor for
  the *upload_progress* path, CVE-2026-109619), and the NVD CPE's unbounded oldest
  range (`< 8.2.35`, no lower bound) is why scanners false-positive PHP 5.x.

## Reproduce

```sh
cd harness
# build the 5.3.15 mod_php image on CentOS 6.10 (needs php-5.3.15.tar.bz2 beside
# the Dockerfile; SHA-256 f9b725659e64228a60883bd134afe1f638900b6b8fa93ba98053095b0892f1ef)
docker build --platform linux/amd64 -t php53lab:5.3.15 .
docker pull php:8.3.0-apache      # pre-fix 8.x control
docker pull php:8.3.36-apache     # fixed control
./difftest.sh                     # brings the three up, runs the test, tears down
```

`difftest.sh` sets `memory_limit=2M` (so OOM is reachable under the default 8M
`post_max_size`), posts a single 7 MB well-formed multipart text field, and
reports the HTTP status and PHP error log for each build. The 7 MB field is an
ordinary large form value, not a crafted corruption payload.

## Corrections this analysis forces on the earlier write-up

1. **"5.3.15 is affected by CVE-2026-109618" is wrong** — retracted here. The OOM
   is reachable, but the corruption primitive is PHP 7+ only.
2. **"5.3.15 is *more* exposed than 5.4" is wrong.** The argument was that
   `fill_buffer` lacks the `post_max_size` guard — but 5.4.0 lacks it too; that
   guard exists only in the fixed 8.x code.
3. The remote checker (`exposure/check_php2shell.py --url`) misreads the version:
   it joins the `Server` and `X-Powered-By` headers and the regex takes the first
   `d.d.d`, which is Apache's version, not PHP's. Against this lab it reported
   "PHP 2.2.15" (Apache/2.2.15) and reached VULNERABLE for the wrong reason.
