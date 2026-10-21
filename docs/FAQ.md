# PHP2Shell — FAQ (CVE-2026-109618 / CVE-2026-109619)

**What is PHP2Shell?**
Two critical, pre-authentication memory-safety vulnerabilities in the PHP
engine, published by PHP on 2026-10-21 and rated CVSS v4.0 9.2.
CVE-2026-109618 is out-of-memory corruption; CVE-2026-109619 is stale global
state reused by the next request on the same worker. Each can lead to
unauthenticated remote code execution on its own; CVE-2026-109619 also
discloses memory. See `TECHNICAL.md`.

**Is my site affected if I run WordPress / Laravel / Magento?**
The bug is in PHP itself, not the app. If the PHP runtime under any of them is
unpatched, you are affected. Updating the app or plugins does not fix it, and
neither does the app's maintenance mode.

**I disabled `session.upload_progress`. Am I safe?**
No. It removes one route (the session case of CVE-2026-109619). It does not
touch CVE-2026-109618 or the PHP 8.5 backtrace case. PHP lists three
configuration stopgaps, none complete (see `../mitigations/php.ini.hardening.ini`);
patch.

**How do I check if I'm vulnerable?**
Run `exposure/check_php2shell.py` (or `.sh`) on the server: it checks the
version and whether the build carries the fix (`memory_hard_limit_percent`
exists only in fixed builds, including distribution backports). Use
`--version X.Y.Z` to judge a version string, or `exposure/scan_fleet.py` for
many hosts by advertised version. These checks send no exploit traffic.

**Can a scanner confirm PHP2Shell remotely?**
Not without exploiting it. Over HTTP, the advertised version is the only safe
signal. Tools that report "PHP2Shell confirmed" by injecting text into a session
file and reading it back through a file-inclusion endpoint are testing an older,
separate technique that needs a file-inclusion bug in the application.
`exposure/php2shell_scan.py` keeps that test, labelled as what it is.

**The remote check says UNKNOWN. Does that mean I'm safe?**
No. It means the host hides its PHP version in headers. Check the version on the
server itself.

**Is there a public exploit?**
Code claiming to exploit PHP2Shell is public. At release, PHP said the post-leak
proofs of concept it inspected were not functional exploits of these bugs, and
some public "PHP2Shell" exploits target older upload-progress techniques that
need an application bug. Cloudflare reported early attacks and watchTowr
reported exploitation attempts. This repo deliberately ships no exploit.

**What's the real fix?**
Upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or later on your branch), or
install your distribution's patched package. Everything else here is a stopgap.

**I'm on PHP 8.1 or older.**
There is no release. For 7.4 – 8.1, PHP's security team published minimal source
backports, and distributions / LTS vendors received the patches in advance:
check your vendor. For 5.4 – 7.3 there is no fix from PHP. Until you are on a
fixed build, apply the configuration and WAF mitigations and isolate the host.

**Should I set `memory_limit = -1`?**
It is PHP's primary configuration stopgap for CVE-2026-109618: it removes the
predictable per-request limit the confirmed exploit relies on. It is not
complete, and it lets a single request exhaust server RAM (a DoS risk). If you
use it, set it administratively, put a container or cgroup memory limit in its
place, never `RLIMIT_AS`/`RLIMIT_DATA`, and restore a sane limit after patching.
