# PHP2Shell — FAQ (CVE-2026-109618 / CVE-2026-109619)

**What is PHP2Shell?**
Two critical, pre-authentication use-after-free vulnerabilities in PHP core,
disclosed 2026-10-21, rated CVSS 9.2. Chained, they allow unauthenticated
remote code execution and worker-memory disclosure.

**Is my site affected if I run WordPress / Laravel / Magento?**
The bug is in PHP itself, not the app. If the PHP runtime under any of them is
unpatched, you are affected. Updating the app or plugins does not fix it.

**I disabled `session.upload_progress`. Am I safe?**
No. Public advisories say that alone is not sufficient. It reduces exposure but
you still need to patch. Combine config mitigation + WAF rules until patched.

**How do I check if I'm vulnerable?**
Run `exposure/check_php2shell.py` (or `.sh`) locally, `--version X.Y.Z` to judge a
version string, or `exposure/scan_fleet.py` for many hosts by advertised version.
These are safe checks and send no exploit traffic.

**The remote check says UNKNOWN. Does that mean I'm safe?**
No. It means the host hides its PHP version in headers. Check the version on the
server itself.

**Is there a public exploit?**
Yes, public proof-of-concept exploit code exists elsewhere, and attacks were
seen in the wild on disclosure day. This repo deliberately does not ship a
weaponized exploit; its job is to help you validate exposure and defend.

**What's the real fix?**
Upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or later on your branch).
Everything else here is a stopgap.

**I'm on PHP 8.1 or older.**
No official patch exists. Migrate to a supported branch. Until then, apply the
config and WAF mitigations and isolate the host from the internet.

**Should I set `memory_limit = -1`?**
Be careful. Some advisories mention it because the UAF is OOM-triggered, but
removing the cap lets a single request exhaust server RAM (a DoS risk). If used
at all, monitor memory and restore a sane limit the moment you patch.
