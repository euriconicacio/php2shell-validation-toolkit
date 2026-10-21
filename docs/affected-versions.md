# PHP2Shell — affected and fixed versions

CVE-2026-109618 / CVE-2026-109619. Per public advisories, the vulnerable code
dates back to PHP 5.4.0, so effectively every currently deployed PHP branch is
affected in its default configuration (both mod_php and PHP-FPM).

## Fixed releases

| Branch | Status | First fixed release |
| --- | --- | --- |
| 8.5.x | Supported | **8.5.12** |
| 8.4.x | Supported | **8.4.27** |
| 8.3.x | Supported | **8.3.36** |
| 8.2.x | Supported | **8.2.35** |
| 8.1.x | End-of-life | No official fix — upgrade the branch |
| 8.0.x and older | End-of-life | No official fix — upgrade the branch |

Run below the fixed release on a supported branch → **vulnerable, patch now**.
Run an EOL branch → **vulnerable, migrate to a supported branch**.

## Notes

- Third-party RPM/DEB repositories may lag the upstream release. Confirm the
  package you install actually contains the fix; do not assume same-day parity.
- "Default configuration is vulnerable" — you do not need any unusual settings
  to be exposed.
- Use `../exposure/check_php2shell.py` / `.sh` to judge a specific install, and
  `../exposure/scan_fleet.py` to sweep many hosts by advertised version.
