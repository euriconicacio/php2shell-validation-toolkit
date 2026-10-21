# PHP2Shell — affected and fixed versions

CVE-2026-109618 / CVE-2026-109619. PHP's advisories list the supported branches
below. Calif's write-up traces the earliest affected code path to PHP 5.4.0, so
older branches should be treated as affected too.

## Fixed releases

| Branch | Status | First fixed release |
| --- | --- | --- |
| 8.5.x | Supported | **8.5.12** |
| 8.4.x | Supported | **8.4.27** |
| 8.3.x | Supported | **8.3.36** |
| 8.2.x | Supported | **8.2.35** |
| 7.4.x – 8.1.x | End-of-life | No release. PHP's security team published minimal source backports for people who build PHP themselves; distributions and LTS vendors received the patches in advance |
| 5.4.x – 7.3.x | End-of-life | No fix from PHP — upgrade the branch, or ask your distribution / LTS vendor |

Run below the fixed release on a supported branch → **vulnerable, patch now**.
Run an EOL branch → **vulnerable**: apply a vetted backport or your vendor's
package, or migrate to a supported branch.

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
  CVE-2026-109618. Exposure differs by SAPI (see `TECHNICAL.md`): on PHP-FPM no
  complete exploit of CVE-2026-109618 has been shown, and the validated FPM path
  of CVE-2026-109619 needs a suitable application operation. Patch regardless.
- Use `../exposure/check_php2shell.py` / `.sh` to judge a specific install, and
  `../exposure/scan_fleet.py` to sweep many hosts by advertised version.
