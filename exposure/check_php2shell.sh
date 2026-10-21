#!/usr/bin/env bash
# check_php2shell.sh — Safe exposure checker for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619). No exploitation: version + config only.
# Run on systems you own or are authorized to assess.
set -euo pipefail

# First patched release per branch "MAJOR.MINOR:PATCH".
FIXED_8_2=35
FIXED_8_3=36
FIXED_8_4=27
FIXED_8_5=12

if ! command -v php >/dev/null 2>&1; then
  echo "[UNKNOWN] No PHP CLI found on PATH. Check the version on the server directly."
  exit 2
fi

VER="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
MAJOR="$(echo "$VER" | cut -d. -f1)"
MINOR="$(echo "$VER" | cut -d. -f2)"
PATCH="$(echo "$VER" | cut -d. -f3 | tr -dc '0-9')"

echo "PHP2Shell exposure check (CVE-2026-109618 / CVE-2026-109619)"
echo "Local PHP version: $VER"
echo

verdict="UNKNOWN"
case "${MAJOR}.${MINOR}" in
  8.2) [ "${PATCH:-0}" -lt "$FIXED_8_2" ] && verdict="VULNERABLE" || verdict="PATCHED" ;;
  8.3) [ "${PATCH:-0}" -lt "$FIXED_8_3" ] && verdict="VULNERABLE" || verdict="PATCHED" ;;
  8.4) [ "${PATCH:-0}" -lt "$FIXED_8_4" ] && verdict="VULNERABLE" || verdict="PATCHED" ;;
  8.5) [ "${PATCH:-0}" -lt "$FIXED_8_5" ] && verdict="VULNERABLE" || verdict="PATCHED" ;;
  *)
    if [ "${MAJOR}" -lt 8 ] || { [ "${MAJOR}" -eq 8 ] && [ "${MINOR}" -le 1 ]; }; then
      verdict="VULNERABLE"  # EOL, no release
    else
      echo "[UNKNOWN] No fixed-release data for branch ${MAJOR}.${MINOR}. Check the PHP advisory."
    fi
    ;;
esac

# memory_hard_limit_percent only exists in builds carrying the fix
# (php/php-src@31c0ea7d7); ini_get() returns false where it does not exist.
MARKER="$(php -r 'echo ini_get("memory_hard_limit_percent") === false ? "absent" : "present";' 2>/dev/null || echo '?')"
if [ "$verdict" = "VULNERABLE" ] && [ "$MARKER" = "present" ]; then
  verdict="BACKPORT"
elif [ "$verdict" = "PATCHED" ] && [ "$MARKER" = "absent" ]; then
  verdict="UNKNOWN"
  echo "[UNKNOWN] PHP ${VER} is at or above the fixed release, but the fix marker"
  echo "          memory_hard_limit_percent is missing. Check how this PHP was built."
fi

case "$verdict" in
  BACKPORT)
    echo "[PATCHED] PHP ${VER} carries the fix as a backport: memory_hard_limit_percent"
    echo "          exists, and it only exists in fixed builds."
    verdict="PATCHED"
    ;;
  VULNERABLE)
    if [ "${MAJOR}.${MINOR}" = "8.2" ] || [ "${MAJOR}.${MINOR}" = "8.3" ] || \
       [ "${MAJOR}.${MINOR}" = "8.4" ] || [ "${MAJOR}.${MINOR}" = "8.5" ]; then
      echo "[VULNERABLE] PHP ${VER} is below the fixed release for its branch. Update now."
    elif [ "${MAJOR}" -gt 7 ] || { [ "${MAJOR}" -eq 7 ] && [ "${MINOR}" -ge 4 ]; }; then
      echo "[VULNERABLE] PHP ${VER} is end-of-life with no release. PHP published minimal"
      echo "             source backports for 7.4-8.1: check your distribution / LTS vendor."
    else
      echo "[VULNERABLE] PHP ${VER} is end-of-life. No fix from PHP. Upgrade the branch."
    fi
    ;;
  PATCHED) echo "[PATCHED] PHP ${VER} is at or above the fixed release for its branch." ;;
esac

echo "  Fix marker memory_hard_limit_percent: ${MARKER}"
echo
echo "Configuration audit (PHP CLI values; FPM pools and Apache may differ):"
UP="$(php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null || echo '?')"
if [ "$UP" = "1" ]; then
  echo "  - session.upload_progress.enabled is ON (default) -> session case of CVE-2026-109619."
  echo "    Interim stopgap: set it to 0 in php.ini or the FPM pool (NOT .user.ini)."
else
  echo "  - session.upload_progress.enabled = '${UP}' (0/empty = stopgap in place)."
fi
BT="$(php -r '$v = ini_get("fatal_error_backtraces"); echo $v === false ? "n/a" : $v;' 2>/dev/null || echo '?')"
if [ "$BT" = "1" ]; then
  echo "  - fatal_error_backtraces is ON (PHP 8.5 default) -> backtrace case of CVE-2026-109619."
  echo "    Interim stopgap: set it to 0 administratively."
elif [ "$BT" != "n/a" ]; then
  echo "  - fatal_error_backtraces = '${BT}' (0/empty = stopgap in place)."
fi
MEM="$(php -r 'echo ini_get("memory_limit");' 2>/dev/null || echo '?')"
echo "  - memory_limit = ${MEM} (PHP's stopgap for CVE-2026-109618 is -1, with a DoS cost;"
echo "    see mitigations/php.ini.hardening.ini)."

[ "$verdict" = "PATCHED" ] && exit 0 || exit 1
