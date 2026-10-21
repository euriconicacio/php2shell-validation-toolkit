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
      verdict="VULNERABLE"  # EOL, no official fix
      echo "[VULNERABLE] PHP ${VER} is end-of-life. No official patch. Upgrade."
    else
      echo "[UNKNOWN] No fixed-release data for branch ${MAJOR}.${MINOR}. Check the PHP advisory."
    fi
    ;;
esac

case "$verdict" in
  VULNERABLE)
    if [ "${MAJOR}.${MINOR}" = "8.2" ] || [ "${MAJOR}.${MINOR}" = "8.3" ] || \
       [ "${MAJOR}.${MINOR}" = "8.4" ] || [ "${MAJOR}.${MINOR}" = "8.5" ]; then
      echo "[VULNERABLE] PHP ${VER} is below the fixed release for its branch. Update now."
    fi
    ;;
  PATCHED) echo "[PATCHED] PHP ${VER} is at or above the fixed release for its branch." ;;
esac

echo
echo "Configuration audit:"
UP="$(php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null || echo '?')"
if [ "$UP" = "1" ]; then
  echo "  - session.upload_progress.enabled is ON (default) -> feeds the CVE-2026-109618 path."
  echo "    Interim mitigation: set it to 0 in php.ini or the FPM pool (NOT .user.ini)."
else
  echo "  - session.upload_progress.enabled = '${UP}' (0/empty = interim mitigation in place)."
fi
MEM="$(php -r 'echo ini_get("memory_limit");' 2>/dev/null || echo '?')"
echo "  - memory_limit = ${MEM} (informational; patching is the only real fix)."

[ "$verdict" = "PATCHED" ] && exit 0 || exit 1
