#!/usr/bin/env bash
# quick-fix/run.sh — PHP2Shell interim mitigation helper
# (CVE-2026-109618 / CVE-2026-109619).
#
# Disables session.upload_progress.enabled by dropping a dedicated .ini file.
# This removes one route, the session upload-progress case of CVE-2026-109619.
# It does not cover CVE-2026-109618 or the PHP 8.5 fatal_error_backtraces case;
# see ../php.ini.hardening.ini for those. This is a STOPGAP. The only complete
# fix is upgrading PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or later on that
# branch).
#
# Usage:
#   sudo ./run.sh --check       # report current state, change nothing
#   sudo ./run.sh --dry-run     # show exactly what would change
#   sudo ./run.sh               # apply the mitigation
#   sudo ./run.sh --revert      # remove the mitigation this script added
#
# Author: Eurico Nicacio
set -euo pipefail

MITIGATION_TAG="php2shell-mitigation (CVE-2026-109618/109619)"
DROPIN_NAME="99-php2shell-mitigation.ini"

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

need_root() {
  if [ "$(id -u)" -ne 0 ] && [ "${MODE}" != "check" ] && [ "${MODE}" != "dry-run" ]; then
    warn "Run with sudo to apply or revert."
    exit 1
  fi
}

current_setting() {
  if command -v php >/dev/null 2>&1; then
    php -r 'echo ini_get("session.upload_progress.enabled") === "" ? "unset" : ini_get("session.upload_progress.enabled");' 2>/dev/null || echo "unknown"
  else
    echo "no-php-cli"
  fi
}

# Discover candidate conf.d directories across common PHP packagings.
dropin_dirs() {
  local dirs=()
  # From loaded php.ini location + scan dir, if the CLI is present.
  if command -v php >/dev/null 2>&1; then
    local scandir
    scandir="$(php -i 2>/dev/null | awk -F'=> ' '/Scan this dir for additional .ini files/{print $2}' | tr -d ' ')"
    [ -n "${scandir:-}" ] && [ -d "$scandir" ] && dirs+=("$scandir")
  fi
  # Common distro locations (FPM pools and mods-available vary; conf.d is safe).
  for g in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cli/conf.d \
           /etc/php.d /usr/local/etc/php/conf.d /etc/php*/conf.d; do
    for dd in $g; do [ -d "$dd" ] && dirs+=("$dd"); done
  done
  # Guard empty-array expansion under `set -u` (portable to bash 3.2).
  if [ "${#dirs[@]}" -gt 0 ]; then
    printf '%s\n' "${dirs[@]}" | awk 'NF' | sort -u
  fi
}

MODE="apply"
case "${1:-}" in
  --check)   MODE="check" ;;
  --dry-run) MODE="dry-run" ;;
  --revert)  MODE="revert" ;;
  "" )       MODE="apply" ;;
  * ) warn "Unknown option: $1"; exit 2 ;;
esac
need_root

echo "PHP2Shell quick-fix  ::  mode=${MODE}"
echo "Current session.upload_progress.enabled = $(current_setting)"
echo

# Portable read into array (avoids `mapfile`, absent on bash 3.2 / macOS).
DIRS=()
while IFS= read -r _d; do
  [ -n "$_d" ] && DIRS+=("$_d")
done < <(dropin_dirs || true)

if [ "${#DIRS[@]}" -eq 0 ]; then
  warn "No PHP conf.d directory found. Edit php.ini manually:"
  warn "    session.upload_progress.enabled = 0"
  [ "$MODE" = "check" ] && exit 0 || exit 1
fi

case "$MODE" in
  check)
    for d in "${DIRS[@]}"; do
      if [ -f "$d/$DROPIN_NAME" ]; then ok "mitigation present: $d/$DROPIN_NAME"
      else log "no mitigation in: $d"; fi
    done
    ;;
  dry-run)
    for d in "${DIRS[@]}"; do
      echo "would write $d/$DROPIN_NAME:"
      echo "    ; ${MITIGATION_TAG}"
      echo "    session.upload_progress.enabled = 0"
    done
    echo
    echo "then reload: systemctl reload php*-fpm  (or restart apache)"
    ;;
  apply)
    for d in "${DIRS[@]}"; do
      printf '; %s\nsession.upload_progress.enabled = 0\n' "$MITIGATION_TAG" > "$d/$DROPIN_NAME"
      ok "wrote $d/$DROPIN_NAME"
    done
    echo
    warn "Reload PHP for changes to take effect, e.g.:"
    warn "    systemctl reload 'php*-fpm'   OR   systemctl restart apache2"
    warn "Then re-run: ../../exposure/check_php2shell.sh"
    warn "This covers one route only; see ../php.ini.hardening.ini for the others."
    ;;
  revert)
    for d in "${DIRS[@]}"; do
      if [ -f "$d/$DROPIN_NAME" ]; then
        rm -f "$d/$DROPIN_NAME"; ok "removed $d/$DROPIN_NAME"
      fi
    done
    warn "Reload PHP to apply the revert."
    ;;
esac
