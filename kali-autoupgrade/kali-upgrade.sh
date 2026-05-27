#!/usr/bin/env bash
#
# Simple Kali Linux autoupgrade script
# Target: Kali GNU/Linux Rolling (2026.1)
#
# Performs: update → upgrade → full-upgrade (dist-upgrade) → autoremove → autoclean
#
# Usage:
#   sudo ./kali-upgrade.sh           # interactive (asks for confirmation)
#   sudo ./kali-upgrade.sh -y        # non-interactive (auto-confirm)
#   sudo ./kali-upgrade.sh --yes
#
# Recommended: place in ~/bin and run manually, or wire to a systemd timer.
#

set -euo pipefail

# --- Config -------------------------------------------------------------------
LOGFILE="${HOME}/kali-upgrade.log"
YES_MODE=false

# --- Argument parsing ---------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)
            YES_MODE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-y|--yes]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-y|--yes]"
            exit 1
            ;;
    esac
done

# --- Helpers ------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

confirm() {
    if $YES_MODE; then
        return 0
    fi
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# --- Pre-flight checks --------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
    echo "ERROR: apt not found. This script is for Debian-based systems only." >&2
    exit 1
fi

# Verify this is Kali (optional but friendly)
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "kali" ]]; then
        echo "WARNING: This system reports as ${PRETTY_NAME:-unknown}. Script is tuned for Kali."
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
fi

# --- Main ---------------------------------------------------------------------
: > "$LOGFILE"   # truncate log for this run
log "Starting Kali system upgrade on $(hostname)"

echo
echo "=== Kali System Upgrade ==="
echo "Log: $LOGFILE"
echo

# 1. Update package lists
log "Running: apt update"
apt update 2>&1 | tee -a "$LOGFILE"

echo
# Show what can be upgraded (nice for user)
echo "Packages that can be upgraded:"
apt list --upgradable 2>/dev/null | tail -n +2 || echo "  (none or unable to list)"

echo

# 2. Upgrade (safe, no new packages)
if confirm "Proceed with 'apt upgrade'?"; then
    log "Running: apt upgrade"
    if $YES_MODE; then
        DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1 | tee -a "$LOGFILE"
    else
        apt upgrade 2>&1 | tee -a "$LOGFILE"
    fi
else
    log "Skipped: apt upgrade"
fi

echo

# 3. Full upgrade (dist-upgrade equivalent - handles dependency changes)
if confirm "Proceed with 'apt full-upgrade' (dist-upgrade)?"; then
    log "Running: apt full-upgrade"
    if $YES_MODE; then
        DEBIAN_FRONTEND=noninteractive apt full-upgrade -y 2>&1 | tee -a "$LOGFILE"
    else
        apt full-upgrade 2>&1 | tee -a "$LOGFILE"
    fi
else
    log "Skipped: apt full-upgrade"
fi

echo

# 4. Autoremove
if confirm "Proceed with 'apt autoremove'?"; then
    log "Running: apt autoremove"
    if $YES_MODE; then
        DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>&1 | tee -a "$LOGFILE"
    else
        apt autoremove 2>&1 | tee -a "$LOGFILE"
    fi
else
    log "Skipped: apt autoremove"
fi

echo

# 5. Autoclean (good hygiene - remove old .deb files from cache)
if confirm "Proceed with 'apt autoclean'?"; then
    log "Running: apt autoclean"
    apt autoclean 2>&1 | tee -a "$LOGFILE"
else
    log "Skipped: apt autoclean"
fi

echo

# --- Post-upgrade checks ------------------------------------------------------
log "Upgrade run completed."

if [[ -f /var/run/reboot-required ]]; then
    echo ">>> REBOOT REQUIRED <<<<"
    echo "    Reason: $(cat /var/run/reboot-required 2>/dev/null || echo 'unknown')"
    echo "    Run: sudo reboot"
    log "REBOOT REQUIRED"
else
    echo "No reboot required."
fi

echo
echo "Upgrade finished. Review the log at: $LOGFILE"
log "Script finished successfully"

exit 0
