#!/usr/bin/env bash
#
# deploy.sh
# Single source of truth deployment script for the Kali autoupgrade system.
#
# This script:
#   - Uses `systemctl link` to create symlinks from this repo folder
#     into /etc/systemd/system/ for the unit files.
#   - Symlinks the shell script into ~/bin/ so manual runs use the repo version.
#   - Runs daemon-reload so systemd picks up any changes.
#   - Enables and starts the timer.
#
# Usage:
#   cd ~/Repositories/jacob-kraniak/kali-autoupgrade
#   ./deploy.sh
#
# After any "git pull" (or edits in this folder), re-run this script.
#
# IMPORTANT:
#   Even with symlinks, systemd unit changes require "daemon-reload".
#   This script handles that for you.
#

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$REPO_DIR/kali-upgrade.service"
TIMER_FILE="$REPO_DIR/kali-upgrade.timer"
SCRIPT_FILE="$REPO_DIR/kali-upgrade.sh"

echo "==> Kali Autoupgrade Deploy"
echo "    Source: $REPO_DIR"
echo

# --- Safety checks -----------------------------------------------------------
if [[ ! -f "$SERVICE_FILE" || ! -f "$TIMER_FILE" || ! -f "$SCRIPT_FILE" ]]; then
    echo "ERROR: Required files not found in $REPO_DIR" >&2
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    echo "ERROR: Do not run this script as root. Run it as your normal user." >&2
    exit 1
fi

# --- 1. Clean up any previously copied (non-symlinked) unit files ------------
echo "==> Removing any previously copied unit files (if present)..."
sudo rm -f /etc/systemd/system/kali-upgrade.service
sudo rm -f /etc/systemd/system/kali-upgrade.timer

# --- 2. Create proper symlinks using systemd's "link" command ----------------
echo "==> Linking unit files from repo into /etc/systemd/system/ ..."
sudo systemctl link "$SERVICE_FILE"
sudo systemctl link "$TIMER_FILE"

# --- 3. Make the script available via ~/bin (single source of truth) ---------
echo "==> Symlinking script into ~/bin/ ..."
mkdir -p "$HOME/bin"
ln -sfv "$SCRIPT_FILE" "$HOME/bin/kali-upgrade.sh"

# --- 4. Reload systemd so it notices the (possibly changed) unit files -------
echo "==> Reloading systemd daemon..."
sudo systemctl daemon-reload

# --- 5. Enable and start the timer -------------------------------------------
echo "==> Enabling and starting the timer..."
sudo systemctl enable --now kali-upgrade.timer

echo
echo "==> Deployment complete."
echo

# --- Show status -------------------------------------------------------------
echo "Timer status:"
systemctl --no-pager --full status kali-upgrade.timer || true

echo
echo "Next scheduled runs:"
systemctl list-timers --no-pager | grep -E 'kali|NEXT' || true

echo
echo "Tip: After any 'git pull' in this folder, just run:"
echo "    cd $REPO_DIR && ./deploy.sh"
echo
echo "To view live logs from the upgrade job:"
echo "    journalctl -u kali-upgrade.service -f"
