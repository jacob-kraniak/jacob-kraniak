# Kali Linux Autoupgrade Scripts

**Development Journal Entry**  
**Date:** May 26, 2026  
**Author:** Jacob Kraniak  
**Hardware Context:** Lenovo ThinkPad X380 Yoga (Kali GNU/Linux Rolling 2026.1)  
**Related Repo:** This documentation lives under `jacob-kraniak` for personal development journaling.

---

## Purpose

Created a simple, safe, and reasonably hardened weekly autoupgrade system for a Kali Linux rolling release machine.

Requested operations:
- `autoremove`
- `update`
- `upgrade`
- `dist-upgrade`

Kali is a rolling distribution used for security work. Automatic upgrades carry real risk (tool breakage, kernel issues, Metasploit/database drift). The goal was **controlled automation** with visibility rather than fully unattended upgrades.

---

## Deliverables

| File                    | Description                                      | Location in this repo      |
|-------------------------|--------------------------------------------------|----------------------------|
| `kali-upgrade.sh`       | Main upgrade script (canonical version)          | (root of this folder)      |
| `kali-upgrade.service`  | systemd oneshot service                          | (root of this folder)      |
| `kali-upgrade.timer`    | Weekly systemd timer                             | (root of this folder)      |
| `deploy.sh`             | Deployment script (sets up symlinks + reload)    | (root of this folder)      |

---

## Architecture: Single Source of Truth via Symlinks

All three files in this folder are the **only** authoritative copies.

- The two systemd unit files are symlinked into `/etc/systemd/system/` using `systemctl link`.
- `kali-upgrade.sh` is symlinked into `~/bin/` for convenient manual execution.
- A `deploy.sh` helper script lives alongside the source files. After any `git pull` (or local edits), you run:

  ```bash
  ./deploy.sh
  ```

This gives you the desired workflow: changes flow from GitHub → this folder → live systemd configuration with a single command, while still requiring the unavoidable `daemon-reload` step.

See the **"Single Source of Truth & GitHub Sync"** section below for full details and caveats.

---

## Design Decisions

- Used **modern `apt full-upgrade`** instead of the legacy `dist-upgrade` command (while still honoring the original request in the script flow).
- Script supports both **interactive** and **non-interactive (`-y`)** modes.
- When run via the timer, it always uses `-y`.
- Logging goes to both:
  - systemd journal (primary when running under the timer)
  - `~/kali-upgrade.log` (or `/root/kali-upgrade.log` when run as root)
- Added post-run detection of `/var/run/reboot-required`.
- systemd unit includes light hardening (`ProtectSystem=full`, `NoNewPrivileges`, lower scheduling priority).
- `Persistent=true` on the timer so missed runs catch up after the laptop wakes.
- `RandomizedDelaySec=45min` to avoid exact weekly thundering herd.
- Kept `ConditionACPower` out of the timer for now (Kali laptop may legitimately need updates on battery).

---

## File Contents

### 1. kali-upgrade.sh

```bash
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
```

---

### 2. kali-upgrade.service

```ini
[Unit]
Description=Kali Linux weekly full system upgrade (update + upgrade + full-upgrade + autoremove)
Documentation=https://www.kali.org/docs/general/upgrade/
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/home/jacob/bin/kali-upgrade.sh -y
User=root
Group=root

# Logging - goes to journalctl
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kali-upgrade

# Be nice to the system (lower priority)
Nice=10
CPUSchedulingPolicy=batch
IOSchedulingClass=best-effort
IOSchedulingPriority=7

# Reasonable security hardening while still allowing apt to function
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

---

### 3. kali-upgrade.timer

```ini
[Unit]
Description=Run Kali full system upgrade weekly
Requires=kali-upgrade.service

[Timer]
# Runs once per week. Default is Sunday at 00:00.
# You can change this to something like "Mon 04:00" or "weekly".
OnCalendar=weekly

# If the system was powered off when the timer should have fired,
# it will run shortly after the next boot.
Persistent=true

# Spread the load a bit (useful if you have multiple machines)
RandomizedDelaySec=45min

[Install]
WantedBy=timers.target
```

---

## Single Source of Truth & GitHub Sync (Recommended Setup)

The canonical copies of all three files live **only in this repository folder**.

We use symlinks so that:

- Running `git pull` (or editing files locally) updates the real source.
- The systemd units and `~/bin/kali-upgrade.sh` point back to this folder.
- After any change from GitHub, one command (`./deploy.sh`) syncs everything and makes systemd aware of the updates.

### Why symlinks + a deploy script?

- `systemctl link` creates proper, managed symlinks from this folder into `/etc/systemd/system/`.
- The shell script is symlinked into `~/bin/` so manual runs also use the version from the repo.
- **Critical limitation**: Even with symlinks, **systemd does not auto-detect changes** to unit files. You **must** run `systemctl daemon-reload` after pulling updates. The `deploy.sh` script does this for you.

This gives you the workflow you asked for: edit/push on GitHub → pull on the laptop → run one script → systemd is updated.

### How to deploy / update after a git pull

```bash
cd ~/Repositories/jacob-kraniak/kali-autoupgrade
./deploy.sh
```

The `deploy.sh` script will:

1. Remove any old copied (non-symlinked) unit files.
2. Use `systemctl link` to create symlinks from this repo into `/etc/systemd/system/`.
3. Symlink `kali-upgrade.sh` into `~/bin/`.
4. Run `systemctl daemon-reload`.
5. Enable and start the timer.
6. Show you the current status and next scheduled run time.

### Switching from the old copied setup to the symlink setup

If you previously installed via `sudo cp`, just run the deploy script once — it will clean up the old files and replace them with symlinks.

### Current symlinks after deployment (example)

```bash
# The unit files in /etc/systemd/system/ should be symlinks:
ls -l /etc/systemd/system/kali-upgrade.*

# Example output:
# lrwxrwxrwx ... /etc/systemd/system/kali-upgrade.service -> /home/jacob/Repositories/jacob-kraniak/kali-autoupgrade/kali-upgrade.service
# lrwxrwxrwx ... /etc/systemd/system/kali-upgrade.timer  -> /home/jacob/Repositories/jacob-kraniak/kali-autoupgrade/kali-upgrade.timer

# The script in your PATH:
ls -l ~/bin/kali-upgrade.sh
# lrwxrwxrwx ... /home/jacob/bin/kali-upgrade.sh -> /home/jacob/Repositories/jacob-kraniak/kali-autoupgrade/kali-upgrade.sh
```

### Important Caveats

- If you ever move this repository folder, the symlinks will break. Re-run `./deploy.sh` after moving.
- The `deploy.sh` script must be run as your normal user (it uses `sudo` internally only where needed).
- Changes to `kali-upgrade.sh` itself take effect on the **next execution** (no reload required).
- Changes to the `.service` or `.timer` files **always** require a `daemon-reload` (handled by the deploy script).

---

## Legacy Installation Notes (old copy-based method)

(Kept for reference — the symlink + `deploy.sh` method above is strongly preferred.)

```bash
# Old copy method (not recommended anymore)
sudo cp kali-upgrade.service /etc/systemd/system/
sudo cp kali-upgrade.timer  /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now kali-upgrade.timer
```

---

## Future Improvements (Journal Notes)

- [x] Use repository folder as single source of truth with symlinks + `deploy.sh` (implemented May 2026)
- [ ] Add `ConditionACPower=true` to the service for laptop use
- [ ] Optional email / Matrix / Discord notification on completion or failure
- [ ] Pre-upgrade snapshot with `timeshift` or `btrfs` (if using BTRFS)
- [ ] Track last successful upgrade date in a small state file
- [ ] Separate "security-only" upgrade path vs full tool upgrade
- [ ] Integrate with `apt-listchanges` or `apticron` style reporting

---

## References

- Official Kali upgrade docs: https://www.kali.org/docs/general/upgrade/
- systemd timer documentation
- Debian `apt` best practices for rolling distributions

---

**Status:** Deployed and documented. Ready for weekly use on the Kali ThinkPad. 

*This entry is part of personal development journaling under the jacob-kraniak GitHub organization.*