#!/usr/bin/env bash
#
# AuditXS — checks/10-updates.sh
# Category: Updates — keeping the system patched is the single most
# effective baseline control.
#

register_check "UPD-001" "Updates" "medium" "server,workstation" \
    "No pending package updates"
set_meta UPD-001 desc "Counts package updates pending in the package manager's cache. Unpatched software is the most common initial access vector; known vulnerabilities in outdated packages are actively exploited. The fix applies the pending updates — but only after taking a Timeshift system snapshot, because package upgrades cannot be undone by the AuditXS snapshot engine."
set_meta UPD-001 fix "Takes a Timeshift system snapshot ('AuditXS pre-update …'), then applies all pending updates with the distribution package manager. Timeshift is REQUIRED so the change stays recoverable; if it is not installed/configured the fix declines with guidance. You can also run 'sudo auditxs update' directly."
set_meta UPD-001 revert "This is the one fix NOT reversed by 'auditxs rollback' — a package upgrade is not something the snapshot engine can undo. Instead restore the Timeshift snapshot taken just before it: 'sudo timeshift --restore' (or 'sudo timeshift --list' to choose)."

audit_UPD_001() {
    local n
    n=$(pending_updates)
    if [ "$n" = "?" ]; then
        DETAIL="Could not determine pending updates on this system"
        return 2
    fi
    if [ "$n" -eq 0 ]; then
        DETAIL="No pending updates in the package cache"
        return 0
    fi
    DETAIL="$n package update(s) pending (based on the local package cache). Fix applies them after a Timeshift snapshot; or run 'sudo auditxs update'."
    return 2
}

# The update fix is deliberately gated on Timeshift: package upgrades are not
# reversible by 'auditxs rollback', so we only apply them inside the (otherwise
# fully reversible) harden flow when Timeshift can snapshot the system first.
fix_UPD_001() {
    if ! timeshift_available; then
        DETAIL="Timeshift is not installed — required so the update stays reversible. Install it (sudo auditxs tools install timeshift) and run 'sudo timeshift --create' once, or apply updates with 'sudo auditxs update'."
        return 1
    fi
    if ! timeshift_configured; then
        DETAIL="Timeshift is installed but not configured. Run 'sudo timeshift --create' once to choose a backup device, then re-run this fix."
        return 1
    fi
    timeshift_snapshot "AuditXS pre-update (UPD-001 fix)" || {
        DETAIL="Timeshift snapshot failed — update aborted to stay recoverable (see AX5006)."
        return 1
    }
    if _update_apply all; then
        DETAIL="Pending updates applied after a Timeshift snapshot. Roll back with 'sudo timeshift --restore' if needed; a reboot may be required (UPD-003)."
        return 0
    fi
    DETAIL="Package manager reported an error while updating (see AX5005). The Timeshift snapshot is available to restore."
    return 1
}

register_check "UPD-002" "Updates" "high" "server,workstation" \
    "Automatic security updates are enabled"
set_meta UPD-002 desc "Verifies that the distribution's automatic (security) update mechanism is installed and enabled: unattended-upgrades on Debian/Ubuntu/Pop!_OS, dnf-automatic on Fedora. Automatic security updates close the window between a patch being released and it being applied. On Arch and openSUSE there is no official unattended mechanism, so this check only advises."
set_meta UPD-002 fix "Debian family: installs the 'unattended-upgrades' package and writes /etc/apt/apt.conf.d/20auto-upgrades enabling daily list updates and unattended security upgrades. Fedora: installs 'dnf-automatic' and enables the dnf-automatic.timer systemd unit. No other update behaviour is changed."
set_meta UPD-002 revert "The snapshot records the previous content of 20auto-upgrades (or that it did not exist) and the previous state of dnf-automatic.timer. 'sudo auditxs rollback' restores both; packages installed by AuditXS are offered for removal during rollback."

audit_UPD_002() {
    case $DISTRO_FAMILY in
        debian)
            if ! pkg_installed unattended-upgrades; then
                DETAIL="Package 'unattended-upgrades' is not installed"
                return 1
            fi
            local v
            v=$(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/.*"\(.*\)".*/\1/p')
            if [ "$v" = "1" ]; then
                DETAIL="unattended-upgrades installed and APT::Periodic::Unattended-Upgrade=1"
                return 0
            fi
            DETAIL="unattended-upgrades is installed but not enabled (APT::Periodic::Unattended-Upgrade=${v:-unset})"
            return 1
            ;;
        redhat)
            if ! pkg_installed dnf-automatic; then
                DETAIL="Package 'dnf-automatic' is not installed"
                return 1
            fi
            if svc_enabled dnf-automatic.timer; then
                DETAIL="dnf-automatic.timer is enabled"
                return 0
            fi
            DETAIL="dnf-automatic is installed but dnf-automatic.timer is not enabled"
            return 1
            ;;
        arch)
            DETAIL="Arch has no official unattended-update mechanism (partial upgrades are unsupported). Update regularly with 'pacman -Syu' and subscribe to https://archlinux.org/feeds/news/"
            return 2
            ;;
        suse)
            DETAIL="Configure automatic online updates via YaST ('Online Update Configuration') or a systemd timer running 'zypper patch'. AuditXS does not change this automatically."
            return 2
            ;;
        *)
            DETAIL="Unsupported distribution family"
            return 3
            ;;
    esac
}

fix_UPD_002() {
    case $DISTRO_FAMILY in
        debian)
            pkg_install unattended-upgrades || return 1
            local f=/etc/apt/apt.conf.d/20auto-upgrades
            track_file "$f"
            write_file "$f" 0644 '// AuditXS UPD-002 — enable unattended security upgrades.
// Revert with: sudo auditxs rollback <snapshot>
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
            ;;
        redhat)
            pkg_install dnf-automatic || return 1
            enable_unit dnf-automatic.timer
            ;;
        *)
            DETAIL="No automatic fix on this distribution"
            return 1
            ;;
    esac
}

register_check "UPD-003" "Updates" "medium" "server,workstation" \
    "No reboot pending to activate updates"
set_meta UPD-003 desc "Detects when installed updates (typically a new kernel or core libraries) require a reboot to actually take effect. Until the reboot, the system keeps running the old, vulnerable code. Report-only: AuditXS never reboots a system."

audit_UPD_003() {
    case $DISTRO_FAMILY in
        debian)
            if [ -f /var/run/reboot-required ]; then
                DETAIL="Reboot required: $(tr -d '\n' < /var/run/reboot-required 2>/dev/null)$( [ -f /var/run/reboot-required.pkgs ] && printf ' (%s)' "$(sort -u /var/run/reboot-required.pkgs | tr '\n' ' ')" )"
                return 2
            fi
            DETAIL="No reboot pending"
            return 0
            ;;
        redhat)
            if have needs-restarting; then
                if needs-restarting -r >/dev/null 2>&1; then
                    DETAIL="No reboot pending"
                    return 0
                fi
                DETAIL="'needs-restarting -r' reports that a reboot is required"
                return 2
            fi
            DETAIL="Install 'dnf-utils' (needs-restarting) to detect pending reboots"
            return 3
            ;;
        *)
            # Generic heuristic: newest installed kernel modules vs the running kernel.
            local running latest
            running=$(uname -r)
            latest=$(ls -1 /lib/modules 2>/dev/null | sort -V | tail -n1)
            if [ -n "$latest" ] && [ "$latest" != "$running" ]; then
                DETAIL="Running kernel $running but $latest is installed — reboot to activate it"
                return 2
            fi
            DETAIL="Running the newest installed kernel ($running)"
            return 0
            ;;
    esac
}
