#!/usr/bin/env bash
#
# AuditXS — checks/65-mac.sh
# Category: MAC — mandatory access control (SELinux / AppArmor).
#
# Deliberately report-only: enabling a MAC system requires kernel command
# line / bootloader changes and a reboot, which AuditXS cannot make safely
# reversible — so it explains the distribution-appropriate path instead.
#

register_check "MAC-001" "MAC" "high" "server,workstation" \
    "A mandatory access control system is active (SELinux/AppArmor)"
set_meta MAC-001 desc "Checks whether SELinux is enforcing or AppArmor is active with loaded profiles. MAC systems confine what a compromised service can do, containing exploits that would otherwise have the full run of the system. Every supported distribution ships one: SELinux on Fedora; AppArmor on Ubuntu, Pop!_OS, Debian and openSUSE (Arch supports AppArmor but does not enable it by default). Report-only: enabling a MAC system needs kernel-parameter/bootloader changes and a reboot, which cannot be made safely reversible — the finding explains the right path for your distribution instead."

audit_MAC_001() {
    local mode profiles
    # SELinux first (authoritative where present)
    if have getenforce; then
        mode=$(getenforce 2>/dev/null)
        case $mode in
            Enforcing)
                DETAIL="SELinux is enforcing"
                return 0 ;;
            Permissive)
                DETAIL="SELinux is in permissive mode — violations are logged but NOT blocked. Set SELINUX=enforcing in /etc/selinux/config and reboot (check 'ausearch -m avc' for denials first)."
                return 2 ;;
        esac
    fi
    # AppArmor
    if [ -d /sys/kernel/security/apparmor ]; then
        profiles=$(wc -l < /sys/kernel/security/apparmor/profiles 2>/dev/null || echo 0)
        if [ "${profiles:-0}" -gt 0 ] 2>/dev/null; then
            DETAIL="AppArmor is active with $profiles profile(s) loaded"
            return 0
        fi
        DETAIL="AppArmor is enabled but no profiles are loaded — install the profile packages (Debian family: 'apparmor-profiles'; openSUSE: 'apparmor-profiles'; Arch: 'apparmor')."
        return 2
    fi
    case $DISTRO_FAMILY in
        redhat)
            DETAIL="SELinux appears disabled. Fedora enables it by default — check /etc/selinux/config (SELINUX=enforcing) and remove any 'selinux=0' kernel parameter, then reboot." ;;
        debian)
            DETAIL="No MAC system is active. Ubuntu and Pop!_OS enable AppArmor by default; on Debian install 'apparmor apparmor-profiles' and add 'apparmor=1 security=apparmor' to the kernel command line, then reboot." ;;
        suse)
            DETAIL="No MAC system is active. openSUSE ships AppArmor by default — ensure the 'apparmor' service is enabled and profiles are installed." ;;
        arch)
            DETAIL="No MAC system is active. On Arch, install 'apparmor', add 'lsm=landlock,lockdown,yama,integrity,apparmor,bpf' to the kernel command line, enable apparmor.service and reboot." ;;
        *)
            DETAIL="No mandatory access control system (SELinux/AppArmor) detected." ;;
    esac
    return 2
}
