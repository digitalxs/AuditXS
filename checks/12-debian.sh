#!/usr/bin/env bash
#
# AuditXS — checks/12-debian.sh
# Category: Debian — Debian-family specific hardening (Debian 13 "trixie" and
# derivatives). Skipped on non-Debian systems.
#

_is_debian_family() { [ "$DISTRO_FAMILY" = debian ]; }

register_check "DEB-001" "Debian" "high" "server,workstation" \
    "APT does not accept unauthenticated packages"
set_meta DEB-001 desc "Checks that APT is not configured to install packages that fail signature verification (APT::Get::AllowUnauthenticated and Acquire::AllowInsecureRepositories must not be enabled). Package signatures are what stop a tampered mirror or man-in-the-middle from installing malicious code — turning verification off removes the whole chain of trust behind apt."
set_meta DEB-001 fix "Writes /etc/apt/apt.conf.d/99-auditxs-secure with 'APT::Get::AllowUnauthenticated \"false\";' and 'Acquire::AllowInsecureRepositories \"false\";', re-asserting the secure defaults. Existing apt configuration is not edited."
set_meta DEB-001 revert "'sudo auditxs rollback' deletes the drop-in (or restores its previous content)."
set_meta DEB-001 nist "PR.DS-06, PR.PS-01"

audit_DEB_001() {
    _is_debian_family || { DETAIL="Not a Debian-family system"; return 3; }
    have apt-config || { DETAIL="apt-config not available"; return 3; }
    local unauth insecure
    unauth=$(apt-config dump APT::Get::AllowUnauthenticated 2>/dev/null | sed -n 's/.*"\(.*\)".*/\1/p')
    insecure=$(apt-config dump Acquire::AllowInsecureRepositories 2>/dev/null | sed -n 's/.*"\(.*\)".*/\1/p')
    if [ "${unauth,,}" = "true" ] || [ "${insecure,,}" = "true" ]; then
        DETAIL="APT accepts unauthenticated packages (AllowUnauthenticated=${unauth:-unset}, AllowInsecureRepositories=${insecure:-unset}) — signature verification is weakened."
        return 1
    fi
    DETAIL="APT enforces package signature verification"
    return 0
}

fix_DEB_001() {
    local f=/etc/apt/apt.conf.d/99-auditxs-secure
    track_file "$f"
    write_file "$f" 0644 "// AuditXS DEB-001 — enforce APT package authentication.
// Written by AuditXS $AUDITXS_VERSION on $(date -Is).
// Revert with: sudo auditxs rollback <snapshot>
APT::Get::AllowUnauthenticated \"false\";
Acquire::AllowInsecureRepositories \"false\";"
}

register_check "DEB-002" "Debian" "high" "server,workstation" \
    "The Debian/Ubuntu release still receives security support"
set_meta DEB-002 desc "Compares the running release against the known end-of-life horizon. Debian 13 'trixie' (2025) and Debian 12 'bookworm' are current; releases past end-of-life (Debian ≤ 10, Ubuntu non-LTS past date) stop receiving security patches, so every later vulnerability stays unfixed. Report-only: a distribution upgrade is a major operation AuditXS will not perform for you."
set_meta DEB-002 nist "ID.RA-01, PR.PS-02"

audit_DEB_002() {
    _is_debian_family || { DETAIL="Not a Debian-family system"; return 3; }
    if [ "$DISTRO_ID" = debian ]; then
        local major=${DISTRO_VERSION%%.*}
        case $major in
            13|12) DETAIL="Debian $DISTRO_VERSION (${DISTRO_CODENAME:-current}) is a supported release"; return 0 ;;
            11)    DETAIL="Debian 11 'bullseye' is on LTS/ELTS only — plan an upgrade to 12/13 for full security support"; return 2 ;;
            ""|*[!0-9]*) DETAIL="Could not determine Debian version"; return 2 ;;
            *) if [ "$major" -le 10 ] 2>/dev/null; then
                   DETAIL="Debian $DISTRO_VERSION is END-OF-LIFE — it no longer receives security updates. Upgrade urgently."
                   return 1
               fi
               DETAIL="Debian $DISTRO_VERSION (${DISTRO_CODENAME:-?})"; return 0 ;;
        esac
    fi
    # Ubuntu / Pop!_OS: LTS majors get 5y support; recommend keeping current.
    DETAIL="$DISTRO_NAME — verify this release is still within its security-support window (Ubuntu: prefer LTS; https://ubuntu.com/about/release-cycle)"
    return 0
}

register_check "DEB-003" "Debian" "low" "server" \
    "needrestart reports services needing a restart after upgrades"
set_meta DEB-003 desc "Checks that 'needrestart' is installed. After a library security update, long-running services keep the OLD vulnerable library mapped in memory until restarted; needrestart detects exactly which services need restarting so the patch actually takes effect. Complements the reboot check (UPD-003)."
set_meta DEB-003 fix "Installs the 'needrestart' package. It then runs automatically after apt operations to list (and, interactively, restart) affected services."
set_meta DEB-003 revert "'sudo auditxs rollback' offers to remove the package it installed."
set_meta DEB-003 nist "PR.PS-02, ID.RA-01"

audit_DEB_003() {
    _is_debian_family || { DETAIL="Not a Debian-family system"; return 3; }
    if pkg_installed needrestart || have needrestart; then
        DETAIL="needrestart is installed"
        return 0
    fi
    DETAIL="needrestart is not installed — services may keep running vulnerable libraries after an update until manually restarted"
    return 1
}

fix_DEB_003() { pkg_install needrestart; }
