#!/usr/bin/env bash
#
# AuditXS — checks/92-tooling.sh
# Category: SecurityTools — is the host equipped with the defensive tooling a
# well-run system is expected to have? These checks report presence/health;
# 'auditxs tools install <name>' is the guided, reversible way to add them.
#

register_check "SEC-001" "SecurityTools" "medium" "server,workstation" \
    "A host audit scanner is installed (Lynis)"
set_meta SEC-001 desc "Checks for Lynis, the de-facto open-source host security auditor. Lynis performs hundreds of deep checks that complement AuditXS. Having it available means you can cross-verify hardening and produce an independent report ('auditxs tools scan lynis')."
set_meta SEC-001 fix "Installs 'lynis' from the distribution repositories (recorded for rollback). AuditXS does not run it automatically — use 'auditxs tools scan lynis'."
set_meta SEC-001 revert "'sudo auditxs rollback' offers to remove the package it installed."
set_meta SEC-001 nist "ID.RA-01, DE.CM-08"

audit_SEC_001() {
    if have lynis || pkg_installed lynis; then DETAIL="Lynis is installed ('auditxs tools scan lynis' to run it)"; return 0; fi
    DETAIL="Lynis is not installed — install with 'auditxs tools install lynis' for independent host auditing"
    return 1
}
fix_SEC_001() { pkg_install lynis; }

register_check "SEC-002" "SecurityTools" "medium" "server" \
    "A rootkit / malware detector is installed"
set_meta SEC-002 desc "Checks for a rootkit detector (rkhunter or chkrootkit). These scan for known rootkits, suspicious SUID files, and altered system binaries — a basic detective control on any server. Run via 'auditxs tools scan rkhunter'."
set_meta SEC-002 fix "Installs 'rkhunter' (recorded for rollback) and performs its initial file-property baseline ('rkhunter --propupd') so future scans can detect changes."
set_meta SEC-002 revert "'sudo auditxs rollback' offers to remove the package it installed."
set_meta SEC-002 nist "DE.CM-08, DE.CM-01"

audit_SEC_002() {
    if have rkhunter || have chkrootkit || pkg_installed rkhunter; then
        DETAIL="A rootkit detector is installed ($(have rkhunter && echo rkhunter)$(have chkrootkit && echo ' chkrootkit'))"
        return 0
    fi
    DETAIL="No rootkit detector (rkhunter/chkrootkit) installed"
    return 1
}
fix_SEC_002() {
    pkg_install rkhunter || return 1
    [ "$DRYRUN" = 1 ] || { have rkhunter && xrun_q rkhunter --propupd; }
    return 0
}

register_check "SEC-003" "SecurityTools" "medium" "server" \
    "A file integrity monitor is installed (AIDE)"
set_meta SEC-003 desc "Checks for AIDE (Advanced Intrusion Detection Environment). AIDE records cryptographic hashes of system files so tampering by an intruder is detected at the next check. It is the standard CIS/STIG file-integrity control. Report/installs only — AuditXS does not initialise the database automatically because that can take time and must happen on a known-good system."
set_meta SEC-003 fix "Installs 'aide'. IMPORTANT: after install, initialise the baseline on a trusted system with 'aideinit' (Debian) or 'aide --init', then move the new database into place. AuditXS does not do this for you so the baseline reflects a state you have verified."
set_meta SEC-003 revert "'sudo auditxs rollback' offers to remove the package it installed."
set_meta SEC-003 nist "PR.DS-06, DE.CM-01"

audit_SEC_003() {
    if have aide || have aide.wrapper || pkg_installed aide; then
        local db=""
        [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ] && db=" (database present)"
        DETAIL="AIDE is installed$db"
        return 0
    fi
    DETAIL="No file integrity monitor (AIDE) installed"
    return 1
}
fix_SEC_003() { pkg_install aide aide-common 2>/dev/null || pkg_install aide; }

register_check "SEC-004" "SecurityTools" "low" "server" \
    "An intrusion prevention / IDS engine is present (CrowdSec/Suricata/fail2ban)"
set_meta SEC-004 desc "Checks whether at least one active-defence engine is present: CrowdSec (collaborative IPS), Suricata (network IDS/IPS) or fail2ban (log-based banning). At least one is expected on an internet-facing server to detect and block attacks in progress. Use 'auditxs tools install crowdsec|suricata' for a guided setup."
set_meta SEC-004 nist "DE.CM-01, PR.IR-01"

audit_SEC_004() {
    local found=""
    have cscli && found+="CrowdSec "
    have suricata && found+="Suricata "
    { have fail2ban-client || svc_active fail2ban.service; } && found+="fail2ban "
    if [ -n "$found" ]; then DETAIL="Active-defence engine present: $found"; return 0; fi
    DETAIL="No IDS/IPS engine detected (CrowdSec, Suricata or fail2ban). Install one with 'auditxs tools install crowdsec' (or suricata)."
    return 2
}

# ---------------------------------------------------------------- SEC-005 ---
register_check "SEC-005" "SecurityTools" "low" "server,workstation" \
    "USB device control (USBGuard) is active"
set_meta SEC-005 desc "Checks whether USBGuard is installed and running to allow-list USB devices — a defence against BadUSB / rogue-device attacks at physical ports. Report-only: enable it only after generating a policy from your known-good devices ('auditxs tools install usbguard'), or you can lock out your own keyboard."
set_meta SEC-005 revert "No change is made (report-only)."
audit_SEC_005() {
    if svc_active usbguard.service || svc_active usbguard; then
        DETAIL="USBGuard is active (USB devices are allow-listed)"; return 0
    fi
    if pkg_installed usbguard 2>/dev/null || have usbguard; then
        DETAIL="USBGuard is installed but not active — generate a policy then enable it (see 'auditxs tools install usbguard')"; return 2
    fi
    DETAIL="No USB device control. Optional defence-in-depth for exposed/physical machines: 'auditxs tools install usbguard'."
    return 2
}

# ---------------------------------------------------------------- SEC-006 ---
register_check "SEC-006" "SecurityTools" "low" "server" \
    "A security scan runs on a schedule"
set_meta SEC-006 desc "Checks that a recurring security scan is scheduled (a cron entry or systemd timer for rkhunter, lynis, aide, chkrootkit or 'auditxs schedule'). Installing a scanner is only useful if it actually runs regularly. Report-only."
set_meta SEC-006 revert "No change is made (report-only)."
audit_SEC_006() {
    local found=""
    svc_enabled auditxs-audit.timer 2>/dev/null && found+="auditxs "
    if has_systemd; then
        systemctl list-timers --all 2>/dev/null | grep -qiE 'rkhunter|lynis|aide|chkrootkit|auditxs' && found+="timer "
    fi
    grep -rqsiE 'rkhunter|lynis|aidecheck|aide --check|chkrootkit' "$(axpath /etc/cron.d)" "$(axpath /etc/cron.daily)" "$(axpath /etc/cron.weekly)" 2>/dev/null && found+="cron "
    if [ -n "$found" ]; then
        DETAIL="A scheduled security scan is present ($found)"; return 0
    fi
    DETAIL="No scheduled security scan found. Schedule one: 'auditxs schedule enable', or a cron/timer for rkhunter/lynis/aide."
    return 2
}
