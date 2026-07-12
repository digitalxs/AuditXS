#!/usr/bin/env bash
#
# AuditXS — checks/90-logging.sh
# Category: Logging — you cannot respond to what you cannot see.
#

register_check "LOG-001" "Logging" "medium" "server,workstation" \
    "System journal is persistent across reboots"
set_meta LOG-001 desc "Checks that systemd-journald stores logs on disk (/var/log/journal) instead of only in memory. With a volatile journal, every reboot — including one forced by an attacker — erases the evidence."
set_meta LOG-001 fix "Creates /var/log/journal and writes /etc/systemd/journald.conf.d/99-auditxs.conf with 'Storage=persistent', then restarts systemd-journald. Existing journald settings in other files are not modified."
set_meta LOG-001 revert "'sudo auditxs rollback' removes the drop-in and restarts journald. The /var/log/journal directory (and logs accumulated in it) is deliberately left in place — deleting logs on rollback would itself be a security problem; remove it manually if desired."

audit_LOG_001() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    local storage
    storage=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | awk -F= '$1=="Storage"{v=$2} END{print v}')
    if [ -d /var/log/journal ] && [ "$storage" != "volatile" ] && [ "$storage" != "none" ]; then
        DETAIL="Persistent journal directory exists (/var/log/journal)"
        return 0
    fi
    if [ "$storage" = "persistent" ]; then
        DETAIL="Storage=persistent is configured"
        return 0
    fi
    DETAIL="Journal is not persistent (Storage=${storage:-auto}, /var/log/journal $( [ -d /var/log/journal ] && echo exists || echo missing))"
    return 1
}

fix_LOG_001() {
    local f=/etc/systemd/journald.conf.d/99-auditxs.conf
    track_file "$f"
    write_file "$f" 0644 "# AuditXS LOG-001 — keep logs across reboots.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>
[Journal]
Storage=persistent" || return 1
    if [ ! -d /var/log/journal ]; then
        record_action note /var/log/journal "absent" "created (kept on rollback — logs are evidence)"
        xrun mkdir -p /var/log/journal || return 1
        have systemd-tmpfiles && xrun_q systemd-tmpfiles --create --prefix /var/log/journal
    fi
    xrun_q systemctl try-restart systemd-journald
}

register_check "LOG-002" "Logging" "high" "server" \
    "The Linux audit daemon (auditd) is installed and running"
set_meta LOG-002 desc "Checks that auditd — the kernel's audit trail collector — is installed, enabled and active. auditd records security-relevant events (authentication, privilege use, file access rules) in a tamper-resistant log that forensic investigation depends on."
set_meta LOG-002 fix "Installs the audit package (auditd/audit depending on distribution) if missing and enables + starts auditd.service. Previous service state and the installed package are recorded."
set_meta LOG-002 revert "'sudo auditxs rollback' restores the previous service state and offers to remove the package if AuditXS installed it."

_audit_pkg_name() {
    case $DISTRO_FAMILY in
        debian) echo auditd ;;
        *)      echo audit ;;
    esac
}

audit_LOG_002() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    if ! pkg_installed "$(_audit_pkg_name)" && ! have auditctl; then
        DETAIL="auditd is not installed"
        return 1
    fi
    if svc_active auditd.service; then
        DETAIL="auditd is running"
        return 0
    fi
    DETAIL="auditd is installed but not running"
    return 1
}

fix_LOG_002() {
    pkg_install "$(_audit_pkg_name)" || return 1
    enable_unit auditd.service
}

register_check "LOG-003" "Logging" "medium" "server" \
    "Baseline audit rules are loaded"
set_meta LOG-003 desc "Checks that auditd has at least a baseline rule set loaded. An audit daemon with zero rules records almost nothing. The AuditXS baseline watches identity files (/etc/passwd, shadow, group), sudoers, SSH server configuration, and (on x86_64) time changes and kernel module loading."
set_meta LOG-003 fix "Writes /etc/audit/rules.d/99-auditxs.rules with the baseline watches described above and loads it with 'augenrules --load'. Existing rules are not modified. Note: if auditd runs in immutable mode (-e 2) a reboot is needed before new rules take effect."
set_meta LOG-003 revert "'sudo auditxs rollback' deletes the rules file and reloads the audit rules."

audit_LOG_003() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    have auditctl || { DETAIL="auditd is not installed — see LOG-002"; return 3; }
    svc_active auditd.service || { DETAIL="auditd is not running — see LOG-002"; return 3; }
    local n
    n=$(auditctl -l 2>/dev/null | grep -cv '^No rules')
    if [ "$n" -gt 0 ]; then
        DETAIL="$n audit rule(s) loaded"
        return 0
    fi
    DETAIL="auditd is running with no rules loaded"
    return 1
}

fix_LOG_003() {
    local f=/etc/audit/rules.d/99-auditxs.rules
    local content="# AuditXS LOG-003 — baseline audit rules.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and run 'augenrules --load')
-w /etc/passwd -p wa -k auditxs-identity
-w /etc/shadow -p wa -k auditxs-identity
-w /etc/group -p wa -k auditxs-identity
-w /etc/gshadow -p wa -k auditxs-identity
-w /etc/sudoers -p wa -k auditxs-sudo
-w /etc/sudoers.d/ -p wa -k auditxs-sudo
-w /etc/ssh/sshd_config -p wa -k auditxs-ssh
-w /etc/ssh/sshd_config.d/ -p wa -k auditxs-ssh"
    if [ "$(uname -m)" = "x86_64" ]; then
        content+="
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k auditxs-time
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k auditxs-modules"
    fi
    track_file "$f"
    write_file "$f" 0640 "$content" || return 1
    if have augenrules; then
        xrun_q augenrules --load || warn "audit rules written but could not be loaded (immutable mode? reboot to apply)"
    fi
    return 0
}

register_check "LOG-004" "Logging" "medium" "server,workstation" \
    "No world-writable log files"
set_meta LOG-004 desc "Checks /var/log for files that any user can modify. World-writable logs let an attacker falsify or destroy the record of their own activity."
set_meta LOG-004 fix "Removes the world-write bit (chmod o-w) from each affected file under /var/log, recording every file's previous mode. Nothing is deleted; read permissions are not changed."
set_meta LOG-004 revert "'sudo auditxs rollback' restores each file's exact previous mode."

_ww_logs() { find /var/log -xdev -type f -perm -0002 2>/dev/null | sort -u; }

audit_LOG_004() {
    [ -d /var/log ] || { DETAIL="/var/log not found"; return 3; }
    local files n
    files=$(_ww_logs)
    if [ -z "$files" ]; then
        DETAIL="No world-writable files under /var/log"
        return 0
    fi
    n=$(echo "$files" | wc -l)
    DETAIL="$n world-writable log file(s):"$'\n'"$(echo "$files" | head -n 10)"
    return 1
}

fix_LOG_004() {
    local f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        record_mode "$f" "o-w"
        xrun chmod o-w "$f" || return 1
    done <<< "$(_ww_logs)"
}
