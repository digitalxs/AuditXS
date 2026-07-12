#!/usr/bin/env bash
#
# AuditXS — checks/20-ssh.sh
# Category: SSH — the most attacked remote entry point on Linux systems.
# All checks are skipped when the OpenSSH server is not installed.
# Every fix is written to a clearly-labelled drop-in
# (/etc/ssh/sshd_config.d/99-auditxs.conf), validated with 'sshd -t' and
# automatically restored if validation fails.
#

register_check "SSH-001" "SSH" "critical" "server,workstation" \
    "SSH root login is disabled"
set_meta SSH-001 desc "Checks the effective 'PermitRootLogin' value (via sshd -T). Direct root login is the primary target of SSH brute-force campaigns and removes the audit trail of who logged in. Administrators should log in as a normal user and elevate with sudo."
set_meta SSH-001 fix "Sets 'PermitRootLogin no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates the configuration with 'sshd -t' and reloads the SSH service. If you currently log in as root over SSH, make sure a normal user with sudo works FIRST — auditxs asks before applying and this warning is shown here on purpose."
set_meta SSH-001 revert "The previous SSH configuration is saved in the snapshot; 'sudo auditxs rollback' restores it, re-validates with 'sshd -t' and reloads sshd."

audit_SSH_001() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v
    v=$(sshd_effective permitrootlogin)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration (sshd -T failed)"; return 2; }
    case $v in
        no) DETAIL="PermitRootLogin no"; return 0 ;;
        prohibit-password|without-password)
            DETAIL="Root may still log in with SSH keys (PermitRootLogin $v). Recommended: no — log in as a normal user and use sudo."
            return 1 ;;
        *)  DETAIL="PermitRootLogin is '$v'"; return 1 ;;
    esac
}
fix_SSH_001() { sshd_set PermitRootLogin no && sshd_apply; }

register_check "SSH-002" "SSH" "medium" "server,workstation" \
    "SSH authentication attempts are limited"
set_meta SSH-002 desc "Checks that 'MaxAuthTries' is 4 or lower. A low limit slows down password-guessing over a single connection and creates log noise attackers cannot avoid."
set_meta SSH-002 fix "Sets 'MaxAuthTries 3' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd."
set_meta SSH-002 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot."

audit_SSH_002() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v
    v=$(sshd_effective maxauthtries)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$v" -le 4 ] 2>/dev/null; then
        DETAIL="MaxAuthTries $v"
        return 0
    fi
    DETAIL="MaxAuthTries is $v (recommended: 4 or lower)"
    return 1
}
fix_SSH_002() { sshd_set MaxAuthTries 3 && sshd_apply; }

register_check "SSH-003" "SSH" "critical" "server,workstation" \
    "SSH rejects empty passwords"
set_meta SSH-003 desc "Checks that 'PermitEmptyPasswords' is disabled. Allowing empty passwords over SSH lets anyone log into accounts that have no password set."
set_meta SSH-003 fix "Sets 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd."
set_meta SSH-003 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot."

audit_SSH_003() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v
    v=$(sshd_effective permitemptypasswords)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$v" = "no" ]; then
        DETAIL="PermitEmptyPasswords no"
        return 0
    fi
    DETAIL="PermitEmptyPasswords is '$v'"
    return 1
}
fix_SSH_003() { sshd_set PermitEmptyPasswords no && sshd_apply; }

register_check "SSH-004" "SSH" "low" "server" \
    "SSH X11 forwarding is disabled on servers"
set_meta SSH-004 desc "Checks that 'X11Forwarding' is disabled. Servers rarely need to forward graphical applications; when enabled, a compromised server can attack connecting clients through the X11 channel."
set_meta SSH-004 fix "Sets 'X11Forwarding no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd."
set_meta SSH-004 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot."

audit_SSH_004() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v
    v=$(sshd_effective x11forwarding)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$v" = "no" ]; then
        DETAIL="X11Forwarding no"
        return 0
    fi
    DETAIL="X11Forwarding is '$v'"
    return 1
}
fix_SSH_004() { sshd_set X11Forwarding no && sshd_apply; }

register_check "SSH-005" "SSH" "high" "server" \
    "SSH uses key-based authentication (passwords disabled)"
set_meta SSH-005 desc "Checks whether 'PasswordAuthentication' is disabled. Key-based authentication is immune to password guessing and credential stuffing. SAFETY GUARD: AuditXS will only offer this fix when at least one regular user already has ~/.ssh/authorized_keys — otherwise disabling passwords would lock you out, so it only warns."
set_meta SSH-005 fix "Sets 'PasswordAuthentication no' in /etc/ssh/sshd_config.d/99-auditxs.conf — but ONLY after re-verifying that at least one regular user has an authorized_keys file; the fix refuses to apply otherwise. Validates with 'sshd -t' and reloads sshd. Test key login in a SECOND terminal before closing your current session."
set_meta SSH-005 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot and reloads sshd, re-enabling password login."

users_with_authorized_keys() {
    local count=0 user pass uid gid gecos home shell
    while IFS=: read -r user pass uid gid gecos home shell; do
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uid" -ge 65534 ] && continue
        [ -s "$home/.ssh/authorized_keys" ] && count=$((count + 1))
    done < /etc/passwd
    echo "$count"
}

audit_SSH_005() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v keys
    v=$(sshd_effective passwordauthentication)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$v" = "no" ]; then
        DETAIL="PasswordAuthentication no (key-based login only)"
        return 0
    fi
    keys=$(users_with_authorized_keys)
    if [ "$keys" -gt 0 ]; then
        DETAIL="Password authentication is enabled. $keys regular user(s) already have authorized_keys, so switching to key-only login is possible. Verify key login works in a second session before applying."
        return 1
    fi
    DETAIL="Password authentication is enabled and NO regular user has an authorized_keys file. Set up SSH keys first (ssh-copy-id user@host) — AuditXS will not disable passwords in this state."
    return 2
}

fix_SSH_005() {
    if [ "$(users_with_authorized_keys)" -eq 0 ]; then
        DETAIL="Refused: no regular user has ~/.ssh/authorized_keys — disabling passwords would lock you out"
        return 1
    fi
    sshd_set PasswordAuthentication no && sshd_apply
}

register_check "SSH-006" "SSH" "medium" "server" \
    "Idle SSH sessions are disconnected"
set_meta SSH-006 desc "Checks that 'ClientAliveInterval' (1–900 s) and 'ClientAliveCountMax' (3 or less) are configured so that dead or abandoned SSH sessions are closed instead of staying open indefinitely on unattended terminals."
set_meta SSH-006 fix "Sets 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' (idle sessions are dropped after ~10 minutes) in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd."
set_meta SSH-006 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot."

audit_SSH_006() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local iv cm
    iv=$(sshd_effective clientaliveinterval)
    cm=$(sshd_effective clientalivecountmax)
    [ -z "$iv" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$iv" -ge 1 ] 2>/dev/null && [ "$iv" -le 900 ] 2>/dev/null && [ "$cm" -le 3 ] 2>/dev/null; then
        DETAIL="ClientAliveInterval $iv, ClientAliveCountMax $cm"
        return 0
    fi
    DETAIL="ClientAliveInterval=$iv, ClientAliveCountMax=$cm (recommended: interval 1–900 and count ≤ 3)"
    return 1
}
fix_SSH_006() { sshd_set ClientAliveInterval 300 && sshd_set ClientAliveCountMax 2 && sshd_apply; }

register_check "SSH-007" "SSH" "low" "server,workstation" \
    "SSH login grace time is limited"
set_meta SSH-007 desc "Checks that 'LoginGraceTime' is 60 seconds or less. The grace period holds a connection slot open for unauthenticated clients; long values make denial-of-service against sshd easier."
set_meta SSH-007 fix "Sets 'LoginGraceTime 45' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd."
set_meta SSH-007 revert "'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot."

audit_SSH_007() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local v
    v=$(sshd_effective logingracetime)
    [ -z "$v" ] && { DETAIL="Could not read the effective sshd configuration"; return 2; }
    if [ "$v" -le 60 ] 2>/dev/null && [ "$v" -gt 0 ] 2>/dev/null; then
        DETAIL="LoginGraceTime $v"
        return 0
    fi
    DETAIL="LoginGraceTime is $v (recommended: 60 or less, not 0)"
    return 1
}
fix_SSH_007() { sshd_set LoginGraceTime 45 && sshd_apply; }

register_check "SSH-008" "SSH" "high" "server" \
    "SSH brute-force protection is active (fail2ban/sshguard)"
set_meta SSH-008 desc "Checks that an intrusion-prevention service (fail2ban with an sshd jail, or sshguard) is running to ban IPs that repeatedly fail SSH authentication. Rate-limiting brute-force attempts drastically reduces credential-guessing risk and log noise on exposed servers."
set_meta SSH-008 fix "Installs fail2ban (plus the python systemd bindings it needs to read the journal), writes /etc/fail2ban/jail.d/99-auditxs.conf enabling the sshd jail with 'backend = systemd', and enables + restarts the fail2ban service. Existing fail2ban configuration is not modified — the drop-in only enables the sshd jail. Defaults apply (5 failures → 10 minute ban)."
set_meta SSH-008 revert "'sudo auditxs rollback' removes the jail drop-in, restores the previous service state and offers to remove packages AuditXS installed."

audit_SSH_008() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    has_systemd   || { DETAIL="systemd not detected"; return 3; }
    if svc_active fail2ban.service; then
        if have fail2ban-client && fail2ban-client status 2>/dev/null | grep -qw sshd; then
            DETAIL="fail2ban is running with an sshd jail"
            return 0
        fi
        DETAIL="fail2ban is running but no sshd jail is enabled"
        return 1
    fi
    if svc_active sshguard.service; then
        DETAIL="sshguard is running"
        return 0
    fi
    if pkg_installed fail2ban; then
        DETAIL="fail2ban is installed but not running"
        return 1
    fi
    DETAIL="No SSH brute-force protection detected (fail2ban or sshguard)"
    return 1
}

fix_SSH_008() {
    pkg_install fail2ban || return 1
    # Journal backend bindings — best effort, name differs per family.
    case $DISTRO_FAMILY in
        arch) pkg_install python-systemd  || warn "python-systemd not installed — fail2ban's systemd backend may not work" ;;
        *)    pkg_install python3-systemd || warn "python3-systemd not installed — fail2ban's systemd backend may not work" ;;
    esac
    local f=/etc/fail2ban/jail.d/99-auditxs.conf
    track_file "$f"
    write_file "$f" 0644 "# AuditXS SSH-008 — ban IPs that repeatedly fail SSH authentication.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and restart fail2ban)
[sshd]
enabled = true
backend = systemd" || return 1
    enable_unit fail2ban.service || return 1
    [ "$DRYRUN" = 1 ] || xrun_q systemctl restart fail2ban.service
}
