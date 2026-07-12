#!/usr/bin/env bash
#
# AuditXS — checks/45-privileged.sh
# Category: Privileged — privileged access management: sudo accountability,
# multi-factor authentication, and visibility of administrative accounts.
#

register_check "PRV-001" "Privileged" "medium" "server,workstation" \
    "sudo sessions use a pty and are logged"
set_meta PRV-001 desc "Checks that sudo is configured with 'Defaults use_pty' (prevents a malicious program run under sudo from detaching into the background with root privileges — CIS 5.2.2) and 'Defaults logfile' (a dedicated, append-friendly record of every sudo command — CIS 5.2.3). Privileged-command accountability is a core audit-trail requirement."
set_meta PRV-001 fix "Creates /etc/sudoers.d/99-auditxs (mode 0440) containing only 'Defaults use_pty' and 'Defaults logfile=\"/var/log/sudo.log\"'. The file is validated with 'visudo -cf' and the whole sudo configuration re-validated with 'visudo -c'; if either fails the file is removed immediately. No existing sudoers file is edited."
set_meta PRV-001 revert "'sudo auditxs rollback' deletes the drop-in (or restores its previous content)."
set_meta PRV-001 nist "PR.AA-05, PR.PS-04"

audit_PRV_001() {
    [ -r /etc/sudoers ] || { DETAIL="/etc/sudoers is not readable"; return 3; }
    local missing=""
    grep -rqsE '^[^#]*Defaults[^#]*\buse_pty\b' /etc/sudoers /etc/sudoers.d/ || missing+="use_pty "
    grep -rqsE '^[^#]*Defaults[^#]*\blogfile\b'  /etc/sudoers /etc/sudoers.d/ || missing+="logfile "
    if [ -n "$missing" ]; then
        DETAIL="Missing sudo Defaults: $missing"
        return 1
    fi
    DETAIL="sudo uses a pty and logs to a dedicated logfile"
    return 0
}

fix_PRV_001() {
    have visudo || { DETAIL="visudo not found — is sudo installed?"; return 1; }
    local f=/etc/sudoers.d/99-auditxs
    track_file "$f"
    write_file "$f" 0440 "# AuditXS PRV-001 — sudo accountability.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file)
Defaults use_pty
Defaults logfile=\"/var/log/sudo.log\"" || return 1
    if [ "$DRYRUN" != 1 ]; then
        if ! visudo -cf "$f" >/dev/null 2>&1 || ! visudo -c >/dev/null 2>&1; then
            err "sudoers validation failed — removing the new drop-in."
            emergency_restore_file "$f"
            DETAIL="visudo rejected the change; nothing was modified"
            return 1
        fi
    fi
    return 0
}

register_check "PRV-002" "Privileged" "high" "server" \
    "SSH logins use multi-factor authentication"
set_meta PRV-002 desc "Checks whether SSH requires more than one authentication factor: either 'AuthenticationMethods' chains factors (e.g. 'publickey,keyboard-interactive'), or an MFA PAM module (pam_google_authenticator, pam_u2f, pam_oath, pam_duo) is wired into the sshd stack. MFA is one of the highest-impact controls against credential theft. Report-only: enabling MFA requires enrolling every administrator first — automating it would lock people out, so AuditXS explains the path instead (aligned with NIST CSF PR.AA-03)."
set_meta PRV-002 nist "PR.AA-03"

audit_PRV_002() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }
    local methods pam
    methods=$(sshd_effective authenticationmethods)
    if [ -n "$methods" ] && [ "$methods" != "any" ] && printf '%s' "$methods" | grep -q ','; then
        DETAIL="Multi-factor via AuthenticationMethods: $methods"
        return 0
    fi
    pam=$(grep -lsE '^[^#]*pam_(google_authenticator|u2f|oath|duo)' /etc/pam.d/sshd 2>/dev/null)
    if [ -n "$pam" ]; then
        if [ "$(sshd_effective kbdinteractiveauthentication)" = "yes" ]; then
            DETAIL="MFA PAM module active in the sshd stack"
            return 0
        fi
        DETAIL="An MFA PAM module is configured but KbdInteractiveAuthentication is disabled — the second factor is never asked for"
        return 2
    fi
    if [ "$(sshd_effective passwordauthentication)" = "no" ]; then
        DETAIL="Key-only login (strong single factor). For true MFA: enrol admins with google-authenticator or pam_u2f, then set 'AuthenticationMethods publickey,keyboard-interactive'."
        return 2
    fi
    DETAIL="No MFA detected. Recommended path: install libpam-google-authenticator (or pam_u2f for hardware keys), enrol every admin, add the module to /etc/pam.d/sshd, then set 'AuthenticationMethods publickey,keyboard-interactive' — test in a second session before logging out."
    return 2
}

register_check "PRV-003" "Privileged" "low" "server,workstation" \
    "Administrative account inventory"
set_meta PRV-003 desc "Lists every account with administrative rights: members of the sudo/wheel/admin groups plus explicit user entries in sudoers. Least privilege starts with knowing who holds privilege — review this list regularly and remove anyone who no longer needs it. Informational."
set_meta PRV-003 nist "PR.AA-05, ID.AM-05"

audit_PRV_003() {
    local g members="" extra list
    for g in sudo wheel admin; do
        list=$(getent group "$g" 2>/dev/null | cut -d: -f4)
        [ -n "$list" ] && members+="$g: $list"$'\n'
    done
    extra=$(grep -rhsE '^[^#%]*\bALL\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | awk '{print $1}' | grep -vE '^(Defaults|root|ALL)$' | sort -u | tr '\n' ' ')
    DETAIL="Accounts with administrative rights — review regularly:"$'\n'"${members:-no sudo/wheel/admin group members}"
    [ -n "$extra" ] && DETAIL+="direct sudoers entries: $extra"
    return 0
}
