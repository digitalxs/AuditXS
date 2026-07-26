#!/usr/bin/env bash
#
# AuditXS — checks/40-accounts.sh
# Category: Accounts — authentication and privilege fundamentals.
#

register_check "ACC-001" "Accounts" "critical" "server,workstation" \
    "Only root has UID 0"
set_meta ACC-001 desc "Scans /etc/passwd for accounts other than 'root' with UID 0. A second UID-0 account is a classic backdoor: it has full root power under an innocent name. Report-only: removing accounts is a decision AuditXS will not automate."

audit_ACC_001() {
    local extra
    extra=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' "$(axpath /etc/passwd)" 2>/dev/null)
    if [ -n "$extra" ]; then
        DETAIL="Additional UID-0 account(s) found: $(echo "$extra" | tr '\n' ' '). Investigate immediately — if unexpected, treat the system as compromised."
        return 2
    fi
    DETAIL="root is the only UID-0 account"
    return 0
}

register_check "ACC-002" "Accounts" "critical" "server,workstation" \
    "No accounts have empty passwords"
set_meta ACC-002 desc "Scans /etc/shadow for accounts whose password field is empty. Such accounts can be logged into without any password at all (locally, and over any service that permits it)."
set_meta ACC-002 fix "Locks each affected account with 'passwd -l <user>' (places a '!' in the password field, blocking password login while leaving the account and its files intact). /etc/shadow is backed up to the snapshot first."
set_meta ACC-002 revert "'sudo auditxs rollback' restores the saved /etc/shadow, returning the accounts to their previous state."

audit_ACC_002() {
    local shadow; shadow=$(axpath /etc/shadow)
    [ -r "$shadow" ] || { DETAIL="/etc/shadow is not readable"; return 2; }
    local empty
    empty=$(awk -F: '($2 == "") {print $1}' "$shadow")
    if [ -n "$empty" ]; then
        DETAIL="Account(s) with EMPTY password: $(echo "$empty" | tr '\n' ' ')"
        return 1
    fi
    DETAIL="No empty-password accounts"
    return 0
}

fix_ACC_002() {
    local u
    track_file /etc/shadow
    for u in $(awk -F: '($2 == "") {print $1}' /etc/shadow); do
        xrun_q passwd -l "$u" || return 1
        say "  locked account: $u"
    done
}

register_check "ACC-003" "Accounts" "medium" "server,workstation" \
    "Password aging policy is configured"
set_meta ACC-003 desc "Checks /etc/login.defs for a sane password aging baseline: PASS_MAX_DAYS ≤ 365, PASS_MIN_DAYS ≥ 1 and PASS_WARN_AGE ≥ 7. This bounds how long a leaked password stays valid and prevents instant password re-use. Applies to newly created accounts; existing accounts keep their current aging until changed with 'chage'."
set_meta ACC-003 fix "Edits /etc/login.defs (backed up first) setting PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7. Existing accounts are NOT modified — the report lists the 'chage' command to update them if you wish."
set_meta ACC-003 revert "'sudo auditxs rollback' restores the saved /etc/login.defs."

_logindefs_val() {
    awk -v k="$1" '$1 == k {print $2}' "$(axpath /etc/login.defs)" 2>/dev/null | tail -n1
}

audit_ACC_003() {
    [ -f "$(axpath /etc/login.defs)" ] || { DETAIL="/etc/login.defs not found"; return 3; }
    local max min warnage bad=""
    max=$(_logindefs_val PASS_MAX_DAYS)
    min=$(_logindefs_val PASS_MIN_DAYS)
    warnage=$(_logindefs_val PASS_WARN_AGE)
    [ -n "$max" ] && [ "$max" -le 365 ] 2>/dev/null || bad+="PASS_MAX_DAYS=${max:-unset} (want ≤365) "
    [ -n "$min" ] && [ "$min" -ge 1 ] 2>/dev/null || bad+="PASS_MIN_DAYS=${min:-unset} (want ≥1) "
    [ -n "$warnage" ] && [ "$warnage" -ge 7 ] 2>/dev/null || bad+="PASS_WARN_AGE=${warnage:-unset} (want ≥7) "
    if [ -n "$bad" ]; then
        DETAIL="$bad— applies to new accounts; update existing ones with: chage --maxdays 365 --mindays 1 --warndays 7 <user>"
        return 1
    fi
    DETAIL="PASS_MAX_DAYS=$max PASS_MIN_DAYS=$min PASS_WARN_AGE=$warnage"
    return 0
}

fix_ACC_003() {
    local max min warnage
    max=$(_logindefs_val PASS_MAX_DAYS)
    min=$(_logindefs_val PASS_MIN_DAYS)
    warnage=$(_logindefs_val PASS_WARN_AGE)
    { [ -n "$max" ] && [ "$max" -le 365 ] 2>/dev/null; } || set_logindefs PASS_MAX_DAYS 365
    { [ -n "$min" ] && [ "$min" -ge 1 ] 2>/dev/null; } || set_logindefs PASS_MIN_DAYS 1
    { [ -n "$warnage" ] && [ "$warnage" -ge 7 ] 2>/dev/null; } || set_logindefs PASS_WARN_AGE 7
}

register_check "ACC-004" "Accounts" "high" "server,workstation" \
    "sudo always requires a password"
set_meta ACC-004 desc "Scans /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries. Passwordless sudo turns any compromise of that user account (or an unlocked terminal) into an instant full-root compromise. Report-only: sudoers changes are risky to automate, so AuditXS shows you exactly which lines to review with 'visudo'."

audit_ACC_004() {
    [ -r /etc/sudoers ] || { DETAIL="/etc/sudoers is not readable"; return 2; }
    local hits
    hits=$(grep -rsHnE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
    if [ -n "$hits" ]; then
        DETAIL="NOPASSWD entries found (review with 'visudo'):"$'\n'"$hits"
        return 2
    fi
    DETAIL="No NOPASSWD entries in sudoers"
    return 0
}

register_check "ACC-005" "Accounts" "medium" "server,workstation" \
    "System accounts cannot log in"
set_meta ACC-005 desc "Checks that system (service) accounts — UID below the regular-user threshold — have a non-login shell such as /usr/sbin/nologin. Service accounts with real shells are convenient footholds after a service compromise."
set_meta ACC-005 fix "Backs up /etc/passwd, then sets the shell of each affected system account to 'nologin' with 'usermod -s'. Regular user accounts and root are never touched."
set_meta ACC-005 revert "'sudo auditxs rollback' restores the saved /etc/passwd, returning the original shells."

_system_accounts_with_shell() {
    local uid_min
    uid_min=$(_logindefs_val UID_MIN)
    uid_min=${uid_min:-1000}
    awk -F: -v m="$uid_min" \
        '($3 > 0 && $3 < m && $1 != "root" && $7 !~ /(nologin|false)$/ && $1 !~ /^(sync|shutdown|halt)$/) {print $1}' \
        "$(axpath /etc/passwd)" 2>/dev/null
}

audit_ACC_005() {
    local bad
    bad=$(_system_accounts_with_shell)
    if [ -n "$bad" ]; then
        DETAIL="System account(s) with a login shell: $(echo "$bad" | tr '\n' ' ')"
        return 1
    fi
    DETAIL="All system accounts use a non-login shell"
    return 0
}

fix_ACC_005() {
    local nlg u
    nlg=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
    [ -x "$nlg" ] || { DETAIL="nologin binary not found"; return 1; }
    track_file /etc/passwd
    for u in $(_system_accounts_with_shell); do
        xrun_q usermod -s "$nlg" "$u" || return 1
        say "  shell of '$u' set to $nlg"
    done
}

register_check "ACC-006" "Accounts" "low" "server" \
    "Default umask is restrictive (027)"
set_meta ACC-006 desc "Checks that the default UMASK in /etc/login.defs is 027 or stricter, so files created by users are not readable by every other account on the system. Applied to the server profile only — on single-user workstations the default 022 is a common and acceptable trade-off."
set_meta ACC-006 fix "Edits /etc/login.defs (backed up first) setting 'UMASK 027'. Only affects newly created login sessions; existing files are not changed."
set_meta ACC-006 revert "'sudo auditxs rollback' restores the saved /etc/login.defs."

audit_ACC_006() {
    [ -f "$(axpath /etc/login.defs)" ] || { DETAIL="/etc/login.defs not found"; return 3; }
    local um
    um=$(_logindefs_val UMASK)
    case $um in
        027|077) DETAIL="UMASK $um"; return 0 ;;
        *)       DETAIL="UMASK is ${um:-unset} (recommended: 027)"; return 1 ;;
    esac
}

fix_ACC_006() { set_logindefs UMASK 027; }

register_check "ACC-007" "Accounts" "medium" "server,workstation" \
    "Password quality requirements are enforced"
set_meta ACC-007 desc "Checks that pam_pwquality is part of the PAM password stack and that the effective minimum password length (minlen, including /etc/security/pwquality.conf.d drop-ins) is at least 12. Without quality rules users can set trivially guessable passwords. The policy applies when passwords are set or changed — existing passwords are not affected."
set_meta ACC-007 fix "Debian family: installs 'libpam-pwquality' (Debian wires it into the PAM stack automatically via pam-auth-update). openSUSE: enables the module with 'pam-config -a --pwquality' (the distribution's supported tool). Then writes /etc/security/pwquality.conf.d/99-auditxs.conf with 'minlen = 12' and 'minclass = 3'. PAM files are never edited directly. On Fedora/Arch with the module missing, AuditXS only reports (PAM stacks there should be changed via authselect / by hand)."
set_meta ACC-007 revert "'sudo auditxs rollback' removes the pwquality drop-in, reverts the pam-config change on openSUSE, and offers to remove the package if AuditXS installed it."

_pwquality_in_pam() { grep -rqsE '^[^#]*pam_pwquality\.so' /etc/pam.d/; }

_pwquality_minlen() {
    local f x v=""
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [ -f "$f" ] || continue
        x=$(sed -n 's/^[[:space:]]*minlen[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$f" | tail -n1)
        [ -n "$x" ] && v=$x
    done
    echo "${v:-8}"   # libpwquality compiled-in default
}

audit_ACC_007() {
    [ -d /etc/pam.d ] || { DETAIL="/etc/pam.d not found"; return 3; }
    if ! _pwquality_in_pam; then
        case $DISTRO_FAMILY in
            debian) DETAIL="libpam-pwquality is not installed (pam_pwquality missing from the PAM stack)"; return 1 ;;
            suse)   DETAIL="pam_pwquality is not enabled in the PAM stack"; return 1 ;;
            redhat) DETAIL="pam_pwquality is not in the PAM stack. Fedora enables it by default — restore it with authselect rather than editing PAM files by hand."; return 2 ;;
            *)      DETAIL="pam_pwquality is not in the PAM stack. Add 'password requisite pam_pwquality.so' to your PAM password stack (e.g. /etc/pam.d/system-auth on Arch) — AuditXS does not edit PAM files."; return 2 ;;
        esac
    fi
    local minlen
    minlen=$(_pwquality_minlen)
    if [ "$minlen" -ge 12 ] 2>/dev/null; then
        DETAIL="pam_pwquality is active with minlen=$minlen"
        return 0
    fi
    DETAIL="pam_pwquality is active but minlen=$minlen (recommended: 12 or more)"
    return 1
}

fix_ACC_007() {
    if ! _pwquality_in_pam; then
        case $DISTRO_FAMILY in
            debian)
                pkg_install libpam-pwquality || return 1 ;;
            suse)
                have pam-config || { DETAIL="pam-config not found"; return 1; }
                record_action pam_config pwquality absent added
                xrun_q pam-config -a --pwquality || return 1 ;;
            *)
                DETAIL="No safe automatic way to edit the PAM stack on this distribution"
                return 1 ;;
        esac
    fi
    if [ "$(_pwquality_minlen)" -lt 12 ] 2>/dev/null; then
        local f=/etc/security/pwquality.conf.d/99-auditxs.conf
        track_file "$f"
        write_file "$f" 0644 "# AuditXS ACC-007 — minimum password quality for new passwords.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file)
minlen = 12
minclass = 3" || return 1
    fi
    return 0
}

# ---- PAM authentication hardening (report-only: a bad PAM edit can lock out
#      every account, so AuditXS never rewrites PAM automatically) -----------
_pam_auth_files()   { local f; for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do [ -f "$(axpath "$f")" ] && echo "$(axpath "$f")"; done; }
_pam_passwd_files() { local f; for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do [ -f "$(axpath "$f")" ] && echo "$(axpath "$f")"; done; }

register_check "ACC-008" "Accounts" "medium" "server,workstation" \
    "Failed logins lock the account (pam_faillock)"
set_meta ACC-008 desc "Checks that PAM locks an account after repeated failed logins (pam_faillock, or legacy pam_tally2). This slows password guessing at the console and for services that use PAM. Report-only — PAM changes are applied manually to avoid lockout risk."
set_meta ACC-008 revert "No change is made (report-only)."
audit_ACC_008() {
    local files; files=$(_pam_auth_files)
    [ -n "$files" ] || { DETAIL="No PAM auth stack found"; return 3; }
    # shellcheck disable=SC2086
    if grep -qsE 'pam_faillock\.so|pam_tally2\.so' $files; then
        DETAIL="Account lockout on failed logins is configured (pam_faillock/pam_tally2)"; return 0
    fi
    DETAIL="No account-lockout module in the PAM auth stack. Enable pam_faillock (via authselect / pam-auth-update, or add pam_faillock.so deny=5)."
    return 1
}

register_check "ACC-009" "Accounts" "low" "server,workstation" \
    "Password reuse is limited (pam_pwhistory)"
set_meta ACC-009 desc "Checks that PAM remembers previous passwords (pam_pwhistory 'remember=N') so users cannot immediately cycle back to an old password when forced to change. Report-only."
set_meta ACC-009 revert "No change is made (report-only)."
audit_ACC_009() {
    local files; files=$(_pam_passwd_files)
    [ -n "$files" ] || { DETAIL="No PAM password stack found"; return 3; }
    if grep -qsE 'pam_pwhistory\.so.*remember=[1-9]' $files \
       || { [ -f "$(axpath /etc/security/pwhistory.conf)" ] && grep -qsE '^[[:space:]]*remember[[:space:]]*=[[:space:]]*[1-9]' "$(axpath /etc/security/pwhistory.conf)"; }; then
        DETAIL="Password history is enforced (pam_pwhistory remember=N)"; return 0
    fi
    DETAIL="Password reuse is not limited. Add 'pam_pwhistory.so remember=5' to the PAM password stack ($files)."
    return 2
}

register_check "ACC-010" "Accounts" "medium" "server,workstation" \
    "Interactive accounts have authenticated recently"
set_meta ACC-010 desc "Flags interactive user accounts (UID >= UID_MIN with a real login shell) that have not authenticated within AUDITXS_INACTIVE_DAYS days (default 90; set it as low as 30 for tighter control). Dormant accounts are a favoured foothold: they tend to keep weak or reused credentials and their misuse goes unnoticed. Report-only — locking an account is a judgement call (a rarely-used admin, or a login identity for automation, can be legitimate), so AuditXS lists the accounts with the exact lock/expire command instead of acting on its own."
set_meta ACC-010 revert "No change is made (report-only)."

# Interactive login accounts: UID in [UID_MIN, 65533] with a real login shell
# (one username per line). Reused by the inactivity check and unit-testable
# against a fixture /etc/passwd.
_human_login_accounts() {
    local uid_min; uid_min=$(_logindefs_val UID_MIN); uid_min=${uid_min:-1000}
    awk -F: -v m="$uid_min" \
        '($3 >= m && $3 < 65534 && $7 != "" && $7 !~ /(nologin|false|\/sync|\/shutdown|\/halt)$/) {print $1}' \
        "$(axpath /etc/passwd)" 2>/dev/null
}

audit_ACC_010() {
    local days=${AUDITXS_INACTIVE_DAYS:-90}
    local humans; humans=$(_human_login_accounts)
    [ -n "$humans" ] || { DETAIL="No interactive user accounts to evaluate"; return 0; }
    have lastlog || { DETAIL="lastlog is not available — cannot determine last-login times (install util-linux / the shadow utilities)."; return 3; }
    local stale="" u rest
    while read -r u rest; do
        [ -n "$u" ] || continue
        grep -qx "$u" <<<"$humans" || continue
        if echo "$rest" | grep -q "Never logged in"; then stale+="${u}(never) "; else stale+="${u} "; fi
    done < <(lastlog -b "$days" 2>/dev/null | awk 'NR>1')
    if [ -n "$stale" ]; then
        DETAIL="Interactive account(s) not authenticated in the last ${days} day(s): ${stale}— review and, if unused, lock ('sudo passwd -l <user>') or expire ('sudo chage -E \$(date +%F) <user>'). AuditXS does not auto-lock accounts."
        return 2
    fi
    DETAIL="All interactive accounts have authenticated within the last ${days} day(s)"
    return 0
}
