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
    extra=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null)
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
    [ -r /etc/shadow ] || { DETAIL="/etc/shadow is not readable"; return 2; }
    local empty
    empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
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
    awk -v k="$1" '$1 == k {print $2}' /etc/login.defs 2>/dev/null | tail -n1
}

audit_ACC_003() {
    [ -f /etc/login.defs ] || { DETAIL="/etc/login.defs not found"; return 3; }
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
        /etc/passwd 2>/dev/null
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
    [ -f /etc/login.defs ] || { DETAIL="/etc/login.defs not found"; return 3; }
    local um
    um=$(_logindefs_val UMASK)
    case $um in
        027|077) DETAIL="UMASK $um"; return 0 ;;
        *)       DETAIL="UMASK is ${um:-unset} (recommended: 027)"; return 1 ;;
    esac
}

fix_ACC_006() { set_logindefs UMASK 027; }
