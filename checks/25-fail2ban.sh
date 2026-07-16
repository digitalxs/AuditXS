#!/usr/bin/env bash
#
# AuditXS — checks/25-fail2ban.sh
# Category: Fail2ban — configuration quality of the fail2ban intrusion-
# prevention service, beyond the SSH-specific check in 20-ssh.sh (SSH-008).
#
# Every check SKIPs cleanly when fail2ban is not installed. Config is read
# through axpath() so the logic is fixture-testable (tests/check_test.sh).
# Reversible fixes write clearly-labelled drop-ins under jail.d/ and never
# touch the user's existing configuration.
#

# fail2ban is present if the package/binaries are installed, or a config tree
# exists in the (possibly fixture-prefixed) root.
f2b_installed() {
    pkg_installed fail2ban 2>/dev/null || have fail2ban-client || have fail2ban-server \
        || [ -d "$(axpath /etc/fail2ban)" ]
}

# _f2b_get <key> [section=DEFAULT] — effective value of an ini key within a
# section, honouring fail2ban's precedence: jail.conf < jail.local < jail.d/*.
# The last definition wins. Inline comments and surrounding space are stripped.
_f2b_get() {
    local key=$1 section=${2:-DEFAULT} f
    local files=()
    f=$(axpath /etc/fail2ban/jail.conf);  [ -f "$f" ] && files+=("$f")
    f=$(axpath /etc/fail2ban/jail.local); [ -f "$f" ] && files+=("$f")
    local d; d=$(axpath /etc/fail2ban/jail.d)
    if [ -d "$d" ]; then
        while IFS= read -r f; do files+=("$f"); done \
            < <(find "$d" -maxdepth 1 -name '*.conf' 2>/dev/null | sort)
    fi
    [ ${#files[@]} -gt 0 ] || return 0
    awk -v want_sec="$section" -v want_key="$key" '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            s=$0; gsub(/[][[:space:]]/,"",s); cur=s; next
        }
        {
            eq=index($0,"=")
            if (eq==0) next
            k=substr($0,1,eq-1); v=substr($0,eq+1)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",k)
            sub(/[[:space:]]+[#;].*/,"",v)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",v)
            if (cur==want_sec && k==want_key) val=v
        }
        END { if (val!="") print val }
    ' "${files[@]}"
}

# _f2b_seconds <bantime> — normalise a fail2ban time (600, 10m, 1h, 1d, 1w,
# combinations like 1d2h, or -1 for permanent) into seconds.
_f2b_seconds() {
    local v=${1//[[:space:]]/} total=0 num unit
    [ "$v" = "-1" ] && { echo 999999999; return; }
    [[ $v =~ ^[0-9]+$ ]] && { echo "$v"; return; }
    while [[ $v =~ ^([0-9]+)([smhdw])(.*)$ ]]; do
        num=${BASH_REMATCH[1]}; unit=${BASH_REMATCH[2]}; v=${BASH_REMATCH[3]}
        case $unit in
            s) total=$((total+num)) ;;      m) total=$((total+num*60)) ;;
            h) total=$((total+num*3600)) ;; d) total=$((total+num*86400)) ;;
            w) total=$((total+num*604800)) ;;
        esac
    done
    [[ $v =~ ^[0-9]+$ ]] && total=$((total+v))
    echo "$total"
}

# --------------------------------------------------------------- F2B-001 ---
register_check "F2B-001" "Fail2ban" "medium" "server,workstation" \
    "fail2ban is enabled to start at boot"
set_meta F2B-001 desc "Checks that the fail2ban service is enabled (starts automatically at boot). A fail2ban that is running now but not enabled loses all brute-force protection after the next reboot — a common and easily-missed gap."
set_meta F2B-001 fix "Enables the fail2ban service (systemctl enable fail2ban.service) so it starts on boot. Does not change any jail or ban configuration."
set_meta F2B-001 revert "'sudo auditxs rollback' disables the service again if it was disabled before."

audit_F2B_001() {
    f2b_installed || { DETAIL="fail2ban is not installed"; return 3; }
    if svc_enabled fail2ban.service; then
        DETAIL="fail2ban.service is enabled at boot"; return 0
    fi
    if svc_active fail2ban.service; then
        DETAIL="fail2ban is running but NOT enabled — protection is lost after a reboot"; return 1
    fi
    DETAIL="fail2ban is installed but neither enabled nor running (see SSH-008 to configure it)"; return 1
}
fix_F2B_001() { enable_unit fail2ban.service; }

# --------------------------------------------------------------- F2B-002 ---
register_check "F2B-002" "Fail2ban" "low" "server,workstation" \
    "fail2ban ban policy is not too permissive"
set_meta F2B-002 desc "Checks the effective default ban policy: 'maxretry' (failures before a ban) should be low (<= 5) and 'bantime' should be meaningful (>= 10 minutes). A high maxretry or a very short bantime lets brute-force attacks continue with little cost. Report-only — tuning ban policy is environment-specific."
set_meta F2B-002 revert "No change is made (report-only)."

audit_F2B_002() {
    f2b_installed || { DETAIL="fail2ban is not installed"; return 3; }
    local maxretry bantime bt
    maxretry=$(_f2b_get maxretry DEFAULT); : "${maxretry:=5}"
    bantime=$(_f2b_get bantime DEFAULT);   : "${bantime:=600}"
    bt=$(_f2b_seconds "$bantime")
    local issues=""
    [[ $maxretry =~ ^[0-9]+$ ]] && [ "$maxretry" -gt 6 ] && \
        issues+="maxretry=$maxretry is lenient (recommend ≤ 5); "
    [ "${bt:-0}" -gt 0 ] 2>/dev/null && [ "$bt" -lt 600 ] && \
        issues+="bantime=$bantime is short (recommend ≥ 10m); "
    if [ -n "$issues" ]; then
        DETAIL="${issues% }"; return 2
    fi
    DETAIL="Ban policy is reasonable (maxretry=$maxretry, bantime=$bantime)"; return 0
}

# --------------------------------------------------------------- F2B-003 ---
register_check "F2B-003" "Fail2ban" "low" "server,workstation" \
    "A recidive jail bans repeat offenders"
set_meta F2B-003 desc "Checks for an enabled 'recidive' jail. Recidive watches fail2ban's own log and applies long bans to IPs that keep getting banned across jails — a cheap, high-value defence-in-depth layer against persistent attackers."
set_meta F2B-003 fix "Writes /etc/fail2ban/jail.d/99-auditxs-recidive.conf enabling the built-in [recidive] jail and restarts fail2ban. Recidive reads fail2ban's own logfile (/var/log/fail2ban.log); if your fail2ban logs only to the journal, set 'logtarget' to a file for recidive to work."
set_meta F2B-003 revert "'sudo auditxs rollback' removes the drop-in and restarts fail2ban."

audit_F2B_003() {
    f2b_installed || { DETAIL="fail2ban is not installed"; return 3; }
    # Prefer the live daemon when available; fall back to config.
    if have fail2ban-client && fail2ban-client status 2>/dev/null | grep -qw recidive; then
        DETAIL="A recidive jail is active"; return 0
    fi
    local en; en=$(_f2b_get enabled recidive)
    case ${en,,} in
        true|1|yes) DETAIL="The recidive jail is enabled in configuration"; return 0 ;;
    esac
    DETAIL="No recidive jail — repeat offenders are not given longer bans"; return 1
}
fix_F2B_003() {
    local f=/etc/fail2ban/jail.d/99-auditxs-recidive.conf
    track_file "$f"
    write_file "$f" 0644 "# AuditXS F2B-003 — ban IPs that are repeatedly banned (recidive).
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and restart fail2ban)
# Note: recidive reads fail2ban's own logfile; ensure fail2ban logs to a file
# (logtarget) if you use the systemd journal only.
[recidive]
enabled = true" || return 1
    # Reload only if fail2ban is actually running (xrun_q respects --dry-run).
    svc_active fail2ban.service && xrun_q systemctl restart fail2ban.service
    return 0
}

# --------------------------------------------------------------- F2B-004 ---
register_check "F2B-004" "Fail2ban" "medium" "server,workstation" \
    "fail2ban ignoreip is not overly broad"
set_meta F2B-004 desc "Checks that the 'ignoreip' allow-list does not whitelist large public ranges. A broad ignoreip (e.g. 0.0.0.0/0 or a public /8) silently exempts attackers from banning. Loopback and private (RFC1918) ranges are expected and fine. Report-only — the correct allow-list is site-specific, and editing it automatically could lock you out."
set_meta F2B-004 revert "No change is made (report-only)."

audit_F2B_004() {
    f2b_installed || { DETAIL="fail2ban is not installed"; return 3; }
    local ignoreip; ignoreip=$(_f2b_get ignoreip DEFAULT)
    [ -n "$ignoreip" ] || { DETAIL="No ignoreip set (defaults to loopback only) — fine"; return 0; }
    local tok broad=""
    for tok in ${ignoreip//,/ }; do
        case $tok in
            0.0.0.0/0|::/0|*/0) broad+="$tok " ;;
            127.*|::1|localhost) : ;;                 # loopback — always fine
            10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|fd*|fc*) : ;;  # RFC1918/ULA
            *)
                # public IPv4 with a very broad prefix (<= /8) is suspicious
                if [[ $tok =~ ^([0-9]+)\.[0-9.]*/([0-9]+)$ ]] && [ "${BASH_REMATCH[2]}" -le 8 ]; then
                    broad+="$tok "
                fi ;;
        esac
    done
    if [ -n "$broad" ]; then
        DETAIL="ignoreip whitelists broad range(s): ${broad% } — attackers in these ranges are never banned"
        return 2
    fi
    DETAIL="ignoreip is scoped to loopback/private/specific addresses"; return 0
}
