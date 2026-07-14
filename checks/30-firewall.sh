#!/usr/bin/env bash
#
# AuditXS — checks/30-firewall.sh
# Category: Firewall — a host firewall is the fundamental network control.
# Distribution conventions are respected: ufw on the Debian family and Arch,
# firewalld on Fedora and openSUSE. LOCKOUT GUARD: before enabling any
# firewall, AuditXS explicitly allows the SSH port when the machine is
# managed over SSH.
#

# Preferred firewall tool on this system, honouring distro conventions.
firewall_tool() {
    case $DISTRO_FAMILY in
        redhat|suse)
            if have firewall-cmd; then echo firewalld; return; fi ;;
    esac
    if have ufw; then
        echo ufw
    elif have firewall-cmd; then
        echo firewalld
    elif have nft && nft list ruleset 2>/dev/null | grep -q 'hook input'; then
        echo nftables
    else
        echo none
    fi
}

register_check "FW-001" "Firewall" "critical" "server,workstation" \
    "A host firewall is installed"
set_meta FW-001 desc "Checks that a host firewall front-end is available: ufw, firewalld, or an active nftables input ruleset. Without a host firewall every listening service — including ones started accidentally — is reachable from the network."
set_meta FW-001 fix "Installs the distribution's conventional firewall front-end: 'ufw' on Debian/Ubuntu/Pop!_OS/Arch, 'firewalld' on Fedora/openSUSE. Installing the package does NOT enable the firewall yet — that is check FW-002, which asks separately."
set_meta FW-001 revert "The installed package is recorded in the snapshot; 'sudo auditxs rollback' offers to remove it again."

audit_FW_001() {
    local tool
    tool=$(firewall_tool)
    if [ "$tool" != "none" ]; then
        DETAIL="Detected firewall tooling: $tool"
        return 0
    fi
    DETAIL="No firewall front-end found (looked for ufw, firewalld, and an nftables input ruleset)"
    return 1
}

fix_FW_001() {
    case $DISTRO_FAMILY in
        debian|arch)  pkg_install ufw ;;
        redhat|suse)  pkg_install firewalld ;;
        *) DETAIL="Unsupported distribution family"; return 1 ;;
    esac
}

register_check "FW-002" "Firewall" "critical" "server,workstation" \
    "The host firewall is enabled and active"
set_meta FW-002 desc "Checks that the detected firewall is actually running: 'ufw status' reports active, or the firewalld service is active, or an nftables input ruleset is loaded. An installed-but-disabled firewall provides no protection."
set_meta FW-002 fix "ufw: allows the SSH port(s) first when the system is managed over SSH (lockout guard), then runs 'ufw --force enable'. firewalld: enables and starts the firewalld service and ensures the 'ssh' service is allowed in the active zone when SSH is in use. Nothing else is opened or closed."
set_meta FW-002 revert "The previous firewall state and any SSH allow-rule added by AuditXS are recorded; 'sudo auditxs rollback' disables the firewall again (if it was inactive before) and removes the added rules."

audit_FW_002() {
    local tool
    tool=$(firewall_tool)
    case $tool in
        ufw)
            if ufw status 2>/dev/null | grep -q '^Status: active'; then
                DETAIL="ufw is active"
                return 0
            fi
            DETAIL="ufw is installed but inactive"
            return 1 ;;
        firewalld)
            if svc_active firewalld; then
                DETAIL="firewalld is running"
                return 0
            fi
            DETAIL="firewalld is installed but not running"
            return 1 ;;
        nftables)
            DETAIL="An nftables ruleset with an input hook is loaded"
            return 0 ;;
        none)
            DETAIL="No firewall installed — see FW-001"
            return 1 ;;
    esac
}

fix_FW_002() {
    local tool port
    tool=$(firewall_tool)
    case $tool in
        ufw)
            if ssh_in_use; then
                for port in $(ssh_ports); do
                    info "Lockout guard: allowing SSH port $port/tcp before enabling the firewall"
                    record_action ufw_rule "allow $port/tcp" absent added
                    xrun_q ufw allow "$port/tcp"
                done
            fi
            record_action ufw_state ufw \
                "$(ufw status 2>/dev/null | awk 'NR==1{print $2}')" active
            xrun_q ufw --force enable
            ;;
        firewalld)
            enable_unit firewalld.service || return 1
            if [ "$DRYRUN" != 1 ] && ssh_in_use; then
                if ! firewall-cmd --list-services 2>/dev/null | grep -qw ssh; then
                    info "Lockout guard: allowing the ssh service in the active firewalld zone"
                    record_action fw_service ssh absent added
                    xrun_q firewall-cmd --permanent --add-service=ssh
                    xrun_q firewall-cmd --reload
                fi
            fi
            ;;
        nftables)
            DETAIL="nftables is in use but not managed by AuditXS — enable your ruleset service manually"
            return 1 ;;
        none)
            DETAIL="No firewall tool installed — apply FW-001 first"
            return 1 ;;
    esac
}

register_check "FW-003" "Firewall" "high" "server,workstation" \
    "Firewall default-denies inbound traffic"
set_meta FW-003 desc "Checks that unsolicited inbound traffic is denied by default so only explicitly allowed services are reachable. ufw: 'deny (incoming)' default policy; firewalld: the default zone must not have target ACCEPT."
set_meta FW-003 fix "ufw: runs 'ufw default deny incoming' (existing allow rules keep working). firewalld: sets the default zone's target back to 'default' (reject unmatched traffic) and reloads. Outbound traffic is not touched."
set_meta FW-003 revert "The previous default policy / zone target is recorded; 'sudo auditxs rollback' restores it."

audit_FW_003() {
    local tool line zone target
    tool=$(firewall_tool)
    case $tool in
        ufw)
            line=$(ufw status verbose 2>/dev/null | grep -i '^Default:')
            if printf '%s' "$line" | grep -qiE '(deny|reject) \(incoming\)'; then
                DETAIL="$line"
                return 0
            fi
            if [ -z "$line" ]; then
                DETAIL="ufw default policy not readable (is ufw active?)"
                return 2
            fi
            DETAIL="$line"
            return 1 ;;
        firewalld)
            svc_active firewalld || { DETAIL="firewalld is not running — see FW-002"; return 2; }
            zone=$(firewall-cmd --get-default-zone 2>/dev/null)
            target=$(firewall-cmd --permanent --zone="$zone" --get-target 2>/dev/null)
            if [ "$target" = "ACCEPT" ]; then
                DETAIL="Default zone '$zone' has target ACCEPT — all inbound traffic is allowed"
                return 1
            fi
            DETAIL="Default zone '$zone' target: ${target:-default} (unmatched inbound traffic is rejected)"
            return 0 ;;
        nftables)
            DETAIL="nftables in use — verify your input chain policy is 'drop' (not managed by AuditXS)"
            return 2 ;;
        none)
            DETAIL="No firewall installed — see FW-001"
            return 1 ;;
    esac
}

fix_FW_003() {
    local tool line prev zone
    tool=$(firewall_tool)
    case $tool in
        ufw)
            line=$(ufw status verbose 2>/dev/null | grep -i '^Default:')
            prev=$(printf '%s' "$line" | sed -n 's/^Default: \([a-z]*\) (incoming).*/\1/p')
            record_action ufw_default incoming "${prev:-?}" deny
            xrun_q ufw default deny incoming
            ;;
        firewalld)
            zone=$(firewall-cmd --get-default-zone 2>/dev/null)
            [ -n "$zone" ] || { DETAIL="Could not determine the default firewalld zone"; return 1; }
            record_action fw_target "$zone" \
                "$(firewall-cmd --permanent --zone="$zone" --get-target 2>/dev/null || echo '?')" default
            xrun_q firewall-cmd --permanent --zone="$zone" --set-target=default
            xrun_q firewall-cmd --reload
            ;;
        *)
            DETAIL="No automatic fix for this firewall setup"
            return 1 ;;
    esac
}

register_check "FW-004" "Firewall" "low" "server,workstation" \
    "ufw logging is enabled"
set_meta FW-004 desc "Checks that ufw logging is on (at least 'low'), so blocked/allowed connection decisions are recorded. Firewall logs are essential evidence when investigating scans, intrusions or misconfigured services. Only applies where ufw is the active firewall."
set_meta FW-004 fix "Runs 'ufw logging low', recording the previous logging state so rollback restores it. No rules are changed."
set_meta FW-004 revert "'sudo auditxs rollback' restores the previous ufw logging level."
set_meta FW-004 nist "DE.CM-01, PR.PS-04"

audit_FW_004() {
    [ "$(firewall_tool)" = ufw ] || { DETAIL="ufw is not the active firewall on this system"; return 3; }
    local lvl
    lvl=$(ufw status verbose 2>/dev/null | sed -n 's/^Logging: \(.*\)/\1/p')
    case $lvl in
        on*) DETAIL="ufw logging is $lvl"; return 0 ;;
        off) DETAIL="ufw logging is off — firewall decisions are not recorded"; return 1 ;;
        "")  DETAIL="ufw logging state not readable (is ufw active?)"; return 2 ;;
        *)   DETAIL="ufw logging: $lvl"; return 0 ;;
    esac
}

fix_FW_004() {
    local prev
    prev=$(ufw status verbose 2>/dev/null | sed -n 's/^Logging: \([a-z]*\).*/\1/p')
    record_action ufw_logging logging "${prev:-off}" low
    xrun_q ufw logging low
}

register_check "FW-005" "Firewall" "low" "workstation" \
    "A firewall management GUI is available on desktops (gufw)"
set_meta FW-005 desc "On workstations with a graphical desktop, checks for 'gufw' — the graphical front-end for ufw — so non-CLI users can review and manage firewall rules. Purely a usability/visibility control; the firewall itself is covered by FW-001..004. Report-only."
set_meta FW-005 nist "PR.IR-01"

audit_FW_005() {
    [ "$(firewall_tool)" = ufw ] || { DETAIL="Applies to ufw-based systems only"; return 3; }
    if [ -z "${XDG_CURRENT_DESKTOP:-}${DISPLAY:-}" ] && [ ! -d /usr/share/xsessions ]; then
        DETAIL="No graphical desktop detected — gufw not needed"
        return 3
    fi
    if have gufw || pkg_installed gufw; then DETAIL="gufw is installed"; return 0; fi
    DETAIL="gufw (graphical ufw manager) is not installed — 'sudo apt install gufw' for a desktop firewall UI"
    return 2
}
