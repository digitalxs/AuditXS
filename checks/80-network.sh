#!/usr/bin/env bash
#
# AuditXS — checks/80-network.sh
# Category: Network — exposure and protocol surface.
#

register_check "NET-001" "Network" "low" "server,workstation" \
    "Listening network services inventory"
set_meta NET-001 desc "Lists every TCP/UDP port the system is listening on. Informational — the point is that YOU can verify each entry is expected. Anything you do not recognize deserves investigation ('ss -tulpn' shows the owning process)."

audit_NET_001() {
    have ss || { DETAIL="'ss' (iproute2) not available"; return 3; }
    local listeners n
    listeners=$(ss -tulnH 2>/dev/null | awk '{printf "%-5s %s\n", $1, $5}' | sort -u)
    if [ -z "$listeners" ]; then
        DETAIL="No listening TCP/UDP sockets"
        return 0
    fi
    n=$(echo "$listeners" | wc -l)
    DETAIL="$n listening socket(s) — verify each is expected (details: ss -tulpn):"$'\n'"$(echo "$listeners" | head -n 20)"
    return 0
}

register_check "NET-002" "Network" "medium" "server,workstation" \
    "Uncommon network protocols are disabled"
set_meta NET-002 desc "Checks that rarely-used kernel network protocols (DCCP, SCTP, RDS, TIPC) cannot be auto-loaded. These modules have repeatedly been the vehicle for kernel privilege-escalation bugs, and almost no system needs them. If you knowingly use one (e.g. SCTP for telecom software), skip this fix."
set_meta NET-002 fix "Writes /etc/modprobe.d/99-auditxs-netproto.conf with 'install <module> /bin/false' for dccp, sctp, rds and tipc, preventing them from being loaded in the future. Modules already loaded are reported but NOT unloaded (no disruption)."
set_meta NET-002 revert "'sudo auditxs rollback' deletes the modprobe drop-in (or restores its previous content)."

NET_002_PROTOS="dccp sctp rds tipc"

audit_NET_002() {
    local m missing="" loaded=""
    for m in $NET_002_PROTOS; do
        grep -rqsE "^[[:space:]]*(install[[:space:]]+$m[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+$m)([[:space:]]|$)" /etc/modprobe.d/ \
            || missing+="$m "
        lsmod 2>/dev/null | grep -q "^$m " && loaded+="$m "
    done
    if [ -z "$missing" ]; then
        DETAIL="dccp, sctp, rds and tipc are prevented from loading${loaded:+ (currently loaded: $loaded— unload or reboot to fully apply)}"
        [ -n "$loaded" ] && return 2
        return 0
    fi
    DETAIL="Not prevented from auto-loading: $missing${loaded:+(currently loaded: $loaded)}"
    return 1
}

fix_NET_002() {
    local f=/etc/modprobe.d/99-auditxs-netproto.conf m content
    content="# AuditXS NET-002 — prevent auto-loading of uncommon network protocols.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file)"
    for m in $NET_002_PROTOS; do
        content+=$'\n'"install $m /bin/false"
    done
    track_file "$f"
    write_file "$f" 0644 "$content"
}

register_check "NET-003" "Network" "low" "server" \
    "No wireless interfaces on servers"
set_meta NET-003 desc "Detects Wi-Fi interfaces on machines using the server profile. Wireless links on servers bypass wired network controls and extend the attack surface into radio range. Report-only: disabling networking automatically could sever your own connection, so AuditXS shows the 'rfkill block wifi' command instead."

audit_NET_003() {
    local w=""
    local d
    for d in /sys/class/net/*/wireless; do
        [ -d "$d" ] && w+="$(basename "$(dirname "$d")") "
    done
    if [ -n "$w" ]; then
        DETAIL="Wireless interface(s) present: $w— if unused, disable with 'rfkill block wifi' and consider removing the driver"
        return 2
    fi
    DETAIL="No wireless interfaces"
    return 0
}
