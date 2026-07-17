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
        grep -rqsE "^[[:space:]]*(install[[:space:]]+${m}[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+${m})([[:space:]]|$)" /etc/modprobe.d/ \
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

register_check "NET-004" "Network" "high" "server" \
    "Listening ports match the approved allowlist"
set_meta NET-004 desc "Compares every listening TCP/UDP port against the administrator-approved allowlist in /etc/auditxs/allowed-ports.conf. This turns 'what is listening?' (NET-001) into drift detection: a service that appears without being approved — a forgotten debug port, a dropped implant, a misconfigured install — is flagged immediately. Report-only: YOU decide what belongs on the list; AuditXS never opens or closes ports. Pair with 'auditxs schedule' for continuous drift monitoring."
set_meta NET-004 nist "DE.CM-01, PR.IR-01"

_current_listeners() { # "proto port" per line
    ss -tulnH 2>/dev/null | awk '{n=split($5,a,":"); print $1, a[n]}' | sort -u
}

audit_NET_004() {
    have ss || { DETAIL="'ss' (iproute2) not available"; return 3; }
    local f=/etc/auditxs/allowed-ports.conf
    local listeners proto port bad=""
    listeners=$(_current_listeners)
    if [ ! -f "$f" ]; then
        DETAIL="No allowlist yet. Review the current listeners (NET-001), then approve them with:
  ss -tulnH | awk '{n=split(\$5,a,\":\"); print \$1, a[n]}' | sort -u | sudo tee $f
From then on, any NEW listening port fails this check (drift detection)."
        return 2
    fi
    while read -r proto port; do
        [ -n "$proto" ] || continue
        grep -qsE "^[[:space:]]*${proto}[[:space:]]+${port}([[:space:]]|\$)" "$f" || bad+="$proto $port"$'\n'
    done <<< "$listeners"
    if [ -n "$bad" ]; then
        DETAIL="Listening but NOT in the allowlist ($f) — investigate, then either stop the service or approve it:
$bad"
        return 1
    fi
    DETAIL="All $(echo "$listeners" | grep -c .) listening socket(s) are approved in $f"
    return 0
}

# ---------------------------------------------------------------- NET-005 ---
register_check "NET-005" "Network" "medium" "server,workstation" \
    "No network interface is in promiscuous mode"
set_meta NET-005 desc "Checks for interfaces in promiscuous mode (capturing all traffic on the segment). This is expected for bridges, some virtualisation and packet sniffers, but on a plain host it can indicate a sniffer left running or a compromise. Report-only — verify each one is expected."
set_meta NET-005 revert "No change is made (report-only)."

audit_NET_005() {
    have ip || { DETAIL="'ip' (iproute2) not available"; return 3; }
    local promisc
    promisc=$(ip -o link show 2>/dev/null | awk '/PROMISC/{sub(/@.*/,"",$2); printf "%s ", $2}')
    if [ -n "$promisc" ]; then
        DETAIL="Interface(s) in promiscuous mode: ${promisc% } — expected for bridges/sniffers, otherwise investigate"
        return 2
    fi
    DETAIL="No interfaces are in promiscuous mode"
    return 0
}

# ---------------------------------------------------------------- NET-006 ---
register_check "NET-006" "Network" "medium" "server,workstation" \
    "System time is kept in sync (NTP)"
set_meta NET-006 desc "Checks that a time-synchronisation service is active (chrony, ntpd, systemd-timesyncd or openntpd). Accurate time underpins log correlation during incidents, TLS certificate validity, Kerberos/auth, and scheduled jobs. A drifting clock quietly breaks all of these."
set_meta NET-006 fix "Enables an available time-sync service (systemd-timesyncd, chrony or ntp). If none is installed, AuditXS reports which to install rather than pulling in a package silently. The service enablement is recorded and reversible."
set_meta NET-006 revert "'sudo auditxs rollback' disables the time-sync service again if it was disabled before."

audit_NET_006() {
    local s
    for s in chrony.service chronyd.service ntp.service ntpd.service systemd-timesyncd.service openntpd.service; do
        if svc_active "$s"; then DETAIL="Time synchronisation is active ($s)"; return 0; fi
    done
    if have timedatectl && timedatectl show -p NTPSynchronized 2>/dev/null | grep -q 'NTPSynchronized=yes'; then
        DETAIL="Time is synchronised (timedatectl reports NTPSynchronized=yes)"; return 0
    fi
    DETAIL="No active time-synchronisation service — install chrony (or enable systemd-timesyncd) so logs, TLS and auth have accurate time"
    return 1
}
fix_NET_006() {
    local s
    for s in systemd-timesyncd.service chrony.service chronyd.service ntp.service; do
        if unit_exists "$s"; then enable_unit "$s" && return 0; fi
    done
    warn "No time-sync service is installed. Install one (e.g. 'chrony') and re-run harden."
    return 1
}
