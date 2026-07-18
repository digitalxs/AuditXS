#!/usr/bin/env bash
#
# AuditXS — checks/60-kernel.sh
# Category: Kernel — sysctl hardening. Each fix writes ONE clearly-labelled
# drop-in file per check under /etc/sysctl.d/ (99-auditxs-<id>.conf), records
# the previous runtime values, and applies the new values immediately.
# Rollback deletes the drop-in and restores the recorded runtime values.
#

register_check "KRN-001" "Kernel" "high" "server,workstation" \
    "Address space layout randomization (ASLR) is fully enabled"
set_meta KRN-001 desc "Checks kernel.randomize_va_space=2. ASLR randomizes process memory layout, making memory-corruption exploits substantially harder. 2 (full, including heap) is the kernel default; anything lower means it was weakened."
set_meta KRN-001 fix "Writes /etc/sysctl.d/99-auditxs-krn-001.conf with 'kernel.randomize_va_space = 2' and applies it at runtime. Previous value is recorded."
set_meta KRN-001 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value."

audit_KRN_001() { audit_sysctl_group "kernel.randomize_va_space=2"; }
fix_KRN_001()   { fix_sysctl_group KRN-001 "full ASLR" "kernel.randomize_va_space=2"; }

register_check "KRN-002" "Kernel" "medium" "server,workstation" \
    "Kernel address and log exposure is restricted"
set_meta KRN-002 desc "Checks kernel.kptr_restrict ≥ 1 (hide kernel pointers from unprivileged users) and kernel.dmesg_restrict = 1 (require privilege to read the kernel log). Kernel addresses and dmesg output are building blocks for kernel exploits and information leaks."
set_meta KRN-002 fix "Writes /etc/sysctl.d/99-auditxs-krn-002.conf setting only the values that are currently weaker than recommended (kptr_restrict=1, dmesg_restrict=1) and applies them at runtime. Values already stricter are left untouched."
set_meta KRN-002 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

audit_KRN_002() { audit_sysctl_group "kernel.kptr_restrict=1|2" "kernel.dmesg_restrict=1"; }
fix_KRN_002() {
    local kv=()
    [[ "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" =~ ^(1|2)$ ]] || kv+=("kernel.kptr_restrict=1")
    [ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" = 1 ] || kv+=("kernel.dmesg_restrict=1")
    [ ${#kv[@]} -eq 0 ] && return 0
    fix_sysctl_group KRN-002 "restrict kernel pointer/log exposure" "${kv[@]}"
}

register_check "KRN-003" "Kernel" "high" "server,workstation" \
    "TCP SYN cookies are enabled"
set_meta KRN-003 desc "Checks net.ipv4.tcp_syncookies=1. SYN cookies keep the system reachable during SYN-flood denial-of-service attacks instead of exhausting the connection backlog."
set_meta KRN-003 fix "Writes /etc/sysctl.d/99-auditxs-krn-003.conf with 'net.ipv4.tcp_syncookies = 1' and applies it at runtime."
set_meta KRN-003 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value."

audit_KRN_003() { audit_sysctl_group "net.ipv4.tcp_syncookies=1"; }
fix_KRN_003()   { fix_sysctl_group KRN-003 "TCP SYN cookies" "net.ipv4.tcp_syncookies=1"; }

register_check "KRN-004" "Kernel" "medium" "server,workstation" \
    "ICMP redirects are ignored and not sent"
set_meta KRN-004 desc "Checks that the system neither accepts nor sends ICMP redirect messages (IPv4 and IPv6). Accepted redirects let an on-path attacker rewrite the routing table and intercept traffic; hosts that are not routers have no reason to send them."
set_meta KRN-004 fix "Writes /etc/sysctl.d/99-auditxs-krn-004.conf disabling accept_redirects (v4+v6, all/default), secure_redirects and send_redirects, and applies the values at runtime."
set_meta KRN-004 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

KRN_004_KV=(
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
)
audit_KRN_004() { audit_sysctl_group "${KRN_004_KV[@]}"; }
fix_KRN_004()   { fix_sysctl_group KRN-004 "ignore ICMP redirects" "${KRN_004_KV[@]}"; }

register_check "KRN-005" "Kernel" "medium" "server,workstation" \
    "Source-routed packets are rejected"
set_meta KRN-005 desc "Checks that accept_source_route is 0 for IPv4 and IPv6. Source routing lets the sender dictate a packet's path — a technique for bypassing firewall policy and spoofing; end hosts should never accept it."
set_meta KRN-005 fix "Writes /etc/sysctl.d/99-auditxs-krn-005.conf disabling accept_source_route (v4+v6, all/default) and applies the values at runtime."
set_meta KRN-005 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

KRN_005_KV=(
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
)
audit_KRN_005() { audit_sysctl_group "${KRN_005_KV[@]}"; }
fix_KRN_005()   { fix_sysctl_group KRN-005 "reject source-routed packets" "${KRN_005_KV[@]}"; }

register_check "KRN-006" "Kernel" "medium" "server,workstation" \
    "Reverse-path filtering is enabled"
set_meta KRN-006 desc "Checks net.ipv4.conf.{all,default}.rp_filter is 1 (strict) or 2 (loose). Reverse-path filtering drops packets whose source address could not be routed back the way they came, blunting IP spoofing."
set_meta KRN-006 fix "Writes /etc/sysctl.d/99-auditxs-krn-006.conf with rp_filter=1 for all/default and applies it at runtime. If your host does asymmetric routing (rare, multi-homed setups), skip this fix."
set_meta KRN-006 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

audit_KRN_006() { audit_sysctl_group "net.ipv4.conf.all.rp_filter=1|2" "net.ipv4.conf.default.rp_filter=1|2"; }
fix_KRN_006()   { fix_sysctl_group KRN-006 "reverse-path filtering" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }

register_check "KRN-007" "Kernel" "low" "server" \
    "Suspicious (martian) packets are logged"
set_meta KRN-007 desc "Checks net.ipv4.conf.{all,default}.log_martians=1 so packets with impossible source addresses are logged. On servers this gives early warning of spoofing or misrouted traffic; on busy networks it adds log volume, which is why it is server-profile only."
set_meta KRN-007 fix "Writes /etc/sysctl.d/99-auditxs-krn-007.conf with log_martians=1 for all/default and applies it at runtime."
set_meta KRN-007 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

audit_KRN_007() { audit_sysctl_group "net.ipv4.conf.all.log_martians=1" "net.ipv4.conf.default.log_martians=1"; }
fix_KRN_007()   { fix_sysctl_group KRN-007 "log martian packets" "net.ipv4.conf.all.log_martians=1" "net.ipv4.conf.default.log_martians=1"; }

register_check "KRN-008" "Kernel" "high" "server,workstation" \
    "IP forwarding is disabled (unless this host routes traffic)"
set_meta KRN-008 desc "Checks that IPv4/IPv6 forwarding is off. A host that silently forwards packets can be abused to pivot between networks. DETECTION: if Docker, Podman or libvirt is present, forwarding is required and this check passes with a note instead."
set_meta KRN-008 fix "Writes /etc/sysctl.d/99-auditxs-krn-008.conf disabling net.ipv4.ip_forward and net.ipv6.conf.all.forwarding and applies it at runtime. The fix is only offered when no container/VM runtime was detected — do not apply it on routers or VPN gateways."
set_meta KRN-008 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values."

_forwarding_needed() {
    have docker || have podman || svc_active libvirtd || svc_active containerd || have tailscale
}

audit_KRN_008() {
    local v4 v6
    v4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    v6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)
    if [ "${v4:-0}" = 0 ] && [ "${v6:-0}" = 0 ]; then
        DETAIL="IP forwarding is disabled"
        return 0
    fi
    if _forwarding_needed; then
        DETAIL="IP forwarding is enabled (ipv4=$v4 ipv6=$v6) but a container/VM runtime was detected that requires it — leaving as is"
        return 0
    fi
    DETAIL="IP forwarding is enabled (ipv4=$v4 ipv6=$v6) and no container/VM runtime was detected. If this host is not a router or VPN gateway, disable it."
    return 1
}

fix_KRN_008() {
    if _forwarding_needed; then
        DETAIL="Refused: a container/VM runtime that needs forwarding was detected"
        return 1
    fi
    fix_sysctl_group KRN-008 "disable IP forwarding" \
        "net.ipv4.ip_forward=0" "net.ipv6.conf.all.forwarding=0"
}

register_check "KRN-009" "Kernel" "medium" "server,workstation" \
    "Core dumps of privileged programs are disabled"
set_meta KRN-009 desc "Checks fs.suid_dumpable=0. Core dumps of setuid programs can spill password hashes and other secrets those programs held in memory into files an attacker may read."
set_meta KRN-009 fix "Writes /etc/sysctl.d/99-auditxs-krn-009.conf with 'fs.suid_dumpable = 0' and applies it at runtime."
set_meta KRN-009 revert "'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value."

audit_KRN_009() { audit_sysctl_group "fs.suid_dumpable=0"; }
fix_KRN_009()   { fix_sysctl_group KRN-009 "no setuid core dumps" "fs.suid_dumpable=0"; }

register_check "KRN-010" "Kernel" "low" "server" \
    "Ctrl-Alt-Del does not reboot the system"
set_meta KRN-010 desc "Checks that the ctrl-alt-del systemd target is masked. On servers, anyone with (physical or remote-console) keyboard access could otherwise trigger an unclean reboot without authentication."
set_meta KRN-010 fix "Masks the target by linking /etc/systemd/system/ctrl-alt-del.target to /dev/null and runs 'systemctl daemon-reload'. No other keyboard behaviour changes."
set_meta KRN-010 revert "'sudo auditxs rollback' removes the mask link (restoring the saved file if one existed) and reloads systemd."

audit_KRN_010() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    if [ "$(readlink /etc/systemd/system/ctrl-alt-del.target 2>/dev/null)" = "/dev/null" ]; then
        DETAIL="ctrl-alt-del.target is masked"
        return 0
    fi
    DETAIL="Ctrl-Alt-Del triggers a reboot (ctrl-alt-del.target is not masked)"
    return 1
}

fix_KRN_010() {
    track_file /etc/systemd/system/ctrl-alt-del.target
    xrun ln -sfn /dev/null /etc/systemd/system/ctrl-alt-del.target || return 1
    xrun_q systemctl daemon-reload
}

# ---------------------------------------------------------------- KRN-011 ---
register_check "KRN-011" "Kernel" "low" "server,workstation" \
    "Core dumps are restricted"
set_meta KRN-011 desc "Checks that process core dumps are restricted. Core dumps can contain passwords, keys and other secrets from process memory; on a server they are rarely needed. Looks for a hard 'core 0' limit and, on systemd, Storage=none/ProcessSizeMax=0 in coredump.conf. (Kernel fs.suid_dumpable is covered by KRN-009.) Report-only."
set_meta KRN-011 revert "No change is made (report-only)."
audit_KRN_011() {
    local lim=0 sysd=0 f
    for f in /etc/security/limits.conf $(ls "$(axpath /etc/security/limits.d)"/*.conf 2>/dev/null); do
        f=$(axpath "$f"); [ -f "$f" ] || continue
        grep -qsE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' "$f" && lim=1
    done
    f=$(axpath /etc/systemd/coredump.conf)
    [ -f "$f" ] && grep -qsiE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none|^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0' "$f" && sysd=1
    if [ "$lim" = 1 ] || [ "$sysd" = 1 ]; then
        DETAIL="Core dumps are restricted (hard core limit and/or systemd coredump storage disabled)"; return 0
    fi
    DETAIL="Core dumps are not restricted — they can leak secrets from memory. Add '* hard core 0' to limits.conf and/or 'Storage=none' to /etc/systemd/coredump.conf."
    return 2
}
