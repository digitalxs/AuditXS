#!/usr/bin/env bash
#
# AuditXS — checks/70-services.sh
# Category: Services — reduce the attack surface by disabling services the
# machine's role does not need. Fixes DISABLE services (recording their
# previous state for rollback); packages are never removed automatically.
#

LEGACY_UNITS="telnet.socket telnetd.service inetd.service openbsd-inetd.service xinetd.service rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa.service ypserv.service nis.service"

register_check "SVC-001" "Services" "high" "server,workstation" \
    "Legacy plaintext network services are not running"
set_meta SVC-001 desc "Checks for enabled/active legacy services that transmit credentials in cleartext or are historically unsafe: telnet, rsh/rlogin/rexec, tftp, xinetd/inetd, NIS (ypserv). These have modern encrypted replacements (SSH, SFTP) and should not run anywhere."
set_meta SVC-001 fix "Disables and stops each detected unit with 'systemctl disable --now', recording its previous enabled/active state. Packages are left installed (remove them manually if unneeded)."
set_meta SVC-001 revert "'sudo auditxs rollback' re-enables and restarts each service exactly as it was before."

_active_legacy_units() {
    local u
    for u in $LEGACY_UNITS; do
        unit_exists "$u" || continue
        if svc_enabled "$u" || svc_active "$u"; then
            echo "$u"
        fi
    done
}

audit_SVC_001() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    local found
    found=$(_active_legacy_units)
    if [ -n "$found" ]; then
        DETAIL="Legacy service(s) enabled or running: $(echo "$found" | tr '\n' ' ')"
        return 1
    fi
    DETAIL="No legacy plaintext services enabled or running"
    return 0
}

fix_SVC_001() {
    local u
    for u in $(_active_legacy_units); do
        disable_unit "$u" || return 1
        say "  disabled $u"
    done
}

register_check "SVC-002" "Services" "medium" "server" \
    "Avahi (mDNS) daemon is disabled on servers"
set_meta SVC-002 desc "Checks that avahi-daemon is not running. Avahi advertises the machine and its services on the local network (mDNS/zeroconf) — useful on desktops, but on servers it is unneeded broadcast surface and information disclosure."
set_meta SVC-002 fix "Disables and stops avahi-daemon.service and avahi-daemon.socket, recording their previous state. The package stays installed."
set_meta SVC-002 revert "'sudo auditxs rollback' re-enables and restarts the units exactly as they were."

audit_SVC_002() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    unit_exists avahi-daemon.service || { DETAIL="avahi-daemon is not installed"; return 3; }
    if svc_active avahi-daemon.service || svc_enabled avahi-daemon.service; then
        DETAIL="avahi-daemon is enabled/running"
        return 1
    fi
    DETAIL="avahi-daemon is disabled"
    return 0
}

fix_SVC_002() {
    disable_unit avahi-daemon.socket
    disable_unit avahi-daemon.service
}

register_check "SVC-003" "Services" "medium" "server" \
    "Printing services (CUPS) are disabled on servers"
set_meta SVC-003 desc "Checks that CUPS is not running. Print services listen on the network and have a long CVE history; servers that never print should not run them."
set_meta SVC-003 fix "Disables and stops cups.service, cups.socket and cups-browsed.service (where present), recording their previous state. The packages stay installed."
set_meta SVC-003 revert "'sudo auditxs rollback' re-enables and restarts the units exactly as they were."

audit_SVC_003() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    unit_exists cups.service || { DETAIL="CUPS is not installed"; return 3; }
    if svc_active cups.service || svc_enabled cups.service; then
        DETAIL="CUPS is enabled/running"
        return 1
    fi
    DETAIL="CUPS is disabled"
    return 0
}

fix_SVC_003() {
    disable_unit cups-browsed.service
    disable_unit cups.socket
    disable_unit cups.service
}

register_check "SVC-004" "Services" "medium" "server" \
    "Bluetooth is disabled on servers"
set_meta SVC-004 desc "Checks that the bluetooth service is not running. Servers rarely use Bluetooth; the stack adds kernel attack surface reachable from physical proximity."
set_meta SVC-004 fix "Disables and stops bluetooth.service, recording its previous state. The package stays installed."
set_meta SVC-004 revert "'sudo auditxs rollback' re-enables and restarts the unit exactly as it was."

audit_SVC_004() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    unit_exists bluetooth.service || { DETAIL="Bluetooth stack is not installed"; return 3; }
    if svc_active bluetooth.service || svc_enabled bluetooth.service; then
        DETAIL="bluetooth.service is enabled/running"
        return 1
    fi
    DETAIL="bluetooth.service is disabled"
    return 0
}

fix_SVC_004() { disable_unit bluetooth.service; }

register_check "SVC-005" "Services" "low" "server,workstation" \
    "systemd service sandboxing overview"
set_meta SVC-005 desc "Summarizes 'systemd-analyze security', which scores every running service by how much sandboxing (namespaces, capability limits, syscall filters) it uses. Informational: use it to pick services worth confining with systemd hardening directives."

audit_SVC_005() {
    has_systemd || { DETAIL="systemd not detected"; return 3; }
    have systemd-analyze || { DETAIL="systemd-analyze not available"; return 3; }
    local out n total
    out=$(timeout 30 systemd-analyze security --no-pager 2>/dev/null)
    [ -n "$out" ] || { DETAIL="systemd-analyze security produced no output"; return 3; }
    total=$(echo "$out" | grep -c '\.service')
    n=$(echo "$out" | grep -c 'UNSAFE')
    DETAIL="$n of $total running services are rated UNSAFE by systemd-analyze (informational — run 'systemd-analyze security <unit>' for details)"
    return 0
}
