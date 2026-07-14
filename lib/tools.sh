#!/usr/bin/env bash
#
# AuditXS — lib/tools.sh
# Security-tooling integration: the 'auditxs tools' subcommand.
#
#   tools status              inventory of defensive tooling + state
#   tools install <name...>   guided, reversible install of a security tool
#   tools scan [name]         run installed external scanners, save reports
#   tools vpn                 inspect VPN configuration (WireGuard / OpenVPN)
#
# AuditXS does not reimplement scanners — it installs, runs and collects the
# output of the established ones (Lynis, rkhunter, Tiger, chkrootkit,
# checksecurity, lsat) and helps set up active-defence engines (CrowdSec,
# Suricata) and host IDS (OSSEC/Wazuh). Installs go through the same
# snapshot/rollback machinery as every other change.
#

TOOLS_REPORT_DIR_ROOT="/var/lib/auditxs/reports/tools"

# name → package (empty = not a simple distro package; handled specially)
_tool_pkg() {
    case "$1" in
        lynis)         echo lynis ;;
        rkhunter)      echo rkhunter ;;
        chkrootkit)    echo chkrootkit ;;
        tiger)         echo tiger ;;
        checksecurity) echo checksecurity ;;
        lsat)          echo lsat ;;
        aide)          echo aide ;;
        debsecan)      echo debsecan ;;
        suricata)      echo suricata ;;
        fail2ban)      echo fail2ban ;;
        crowdsec)      echo crowdsec ;;      # may need the CrowdSec repo
        *)             echo "" ;;
    esac
}

_tool_present() {
    case "$1" in
        crowdsec) have cscli || have crowdsec ;;
        ossec)    [ -d /var/ossec ] || have ossec-control ;;
        *)        have "$1" || pkg_installed "$(_tool_pkg "$1")" 2>/dev/null ;;
    esac
}

# ---------------------------------------------------------------- status ---
cmd_tools_status() {
    nala_box "Security tooling inventory"
    local t state
    for t in lynis rkhunter chkrootkit tiger checksecurity lsat aide debsecan \
             fail2ban crowdsec suricata; do
        if _tool_present "$t"; then state="${GREEN}installed${RC}"; else state="${DIM}not installed${RC}"; fi
        nala_row "$(printf '%-14s %b' "$t" "$state")"
    done
    nala_row "${DIM}ossec/wazuh:${RC} $(_tool_present ossec && echo present || echo 'not present (see: auditxs tools install ossec)')"
    nala_end
    say ""
    say "Install one with: ${BOLD}sudo auditxs tools install <name>${RC}"
    say "Run scanners with: ${BOLD}sudo auditxs tools scan${RC}    ·    Check VPNs: ${BOLD}auditxs tools vpn${RC}"
}

# --------------------------------------------------------------- install ---
cmd_tools_install() {
    require_root "tools install"
    [ $# -ge 1 ] || die "Usage: sudo auditxs tools install <lynis|rkhunter|tiger|chkrootkit|checksecurity|lsat|aide|debsecan|suricata|crowdsec|ossec> ..."
    local name pkg rc=0
    for name in "$@"; do
        name=${name,,}
        case $name in
            crowdsec) _install_crowdsec || rc=1 ;;
            ossec|wazuh) _install_ossec_guidance ;;
            ayasat) _install_ayasat_guidance ;;
            *)
                pkg=$(_tool_pkg "$name")
                if [ -z "$pkg" ]; then
                    warn "Unknown tool '$name'. Known: lynis rkhunter chkrootkit tiger checksecurity lsat aide debsecan suricata crowdsec ossec"
                    rc=1; continue
                fi
                info "Installing $name ($pkg) …"
                if pkg_install "$pkg"; then
                    ok "$name installed."
                    case $name in
                        rkhunter) [ "$DRYRUN" = 1 ] || { have rkhunter && xrun_q rkhunter --propupd; ok "rkhunter baseline initialised (rkhunter --propupd)"; } ;;
                        aide)     say "  Next: initialise the AIDE database on this known-good system (aideinit / aide --init)." ;;
                        suricata) say "  Next: set your monitored interface in /etc/suricata/suricata.yaml, then 'systemctl enable --now suricata'." ;;
                    esac
                else
                    warn "Could not install $name from the distribution repositories."
                    rc=1
                fi ;;
        esac
    done
    snapshot_finish
    return $rc
}

_install_crowdsec() {
    if pkg_installed crowdsec || have cscli; then ok "CrowdSec is already installed."; return 0; fi
    # CrowdSec ships in Debian 13 / recent Ubuntu; otherwise it needs their repo.
    info "Installing CrowdSec …"
    if pkg_install crowdsec 2>/dev/null && (have cscli || pkg_installed crowdsec); then
        pkg_install crowdsec-firewall-bouncer-iptables 2>/dev/null || \
            pkg_install crowdsec-firewall-bouncer-nftables 2>/dev/null || \
            say "  (install a bouncer to enforce decisions: crowdsec-firewall-bouncer-nftables)"
        ok "CrowdSec installed. Review decisions with 'sudo cscli decisions list'."
        return 0
    fi
    warn "CrowdSec is not in this system's repositories."
    say  "  Guided setup (official, review before running):"
    say  "    curl -s https://install.crowdsec.net | sudo sh   # adds the CrowdSec repo"
    say  "    sudo apt install crowdsec"
    say  "  AuditXS will not pipe a remote script to your shell for you — that is your decision to make."
    return 1
}

_install_ossec_guidance() {
    info "OSSEC / Wazuh host IDS is not a single distribution package."
    say  "  OSSEC (self-hosted, lightweight):"
    say  "    Download and verify from https://www.ossec.net/download-ossec/ then run its installer."
    say  "  Wazuh (OSSEC fork, actively maintained, recommended):"
    say  "    Follow https://documentation.wazuh.com/ — adds a signed repo and installs the agent."
    say  "  AuditXS deliberately does not fetch and run third-party installers for you."
}

_install_ayasat_guidance() {
    info "'ayasat' is not a packaged tool in the supported distributions."
    say  "  For host auditing use Lynis ('auditxs tools install lynis'); for legacy-style"
    say  "  checklist audits, 'tiger' and 'lsat' are packaged and integrated here."
}

# ------------------------------------------------------------------ scan ---
cmd_tools_scan() {
    require_root "tools scan"
    local want=${1:-all} dir ts any=0
    ts=$(date +%Y%m%d-%H%M%S)
    dir="$TOOLS_REPORT_DIR_ROOT/$ts"
    mkdir -p "$dir" 2>/dev/null || die "Cannot create $dir"
    chmod 750 "$TOOLS_REPORT_DIR_ROOT" "$dir" 2>/dev/null

    _run_scan() { # <name> <command...>
        local n=$1; shift
        [ "$want" = all ] || [ "$want" = "$n" ] || return 0
        if ! _tool_present "$n"; then
            [ "$want" = "$n" ] && warn "$n is not installed (auditxs tools install $n)"
            return 0
        fi
        any=1
        info "Running $n … (output: $dir/$n.txt)"
        { echo "# AuditXS tools scan — $n — $(date -Is)"; "$@"; } > "$dir/$n.txt" 2>&1 || \
            warn "$n exited non-zero (its findings are still in $dir/$n.txt)"
        ok "$n finished."
    }

    _run_scan lynis          lynis audit system --quick --no-colors
    _run_scan rkhunter       rkhunter --check --sk --nocolors
    _run_scan chkrootkit     chkrootkit -q
    _run_scan tiger          tiger -q
    _run_scan checksecurity  checksecurity
    _run_scan lsat           lsat -o /dev/stdout

    if [ "$any" = 0 ]; then
        warn "No requested scanner is installed. Install one with 'auditxs tools install lynis' (recommended)."
        return 0
    fi
    hr
    ok "External scanner reports saved under: $dir"
    say "Review them and feed anything relevant back into your hardening plan."
}

# ------------------------------------------------------------------- vpn ---
cmd_tools_vpn() {
    nala_box "VPN configuration review"
    local found=0

    # WireGuard
    if have wg || ls /etc/wireguard/*.conf >/dev/null 2>&1; then
        found=1
        nala_row "${BOLD}WireGuard${RC}"
        local c mode
        for c in /etc/wireguard/*.conf; do
            [ -f "$c" ] || continue
            mode=$(stat -c %a "$c" 2>/dev/null)
            if [ "$mode" = 600 ] || [ "$mode" = 640 ] || [ "$mode" = 400 ]; then
                nala_row "  ${GREEN}✓${RC} $c (mode $mode — private key protected)"
            else
                nala_row "  ${RED}✗${RC} $c is mode $mode — contains a private key and must be 600. Fix: sudo chmod 600 $c"
            fi
        done
        have wg && nala_row "  active tunnels: $(wg show interfaces 2>/dev/null || echo none)"
    fi

    # OpenVPN
    if have openvpn || ls /etc/openvpn/**/*.conf /etc/openvpn/*.conf >/dev/null 2>&1; then
        found=1
        nala_row "${BOLD}OpenVPN${RC}"
        local f
        for f in /etc/openvpn/*.conf /etc/openvpn/server/*.conf /etc/openvpn/client/*.conf; do
            [ -f "$f" ] || continue
            if grep -qiE '^[[:space:]]*cipher[[:space:]]+(BF-CBC|DES|RC2|none)' "$f" 2>/dev/null; then
                nala_row "  ${RED}✗${RC} $f uses a weak/legacy cipher — move to AES-256-GCM (data-ciphers)."
            elif grep -qiE '^[[:space:]]*(data-ciphers|cipher)[[:space:]]+AES' "$f" 2>/dev/null; then
                nala_row "  ${GREEN}✓${RC} $f uses an AES cipher"
            else
                nala_row "  ${YELLOW}!${RC} $f — cipher not explicitly set; confirm data-ciphers AES-256-GCM"
            fi
            grep -qiE '^[[:space:]]*auth[[:space:]]+SHA(256|512)' "$f" 2>/dev/null || \
                nala_row "  ${YELLOW}!${RC} $f — consider 'auth SHA256' or better for HMAC"
        done
    fi

    if [ "$found" = 0 ]; then
        nala_row "No WireGuard or OpenVPN configuration found on this host."
        nala_row "${DIM}(If you use a commercial VPN client, review its own settings — kill-switch, DNS leak protection.)${RC}"
    fi
    nala_end
}

# ---------------------------------------------------------------- router ---
cmd_tools() {
    local sub=${1:-status}
    [ $# -gt 0 ] && shift
    case $sub in
        status)  cmd_tools_status ;;
        install) cmd_tools_install "$@" ;;
        scan)    cmd_tools_scan "$@" ;;
        vpn)     cmd_tools_vpn ;;
        *) die "Usage: auditxs tools status | install <name...> | scan [name] | vpn" ;;
    esac
}
