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
        clamav)        echo clamav ;;
        openscap)      echo openscap-scanner ;;   # provides the 'oscap' binary
        arpwatch)      echo arpwatch ;;
        usbguard)      echo usbguard ;;
        firejail)      echo firejail ;;
        logwatch)      echo logwatch ;;
        acct)          echo acct ;;               # process accounting (lastcomm/sa)
        timeshift)     echo timeshift ;;          # system snapshots (undo package updates)
        crowdsec)      echo crowdsec ;;           # may need the CrowdSec repo
        auditd)        case $DISTRO_FAMILY in debian) echo auditd ;; *) echo audit ;; esac ;;
        *)             echo "" ;;
    esac
}

_tool_present() {
    case "$1" in
        crowdsec) have cscli || have crowdsec ;;
        ossec)    [ -d /var/ossec ] || have ossec-control ;;
        clamav)   have clamscan || have clamdscan ;;
        openscap) have oscap ;;
        osquery)  have osqueryi || have osqueryd ;;
        auditd)   have auditctl || svc_active auditd.service ;;
        acct)     have lastcomm || have sa || pkg_installed acct 2>/dev/null ;;
        trivy)    have trivy ;;
        *)        have "$1" || pkg_installed "$(_tool_pkg "$1")" 2>/dev/null ;;
    esac
}

# ---------------------------------------------------------------- status ---
# Grouped inventory: each tool tagged with the defensive capability it provides,
# so an operator can see coverage gaps (e.g. "no file-integrity monitor").
cmd_tools_status() {
    nala_box "Security tooling inventory"
    local t state
    _status_group() { # <heading> <tool...>
        nala_row "${BOLD}$1${RC}"; shift
        for t in "$@"; do
            if _tool_present "$t"; then state="${GREEN}installed${RC}"; else state="${DIM}not installed${RC}"; fi
            nala_row "  $(printf '%-14s %b' "$t" "$state")"
        done
    }
    _status_group "Host auditing / compliance" lynis tiger lsat checksecurity openscap
    _status_group "Rootkit / malware"          rkhunter chkrootkit clamav
    _status_group "File integrity"             aide
    _status_group "Vulnerability data"         debsecan trivy
    _status_group "Audit / accounting"         auditd acct
    _status_group "Active defence / IDS"       fail2ban crowdsec suricata arpwatch
    _status_group "Isolation / device control" firejail usbguard
    _status_group "Endpoint visibility / logs" osquery logwatch
    nala_row "${DIM}ossec/wazuh:${RC} $(_tool_present ossec && echo present || echo 'not present (see: auditxs tools install ossec)')"
    nala_end
    say ""
    say "Install one with: ${BOLD}sudo auditxs tools install <name>${RC}"
    say "Run scanners with: ${BOLD}sudo auditxs tools scan${RC}    ·    Check VPNs: ${BOLD}auditxs tools vpn${RC}"
}

# --------------------------------------------------------------- install ---
# The package-backed security tools AuditXS can install / uninstall / repair.
# (Guidance-only integrations like osquery/trivy/ossec are handled separately
# and are not in this list because there is no single distro package to manage.)
tools_list() {
    echo "lynis rkhunter chkrootkit tiger checksecurity lsat aide debsecan \
suricata fail2ban clamav openscap auditd arpwatch usbguard firejail logwatch acct timeshift crowdsec"
}

# _tool_service <tool> — the systemd unit to stop/disable when uninstalling
# (empty for tools that install no long-running service).
_tool_service() {
    case $1 in
        fail2ban) echo fail2ban ;;
        suricata) echo suricata ;;
        clamav)   echo clamav-freshclam ;;
        auditd)   echo auditd ;;
        arpwatch) echo arpwatch ;;
        usbguard) echo usbguard ;;
        crowdsec) echo crowdsec ;;
        acct)     echo acct ;;
        *)        echo "" ;;
    esac
}

cmd_tools_install() {
    require_root "tools install"
    local known; known=$(tools_list)
    [ $# -ge 1 ] || die "Usage: sudo auditxs tools install <name...>
Known: $(echo $known | tr -s ' ')"
    local name pkg rc=0
    for name in "$@"; do
        name=${name,,}
        case $name in
            crowdsec) _install_crowdsec || rc=1 ;;
            ossec|wazuh) _install_ossec_guidance ;;
            ayasat) _install_ayasat_guidance ;;
            osquery|trivy) _install_endpoint_guidance "$name" ;;
            *)
                pkg=$(_tool_pkg "$name")
                if [ -z "$pkg" ]; then
                    warn "Unknown tool '$name'. Known: $(echo $known | tr -s ' ')"
                    rc=1; continue
                fi
                info "Installing $name ($pkg) …"
                if pkg_install "$pkg"; then
                    ok "$name installed."
                    _install_post "$name"
                else
                    warn "Could not install $name from the distribution repositories."
                    rc=1
                fi ;;
        esac
    done
    snapshot_finish
    return $rc
}

# cmd_tools_uninstall <name...> — stop/disable any service, then remove the
# package (keeps config; use 'repair' for a clean reinstall).
cmd_tools_uninstall() {
    require_root "tools uninstall"
    [ $# -ge 1 ] || die "Usage: sudo auditxs tools uninstall <name...>"
    local name pkg svc rc=0
    for name in "$@"; do
        name=${name,,}
        pkg=$(_tool_pkg "$name")
        if [ -z "$pkg" ]; then warn "Unknown tool '$name'. Known: $(tools_list)"; rc=1; continue; fi
        if ! _tool_present "$name" && ! pkg_installed "$pkg"; then
            ok "$name is not installed."; continue
        fi
        svc=$(_tool_service "$name")
        if [ -n "$svc" ] && has_systemd; then
            info "Stopping and disabling ${svc} …"
            xrun_q systemctl disable --now "$svc" 2>/dev/null || true
        fi
        info "Removing $name ($pkg) …"
        if xrun pkg_remove "$pkg"; then
            ok "$name removed."
            ledger "tools: uninstalled $name ($pkg)"
        else
            ax_error AX5001 "could not remove $pkg"; rc=1
        fi
    done
    return $rc
}

# cmd_tools_repair <name...> — reinstall with FRESH configuration: purge the
# package (removing its config), then install it again so package defaults are
# laid down, then re-run post-install setup.
cmd_tools_repair() {
    require_root "tools repair"
    [ $# -ge 1 ] || die "Usage: sudo auditxs tools repair <name...>"
    local name pkg svc rc=0
    for name in "$@"; do
        name=${name,,}
        pkg=$(_tool_pkg "$name")
        if [ -z "$pkg" ]; then warn "Unknown tool '$name'. Known: $(tools_list)"; rc=1; continue; fi
        svc=$(_tool_service "$name")
        [ -n "$svc" ] && has_systemd && xrun_q systemctl stop "$svc" 2>/dev/null || true
        info "Repairing $name — purging old configuration, then reinstalling …"
        xrun pkg_purge "$pkg" >/dev/null 2>&1 || true    # ok if it was not installed
        if pkg_install "$pkg"; then
            ok "$name reinstalled with fresh default configuration."
            _install_post "$name"
            ledger "tools: repaired $name ($pkg) with fresh config"
        else
            ax_error AX5001 "could not reinstall $pkg"; rc=1
        fi
    done
    snapshot_finish
    return $rc
}

# _enable_note <success-msg> <unit...> — enable+start the first unit that
# exists, and print an honest message only if one actually came up. No-op in
# dry-run mode (the change is not made, so nothing is claimed).
_enable_note() {
    local msg=$1; shift
    [ "$DRYRUN" = 1 ] && return 0
    local u
    for u in "$@"; do
        if svc_enable "$u" 2>/dev/null; then ok "$msg"; return 0; fi
    done
    warn "Installed, but could not enable a service unit automatically — start it manually when ready."
    return 0
}

# Post-install setup guidance / baseline initialisation, per tool.
_install_post() {
    case $1 in
        rkhunter) [ "$DRYRUN" = 1 ] || { have rkhunter && xrun_q rkhunter --propupd; ok "rkhunter baseline initialised (rkhunter --propupd)"; } ;;
        aide)     say "  Next: initialise the AIDE database on this known-good system (aideinit / aide --init)." ;;
        suricata) say "  Next: set your monitored interface in /etc/suricata/suricata.yaml, then 'systemctl enable --now suricata'." ;;
        clamav)   say "  Next: update signatures with 'sudo freshclam', then scan with 'sudo auditxs tools scan clamav'."
                  say "  Tip: enable the freshclam service for automatic signature updates (systemctl enable --now clamav-freshclam)." ;;
        openscap) say "  SCAP policy content is shipped separately. Install it, then evaluate a profile:"
                  case $DISTRO_FAMILY in
                      debian) say "    sudo apt install ssg-debderived   # SCAP Security Guide content" ;;
                      redhat) say "    sudo dnf install scap-security-guide" ;;
                      suse)   say "    sudo zypper install scap-security-guide" ;;
                      *)      say "    install the 'scap-security-guide' (SSG) content package for your distro" ;;
                  esac
                  say "  Then: sudo auditxs tools scan openscap   (or: oscap xccdf eval --profile <id> <ssg.xml>)" ;;
        auditd)   _enable_note "auditd enabled — kernel audit events are now recorded." auditd.service auditd
                  say "  Review rules in /etc/audit/rules.d/ ; a CIS-aligned ruleset greatly improves forensics." ;;
        usbguard) say "  Next: generate an allow-list from currently-connected devices BEFORE enabling, or you may lock out your keyboard:"
                  say "    sudo usbguard generate-policy > /etc/usbguard/rules.conf && systemctl enable --now usbguard" ;;
        arpwatch) _enable_note "arpwatch enabled — ARP/MAC changes will be logged (watch for spoofing)." arpwatch.service arpwatch ;;
        acct)     _enable_note "process accounting active — audit with 'lastcomm' / 'sa'." acct.service psacct.service ;;
        firejail) say "  Sandbox an application with: firejail <program>. See 'firejail --list' for active sandboxes." ;;
        logwatch) say "  Next: review /etc/logwatch/conf/logwatch.conf ; a daily summary lands in root's mail or /var/log." ;;
    esac
}

_install_endpoint_guidance() {
    case $1 in
        osquery) info "osquery (SQL-based endpoint visibility) is distributed by its upstream project, not the base repos."
                 say  "  Install from the signed osquery repository: https://osquery.io/downloads"
                 say  "  Once installed, 'osqueryi' gives an interactive SQL shell over live system state." ;;
        trivy)   info "Trivy (vulnerability & misconfiguration scanner) is distributed by Aqua Security."
                 say  "  Install from the signed Aqua repository: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
                 say  "  Then scan the filesystem with: trivy filesystem /   or an image with: trivy image <name>." ;;
    esac
    say "  AuditXS deliberately does not add third-party repositories or run remote installers for you."
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

# Locate installed SCAP Security Guide content and evaluate a sensible profile.
# Prints guidance (and returns non-zero) when content or a profile is missing,
# so the scan report explains exactly what to install rather than failing blank.
_scan_openscap() {
    have oscap || { echo "oscap not installed"; return 1; }
    local ds
    ds=$(ls -1 /usr/share/xml/scap/ssg/content/*-ds.xml 2>/dev/null | head -1)
    if [ -z "$ds" ]; then
        echo "No SCAP Security Guide (SSG) content found under /usr/share/xml/scap/ssg/content/."
        echo "Install it, then re-run this scan:"
        case $DISTRO_FAMILY in
            debian) echo "  sudo apt install ssg-debderived" ;;
            redhat) echo "  sudo dnf install scap-security-guide" ;;
            suse)   echo "  sudo zypper install scap-security-guide" ;;
            *)      echo "  install the 'scap-security-guide' content package for your distro" ;;
        esac
        return 1
    fi
    # Prefer a CIS or standard profile if the datastream advertises one.
    local prof
    prof=$(oscap info "$ds" 2>/dev/null \
           | grep -oE 'xccdf_org\.ssgproject\.content_profile_[A-Za-z0-9._-]+' \
           | grep -iE 'cis|standard|stig' | head -1)
    [ -n "$prof" ] || prof=$(oscap info "$ds" 2>/dev/null \
           | grep -oE 'xccdf_org\.ssgproject\.content_profile_[A-Za-z0-9._-]+' | head -1)
    if [ -z "$prof" ]; then
        echo "SSG content $ds advertises no profiles; run 'oscap info $ds' to inspect."
        return 1
    fi
    echo "# datastream: $ds"
    echo "# profile:    $prof"
    oscap xccdf eval --profile "$prof" "$ds"
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
    # ClamAV: recursive, report infected only, on the areas most likely to be hit.
    _run_scan clamav         clamscan -ri --exclude-dir='^/(proc|sys|dev|run)' /home /tmp /var/tmp /etc /usr/local
    # OpenSCAP: evaluate against installed SSG content (best-effort profile pick).
    _run_scan openscap       _scan_openscap

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
        status)            cmd_tools_status ;;
        list)              tools_list | tr ' ' '\n' | sed '/^$/d' ;;   # machine-readable
        state)             # one line per tool: "<name> installed|absent" (for GUIs)
                           local _t
                           for _t in $(tools_list); do
                               if _tool_present "$_t"; then echo "$_t installed"; else echo "$_t absent"; fi
                           done ;;
        install)           cmd_tools_install "$@" ;;
        uninstall|remove)  cmd_tools_uninstall "$@" ;;
        repair|reinstall)  cmd_tools_repair "$@" ;;
        scan)              cmd_tools_scan "$@" ;;
        vpn)               cmd_tools_vpn ;;
        *) die "Usage: auditxs tools status | list | install <name> | uninstall <name> | repair <name> | scan [name] | vpn" ;;
    esac
}
