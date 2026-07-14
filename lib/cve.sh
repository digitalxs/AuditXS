#!/usr/bin/env bash
#
# AuditXS — lib/cve.sh
# Known-vulnerability / CVE awareness for installed packages.
#
# AuditXS is not a vulnerability scanner and never pretends to be one. This
# module surfaces vulnerabilities that the *distribution's own* security data
# already reports for the versions you have installed — the most reliable,
# false-positive-free signal available offline/locally:
#
#   * Debian:      debsecan (precise CVE list) when installed, else
#                  security-suite upgrade count from the apt cache.
#   * Ubuntu/Pop:  security-suite upgrade count (or 'pro'/'ubuntu-security-status'
#                  guidance).
#   * Fedora:      'dnf updateinfo' security advisory count.
#   * openSUSE:    'zypper list-patches' security count.
#
# A non-zero result means: an installed package has a known security issue
# with a fix available in your configured repositories. The warning is shown
# on the console, written to the log, exposed as check VULN-001 (so it lands
# in JSON/HTML reports) and read by the GUI.
#

CVE_COUNT="?"
CVE_SOURCE="none"
CVE_LIST=""

# cve_scan — populate CVE_COUNT / CVE_SOURCE / CVE_LIST. Read-only, bounded by
# a timeout so a blocked network never hangs an audit.
cve_scan() {
    CVE_COUNT="?"; CVE_SOURCE="none"; CVE_LIST=""
    case $DISTRO_FAMILY in
        debian)
            if have debsecan && [ "$DISTRO_ID" = debian ]; then
                local out
                out=$(timeout 120 debsecan --only-fixed --format packages 2>/dev/null | sort -u | grep -c . )
                if [ -n "$out" ] && [ "$out" != 0 ]; then
                    CVE_SOURCE=debsecan; CVE_COUNT=$out
                    CVE_LIST=$(timeout 120 debsecan --only-fixed --format packages 2>/dev/null | sort -u | head -n 30)
                    return 0
                fi
                # debsecan present but empty → either clean or no data
                CVE_SOURCE=debsecan; CVE_COUNT=0; return 0
            fi
            _cve_apt_security ;;
        redhat)
            have dnf || { CVE_COUNT="?"; return 0; }
            local n
            n=$(timeout 120 dnf -q updateinfo list --security 2>/dev/null | grep -cE '/(Sec|Security)|Important|Critical|Moderate|Low')
            case $n in ''|*[!0-9]*) CVE_COUNT="?" ;; *) CVE_SOURCE="dnf-updateinfo"; CVE_COUNT=$n ;; esac ;;
        suse)
            have zypper || { CVE_COUNT="?"; return 0; }
            local n
            n=$(timeout 120 zypper --non-interactive list-patches --category security 2>/dev/null | grep -c 'security')
            case $n in ''|*[!0-9]*) CVE_COUNT="?" ;; *) CVE_SOURCE="zypper-patches"; CVE_COUNT=$n ;; esac ;;
    esac
}

# apt security-suite upgrade count (offline: uses the local apt cache).
_cve_apt_security() {
    have apt-get || { CVE_COUNT="?"; return 0; }
    local sim
    sim=$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null \
        | grep '^Inst' | grep -iE 'security' )
    if [ -z "$sim" ]; then
        # No security-origin upgrades pending (or origin strings differ).
        CVE_SOURCE="apt-security"; CVE_COUNT=0; return 0
    fi
    CVE_SOURCE="apt-security"
    CVE_COUNT=$(printf '%s\n' "$sim" | grep -c .)
    CVE_LIST=$(printf '%s\n' "$sim" | awk '{print $2}' | sort -u | head -n 30)
}

# cve_banner — human banner used by 'audit' (console) and logged. Safe to call
# after cve_scan.
cve_banner() {
    [ "$QUIET" = 1 ] && { log "[cve] source=$CVE_SOURCE count=$CVE_COUNT"; return 0; }
    case $CVE_COUNT in
        0)   ok "No known-vulnerable packages reported by $CVE_SOURCE." ;;
        "?") warn "Vulnerability data unavailable (install 'debsecan' on Debian, or check network). No CVE assessment made." ;;
        *)
            printf '%b\n' "${RED}${BOLD}⚠ VULNERABILITY WARNING${RC} ${RED}$CVE_COUNT installed package(s) have a reported security issue with a fix available (source: $CVE_SOURCE).${RC}"
            [ -n "$CVE_LIST" ] && printf '%s\n' "$CVE_LIST" | sed 's/^/    /' | head -n 15
            printf '%b\n' "    ${YELLOW}Apply security updates promptly. Details: auditxs cve${RC}"
            ;;
    esac
    log "[cve] source=$CVE_SOURCE count=$CVE_COUNT"
}

# cmd_cve — the 'auditxs cve' subcommand. Exit 1 when vulnerabilities are found
# (CI/monitoring friendly), 0 when clean, 0 when undetermined.
cmd_cve() {
    info "Scanning installed packages against $DISTRO_NAME security data…"
    cve_scan
    hr
    case $CVE_COUNT in
        0)   ok "No known-vulnerable packages ($CVE_SOURCE)."; return 0 ;;
        "?") warn "Could not determine vulnerability status on this system."
             say  "  Debian: 'sudo apt install debsecan' for a precise CVE list."
             say  "  Ubuntu: 'pro security-status' / 'ubuntu-security-status'."
             return 0 ;;
        *)
            printf '%b\n' "${RED}${BOLD}$CVE_COUNT package(s) have a reported vulnerability with an available fix${RC} (source: $CVE_SOURCE):"
            [ -n "$CVE_LIST" ] && printf '%s\n' "$CVE_LIST" | sed 's/^/  /'
            hr
            say "Remediate with your package manager's security updates (AuditXS never upgrades packages automatically)."
            return 1 ;;
    esac
}
