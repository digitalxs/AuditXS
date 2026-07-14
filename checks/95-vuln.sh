#!/usr/bin/env bash
#
# AuditXS — checks/95-vuln.sh
# Category: Vulnerabilities — surface known CVEs in installed packages so they
# appear in the audit, the score, the reports and the drift baseline.
# Backed by lib/cve.sh (distribution security data — no external scanner).
#

register_check "VULN-001" "Vulnerabilities" "critical" "server,workstation" \
    "No installed package has a known vulnerability with an available fix"
set_meta VULN-001 desc "Cross-references installed package versions against the distribution's own security data (Debian: debsecan or the security apt suite; Ubuntu: security suite; Fedora: dnf updateinfo; openSUSE: zypper patches). A finding means a package you have installed is known-vulnerable and a fixed version is already available in your repositories — the highest-value, lowest-noise vulnerability signal a host can produce offline. Report-only: AuditXS never upgrades packages, because upgrades are not reversible; apply security updates with your package manager."
set_meta VULN-001 nist "ID.RA-01, DE.CM-08, PR.PS-02"

audit_VULN_001() {
    cve_scan
    case $CVE_COUNT in
        0)   DETAIL="No known-vulnerable packages ($CVE_SOURCE)"; return 0 ;;
        "?") DETAIL="Vulnerability data unavailable on this system. On Debian install 'debsecan'; on Ubuntu use 'pro security-status'. No assessment could be made."; return 2 ;;
        *)
            DETAIL="$CVE_COUNT installed package(s) have a reported vulnerability with a fix available (source: $CVE_SOURCE):"$'\n'"${CVE_LIST:-}"$'\n'"Apply security updates promptly — details: auditxs cve"
            return 1 ;;
    esac
}

register_check "VULN-002" "Vulnerabilities" "medium" "server,workstation" \
    "A precise CVE data source is available"
set_meta VULN-002 desc "Checks that the host can produce a precise per-CVE report, not just a security-update count. On Debian this is the 'debsecan' package (queries the Debian Security Tracker); on Ubuntu it is Ubuntu Pro / ubuntu-security-status. Having it installed means VULN-001 can name exact CVEs rather than approximating from the security suite."
set_meta VULN-002 fix "Debian: installs 'debsecan'. Other families already ship their advisory tooling (dnf updateinfo, zypper patches) and this check passes there."
set_meta VULN-002 revert "'sudo auditxs rollback' offers to remove the package it installed."
set_meta VULN-002 nist "ID.RA-01, DE.CM-08"

audit_VULN_002() {
    case $DISTRO_FAMILY in
        debian)
            if [ "$DISTRO_ID" = debian ]; then
                if have debsecan; then DETAIL="debsecan is installed (precise CVE tracking)"; return 0; fi
                DETAIL="debsecan not installed — VULN-001 falls back to a security-update count. Install for exact CVE IDs."
                return 1
            fi
            DETAIL="On Ubuntu/derivatives, enable Ubuntu Pro ('pro security-status') for precise CVE data; the security-suite count is used otherwise."
            return 2 ;;
        redhat) DETAIL="dnf updateinfo provides security advisory data"; return 0 ;;
        suse)   DETAIL="zypper list-patches provides security advisory data"; return 0 ;;
        *)      DETAIL="No known precise CVE data source for this distribution"; return 2 ;;
    esac
}

fix_VULN_002() {
    [ "$DISTRO_ID" = debian ] || { DETAIL="No package to install on this distribution"; return 1; }
    pkg_install debsecan
}
