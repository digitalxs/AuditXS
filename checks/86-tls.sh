#!/usr/bin/env bash
#
# AuditXS — checks/86-tls.sh
# Category: TLS — server-certificate expiry. An expired certificate breaks
# HTTPS/SMTPS/IMAPS and often causes an outage before anyone notices; expiry
# monitoring is a basic operational control. Report-only (renewal is service-
# specific). SKIPs when openssl is unavailable or no certificates are found.
#

_tls_warn_days=30

# Candidate server-certificate files (Let's Encrypt + common explicit paths).
_tls_certs() {
    local d le; le=$(axpath /etc/letsencrypt/live)
    [ -d "$le" ] && find "$le" -maxdepth 2 -name 'fullchain.pem' 2>/dev/null
    for d in /etc/nginx/ssl /etc/apache2/ssl /etc/ssl/localcerts /etc/pki/tls/certs /etc/dovecot/private /etc/postfix; do
        [ -d "$(axpath "$d")" ] || continue
        find "$(axpath "$d")" -maxdepth 1 \( -name '*.pem' -o -name '*.crt' \) 2>/dev/null
    done
}

register_check "TLS-001" "TLS" "high" "server" \
    "No server TLS certificate is expired or expiring soon"
set_meta TLS-001 desc "Scans common certificate locations (Let's Encrypt and standard service directories) and checks each server certificate's expiry with openssl. Expired certificates cause outages and security warnings; certificates within ${_tls_warn_days} days of expiry need renewal now. Report-only — renewal is service-specific (certbot, ACME, manual)."
set_meta TLS-001 revert "No change is made (report-only)."

audit_TLS_001() {
    have openssl || { DETAIL="openssl is not installed — cannot inspect certificates"; return 3; }
    local f end end_epoch now soon=$(( $(date +%s) + _tls_warn_days*86400 ))
    now=$(date +%s)
    local expired="" expiring="" checked=0
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        # Skip obvious CA bundles.
        case $f in *ca-bundle*|*ca-certificates*) continue ;; esac
        end=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | sed 's/notAfter=//')
        [ -n "$end" ] || continue
        checked=$((checked+1))
        end_epoch=$(date -d "$end" +%s 2>/dev/null) || continue
        if [ "$end_epoch" -lt "$now" ]; then
            expired+="${f#"$AX_ROOT"} "
        elif [ "$end_epoch" -lt "$soon" ]; then
            expiring+="${f#"$AX_ROOT"}(expires $(date -d "$end" +%Y-%m-%d 2>/dev/null)) "
        fi
    done < <(_tls_certs)
    [ "$checked" -gt 0 ] || { DETAIL="No server certificates found in the standard locations"; return 3; }
    if [ -n "$expired" ]; then
        DETAIL="EXPIRED certificate(s): ${expired% } — renew immediately (certbot renew / your ACME client)"
        return 1
    fi
    if [ -n "$expiring" ]; then
        DETAIL="Certificate(s) expiring within ${_tls_warn_days} days: ${expiring% } — renew now"
        return 2
    fi
    DETAIL="All $checked checked certificate(s) are valid for more than ${_tls_warn_days} days"
    return 0
}
